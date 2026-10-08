//! Running the REAL `yadgar-iam-db` binary the way a pod runs it: with
//! `/etc/yadgar/config/shared/shared.yaml` mounted, as the only file it reads
//! from a fixed path (ledger 748). COPIED FROM `yadgarhq/task`'s own
//! `tests/support/mod.rs` at `origin/main` (ledger 748's task canary, #70),
//! NOT RE-DERIVED — see that file's header for the measurements behind the
//! mount-namespace rig and the per-wait-fails-loud discipline.
//!
//! **WHAT DIFFERS FROM THE TASK CANARY, so a reader diffing the two meets the
//! list rather than reconstructing it:**
//!
//!   - iam-db PROBES AND MIGRATES BEFORE IT LISTENS (D7, D69): `task` has no
//!     database at all, so its harness never needed one. [`boot_env`] creates
//!     a FRESH, throwaway database on the real engine named by
//!     `YADGAR_TEST_DSN` before every boot, and writes a real password file
//!     — without both, the binary never reaches the "listening" line this
//!     harness waits for.
//!   - `BIN` is `yadgar-iam-db`, and the "listening" line is `"iam-db
//!     listening"` (`src/main.rs`'s own `tracing::info!`), not `"task
//!     listening"`.
//!   - There is no `Booted::start(vars)` taking an arbitrary environment:
//!     every case in `tests/exit_chain.rs` needs the same full environment
//!     (a working pool plus the rotation mount), so [`Booted::start`] takes
//!     nothing and assembles it internally.
//!   - `cleartext_env` is RENAMED `boot_env` and returns `Vec<(&'static str,
//!     String)>` rather than `Vec<(&'static str, &'static str)>`: the
//!     database host, name and password path are resolved at runtime from
//!     `YADGAR_TEST_DSN` and the per-test root, not stated as literals.

// Each test target compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use sqlx::Connection;

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_yadgar-iam-db");

/// The rotation schedule every run is given: poll each second, no splay. A
/// rewrite is therefore noticed within one second and acted on at once.
pub const FIXTURE: &str = "tlsRotation:\n  pollSeconds: 1\n  splayMaxSeconds: 0\n";

/// The poll and splay in [`FIXTURE`], for deadlines derived from them.
pub const POLL: Duration = Duration::from_secs(1);
pub const SPLAY_MAX: Duration = Duration::from_secs(0);

/// What every deadline adds on top of the time the binary is allowed. Generous,
/// because a shared CI runner is slow; the waits it bounds are seconds long —
/// except the boot deadline, which also has to cover a fresh `CREATE DATABASE`
/// and a real migration.
pub const MARGIN: Duration = Duration::from_secs(10);

/// How long a boot may take to reach its "listening" line. Longer than the
/// task canary's: this boot probes the engine and runs every migration on a
/// freshly created database first.
pub const BOOT_DEADLINE: Duration = Duration::from_secs(30);

/// The script `unshare` runs. Paths arrive as positional arguments — `$1` the
/// per-test root, `$2` the binary — rather than interpolated into the text.
const SCRIPT: &str = r#"set -e
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$1/upper,workdir=$1/work" /etc
mkdir -p /etc/yadgar/config/shared
mount --bind "$1/shared" /etc/yadgar/config/shared
exec "$2""#;

/// `YADGAR_TEST_DSN`, split into its parts. `tests/contract.rs` needs the
/// same split for the same reason: CI's DSN ends in a database name
/// (`mysql://root:ci@127.0.0.1:3306/ci`), so a connection meant for a
/// DIFFERENT database must drop it rather than append past it.
struct Dsn {
    host: String,
    port: String,
    user: String,
    password: String,
    /// The DSN with its own trailing database component removed — a
    /// connection string this harness can still append its OWN fresh
    /// database name to.
    base: String,
}

fn test_dsn() -> Dsn {
    // `.expect(...)`, the same shape `tests/contract.rs`'s own `dsn()` reads this
    // key with — never `unwrap_or_else`/`unwrap_or_default`, which is the inline
    // fallback shape ADR-0569's gate forbids.
    let dsn = std::env::var("YADGAR_TEST_DSN").expect(
        "YADGAR_TEST_DSN is unset; this harness boots the real binary against a real engine, \
         the same requirement tests/contract.rs states",
    );
    // NONE OF THESE PANICS PRINT `dsn`. It carries the engine password in
    // plaintext (`mysql://user:pass@host:port/db`), and a panic message
    // lands in this harness's own captured stdout/stderr — which
    // `Booted::fail` then echoes into the test output on every failure.
    // Naming the STRUCTURE that is missing is enough to act on; the value
    // never needs to be.
    let (base, _database) = dsn.rsplit_once('/').unwrap_or_else(|| {
        panic!("YADGAR_TEST_DSN has no database component (no '/' after the host:port)")
    });
    let after_scheme = dsn
        .strip_prefix("mysql://")
        .unwrap_or_else(|| panic!("YADGAR_TEST_DSN is not a mysql:// DSN"));
    let (credentials, host_and_port) = after_scheme
        .split_once('@')
        .unwrap_or_else(|| panic!("YADGAR_TEST_DSN has no user@host component"));
    let (host_and_port, _) = host_and_port
        .rsplit_once('/')
        .unwrap_or_else(|| panic!("YADGAR_TEST_DSN has no database component"));
    let (user, password) = credentials.split_once(':').unwrap_or((credentials, ""));
    let (host, port) = host_and_port
        .split_once(':')
        .unwrap_or_else(|| panic!("YADGAR_TEST_DSN has no host:port component"));
    Dsn {
        host: host.to_string(),
        port: port.to_string(),
        user: user.to_string(),
        password: password.to_string(),
        base: base.to_string(),
    }
}

/// A fresh, empty database on the real engine, named uniquely per call so
/// cases running on threads of one process (ledger 706) never collide.
fn fresh_database(dsn: &Dsn) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "iam_db_exit_chain_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let runtime =
        tokio::runtime::Runtime::new().expect("a tokio runtime for the test rig's own setup");
    runtime.block_on(async {
        let mut conn = sqlx::MySqlConnection::connect(&dsn.base)
            .await
            .unwrap_or_else(|e| {
                panic!("the test rig could not connect as root to set up a fresh database: {e}")
            });
        for statement in [
            format!("DROP DATABASE IF EXISTS {name}"),
            format!("CREATE DATABASE {name}"),
        ] {
            // AUDIT: `name` is built from a pid and a counter in this file, never from input.
            sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                .execute(&mut conn)
                .await
                .unwrap_or_else(|e| {
                    panic!("the test rig could not prepare database {name:?}: {e}")
                });
        }
    });
    name
}

/// Every variable the real binary needs to boot, probe, migrate and listen in
/// cleartext — a FRESH database on the real engine named by
/// `YADGAR_TEST_DSN`, and the rotation mount's schedule. `root` is where the
/// password file is written; it must already exist.
///
/// Port 0 on both listeners, because the cases in a target run in parallel.
/// `LISTEN_TLS_ENABLED` is stated as `"0"` rather than left absent — ADR-0845
/// makes absence a boot refusal now, which is exactly the regression
/// `tests/boot_message.rs` holds; this harness states the flag explicitly for
/// the same reason a chart does.
pub fn boot_env(root: &Path) -> Vec<(&'static str, String)> {
    let dsn = test_dsn();
    let database = fresh_database(&dsn);

    let password_path = root.join("db-password");
    std::fs::write(&password_path, &dsn.password)
        .unwrap_or_else(|e| panic!("the password file must be writable: {e}"));

    vec![
        ("DB_HOST", dsn.host),
        ("DB_PORT", dsn.port),
        ("DB_NAME", database),
        ("DB_USER", dsn.user),
        ("DB_MAX_CONNECTIONS", "4".to_string()),
        ("REPLICAS", "1".to_string()),
        ("DB_ENGINE_MAX_CONNECTIONS", "20".to_string()),
        // The four C-DB2 knobs (`yadgar-store` v0.4.0, ADR-0837, ADR-0849):
        // this harness states the chart's own shipped values, the same
        // reason it states every other knob above explicitly rather than
        // relying on a default that no longer exists.
        ("DB_ENGINE_OPERATOR_RESERVE", "5".to_string()),
        ("DB_ACQUIRE_TIMEOUT_SECONDS", "25".to_string()),
        ("DB_IDLE_TIMEOUT_SECONDS", "600".to_string()),
        ("DB_MAX_LIFETIME_SECONDS", "1800".to_string()),
        ("DB_SSL_MODE", "disabled".to_string()),
        ("DB_MIGRATION_LOCK_TIMEOUT_SECONDS", "60".to_string()),
        (
            "DB_PASSWORD_FILE",
            password_path
                .to_str()
                .unwrap_or_else(|| panic!("the password file path must be UTF-8"))
                .to_string(),
        ),
        ("LISTEN", "127.0.0.1:0".to_string()),
        ("METRICS_LISTEN", "127.0.0.1:0".to_string()),
        ("LISTEN_TLS_ENABLED", "0".to_string()),
    ]
}

/// One line the binary wrote, and which stream it came from.
enum Line {
    Out(String),
    Err(String),
}

/// The binary, running in its own mount namespace, with its output pumped,
/// against a fresh database it alone owns.
pub struct Booted {
    child: Child,
    lines: Receiver<Line>,
    seen: Vec<String>,
    root: PathBuf,
}

impl Booted {
    /// Start the binary with [`boot_env`]'s environment and exactly that —
    /// `PATH` aside, for `unshare`, `mount` and `sh`.
    pub fn start() -> Self {
        let root = fresh_root();
        let vars = boot_env(&root);

        // `unshare`, `mount` and `sh` are found on the caller's PATH; on some
        // hosts none of them is under /usr/bin. A rig with no PATH fails here
        // rather than guessing one.
        let path = std::env::var_os("PATH").expect("the test runner must have a PATH");
        let mut child = Command::new("unshare")
            .args(["-rm", "sh", "-c", SCRIPT, "sh"])
            .arg(&root)
            .arg(BIN)
            .env_clear()
            .env("PATH", path)
            .envs(vars.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("`unshare` could not be started: {e}"));

        // ONE THREAD PER STREAM, pumping for the life of the child. Reading
        // only until the "listening" line would leave the pipe to fill and the
        // binary to block on its next log line.
        let (tx, lines) = mpsc::channel();
        let out = child.stdout.take().expect("stdout was piped");
        let err = child.stderr.take().expect("stderr was piped");
        let tx_err = tx.clone();
        std::thread::spawn(move || pump(out, move |l| tx.send(Line::Out(l)).is_ok()));
        std::thread::spawn(move || pump(err, move |l| tx_err.send(Line::Err(l)).is_ok()));

        Self {
            child,
            lines,
            seen: Vec::new(),
            root,
        }
    }

    /// The binary's pid. `exec` all the way down makes it the direct child.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for a line satisfying `matches`, or fail on `deadline`.
    ///
    /// A child whose output ends first — it exited, or the mount namespace was
    /// refused and it never started — fails at once with what it printed,
    /// rather than as a timeout.
    pub fn wait_for_line(
        &mut self,
        what: &str,
        deadline: Duration,
        matches: impl Fn(&str) -> bool,
    ) -> String {
        let until = Instant::now() + deadline;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(Line::Out(l) | Line::Err(l)) => {
                    self.seen.push(l.clone());
                    if matches(&l) {
                        return l;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.fail(&format!("waited {deadline:?} for {what}; it never came"))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.reap(Duration::from_secs(5));
                    self.fail(&format!(
                        "the binary's output ended before {what} ({})",
                        describe(status)
                    ))
                }
            }
        }
    }

    /// Wait for the boot to reach the line `main.rs`'s `serve_until_drained`
    /// logs once the signal handlers are armed and the server is spawned.
    pub fn wait_until_listening(&mut self) {
        self.wait_for_line("the \"iam-db listening\" line", BOOT_DEADLINE, |l| {
            l.contains("\"iam-db listening\"")
        });
    }

    /// Send SIGTERM, the way kubelet ends a pod.
    pub fn terminate(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap_or_else(|e| panic!("`kill` could not be started: {e}"));
        if !status.success() {
            self.fail(&format!("`kill -TERM` failed: {status}"));
        }
    }

    /// Wait for the process to exit, or fail on `deadline`.
    pub fn wait_for_exit(&mut self, what: &str, deadline: Duration) -> ExitStatus {
        match self.reap(deadline) {
            Some(status) => {
                self.drain_lines();
                status
            }
            None => self.fail(&format!(
                "waited {deadline:?} for the process to exit {what}; it was still running"
            )),
        }
    }

    /// Replace the mounted `shared.yaml` the way kubelet replaces a projected
    /// file: write a sibling, then rename it over the original.
    pub fn rewrite_shared(&self, contents: &str) {
        let dir = self.root.join("shared");
        let staged = dir.join(".shared.yaml.next");
        std::fs::write(&staged, contents).expect("the staged document must be written");
        std::fs::rename(&staged, dir.join("shared.yaml"))
            .expect("the staged document must replace the mounted one");
    }

    /// Every line the binary has written so far.
    pub fn seen(&self) -> &[String] {
        &self.seen
    }

    /// Fail the test: kill the child, then panic with everything it printed.
    pub fn fail(&mut self, why: &str) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.drain_lines();
        panic!(
            "{why}\n--- everything the binary wrote ---\n{}",
            self.seen.join("\n")
        );
    }

    fn reap(&mut self, deadline: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + deadline;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() >= until => return None,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("the child could not be waited on: {e}"),
            }
        }
    }

    fn drain_lines(&mut self) {
        // The pumps end at EOF, which follows the exit closely; a short bound
        // keeps a stray grandchild holding the pipe from hanging the test.
        while let Ok(Line::Out(l) | Line::Err(l)) =
            self.lines.recv_timeout(Duration::from_millis(500))
        {
            self.seen.push(l);
        }
    }
}

impl Drop for Booted {
    fn drop(&mut self) {
        // A panicking test must not leave a server running.
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_root(&self.root);
    }
}

/// The exit status as a sentence that says whether a signal ended it.
pub fn describe(status: Option<ExitStatus>) -> String {
    match status {
        None => "still running".to_string(),
        Some(s) => format!("code {:?}, signal {:?}", s.code(), s.signal()),
    }
}

/// A per-test directory: the overlay's upper and work dirs, and the directory
/// bind-mounted as `/etc/yadgar/config/shared`.
///
/// Under the system temp dir, which must not itself be an overlay: an overlay's
/// upperdir cannot sit on one. The name carries a counter as well as the pid,
/// because the cases of a target run on threads of one process (ledger 706).
fn fresh_root() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "yadgar-iam-db-exit-chain-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    for dir in ["upper", "work", "shared"] {
        std::fs::create_dir_all(root.join(dir)).expect("the test root must be created");
    }
    std::fs::write(root.join("shared").join("shared.yaml"), FIXTURE)
        .expect("the fixture document must be written");
    root
}

/// Best effort. Overlayfs leaves `work/work` with mode 0, so it is opened up
/// before the tree is removed.
fn remove_root(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        root.join("work").join("work"),
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::remove_dir_all(root);
}

fn pump(stream: impl Read, mut send: impl FnMut(String) -> bool) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        if !send(line) {
            return;
        }
    }
}
