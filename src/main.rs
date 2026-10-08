//! Boot order is the decision here, not the wiring.
//!
//! Probe, migrate, then serve — and the service does not report ready until all
//! three have succeeded. D7 makes a capability gap a boot failure, and D69 puts
//! the probe before the pool is declared ready precisely so a failure is a
//! crash-loop rather than a pod that accepts traffic and fails queries. Under
//! D68 the second shape is actively harmful: a pod that starts and then errors is
//! one the HPA adds replicas around.
//!
//! **The listener's TRANSPORT is decided first, before the probe.** It is a
//! deployment mistake rather than an outage — the same class as an engine that
//! cannot satisfy D7 — so it fails the boot, and it fails it before a migration
//! runs, so an operator who mounted the wrong Secret is told at once. Nothing
//! here falls back to a plaintext listener when TLS was asked for: a service that
//! did would look healthy while carrying every credential in the module across
//! the pod network in the clear, which is exactly the failure nobody can see.
//!
//! TLS is OPT-IN, and `LISTEN_TLS_ENABLED` must say so explicitly — see
//! `serve`'s module documentation for why absence no longer means cleartext
//! (ADR-0845).
//!
//! **THE TWO LISTENER ADDRESSES ARE DECIDED HERE TOO, before the probe**
//! (ledger 1257), for the same reason the transport is: `LISTEN` and
//! `METRICS_LISTEN` used to be parsed deep inside `serve_until_drained`,
//! which runs only after the probe and the migration succeed — so a bad
//! address was reachable only with a real engine behind it, and
//! `tests/boot_message.rs`'s promise that no engine is needed could not
//! reach it. Neither address depends on the engine, so both parse up front.

use std::net::SocketAddr;
use std::path::PathBuf;

use sqlx::{Connection, MySqlPool};
use tonic::transport::Server;
use yadgar_lifecycle::{drain_within, Drain, DRAIN_BUDGET};
use yadgar_store::capability::{Capability, CapabilitySet};
use yadgar_store::credentials::{CredentialSource, Secret};
use yadgar_store::pool::PoolConfig;
use yadgar_store::{migrate, probe};

use yadgar_iam_db::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbServiceServer;
use yadgar_iam_db::{boot, rotate, schema, serve, service::IamDb};

/// What this module needs of its engine (D69). Addressed, not ranked — so no
/// vector search and no full-text (D10). Requiring either would make this module
/// refuse to boot on an engine that serves it perfectly well.
fn required() -> CapabilitySet {
    CapabilitySet::from([Capability::Transactions, Capability::RowLocking])
}

/// One configuration knob, read from its ONE source, with no compiled-in
/// default behind it (ADR-0569).
///
/// This replaced `env_or(key, default)`, and the deletion is the point rather
/// than the rename: while the helper took a `default` argument, every knob in
/// this binary had somewhere for a fallback to live, and a fallback is invisible
/// at the point of use, survives an upgrade unnoticed, and makes the effective
/// setting depend on which layer a reader happens to inspect.
///
/// AN EMPTY VALUE REFUSES TOO, and with its own message. A set-but-empty
/// variable and an absent one collapsing into a single branch is a defect this
/// estate found three separate times in one week: Helm renders an unset value as
/// `""`, so the empty case is what a nulled chart value actually produces, and it
/// is the one an operator is most likely to hit.
///
/// The twin of `boot::env_required`, which takes the environment as a lookup so
/// a test can state one without mutating the process. This one reads `std::env`
/// because the three knobs it serves are read in `main` itself, where there is
/// no lookup to inject.
fn env_required(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it; a values override that nulls it \
             produces exactly this."
        )),
        Err(_) => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it."
        )),
    }
}

/// Ledger 1257: `LISTEN` and `METRICS_LISTEN` used to be parsed with a bare
/// `.parse()?`, which converts an `AddrParseError` into `Box<dyn Error>`
/// through its own `Display` — "invalid socket address syntax", naming
/// NEITHER variable. An operator staring at that sentence in a crash loop
/// has two candidates and nothing telling them apart.
///
/// Neither address has a chart key of its own: `templates/deployment.yaml`
/// hardcodes both (`"0.0.0.0:50051"`, `"0.0.0.0:9090"`) rather than reading
/// them from `values.yaml`, so there is nothing to NAME beyond the variable
/// — unlike the chart-driven knobs in `boot::pool_config`, which name a
/// chart key too.
fn parse_required_addr(key: &str) -> Result<SocketAddr, String> {
    let value = env_required(key)?;
    value
        .parse()
        .map_err(|e| format!("{key} is {value:?}, which is not a valid address (host:port): {e}"))
}

/// The JSON subscriber, and the default that keeps this process observable.
///
/// Extracted from `main` for the file-and-function ceilings, and it is the one
/// step of the boot that is not a decision about this service: every binary in
/// the estate installs the same thing before it reads anything.
fn install_logging() {
    tracing_subscriber::fmt()
        .json()
        // A DEFAULT, because from_default_env() with RUST_LOG unset enables
        // NOTHING — the service runs silently and its boot sequence, its
        // capability probe result and its errors all vanish. Found by deploying:
        // two replicas were Running and `kubectl logs` returned nothing at all,
        // so the only way to see why one had restarted was the previous
        // container's exit output.
        //
        // A service nobody can observe is one D67 cannot measure either.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // The log level is observability, not behaviour, and "info" is
                // the one fallback every binary in the estate shares rather
                // than a knob this chart renders — see B8 of the ADR-0705
                // census.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")), // ADR-0569-EXCEPTION(LIB): the log level is observability, not behaviour.
        )
        .init();
}

/// D7's capability probe, on a connection of its own and before the pool exists.
///
/// Step 1 of the boot, whole: the options, the connection, the probe, the
/// verdict against [`required`], and the close. It is one function because a
/// caller that could run any part of it without the verdict would be the defect
/// D7 exists to refuse.
async fn probe_engine(
    config: &PoolConfig,
    secret: &Secret,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. PROBE, on a connection of its own and before the pool exists. Refusing
    //    here is the whole point of D7.
    //
    //    Its own CONNECTION, never its own connection OPTIONS. This used to be a
    //    `format!`-ed DSN with no `ssl-mode` in it, so the probe ran on sqlx's
    //    `Preferred` default — which falls back to an unencrypted connection —
    //    while the pool three lines down was on `Required`. The options come
    //    from the same function the pool uses, so the two cannot disagree.
    //
    //    `.to_string()` for the same reason the listener's refusals carry it:
    //    building these options REFUSES `verify_ca`, and that refusal is a
    //    paragraph naming the mode to use instead. A bare `?` would Debug-print
    //    `SslModeCannotVerify { .. }` into the crash loop and throw the sentence
    //    away.
    let options = boot::probe_connect_options(config, secret).map_err(|e| e.to_string())?;
    let mut conn = sqlx::MySqlConnection::connect_with(&options).await?;
    let report = probe::run(&mut conn).await?;
    report.satisfies(&required())?;
    conn.close().await?;
    tracing::info!("engine satisfies the required capabilities");
    Ok(())
}

/// Step 2a, and the rotation watch set it joins (ADR-0569, ADR-0570, ADR-0523).
///
/// Extracted from `run`, under this file's own 120-line function ceiling.
/// `run` still calls this at the exact point boot always assembled it — the
/// ordering this function's own body argues for (built immediately after the
/// last of its members is read, never deferred to the watcher's first poll)
/// is unchanged by where the lines live.
///
/// STEP 2A OF THE ROTATION-KNOB CUT-OVER (ADR-0569, ADR-0570). The document
/// `yadgarhq/config` renders into the `shared` ConfigMap, mounted at
/// `/etc/yadgar/config/shared/shared.yaml`. There is no compiled-in default
/// behind it any more: an absent, empty, or half-written document refuses
/// the boot and names the file. The chart still sets TLS_ROTATION_POLL_SECS
/// and TLS_ROTATION_SPLAY_MAX_SECS — this binary no longer reads either, but
/// they stay so a rollout that lands this chart before this binary's digest
/// still resolves a schedule on the old one. The runbook is
/// `yadgarhq/deploy`'s MIGRATION_NOTES.md, steps 2a and 2b — NOT this
/// repository's, which has no such section.
///
/// THE WATCH SET, ASSEMBLED FROM THE RESOLVED CONFIGURATION AND HASHED AS
/// THE PROCESS READS IT (ADR-0523). FOUR MATERIALS, THREE OF WHICH ARE NOT
/// THE CERTIFICATE: the database password is read once and baked into a
/// pool that outlives every reconnect, the engine's CA is mounted the same
/// way, and the mounted configuration document joins the same set (step 2a)
/// — so all three are watched exactly as the leaf is.
///
/// ONE CALL, AND THE SAME ONE `tests/assembly.rs` MAKES. Nothing in a binary
/// entry point is reachable from a test, so a member deleted from a list
/// built here would compile, pass everything, and ship a process blind to
/// that file. The list lives in `rotate::watch_set`.
///
/// THE SCHEDULE IS READ FROM THE SAME DOCUMENT THE WATCH SET JUST JOINED. A
/// value the document names and this binary cannot use is a mistake to
/// refuse, not one to paper over with a default nobody chose — and refusing
/// it here means it is refused on a cleartext deployment too, which is
/// where it would otherwise sit unnoticed until the cut-over.
fn watch_and_schedule(
    listen_tls: Option<&serve::ServerTls>,
    db_password_file: &std::path::Path,
    ssl_ca: Option<&std::path::Path>,
) -> Result<(rotate::Inputs, rotate::Schedule), Box<dyn std::error::Error>> {
    let rotation_config = rotate::Configuration::mounted();
    let watch_inputs = rotate::watch_set(listen_tls, db_password_file, ssl_ca, &rotation_config);
    let schedule = rotation_config.schedule().map_err(|e| e.to_string())?;
    Ok((watch_inputs, schedule))
}

/// Step 3, from the listener address to the last in-flight call.
///
/// The boot log, the signal handlers, the spawned server, the two things that
/// end it and the drain budget are ONE function because they are one ordering,
/// and the ordering is what this file is about: the handlers arm BEFORE the
/// server is spawned, and the budget's clock starts when shutdown is REQUESTED.
/// Splitting them would let a later edit move one without the others.
///
/// The listener itself arrives LAST and by value, because the boot log is the
/// only thing left that asks whether it is there. Everything that needed to
/// borrow it — the server builder and the watch set — has already run.
///
/// `addr` ARRIVES ALREADY PARSED, rather than being read here. It used to be
/// read and parsed inside this function, which runs only after `run` has
/// probed the engine and migrated — so `LISTEN=notanaddr` refused only once
/// a real engine had answered, and no test lacking one could reach that
/// refusal. `run` hoists both listener addresses beside its other boot-order
/// decisions, none of which need an engine either.
async fn serve_until_drained(
    mut server: Server,
    pool: MySqlPool,
    watch_inputs: rotate::Inputs,
    schedule: rotate::Schedule,
    listen_tls: Option<serve::ServerTls>,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // `tls` is recorded because "is this listener encrypted?" must be answerable
    // from the boot log rather than inferred from which variables somebody
    // believes they set. `watching` for the same reason applied to the rotation
    // watcher: a zero there is a process that will notice nothing.
    tracing::info!(
        %addr,
        tls = listen_tls.is_some(),
        watching = watch_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = DRAIN_BUDGET.as_secs(),
        "iam-db listening"
    );

    // ARMED BEFORE THE SERVER IS SPAWNED, and that ordering is the fix rather
    // than an accident of where the line sits. `yadgar_lifecycle::shutdown` is a
    // `fn` returning a future rather than an `async fn`, so both signal handlers
    // install when it is CALLED — a SIGTERM arriving between here and the first
    // poll of the future would otherwise take the process's default disposition
    // and kill it outright.
    //
    // FROM THE SHARED CRATE, not from this repository. Which signals end a
    // process is one decision for the estate (D19, ADR-0526); it was five copies
    // and wrong in all five.
    let signals = yadgar_lifecycle::shutdown().map_err(|e| {
        format!(
            "the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a \
             server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one"
        )
    })?;

    // THE SERVER IS SPAWNED WITH A ONESHOT AS ITS SHUTDOWN FUTURE, and the wait
    // happens OUTSIDE it. `drain_within` starts the budget's clock when shutdown
    // is REQUESTED; a `timeout` wrapped round the serving future itself would fix
    // its deadline at boot and end the process a few seconds later on every boot,
    // having asked nothing to stop.
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(
        server
            .add_service(IamDbServiceServer::new(IamDb::new(pool)))
            // ONE DRAIN PATH, TWO REASONS TO TAKE IT. `serve_with_shutdown` stops
            // accepting and lets in-flight calls finish, so the rotation exit gets
            // the same drain a signal does rather than a second mechanism beside
            // it.
            .serve_with_shutdown(addr, async {
                let _ = stop_requested.await;
            }),
    );

    // WHAT ENDS THE SERVE, and nothing else does.
    //
    // **THE BUDGET IS PART OF THIS CHANGE RATHER THAN A FOLLOW-UP TO IT.** tokio
    // never unregisters a libc signal handler, so once the rotation arm wins this
    // `select!` a later SIGTERM is SWALLOWED and only SIGKILL remains. A watcher
    // added without `drain_within` would trade an expired certificate for a pod
    // that cannot be stopped politely — `serve.rs` named the three as one
    // decision, and this is that.
    let stop = async {
        tokio::select! {
            // SIGTERM and SIGINT, already armed above. SIGTERM is the one
            // Kubernetes sends.
            () = signals => {}
            // `rotate::watch` resolves ONLY when it has read a change, and never
            // at all when there is nothing to watch.
            () = rotate::watch(watch_inputs, schedule) => {}
        }
    };

    match drain_within(serving, ask_to_stop, stop, DRAIN_BUDGET).await {
        Drain::Finished(result) => result?,
        // EXIT 0 ANYWAY. The restart is the point; a drain that overran is worth
        // an error in the log, not a CrashLoopBackOff on top of it.
        Drain::Overran => tracing::error!(
            budget_secs = DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }
    Ok(())
}

/// The process entry point: run the service, and print a refusal as its SENTENCE.
///
/// **NOT `main() -> Result`.** Rust prints a `main` that returns `Err` with
/// DEBUG, so a `BootError` arrived as its variant name (`ObsoleteRequireTls`)
/// and even a refusal already converted to its sentence arrived as a quoted,
/// escaped string — `Error: "… is \"0\" …"`. ADR-0569 asks a refusal to name the
/// knob and where it is set; an operator reading a crash loop must get that as
/// plain text. `tests/boot_message.rs` runs the binary and holds it.
///
/// The exit status is unchanged: an `Err` from `main` exits 1, and so does
/// `ExitCode::FAILURE`.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    install_logging();

    // Every default, every refusal and the transport mode live in `boot`, which
    // a test can reach. `main` prints a refusal with Display, so it reaches the
    // operator as the sentence naming the knob (ADR-0569); `tests/boot_message.rs`
    // holds it. The lock wait has no default (ledger 814).
    let config = boot::pool_config(|key| std::env::var(key).ok()).map_err(|e| e.to_string())?;
    let migration_lock =
        boot::migration_lock(|key| std::env::var(key).ok()).map_err(|e| e.to_string())?;

    // 0. THE TRANSPORT THIS SERVICE LISTENS ON, before anything else runs. A
    //    missing certificate, an unreadable one, a file holding no certificate
    //    at all, a key belonging to a different certificate, an absent
    //    client-auth mode and a client CA holding no authority are all refused
    //    HERE — never downgraded to the plaintext listener.
    //
    //    `serve::refusal` on the way out, and not decoration: a bare `?` would
    //    print the error with DEBUG, and `to_string()` would drop tonic's
    //    `source` — the only layer that says WHY a key was refused.
    let listen_tls = serve::from_env().map_err(|e| serve::refusal(&e))?;
    let server = serve::builder(listen_tls.as_ref()).map_err(|e| serve::refusal(&e))?;

    // THE TWO LISTENER ADDRESSES, hoisted here rather than read where each is
    // used (ledger 1257). Neither depends on anything the probe or the
    // migration produces, so both move beside the other decisions this
    // function makes before opening anything — and `LISTEN=notanaddr` is now
    // reachable from `tests/boot_message.rs`, which promises no engine is
    // needed.
    let addr = parse_required_addr("LISTEN")?;
    let metrics_addr = parse_required_addr("METRICS_LISTEN")?;

    // The credential never arrives as an environment variable — it is a mounted
    // Secret the operator issued (D58), read through the seam so this module has
    // no idea which deployment target it is on.
    //
    // THE PATH IS HOISTED INTO A VARIABLE because two things need it: the read
    // below, and the rotation watch set. `Secret` deliberately holds the VALUE
    // and not where it came from, so the path has to be named once here rather
    // than recovered from the secret afterwards.
    //
    // NO COMPILED-IN DEFAULT any more (ADR-0569). The path used to be
    // `/var/run/secrets/iam-db/password` in this line AND the mount path
    // `/var/run/secrets/iam-db` in the chart's `volumeMounts` — one path written
    // twice, in two repositories' worth of reader attention, with nothing making
    // them move together. The chart now renders the variable next to the mount
    // that supplies the directory, so both copies sit in one file where a reader
    // sees them at once.
    let db_password_file: PathBuf = env_required("DB_PASSWORD_FILE")?.into();
    let secret: Secret = CredentialSource::SecretFile(db_password_file.clone()).resolve()?;

    let (watch_inputs, schedule) = watch_and_schedule(
        listen_tls.as_ref(),
        &db_password_file,
        config.ssl_ca.as_deref(),
    )?;

    // 1. PROBE. The connection it opens, and every reason it opens its own,
    //    are in `probe_engine`.
    probe_engine(&config, &secret).await?;

    // 2. MIGRATE. Refuses outright if the database is ahead of this binary.
    let pool = yadgar_store::pool::connect(&config, &secret).await?;
    let applied = migrate::apply(&pool, &schema::migrations()?, &migration_lock).await?;
    tracing::info!(applied, "schema at migration {applied}");

    // 3. SERVE. Only now.
    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    //
    // `metrics_addr` was already parsed above, before the probe — this is just
    // where it is first USED.
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // AFTER THE EXPORTER, NEVER BEFORE IT: a value recorded while there is no
    // recorder is a value nobody ever sees. This is the half of the rotation work
    // that makes a failure LOUD — if the watcher below dies, this gauge still
    // shows the loaded leaf ageing out.
    watch_inputs.export_not_after();

    serve_until_drained(server, pool, watch_inputs, schedule, listen_tls, addr).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::env_required;

    // Each test owns a UNIQUE key. `std::env` is process-global and `cargo test`
    // runs these on threads of one process, so tests sharing a variable name
    // would pass or fail depending on scheduling.

    /// The case a naive test omits, and the only one that proves the value is
    /// USED. A test that merely asserts "boot succeeds" passes just as happily
    /// with a compiled-in default still in place behind the read.
    #[test]
    fn a_set_value_is_returned_verbatim() {
        std::env::set_var("YADGAR_TEST_REQUIRED_PRESENT", "0.0.0.0:50051");
        assert_eq!(
            env_required("YADGAR_TEST_REQUIRED_PRESENT").as_deref(),
            Ok("0.0.0.0:50051")
        );
    }

    #[test]
    fn an_absent_knob_refuses_and_names_itself() {
        std::env::remove_var("YADGAR_TEST_REQUIRED_ABSENT");
        let err = env_required("YADGAR_TEST_REQUIRED_ABSENT").unwrap_err();
        assert!(
            err.contains("YADGAR_TEST_REQUIRED_ABSENT"),
            "the refusal must name the knob, got: {err}"
        );
        assert!(err.contains("NOT SET"), "got: {err}");
    }

    /// **THE CASE THAT DISCRIMINATES.** Helm renders an unset value as `""`, so
    /// a nulled chart value arrives here as set-but-empty rather than as absent.
    /// An implementation that collapses the two into one branch is the defect
    /// this estate found three separate times in one week, so the messages are
    /// asserted to DIFFER rather than merely to exist.
    #[test]
    fn an_empty_knob_refuses_with_its_own_message() {
        std::env::set_var("YADGAR_TEST_REQUIRED_EMPTY", "");
        std::env::remove_var("YADGAR_TEST_REQUIRED_EMPTY_ABSENT");
        let empty = env_required("YADGAR_TEST_REQUIRED_EMPTY").unwrap_err();
        let absent = env_required("YADGAR_TEST_REQUIRED_EMPTY_ABSENT").unwrap_err();
        assert!(empty.contains("set but EMPTY"), "got: {empty}");
        assert!(
            empty.replace("YADGAR_TEST_REQUIRED_EMPTY", "K")
                != absent.replace("YADGAR_TEST_REQUIRED_EMPTY_ABSENT", "K"),
            "empty and absent must not share one message"
        );
    }
}
