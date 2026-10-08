//! THE EXIT CHAIN, held at the binary (ledger 748): the two ways a running
//! `iam-db` is asked to stop both end in a drain and exit code 0. COPIED FROM
//! `yadgarhq/task`'s own `tests/exit_chain.rs` at `origin/main` (the task
//! canary, #70), NOT RE-DERIVED — see `tests/support/mod.rs`'s header for
//! what differs and why.
//!
//! The library tests prove the parts — `yadgar-lifecycle` that a signal
//! resolves `shutdown()` and that a changed file resolves `rotate::watch`,
//! `tests/assembly.rs` that the watch set holds the right files,
//! `tests/shutdown.rs` that a real SIGTERM drains the real listener this
//! repository builds. None of them can see `main.rs`'s `run()` and
//! `serve_until_drained` wiring those futures into the `select!` that stops
//! the server, OR that the binary reaches that `select!` at all — this
//! repository's `main` already probes the engine, migrates, and returns
//! `ExitCode` rather than a `Result` `main` prints with Debug (ledger 1257's
//! own card: "the `-db` mains are already `-> ExitCode`"), so what 748 adds
//! here is the harness that proves the SELECT, not the exit type. Only
//! running the binary can tell.
//!
//! **What each case kills, measured by mutating `src/main.rs`:**
//!
//! - Delete the `signals` binding AND its `select!` arm: no handler is ever
//!   installed, SIGTERM takes the kernel default, the status carries signal
//!   15 and no code, and [`sigterm_drains_and_exits_zero`]'s `Some(0)` is
//!   red.
//! - Delete the arm ONLY: the handler is installed when `shutdown()` is
//!   CALLED and tokio never removes it, so SIGTERM is swallowed and the
//!   server keeps serving. The exit wait's deadline fires; the test kills
//!   the child and fails.
//! - Delete the rotation arm: nothing polls the watcher, so
//!   [`a_rewritten_shared_document_drains_and_exits_zero`] never sees the
//!   CHANGED line and fails on its deadline.
//!
//! A failing drain is NOT one of these cases. `Drain::Overran` exits 0 by
//! design and `Drain::Finished(Err)` exits 1 under either shape of `main`, so
//! nothing about the drain's own outcome moves the code this file asserts.
//!
//! See `tests/support/mod.rs` for why each run is in its own mount namespace,
//! and for why this harness creates a fresh database on the real engine
//! named by `YADGAR_TEST_DSN` before every boot.

mod support;

use std::os::unix::process::ExitStatusExt;

use support::{describe, Booted, MARGIN, POLL, SPLAY_MAX};
use yadgar_lifecycle::DRAIN_BUDGET;

/// Case (i): kubelet's SIGTERM ends the process with 0.
///
/// The deadline is the drain's whole budget plus a margin, not less: an
/// `Overran` drain is a legal exit 0 that arrives one budget after the signal.
#[test]
fn sigterm_drains_and_exits_zero() {
    let mut iam_db = Booted::start();
    iam_db.wait_until_listening();

    iam_db.terminate();
    let status = iam_db.wait_for_exit("after SIGTERM", DRAIN_BUDGET + MARGIN);

    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must drain and exit 0 ({}); signal 15 here means no handler was \
         installed",
        describe(Some(status))
    );
    assert_eq!(status.signal(), None);
    assert!(
        iam_db
            .seen()
            .iter()
            .any(|l| l.contains("draining in-flight requests") && l.contains("SIGTERM")),
        "the drain must name the signal that started it"
    );
}

/// Case (ii): a rewritten watched file ends the process with 0.
///
/// `shared.yaml` is the one watched file a cleartext deployment has. The
/// rewrite keeps the schedule valid and changes the bytes, which is all the
/// watcher compares.
#[test]
fn a_rewritten_shared_document_drains_and_exits_zero() {
    let mut iam_db = Booted::start();
    iam_db.wait_until_listening();

    iam_db.rewrite_shared(&format!(
        "{}# rotated by tests/exit_chain.rs\n",
        support::FIXTURE
    ));
    // One poll to notice, the splay, then the drain's whole budget.
    let deadline = POLL + SPLAY_MAX + DRAIN_BUDGET + MARGIN;
    let started = std::time::Instant::now();

    let changed = iam_db.wait_for_line("the watcher's CHANGED line", deadline, |l| {
        l.contains("have CHANGED on disk")
    });
    assert!(
        changed.contains("shared.yaml"),
        "the CHANGED line must name the file that changed: {changed}"
    );
    // TLS is off, and there is no client-auth leaf yet (B-U5E leaves
    // `tls.clientAuth` unenforced), so all four fingerprints are reported,
    // and reported as `none`.
    for field in [
        "\"serving_before\":\"none\"",
        "\"serving_after\":\"none\"",
        "\"client_before\":\"none\"",
        "\"client_after\":\"none\"",
    ] {
        assert!(
            changed.contains(field),
            "the CHANGED line must carry {field}: {changed}"
        );
    }

    let status = iam_db.wait_for_exit(
        "after the watched file changed",
        deadline.saturating_sub(started.elapsed()),
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a rotation is not an error; it must drain and exit 0 ({})",
        describe(Some(status))
    );
}
