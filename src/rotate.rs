//! WHICH FILES THIS PROCESS READ AT BOOT, and therefore which ones ending the
//! process is the correct response to a change in (ADR-0523).
//!
//! **THE WATCHER ITSELF IS NOT HERE.** `Schedule`, `Inputs`, `File`, `Presented`
//! and `watch` are [`yadgar_lifecycle::rotate`]'s, pinned by tag like every
//! in-org crate. What lives in this file is the only half that is this
//! repository's own: the [`Material`] implementations naming this service's
//! files, and [`watch_set`], the one expression that lists them.
//!
//! # Why this service needed it, and why it did not have it
//!
//! `iam-db` took `yadgar-lifecycle` with `default-features = false`, which
//! compiles the whole `rotate` module out. The manifest said so and gave a
//! reason: nothing here ends the serving future on its own, so the drain budget
//! would have been a number bounding nothing. That was true of the drain and
//! never true of the certificate — `serve.rs` said as much in its own doc
//! comment, and dated the reasoning rather than settling it.
//!
//! **THE DATE WAS 2026-12-01.** `iam-db-tls` expires then. cert-manager rewrites
//! the Secret at renewal and kubelet swaps the mount, but a process that read
//! its leaf once at boot goes on presenting the OLD one until something restarts
//! it — so after that date every internal mTLS handshake into this service
//! fails, and until then only an ordinary release rescues it by accident.
//!
//! # What is watched, and why it is more than the certificate
//!
//! ADR-0523's rule is about PROVENANCE rather than payload: a file this process
//! read once, out of a mount that can be rewritten underneath it, is watched
//! whatever the bytes mean. Four materials:
//!
//! - the listener's certificate AND its private key — both halves, or the pair
//!   rotates half-watched;
//! - **the database password**, which is not a certificate and is the member
//!   with no other signal at all. It is read once by
//!   `CredentialSource::SecretFile` and baked into a pool that lives as long as
//!   the process, so a rotated Secret breaks nothing until the next reconnect —
//!   which may be hours later, in a pod nobody is looking at, as a wave of
//!   authentication failures with no cause attached;
//! - the CA the engine's own certificate is verified against, when a deployment
//!   names one;
//! - **the mounted configuration document (step 2a of the rotation-knob
//!   cut-over, ADR-0569, ADR-0570)** — `shared/shared.yaml`, rendered by
//!   `yadgarhq/config` into the `shared` ConfigMap. It is the source the
//!   rotation schedule itself now comes from, so an operator editing it
//!   restarts this pod exactly as editing a CA bundle would.
//!
//! # The property every change here must keep
//!
//! **If the watcher dies you get today's behaviour, never worse.** A file that
//! cannot be read is not a changed one; no material at all means no watch.
//! Nothing may end the watch over a state it is merely unsure about, because
//! ending it exits the process. The crate holds that property and the tests for
//! it; `tests/assembly.rs` holds the claim only this repository can make — that
//! an `iam-db` configured this way reads exactly these files.

use std::path::Path;

pub use yadgar_lifecycle::rotate::{
    watch, Configuration, File, Inputs, Material, Presented, Schedule, ScheduleError,
    CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

use crate::serve::ServerTls;
use crate::service::SERVICE;

/// The listener's certificate and the private key belonging to it.
///
/// **Both halves, or the pair rotates half-watched.** kubelet swaps a mount
/// atomically, so a set holding only the certificate still fires on an ordinary
/// rotation — but a deployment that rewrites the key alone would pass unnoticed.
impl Material for ServerTls {
    fn files(&self) -> Vec<File<'_>> {
        vec![
            File::certificate(Presented::Serving, self.cert_file()),
            File::read(self.key_file()),
        ]
    }
}

/// Everything this deployment read at boot, hashed as it was read.
///
/// **A CLEARTEXT `iam-db` STILL WATCHES SOMETHING**, which is why the password
/// is a `&Path` rather than an `Option`: the listener's TLS is opt-in and off by
/// default, but the database password is read on every boot there is. A watch
/// set that admitted only TLS files would be EMPTY in the deployment this estate
/// actually runs today, and an empty set means no watch at all.
///
/// **THE LIST IS THE ASSERTION.** It used to be a run of builder calls in
/// `main.rs`, in every service that had a watcher, where no test could reach
/// them — so deleting one compiled, passed everything, and shipped a process
/// that would never notice that file rotating. `Inputs::of` makes the set a
/// VALUE, and a value is something `tests/assembly.rs` can call the SAME
/// function for.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS THE FOURTH MEMBER (step 2a).**
/// `config` is `shared/shared.yaml`, mounted from `yadgarhq/config`'s `shared`
/// ConfigMap, and it is a [`Material`] like the other three: `Configuration`
/// implements the trait by returning the one file it read its schedule from
/// (`yadgar_lifecycle::rotate::Configuration::files`), so folding it in here
/// joins the document to the ADR-0523 watch set through the exact same
/// `Inputs::of` path the certificate, the password and the CA already take. It
/// is folded LAST, and required rather than `Option`-wrapped — unlike the
/// listener and the CA, every deployment mounts it and reads a schedule from
/// it, so there is no configuration under which it is absent.
///
/// Called from `main.rs` INSIDE boot, beside the code that read these files.
/// Collecting paths and reading them when the watcher first polls would put the
/// rest of boot inside a window where a kubelet swap quietly becomes the
/// baseline, and the real rotation would never be noticed.
pub fn watch_set(
    listener: Option<&ServerTls>,
    db_password: &Path,
    db_ssl_ca: Option<&Path>,
    config: &Configuration,
) -> Inputs {
    Inputs::of(SERVICE, &[&listener, &db_password, &db_ssl_ca, config])
}
