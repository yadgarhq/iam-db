//! The transport this service LISTENS on.
//!
//! # One implementation, adopted (ADR-0846, card B-U5)
//!
//! This module used to hold its own `ServerTls`: a `LISTEN_TLS_*` triple read
//! through an injected lookup, file checks that named the bad file, and a
//! builder that never returned a cleartext server for a failed TLS
//! configuration. Six gRPC servers held a near-identical copy, and NONE verified
//! a client certificate. The copy is deleted. What is left here is the half only
//! this repository can state: the PREFIX ([`LISTEN`]) and the CHART KEY
//! ([`CHART_KEY`]) every refusal names, and the one flattener `main` prints a
//! refusal through. Everything else is `yadgar_lifecycle::serve_tls`'s, pinned
//! by tag, and tested there.
//!
//! # The keys, and why none of them has a default
//!
//! | variable | chart value | values |
//! | --- | --- | --- |
//! | `LISTEN_TLS_ENABLED` | `tls.enabled` | exactly `1` or `0` |
//! | `LISTEN_TLS_CERT_FILE`, `LISTEN_TLS_KEY_FILE` | `tls.certSecret` | paths |
//! | `LISTEN_TLS_CLIENT_AUTH` | `tls.clientAuth` | exactly `off`, `optional`, `required` |
//! | `LISTEN_TLS_CLIENT_CA_FILE` | `tls.clientCaSecret` | a path |
//!
//! **The switch and the mode are REQUIRED, and absence refuses to boot**
//! (ADR-0845, extended to the mode by X-ADR-1). The mode is read whether or not
//! TLS is on: `off` is the emergency value, and deleting the variable is a boot
//! refusal, not a way to turn verification off. The chart renders both
//! unconditionally and ships no default for either key.
//!
//! # Configuration is file paths and a flag, never an issuer-specific resource
//!
//! D80. A certificate, a key and a client authority on disk are written by
//! cert-manager in the reference deployment and by a hand-assembled Secret
//! anywhere else, and nothing here can tell the difference — which is the point.
//!
//! # A misconfiguration is an error, never a downgrade
//!
//! A flag that is on with a path that names nothing, a file that cannot be read,
//! a PEM that holds no certificate, a key that does not match its certificate,
//! or a client CA file that holds no authority — all of them stop [`builder`]
//! with a message naming the file. None of them returns a server, because the
//! only server that could be returned is a PLAINTEXT one carrying a TLS
//! configuration that failed.
//!
//! # Client verification
//!
//! `required` makes every caller present a certificate the authority at
//! `LISTEN_TLS_CLIENT_CA_FILE` signed; `optional` verifies a presented one and
//! admits a caller presenting none (a staging step, not a control); `off` asks
//! for nothing. `tests/serve_tls.rs` proves each through this binary's wiring
//! with real handshakes. Which mode each hop runs is a deployment decision made
//! in the values, hop by hop — the chart ships none.
//!
//! # ALPN
//!
//! tonic pushes `h2` onto the acceptor's ALPN list itself, and
//! `tests/serve_tls.rs` proves it by consequence: tonic's client REFUSES a
//! connection that did not negotiate `h2`.
//!
//! # Shutdown and rotation
//!
//! **NOT HERE.** `shutdown`, `drain_within` and the rotation watcher are
//! `yadgar_lifecycle`'s (D19, ADR-0526, ADR-0523). The files this listener
//! reads at boot — the serving certificate, its key and, for a verifying mode,
//! the client CA — are the lifted `ServerTls`'s own watch set, which
//! [`crate::rotate::watch_set`] folds in; `tests/assembly.rs` holds it.

use tonic::transport::Server;
// THE ONE ERROR-CHAIN FLATTENER FOR THE ESTATE (ADR-0591). The lifted error
// keeps tonic's transport error as its `source` rather than flattening it, so
// the binary flattens once, here.
use yadgar_telemetry::diagnose::chain;

pub use yadgar_lifecycle::serve_tls::{ClientAuth, ServeTlsError, ServerTls, LISTEN};

/// The chart block every listener key renders from. Each refusal names
/// `tls.<leaf>` so an operator reading a crash log knows which value to edit.
pub const CHART_KEY: &str = "tls";

/// Read the listener's configuration from the process environment.
///
/// `Ok(None)` is the cleartext listener, and only an EXPLICIT
/// `LISTEN_TLS_ENABLED=0` with `LISTEN_TLS_CLIENT_AUTH=off` produces it.
pub fn from_env() -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_env(LISTEN, CHART_KEY)
}

/// The same decision, over an injected lookup — a seam, because environment
/// variables are process-global and a test that set one would steer every other
/// test in the same binary.
pub fn from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_lookup(LISTEN, CHART_KEY, lookup)
}

/// The server this service listens with, encrypted or not.
///
/// `None` is the plaintext listener; `Some` is TLS — verifying callers as its
/// mode says — or an ERROR, never a plaintext server. Every file is read and
/// the acceptor built HERE, so a bad mount refuses at boot. The caller adds its
/// own services to what comes back, which is what lets `tests/serve_tls.rs`
/// stand the real thing up on a port it chose.
pub fn builder(tls: Option<&ServerTls>) -> Result<Server, ServeTlsError> {
    yadgar_lifecycle::serve_tls::server(tls)
}

/// A listener refusal as the sentence an operator reads, its whole `source`
/// chain included.
///
/// NOT `to_string()`. A mismatched key reaches here as tonic's transport error,
/// whose own `Display` is the two words "transport error"; the reason is one
/// `source()` hop down. `main` prints every listener refusal through this.
pub fn refusal(e: &ServeTlsError) -> String {
    chain(e)
}

#[cfg(test)]
mod tests;
