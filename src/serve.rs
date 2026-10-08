//! The transport this service LISTENS on.
//!
//! The mirror image of `iam`'s `upstream` module, and deliberately the same
//! shape: a `<PREFIX>_TLS_*` triple read through an injected lookup, a flag that
//! must be exactly `"1"`, and a misconfiguration that is an error rather than a
//! downgrade. The prefix there names the upstream being dialled; the prefix here
//! is `LISTEN`, which is already the variable naming the address this service
//! binds.
//!
//! # It is OPT-IN, and the flag must say so (ADR-0845)
//!
//! Set `LISTEN_TLS_ENABLED=0` and this binds exactly the plaintext listener it
//! always has. That is deliberate rather than timid: the certificates do not
//! exist yet, the callers' matching flag ships turned off too, and the
//! cut-over is a separate change that can be reverted on its own.
//!
//! **ABSENCE IS NO LONGER "OFF".** It used to be: an unset `LISTEN_TLS_ENABLED`
//! and an explicit `"0"` both bound the plaintext listener, so a chart that
//! failed to render the flag at all — a template bug, a values file that
//! dropped the key — produced the exact same cleartext listener as a
//! deployment that chose it on purpose, with nothing to tell the two apart.
//! H1 of the ADR-0705 census makes that a refusal: `LISTEN_TLS_ENABLED` must
//! be exactly `"1"` or `"0"`, stated. The chart renders it unconditionally as
//! `tls.enabled` and ships no default for that key, so the same rule holds at
//! the values file too.
//!
//! # Configuration is file paths and a flag, never an issuer-specific resource
//!
//! D80. A certificate and a private key on disk are written by cert-manager in
//! the reference deployment and by a hand-assembled Secret anywhere else, and
//! this module cannot tell the difference — which is the point. Nothing here
//! names an issuer, a mesh or an ingress implementation.
//!
//! # A misconfiguration is an error, never a downgrade
//!
//! **This is the entire defect the change exists to remove.** A flag that is on
//! with a path that names nothing, a file that cannot be read, a PEM that
//! decodes to no certificate, or a key that does not match its certificate — all
//! of them stop [`builder`] with a message naming the file. None of them returns
//! a server, because the only server that could be returned is a PLAINTEXT one
//! carrying a TLS configuration that failed, and an operator who asked for
//! encryption would then have an unencrypted listener nobody could see was
//! unencrypted.
//!
//! # ALPN
//!
//! A TLS gRPC listener that does not negotiate `h2` answers nothing useful.
//! tonic pushes `h2` onto the acceptor's ALPN list itself — see
//! `tonic/src/transport/server/service/tls.rs` — so this module adds nothing,
//! and `tests/serve_tls.rs` proves it rather than assuming it: tonic's own
//! client REFUSES a connection that did not negotiate `h2`, so a gRPC request
//! that crosses the transport is the proof.
//!
//! # Shutdown
//!
//! **NOT HERE ANY MORE.** `shutdown` is `yadgar_lifecycle::shutdown`, and the
//! reason it left is the reason it was here: which signals end this process is
//! a decision that fails silently. It stood in five copies across this estate —
//! `iam`, `task`, `gateway`, `task-db` and this one — and the same wrong answer,
//! SIGINT alone, had to be corrected in four binaries separately. One idea
//! spelled five ways is its own defect, so it is spelled once (D19, ADR-0526).
//! `main` still calls it before it spawns the server, and `tests/shutdown.rs`
//! still proves that a real SIGTERM drains this service's real listener. What
//! moved is WHERE the handlers are installed, never WHEN: the crate's
//! `shutdown` is a `fn` returning a future, exactly as this one was.
//!
//! **THIS SERVICE NOW TAKES ALL THREE UNITS, AND THE DATE THIS SECTION SET IS
//! WHY.** It used to take `shutdown` and nothing else, on the argument that
//! nothing here ended the serving future on its own, so `DRAIN_BUDGET` and
//! `drain_within` would have bounded a drain no signal began. That argument was
//! sound about the drain and it carried its own expiry — ADR-0523 requires an
//! exit-on-rotation watcher in every process that reads security material once
//! at boot, and this one does: it reads its serving certificate and its key
//! right here, when the listener is built.
//!
//! **THE EXPIRY WAS 2026-12-01T19:35:07Z**, which is when `iam-db-tls` runs out.
//! cert-manager rewrites the Secret at renewal and kubelet swaps the mount, and
//! a process that read the leaf once goes on presenting the OLD one until
//! something restarts it. Until this change only an ordinary release rescued it,
//! by accident.
//!
//! So the watcher is here, and it brought the budget with it in the same change,
//! exactly as this section said it must: tokio never unregisters a libc signal
//! handler, so once a non-signal arm wins the `select!` a later SIGTERM is
//! swallowed and only SIGKILL remains. `main` selects on
//! `yadgar_lifecycle::shutdown` and `rotate::watch`, and `drain_within` bounds
//! whichever wins. The three are one decision and they landed as one.
//!
//! **WHICH FILES ARE WATCHED IS [`crate::rotate`]'s**, not this module's — the
//! listener's certificate and key are two of the three, and the database
//! password and the engine's CA are watched on the same ADR-0523 ground.
//! `tests/assembly.rs` is what a member deleted from that list dies against.
//!
//! # What is deliberately NOT here
//!
//! **Mutual TLS.** Verifying a CLIENT certificate is `ServerTlsConfig`'s
//! `client_ca_root` plus one more path, and the seam is left open by taking a
//! struct rather than a list of arguments — the same way `yadgar_dial`'s
//! `TlsOptions` leaves room for `ClientTlsConfig::identity`. It is a later
//! decision, not an omission from this one.

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tonic::transport::{Identity, Server, ServerTlsConfig};
// THE ONE ERROR-CHAIN FLATTENER FOR THE ESTATE (ADR-0591). The body that used to
// sit below `builder` in this file was one of five — `iam`, `task`, `task-db`,
// `project-db` and here — byte-identical apart from local names, under TWO
// names: `chain` here and in `iam`, `describe` in the other three. It is deleted
// rather than left beside the shared one, because a consolidation that adds a
// sixth copy without removing the five is worse than none. The call site is
// unchanged: the published signature is the PERMISSIVE `&dyn Error`, which
// accepts everything the `&(dyn Error + 'static)` written here did.
use yadgar_telemetry::diagnose::chain;

mod error;
pub use error::ServerTlsError;

/// The prefix the listener's transport is configured from:
/// `LISTEN_TLS_ENABLED`, `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE`.
///
/// `LISTEN` because that is already the variable naming what is being
/// configured — the address this service binds. A client's prefix names the
/// upstream it dials for the same reason.
pub const LISTEN: &str = "LISTEN";

/// The certificate and key this service presents to its callers.
///
/// **Two paths, and nothing else.** No issuer, no Secret name, no namespace —
/// see the module documentation for why D80 makes that the whole of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTls {
    cert_file: PathBuf,
    key_file: PathBuf,
}

impl ServerTls {
    /// Read the listener's transport configuration from the environment.
    ///
    /// `Ok(None)` is the ordinary answer today: TLS is opt-in, so an
    /// unconfigured deployment binds the plaintext listener exactly as before.
    pub fn from_env(prefix: &'static str) -> Result<Option<Self>, ServerTlsError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between an encrypted listener and a cleartext one
    /// could not be tested at all without this.
    pub fn from_lookup(
        prefix: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ServerTlsError> {
        let get = |suffix: &str| {
            lookup(&format!("{prefix}_{suffix}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        // H1 (ADR-0705 census) / ADR-0845: EXACTLY "1" or "0", and nothing
        // else — ABSENT OR EMPTY INCLUDED. A permissive parse — "0", "false"
        // and "no" all enabling it, or absence quietly meaning "0" — is how a
        // setting meant to be off ends up on, or how a chart that failed to
        // render the flag at all binds a cleartext listener indistinguishable
        // from one chosen on purpose. It is the same rule the client side
        // applies to its own flag, now widened to refuse the absent case too.
        //
        // RAW, NOT `get`: absent and set-but-empty must produce DIFFERENT
        // sentences (`EnabledNotSet` vs `EnabledEmpty`, the same discrimination
        // `boot::env_required` makes for every DB_* knob), and `get`'s own
        // trim-and-empty-filter collapses that distinction into one `None`.
        let raw_enabled = lookup(&format!("{prefix}_TLS_ENABLED")).map(|v| v.trim().to_string());
        match raw_enabled.as_deref() {
            Some("1") => Ok(Some(Self {
                cert_file: PathBuf::from(
                    get("TLS_CERT_FILE").ok_or(ServerTlsError::NoCertFile(prefix))?,
                ),
                key_file: PathBuf::from(
                    get("TLS_KEY_FILE").ok_or(ServerTlsError::NoKeyFile(prefix))?,
                ),
            })),
            Some("0") => {
                if get("TLS_CERT_FILE").is_some() || get("TLS_KEY_FILE").is_some() {
                    // NOT an error. Leaving the paths in place while the flag is
                    // off is exactly how the cut-over gets reverted, so refusing
                    // it would make the lever unusable. It is still worth a
                    // line: a deployment that believes it is encrypted and is
                    // not should be able to see that from the boot log.
                    tracing::warn!(
                        prefix,
                        "a certificate is configured but {prefix}_TLS_ENABLED is not \"1\", \
                         so this service listens in CLEARTEXT"
                    );
                }
                Ok(None)
            }
            // SET BUT EMPTY — Helm renders a nulled chart value as "", which
            // is a DIFFERENT state from absence and gets its own message.
            Some("") => Err(ServerTlsError::EnabledEmpty(prefix)),
            // Present, non-empty, and neither "1" nor "0" — "true", "false",
            // "yes", anything.
            Some(other) => Err(ServerTlsError::EnabledInvalid {
                prefix,
                value: other.to_string(),
            }),
            // ABSENT. Used to mean cleartext, the same as an explicit "0";
            // H1 makes it a refusal instead, because an operator who meant
            // to turn TLS off has "0" to write, and a value that never
            // arrived is not that.
            None => Err(ServerTlsError::EnabledNotSet(prefix)),
        }
    }

    /// The PEM certificate this service presents.
    pub fn cert_file(&self) -> &Path {
        &self.cert_file
    }

    /// The PEM private key belonging to that certificate.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Read and CHECK both files, and build the acceptor's settings.
    ///
    /// Everything that can be wrong is wrong HERE, once, before a listener
    /// exists — so a bad path is a startup error naming a file rather than a
    /// handshake failure much later, and never a quiet downgrade.
    fn tls_config(&self) -> Result<ServerTlsConfig, ServerTlsError> {
        // ADR-0523-WATCHED: ServerTls
        let cert =
            std::fs::read(&self.cert_file).map_err(|source| ServerTlsError::CertUnreadable {
                path: self.cert_file.clone(),
                source,
            })?;
        // ADR-0523-WATCHED: ServerTls
        let key =
            std::fs::read(&self.key_file).map_err(|source| ServerTlsError::KeyUnreadable {
                path: self.key_file.clone(),
                source,
            })?;

        // THE ASSERTION THIS FUNCTION EXISTS FOR. The PEM reader yields nothing
        // — rather than an error — for input that contains no certificate
        // section, so "parsed successfully" can mean "parsed nothing". Left
        // unchecked it surfaces from inside the acceptor as a sentence about a
        // certificate chain, naming neither file.
        let certificates = CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ServerTlsError::CertUnparsable {
                path: self.cert_file.clone(),
                source,
            })?;
        if certificates.is_empty() {
            return Err(ServerTlsError::CertEmpty {
                path: self.cert_file.clone(),
            });
        }

        // Decoded and DISCARDED, deliberately: the point is to find out which
        // file is wrong while both paths are still in hand. tonic decodes them
        // again from the `Identity` below, and its error names neither.
        PrivateKeyDer::from_pem_slice(&key).map_err(|source| ServerTlsError::KeyUnparsable {
            path: self.key_file.clone(),
            source,
        })?;

        Ok(ServerTlsConfig::new().identity(Identity::from_pem(&cert, &key)))
    }
}

/// The server this service listens with, encrypted or not.
///
/// **`tls` decides the transport, and there is no third state.** `None` is the
/// plaintext listener this service has always bound; `Some` is the same server
/// with the connection encrypted, and it returns an ERROR rather than a
/// plaintext server if the certificate or key is unusable.
///
/// The caller adds its own services to what comes back. Returning the builder
/// rather than serving from here is what lets `tests/serve_tls.rs` stand the
/// real thing up on a port it chose.
pub fn builder(tls: Option<&ServerTls>) -> Result<Server, ServerTlsError> {
    let Some(tls) = tls else {
        return Ok(Server::builder());
    };

    let config = tls.tls_config()?;
    // The acceptor is built HERE, eagerly, and that is why a mismatched key is a
    // boot failure: `tls_config` checks each file on its own, and only rustls
    // comparing the certificate's public key against the private one catches a
    // pair that is individually valid and jointly wrong.
    //
    // `chain` on the way out is NOT decoration, and it is the SHARED one
    // (ADR-0591). tonic's transport error renders as the two words "transport
    // error" and keeps everything useful in its `source` chain, so a message
    // that did not walk that chain would tell an operator nothing at all.
    Server::builder()
        .tls_config(config)
        .map_err(|e| ServerTlsError::Rejected {
            cert: tls.cert_file.clone(),
            key: tls.key_file.clone(),
            detail: chain(&e),
        })
}

#[cfg(test)]
mod tests;
