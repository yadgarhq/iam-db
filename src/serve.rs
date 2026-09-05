//! The transport this service LISTENS on.
//!
//! The mirror image of `iam`'s `upstream` module, and deliberately the same
//! shape: a `<PREFIX>_TLS_*` triple read through an injected lookup, a flag that
//! must be exactly `"1"`, and a misconfiguration that is an error rather than a
//! downgrade. The prefix there names the upstream being dialled; the prefix here
//! is `LISTEN`, which is already the variable naming the address this service
//! binds.
//!
//! # It is OPT-IN, and OFF unless a deployment asks for it
//!
//! With nothing configured this binds exactly the plaintext listener it always
//! has. That is deliberate rather than timid: the certificates do not exist yet,
//! the callers' matching flag ships turned off too, and the cut-over is a
//! separate change that can be reverted on its own.
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

/// The prefix the listener's transport is configured from:
/// `LISTEN_TLS_ENABLED`, `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE`.
///
/// `LISTEN` because that is already the variable naming what is being
/// configured — the address this service binds. A client's prefix names the
/// upstream it dials for the same reason.
pub const LISTEN: &str = "LISTEN";

/// What a deployment got wrong about the listener's transport.
///
/// Every variant is a BOOT FAILURE. None of them has a fallback, and the absence
/// of one is the point: the only fallback available is a plaintext listener, and
/// that is what an operator who set the flag was trying to stop.
#[derive(Debug, thiserror::Error)]
pub enum ServerTlsError {
    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_CERT_FILE names no certificate. TLS was \
         asked for, so this is a deployment mistake rather than a reason to listen in \
         cleartext — and it is NOT the same as leaving TLS off, which is the supported \
         way to run without one. Point {0}_TLS_CERT_FILE at the PEM certificate this \
         service should present."
    )]
    NoCertFile(&'static str),

    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_KEY_FILE names no private key. A \
         certificate without its key serves nothing, and listening in cleartext is not \
         the answer to a half-finished configuration. Point {0}_TLS_KEY_FILE at the PEM \
         private key belonging to the certificate at {0}_TLS_CERT_FILE."
    )]
    NoKeyFile(&'static str),

    #[error(
        "the certificate at {path} could not be read ({source}). TLS was asked for, so \
         this service refuses to start rather than fall back to a cleartext listener. \
         The usual cause is a Secret that was never mounted, so check that the volume \
         exists and that this path is inside it."
    )]
    CertUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "the private key at {path} could not be read ({source}). TLS was asked for, so \
         this service refuses to start rather than fall back to a cleartext listener. \
         The usual cause is a mount that selected the certificate and not the key."
    )]
    KeyUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "the certificate at {path} is not valid PEM ({source}). A file that cannot be \
         decoded cannot be served, and a cleartext listener is not what was asked for."
    )]
    CertUnparsable {
        path: PathBuf,
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the file at {path} holds no certificate. It was read and decoded without \
         error, and it contained no CERTIFICATE section at all — which the PEM reader \
         reports as an empty list rather than as a failure, so it looks like a file \
         that parsed fine. A listener with no certificate is not a listener, and \
         cleartext is not the fallback."
    )]
    CertEmpty { path: PathBuf },

    #[error(
        "the file at {path} holds no usable private key ({source}). Only PKCS#8, PKCS#1 \
         and SEC1 PEM keys are understood. A cleartext listener is not the answer."
    )]
    KeyUnparsable {
        path: PathBuf,
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the certificate at {cert} and the private key at {key} were both decoded and \
         then refused together: {detail}. The usual cause is a key that belongs to a \
         DIFFERENT certificate, which no check of either file on its own can see. This \
         service refuses to start rather than bind a cleartext listener."
    )]
    Rejected {
        cert: PathBuf,
        key: PathBuf,
        detail: String,
    },
}

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

        // Exactly "1". A permissive parse here — "0", "false" and "no" all
        // enabling it — is how a setting meant to be off ends up on, and the
        // reverse mistake is worse: this flag is the revert lever for the
        // cut-over, and a lever that does not move is not one. It is the same
        // rule the client side applies to its own flag.
        if get("TLS_ENABLED").as_deref() != Some("1") {
            if get("TLS_CERT_FILE").is_some() || get("TLS_KEY_FILE").is_some() {
                // NOT an error. Leaving the paths in place while the flag is off
                // is exactly how the cut-over gets reverted, so refusing it would
                // make the lever unusable. It is still worth a line: a deployment
                // that believes it is encrypted and is not should be able to see
                // that from the boot log.
                tracing::warn!(
                    prefix,
                    "a certificate is configured but {prefix}_TLS_ENABLED is not \"1\", so \
                     this service listens in CLEARTEXT"
                );
            }
            return Ok(None);
        }

        Ok(Some(Self {
            cert_file: PathBuf::from(
                get("TLS_CERT_FILE").ok_or(ServerTlsError::NoCertFile(prefix))?,
            ),
            key_file: PathBuf::from(get("TLS_KEY_FILE").ok_or(ServerTlsError::NoKeyFile(prefix))?),
        }))
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
        let cert =
            std::fs::read(&self.cert_file).map_err(|source| ServerTlsError::CertUnreadable {
                path: self.cert_file.clone(),
                source,
            })?;
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
    // `.to_string()` on the way out is NOT decoration. tonic's transport error
    // renders as the three words "transport error" and keeps everything useful
    // in its `source` chain, so a message that did not walk that chain would
    // tell an operator nothing at all.
    Server::builder()
        .tls_config(config)
        .map_err(|e| ServerTlsError::Rejected {
            cert: tls.cert_file.clone(),
            key: tls.key_file.clone(),
            detail: chain(&e),
        })
}

/// Flatten an error and everything underneath it into one sentence.
fn chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        rendered.push_str(": ");
        rendered.push_str(&current.to_string());
        source = current.source();
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values below are SENTINELS: nothing in `serve.rs` could produce
    /// either of them, so a test that sees one saw it travel from the lookup.
    const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/server.pem";
    const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/server-key.pem";

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// THE DEFAULT, and the property the whole change is built around: nothing
    /// configured means the plaintext listener, unchanged.
    #[test]
    fn nothing_configured_means_no_tls() {
        assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&[])).unwrap(), None);
    }

    /// Paths without the flag are the REVERTED state, not an error. The flag is
    /// the lever; leaving the files named is how it gets pulled back.
    #[test]
    fn a_certificate_alone_does_not_enable_tls() {
        let vars = [
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
    }

    /// Anything but "1" is off. A permissive parse is how a setting meant to be
    /// off ends up on — and here also how one meant to be revertible stops
    /// being.
    #[test]
    fn only_exactly_one_enables_tls() {
        for value in ["0", "false", "no", "true", "yes", "", " "] {
            let vars = [
                ("LISTEN_TLS_ENABLED", value),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
                ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ];
            assert_eq!(
                ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(),
                None,
                "{value:?} must not enable TLS"
            );
        }
    }

    /// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
    /// certificate is a deployment mistake, and the answer to it is an error
    /// rather than a plaintext listener.
    #[test]
    fn asking_for_tls_without_a_certificate_is_an_error() {
        for vars in [
            vec![("LISTEN_TLS_ENABLED", "1")],
            vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "")],
            vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "   ")],
        ] {
            assert!(
                matches!(
                    ServerTls::from_lookup(LISTEN, lookup(&vars)),
                    Err(ServerTlsError::NoCertFile("LISTEN"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// And the same for the key, separately — a certificate with no key serves
    /// nothing, and half a configuration is not a reason to serve cleartext.
    #[test]
    fn asking_for_tls_without_a_key_is_an_error() {
        for vars in [
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ],
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
                ("LISTEN_TLS_KEY_FILE", "  "),
            ],
        ] {
            assert!(
                matches!(
                    ServerTls::from_lookup(LISTEN, lookup(&vars)),
                    Err(ServerTlsError::NoKeyFile("LISTEN"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// Both paths reach the settings, proved with names the module could not
    /// have chosen for itself.
    #[test]
    fn both_paths_arrive() {
        let vars = [
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        let tls = ServerTls::from_lookup(LISTEN, lookup(&vars))
            .unwrap()
            .expect("a flag, a certificate and a key enable TLS");
        assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
        assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
    }

    /// The prefix is what selects the variables, so a value meant for something
    /// else cannot configure the listener.
    #[test]
    fn variables_under_another_prefix_do_not_configure_the_listener() {
        let vars = [
            ("TLS_ENABLED", "1"),
            ("SERVER_TLS_ENABLED", "1"),
            ("IAM_DB_TLS_ENABLED", "1"),
            ("TLS_CERT_FILE", SENTINEL_CERT),
        ];
        assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
    }

    /// A CONFIGURATION error and a FILE error are different failures, and only
    /// the first is decided here. `from_lookup` never touches the filesystem, so
    /// a path that does not exist is still a complete configuration — the
    /// refusal comes from `builder`, which is what `tests/serve_tls.rs` proves.
    #[test]
    fn from_lookup_does_not_read_the_files() {
        let vars = [
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert!(ServerTls::from_lookup(LISTEN, lookup(&vars)).is_ok());
    }
}
