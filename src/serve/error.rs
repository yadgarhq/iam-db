//! What a deployment got wrong about the listener's transport — the error half
//! of [`crate::serve`], split out under the 500-line ceiling.

use std::path::PathBuf;

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
