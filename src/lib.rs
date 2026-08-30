//! `iam-db` — the only writer of the identity store (D4).
//!
//! It holds no business rules. Its job is the boundary: one call is one
//! transaction (D5), identity is enforced here, and the logic service reaches
//! this store only over gRPC — never by opening a connection of its own. It also
//! holds the only argon2 and blind-index dependencies in the fleet (D72):
//! passwords and other personal data leave this boundary already hashed,
//! encrypted, or HMAC'd, and never as plaintext.

#![forbid(unsafe_code)]

pub mod schema;
pub mod service;

/// Generated from the vendored contract (D16, D70).
///
/// The module tree MIRRORS the protobuf package path, and has to: generated
/// cross-package references are emitted as `super::super::common::v1::Meta`, so
/// a flattened tree fails to compile with an error that points at generated code
/// rather than at this file.
pub mod pb {
    pub mod yadgar {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("yadgar.common.v1");
            }
        }
        pub mod iamdb {
            pub mod v1 {
                tonic::include_proto!("yadgar.iamdb.v1");
            }
        }
    }
}
