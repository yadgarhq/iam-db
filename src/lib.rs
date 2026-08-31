//! `iam-db` — the only writer of the identity store (D4).
//!
//! It holds no business rules. Its job is the boundary: one call is one
//! transaction (D5), identity is enforced here, and the logic service reaches
//! this store only over gRPC — never by opening a connection of its own.
//!
//! **It holds NO key material and no cryptographic dependency at all (D72).**
//! There is no argon2, hmac or sha2 in this crate's tree: passwords, usernames
//! and tokens arrive already hashed, HMAC'd or encrypted by `iam`, which holds
//! the keys — see `iam/src/crypto.rs`, which really is the only module in the
//! fleet that has them. This file used to claim the opposite, and the two claims
//! could not both be true; a dump of this database, on its own, is opaque
//! precisely BECAUSE the primitives live on the other side of the boundary.

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
