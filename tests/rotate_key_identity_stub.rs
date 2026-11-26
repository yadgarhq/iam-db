//! `RotateKeyIdentity` is a stub until yaadgaar 168 builds it: for the iam
//! caller it answers `UNIMPLEMENTED` and opens no store connection.
//!
//! **NO DATABASE, AND THAT IS THE ZERO-CALL ASSERTION.** The service runs on a
//! lazy pool aimed at a [`CountingStore`]: a TCP listener that counts every
//! connection and answers none. A stub that acquired a connection would leave
//! a mark; one that read the request would answer `INVALID_ARGUMENT` for the
//! empty default request instead of `UNIMPLEMENTED`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::common::v1::Idempotency;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

/// A listener standing where the database would be. It accepts, counts and
/// drops every connection.
struct CountingStore {
    port: u16,
    connections: Arc<AtomicUsize>,
}

impl CountingStore {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a local port");
        let port = listener.local_addr().expect("a local address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// The service under test, on a LAZY pool aimed at this listener.
    fn service(&self) -> IamDb {
        let pool = MySqlPoolOptions::new()
            .acquire_timeout(Duration::from_millis(300))
            .connect_lazy(&format!("mysql://stub:stub@127.0.0.1:{}/stub", self.port))
            .expect("a lazy pool");
        IamDb::new(pool)
    }
}

#[tokio::test]
async fn default_request_is_unimplemented_and_opens_no_connection() {
    // AC7: a default request answers UNIMPLEMENTED (not INVALID_ARGUMENT), zero connections.
    let store = CountingStore::start().await;
    let svc = store.service();

    let out = svc
        .rotate_key_identity_as(
            Some(IAM_CALLER),
            Request::new(RotateKeyIdentityRequest::default()),
        )
        .await;

    let status = out.expect_err("the stub never succeeds");
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(store.connections(), 0);
}

#[tokio::test]
async fn well_formed_request_with_expect_stored_is_unimplemented_and_opens_no_connection() {
    // AC7: a key "k-1" and an expect_stored marker still answer UNIMPLEMENTED, zero connections.
    let store = CountingStore::start().await;
    let svc = store.service();

    let out = svc
        .rotate_key_identity_as(
            Some(IAM_CALLER),
            Request::new(RotateKeyIdentityRequest {
                idempotency: Some(Idempotency { key: "k-1".into() }),
                expect_marker: Some(rotate_key_identity_request::ExpectMarker::ExpectStored(
                    KeyIdentityMarker {
                        derivation_version: 1,
                        key_fingerprint: vec![0xAB; 32],
                    },
                )),
                new_marker: Some(KeyIdentityMarker {
                    derivation_version: 1,
                    key_fingerprint: vec![0xCD; 32],
                }),
                rows: Vec::new(),
            }),
        )
        .await;

    let status = out.expect_err("the stub never succeeds");
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(store.connections(), 0);
}

#[tokio::test]
async fn expect_absent_request_under_another_key_is_unimplemented_with_no_connection() {
    // AC7: triangulation, a different key and the expect_absent arm answer the same way.
    let store = CountingStore::start().await;
    let svc = store.service();

    let out = svc
        .rotate_key_identity_as(
            Some(IAM_CALLER),
            Request::new(RotateKeyIdentityRequest {
                idempotency: Some(Idempotency { key: "k-2".into() }),
                expect_marker: Some(rotate_key_identity_request::ExpectMarker::ExpectAbsent(
                    NoKeyIdentityMarker {},
                )),
                new_marker: Some(KeyIdentityMarker {
                    derivation_version: 2,
                    key_fingerprint: vec![0x01; 32],
                }),
                rows: Vec::new(),
            }),
        )
        .await;

    let status = out.expect_err("the stub never succeeds");
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(store.connections(), 0);
}
