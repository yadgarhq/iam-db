//! `LookupUser` input validation: no blind index of a length other than 32
//! bytes reaches the store (AC4).
//!
//! NO DATABASE. The service runs on a lazy pool aimed at a [`CountingStore`]:
//! a TCP listener that counts and drops every connection. A refused request
//! must come back `INVALID_ARGUMENT` with the count still zero. A 32-byte
//! index goes on to the store, which is dead, so it comes back `UNAVAILABLE`
//! with the count above zero.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use tonic::{Code, Request};
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
            .connect_lazy(&format!("mysql://gate:gate@127.0.0.1:{}/gate", self.port))
            .expect("a lazy pool");
        IamDb::new(pool)
    }
}

/// One `LookupUser` as the admitted caller; the code of the answer.
async fn lookup(svc: &IamDb, blind_index: Vec<u8>) -> Result<(), Code> {
    let req = LookupUserRequest {
        external_id_blind_index: blind_index,
        ..Default::default()
    };
    svc.lookup_user_as(Some(IAM_CALLER), Request::new(req))
        .await
        .map(|_| ())
        .map_err(|s| s.code())
}

/// Assert `blind_index` is refused `INVALID_ARGUMENT` with no store connection.
async fn assert_refused_before_the_store(blind_index: Vec<u8>) {
    let len = blind_index.len();
    let store = CountingStore::start().await;
    let svc = store.service();
    assert_eq!(
        lookup(&svc, blind_index).await,
        Err(Code::InvalidArgument),
        "a {len}-byte blind index must be INVALID_ARGUMENT"
    );
    assert_eq!(
        store.connections(),
        0,
        "a {len}-byte blind index must reach no store"
    );
}

// AC4: an empty blind index is refused before any store connection.
#[tokio::test]
async fn empty_blind_index_is_invalid_argument_without_a_connection() {
    assert_refused_before_the_store(vec![]).await;
}

// AC4: 31 bytes (one short) is refused before any store connection.
#[tokio::test]
async fn thirty_one_bytes_is_invalid_argument_without_a_connection() {
    assert_refused_before_the_store(vec![5u8; 31]).await;
}

// AC4: 33 bytes (one over) is refused before any store connection.
#[tokio::test]
async fn thirty_three_bytes_is_invalid_argument_without_a_connection() {
    assert_refused_before_the_store(vec![5u8; 33]).await;
}

// AC4: 4096 bytes is refused before any store connection.
#[tokio::test]
async fn four_kib_is_invalid_argument_without_a_connection() {
    assert_refused_before_the_store(vec![5u8; 4096]).await;
}

// AC4 (triangulation): other wrong lengths with other byte values are refused too.
#[tokio::test]
async fn other_wrong_lengths_are_invalid_argument_without_a_connection() {
    assert_refused_before_the_store(vec![0xAB; 1]).await;
    assert_refused_before_the_store(vec![0x00; 16]).await;
    assert_refused_before_the_store(vec![0xFF; 64]).await;
}

// AC4 (property): no length other than 32 reaches the store.
#[tokio::test]
async fn no_length_other_than_32_reaches_the_store() {
    let store = CountingStore::start().await;
    let svc = store.service();
    for len in (0..=96usize).filter(|n| *n != 32) {
        assert_eq!(
            lookup(&svc, vec![7u8; len]).await,
            Err(Code::InvalidArgument),
            "a {len}-byte blind index must be INVALID_ARGUMENT"
        );
    }
    assert_eq!(
        store.connections(),
        0,
        "no wrong length may reach the store"
    );
}

// AC4: a 32-byte index goes on to the store; a dead store answers UNAVAILABLE.
#[tokio::test]
async fn thirty_two_bytes_reaches_the_store_and_a_dead_store_is_unavailable() {
    let store = CountingStore::start().await;
    let svc = store.service();
    assert_eq!(lookup(&svc, vec![1u8; 32]).await, Err(Code::Unavailable));
    assert!(
        store.connections() > 0,
        "a 32-byte blind index must reach the store"
    );
}

// AC4 (triangulation): another 32-byte value also goes on to the store.
#[tokio::test]
async fn another_thirty_two_byte_index_reaches_the_store() {
    let store = CountingStore::start().await;
    let svc = store.service();
    assert_eq!(lookup(&svc, vec![0xEE; 32]).await, Err(Code::Unavailable));
    assert!(
        store.connections() > 0,
        "a 32-byte blind index must reach the store"
    );
}
