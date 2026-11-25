//! ADR-1019 (yaadgaar #337) for `LookupUser`: the RPC bounds its pool acquire
//! by the caller's `grpc-timeout`, and the pool's `acquire_timeout` stays the
//! ceiling.
//!
//! Real MariaDB named by `YADGAR_TEST_DSN` (D69: panics rather than skips).
//! Each case builds a ONE-connection pool on a fresh, migrated database and
//! holds that connection, so the RPC under test can only wait. The blind index
//! is always a well-formed 32 bytes, so the wait is the acquire and nothing
//! else.

mod db;

use std::time::{Duration, Instant};

use sqlx::mysql::MySqlPoolOptions;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::schema;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

/// A migrated store whose pool holds ONE connection and waits at most
/// `acquire_timeout` for it.
async fn one_connection_store(name: &str, acquire_timeout: Duration) -> IamDb {
    let migrated = db::empty(name).await;
    db::migrate(&migrated, &schema::migrations().expect("migrations")).await;
    migrated.close().await;
    let base = db::dsn()
        .rsplit_once('/')
        .expect("dsn has a database component")
        .0
        .to_string();
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(acquire_timeout)
        .connect(&format!("{base}/{name}"))
        .await
        .expect("pool");
    IamDb::new(pool)
}

/// A well-formed lookup of `fill` repeated 32 times, with an optional
/// caller deadline.
fn lookup(fill: u8, timeout: Option<Duration>) -> Request<LookupUserRequest> {
    let mut req = Request::new(LookupUserRequest {
        external_id_blind_index: vec![fill; 32],
        unverified_actor: None,
    });
    if let Some(timeout) = timeout {
        req.set_timeout(timeout);
    }
    req
}

/// Holds the only connection, runs one lookup, and returns its error and how
/// long it took.
async fn lookup_against_a_held_pool(
    name: &str,
    ceiling: Duration,
    fill: u8,
    timeout: Option<Duration>,
) -> (tonic::Status, Duration) {
    let svc = one_connection_store(name, ceiling).await;
    let _held = svc
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");
    let started = Instant::now();
    let refused = svc
        .lookup_user_as(Some(IAM_CALLER), lookup(fill, timeout))
        .await
        .expect_err("no connection was free");
    (refused, started.elapsed())
}

/// **A 300 MS CALLER AGAINST A 5 S CEILING: DEADLINE_EXCEEDED, BEFORE THE
/// CALLER GIVES UP.**
#[tokio::test]
async fn a_300_ms_caller_gets_deadline_exceeded_before_its_deadline() {
    let (refused, took) = lookup_against_a_held_pool(
        "iam_db_lu_dl_300",
        Duration::from_secs(5),
        31,
        Some(Duration::from_millis(300)),
    )
    .await;

    // AC6: a one-connection pool, 5 s ceiling, connection held, 300 ms caller.
    assert_eq!(refused.code(), Code::DeadlineExceeded, "{refused:?}");
    assert!(
        took < Duration::from_millis(300),
        "answered after the caller's deadline: {took:?}"
    );
}

/// **TRIANGULATION: A 200 MS CALLER, A DIFFERENT BLIND INDEX.** The bound
/// follows the caller's deadline, not a fixed 300 ms.
#[tokio::test]
async fn a_200_ms_caller_gets_deadline_exceeded_before_its_deadline() {
    let (refused, took) = lookup_against_a_held_pool(
        "iam_db_lu_dl_200",
        Duration::from_secs(5),
        7,
        Some(Duration::from_millis(200)),
    )
    .await;

    // AC6: a one-connection pool, 5 s ceiling, connection held, 200 ms caller.
    assert_eq!(refused.code(), Code::DeadlineExceeded, "{refused:?}");
    assert!(
        took < Duration::from_millis(200),
        "answered after the caller's deadline: {took:?}"
    );
}

/// **NO DEADLINE: THE CEILING STILL HOLDS.** A caller with no `grpc-timeout`
/// waits the pool's own `acquire_timeout` and gets UNAVAILABLE.
#[tokio::test]
async fn without_a_deadline_the_acquire_fails_at_the_configured_ceiling() {
    let ceiling = Duration::from_millis(500);
    let (refused, took) =
        lookup_against_a_held_pool("iam_db_lu_dl_ceiling", ceiling, 31, None).await;

    // AC6: acquire_timeout 500 ms, connection held, no timeout.
    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
    assert!(took >= ceiling, "gave up before the ceiling: {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}

/// **TRIANGULATION: A SHORTER CEILING, A DIFFERENT BLIND INDEX.** The wait
/// ends at the configured ceiling, not at a fixed 500 ms.
#[tokio::test]
async fn a_shorter_ceiling_with_no_deadline_ends_at_that_ceiling() {
    let ceiling = Duration::from_millis(300);
    let (refused, took) =
        lookup_against_a_held_pool("iam_db_lu_dl_ceiling_short", ceiling, 7, None).await;

    // AC6: the pool's acquire_timeout stays the ceiling.
    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
    assert!(took >= ceiling, "gave up before the ceiling: {took:?}");
    assert!(took < Duration::from_secs(2), "took {took:?}");
}

/// **A DEADLINE LONGER THAN THE CEILING CHANGES NOTHING.** A 30 s caller
/// against a 500 ms ceiling still gets UNAVAILABLE at 500 ms.
#[tokio::test]
async fn a_deadline_longer_than_the_ceiling_does_not_raise_it() {
    let ceiling = Duration::from_millis(500);
    let (refused, took) = lookup_against_a_held_pool(
        "iam_db_lu_dl_no_raise",
        ceiling,
        31,
        Some(Duration::from_secs(30)),
    )
    .await;

    // AC6: acquire_timeout 500 ms, connection held, 30 s caller.
    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
    assert!(took >= ceiling, "took {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}
