//! AC1: every successful `SetUserAdmin` advances `iam_user.version` by exactly 1
//! and sets `updated_at`, whether the flag changes or is re-asserted. Against a
//! real MariaDB; `version` and `updated_at` are read by SQL on the pool.

mod db;

use db::*;
use tonic::Request;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

const SEEDED: i64 = 1_000_000_000;

/// Put `updated_at` of `user_id` at a known past instant.
async fn seed_updated_at(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("seed updated_at");
}

async fn version(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT CAST(version AS SIGNED) FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read version")
}

async fn updated_at_secs(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) FROM iam_user WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(svc.pool())
    .await
    .expect("read updated_at")
}

async fn is_admin(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT CAST(is_admin AS SIGNED) FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read is_admin")
}

async fn set_admin(svc: &IamDb, user_id: &str, flag: bool) {
    svc.set_user_admin_as(
        Some(IAM_CALLER),
        Request::new(SetUserAdminRequest {
            user_id: user_id.into(),
            is_admin: flag,
            ..Default::default()
        }),
    )
    .await
    .expect("set_user_admin must succeed");
}

#[tokio::test]
async fn promote_advances_version_and_sets_updated_at() {
    let svc = fresh("iam_db_version_promote").await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    // AC1: version starts at 1.
    assert_eq!(version(&svc, &a).await, 1);

    set_admin(&svc, &a, true).await;

    // AC1: promote advances version to 2, sets updated_at, sets the flag.
    assert_eq!(version(&svc, &a).await, 2);
    assert!(updated_at_secs(&svc, &a).await > SEEDED);
    assert_eq!(is_admin(&svc, &a).await, 1);
}

#[tokio::test]
async fn reassert_same_value_still_advances_version() {
    let svc = fresh("iam_db_version_reassert").await;
    let a = person(&svc, 1).await;
    make_admin(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    // AC1: version reads 2 after the first promote.
    assert_eq!(version(&svc, &a).await, 2);

    set_admin(&svc, &a, true).await;

    // AC1: re-asserting the same flag still adds exactly 1 and sets updated_at.
    assert_eq!(version(&svc, &a).await, 3);
    assert!(updated_at_secs(&svc, &a).await > SEEDED);
    assert_eq!(is_admin(&svc, &a).await, 1);
}

#[tokio::test]
async fn demote_advances_version_and_sets_updated_at() {
    let svc = fresh("iam_db_version_demote").await;
    let a = person(&svc, 1).await;
    make_admin(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    // AC1: version reads 2 before the demote.
    assert_eq!(version(&svc, &a).await, 2);

    set_admin(&svc, &a, false).await;

    // AC1: demote advances version to 3, sets updated_at, clears the flag.
    assert_eq!(version(&svc, &a).await, 3);
    assert!(updated_at_secs(&svc, &a).await > SEEDED);
    assert_eq!(is_admin(&svc, &a).await, 0);
}

#[tokio::test]
async fn two_calls_add_exactly_one_each() {
    let svc = fresh("iam_db_version_twice").await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    assert_eq!(version(&svc, &a).await, 1);

    set_admin(&svc, &a, true).await;
    set_admin(&svc, &a, true).await;

    // AC1: two identical calls, exactly +1 each.
    assert_eq!(version(&svc, &a).await, 3);
}

#[tokio::test]
async fn other_persons_row_is_untouched() {
    let svc = fresh("iam_db_version_other").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    seed_updated_at(&svc, &a).await;
    seed_updated_at(&svc, &b).await;
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(version(&svc, &b).await, 1);

    set_admin(&svc, &a, true).await;

    // AC1: the target moves, the other person does not.
    assert_eq!(version(&svc, &a).await, 2);
    assert_eq!(version(&svc, &b).await, 1);
    assert_eq!(updated_at_secs(&svc, &b).await, SEEDED);
    assert_eq!(is_admin(&svc, &b).await, 0);
}

/// Triangulation and property: a table of flag sequences, each call adds exactly 1.
#[tokio::test]
async fn every_call_in_a_sequence_adds_exactly_one() {
    let svc = fresh("iam_db_version_sequence").await;
    let a = person(&svc, 3).await;
    let b = person(&svc, 4).await;
    seed_updated_at(&svc, &b).await;
    let mut expected = 1;
    assert_eq!(version(&svc, &a).await, expected);

    for flag in [true, false, false, true, true, false] {
        seed_updated_at(&svc, &a).await;
        set_admin(&svc, &a, flag).await;
        expected += 1;
        // AC1: each success adds exactly 1, flag changed or re-asserted.
        assert_eq!(version(&svc, &a).await, expected);
        assert!(updated_at_secs(&svc, &a).await > SEEDED);
        assert_eq!(is_admin(&svc, &a).await, i64::from(flag));
    }
    // AC1: the final literal, 1 + 6 calls.
    assert_eq!(version(&svc, &a).await, 7);
    // AC1: the bystander never moved.
    assert_eq!(version(&svc, &b).await, 1);
    assert_eq!(updated_at_secs(&svc, &b).await, SEEDED);
}
