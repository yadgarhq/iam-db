//! D8 guard: a REFUSED SetUserAdmin adds nothing to `iam_user.version`.
//!
//! `Meta.version` is "incremented ... on every successful update"
//! (`common.proto:282-283`), so a refusal adds 0. These tests pass on the code
//! before the version bump and must keep passing after it: the bump must ride
//! the `deleted_at IS NULL` match, not run for a refused call.
//!
//! Spec: `src/service/policy.rs:51` (a mistyped user id must not report
//! success), `:36-38` (no promotion of a soft-deleted person), `:63-65`
//! (NOT_FOUND for an unknown id or a soft-deleted person).
//!
//! `updated_at` is seeded with `FROM_UNIXTIME(1000000000)` and compared with
//! `UNIX_TIMESTAMP(updated_at)`, which is independent of the session zone.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

const SEED: i64 = 1_000_000_000;

async fn set_admin(svc: &IamDb, user_id: &str, is_admin: bool) -> Result<(), tonic::Status> {
    svc.set_user_admin_as(
        Some(IAM_CALLER),
        Request::new(SetUserAdminRequest {
            user_id: user_id.into(),
            is_admin,
            ..Default::default()
        }),
    )
    .await
    .map(|_| ())
}

async fn seed_updated_at(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("seed updated_at");
}

async fn soft_delete(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");
}

async fn version(svc: &IamDb, user_id: &str) -> u64 {
    sqlx::query_scalar("SELECT version FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read version")
}

async fn updated_at(svc: &IamDb, user_id: &str) -> i64 {
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

async fn rows_for(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("count rows")
}

async fn unknown_id_refused(db_name: &str, ghost: &str, flag: bool) {
    let svc = fresh(db_name).await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    assert_eq!(version(&svc, &a).await, 1);

    let err = set_admin(&svc, ghost, flag)
        .await
        .expect_err("an unknown id must not report success");

    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(updated_at(&svc, &a).await, SEED);
    assert_eq!(rows_for(&svc, ghost).await, 0);
}

#[tokio::test]
async fn unknown_user_is_not_found_and_writes_nothing() {
    // AC3: SetUserAdmin for an id with no row answers NOT_FOUND, writes no row.
    unknown_id_refused(
        "iam_db_vguard_unknown",
        "yadgar:user:01a1b2dd-0000-7000-8000-000000000000",
        true,
    )
    .await;
}

#[tokio::test]
async fn another_unknown_user_with_the_flag_cleared_is_not_found_too() {
    // AC3: triangulation, a different unknown id and the demote direction.
    unknown_id_refused(
        "iam_db_vguard_unknown_demote",
        "yadgar:user:01a1b2ee-0000-7000-8000-000000000001",
        false,
    )
    .await;
}

#[tokio::test]
async fn soft_deleted_person_is_not_found_and_not_promoted() {
    // AC3: a soft-deleted person is refused, version, updated_at, is_admin stay.
    let svc = fresh("iam_db_vguard_deleted").await;
    let a = person(&svc, 1).await;
    soft_delete(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version(&svc, &a).await;
    assert_eq!(v0, 1);

    let err = set_admin(&svc, &a, true)
        .await
        .expect_err("a soft-deleted person must not be promoted");

    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(version(&svc, &a).await, v0);
    assert_eq!(updated_at(&svc, &a).await, SEED);
    assert_eq!(is_admin(&svc, &a).await, 0);
}

#[tokio::test]
async fn soft_deleted_admin_is_not_found_and_not_demoted() {
    // AC3: triangulation, the demote direction on a person who held the flag;
    // another live person is untouched.
    let svc = fresh("iam_db_vguard_deleted_admin").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    make_admin(&svc, &a).await;
    soft_delete(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    seed_updated_at(&svc, &b).await;
    let v_a = version(&svc, &a).await;
    let v_b = version(&svc, &b).await;

    let err = set_admin(&svc, &a, false)
        .await
        .expect_err("a soft-deleted person is not live");

    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(version(&svc, &a).await, v_a);
    assert_eq!(updated_at(&svc, &a).await, SEED);
    assert_eq!(is_admin(&svc, &a).await, 1);
    assert_eq!(version(&svc, &b).await, v_b);
    assert_eq!(updated_at(&svc, &b).await, SEED);
}
