//! D8 guard (`common.proto:282-283`): `iam_user.version` is incremented only on
//! a SUCCESSFUL update. A refused credential-epoch operation writes nothing to
//! `iam_user`, so it leaves `version` and `updated_at` as seeded.
//!
//! These tests pass on the code before the version fix and must still pass
//! after it (they guard the refusals). Each asserts the refusal AND the
//! no-write, against a real MariaDB.
//!
//! Spec: `iamdb.proto:705` (NOT_FOUND means no `iam_user` row at all),
//! `src/service/epoch.rs:49-50` (SetPassword's zero is NOT_FOUND, decided
//! before anything is written), `iamdb.proto:462-463` (expiry is evaluated in
//! the redeeming statement).
//!
//! `updated_at` is seeded with `FROM_UNIXTIME(1000000000)` and compared with
//! `UNIX_TIMESTAMP(updated_at)`, so the check is zone-independent.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

const SEEDED: i64 = 1_000_000_000;

/// Set `updated_at` of `user_id` to the seed instant. Does not move `version`.
async fn seed_updated_at(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("seed updated_at");
}

async fn version(svc: &IamDb, user_id: &str) -> u64 {
    sqlx::query_scalar("SELECT version FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read version")
}

async fn updated_at_unix(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) FROM iam_user WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(svc.pool())
    .await
    .expect("read updated_at")
}

async fn soft_delete(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");
}

async fn set_password_refused(svc: &IamDb, user_id: &str, hash: &str) -> tonic::Status {
    svc.set_password_as(
        Some(IAM_CALLER),
        Request::new(SetPasswordRequest {
            user_id: user_id.into(),
            argon2id_hash: hash.into(),
            ..Default::default()
        }),
    )
    .await
    .expect_err("SetPassword for a soft-deleted person must be refused")
}

#[tokio::test]
async fn revoke_all_for_an_unknown_user_writes_nothing() {
    // AC4: revoke_all for an unknown user answers NOT_FOUND, version and updated_at as seeded.
    let svc = fresh("iam_db_vguard_revoke_unknown").await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version(&svc, &a).await;
    assert_eq!(v0, 1, "a new person starts at version 1");

    let err = revoke_all(&svc, "yadgar:user:01a1b2dd-0000-7000-8000-000000000000")
        .await
        .expect_err("an unknown user is NOT_FOUND");

    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(updated_at_unix(&svc, &a).await, SEEDED);
}

#[tokio::test]
async fn revoke_all_for_another_unknown_user_writes_nothing() {
    // AC4: triangulation: a different unknown id, two existing people, none touched.
    let svc = fresh("iam_db_vguard_revoke_unknown_two").await;
    let a = person(&svc, 2).await;
    let b = person(&svc, 3).await;
    seed_updated_at(&svc, &a).await;
    seed_updated_at(&svc, &b).await;

    let err = revoke_all(&svc, "yadgar:user:01a1b2dd-0000-7000-8000-0000000000ff")
        .await
        .expect_err("an unknown user is NOT_FOUND");

    assert_eq!(err.code(), Code::NotFound);
    for id in [&a, &b] {
        assert_eq!(version(&svc, id).await, 1);
        assert_eq!(updated_at_unix(&svc, id).await, SEEDED);
    }
}

#[tokio::test]
async fn set_password_for_a_soft_deleted_person_writes_nothing() {
    // AC4: SetPassword for a soft-deleted person answers NOT_FOUND, version and updated_at as seeded.
    let svc = fresh("iam_db_vguard_set_password_deleted").await;
    let a = person(&svc, 1).await;
    soft_delete(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version(&svc, &a).await;
    assert_eq!(v0, 1);

    let err = set_password_refused(&svc, &a, GOOD_HASH).await;

    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(updated_at_unix(&svc, &a).await, SEEDED);
}

#[tokio::test]
async fn set_password_for_another_soft_deleted_person_writes_nothing() {
    // AC4: triangulation: a different person and hash; the live neighbour is untouched too.
    let svc = fresh("iam_db_vguard_set_password_deleted_two").await;
    let a = person(&svc, 4).await;
    let b = person(&svc, 5).await;
    soft_delete(&svc, &b).await;
    seed_updated_at(&svc, &a).await;
    seed_updated_at(&svc, &b).await;

    let err = set_password_refused(&svc, &b, OTHER_HASH).await;

    assert_eq!(err.code(), Code::NotFound);
    for id in [&a, &b] {
        assert_eq!(version(&svc, id).await, 1);
        assert_eq!(updated_at_unix(&svc, id).await, SEEDED);
    }
}

#[tokio::test]
async fn an_expired_redemption_writes_nothing() {
    // AC4: an expired redemption answers Expired, version and updated_at as seeded.
    let svc = fresh("iam_db_vguard_redeem_expired").await;
    let a = person(&svc, 1).await;
    enrol(&svc, &a, 9, false, -60).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version(&svc, &a).await;
    assert_eq!(v0, 1);

    let got = redeem(&svc, 9, GOOD_HASH, "k3").await;

    assert_eq!(got.outcome, RedeemOutcome::Expired as i32);
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(updated_at_unix(&svc, &a).await, SEEDED);
}

#[tokio::test]
async fn another_expired_redemption_writes_nothing() {
    // AC4: triangulation: a flagged enrolment long expired, a different secret, no idempotency key.
    let svc = fresh("iam_db_vguard_redeem_expired_two").await;
    let a = person(&svc, 6).await;
    enrol(&svc, &a, 7, true, -3600).await;
    seed_updated_at(&svc, &a).await;

    let got = redeem(&svc, 7, OTHER_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Expired as i32);
    assert_eq!(version(&svc, &a).await, 1);
    assert_eq!(updated_at_unix(&svc, &a).await, SEEDED);
}
