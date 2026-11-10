//! D8 (`common.proto`: `Meta.version` is "Incremented by the -db service on
//! every successful update"): every credential-epoch bump on `iam_user` also
//! advances `version` by exactly 1 and sets `updated_at`, against a real
//! MariaDB. Covers RevokeAllCredentials, SetPassword and redemption.
//!
//! `version` and `updated_at` are exposed by no read RPC, so they are read with
//! SQL. `updated_at` is seeded with `FROM_UNIXTIME(1000000000)` and compared
//! through `UNIX_TIMESTAMP`, which is zone-independent.

mod db;

use db::*;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::IamDb;

/// The stored `version` of `user_id`.
async fn version_of(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT CAST(version AS SIGNED) FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read the version")
}

/// The stored `updated_at` of `user_id` as a UTC unix instant.
async fn updated_at_of(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) FROM iam_user WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(svc.pool())
    .await
    .expect("read updated_at")
}

/// Seed `updated_at` to the unix instant 1000000000, leaving `version` alone.
async fn seed_updated_at(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET updated_at = FROM_UNIXTIME(1000000000) WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("seed updated_at");
    assert_eq!(updated_at_of(svc, user_id).await, 1_000_000_000, "seeded");
}

async fn soft_delete(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");
}

#[tokio::test]
async fn revoke_all_advances_the_version_by_one() {
    let svc = fresh("iam_db_version_revoke_all").await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1, "a new person starts at version 1");

    revoke_all(&svc, &a).await.expect("revoke all");

    // AC2: RevokeAllCredentials on a live person adds exactly 1.
    assert_eq!(version_of(&svc, &a).await, v0 + 1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);
    assert_eq!(stored_epoch(&svc, &a).await, 1);

    // AC2 triangulation: a second revoke-all adds one more, not a fixed value.
    seed_updated_at(&svc, &a).await;
    revoke_all(&svc, &a).await.expect("revoke all again");
    assert_eq!(version_of(&svc, &a).await, 3);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);
}

#[tokio::test]
async fn revoke_all_advances_the_version_of_a_soft_deleted_person() {
    let svc = fresh("iam_db_version_revoke_deleted").await;
    let a = person(&svc, 1).await;
    soft_delete(&svc, &a).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1);

    revoke_all(&svc, &a).await.expect("revoke all");

    // AC2: a soft-deleted person's revoke-all adds exactly 1 as well.
    assert_eq!(version_of(&svc, &a).await, v0 + 1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);

    // AC2 triangulation: a different soft-deleted person, one bump, version 2.
    let b = person(&svc, 9).await;
    soft_delete(&svc, &b).await;
    seed_updated_at(&svc, &b).await;
    revoke_all(&svc, &b).await.expect("revoke all b");
    assert_eq!(version_of(&svc, &b).await, 2);
}

#[tokio::test]
async fn set_password_advances_the_version_by_one() {
    let svc = fresh("iam_db_version_set_password").await;
    let a = person(&svc, 1).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1);

    set_password(&svc, &a, GOOD_HASH).await;

    // AC2: SetPassword adds exactly 1.
    assert_eq!(version_of(&svc, &a).await, v0 + 1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);

    // AC2 triangulation: a second SetPassword with another hash adds one more.
    seed_updated_at(&svc, &a).await;
    set_password(&svc, &a, OTHER_HASH).await;
    assert_eq!(version_of(&svc, &a).await, 3);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);
}

#[tokio::test]
async fn an_unflagged_redemption_advances_the_version_by_one() {
    let svc = fresh("iam_db_version_redeem").await;
    let a = person(&svc, 1).await;
    enrol(&svc, &a, 7, false, 3600).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1);

    let got = redeem(&svc, 7, GOOD_HASH, "k1").await;

    // AC2: an unflagged redemption adds exactly 1.
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &a).await, v0 + 1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);

    // AC2 triangulation: another person, another secret and key, same +1.
    let b = person(&svc, 2).await;
    enrol(&svc, &b, 11, false, 3600).await;
    seed_updated_at(&svc, &b).await;
    let got = redeem(&svc, 11, OTHER_HASH, "k5").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &b).await, 2);
}

#[tokio::test]
async fn a_flagged_redemption_advances_the_version_by_exactly_one() {
    let svc = fresh("iam_db_version_redeem_flagged").await;
    let a = person(&svc, 1).await;
    enrol(&svc, &a, 8, true, 3600).await;
    seed_updated_at(&svc, &a).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1);

    let got = redeem(&svc, 8, GOOD_HASH, "k2").await;

    // AC2: a flagged redemption (revoke_existing_credentials) bumps once, not twice.
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &a).await, v0 + 1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);

    // AC2 triangulation: a person who already had a password (version 2 after
    // SetPassword) ends at 3 after a flagged redemption.
    let b = person(&svc, 2).await;
    set_password(&svc, &b, GOOD_HASH).await;
    enrol(&svc, &b, 12, true, 3600).await;
    seed_updated_at(&svc, &b).await;
    let vb = version_of(&svc, &b).await;
    assert_eq!(vb, 2);
    let got = redeem(&svc, 12, OTHER_HASH, "k6").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &b).await, 3);
}

#[tokio::test]
async fn a_redemption_replay_adds_nothing() {
    let svc = fresh("iam_db_version_redeem_replay").await;
    let a = person(&svc, 1).await;
    enrol(&svc, &a, 10, false, 3600).await;
    let v0 = version_of(&svc, &a).await;
    assert_eq!(v0, 1);

    let first = redeem(&svc, 10, GOOD_HASH, "k4").await;
    assert_eq!(first.outcome, RedeemOutcome::Redeemed as i32);
    seed_updated_at(&svc, &a).await;
    let v1 = version_of(&svc, &a).await;
    // AC2: the first delivery adds 1.
    assert_eq!(v1, v0 + 1);

    let replay = redeem(&svc, 10, GOOD_HASH, "k4").await;

    // AC2: the replay answers Redeemed, adds 0 and leaves updated_at alone.
    assert_eq!(replay.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &a).await, v1);
    assert_eq!(version_of(&svc, &a).await, 2);
    assert_eq!(updated_at_of(&svc, &a).await, 1_000_000_000);

    // AC2 triangulation: another person; two replays still total exactly +1.
    let b = person(&svc, 2).await;
    enrol(&svc, &b, 13, true, 3600).await;
    redeem(&svc, 13, OTHER_HASH, "k7").await;
    seed_updated_at(&svc, &b).await;
    redeem(&svc, 13, OTHER_HASH, "k7").await;
    redeem(&svc, 13, OTHER_HASH, "k7").await;
    assert_eq!(version_of(&svc, &b).await, 2);
    assert_eq!(updated_at_of(&svc, &b).await, 1_000_000_000);
}

#[tokio::test]
async fn an_epoch_bump_leaves_another_persons_row_untouched() {
    let svc = fresh("iam_db_version_epoch_other").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    seed_updated_at(&svc, &a).await;
    seed_updated_at(&svc, &b).await;
    assert_eq!(version_of(&svc, &a).await, 1);
    assert_eq!(version_of(&svc, &b).await, 1);

    revoke_all(&svc, &a).await.expect("revoke all");

    // AC2: only the target moves; the other person's row is untouched.
    assert_eq!(version_of(&svc, &a).await, 2);
    assert_eq!(version_of(&svc, &b).await, 1);
    assert_eq!(updated_at_of(&svc, &b).await, 1_000_000_000);

    // AC2 triangulation: a SetPassword on b moves b and leaves a at 2.
    set_password(&svc, &b, GOOD_HASH).await;
    assert_eq!(version_of(&svc, &b).await, 2);
    assert_eq!(version_of(&svc, &a).await, 2);
}

#[tokio::test]
async fn every_successful_bump_in_a_sequence_adds_exactly_one() {
    // AC2 property: each successful epoch bump adds exactly 1 to version.
    let svc = fresh("iam_db_version_property").await;
    let a = person(&svc, 1).await;
    let mut expected = version_of(&svc, &a).await;
    assert_eq!(expected, 1);

    for step in 0..6u8 {
        match step % 3 {
            0 => set_password(&svc, &a, GOOD_HASH).await,
            1 => {
                revoke_all(&svc, &a).await.expect("revoke all");
            }
            _ => set_password(&svc, &a, OTHER_HASH).await,
        }
        expected += 1;
        assert_eq!(
            version_of(&svc, &a).await,
            expected,
            "step {step} must add exactly one"
        );
    }
}

/// Seed `version` to `v`, so it differs from `credential_epoch + 1`.
async fn seed_version(svc: &IamDb, user_id: &str, v: i64) {
    sqlx::query("UPDATE iam_user SET version = ? WHERE id = ?")
        .bind(v)
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("seed version");
    assert_eq!(version_of(svc, user_id).await, v, "seeded");
}

#[tokio::test]
async fn a_bump_adds_one_to_a_version_that_is_not_the_epoch_plus_one() {
    // AC2 triangulation: version is decoupled from credential_epoch by SQL, so a
    // bump that writes `version = credential_epoch + 1` (instead of adding 1)
    // fails. Every person starts at epoch 0 with a seeded version of 5.
    let svc = fresh("iam_db_version_decoupled").await;

    // AC2: RevokeAllCredentials adds exactly 1 to a seeded version.
    let a = person(&svc, 1).await;
    seed_version(&svc, &a, 5).await;
    seed_updated_at(&svc, &a).await;
    revoke_all(&svc, &a).await.expect("revoke all");
    assert_eq!(version_of(&svc, &a).await, 6);
    assert!(updated_at_of(&svc, &a).await > 1_000_000_000);

    // AC2: SetPassword adds exactly 1 to a seeded version.
    let b = person(&svc, 2).await;
    seed_version(&svc, &b, 5).await;
    seed_updated_at(&svc, &b).await;
    set_password(&svc, &b, GOOD_HASH).await;
    assert_eq!(version_of(&svc, &b).await, 6);
    assert!(updated_at_of(&svc, &b).await > 1_000_000_000);

    // AC2: an unflagged redemption adds exactly 1 to a seeded version.
    let c = person(&svc, 3).await;
    seed_version(&svc, &c, 5).await;
    enrol(&svc, &c, 14, false, 3600).await;
    seed_updated_at(&svc, &c).await;
    let got = redeem(&svc, 14, GOOD_HASH, "k8").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(version_of(&svc, &c).await, 6);
    assert!(updated_at_of(&svc, &c).await > 1_000_000_000);
}
