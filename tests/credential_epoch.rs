//! ADR-0972 (4): the per-user credential epoch, against a real MariaDB.
//!
//! THE RACE THIS CLOSES (ledger 1578 a). `iam`'s Login reads the hash with
//! `GetPasswordHash`, verifies it, and mints with `CreateCredential` in a
//! separate transaction. Before the epoch, a Login that verified the OLD
//! password before a reset or a revoke-all committed waited on the user-row
//! lock and then minted a credential that survived the reset. Now every
//! password-setting redemption, `RevokeAllCredentials` and `SetPassword` bump
//! `iam_user.credential_epoch`; `GetPasswordHash` returns the epoch in the
//! same statement as the hash; and a mint carrying
//! `expected_credential_epoch` inserts nothing and answers
//! FAILED_PRECONDITION when the epoch moved.
//!
//! EVERY REFUSED MINT ALSO ASSERTS NO ROW WAS INSERTED. `mint_credential`'s
//! zero-row branch used to fall through to OK when the user was live, which
//! the epoch makes reachable: a refusal that still returned an id for a row it
//! never wrote is the false green these counts catch.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::IAM_CALLER;

/// A person with a password, under blind index `[blind; 32]`.
async fn with_password(svc: &yadgar_iam_db::service::IamDb, blind: u8) -> String {
    let user_id = person(svc, blind).await;
    set_password(svc, &user_id, GOOD_HASH).await;
    user_id
}

fn refused_as_stale(got: Result<String, tonic::Status>, what: &str) {
    let err = got.expect_err(what);
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "a mint whose epoch moved must be FAILED_PRECONDITION, got {err:?}"
    );
}

#[tokio::test]
async fn get_password_hash_returns_the_epoch_with_the_hash() {
    let svc = fresh("iam_db_epoch_hash").await;
    let user_id = with_password(&svc, 1).await;

    let first = password_hash(&svc, 1).await;
    assert_eq!(first.user_id, user_id);
    assert_eq!(first.argon2id_hash, GOOD_HASH);
    assert_eq!(
        first.credential_epoch,
        stored_epoch(&svc, &user_id).await,
        "the epoch handed back must be the stored one"
    );

    set_password(&svc, &user_id, OTHER_HASH).await;
    let second = password_hash(&svc, 1).await;
    assert_eq!(second.argon2id_hash, OTHER_HASH);
    assert_eq!(
        second.credential_epoch,
        first.credential_epoch + 1,
        "the hash and the epoch move together, read as one snapshot"
    );
}

#[tokio::test]
async fn set_password_bumps_the_epoch() {
    let svc = fresh("iam_db_epoch_set_password").await;
    let user_id = person(&svc, 2).await;
    assert_eq!(
        stored_epoch(&svc, &user_id).await,
        0,
        "a new person starts at 0"
    );

    set_password(&svc, &user_id, GOOD_HASH).await;
    assert_eq!(stored_epoch(&svc, &user_id).await, 1);
    set_password(&svc, &user_id, OTHER_HASH).await;
    assert_eq!(stored_epoch(&svc, &user_id).await, 2);
}

#[tokio::test]
async fn a_set_password_for_a_soft_deleted_person_bumps_nothing() {
    // The bump rides the liveness check: a refused SetPassword writes neither
    // the password nor the epoch.
    let svc = fresh("iam_db_epoch_set_password_deleted").await;
    let user_id = person(&svc, 3).await;
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(&user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");

    let err = svc
        .set_password_as(
            Some(IAM_CALLER),
            Request::new(SetPasswordRequest {
                user_id: user_id.clone(),
                argon2id_hash: GOOD_HASH.into(),
                ..Default::default()
            }),
        )
        .await
        .expect_err("a soft-deleted person is not live");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(stored_epoch(&svc, &user_id).await, 0);
    assert_eq!(stored_hash(&svc, &user_id).await, None);
}

#[tokio::test]
async fn an_unflagged_redemption_bumps_the_epoch() {
    // §10 C1: every redemption sets a password, so every redemption bumps.
    let svc = fresh("iam_db_epoch_unflagged").await;
    let user_id = person(&svc, 4).await;
    enrol(&svc, &user_id, 4, false, 3600).await;

    let got = redeem(&svc, 4, GOOD_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(stored_epoch(&svc, &user_id).await, 1);
    assert_eq!(
        got.credential_epoch, 1,
        "the response carries the epoch AFTER this redemption's bump"
    );
}

#[tokio::test]
async fn a_flagged_redemption_bumps_the_epoch() {
    let svc = fresh("iam_db_epoch_flagged").await;
    let user_id = with_password(&svc, 5).await;
    enrol(&svc, &user_id, 5, true, 3600).await;

    let got = redeem(&svc, 5, OTHER_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(
        got.credential_epoch, 2,
        "SetPassword made it 1, the reset 2"
    );
    assert_eq!(stored_epoch(&svc, &user_id).await, 2);
}

#[tokio::test]
async fn a_refused_redemption_bumps_nothing() {
    // The refusal path commits its transaction, so a bump placed before the
    // spend would persist for a redemption that never happened.
    let svc = fresh("iam_db_epoch_refused").await;
    let user_id = person(&svc, 6).await;
    enrol(&svc, &user_id, 6, false, -3600).await;

    let got = redeem(&svc, 6, GOOD_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Expired as i32);
    assert_eq!(got.credential_epoch, 0);
    assert_eq!(stored_epoch(&svc, &user_id).await, 0);
}

#[tokio::test]
async fn revoke_all_bumps_the_epoch() {
    let svc = fresh("iam_db_epoch_revoke_all").await;
    let user_id = person(&svc, 7).await;

    revoke_all(&svc, &user_id).await.expect("revoke all");
    assert_eq!(
        stored_epoch(&svc, &user_id).await,
        1,
        "revoke-all bumps even when it revokes nothing"
    );
}

#[tokio::test]
async fn a_login_that_read_before_a_redemption_mints_nothing() {
    let svc = fresh("iam_db_epoch_login_vs_redeem").await;
    let user_id = with_password(&svc, 8).await;
    enrol(&svc, &user_id, 9, false, 3600).await;

    let read = password_hash(&svc, 8).await;
    redeem(&svc, 9, OTHER_HASH, "").await;

    refused_as_stale(
        mint(&svc, &user_id, 10, Some(read.credential_epoch)).await,
        "a Login that verified the old password must not mint after the reset",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_login_that_read_before_revoke_all_mints_nothing() {
    let svc = fresh("iam_db_epoch_login_vs_revoke_all").await;
    let user_id = with_password(&svc, 11).await;

    let read = password_hash(&svc, 11).await;
    revoke_all(&svc, &user_id).await.expect("revoke all");

    refused_as_stale(
        mint(&svc, &user_id, 12, Some(read.credential_epoch)).await,
        "a Login that read before revoke-all must not mint after it",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_login_that_read_before_set_password_mints_nothing() {
    let svc = fresh("iam_db_epoch_login_vs_set_password").await;
    let user_id = with_password(&svc, 13).await;

    let read = password_hash(&svc, 13).await;
    set_password(&svc, &user_id, OTHER_HASH).await;

    refused_as_stale(
        mint(&svc, &user_id, 14, Some(read.credential_epoch)).await,
        "a Login that read the replaced password must not mint",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_login_after_the_bump_mints_normally() {
    let svc = fresh("iam_db_epoch_login_after").await;
    let user_id = with_password(&svc, 15).await;
    revoke_all(&svc, &user_id).await.expect("revoke all");

    let read = password_hash(&svc, 15).await;
    mint(&svc, &user_id, 16, Some(read.credential_epoch))
        .await
        .expect("a Login that read the current epoch mints");
    assert_eq!(resolve(&svc, 16).await.user_id, user_id);
}

#[tokio::test]
async fn a_create_credential_without_an_epoch_is_unchanged() {
    // ABSENT IS UNCHECKED: IssueCredential and an iam built before ADR-0972 (4)
    // send none, and must mint exactly as before.
    let svc = fresh("iam_db_epoch_absent").await;
    let user_id = with_password(&svc, 17).await;
    set_password(&svc, &user_id, OTHER_HASH).await;

    mint(&svc, &user_id, 18, None)
        .await
        .expect("an unchecked mint ignores the epoch");
    assert_eq!(resolve(&svc, 18).await.user_id, user_id);
}

#[tokio::test]
async fn a_checked_mint_for_a_soft_deleted_person_is_not_found() {
    // NOT_FOUND wins over FAILED_PRECONDITION: the epoch question only arises
    // for a live person.
    let svc = fresh("iam_db_epoch_deleted").await;
    let user_id = with_password(&svc, 19).await;
    let read = password_hash(&svc, 19).await;
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(&user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");

    let err = mint(&svc, &user_id, 20, Some(read.credential_epoch))
        .await
        .expect_err("a soft-deleted person gets no credential");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(credential_rows(&svc, &user_id).await, 0);
}

#[tokio::test]
async fn the_redemptions_own_credential_is_minted_under_the_new_epoch() {
    let svc = fresh("iam_db_epoch_redeem_own").await;
    let user_id = person(&svc, 21).await;
    enrol(&svc, &user_id, 21, false, 3600).await;
    enrol(&svc, &user_id, 22, false, 3600).await;

    let first = redeem(&svc, 21, GOOD_HASH, "").await;
    mint(&svc, &user_id, 23, Some(first.credential_epoch))
        .await
        .expect("the redemption's own credential mints under its epoch");

    // A SECOND RESET BETWEEN A REDEMPTION AND ITS MINT REFUSES THAT MINT.
    let second = redeem(&svc, 22, OTHER_HASH, "").await;
    assert_eq!(second.credential_epoch, first.credential_epoch + 1);
    refused_as_stale(
        mint(&svc, &user_id, 24, Some(first.credential_epoch)).await,
        "a mint under the first redemption's epoch must lose to the second",
    );
    assert_eq!(
        credential_rows(&svc, &user_id).await,
        1,
        "only the first mint"
    );
}

// ---------------------------------------------------------------------------
// The replay (D9). A replayed redemption key answers with the epoch THE FIRST
// DELIVERY recorded, never the current one. A retry with nothing in between
// mints; a retry after a revoke-all, a reset or a SetPassword is refused at the
// mint, because a replay must never yield a credential that the later
// revocation was meant to end. The first build of this branch returned the
// CURRENT epoch and minted straight through a revoke-all (security review).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_replayed_redemption_with_nothing_in_between_mints() {
    // THE D9 RETRY THE REPLAY EXISTS FOR: the first response was lost, and the
    // retry's mint must succeed under the first delivery's epoch.
    let svc = fresh("iam_db_epoch_replay").await;
    let user_id = person(&svc, 25).await;
    enrol(&svc, &user_id, 25, false, 3600).await;

    let first = redeem(&svc, 25, GOOD_HASH, "epoch-replay-key").await;
    let again = redeem(&svc, 25, GOOD_HASH, "epoch-replay-key").await;

    assert_eq!(again.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(again.credential_epoch, first.credential_epoch);
    assert_eq!(again.voided_enrolments, 0, "a replay changed nothing");
    mint(&svc, &user_id, 27, Some(again.credential_epoch))
        .await
        .expect("the retry mints under the first delivery's epoch");
}

#[tokio::test]
async fn a_replay_after_revoke_all_mints_nothing() {
    let svc = fresh("iam_db_epoch_replay_revoke_all").await;
    let user_id = person(&svc, 26).await;
    enrol(&svc, &user_id, 26, false, 3600).await;
    redeem(&svc, 26, GOOD_HASH, "replay-revoke-all").await;
    revoke_all(&svc, &user_id).await.expect("revoke all");

    let again = redeem(&svc, 26, GOOD_HASH, "replay-revoke-all").await;

    refused_as_stale(
        mint(&svc, &user_id, 28, Some(again.credential_epoch)).await,
        "a replay after revoke-all must not mint a live credential",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_replay_after_a_revoking_reset_mints_nothing() {
    // A flagged re-enrolment redeemed after the first redemption: the reset
    // that was meant to contain a leak must also contain the replay.
    let svc = fresh("iam_db_epoch_replay_reset").await;
    let user_id = person(&svc, 29).await;
    enrol(&svc, &user_id, 29, false, 3600).await;
    redeem(&svc, 29, GOOD_HASH, "replay-reset").await;
    enrol(&svc, &user_id, 30, true, 3600).await;
    redeem(&svc, 30, OTHER_HASH, "").await;

    let again = redeem(&svc, 29, GOOD_HASH, "replay-reset").await;

    refused_as_stale(
        mint(&svc, &user_id, 31, Some(again.credential_epoch)).await,
        "a replay after a revoking reset must not mint",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_replay_after_set_password_mints_nothing() {
    let svc = fresh("iam_db_epoch_replay_set_password").await;
    let user_id = person(&svc, 32).await;
    enrol(&svc, &user_id, 32, false, 3600).await;
    redeem(&svc, 32, GOOD_HASH, "replay-set-password").await;
    set_password(&svc, &user_id, OTHER_HASH).await;

    let again = redeem(&svc, 32, GOOD_HASH, "replay-set-password").await;

    refused_as_stale(
        mint(&svc, &user_id, 33, Some(again.credential_epoch)).await,
        "a replay after the password was replaced must not mint",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0, "nothing inserted");
}

#[tokio::test]
async fn a_mint_waiting_on_revoke_all_is_refused_when_it_commits() {
    // THE INTERLEAVING. A Login read the epoch, then revoke-all took the user
    // row and stalled before committing. The Login's checked mint must WAIT on
    // that lock and, once revoke-all commits, see the new epoch and refuse.
    let svc = std::sync::Arc::new(fresh("iam_db_epoch_race_revoke_all").await);
    let user_id = with_password(&svc, 28).await;
    let existing = mint(&svc, &user_id, 29, None).await.expect("existing");
    let read = password_hash(&svc, 28).await;

    // The stall: an exclusive lock on the existing credential row, so
    // revoke-all's UPDATE waits after its user-row lock and before its commit.
    let mut stall = svc.pool().begin().await.expect("stall begins");
    sqlx::query("UPDATE iam_credential SET label = label WHERE id = ?")
        .bind(&existing)
        .execute(&mut *stall)
        .await
        .expect("hold the credential row");

    let revoking = {
        let (svc, user_id) = (std::sync::Arc::clone(&svc), user_id.clone());
        tokio::spawn(async move { revoke_all(&svc, &user_id).await })
    };
    settle().await;
    assert!(!revoking.is_finished(), "revoke-all must be stalled");

    let minting = {
        let (svc, user_id) = (std::sync::Arc::clone(&svc), user_id.clone());
        let epoch = read.credential_epoch;
        tokio::spawn(async move { mint(&svc, &user_id, 30, Some(epoch)).await })
    };
    settle().await;
    assert!(
        !minting.is_finished(),
        "the checked mint must wait on revoke-all's user-row lock"
    );

    stall.rollback().await.expect("release the stall");
    revoking.await.expect("task").expect("revoke all");
    refused_as_stale(
        minting.await.expect("task"),
        "a mint that waited out revoke-all must see the new epoch",
    );
    assert!(resolve(&svc, 30).await.user_id.is_empty());
}

#[tokio::test]
async fn a_mint_waiting_on_a_redemption_is_refused_when_it_commits() {
    // The same interleaving against an UNFLAGGED redemption, which held no
    // user-row lock before ADR-0972. The redemption is stalled on its password
    // upsert by a third transaction holding the password row.
    let svc = std::sync::Arc::new(fresh("iam_db_epoch_race_redeem").await);
    let user_id = with_password(&svc, 31).await;
    enrol(&svc, &user_id, 32, false, 3600).await;
    let read = password_hash(&svc, 31).await;

    let mut stall = svc.pool().begin().await.expect("stall begins");
    sqlx::query("UPDATE iam_password SET argon2id_hash = argon2id_hash WHERE user_id = ?")
        .bind(&user_id)
        .execute(&mut *stall)
        .await
        .expect("hold the password row");

    let redeeming = {
        let svc = std::sync::Arc::clone(&svc);
        tokio::spawn(async move { redeem(&svc, 32, OTHER_HASH, "").await })
    };
    settle().await;
    assert!(!redeeming.is_finished(), "the redemption must be stalled");

    let minting = {
        let (svc, user_id) = (std::sync::Arc::clone(&svc), user_id.clone());
        let epoch = read.credential_epoch;
        tokio::spawn(async move { mint(&svc, &user_id, 33, Some(epoch)).await })
    };
    settle().await;
    assert!(
        !minting.is_finished(),
        "the checked mint must wait on the redemption's user-row lock"
    );

    stall.rollback().await.expect("release the stall");
    let got = redeeming.await.expect("task");
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    refused_as_stale(
        minting.await.expect("task"),
        "a mint that waited out the reset must see the new epoch",
    );
    assert_eq!(credential_rows(&svc, &user_id).await, 0);
}
