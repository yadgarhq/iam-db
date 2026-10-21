//! ADR-0972 (5): voiding a user's other live enrolments, against a real
//! MariaDB.
//!
//! THE GAP THIS CLOSES (ledger 1578 b, 1630). Revoke-all and a revoking
//! redemption tombstoned credentials only, so a leaked, unredeemed enrolment
//! re-opened the account afterwards. Now both set `voided_at` on every
//! enrolment of the user that is neither spent nor already voided — the
//! bootstrap enrolment included — and count them. A voided enrolment answers
//! REDEEM_OUTCOME_VOIDED. Max ruled (§10 C2) that ONLY a revoking redemption
//! and revoke-all void: an unflagged redemption voids nothing.

mod db;

use db::*;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;

#[tokio::test]
async fn a_revoking_redemption_voids_the_users_other_live_enrolments() {
    let svc = fresh("iam_db_void_revoking").await;
    let user_id = person(&svc, 1).await;
    enrol(&svc, &user_id, 1, true, 3600).await;
    enrol(&svc, &user_id, 2, false, 3600).await;
    enrol(&svc, &user_id, 3, false, 3600).await;
    // SOMEBODY ELSE'S ENROLMENT. A void missing its `user_id` predicate would
    // void every enrolment in the store.
    let bystander = person(&svc, 4).await;
    enrol(&svc, &bystander, 4, false, 3600).await;

    let got = redeem(&svc, 1, GOOD_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(
        got.voided_enrolments, 2,
        "both other live enrolments counted"
    );
    assert_eq!(enrolment_state(&svc, 2).await, (false, true));
    assert_eq!(enrolment_state(&svc, 3).await, (false, true));
    assert_eq!(
        redeem(&svc, 4, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32,
        "another user's enrolment must stay redeemable"
    );
}

#[tokio::test]
async fn an_unflagged_redemption_leaves_other_enrolments_live() {
    // §10 C2: ADR-0943's default recovery path is unchanged.
    let svc = fresh("iam_db_void_unflagged").await;
    let user_id = person(&svc, 5).await;
    enrol(&svc, &user_id, 5, false, 3600).await;
    enrol(&svc, &user_id, 6, false, 3600).await;

    let got = redeem(&svc, 5, GOOD_HASH, "").await;

    assert_eq!(got.voided_enrolments, 0);
    assert_eq!(enrolment_state(&svc, 6).await, (false, false));
    assert_eq!(
        redeem(&svc, 6, OTHER_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32
    );
}

#[tokio::test]
async fn the_enrolment_being_redeemed_is_spent_not_voided() {
    let svc = fresh("iam_db_void_self").await;
    let user_id = person(&svc, 7).await;
    enrol(&svc, &user_id, 7, true, 3600).await;

    let got = redeem(&svc, 7, GOOD_HASH, "").await;

    assert_eq!(got.voided_enrolments, 0, "it voids OTHER enrolments only");
    assert_eq!(enrolment_state(&svc, 7).await, (true, false));
}

#[tokio::test]
async fn revoke_all_voids_every_live_enrolment_and_counts_them() {
    // An outstanding BOOTSTRAP enrolment is voided too (ADR-0972 (5)), and so
    // is an unspent one past its deadline: the contract's scope is "neither
    // spent nor already voided". A spent one is left alone.
    let svc = fresh("iam_db_void_revoke_all").await;
    let user_id = person(&svc, 8).await;
    make_admin(&svc, &user_id).await;
    enrol_bootstrap(&svc, &user_id, 8).await;
    enrol(&svc, &user_id, 9, false, 3600).await;
    enrol(&svc, &user_id, 10, false, -3600).await;
    enrol(&svc, &user_id, 11, false, 3600).await;
    redeem(&svc, 11, GOOD_HASH, "").await;
    let bystander = person(&svc, 12).await;
    enrol(&svc, &bystander, 12, false, 3600).await;

    let got = revoke_all(&svc, &user_id).await.expect("revoke all");

    assert_eq!(
        got.voided_enrolments, 3,
        "bootstrap, live and expired-unspent"
    );
    assert_eq!(enrolment_state(&svc, 8).await, (false, true), "bootstrap");
    assert_eq!(enrolment_state(&svc, 9).await, (false, true));
    assert_eq!(enrolment_state(&svc, 10).await, (false, true));
    assert_eq!(
        enrolment_state(&svc, 11).await,
        (true, false),
        "spent stays spent"
    );
    assert_eq!(enrolment_state(&svc, 12).await, (false, false), "bystander");

    let again = revoke_all(&svc, &user_id).await.expect("again");
    assert_eq!(again.voided_enrolments, 0, "a repeat voids nothing new");
}

#[tokio::test]
async fn a_voided_enrolment_cannot_be_redeemed() {
    let svc = fresh("iam_db_void_refused").await;
    let user_id = person(&svc, 13).await;
    set_password(&svc, &user_id, GOOD_HASH).await;
    enrol(&svc, &user_id, 13, false, 3600).await;
    revoke_all(&svc, &user_id).await.expect("revoke all");
    let epoch = stored_epoch(&svc, &user_id).await;

    let got = redeem(&svc, 13, OTHER_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Voided as i32);
    assert!(got.user_id.is_empty(), "a refusal names nobody");
    assert_eq!(
        stored_hash(&svc, &user_id).await.as_deref(),
        Some(GOOD_HASH),
        "a voided enrolment must not set a password"
    );
    assert_eq!(enrolment_state(&svc, 13).await, (false, true), "not spent");
    assert_eq!(stored_epoch(&svc, &user_id).await, epoch, "no bump");
}

#[tokio::test]
async fn a_voided_and_expired_enrolment_answers_voided() {
    // Voided is checked before expired: the void is the act that ended it.
    let svc = fresh("iam_db_void_expired").await;
    let user_id = person(&svc, 14).await;
    enrol(&svc, &user_id, 14, false, -3600).await;
    revoke_all(&svc, &user_id).await.expect("revoke all");

    assert_eq!(
        redeem(&svc, 14, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Voided as i32
    );
}

#[tokio::test]
async fn a_replayed_revoking_redemption_reports_zero_voided() {
    // COUNTED, NOT READ: a replay changed nothing, so it reports 0 and never
    // the first delivery's count.
    let svc = fresh("iam_db_void_replay").await;
    let user_id = person(&svc, 15).await;
    enrol(&svc, &user_id, 15, true, 3600).await;
    enrol(&svc, &user_id, 16, false, 3600).await;

    let first = redeem(&svc, 15, GOOD_HASH, "void-replay-key").await;
    assert_eq!(first.voided_enrolments, 1);
    let again = redeem(&svc, 15, GOOD_HASH, "void-replay-key").await;
    assert_eq!(again.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(again.voided_enrolments, 0);
}

#[tokio::test]
async fn a_redemption_racing_revoke_all_is_voided_not_deadlocked() {
    // THE LOCK ORDER. The void holds the user row and then writes enrolment
    // rows. A redemption that spent its enrolment row FIRST and took the user
    // row second (the bump) is a cycle: revoke-all waits on the spent row, the
    // redemption waits on the user row, and MariaDB kills one with 1213, which
    // `db()` renders as UNAVAILABLE. The redemption therefore takes the user
    // row before it spends, and the race resolves in order instead.
    //
    // The window is held open deterministically: a third transaction holds the
    // user's existing credential row, so revoke-all stalls after its user-row
    // lock and before its void.
    let svc = std::sync::Arc::new(fresh("iam_db_void_race").await);
    let user_id = person(&svc, 17).await;
    let existing = mint(&svc, &user_id, 17, None).await.expect("existing");
    enrol(&svc, &user_id, 18, false, 3600).await;

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

    let redeeming = {
        let svc = std::sync::Arc::clone(&svc);
        tokio::spawn(async move {
            svc.redeem_enrolment_as(
                Some(yadgar_iam_db::service::IAM_CALLER),
                tonic::Request::new(RedeemEnrolmentRequest {
                    secret_hash: vec![18u8; 32],
                    argon2id_hash: GOOD_HASH.into(),
                    idempotency: None,
                }),
            )
            .await
            .map(|r| r.into_inner())
        })
    };
    settle().await;

    stall.rollback().await.expect("release the stall");
    let revoked = revoking.await.expect("task");
    let redeemed = redeemed_or_error(redeeming.await.expect("task"));
    let revoked = revoked.expect("revoke-all must not be a deadlock victim");

    assert_eq!(
        revoked.voided_enrolments, 1,
        "the racing enrolment is voided"
    );
    assert_eq!(
        redeemed.outcome,
        RedeemOutcome::Voided as i32,
        "the redemption runs after revoke-all and finds its enrolment voided"
    );
    assert_eq!(stored_hash(&svc, &user_id).await, None, "no password set");
}

fn redeemed_or_error(
    got: Result<RedeemEnrolmentResponse, tonic::Status>,
) -> RedeemEnrolmentResponse {
    got.unwrap_or_else(|e| panic!("the redemption must not be a deadlock victim: {e:?}"))
}
