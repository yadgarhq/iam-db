//! The redemption's statements after the idempotency check: the owner's lock,
//! the spend, and the two ends — refused or redeemed.
//!
//! In a child file rather than in `enrolment.rs` because that file would cross
//! the 500-line ceiling with ADR-0972's epoch and void.

use crate::service::enrolment::ledger::{replay, unredeemable};
use crate::service::enrolment::revoke;
use crate::service::*;

/// Lock the user row of the enrolment `secret_hash` names, `FOR UPDATE`, before
/// the spend (ADR-0972).
///
/// **THE LOCK ORDER IS USER ROW, THEN ENROLMENT ROW, FOR EVERY WRITER.**
/// ADR-0972's void holds the user row and then writes the person's enrolment
/// rows. A redemption that spent its enrolment row FIRST and took the user row
/// second (for the epoch bump) would close a cycle with it: revoke-all waits on
/// the spent row, the redemption waits on the user row, and MariaDB kills one
/// with 1213, which `db()` renders as UNAVAILABLE. Taking the user row here, a
/// statement ahead of the spend, makes the redemption queue behind a revoke-all
/// or a revoking redemption already in flight, and then find its enrolment
/// voided (`a_redemption_racing_revoke_all_is_voided_not_deadlocked`). Two
/// redemptions of one person's enrolments queue the same way.
///
/// THE OWNER IS READ WITHOUT A LOCK, and that is sound: an enrolment's
/// `user_id` never changes after the insert. An unknown secret reads nothing
/// and locks nothing; the spend then matches nothing and `unspent` answers.
/// A soft-deleted person's row is locked too, which costs nothing: the spend's
/// own liveness join still refuses them.
pub(super) async fn lock_owner(
    tx: &mut sqlx::MySqlTransaction<'_>,
    secret_hash: &[u8],
) -> Result<(), Status> {
    let owner: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM iam_enrolment WHERE secret_hash = ?")
            .bind(secret_hash)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    if let Some(owner) = owner {
        sqlx::query("SELECT id FROM iam_user WHERE id = ? FOR UPDATE")
            .bind(&owner)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    }
    Ok(())
}

/// THE SPEND, and it is one statement.
///
/// Lifted out of [`IamDb::redeem`] whole, with every clause it carries. A caller
/// that could run the check without the write would be the race this statement
/// exists to close, so what comes back is the row count and nothing else.
pub(super) async fn spend(
    tx: &mut sqlx::MySqlTransaction<'_>,
    r: &RedeemEnrolmentRequest,
) -> Result<u64, Status> {
    // CHECK AND SPEND IN ONE STATEMENT. A SELECT followed by an UPDATE is
    // the same race with a longer window: two concurrent redemptions of one
    // single-use secret both read it unspent and both succeed.
    //
    // EXPIRY IS EVALUATED HERE, against the engine's own clock and inside
    // the same statement. A caller-supplied time would let a wrong clock
    // revive an expired enrolment, and the deadline is already stored.
    //
    // The JOIN carries `deleted_at IS NULL`: an enrolment row has no
    // liveness of its own, so whether the PERSON still exists is a property
    // only the join can see.
    //
    // A SINGLE-TABLE UPDATE WITH A SUBQUERY, NOT `UPDATE ... JOIN ...`, and
    // the difference is not cosmetic. MariaDB's multi-table UPDATE collects
    // matching rows by a snapshot read and re-reads them under lock; if one
    // changed in between it gives up with 1020 `ER_CHECKREAD` — "Record has
    // changed since last read" — which `db()` renders as UNAVAILABLE. So the
    // JOIN form turns a concurrent second delivery into a spurious 503
    // instead of the zero row count the branch below is written to handle.
    // A single-table UPDATE re-evaluates its WHERE against the latest
    // committed version and simply matches nothing, which is the behaviour
    // this depends on. Every sequential test passes on either form.
    let spent = sqlx::query(
        "UPDATE iam_enrolment
            SET spent_at = CURRENT_TIMESTAMP
          WHERE secret_hash = ?
            AND spent_at IS NULL
            AND expires_at > CURRENT_TIMESTAMP
            AND voided_at IS NULL
            AND user_id IN (SELECT id FROM iam_user WHERE deleted_at IS NULL)",
    )
    .bind(&r.secret_hash)
    .execute(&mut **tx)
    .await
    .map_err(db)?;

    Ok(spent.rows_affected())
}

/// The answer when the spend matched nothing.
///
/// Either a concurrent delivery of THIS key won the race for the enrolment row,
/// or the secret is genuinely unusable — and the row count alone cannot tell the
/// two apart. The transaction and the `Call` arrive by value because this is the
/// end of the RPC on this path: it commits and it answers.
pub(super) async fn unspent(
    mut tx: sqlx::MySqlTransaction<'_>,
    key: String,
    r: RedeemEnrolmentRequest,
    call: Call,
) -> Result<Response<RedeemEnrolmentResponse>, Status> {
    // THE SECOND LEDGER CHECK, AND IT IS WHAT MAKES THE KEY WORK UNDER
    // CONCURRENCY. Reaching here means either the secret is genuinely
    // unusable, or a concurrent delivery of THIS SAME KEY won the race
    // for the enrolment row — and the two are indistinguishable from the
    // UPDATE's row count alone. Without this check the loser falls into
    // `unredeemable`, sees `spent_at` set by the winner, and answers
    // SPENT: the exact D9 lockout the key exists to prevent, on the path
    // with no resend.
    //
    // The winner is guaranteed to have COMMITTED by the time this runs.
    // The loser's UPDATE blocks on the winner's exclusive row lock and
    // only returns once that transaction ends, so a zero row count here
    // is already a post-commit observation.
    //
    // `Lock::Yes` here, `Lock::No` above, and the asymmetry is
    // deliberate. Locking a key that does not exist yet is what would
    // deadlock; locking one that does is a plain record lock under READ
    // COMMITTED, with no gap. Taking it makes this read wait for a
    // winner that has locked the ledger row but not yet committed,
    // rather than reading past it and answering SPENT.
    if !key.is_empty() {
        if let Some(replayed) = replay(&mut tx, &key, &r.secret_hash, Lock::Yes).await? {
            tx.commit().await.map_err(db)?;
            call.finish(Outcome {
                status: "OK",
                ..Default::default()
            });
            return Ok(Response::new(replayed));
        }
    }

    let outcome = unredeemable(&mut *tx, &r.secret_hash).await?;
    // NOTHING IS RECORDED FOR A FAILURE. A stored NOT_FOUND, SPENT or
    // EXPIRED would replay a stale failure to a caller retrying after a
    // transient error — and the contract's words are "the one this key
    // originally SPENT", which only a redemption did.
    tx.commit().await.map_err(db)?;
    call.finish(Outcome {
        status: "OK",
        ..Default::default()
    });
    Ok(Response::new(RedeemEnrolmentResponse {
        outcome: outcome as i32,
        ..Default::default()
    }))
}

/// The answer when it did: who the enrolment belonged to, the password, the
/// ledger row, and the commit that lands all three or none of them.
///
/// The transaction and the `Call` arrive by value for the same reason they do in
/// [`unspent`] — this is the end of the RPC.
pub(super) async fn redeemed(
    mut tx: sqlx::MySqlTransaction<'_>,
    key: String,
    r: RedeemEnrolmentRequest,
    call: Call,
) -> Result<Response<RedeemEnrolmentResponse>, Status> {
    let row = sqlx::query(
        "SELECT e.id AS enrolment_id, e.user_id, u.external_id_ciphertext,
                e.revoke_existing_credentials
           FROM iam_enrolment e JOIN iam_user u ON u.id = e.user_id
          WHERE e.secret_hash = ?",
    )
    .bind(&r.secret_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;

    let enrolment_id: String = row.try_get("enrolment_id").map_err(db)?;
    let user_id: String = row.try_get("user_id").map_err(db)?;
    let external_id_ciphertext: Vec<u8> = row.try_get("external_id_ciphertext").map_err(db)?;
    let revoking: bool = row.try_get("revoke_existing_credentials").map_err(db)?;

    // ADR-0972 (4): EVERY REDEMPTION BUMPS THE EPOCH, flagged or not (§10 C1),
    // because every redemption sets a password. The user row is already held
    // exclusively (`lock_owner`), so this adds no lock. Here and not before the
    // spend: `unspent` commits its transaction, and a bump made ahead of a
    // refused redemption would persist.
    epoch::bump(&mut tx, &user_id).await?;
    let credential_epoch = epoch::current(&mut tx, &user_id).await?;

    // ADR-0943's REVOKE, in this transaction and ahead of the password — see
    // [`revoke::all`] for why both placements are load-bearing. And ADR-0972
    // (5)'s VOID, on the same flag only (§10 C2): an unflagged redemption
    // leaves the person's other enrolments live.
    let mut voided_enrolments = 0;
    if revoking {
        revoke::all(&mut tx, &user_id).await?;
        voided_enrolments = revoke::void(&mut tx, &user_id).await?;
    }

    // THE SECOND HALF, in the same transaction as the spend above. If this
    // fails — the hash does not fit the column, the engine goes away — the
    // spend rolls back with it and the secret the person holds still works.
    sqlx::query(
        "INSERT INTO iam_password (user_id, argon2id_hash) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE argon2id_hash = VALUES(argon2id_hash)",
    )
    .bind(&user_id)
    .bind(&r.argon2id_hash)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    if !key.is_empty() {
        sqlx::query(
            "INSERT INTO iam_enrolment_redemption
                 (idempotency_key, secret_hash, enrolment_id, user_id)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&key)
        .bind(&r.secret_hash)
        .bind(&enrolment_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    }

    // THE COMMIT IS THE OPERATION. Everything above is one atom until this
    // line: the spend, the bump, the revoke, the void, the password and the
    // ledger row land together or none of them does.
    tx.commit().await.map_err(db)?;

    call.finish(Outcome {
        status: "OK",
        rows: 1,
        ..Default::default()
    });
    Ok(Response::new(RedeemEnrolmentResponse {
        outcome: RedeemOutcome::Redeemed as i32,
        user_id,
        enrolment_id,
        external_id_ciphertext,
        revoked_existing_credentials: revoking,
        credential_epoch,
        voided_enrolments,
    }))
}
