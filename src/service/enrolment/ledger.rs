//! `iam_enrolment_redemption`: what a redemption key already did.
//!
//! D9 as amended refuses a key carrying a DIFFERENT secret rather than replaying
//! it, and ADR-0519's single-use-secret carve-out is why the OUTCOME is stored
//! here rather than re-derived: what `RedeemEnrolment` hands back is spent by
//! definition, so there is nothing to read again.

use crate::service::*;

/// The original outcome of a redemption already recorded under `key`.
///
/// `Ok(None)` means this key has redeemed nothing yet. `Err(INVALID_ARGUMENT)`
/// means it redeemed a DIFFERENT secret: D9 as amended refuses a key carrying a
/// different request rather than replaying it, because replaying would answer a
/// request nobody made and report success. This boundary can make that
/// comparison only because the secret hash is deterministic — the same property
/// that lets an enrolment be found by it. It cannot make the equivalent
/// comparison on the password, so `iam` makes that one.
///
/// **THAT `INVALID_ARGUMENT` IS A STORE-INTERNAL DISTINCTION AND MUST NOT REACH
/// AN UNAUTHENTICATED CALLER.** The comparison precedes the lookup deliberately —
/// a refusal issued after it would report whether the presented secret exists —
/// but that ordering is also what lets somebody holding NO secret present any key
/// and read the answer off the status code. This boundary is right to tell the
/// cases apart, in the same way it tells NOT_FOUND from SPENT from EXPIRED; the
/// collapsing belongs to `iam`, which owes its caller one refusal for all of
/// them, and it now does it for this error too.
pub(super) async fn replay(
    conn: &mut sqlx::MySqlConnection,
    key: &str,
    presented: &[u8],
    lock: Lock,
) -> Result<Option<RedeemEnrolmentResponse>, Status> {
    const BASE: &str = "SELECT secret_hash, enrolment_id, user_id
                          FROM iam_enrolment_redemption
                         WHERE idempotency_key = ?";
    // AUDIT: both arms are literals in this file; `key` is bound, never
    // interpolated.
    let sql = match lock {
        Lock::No => BASE.to_string(),
        Lock::Yes => format!("{BASE} FOR UPDATE"),
    };

    let prior = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(key)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db)?;
    let Some(prior) = prior else {
        return Ok(None);
    };

    let original: Vec<u8> = prior.try_get("secret_hash").map_err(db)?;
    if original != presented {
        return Err(Status::invalid_argument(
            "this idempotency key was used with a different enrolment secret",
        ));
    }

    let user_id: String = prior.try_get("user_id").map_err(db)?;
    let enrolment_id: String = prior.try_get("enrolment_id").map_err(db)?;
    // The username again, because recovering it is what the retry is FOR. Read
    // rather than stored a second time: duplicating personal data into this
    // ledger to answer a replay would put a second copy of it in the schema for
    // no gain.
    let external_id_ciphertext: Vec<u8> =
        sqlx::query_scalar("SELECT external_id_ciphertext FROM iam_user WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(db)?;

    Ok(Some(RedeemEnrolmentResponse {
        outcome: RedeemOutcome::Redeemed as i32,
        user_id,
        enrolment_id,
        external_id_ciphertext,
    }))
}

/// Why a redemption did not happen, decided by a SELECT rather than guessed.
///
/// Reached only when the check-and-spend UPDATE matched nothing, and it has to
/// tell three cases apart that the caller must be able to distinguish from a
/// broken store: the secret is unknown, it was already spent, or its deadline
/// has passed.
///
/// A SOFT-DELETED PERSON'S ENROLMENT IS `NOT_FOUND`. The join makes it so, and
/// the enum has no fourth arm to say anything else — as far as this boundary is
/// concerned there is no live enrolment for a live person, which is what
/// NOT_FOUND means.
pub(super) async fn unredeemable<'e, E>(
    executor: E,
    secret_hash: &[u8],
) -> Result<RedeemOutcome, Status>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let row = sqlx::query(
        "SELECT CAST(e.spent_at IS NOT NULL AS SIGNED) AS is_spent
           FROM iam_enrolment e JOIN iam_user u ON u.id = e.user_id
          WHERE e.secret_hash = ? AND u.deleted_at IS NULL",
    )
    .bind(secret_hash)
    .fetch_optional(executor)
    .await
    .map_err(db)?;

    let Some(row) = row else {
        return Ok(RedeemOutcome::NotFound);
    };
    match row.try_get::<i64, _>("is_spent").map_err(db)? {
        0 => Ok(RedeemOutcome::Expired),
        _ => Ok(RedeemOutcome::Spent),
    }
}
