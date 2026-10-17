//! ADR-0943: a re-enrolment that revokes every credential its target holds.
//!
//! A reset replaces the password, and until this instruction existed it left
//! every bearer token the person already held resolving — so a reset done
//! because a device or a token leaked did not contain the leak (ledger 1569).
//!
//! THE INSTRUCTION IS DECIDED AT ISSUE TIME. [`INSERT`] writes it onto the
//! enrolment row, so it belongs to whoever authorised the issue, and nothing on
//! `RedeemEnrolmentRequest` can add, clear or override it. [`all`] executes it
//! inside the redemption transaction. [`compatible`] is the one refusal it adds:
//! the bootstrap demand never carries it.

use crate::service::*;

/// The ordinary arm CARRYING THE REVOKE INSTRUCTION.
///
/// **A THIRD STATEMENT RATHER THAN A BIND ON THE ORDINARY ONE**, so the
/// absent-field arm stays byte-identical to what it was and the bind list stays
/// the one both existing arms share — id, secret hash, expiry, user id. The only
/// difference is the constant written into `revoke_existing_credentials`, which
/// the redemption reads back inside its own transaction.
pub(super) const INSERT: &str = "INSERT INTO iam_enrolment
                 (id, user_id, secret_hash, expires_at, revoke_existing_credentials)
             SELECT ?, id, ?, FROM_UNIXTIME(?), 1 FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE";

/// Refuse the bootstrap demand carrying the revoke instruction.
///
/// A target that passes the demand holds zero credentials (ADR-0655 as amended
/// by ADR-0656), so there is nothing to revoke and the pair can only be a
/// malformed request — and the bootstrap path, the only caller that sets the
/// demand, must never carry this instruction. Decided from the REQUEST alone,
/// before any statement reads the target, so the refusal reveals nothing about
/// who the target is. That is why it may name the conflict, where the demand's
/// own refusal names nothing (ADR-0657).
pub(super) fn compatible(r: &CreateEnrolmentRequest) -> Result<(), Status> {
    match r.require_zero_credential_admin && r.revoke_existing_credentials {
        true => Err(Status::invalid_argument(
            "`revoke_existing_credentials` cannot be combined with \
             `require_zero_credential_admin`",
        )),
        false => Ok(()),
    }
}

/// Tombstone every live credential `user_id` holds, on the redemption's
/// transaction.
///
/// THE STATEMENT `RevokeCredential` RUNS, keyed on the person rather than on one
/// credential id: `revoked_at` is set, never a delete (D26), so "which
/// credential was used" stays answerable. `revoked_at IS NULL` keeps an earlier
/// revocation's timestamp, as the single-credential verb already does.
///
/// **ON `tx`, AND AHEAD OF THE PASSWORD WRITE**, and both placements are
/// load-bearing. On the transaction, so a redemption that fails afterwards
/// leaves every credential working; ahead of the password, so that failure is
/// the proof (`a_revoking_redemption_that_fails_partway_revokes_nothing`). The
/// credential `iam` mints next is created after the commit and is not touched,
/// and a replay of the redemption key never reaches this function.
///
/// The revoke does not reopen ADR-0655's bootstrap grant: ADR-0656's predicate
/// counts credential rows of any liveness, so a person whose credentials were
/// all revoked here is still outside it.
pub(super) async fn all(tx: &mut sqlx::MySqlTransaction<'_>, user_id: &str) -> Result<(), Status> {
    sqlx::query(
        "UPDATE iam_credential SET revoked_at = CURRENT_TIMESTAMP
          WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    Ok(())
}
