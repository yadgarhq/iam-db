//! ADR-0972 (4): the per-user credential epoch, `iam_user.credential_epoch`.
//!
//! THE RACE IT CLOSES. `iam`'s Login reads the hash (`GetPasswordHash`),
//! verifies it, and mints (`CreateCredential`) in a separate transaction. A
//! reset or a revoke-all that committed between the read and the mint used to
//! leave the Login's credential alive after it. Now each of them bumps the
//! epoch inside its own transaction, `GetPasswordHash` returns the epoch in the
//! statement that reads the hash, and a mint carrying
//! `expected_credential_epoch` matches the user row only while the epoch is
//! unchanged (`credential::mint`).
//!
//! WHY A BUMP IS ENOUGH. The `UPDATE` below takes an exclusive lock on the user
//! row. A checked mint reads that row `LOCK IN SHARE MODE`, so a mint that
//! arrives while a bump is uncommitted waits for the commit and then reads the
//! new value. No writer here needs a lock of its own for the epoch.
//!
//! WHO BUMPS: every redemption that sets a password, flagged or not (§10 C1);
//! `RevokeAllCredentials`; `SetPassword`. Nothing else, and nothing ever sets
//! the column back.

use super::*;

/// Bump `user_id`'s epoch on `tx`, live or soft-deleted, and return how many
/// rows matched: one when the person has a row, zero when not.
///
/// For the two callers that already hold the user row: a redemption, whose
/// user exists because its spend joined it, and `RevokeAllCredentials`, which
/// tombstones a soft-deleted person's credentials too and bumps their epoch
/// for the same reason.
pub(super) async fn bump(
    tx: &mut sqlx::MySqlTransaction<'_>,
    user_id: &str,
) -> Result<u64, Status> {
    let done =
        sqlx::query("UPDATE iam_user SET credential_epoch = credential_epoch + 1 WHERE id = ?")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
    Ok(done.rows_affected())
}

/// Bump `user_id`'s epoch on `tx` only if the person is live, and return how
/// many rows matched.
///
/// `SetPassword`'s form. It runs BEFORE that handler's password write, so the
/// exclusive lock comes first and the write's own share lock on the same row
/// needs no upgrade: two concurrent calls queue on this statement instead of
/// both holding a share lock and deadlocking on the upgrade. Zero is the
/// handler's NOT_FOUND, decided before anything is written.
pub(super) async fn bump_live(
    tx: &mut sqlx::MySqlTransaction<'_>,
    user_id: &str,
) -> Result<u64, Status> {
    let done = sqlx::query(
        "UPDATE iam_user SET credential_epoch = credential_epoch + 1
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    Ok(done.rows_affected())
}

/// `user_id`'s epoch as `conn` sees it now.
///
/// Read on the caller's transaction: after a bump it is that bump's value, and
/// on a replayed redemption it is the CURRENT value rather than the first
/// delivery's, which a later bump may have made stale.
pub(super) async fn current(
    conn: &mut sqlx::MySqlConnection,
    user_id: &str,
) -> Result<u64, Status> {
    sqlx::query_scalar("SELECT credential_epoch FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(conn)
        .await
        .map_err(db)
}
