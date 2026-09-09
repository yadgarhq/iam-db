//! The stored password hash, read and written.
//!
//! **NEITHER OF THESE EVER SEES A PASSWORD.** `iam` hashes and compares; this
//! boundary stores a PHC string and hands it back. Both are here rather than in
//! `credential` because the column is a different table with a different rule:
//! `iam_password` is separate from `iam_user` precisely so a query that reads a
//! person for display cannot pull the hash along with it.

use super::*;

impl IamDb {
    pub(super) async fn password_hash(
        &self,
        r: GetPasswordHashRequest,
        call: Call,
    ) -> Result<Response<GetPasswordHashResponse>, Status> {
        let row = sqlx::query(
            "SELECT u.id AS user_id, p.argon2id_hash
               FROM iam_user u
               JOIN iam_password p ON p.user_id = u.id
              WHERE u.external_id_blind_index = ?
                AND u.deleted_at IS NULL",
        )
        .bind(&r.username_blind_index)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;

        // An empty response for an unknown user. The CALLER must still perform a
        // dummy verification against a throwaway hash before answering — the
        // contract says so, and without it the response time distinguishes "no
        // such user" from "wrong password" and the endpoint enumerates accounts.
        // That cannot be enforced here; the timing that matters is the caller's.
        let resp = match row {
            Some(row) => GetPasswordHashResponse {
                user_id: row.try_get("user_id").map_err(db)?,
                argon2id_hash: row.try_get("argon2id_hash").map_err(db)?,
            },
            None => GetPasswordHashResponse::default(),
        };
        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    pub(super) async fn store_password(
        &self,
        r: SetPasswordRequest,
        call: Call,
    ) -> Result<Response<SetPasswordResponse>, Status> {
        // The same guard RedeemEnrolment applies, on the same column. Both write
        // it, so both check it — a guard on one writer and not the other is how
        // the class of bug this fixes gets reintroduced.
        fits_password_column(&r.argon2id_hash)?;

        // AND THE SAME SENTENCE APPLIES TO LIVENESS, WHICH IS WHY THIS IS HERE.
        // `RedeemEnrolment` writes `iam_password` under `user_id IN (SELECT id
        // FROM iam_user WHERE deleted_at IS NULL)`; this handler wrote the same
        // column with no such clause. Both write it, so both check it.
        //
        // THE LAST WRITE OF THE CLASS PR #29 SWEPT THAT A BORROWED GUARD FITS.
        // `RemoveTeamMember` still takes a `user_id`, still writes, and is
        // deliberately not guarded — not because it revokes, which decides
        // nothing here, but because every check this file could lend it is the
        // wrong one. Its handler carries that argument in full. This one was
        // missed because it HAS NO PRODUCTION CALLER — rotation is outside the first cut
        // (D73), so `iam` exposes no `SetPassword` and nothing in the estate
        // could demonstrate the hole. Guarded now rather than when rotation
        // arrives, so the author who builds rotation inherits a refusal instead
        // of a defect.
        //
        // THE REACHABLE HALF IS THE STATUS, not the liveness. Measured on
        // mariadb:11.8: an unknown `user_id` hits `fk_iam_password_user` and
        // renders through `db()` as UNAVAILABLE — a retryable status for a
        // request that can never succeed, so a client retries a typo forever.
        // That is the defect `SetInheritedSetting`'s team arm and
        // `SetRateLimitOverride` already refuse, and it is reachable today
        // through anything that speaks this contract.
        //
        // AFTER `fits_password_column`, DELIBERATELY. A malformed argument is
        // the caller's to fix whoever it names, and `CreateEnrolment` orders its
        // own expiry check ahead of `live_user` for the same reason.
        //
        // THE CHECK RIDES IN THE WRITE, and this handler is where the shape is
        // argued for the five that follow it (ledger 695, and ledger 704 for
        // `SetInheritedSetting`'s team arm, which that sweep left behind). A
        // `live_user` on the pool followed by an INSERT on the pool is TWO
        // statements with a round trip between them: a person soft-deleted
        // inside that window passed the check and got the password row anyway.
        // The predicate is now in the INSERT's own SELECT, so the row the
        // liveness is read from IS the row the write is derived from, and there
        // is no window between them.
        //
        // `SetUserAdmin` HAS ALWAYS HAD THIS SHAPE — its UPDATE carries
        // `deleted_at IS NULL` in its own WHERE and its `live_user` runs only on
        // a zero match. It was never in the racing set, and what closes the
        // other four is being made to look like it rather than being wrapped in
        // a transaction none of them otherwise needs.
        //
        // `LOCK IN SHARE MODE` RATHER THAN A BARE SELECT, AND IT IS MEASURED.
        // Against mariadb:11.8 holding an uncommitted soft delete on the
        // person's row, the write blocks on that row's exclusive lock either
        // way — but the bare form takes its own shared lock only at REPEATABLE
        // READ. At READ COMMITTED it fails with ER_CHECKREAD (1020), which
        // `db()` renders as UNAVAILABLE: a retryable status for a request that
        // can never succeed. With the clause the statement blocks, re-reads
        // under the lock and matches nothing at BOTH levels. This service sets
        // an isolation level only inside `RedeemEnrolment` and
        // `SetInheritedSetting`, so every statement here inherits the server's —
        // the clause is what stops the answer depending on how that server is
        // configured.
        //
        // THE HASH IS BOUND TWICE INSTEAD OF `VALUES()`. `VALUES()` names the
        // row of an `INSERT ... VALUES`, and what it means inside an
        // `INSERT ... SELECT` is not a question to settle by experiment on the
        // statement that stores a password. Two binds of one parameter say it
        // outright.
        let done = sqlx::query(
            "INSERT INTO iam_password (user_id, argon2id_hash)
             SELECT id, ? FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE
             ON DUPLICATE KEY UPDATE argon2id_hash = ?",
        )
        .bind(&r.argon2id_hash)
        .bind(&r.user_id)
        .bind(&r.argon2id_hash)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        // `live_user` KEPT, FOR THE ZERO ONLY — `SetUserAdmin`'s branch
        // verbatim. `sqlx` reports MATCHED rows, so zero cannot mean "the hash
        // was already that value"; it can only mean the SELECT found no live row
        // for this id. The re-read turns that into NOT_FOUND rather than a
        // silent OK, and answers the same whether the id is unknown or the
        // person is soft-deleted.
        if done.rows_affected() == 0 {
            live_user(&self.pool, &r.user_id).await?;
        }

        call.finish(Outcome {
            status: "OK",
            // FROM THE DRIVER, BECAUSE THE LITERAL `1` THIS REPLACES WAS ALREADY
            // FALSE. An `ON DUPLICATE KEY UPDATE` whose assignment genuinely
            // changes a stored value reports TWO — one for the attempted insert
            // and one for the update the engine counts separately — and
            // REPLACING a password hash is exactly that case. Measured through a
            // real pool: 1 on a first set, 1 on a repeat of the same hash, 2 on a
            // change. The constant was harmless only because rotation is outside
            // the first cut (D73) and this RPC has no caller yet.
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(SetPasswordResponse {}))
    }
}
