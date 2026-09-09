//! What applies to one person: the administrator flag, and the rate limits.
//!
//! Both write a row keyed on a user id that must be live, both are idempotent by
//! the shape of the write rather than by an idempotency key, and both are read
//! back by `ResolveCredential` in the same transaction as the credential itself.
//!
//! The ORGANISATION's and a TEAM's policy is `setting`, not this module. The line
//! between them is whose id keys the row.

use super::*;

impl IamDb {
    pub(super) async fn set_admin(
        &self,
        r: SetUserAdminRequest,
        call: Call,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        // `deleted_at IS NULL` for the reason every clause like it exists here:
        // promoting a soft-deleted person grants authority to an account nobody
        // expects to still act.
        //
        // Idempotent (D9) without a ledger because it ASSIGNS rather than
        // toggles — running it twice reaches the same state.
        let done =
            sqlx::query("UPDATE iam_user SET is_admin = ? WHERE id = ? AND deleted_at IS NULL")
                .bind(r.is_admin)
                .bind(&r.user_id)
                .execute(&self.pool)
                .await
                .map_err(db)?;

        // A MISTYPED USER ID MUST NOT REPORT SUCCESS, the same way
        // RevokeCredential refuses a credential id it does not recognise. This
        // grants or withdraws AUTHORITY: an OK for a write that promoted nobody
        // leaves an operator believing an admin exists, or believing one was
        // demoted while they still hold the flag.
        //
        // DISAMBIGUATED RATHER THAN INFERRED FROM THE ROW COUNT, because a
        // written-but-unconfirmed grant is worse than an explicit failure.
        // `sqlx-mysql` reports MATCHED rows, not CHANGED ones, so re-asserting a
        // flag a user already has still MATCHES that row and reports one, never
        // zero — zero here can only mean the WHERE clause found no live row for
        // this id. `live_user` below re-reads to turn that zero into NOT_FOUND
        // rather than a silent OK, and it answers NOT_FOUND whether the id is
        // unknown or the person is soft-deleted: this branch does not need to
        // tell the two apart, only to refuse reporting success for either.
        if done.rows_affected() == 0 {
            live_user(&self.pool, &r.user_id).await?;
        }

        call.finish(Outcome {
            status: "OK",
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(SetUserAdminResponse {}))
    }

    pub(super) async fn set_rate_limit(
        &self,
        r: SetRateLimitOverrideRequest,
        call: Call,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        // D74 puts system-initiated work outside this mechanism, so KIND_JOB and
        // KIND_UNSPECIFIED are never stored. Refused rather than written: a
        // bucket the gateway will never consult is a limit an operator believes
        // is in force and is not.
        if !matches!(
            ContractKind::try_from(r.kind),
            Ok(ContractKind::Read) | Ok(ContractKind::Write) | Ok(ContractKind::Generate)
        ) {
            return Err(Status::invalid_argument(
                "a rate-limit override must name READ, WRITE or GENERATE",
            ));
        }

        // The liveness check SetUserAdmin carries, on the neighbouring RPC. The
        // FOREIGN KEY proves the user row exists and says nothing about whether
        // the person is live, and `ResolveCredential` never reads a soft-deleted
        // person's overrides — so a limit stored against one is a limit an
        // operator believes is in force and is not. That is this handler's own
        // argument about KIND_JOB, applied to the user rather than to the kind.
        // THE TWO ARMS DECIDE LIVENESS DIFFERENTLY, AND THAT IS THE WHOLE OF
        // WHAT LEDGER 695 CHANGED HERE. A single `live_user` used to run ahead
        // of both. The SET arm now carries the predicate in its own statement;
        // the CLEAR arm keeps the separate check on purpose. Argued below at the
        // arm it applies to rather than in one place that fits neither.
        let done = match &r.limit {
            // Upsert onto the composite primary key — the same structural
            // idempotence AddTeamMember gets from iam_team_member's.
            //
            // THE PREDICATE IS IN THE STATEMENT (ledger 695), because a limit
            // stored for a person soft-deleted mid-call is exactly what this
            // handler's own paragraph above refuses: a limit an operator
            // believes is in force and that `ResolveCredential` never reads.
            //
            // `rate` AND `burst` BOUND TWICE RATHER THAN `VALUES()`, for
            // `SetPassword`'s reason — `VALUES()` names an `INSERT ... VALUES`
            // row and this is an `INSERT ... SELECT`.
            Some(limit) => {
                let done = sqlx::query(
                    "INSERT INTO iam_rate_limit_override (user_id, module, kind, rate, burst)
                     SELECT id, ?, ?, ?, ? FROM iam_user
                      WHERE id = ? AND deleted_at IS NULL
                      LOCK IN SHARE MODE
                     ON DUPLICATE KEY UPDATE rate = ?, burst = ?",
                )
                .bind(&r.module)
                .bind(r.kind)
                .bind(limit.rate)
                .bind(limit.burst)
                .bind(&r.user_id)
                .bind(limit.rate)
                .bind(limit.burst)
                .execute(&self.pool)
                .await
                .map_err(db)?;

                if done.rows_affected() == 0 {
                    live_user(&self.pool, &r.user_id).await?;
                }
                done
            }
            // ABSENT DELETES, restoring the deployment's configured default for
            // this bucket. A stored zero would not: that is a denial.
            //
            // THE CHECK STAYS A SEPARATE STATEMENT ON THIS ARM, AND THE RESIDUAL
            // RACE IS ARGUED HARMLESS RATHER THAN CLOSED. What the window lets
            // through is a DELETE of an override belonging to a person being
            // soft-deleted in the same instant — a row nothing will read again,
            // removed. There is no state an operator could be misled by, which
            // is the harm every other arm of this change is about. That is the
            // whole argument, and it is enough on its own.
            //
            // TWO ARGUMENTS THAT WOULD ALSO FIT HERE ARE FALSE, AND ARE NAMED SO
            // THAT NOBODY REACHES FOR THEM. Joining the predicate into the
            // DELETE does NOT newly make a soft-deleted person's override
            // unclearable: the unconditional `live_user` above already answers
            // NOT_FOUND for exactly that person, so the cost is paid whichever
            // shape this arm takes. Nor is closing it expensive — in the race
            // window a joined predicate would match nothing, giving `rows: 0`
            // with status OK, and `SetRateLimitOverrideResponse` is empty, so no
            // caller could observe the difference. This arm is left as it was
            // because it has no defect to fix, not because fixing it would cost
            // anything.
            //
            // AND IT IS NOT `RemoveTeamMember`'S ARGUMENT. That handler carries
            // NO liveness check at all, and its own comment names this arm as
            // "the same shape as this handler, answered the other way". Citing
            // it here would make two different decisions look like one.
            None => {
                live_user(&self.pool, &r.user_id).await?;
                sqlx::query(
                    "DELETE FROM iam_rate_limit_override
                      WHERE user_id = ? AND module = ? AND kind = ?",
                )
                .bind(&r.user_id)
                .bind(&r.module)
                .bind(r.kind)
                .execute(&self.pool)
                .await
                .map_err(db)?
            }
        };

        call.finish(Outcome {
            status: "OK",
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(SetRateLimitOverrideResponse {}))
    }
}
