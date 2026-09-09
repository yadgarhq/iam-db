//! Who exists, and who is in which team.
//!
//! Creating a person and moving one in and out of a team are one module because
//! they are one question asked three ways, and because all three carry the same
//! guard: a soft-deleted person is not a person any of them may act on.
//!
//! What a person is ALLOWED is next door in `policy`. The split is between the
//! rows that say somebody is here and the rows that say what applies to them.

use super::*;

impl IamDb {
    pub(super) async fn insert_user(
        &self,
        r: CreateUserRequest,
        call: Call,
    ) -> Result<Response<CreateUserResponse>, Status> {
        // `idempotency` IS DISCARDED HERE, AND A RETRY IS NOT A REPLAY. The
        // UNIQUE below turns a redelivered CreateUser into ALREADY_EXISTS, so a
        // caller whose first response was lost never learns the `meta.id` that
        // attempt returned — and this boundary has no verb that would find it,
        // because `external_id_blind_index` is one-way and `GetPasswordHash`
        // answers only for a user who already has a password row. `iam` forwards
        // a key on this hop today. See the module header.
        let id = format!("yadgar:user:{}", uuid::Uuid::now_v7());
        sqlx::query(
            // is_admin is set AT CREATION rather than by a follow-up
            // SetUserAdmin, because D73's first admin has to exist before there
            // is anyone able to log in and promote one.
            "INSERT INTO iam_user
                 (id, created_by, updated_by,
                  external_id_blind_index, external_id_ciphertext, display_name_ciphertext,
                  is_admin)
             VALUES (?, 'system', 'system', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&r.external_id_blind_index)
        .bind(&r.external_id_ciphertext)
        .bind(&r.display_name_ciphertext)
        .bind(r.is_admin)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // The UNIQUE on the blind index is what makes this reachable, and
            // saying "already exists" is safe: the caller supplied the index, so
            // it learns nothing it did not already know.
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                Status::already_exists("a user with that name already exists")
            }
            _ => db(e),
        })?;

        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateUserResponse {
            meta: Some(Meta {
                id,
                version: 1,
                ..Default::default()
            }),
        }))
    }

    pub(super) async fn add_member(
        &self,
        r: AddTeamMemberRequest,
        call: Call,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        // `INSERT IGNORE` SWALLOWED BOTH FOREIGN KEYS, WHICH IS WHY THIS RPC
        // REPORTED SUCCESS FOR A ROW THAT NEVER LANDED. IGNORE downgrades a
        // foreign-key violation to a WARNING: an unknown team or an unknown
        // person inserted nothing, raised nothing, and the handler answered OK.
        // An operator was told the membership was granted, no read will ever
        // return it, and nothing was recorded anywhere to contradict either.
        //
        // The IGNORE was there for the DUPLICATE alone. `ON DUPLICATE KEY UPDATE`
        // keeps that idempotence and swallows nothing else, and the assignment is
        // a no-op on purpose: a repeat must not move `added_by` or `added_at`,
        // which record when the person actually joined rather than when somebody
        // last asked.
        //
        // CHECKED RATHER THAN LEFT TO FIRE, the way SetInheritedSetting's team arm
        // and SetRateLimitOverride's user already are. An unrecognised id rendered
        // through `db()` is UNAVAILABLE — a retryable status for a request that
        // can never succeed, so a client retries a mistake forever.
        //
        // `live_team` and `live_user` rather than "the row is there", because a
        // FOREIGN KEY answers the second question and this boundary needs the
        // first: `ResolveCredential` joins `deleted_at IS NULL`, so a team granted
        // to a removed person is a membership no read returns. That is the same
        // class the three writes above already refuse.
        // Idempotent (D9) by the composite primary key: two concurrent inserts
        // of the same (team_id, user_id) cannot create two rows, only one write
        // and one no-op UPDATE.
        //
        // BOTH PREDICATES RIDE IN THE INSERT (ledger 695), which is the only
        // handler here that needs two. `live_team` and `live_user` used to run
        // ahead of it on the pool, and a person OR a team soft-deleted in the
        // window between them and this statement still got a membership row —
        // soft-delete does not cascade, only `ON DELETE CASCADE` does, and
        // nothing re-checked liveness at write time.
        //
        // `CROSS JOIN` RATHER THAN A MISSING `ON`. The two ids are independent
        // and each `WHERE` clause selects at most one row, so the product is one
        // row or none; there is no join key between these tables to state. It is
        // spelled out because an unqualified `JOIN` here reads as a lost
        // condition.
        //
        // ONE STATEMENT, TWO ANSWERS — hence the pair of re-reads below rather
        // than one. A zero match says only that the product was empty; which of
        // the two ids emptied it is what the caller needs, and `live_team`
        // before `live_user` keeps the order this handler answered in before.
        let done = sqlx::query(
            "INSERT INTO iam_team_member (team_id, user_id, added_by)
             SELECT t.id, u.id, 'system'
               FROM iam_team t CROSS JOIN iam_user u
              WHERE t.id = ? AND t.deleted_at IS NULL
                AND u.id = ? AND u.deleted_at IS NULL
              LOCK IN SHARE MODE
             ON DUPLICATE KEY UPDATE iam_team_member.team_id = iam_team_member.team_id",
        )
        .bind(&r.team_id)
        .bind(&r.user_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        if done.rows_affected() == 0 {
            live_team(&self.pool, &r.team_id).await?;
            live_user(&self.pool, &r.user_id).await?;
        }

        call.finish(Outcome {
            status: "OK",
            // FROM THE DRIVER RATHER THAN A LITERAL, AND IT IS THE SAME NUMBER
            // TODAY. `sqlx-mysql` hardcodes `Capabilities::FOUND_ROWS` into the
            // client capability set (`connection/stream.rs`), masks it against
            // what the server advertises, and exposes no `MySqlConnectOptions`
            // knob to turn it off — so every statement this service runs reports
            // MATCHED rows rather than CHANGED ones. RE-MEASURED THROUGH A REAL
            // POOL AFTER LEDGER 695 CHANGED THE STATEMENT, because a number
            // sourced from the driver is only honest while somebody checks it
            // against the statement it comes from: the `INSERT ... SELECT` form
            // reports 1 on a fresh membership and 1 on every repeat, exactly as
            // the `INSERT ... VALUES` form did. The literal `1` this replaces was
            // correct in each case the handler can still reach.
            //
            // THE THIRD OUTCOME DOES NOT ARISE HERE. An `ON DUPLICATE KEY UPDATE`
            // whose assignment CHANGES a value reports 2 — `SetPassword` and
            // `SetRateLimitOverride` both do, measured — and this one assigns a
            // primary-key column to itself on purpose, so it never changes
            // anything. Zero is the remaining case, and it returns NOT_FOUND
            // above unless BOTH re-reads disagree — `CreateCredential` says why
            // nothing can make them, and what closing that properly needs.
            //
            // WHAT IT BUYS IS THAT THE NUMBER FOLLOWS THE STATEMENT. If the
            // statement changes, or the driver's capability set does, the record
            // moves with it instead of staying a constant somebody has to
            // remember to revisit.
            //
            // WHAT IT DOES NOT BUY IS TELLING A FRESH MEMBERSHIP FROM A REPEAT,
            // and under FOUND_ROWS no count from this statement can. The one case
            // where the constant genuinely lied — a row the foreign keys dropped
            // while the handler answered OK — is unreachable now that those
            // violations are refused above rather than ignored.
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(AddTeamMemberResponse {}))
    }

    pub(super) async fn remove_member(
        &self,
        r: RemoveTeamMemberRequest,
        call: Call,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        // NO `live_user`, NO `live_team`, AND NO EXISTENCE CHECK — DECIDED,
        // rather than the sweep stopping one short again. `AddTeamMember` above
        // refuses an unrecognised id; this one answers OK with `rows: 0`.
        // `SetPassword` WAS guarded in the same change that wrote this comment,
        // so the pair is one decision rather than two.
        //
        // THE REASON IS NOT "A LIVENESS GUARD BELONGS ON A GRANT", AND THAT RULE
        // IS RECORDED HERE ONLY TO STOP THE NEXT READER REACHING FOR IT. This
        // file refutes it twice. `SetRateLimitOverride`'s absent-limit arm IS a
        // DELETE and `live_user` runs unconditionally ahead of it, so clearing an
        // override for an unknown person is NOT_FOUND — the same shape as this
        // handler, answered the other way. And `SetUserAdmin` is guarded in BOTH
        // directions, its comment naming the demotion case explicitly: "an OK for
        // a write that promoted nobody leaves an operator believing an admin
        // exists, or believing one was demoted while they still hold the flag."
        // Taking reach away is not what makes a write safe to leave unchecked.
        //
        // WHAT DECIDES IT IS THAT EVERY AVAILABLE CHECK IS THE WRONG ONE. The
        // borrowable guard is `live_user`/`live_team`, and both would REFUSE
        // work that must stay possible: migration 11 records that a soft delete
        // is an UPDATE no `ON DELETE CASCADE` can see, so a future team deletion
        // strands memberships that THIS CALL is the only way to clear, and
        // `live_team` would refuse exactly that retry. Nor would either catch the
        // defect worth catching — a mistyped `team_id` naming a team that never
        // existed. The check that fits is EXISTENCE rather than liveness, which
        // has no helper in this file and no precedent on this boundary; the
        // foreign key already guarantees a never-created team stranded nothing,
        // so it would refuse only the typo. Adding it is a change to be argued on
        // its own evidence, not a line borrowed from a neighbour.
        //
        // AND THE DEFECT PR #29 CLOSED DOES NOT REACH THIS HANDLER. That one was
        // a FOREIGN KEY left to fire, rendering through `db()` as UNAVAILABLE —
        // a retryable status for an impossible request. A DELETE naming a row
        // that is not there violates no constraint: it is a no-op that already
        // answers with a status a caller can act on. There is nothing of that
        // class here to fix.
        //
        // WHAT IS GIVEN UP IS REAL, AND IT IS AN ASYMMETRY IN THE WORSE
        // DIRECTION. After PR #29 a mistyped `team_id` on a GRANT is NOT_FOUND;
        // the same typo on this REVOCATION is OK, and the caller cannot tell:
        // `RemoveTeamMemberResponse` is empty and `rows` reaches the telemetry
        // record only, never the wire. An operator who mistypes believes they
        // removed an access they did not. The no-op is visible ONLY as
        // `rows_returned: 0` ON THIS SERVICE'S OWN RECORD — `iam`'s relay
        // finishes its `Outcome` with `status: "OK"` and no `rows` at all, so the
        // signal does not even reach the hop the operator is nearer to.
        //
        // `SetInheritedSetting`'s CLEAR arm names a team that was never created
        // and succeeds, which is the one precedent pointing this way — but it
        // supports the STATUS CODE and not the silence, and the distinction is
        // the whole cost above: `SetInheritedSettingResponse` carries every
        // team's override, so a mistyped clear is detectable from the answer.
        // This response carries nothing.
        //
        // CLOSING IT NEEDS THE CONTRACT, WHICH IS NOT THIS REPOSITORY'S TO
        // CHANGE. The honest fix is an outcome on the response — what
        // `RedeemEnrolment` does with `RedeemOutcome` — so the caller learns a
        // removal matched nothing without the boundary having to guess why.
        // `proto/` here is VENDORED from `yadgarhq/proto` at the tag in
        // `PROTO_VERSION` and CI fails on any diff (D70), so the field and this
        // handler have to arrive together across two repositories, the way the
        // module header says the idempotency ledger does. A NOT_FOUND for a
        // never-created team needs no contract change and could land alone; it
        // is the silence on a REAL team that cannot be fixed from here.
        let done = sqlx::query("DELETE FROM iam_team_member WHERE team_id = ? AND user_id = ?")
            .bind(&r.team_id)
            .bind(&r.user_id)
            .execute(&self.pool)
            .await
            .map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(RemoveTeamMemberResponse {}))
    }
}
