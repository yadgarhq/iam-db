//! `SetInheritedSetting`: the one administrative write with two levels.
//!
//! The operation is here. What the REQUEST means — the contract's clauses, the
//! team it names, and the read-back of both levels — is in `inherited`; D9's
//! ledger for this RPC, and the comparison that refuses a repeated key carrying a
//! different payload, is in `claim`.
//!
//! **READ COMMITTED IS PINNED IN THE OPERATION, NEVER ABOVE IT** (ADR-0513). The
//! `SET TRANSACTION` statement configures the NEXT transaction on the SAME
//! connection, so the acquire, the pin and the begin are one unit and stay one
//! unit.

use super::*;

mod claim;
mod inherited;

use claim::{recorded, Claim};
use inherited::{check_inherited_setting, read_inherited_setting, team_id_of};

impl IamDb {
    pub(super) async fn store_setting(
        &self,
        r: SetInheritedSettingRequest,
        call: Call,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        // ADR-0534's RECORDING HALF, and the whole of what this boundary does
        // with the field. It is written to the log and reaches nothing else: no
        // WHERE clause, no branch, no refusal. A request carrying an actor and
        // one carrying none take the identical path.
        //
        // THERE IS NO AUDIT STORE ON THIS BOUNDARY, so the structured log is
        // where an attribution can land today. Said plainly rather than implied:
        // the durable audit record ADR-0534 imagines does not exist here yet.
        //
        // ABSENT AND PRESENT-HOLDING-EMPTY ARE ONE CASE and are recorded as
        // unattributed, NEVER as an actor whose id is the empty string —
        // ADR-0512's collapse, pointed at the audit trail. `filter` is what keeps
        // them together; `unwrap_or_default` would write "" as an actor.
        tracing::info!(
            unverified_actor = r
                .unverified_actor
                .as_ref()
                .map(|a| a.user_id.as_str())
                .filter(|id| !id.is_empty())
                .unwrap_or("<unattributed>"),
            setting = %r.name,
            "an administrative write to an inheritable setting"
        );

        let scope = match check_inherited_setting(&r) {
            Ok(scope) => scope,
            Err(refusal) => {
                call.fail(label(&refusal));
                return Err(refusal);
            }
        };

        // READ COMMITTED, FOR THIS TRANSACTION ONLY (ADR-0513). It is a
        // correctness requirement rather than a tuning knob, and the argument is
        // `RedeemEnrolment`'s verbatim: under the engine's default REPEATABLE
        // READ a read view is established by the ledger read below, and MariaDB
        // then refuses a later write to a row a concurrent winner has changed
        // with 1020 `ER_CHECKREAD` rather than re-evaluating — which `db()`
        // renders as UNAVAILABLE, turning a retry that should replay into a
        // spurious 503.
        //
        // LEDGER 704 GAVE THIS STATEMENT A SECOND JOB, and it is the team arm's
        // rather than the ledger's. The `INSERT ... SELECT` below re-reads the
        // team's liveness under a shared lock, and only at READ COMMITTED does
        // the `live_team` that names its zero see a delete that committed while
        // that statement waited. So this line is load-bearing for two
        // independent reasons.
        //
        // MEASURED (ledger 741, MariaDB 11.8.9), AND THE FAILURE DEPENDS ON
        // WHETHER AN IDEMPOTENCY KEY WAS SENT. With a key, `recorded()` below
        // runs a plain read first and fixes the transaction's REPEATABLE READ
        // snapshot before the team row is touched; the later `INSERT ...
        // SELECT ... LOCK IN SHARE MODE` then becomes a SECOND read against a
        // row the snapshot already covers, and MariaDB raises 1020
        // `ER_CHECKREAD` rather than re-evaluating — which `db()` renders
        // UNAVAILABLE, a retryable 503 for a write that can never succeed.
        // Without a key, that `INSERT ... SELECT` is the transaction's FIRST
        // read, and a locking read is isolation-level-independent: it matches
        // latest committed data regardless, so removing the pin changes
        // nothing observable on that path. Neither path answers OK with
        // `rows: 0` for a team that is gone. See `tests/contract.rs`,
        // `a_team_soft_delete_landing_after_the_idempotency_read_still_refuses_an_inherited_setting_override`.
        //
        // `SET TRANSACTION` WITHOUT `SESSION` OR `GLOBAL` applies to the NEXT
        // transaction and then reverts, so a pooled connection carries nothing to
        // its next borrower. That is what forces `acquire()` then
        // `Acquire::begin` rather than `pool.begin()`: the statement and the
        // transaction it configures must be the same connection.
        let mut conn = self.pool.acquire().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        let mut tx = sqlx::Acquire::begin(&mut *conn).await.map_err(db)?;

        // D9's LEDGER, and the amended half of D9 is what it is for. The key
        // replayed returns the setting; the key carrying a DIFFERENT request is
        // refused with INVALID_ARGUMENT rather than silently overwriting the
        // first one.
        //
        // A PLAIN READ, deliberately NOT `FOR UPDATE`. This catches a retry that
        // arrives after the first attempt COMMITTED, which is the ordinary case.
        // It cannot serialise two deliveries that arrive together, and no lock
        // taken here could: an InnoDB gap lock on an absent row is purely
        // inhibitive — it blocks an INSERT into the gap and does NOT exclude
        // another transaction's gap lock on the same gap, so taking it turns the
        // race into a deadlock rather than preventing it (ADR-0513). The
        // serialisation point is the ledger INSERT further down, which takes a
        // REAL record lock.
        let claim = Claim::of(&r);
        if !claim.key.is_empty() {
            if let Some(prior) = recorded(&mut tx, &claim.key, Lock::No).await? {
                claim.agrees_with(&prior)?;
                // **NOTHING IS WRITTEN ON THIS PATH.** The verb is a
                // state-setter, so re-running it would reach the same state — but
                // re-running it after somebody else legitimately changed the
                // level would UNDO their change and report success, which is the
                // silent overwrite the ledger exists to stop.
                //
                // THE OUTCOME IS RE-DERIVED RATHER THAN STORED, and the contract
                // says why: this RPC is not in ADR-0519's single-use-secret
                // carve-out, because the outcome is the stored setting and the
                // store keeps it. There is nothing spent to hand back.
                let setting = read_inherited_setting(&mut tx, &r.name).await?;
                tx.commit().await.map_err(db)?;
                call.finish(Outcome {
                    status: "OK",
                    ..Default::default()
                });
                return Ok(Response::new(SetInheritedSettingResponse {
                    setting: Some(setting),
                }));
            }
        }

        let done = match (scope, r.clear) {
            // Upsert onto the primary key, the idempotence
            // `SetRateLimitOverride` gets from the same shape. Migration 12 seeds
            // this row, so in practice this always updates — the INSERT arm is
            // what makes the handler correct against a deployment whose row was
            // deleted rather than one that trusts a seed.
            (SettingScope::Org, _) => {
                sqlx::query(
                    "INSERT INTO iam_org_setting (name, value, locked) VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE value = VALUES(value), locked = VALUES(locked)",
                )
                .bind(&r.name)
                // Both `expect`s are discharged by `check_inherited_setting`,
                // which refuses an absent value and an absent lock at this scope
                // before anything reaches here.
                .bind(r.value.expect("validated present at organisation scope"))
                .bind(r.locked.expect("validated present at organisation scope"))
                .execute(&mut *tx)
                .await
                .map_err(db)?
            }
            // THE WITHDRAWAL (ADR-0524). It DELETES rather than storing
            // SETTING_VALUE_UNSPECIFIED, for the reason migration 11 gives:
            // absence is how a team states nothing, and a stored zero would be an
            // absent row wearing a disguise — one the table's own CHECK would
            // refuse anyway.
            //
            // NO LIVENESS CHECK ON THE TEAM, unlike the set arm below, and the
            // asymmetry is deliberate. A clear names a ROW TO REMOVE rather than
            // a team to write to, so there is no foreign key to satisfy; and
            // migration 11 says clearing the override a soft-deleted team strands
            // is the job of whichever RPC does that deletion. Refusing here would
            // leave that RPC with no verb to call.
            (SettingScope::Team, true) => {
                sqlx::query("DELETE FROM iam_team_setting_override WHERE name = ? AND team_id = ?")
                    .bind(&r.name)
                    .bind(team_id_of(&r))
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?
            }
            (SettingScope::Team, false) => {
                // THE FOREIGN KEY IS NOT THE ERROR MESSAGE. Left to fire, an
                // unknown team renders through `db()` as UNAVAILABLE — a
                // retryable status for a request that can never succeed. The
                // check is `SetRateLimitOverride`'s `live_user`, applied to the
                // team.
                //
                // THE PREDICATE RIDES IN THE INSERT (ledger 704), AND A SHARED
                // TRANSACTION IS NOT WHAT PUT IT THERE. Ledger 695 moved five
                // handlers' predicates into their write statements and left this
                // one, on the belief that a check and a write inside one
                // transaction cannot come apart. Measured false: a transaction
                // buys ATOMICITY, which is a different property from "the row I
                // checked is still the row I am writing against". `live_team` is
                // a plain non-locking SELECT wherever it runs, so the check read
                // a snapshot in which the team was live, this upsert then blocked
                // on `fk_iam_team_setting_override_team`'s shared lock while the
                // deleter committed, and the override landed for a team whose
                // `deleted_at` was set — which `read_inherited_setting` handed
                // back as in force. Migration 11 carries the same correction.
                //
                // `LOCK IN SHARE MODE` IS NOT WHAT CLOSES THE RACE, AND SAYING
                // OTHERWISE MISNAMES BOTH HALVES. What closes it is the predicate
                // being IN the write: the row liveness is read from is the row
                // written against, re-read after the deleter commits. The clause
                // buys something narrower and still mandatory — a bare
                // `INSERT ... SELECT` raises 1020 `ER_CHECKREAD` at READ
                // COMMITTED and matches nothing at REPEATABLE READ, and `db()`
                // renders the former as UNAVAILABLE, shipping a retryable status
                // for a request that can never succeed.
                //
                // WHAT THE CLAUSE COSTS, SPLIT BY CASE RATHER THAN CALLED FREE.
                // Wherever the team ROW EXISTS — live or soft-deleted — it costs
                // nothing: InnoDB's foreign-key parent-existence check is itself
                // a locking read and takes S on `iam_team` before the child row
                // lock, so this only makes explicit a lock the engine was already
                // taking. On an UNKNOWN team it is a genuinely new lock, because
                // the old `live_team` refused before the INSERT ran and the
                // foreign key never fired. It is small and it is measured: a
                // shared lock on a MISSING primary key takes a supremum gap lock
                // at REPEATABLE READ, and at the READ COMMITTED this handler pins
                // it is 30ms. Unlike the five siblings, which run autocommit
                // single statements, this one holds it to the end of a
                // transaction that still has the claim INSERT and the read-back
                // to do — so the hold is the transaction's rather than the
                // statement's. Negligible, not absent.
                //
                // `VALUES(value)` DOES NOT SURVIVE THE REWRITE — it names a
                // column of an `INSERT ... VALUES` row, which no longer exists —
                // so the value is bound twice, `SetRateLimitOverride`'s shape.
                // The transposition hazard that shape carries does not arise:
                // there is one data column, and nothing to swap it with.
                //
                // THE ASSIGNMENT IS QUALIFIED because an unqualified column on
                // the left of `ON DUPLICATE KEY UPDATE` inside an
                // `INSERT ... SELECT` is ambiguous (1052) under sqlx's binary
                // protocol, `AddTeamMember`'s reason.
                let done = sqlx::query(
                    "INSERT INTO iam_team_setting_override (name, team_id, value)
                     SELECT ?, id, ? FROM iam_team
                      WHERE id = ? AND deleted_at IS NULL
                      LOCK IN SHARE MODE
                     ON DUPLICATE KEY UPDATE iam_team_setting_override.value = ?",
                )
                .bind(&r.name)
                .bind(r.value.expect("validated present unless clear is set"))
                .bind(team_id_of(&r))
                .bind(r.value.expect("validated present unless clear is set"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;

                // `live_team` IS KEPT ONLY TO NAME THE ZERO, never to guard the
                // write. A zero match says the SELECT found no live team, and the
                // FOREIGN KEY left to fire would have said UNAVAILABLE for both an
                // unknown team and a soft-deleted one.
                //
                // MEASURED (ledger 741): removing this handler's READ COMMITTED
                // pin does not make this re-read answer OK with `rows: 0` for a
                // team that is gone. When the request carries an idempotency
                // key, `recorded()` above already fixed a REPEATABLE READ
                // snapshot before the team row was touched, so the `INSERT ...
                // SELECT` further up — not this read — is the one that fails
                // first, with 1020 `ER_CHECKREAD`, which `db()` renders
                // UNAVAILABLE; this line is never reached on that path. Without
                // a key, the `INSERT ... SELECT` is the transaction's first
                // read and is isolation-level-independent, so it already
                // matches the committed delete and this line correctly finds
                // none. Neither path lets a gone team come back as OK.
                if done.rows_affected() == 0 {
                    live_team(&mut *tx, team_id_of(&r)).await?;
                }
                done
            }
            // `check_inherited_setting` refuses UNSPECIFIED and every number this
            // enum does not declare, so this arm is unreachable. It is a refusal
            // rather than an `unreachable!()`: a panic in a handler takes the
            // whole process down, and this arm's whole subject is a value that
            // arrived from the wire.
            (SettingScope::Unspecified, _) => {
                let refusal =
                    Status::invalid_argument("scope names no level this contract declares");
                call.fail(label(&refusal));
                return Err(refusal);
            }
        };

        // THE CLAIM IS RECORDED LAST, AND THE INSERT IS THE SERIALISATION POINT.
        // A record lock on a real row, never a gap lock on an absent one — which
        // is the shape ADR-0513 says does NOT have the defect it was written
        // about, and which is available here because there is no secret to spend
        // in the same transaction.
        //
        // A DUPLICATE KEY MEANS A CONCURRENT DELIVERY COMMITTED FIRST. The loser
        // blocks on that lock until the winner commits, so the re-check below is
        // the branch ADR-0513 requires — the one where the work turns out already
        // done. Both deliveries did the work, which is harmless because the verb
        // ASSIGNS; what the re-check adds is the refusal when the two payloads
        // differ, and the rollback that unwinds the loser's write.
        if !claim.key.is_empty() {
            if let Err(e) = claim.record(&mut tx).await {
                let duplicate = e
                    .as_database_error()
                    .is_some_and(|d| d.is_unique_violation());
                if !duplicate {
                    return Err(db(e));
                }
                let prior = recorded(&mut tx, &claim.key, Lock::Yes)
                    .await?
                    .ok_or_else(|| {
                        // The row that made the INSERT fail is visible to any
                        // read that follows it at READ COMMITTED, so this cannot
                        // happen — and if it ever does, it is a broken store
                        // rather than a caller's mistake.
                        tracing::error!(
                            "a duplicate idempotency key vanished before it could be re-read"
                        );
                        Status::unavailable("storage unavailable")
                    })?;
                claim.agrees_with(&prior)?;
            }
        }

        // THE SETTING WHOLE, read in the transaction that wrote it. NOT the echo
        // D48 refuses: the caller sent one level, and what goes back is the other
        // level and every OTHER team's override — which the caller did not send
        // and has no administrative read verb to fetch.
        let setting = read_inherited_setting(&mut tx, &r.name).await?;
        tx.commit().await.map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(SetInheritedSettingResponse {
            setting: Some(setting),
        }))
    }
}
