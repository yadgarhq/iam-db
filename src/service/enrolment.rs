//! Minting an enrolment secret, and spending one.
//!
//! `redeem` is the only RPC in this crate that spends something: the secret is
//! marked used and the password is written in ONE transaction, because a crash
//! between the two leaves an enrolment spent and an account with no password.
//! Its idempotency ledger — the replay read and the table it reads — is in the
//! `ledger` child, so this file is the operations and that one is what makes a
//! second delivery safe.
//!
//! The bootstrap-enrolment demand — ADR-0655's predicate as ADR-0656 amends it,
//! and ADR-0657's single refusal — is in the `demand` child for the same reason:
//! this file is what `CreateEnrolment` DOES, and that one is the authorization
//! decision it takes on the way, with the whole of the reasoning beside the
//! statement that carries it.
//!
//! ADR-0943's revoke instruction — a re-enrolment that withdraws every
//! credential its target holds when it is redeemed — is in the `revoke` child:
//! the statement that records it, the statement that executes it, and the one
//! refusal it adds. ADR-0972 (5)'s void of the person's other enrolments is
//! there too, beside the revoke it rides with.
//!
//! The redemption's statements after the idempotency check — the owner's lock,
//! the spend, and the refused and redeemed ends — are in the `redeem` child.

use super::*;

mod declared;
mod demand;
mod ledger;
mod redeem;
pub(super) mod revoke;

use ledger::replay;
use redeem::{lock_owner, redeemed, spend, unspent};

/// The demand arm's statement, reachable by the contract test.
///
/// **EXPORTED SO THE LOCK PROBE RUNS THE STATEMENT ITSELF**, never a
/// transcription of it. Whether this statement's locking read actually blocks a
/// concurrent redemption's `iam_password` insert is the measurement the
/// single-statement shape rests on, and a probe holding its own copy of the SQL
/// would keep passing after the real one changed — which is the whole class of
/// false green this predicate cannot afford. Same argument as [`IamDb::pool`],
/// which is public for the test's benefit and for no caller's.
pub use demand::INSERT as DEMAND_INSERT;

pub use declared::BOOTSTRAP_REENROLMENT;

impl IamDb {
    pub(super) async fn mint_enrolment(
        &self,
        r: CreateEnrolmentRequest,
        rid: &str,
        call: Call,
    ) -> Result<Response<CreateEnrolmentResponse>, Status> {
        // ADR-0534's RECORDING HALF. `r.user_id` is the TARGET — the person being
        // enrolled — and is passed as such; the actor is the separate field.
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "CreateEnrolment",
            &seg(&r.user_id),
        );

        idempotency_sensor(&r);

        // Explicit, because the alternative is worse than a rejection. The
        // column is NOT NULL, so FROM_UNIXTIME(NULL) makes the engine refuse
        // under STRICT_TRANS_TABLES — and `db()` renders every engine error as
        // "storage unavailable", which would report a caller's mistake as this
        // service being down.
        let expires_at = r
            .expires_at
            .ok_or_else(|| Status::invalid_argument("an enrolment must carry an expiry"))?;

        // TEAM-DERIVED ADMIN ON, AND THE DEMAND SET: ADR-0966's declared-
        // administrator predicate in place of ADR-0656's, and the revoke
        // instruction admitted beside it (ADR-1014 point 2). Taken BEFORE
        // `revoke::compatible`, so the derivation-off path below — the refusal
        // of the pair included — is byte-identical to what it was.
        if r.require_zero_credential_admin && r.admin_from_team {
            return declared::issue(&self.pool, &r, expires_at.seconds, rid, call).await;
        }

        if let Err(refusal) = revoke::compatible(&r) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        // The FOREIGN KEY proves the user row EXISTS; it does not prove the
        // person is live. Without the predicate below, an enrolment minted for a
        // soft-deleted account is accepted, reported OK, and is then permanently
        // NOT_FOUND on redeem — because the redemption path DOES check. An admin
        // would be told the enrolment was issued and the person could never use
        // it.
        //
        // IN THE INSERT RATHER THAN AHEAD OF IT (ledger 695), on `SetPassword`'s
        // argument. `RedeemEnrolment` already spends under `user_id IN (SELECT
        // id FROM iam_user WHERE deleted_at IS NULL)`, so the pair of RPCs now
        // decides liveness the same way at both ends of one enrolment's life.
        let id = format!("yadgar:enrolment:{}", uuid::Uuid::now_v7());

        let sql = statement(
            r.require_zero_credential_admin,
            r.revoke_existing_credentials,
        );
        let done = sqlx::query(sql)
            .bind(&id)
            .bind(&r.secret_hash)
            .bind(expires_at.seconds)
            .bind(&r.user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(d) if d.is_unique_violation() => {
                    Status::already_exists("that enrolment secret is already in use")
                }
                _ => db(e),
            })?;

        // A DUPLICATE SECRET STILL WINS OVER A DEAD USER, and it cannot reach
        // this branch: a soft-deleted person's SELECT yields no row, so the
        // unique index is never consulted and the arm above never fires. The two
        // refusals do not compete.
        if done.rows_affected() == 0 {
            live_user(&self.pool, &r.user_id).await?;

            // THE ZERO IS NAMED IN THE DEMAND ARM'S ORDER: liveness first, which
            // is the NOT_FOUND this handler has always answered, then the
            // conjunct. Guarded on the flag rather than on the zero alone,
            // because on the ordinary arm a live user with no row inserted is a
            // state no statement can reach — and inventing a PERMISSION_DENIED
            // for it would change the absent-field path this plan holds fixed.
            if r.require_zero_credential_admin {
                let refusal = demand::refuse(&self.pool, &r.user_id).await;
                call.fail(label(&refusal));
                return Err(refusal);
            }
        }

        call.finish(Outcome {
            status: "OK",
            // A LITERAL FOR THE SAME REASON `CreateCredential`'s is, and with
            // the same narrowing: one row or none, and none returns NOT_FOUND
            // unless the re-read disagrees. That handler carries the argument,
            // including what a fabricated `enrolment_id` would cost if it could
            // happen.
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateEnrolmentResponse { enrolment_id: id }))
    }

    pub(super) async fn redeem(
        &self,
        mut r: RedeemEnrolmentRequest,
        call: Call,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        // ONE TRANSACTION, AND IT IS THE WHOLE POINT OF THIS RPC. Spending the
        // secret and setting the password cannot be separate calls and cannot be
        // separate statements: a crash between a mark-as-spent and a password
        // write leaves the enrolment spent and the account with no password, D73
        // gives no resend, and the person is locked out of an account whose
        // password was never set. Everything below runs on `tx` — a statement
        // that reaches for `&self.pool` instead has silently left the
        // transaction and undone this.
        let mut conn = self.pool.acquire().await.map_err(db)?;

        // READ COMMITTED, FOR THIS TRANSACTION ONLY, and it is a correctness
        // requirement rather than a tuning knob. Two properties of the engine's
        // default REPEATABLE READ each break the concurrent retry this RPC has
        // to survive:
        //
        //   - A read view is established by the first consistent read — the
        //     ledger check below. The spend UPDATE then finds a row that a
        //     concurrent winner has changed since, and MariaDB refuses with 1020
        //     `ER_CHECKREAD` ("Record has changed since last read") rather than
        //     re-evaluating. `db()` renders that as UNAVAILABLE, so a retry that
        //     should have replayed becomes a spurious 503.
        //   - Gap locks. A locking read of an ABSENT idempotency key takes one,
        //     it does not exclude the other transaction's, and it does block the
        //     other transaction's INSERT — so locking the ledger first turns the
        //     race into a deadlock instead of preventing it.
        //
        // Under READ COMMITTED there are no gap locks and an UPDATE re-evaluates
        // its WHERE against the latest committed row, matching nothing and
        // reporting zero. That zero is what the branch below is written to read.
        //
        // Correctness does not rest on repeatable reads here: it rests on the
        // row lock the spend takes. `SET TRANSACTION` without SESSION or GLOBAL
        // applies to the NEXT transaction and then reverts, so this leaves no
        // trace on a pooled connection the next caller will get.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        let mut tx = sqlx::Acquire::begin(&mut *conn).await.map_err(db)?;

        // THE IDEMPOTENCY CHECK COMES FIRST, before anything looks at the
        // presented secret. The contract is explicit that the comparison
        // PRECEDES THE LOOKUP: a refusal issued after the lookup would itself
        // report whether that secret exists.
        let key = r.idempotency.take().map(|i| i.key).unwrap_or_default();
        if !key.is_empty() {
            // A PLAIN READ, and deliberately NOT `FOR UPDATE`. This catches a
            // retry that arrives after the first attempt COMMITTED, which is the
            // ordinary case. It cannot serialise two deliveries that arrive
            // TOGETHER, and no lock taken here could: an InnoDB gap lock on a
            // row that does not exist is purely inhibitive — it blocks an INSERT
            // into the gap and does NOT exclude another transaction's gap lock
            // on the same gap. Two concurrent `FOR UPDATE` reads of one absent
            // key both return nothing and both proceed.
            //
            // Taking the lock anyway would make it worse rather than better:
            // each transaction's gap lock blocks the other's ledger INSERT
            // below, so the race turns into a deadlock.
            //
            // The real serialisation point is the owner's user row, locked by
            // `lock_owner` just ahead of the spend (ADR-0972), and then the
            // enrolment row the spend locks. The second check on the spend's
            // no-op branch is what reads the winner's answer.
            if let Some(replayed) = replay(&mut tx, &key, &r.secret_hash, Lock::No).await? {
                tx.commit().await.map_err(db)?;
                call.finish(Outcome {
                    status: "OK",
                    ..Default::default()
                });
                // THE ORIGINAL OUTCOME, never SPENT. And the password is NOT
                // re-applied: `argon2id_hash` is ignored on this path, so the
                // password the first attempt set is the password that stands.
                return Ok(Response::new(replayed));
            }
        }

        // The hash has to fit `iam_password.argon2id_hash` BEFORE anything is
        // spent. Letting the engine refuse it renders through `db()` as "storage
        // unavailable" — a retryable status for a request that can never
        // succeed, so a client retries an unretryable mistake forever. This is
        // the same reasoning `expires_at` in CreateEnrolment already carries,
        // applied to the adjacent field.
        fits_password_column(&r.argon2id_hash)?;
        lock_owner(&mut tx, &r.secret_hash).await?;
        let spent = spend(&mut tx, &r).await?;

        if spent == 0 {
            return unspent(tx, key, r, call).await;
        }

        redeemed(tx, key, r, call).await
    }
}

/// `CreateEnrolment`'s idempotency key, counted and discarded. Lifted out of
/// `mint_enrolment` whole, for the function-size ceiling.
fn idempotency_sensor(r: &CreateEnrolmentRequest) {
    // `idempotency` IS DISCARDED HERE, AND THIS RPC'S OWN CONTRACT SAYS IT
    // MUST NOT BE. `yadgar.iamdb.v1.CreateEnrolmentRequest` enumerates the
    // payload the key is compared on — `user_id`, `secret_hash`,
    // `expires_at` AND `require_zero_credential_admin`, the last of which
    // JOINED that enumeration at contract v1.12.0 because this handler now
    // REFUSES on it (ADR-0655, amended by ADR-0656), so the
    // `unverified_actor` exclusion's inert-by-construction rationale does not
    // reach it — and states that ADR-0519's refusal of a replayed key is
    // enforced HERE rather than in `iam`, because `iam` holds no store to
    // recognise a key it has seen. `iam` mints a fresh secret on every
    // attempt, so a redelivery arrives with a DIFFERING `secret_hash` and
    // this handler mints a SECOND enrolment where the contract requires
    // INVALID_ARGUMENT. See the module header for why the ledger that closes
    // this cannot land in this repository alone.
    //
    // THE SENSOR. See [`ENROLMENT_IDEMPOTENCY_DISCARDED`]'s doc comment for
    // what firing does and does not prove — in short, it detects the estate
    // ENTERING the exposed state, once, and never a double-mint.
    if r.idempotency.as_ref().is_some_and(|k| !k.key.is_empty()) {
        tracing::warn!(
            user_id = %r.user_id,
            "CreateEnrolment received a non-empty idempotency key, and this \
             handler discards it"
        );
        metrics::counter!(ENROLMENT_IDEMPOTENCY_DISCARDED).increment(1);
    }
}

/// The ORDINARY arm, which is the statement this handler has always run.
///
/// FROM_UNIXTIME for the reason CreateCredential already carries: the contract
/// sends epoch SECONDS and the column is a TIMESTAMP. Binding the integer
/// directly does not error — MariaDB reads it as a datetime literal and stores
/// something else, and the enrolment then expires at a time nobody chose.
const ORDINARY: &str = "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at)
             SELECT ?, id, ?, FROM_UNIXTIME(?) FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE";

/// Which statement the write runs, and that is the whole of the arm choice.
///
/// **TWO STATEMENTS, ONE BIND LIST, AND THE ABSENT-FIELD ARM IS BYTE-IDENTICAL
/// TO WHAT IT WAS.** proto3 defaults a bool to false, so every caller that
/// predates ADR-0655's field takes [`ORDINARY`] unchanged — which is what keeps
/// re-enrolment available as the recovery for a forgotten password
/// (`iam.proto` calls that the contract; `a_spent_enrolment_blocks_no_fresh_one`
/// and `the_absent_demand_still_enrols_an_administrator_who_holds_a_password`
/// are the proofs it did not move).
///
/// **THE DEMAND ARM IS AN AUTHORIZATION DECISION TAKEN INSIDE THE WRITE**, and
/// [`demand::INSERT`] carries the whole argument: what "zero credentials" counts,
/// why no liveness qualifier appears in it, and why its locking read is not the
/// misuse ADR-0513 forbids. There is deliberately NO arm that parses the demand
/// and then runs the ordinary statement — a deployed store that reads the field
/// and ignores it is the false green the whole design exists to refuse.
///
/// **THE REVOKE INSTRUCTION ONLY EVER RIDES THE ORDINARY ARM**, on this, the
/// derivation-off path (`declared` writes its own, ADR-1014). The caller has
/// already refused the demand and the instruction together, so `(true, true)`
/// cannot reach here; it maps to the demand arm rather than to a statement that
/// would write the instruction, so even a caller that skipped that refusal could
/// not get a bootstrap enrolment that revokes.
const fn statement(demand: bool, revoking: bool) -> &'static str {
    match (demand, revoking) {
        (true, _) => demand::INSERT,
        (false, true) => revoke::INSERT,
        (false, false) => ORDINARY,
    }
}
