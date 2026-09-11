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

use super::*;

mod demand;
mod ledger;

use ledger::{replay, unredeemable};

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

impl IamDb {
    pub(super) async fn mint_enrolment(
        &self,
        r: CreateEnrolmentRequest,
        call: Call,
    ) -> Result<Response<CreateEnrolmentResponse>, Status> {
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

        // Explicit, because the alternative is worse than a rejection. The
        // column is NOT NULL, so FROM_UNIXTIME(NULL) makes the engine refuse
        // under STRICT_TRANS_TABLES — and `db()` renders every engine error as
        // "storage unavailable", which would report a caller's mistake as this
        // service being down.
        let expires_at = r
            .expires_at
            .ok_or_else(|| Status::invalid_argument("an enrolment must carry an expiry"))?;

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

        let done = sqlx::query(statement(r.require_zero_credential_admin))
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
            // The real serialisation point is the enrolment row, locked by the
            // spend UPDATE further down. The second check on that statement's
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
        let spent = spend(&mut tx, &r).await?;

        if spent == 0 {
            return unspent(tx, key, r, call).await;
        }

        redeemed(tx, key, r, call).await
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
const fn statement(demand: bool) -> &'static str {
    match demand {
        true => demand::INSERT,
        false => ORDINARY,
    }
}

/// THE SPEND, and it is one statement.
///
/// Lifted out of [`IamDb::redeem`] whole, with every clause it carries. A caller
/// that could run the check without the write would be the race this statement
/// exists to close, so what comes back is the row count and nothing else.
async fn spend(
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
async fn unspent(
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
async fn redeemed(
    mut tx: sqlx::MySqlTransaction<'_>,
    key: String,
    r: RedeemEnrolmentRequest,
    call: Call,
) -> Result<Response<RedeemEnrolmentResponse>, Status> {
    let row = sqlx::query(
        "SELECT e.id AS enrolment_id, e.user_id, u.external_id_ciphertext
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
    // line: the spend, the password and the ledger row land together or none
    // of them does.
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
    }))
}
