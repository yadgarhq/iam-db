//! The bootstrap-enrolment demand: the predicate, and the conjunct that refused.
//!
//! ADR-0655 admits the bootstrap token to `IssueEnrolment` for a user that is an
//! administrator AND holds zero credentials, and requires the predicate to be
//! evaluated INSIDE the write rather than as a read the caller performs first. A
//! check-then-write races a concurrent `RedeemEnrolment`, and that redemption's
//! write is the `iam_password` upsert — which is why the password row is half of
//! the definition.
//!
//! ADR-0656 amends what "zero credentials" counts, and the amendment is the
//! whole reason this file exists rather than a `WHERE` clause written inline.
//! "Zero credentials" means NO `iam_credential` ROW OF ANY LIVENESS — revoked
//! rows count — AND no `iam_password` row. `RevokeCredential`
//! (`super::super::credential::revoke`) tombstones per D26 rather than deleting,
//! so under the natural live-rows reading an established administrator who
//! revoked their own credential would present as holding zero and become
//! enrollable by the bootstrap token: account takeover of an established
//! account, with an unattributable credential. Counting rows of any liveness
//! makes the safety argument a PROPERTY OF THIS STATEMENT — a row is never
//! deleted, only tombstoned, so once a user has ever held a credential they are
//! permanently outside the grant — rather than a fact about which verbs the
//! estate happens to ship.
//!
//! **A `revoked_at IS NULL` QUALIFIER ANYWHERE BELOW IS A DEFECT.** Every other
//! liveness guard on this boundary carries one, which is exactly why ADR-0656
//! had to rule it out here by name. The tripwire is
//! `a_revoked_credential_still_refuses_the_bootstrap_demand` in
//! `tests/contract.rs`: on a fresh account the two readings agree, so that test
//! is the only one in the suite that separates this build from the widened one.
//!
//! ADR-0657 rules what the caller is told: ONE code and ONE body whichever
//! conjunct failed, because a per-conjunct message hands a holder of a leaked
//! bootstrap token an oracle for "which administrators have never logged in" —
//! precisely the set this grant can still take over. The conjunct is recorded
//! where the operator reads and the attacker does not: the warn below, and a
//! counter labelled from the closed set `Conjunct` declares.

use crate::service::*;

/// The demand arm's insert, which is also the whole predicate.
///
/// **THE PREDICATE IS IN THE INSERT'S OWN SELECT**, so the rows the decision is
/// read from are the rows the write is derived from — this file's own idiom,
/// argued at the six writes ledger 695 moved their liveness predicates into and
/// at the team-override upsert. A separate `SELECT` followed by this `INSERT`
/// would be the race ADR-0655 put the predicate inside the write to close.
///
/// **`LEFT JOIN … IS NULL` RATHER THAN `NOT EXISTS`, AND THE DIFFERENCE IS THE
/// LOCK.** A locking clause does not reach rows read inside a nested subquery,
/// so a `NOT EXISTS` form would read `iam_password` and `iam_credential` with no
/// locks at any isolation level — a plain read wearing a locking costume. The
/// joins put both tables in the OUTER query, where `LOCK IN SHARE MODE` reaches
/// them. At the engine's default REPEATABLE READ that is a next-key lock over
/// the absent rows, so a concurrent redemption's `iam_password` insert WAITS
/// until this statement's transaction ends.
///
/// **THAT IS NOT THE MISUSE ADR-0513 FORBIDS**, and the distinction is which
/// party does what with the gap. ADR-0513 condemns `SELECT … FOR UPDATE` of an
/// ABSENT key as a mutual-exclusion primitive between two SYMMETRIC claimers:
/// two identical gap locks do not exclude each other, both claimers pass, and
/// they then deadlock on their inserts into the same gap. Here the party that
/// must be serialised against — `RedeemEnrolment` — does not gap-lock these
/// rows; it INSERTS into the gap, and blocking an insert into a gap is the one
/// thing a gap lock does. Nothing else in this statement is a claim: two
/// concurrent demand-creates take compatible shared locks and insert into
/// `iam_enrolment`, a table neither's gap locks cover, so they cannot cycle.
/// There is no `UPDATE` and no read ahead of the statement, so there is no
/// `ER_CHECKREAD` branch for REPEATABLE READ to poison either.
///
/// Two credential rows joining to two output rows is harmless: `c.id IS NULL`
/// filters every one of them, and in the passing case both joins are empty and
/// the select yields exactly one row.
///
/// The binds are the ORDINARY ARM'S BINDS IN THE ORDINARY ARM'S ORDER — id,
/// secret hash, expiry, user id — so the two statements are interchangeable at
/// the call site and no third thing has to agree with either.
pub const INSERT: &str = "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at)
             SELECT ?, u.id, ?, FROM_UNIXTIME(?)
               FROM iam_user u
               LEFT JOIN iam_password  p ON p.user_id = u.id
               LEFT JOIN iam_credential c ON c.user_id = u.id
              WHERE u.id = ? AND u.deleted_at IS NULL
                AND u.is_admin = 1
                AND p.user_id IS NULL
                AND c.id IS NULL
              LOCK IN SHARE MODE";

/// The ONE sentence, for BOTH conjuncts (ADR-0657).
///
/// It names the PREDICATE — the conjunction, whole — and never which half of it
/// failed. A caller who could tell "not an administrator" from "already holds a
/// credential" would learn the administrator set and, worse, which
/// administrators have never logged in; that is the shortlist for the one attack
/// this predicate exists to prevent. The operator loses nothing, because the
/// conjunct is in the warn and the counter label below and an operator has log
/// and metrics access by construction.
pub(super) const REFUSAL: &str =
    "the bootstrap token may only enrol an administrator who has never held a credential";

/// Which half of the predicate refused, as a CLOSED SET of two.
///
/// Closed because the label reaches Prometheus: an open one mints a series from
/// caller-influenced data, which D67 forbids. Chosen by this store from its own
/// re-read, never from anything the caller sent.
#[derive(Clone, Copy)]
enum Conjunct {
    /// The target is not an administrator.
    NotAdmin,
    /// The target is an administrator who already holds a credential — a
    /// password row, or an `iam_credential` row of ANY liveness.
    HeldCredential,
}

impl Conjunct {
    const fn label(self) -> &'static str {
        match self {
            Self::NotAdmin => "not_admin",
            Self::HeldCredential => "held_credential",
        }
    }
}

/// Name the zero, then refuse.
///
/// **THE RE-READ NAMES AND NEVER GUARDS**, which is this file's standing rule
/// (`live_team` carries the same sentence at the team-override upsert). The
/// decision was taken by [`INSERT`]'s own `WHERE`; everything here runs after
/// it, decides only the log field and the counter label, and cannot turn a
/// refusal into a success. That is why it may trail the write's moment safely:
/// the fail direction is refusal either way.
///
/// The caller has already established that the user is LIVE — a withdrawn or
/// unknown user is the NOT_FOUND the ordinary arm has always answered — so the
/// only question left is the flag, and a live administrator who was refused
/// anyway was refused on the credential conjunct.
pub(super) async fn refuse(pool: &MySqlPool, user_id: &str) -> Status {
    let named = match admin_flag(pool, user_id).await {
        Ok(Some(true)) => Some(Conjunct::HeldCredential),
        Ok(Some(false)) => Some(Conjunct::NotAdmin),
        // THE CONJUNCT CANNOT BE NAMED, AND THE REFUSAL STILL STANDS. Either the
        // engine went away between the insert and this read, or the person was
        // withdrawn inside that window. Both are refusals on the safe side, so
        // this reports what it could not learn rather than inventing a third
        // label — the set has to stay closed for D67, and a counter that
        // under-counts a rare pair of races is better than a series nobody can
        // reason about.
        Ok(None) => {
            tracing::warn!(
                %user_id,
                "the bootstrap enrolment demand was refused and the conjunct \
                 could not be named: the person is no longer live"
            );
            None
        }
        Err(e) => {
            tracing::error!(
                %user_id, error = %e,
                "the bootstrap enrolment demand was refused and the conjunct \
                 could not be named: the naming re-read failed"
            );
            None
        }
    };

    if let Some(conjunct) = named {
        // THE WARN AND THE COUNTER TOGETHER, the shape the idempotency sensor
        // already uses in this crate. The warn answers "why was THIS request
        // refused", joined to the gateway's 403 by the request id that travels
        // the whole chain; the counter answers the aggregate question with no
        // log at all.
        tracing::warn!(
            %user_id,
            conjunct = conjunct.label(),
            "the bootstrap enrolment demand was refused"
        );
        metrics::counter!(ENROLMENT_DEMAND_REFUSED, "conjunct" => conjunct.label()).increment(1);
    }

    Status::permission_denied(REFUSAL)
}

/// The flag, for naming only.
///
/// `None` means no live row — the person was withdrawn between the insert and
/// this read. The error is returned rather than rendered through `db()` because
/// the status this ends in is decided by the caller and is never `UNAVAILABLE`:
/// the write already refused.
async fn admin_flag(pool: &MySqlPool, user_id: &str) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar("SELECT is_admin FROM iam_user WHERE id = ? AND deleted_at IS NULL")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}
