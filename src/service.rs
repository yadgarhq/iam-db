//! `IamDbService`. One RPC is one transaction (D5).
//!
//! **This boundary never sees a name, a password or a token.** It receives
//! hashes and ciphertext, computed by `iam`, which holds the keys. That is not a
//! stylistic preference: it means a query log, a slow-query log and a database
//! backup all contain nothing that identifies a person or authenticates as one.
//!
//! **Nor does it see a `Scope`.** Every other `-db` in the system enforces scope
//! on every path, because every other one serves data belonging to somebody. This
//! one runs *before* there is a caller identity — resolving a credential is how
//! identity comes to exist. Its access control is that only `iam` can reach it.
//!
//! # What happens to `Idempotency`, per RPC
//!
//! **STATED HERE BECAUSE THE SILENCE IS ITSELF THE DEFECT.** ELEVEN request
//! messages on this contract carry `yadgar.common.v1.Idempotency` and this module
//! reads `r.idempotency` on TWO of them. A reader who greps for that field finds
//! nine handlers that accept a key and never mention it, and cannot tell an
//! omission from a mechanism. The nine are not one answer nine times:
//!
//! - **TWO honour the key with a ledger.** `RedeemEnrolment`, on
//!   `iam_enrolment_redemption`, and `SetInheritedSetting`, on
//!   `iam_inherited_setting_write`. Those two tables hold the only columns in
//!   this schema a caller's key reaches.
//! - **SIX deliver D9's replay property BY SHAPE, without reading the key.**
//!   `SetPassword` and `SetRateLimitOverride` upsert, `SetUserAdmin` assigns,
//!   `RevokeCredential` tombstones under `revoked_at IS NULL`, `AddTeamMember`
//!   inserts onto a composite primary key, `RemoveTeamMember` deletes. A repeat
//!   reaches the same state and hands back the same answer, which is what D9's
//!   core rule asks of a replay; each handler argues its own case where it
//!   stands. What none of the six can do is D9's AMENDED half — refuse a repeated
//!   key carrying a DIFFERENT payload — because that needs the prior REQUEST and
//!   no table here keeps one. That gap is not this module's to close alone: it
//!   is booked org-wide as O21.
//! - **THREE DISCARD THE KEY AND PUT NOTHING IN ITS PLACE.** `CreateUser`,
//!   `CreateEnrolment` and `CreateCredential` mint a row per call, so a retry is
//!   not a replay and the shape argument above does not reach them. Each carries
//!   the measured consequence at its own handler.
//!
//! **NOTHING IS REFUSED, AND THAT IS A DECISION RATHER THAN THE OVERSIGHT
//! CONTINUING.** `INVALID_ARGUMENT` on a key this module cannot honour is the
//! loud alternative to the silence, and it would break the callers that send one:
//! `iam` forwards a key onto FIVE of these hops today — `CreateUser`,
//! `CreateEnrolment`, `AddTeamMember`, `RemoveTeamMember` and `RevokeCredential`.
//! The last three are in the shape group, so refusing them would reject writes
//! that are already replay-safe; refusing the first two would take user and
//! enrolment creation down in order to report a defect neither caller can fix.
//!
//! **THE LEDGER IS THE FIX, AND IT CANNOT LAND IN THIS REPOSITORY ALONE.** `iam`
//! bounds a caller's key at the width of the two ledger columns above, and states
//! that whoever gives one of the five discarded keys a ledger must extend that
//! bound to the RPC IN THE SAME CHANGE. That constant is in another repository,
//! so the ledger and the bound have to arrive together, across both.

use sqlx::{MySqlPool, Row};
use tonic::{Request, Response, Status};
use yadgar_telemetry::grpc::status_name;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::pb::yadgar::common::v1::{InheritedSetting, Meta, SettingScope, SettingValue};
use crate::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbService;
use crate::pb::yadgar::iamdb::v1::*;
/// D67's `Kind` AS THE CONTRACT DECLARES IT, aliased because `Kind` above is
/// already the telemetry crate's own copy of the same enum.
///
/// Two types, one meaning, and they never meet: this one arrives in a
/// `SetRateLimitOverride` request and is stored as an integer; the other labels
/// the record `Call::start` emits. Renaming either would hide that they are the
/// same enum from two independently pinned sources.
use crate::pb::yadgar::telemetry::v1::Kind as ContractKind;

// THE OPERATIONS, one module per subject, and the trait implementation that
// reaches them. Private children: `yadgar_iam_db::service::IamDb` and its
// `IamDbService` implementation are reached exactly as they were, and being
// children is also what lets them see this module's `pool`, `db`, `label` and
// the liveness predicates without anything widening.
mod credential;
mod enrolment;
mod handlers;
mod identity;
mod password;
mod policy;
mod setting;

/// This service's name, on every telemetry record and on the rotation
/// watcher's gauges. ONE spelling, because a dashboard selects on it.
pub const SERVICE: &str = "iam-db";

/// What `ListCredentials` returns when the caller names no page size.
const DEFAULT_PAGE_SIZE: i32 = 50;
/// The ceiling, because `page_size` is a caller-supplied `int32`. Without it one
/// request asks for every credential in the table and the memory to hold them.
const MAX_PAGE_SIZE: i32 = 200;

/// The name ADR-0522's setting is stored under, in both settings tables.
///
/// The estate's first inheritable setting. The tables are keyed by name, so a
/// second setting whose value is a `SettingValue` needs no migration of its
/// own; one carrying anything else still needs a table of its own.
const OWNER_READS_OWN_RECORD: &str = "owner_reads_own_record";

/// `CreateEnrolment` received a non-empty idempotency key, and discarded it.
///
/// **A TRANSITION DETECTOR, NOT A TRIPWIRE, AND NOT A DOUBLE-MINT DETECTOR.**
/// `plans/create-enrolment-idempotency.md` §4.2's interim sensor, executed —
/// see the module header and `create_enrolment`'s own comment for what this
/// handler does with the key it is handed. This counter does not, and cannot,
/// recognise a REPEATED key: that needs a ledger retaining prior keys, which is
/// ledger 668's mechanism and 668's class, and is explicitly out of scope here.
///
/// **What it proves is narrower, and it is still the whole point.** The
/// `metrics::counter!` macro below runs only inside the `if`, and that macro
/// call is what REGISTERS the name with the recorder — so before the
/// gateway's `/admin` route exists and nothing sends a key here, this metric
/// is ABSENT from `/metrics` entirely, never present-and-zero. The day that
/// route lands, the gateway forwards a key on EVERY `IssueEnrolment`, and the
/// series comes into existence and STAYS, forever. **The series appearing —
/// not a number moving — is the entire signal.** A steady non-zero RATE after
/// that day is the CORRECT and PERMANENT reading — never an incident, and
/// never evidence this fixes the idempotency defect. It proves the clock
/// started; it does not stop it.
pub const ENROLMENT_IDEMPOTENCY_DISCARDED: &str =
    "yadgar_iamdb_enrolment_idempotency_discarded_total";

pub struct IamDb {
    pool: MySqlPool,
}

impl IamDb {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// The pool, for the contract test to seed rows the API has no RPC for.
    ///
    /// Team creation has no RPC yet — teams arrive administratively and nothing
    /// mints them in the first cut (D72) — so the test inserts one directly
    /// rather than the service growing an endpoint that exists only for tests.
    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }
}

/// D67's join key, carried in gRPC METADATA rather than in the message.
///
/// These RPCs take no `Scope`, because they run before a caller has an identity —
/// so the field that normally carries `request_id` does not exist here. Without
/// this, the `iam-db` hop would emit records that join to nothing and the trace
/// for a login would have a hole exactly where the interesting part is.
///
/// Metadata rather than a contract change because the contract is already tagged
/// and published, and because a correlation id is transport-level context rather
/// than part of what is being asked.
fn request_id_of<T>(req: &Request<T>) -> String {
    req.metadata()
        .get("x-yadgar-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Telemetry scope for a hop that has no `Scope`.
///
/// `user_id` is filled in AFTER a successful resolve where one is known, and left
/// empty otherwise. It is never populated from anything the caller asserted —
/// on this path the caller has not proven anything yet.
fn tel(request_id: String, user_id: &str) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: String::new(),
        user_id: user_id.to_string(),
        project_id: String::new(),
    }
}

fn db(e: sqlx::Error) -> Status {
    // The message is deliberately generic. A database error rendered to the
    // caller can carry a table name, a column, or a fragment of a query — and on
    // THIS service those name the identity schema. The detail goes to the log,
    // where it is wanted, and not to the wire.
    tracing::error!(error = %e, "database error");
    Status::unavailable("storage unavailable")
}

/// `live_user`, for a team.
///
/// A soft-deleted team is NOT_FOUND. An override stored against one is an entry
/// in the answer keyed on a team whose records are on their way out, which is
/// the same argument `SetRateLimitOverride` makes about a soft-deleted person.
async fn live_team<'e, E>(executor: E, team_id: &str) -> Result<(), Status>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let found: Option<String> =
        sqlx::query_scalar("SELECT id FROM iam_team WHERE id = ? AND deleted_at IS NULL")
            .bind(team_id)
            .fetch_optional(executor)
            .await
            .map_err(db)?;
    match found {
        Some(_) => Ok(()),
        None => Err(Status::not_found("no such live team")),
    }
}

/// Whether a ledger read must see the latest committed row or may use this
/// transaction's snapshot.
///
/// A named pair rather than a bare `bool`, because the two call sites differ for
/// a reason that a `true` at the call site would not carry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lock {
    /// Before the spend. A snapshot read is correct and a lock is actively
    /// harmful — see the call site.
    No,
    /// After a spend that matched nothing. The row this is looking for may have
    /// been committed by a concurrent winner AFTER this transaction's snapshot
    /// was taken, and only a locking read sees it.
    Yes,
}

/// `iam_password.argon2id_hash` is `VARCHAR(255)`, counted in CHARACTERS.
const MAX_ARGON2ID_HASH: usize = 255;

/// Refuse a hash the column cannot hold, as the caller's mistake it is.
///
/// Both writers of that column call this. Letting the engine refuse instead
/// renders through `db()` as `UNAVAILABLE` — a retryable status for a request
/// that can never succeed.
fn fits_password_column(hash: &str) -> Result<(), Status> {
    match hash.chars().count() > MAX_ARGON2ID_HASH {
        true => Err(Status::invalid_argument(
            "the argon2id hash is longer than the column can hold",
        )),
        false => Ok(()),
    }
}

/// Refuse to write against a user who does not exist or has been soft-deleted.
///
/// A FOREIGN KEY proves the row EXISTS; it says nothing about whether the person
/// is live, and every read on this boundary already carries `deleted_at IS
/// NULL`. Without this, an administrative write against a removed account
/// succeeds and reports OK — leaving an operator believing a change took effect
/// on an account nobody expects to act again.
async fn live_user<'e, E>(executor: E, user_id: &str) -> Result<(), Status>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let found: Option<String> =
        sqlx::query_scalar("SELECT id FROM iam_user WHERE id = ? AND deleted_at IS NULL")
            .bind(user_id)
            .fetch_optional(executor)
            .await
            .map_err(db)?;
    match found {
        Some(_) => Ok(()),
        None => Err(Status::not_found("no such live user")),
    }
}

/// A status name for the metric label, shared rather than re-spelled per service.
fn label(status: &Status) -> &'static str {
    status_name(status)
}
