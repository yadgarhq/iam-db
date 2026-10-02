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

use crate::pb::yadgar::common::v1::{
    InheritedSetting, Meta, SettingScope, SettingValue, UnverifiedActor,
};
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
pub use enrolment::DEMAND_INSERT;
mod identity;
mod key_identity;
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

/// A `CreateEnrolment` carrying the bootstrap demand was REFUSED, labelled with
/// the conjunct that refused it.
///
/// **THE LABEL IS THE WHOLE POINT, AND ADR-0657 IS WHY IT IS HERE RATHER THAN IN
/// THE RESPONSE.** That ruling gives a refusal on this path ONE status code and
/// ONE constant body whichever conjunct failed, because a per-conjunct message
/// would let a holder of a leaked bootstrap token tell "not an administrator"
/// from "administrator who already holds a credential" — learning the
/// administrator set, and specifically which administrators have never logged
/// in, which is exactly the set this grant can still take over. So the operator's
/// only distinguishing signal is this series and the warn beside it.
///
/// `conjunct` is `not_admin` or `held_credential` and nothing else. The set is
/// CLOSED and chosen by this store from its own re-read: an open label mints a
/// Prometheus series from caller-influenced data, which D67 forbids.
///
/// It counts REFUSALS, not acceptances, so it does not replace the gateway's
/// `yadgar_gateway_bootstrap_accepted_total` — that one counts every bootstrap
/// acceptance including this verb's, and the two answer different questions.
pub const ENROLMENT_DEMAND_REFUSED: &str = "yadgar_iamdb_enrolment_demand_refused_total";

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
///
/// **CAPPED HERE, AND ONLY HERE, WITH [`capped`] — THE SAME BOUND AND MARKER
/// EVERY OTHER CALLER STRING ON THIS BOUNDARY GETS.** A header is bounded only
/// by the transport's own header-size limit — `h2`'s own default is 16 MiB
/// ("a sane default taken from golang http2"), and this service sets no
/// `http2_max_header_list_size` of its own — and this value reaches TWO places
/// from the ONE `String` this function returns: the actor record's
/// `request_id` field, and `tel`'s `Scope`, which carries it into
/// `Call::start`'s span and the `CallRecord` a collector joins the actor line
/// to. Capping at either destination instead of here would let the two
/// diverge on a caller long enough to be cut differently in each place,
/// breaking the very join `request_id` exists for. Capping here instead of
/// refusing the call keeps D67's rule that telemetry emission must never fail
/// a call: a correlation id is transport-level context rather than part of
/// what is being asked, so a malformed one must not be able to fail a request
/// over it.
///
/// `gateway::request_id` (D67) mints this id as a 36-character UUIDv7, and
/// ledger 1248 puts it on the header: yadgarhq/gateway#97 sends it to `iam`,
/// and yadgarhq/iam#88 forwards it here CAPPED with a copy of [`capped`]. Any
/// value long enough to be cut did not come from the gateway's generator.
/// Re-capping what `iam` already capped changes nothing, so both hops'
/// records carry the identical string.
fn request_id_of<T>(req: &Request<T>) -> String {
    req.metadata()
        .get("x-yadgar-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| capped(v).into_owned())
        .unwrap_or_default()
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

/// ADR-0534's RECORDING HALF, and the whole of what this boundary does with
/// `unverified_actor` — for every RPC that carries one.
///
/// **IT IS WRITTEN TO THE LOG AND REACHES NOTHING ELSE: no WHERE clause, no
/// branch, no refusal.** A request carrying an actor and one carrying none take
/// the identical path. The field is self-asserted, this service cannot verify it,
/// and it MUST NOT be an authorisation input.
///
/// **ONE READER OF THE FIELD IN THIS CRATE**, so a grep for `unverified_actor`
/// lands on this paragraph rather than on nine copies of it, and so a later verb
/// that starts carrying an actor gets the absent-and-empty handling for free
/// instead of re-deriving it.
///
/// **IT SITS DIRECTLY BELOW [`tel`] BECAUSE OF WHAT MUST NEVER PASS BETWEEN
/// THEM.** The actor goes here and NEVER into the telemetry `Scope`: every other
/// record in the estate carries an ATTESTED `Scope.user_id`, so putting a
/// self-asserted id in that field would make a dashboard join an unverifiable
/// string to a verified one. `handlers` builds the `Scope`; the operations call
/// this. The two are in different files on purpose.
///
/// **`target` NAMES WHAT WAS ACTED ON AND NEVER WHO ASKED.** On `CreateEnrolment`
/// and `SetUserAdmin` the request's `user_id` is the person the act was done TO,
/// and it is already that record's telemetry scope; recording it as the actor
/// would attribute every promotion to the person promoted. An attribution with no
/// object is also useless during an incident, which is why both are on one line.
///
/// **EACH VERB'S `target`, AND WHY IT IS COMPOSITE WHERE IT IS.** A `/` joins
/// the segments, container first. EVERY CALLER-SUPPLIED SEGMENT IS ESCAPED by
/// [`seg`] — `%` to `%25`, then `/` to `%2F` — because no id grammar in the
/// contract forbids a `/` and the target is rendered before anything validates
/// the request. A segment this service minted (`CreateUser`'s id,
/// `CreateCredential`'s credential id) and an enum name are written as they
/// are; neither can hold a `/`.
///
/// **EVERY CALLER STRING IS CAPPED** at [`ACTOR_RECORD_CAP`] characters, with
/// `...` marking a cut: each target segment inside [`seg`], the actor id here,
/// and `request_id` itself inside [`request_id_of`] — the one caller string on
/// this line that is also read by `tel` for the `CallRecord`, capped at its
/// single point of entry so both consumers agree. A request can be 4 MB, and
/// none of it should reach a log line whole.
///
/// | RPC                    | `target`                                       |
/// | ---------------------- | ---------------------------------------------- |
/// | `CreateUser`           | `{user_id}`, the id just minted                |
/// | `CreateEnrolment`      | `{user_id}`, the person enrolled               |
/// | `SetUserAdmin`         | `{user_id}`, the person promoted or demoted    |
/// | `CreateCredential`     | `{user_id}/{credential_id}`, the id just minted |
/// | `RevokeCredential`     | `{credential_id}`                              |
/// | `SetRateLimitOverride` | `{user_id}/{module}/{kind}/{set\|clear}`       |
/// | `AddTeamMember`        | `{team_id}/{user_id}`                          |
/// | `RemoveTeamMember`     | `{team_id}/{user_id}`                          |
/// | `SetInheritedSetting`  | `{scope}/{team_id}/{name}`                     |
///
/// `CreateCredential` names the credential so its record joins a later
/// `RevokeCredential`'s on the id. `{kind}` and `{scope}` are the contract's enum
/// names (`KIND_READ`, `SETTING_SCOPE_TEAM`), or the raw number when the request
/// carries one the contract does not define — the target is rendered before the
/// request is checked. An absent `team_id` is the empty segment, so an
/// organisation write reads `SETTING_SCOPE_ORG//{name}`.
///
/// **ABSENT AND PRESENT-HOLDING-EMPTY ARE ONE CASE** and are recorded as
/// unattributed, NEVER as an actor whose id is the empty string — ADR-0512's
/// collapse, pointed at the audit trail. `prost` cannot tell an absent message
/// from a default one, so `filter` is what keeps the two together;
/// `unwrap_or_default` would write "" as an actor.
///
/// **ALL NINE RPCs THAT CARRY THE FIELD CALL THIS**, each before any refusal or
/// SQL in its operation. `CreateUser`, `CreateEnrolment`,
/// `SetUserAdmin` and `SetInheritedSetting` came first; `CreateCredential`,
/// `RevokeCredential`, `SetRateLimitOverride`, `AddTeamMember` and
/// `RemoveTeamMember` were wired later (ledger 870), with the same test per verb
/// in `tests/contract.rs`. A tenth verb that starts carrying an actor joins this
/// list and that test pattern, or the grep that lands here finds an omission
/// indistinguishable from a decision again.
///
/// **THE LINE RECORDS AN ATTEMPT, NEVER AN OUTCOME.** It is written before the
/// operation refuses or touches the store, so a request refused as NOT_FOUND or
/// INVALID_ARGUMENT, or one that failed against the engine, still left it.
/// Whether the write HAPPENED is the CallRecord's to say, and `request_id` is the
/// key that joins the two: it is the same `x-yadgar-request-id` the handler
/// hands `tel` for that call's `Scope`. An empty one is a caller that sent none.
///
/// **THERE IS NO AUDIT STORE ON THIS BOUNDARY**, so the structured log is where an
/// attribution can land today (ADR-0620). Said plainly rather than implied: the
/// durable audit record ADR-0534 imagines does not exist here yet.
fn record_actor(request_id: &str, actor: Option<&UnverifiedActor>, rpc: &str, target: &str) {
    tracing::info!(
        request_id = request_id,
        unverified_actor = ?actor
            .map(|a| a.user_id.as_str())
            .filter(|id| !id.is_empty())
            .map_or(std::borrow::Cow::Borrowed("<unattributed>"), capped),
        rpc = rpc,
        target = target,
        "an administrative write carrying a self-asserted actor"
    );
}

/// How many of a caller's characters one string may put on an actor record —
/// and, since [`request_id_of`] caps with this same function, on the
/// `request_id` the actor record and the `CallRecord` both carry.
///
/// A request may be 4 MB, and a header can run to the transport's own limit:
/// the actor id, every caller-supplied target segment, and `x-yadgar-request-id`
/// are all the caller's own strings, read before anything validates them. Past
/// this many characters the rest is cut and [`CUT_MARKER`] marks the cut, so a
/// cut value is at most `ACTOR_RECORD_CAP + 3` characters.
///
/// **`iam` HOLDS A COPY OF THIS BOUND AND OF [`CUT_MARKER`]** (yadgarhq/iam#88,
/// its `REQUEST_ID_CAP` and `capped`). The copies must stay identical, or the
/// two hops cut one over-long request id differently and their records stop
/// joining.
const ACTOR_RECORD_CAP: usize = 256;

/// What marks a cut. **ASCII, and that is load-bearing** (ledger 1248): the
/// capped request id crosses a hop in `x-yadgar-request-id`, and
/// [`request_id_of`] reads it with `to_str()`, which refuses any non-ASCII
/// byte. The `…` this used to be was accepted into metadata and read back as
/// `""`.
const CUT_MARKER: &str = "...";

/// `s` cut to [`ACTOR_RECORD_CAP`] characters, with [`CUT_MARKER`] appended if
/// it was cut.
fn capped(s: &str) -> std::borrow::Cow<'_, str> {
    match s.char_indices().nth(ACTOR_RECORD_CAP) {
        Some((at, _)) => format!("{}{CUT_MARKER}", &s[..at]).into(),
        None => s.into(),
    }
}

/// One caller-supplied segment of a `record_actor` target: capped, then
/// escaped `%` → `%25` FIRST and `/` → `%2F` second.
///
/// No id grammar in this contract forbids a `/`, so an unescaped one would let
/// one object's target read as another's. `%` goes first, or a literal `%2F`
/// would be indistinguishable from an escaped `/`.
fn seg(s: &str) -> String {
    capped(s).replace('%', "%25").replace('/', "%2F")
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

#[cfg(test)]
mod tests;
