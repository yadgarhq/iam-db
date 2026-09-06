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

#[tonic::async_trait]
impl IamDbService for IamDb {
    /// The hot path: a token hash to an identity.
    ///
    /// Called by `iam` on a cache miss, which under D72 is rare — but it is still
    /// the query that stands between every request and its answer, so it is one
    /// round trip and one index lookup.
    async fn resolve_credential(
        &self,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "ResolveCredential", Kind::Read, tel(rid, ""));

        // Liveness is decided IN THE QUERY, not in Rust afterwards.
        //
        // A revoked or expired credential must not come back and then get
        // filtered — a later `if` is a line someone can delete, reorder, or fail
        // to write on a second code path. Here the row simply does not exist.
        //
        // `deleted_at IS NULL` on the user matters as much: a soft-deleted person
        // whose credentials were never revoked would otherwise keep working.
        //
        // ONE TRANSACTION for every read here, because the contract says the
        // admin flag, the overrides and ADR-0522's setting are read in the SAME
        // transaction as the credential. Separate pool queries would each be a
        // different point in time, and the window between them is one in which a
        // withdrawn admin flag or a tightened limit is already gone from the
        // store and not yet in force in the answer — cached, at the caller, for
        // a whole cache lifetime.
        let mut tx = self.pool.begin().await.map_err(db)?;

        let row = sqlx::query(
            "SELECT c.id AS credential_id, c.user_id, u.is_admin
               FROM iam_credential c
               JOIN iam_user u ON u.id = c.user_id
              WHERE c.token_hash = ?
                AND c.revoked_at IS NULL
                AND (c.expires_at IS NULL OR c.expires_at > CURRENT_TIMESTAMP)
                AND u.deleted_at IS NULL",
        )
        .bind(&r.token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;

        let Some(row) = row else {
            // NOT an error. "No live credential" is a 401 at the edge; a broken
            // store is a 503. Collapsing them would make a database outage look
            // like every credential in the system being revoked at once.
            call.finish(Outcome {
                status: "OK",
                ..Default::default()
            });
            return Ok(Response::new(ResolveCredentialResponse::default()));
        };

        let user_id: String = row.try_get("user_id").map_err(db)?;
        let credential_id: String = row.try_get("credential_id").map_err(db)?;
        let is_admin: bool = row.try_get("is_admin").map_err(db)?;

        let team_ids: Vec<String> =
            sqlx::query("SELECT team_id FROM iam_team_member WHERE user_id = ?")
                .bind(&user_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?
                .into_iter()
                .map(|r| r.try_get::<String, _>("team_id"))
                .collect::<Result<_, _>>()
                .map_err(db)?;

        // EMPTY means this user has no override, so the gateway's configured
        // defaults apply unmodified. It does not mean zero and it does not mean
        // deny — clearing an override deletes the row rather than storing one
        // with no limit in it, which is what keeps the two apart.
        let rate_limit_overrides: Vec<RateLimitOverride> = sqlx::query(
            "SELECT module, kind, rate, burst
               FROM iam_rate_limit_override
              WHERE user_id = ?",
        )
        .bind(&user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?
        .into_iter()
        .map(|r| {
            Ok(RateLimitOverride {
                module: r.try_get("module")?,
                kind: r.try_get("kind")?,
                limit: Some(RateLimit {
                    rate: r.try_get("rate")?,
                    burst: r.try_get("burst")?,
                }),
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(db)?;

        // THE INPUTS, NOT THE ANSWER. The organisation's value, its lock and
        // EVERY team's override go back unresolved, because the resolution
        // depends on the team of the ROW being read — which neither this module
        // nor `iam` nor the gateway knows. Resolving it here would hand down a
        // decision made against the wrong team, and nothing about the answer
        // would look wrong.
        //
        // AN ABSENT ROW IS SETTING_VALUE_UNSPECIFIED AND IS NEVER OFF. A store
        // that states no policy must reach the enforcing `-db` as a refusal,
        // rather than as this module quietly choosing the strict one.
        let org = sqlx::query("SELECT value, locked FROM iam_org_setting WHERE name = ?")
            .bind(OWNER_READS_OWN_RECORD)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let (org_value, org_locked) = match org {
            Some(row) => (
                row.try_get::<i32, _>("value").map_err(db)?,
                row.try_get::<bool, _>("locked").map_err(db)?,
            ),
            None => (SettingValue::Unspecified as i32, false),
        };

        // NOT FILTERED BY `user_id`, unlike every other query in this RPC, and
        // the difference is deliberate: the override that matters is the one
        // belonging to the team of the RECORD, and the owner this setting exists
        // for has LEFT that team. Narrowing to the caller's teams would make the
        // setting evaporate in exactly the case it is for.
        //
        // UNBOUNDED ON PURPOSE, on the hottest path, and the bound is SPARSITY
        // rather than a clause: at most one row per team that states something,
        // and a team states something only when an operator writes one. It does
        // not grow with users, credentials or requests. A bare LIMIT would be
        // worse than the unboundedness rather than a mitigation of it — the
        // teams that fell off the end get a WRONG answer instead of a slow one,
        // and nothing says which. Bounding this for real means a cache, or
        // narrowing to the team of the row being read, and that team is not in
        // this request.
        let team_override =
            sqlx::query("SELECT team_id, value FROM iam_team_setting_override WHERE name = ?")
                .bind(OWNER_READS_OWN_RECORD)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?
                .into_iter()
                .map(|r| Ok((r.try_get("team_id")?, r.try_get("value")?)))
                .collect::<Result<_, sqlx::Error>>()
                .map_err(db)?;

        tx.commit().await.map_err(db)?;

        let resp = ResolveCredentialResponse {
            user_id,
            team_ids,
            credential_id,
            is_admin,
            rate_limit_overrides,
            owner_reads_own_record: Some(InheritedSetting {
                org_value,
                org_locked,
                team_override,
            }),
        };
        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    /// Return the stored hash for `iam` to verify against.
    ///
    /// The password never comes here. `iam` hashes and compares; this service
    /// only stores. That keeps a plaintext password out of a second process and
    /// out of anything that process might log.
    async fn get_password_hash(
        &self,
        req: Request<GetPasswordHashRequest>,
    ) -> Result<Response<GetPasswordHashResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "GetPasswordHash", Kind::Read, tel(rid, ""));

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

    async fn set_password(
        &self,
        req: Request<SetPasswordRequest>,
    ) -> Result<Response<SetPasswordResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "SetPassword", Kind::Write, tel(rid, &r.user_id));

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
        // argued for the four that follow it (ledger 695). A `live_user` on the
        // pool followed by an INSERT on the pool is TWO statements with a round
        // trip between them: a person soft-deleted inside that window passed the
        // check and got the password row anyway. The predicate is now in the
        // INSERT's own SELECT, so the row the liveness is read from IS the row
        // the write is derived from, and there is no window between them.
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

    async fn create_credential(
        &self,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "CreateCredential",
            Kind::Write,
            tel(rid, &r.user_id),
        );

        // `idempotency` IS DISCARDED HERE, AND A RETRY IS NOT A REPLAY. Measured
        // against mariadb:11.8.8: a second call carrying the SAME `token_hash`
        // hits `uq_iam_credential_token` and renders through `db()` as
        // UNAVAILABLE — a retryable status for a request that can never succeed —
        // while one carrying a FRESH hash mints a SECOND credential. `iam` sends
        // no key on this hop at all (ADR-0519), so there is nothing here to read;
        // the module header carries what has to land, and where.
        //
        // THE WRITE THE LIVENESS SWEEP MISSED, and the argument is CreateEnrolment's
        // verbatim rather than a new one. The FOREIGN KEY proves the user row
        // EXISTS; it does not prove the person is live. `ResolveCredential` joins
        // `deleted_at IS NULL`, so a credential minted for a soft-deleted account
        // is accepted, reported OK WITH AN ID the caller then hands to somebody,
        // and authenticates nobody for the whole of its lifetime.
        //
        // NOT DELIBERATE, and the two candidate reasons for leaving it out both
        // fail. There is no not-yet-live window to protect: `iam_user.deleted_at`
        // is `NULL DEFAULT NULL`, so a person is live from the INSERT that creates
        // them. And the one caller that mints a credential right after another
        // write — `RedeemEnrolment`, then `IssueCredential` — already spends the
        // enrolment under `user_id IN (SELECT id FROM iam_user WHERE deleted_at IS
        // NULL)`, so liveness is established one call earlier on that path too.
        // THE PREDICATE IS IN THE INSERT, on `SetPassword`'s argument and for
        // its reasons (ledger 695). A `live_user` here followed by an INSERT
        // below is two statements, and a person soft-deleted between them still
        // got a credential — one handed back with an id and accepted by nobody,
        // because `ResolveCredential` joins `deleted_at IS NULL`.
        //
        // THE FOREIGN KEY IS WHAT MADE IT REACHABLE. A soft delete leaves the
        // parent row in place, so `fk_iam_credential_user` is satisfied by an
        // account nobody expects to act again; the constraint proves existence
        // and never liveness, which is this handler's own argument above.
        let id = format!("yadgar:credential:{}", uuid::Uuid::now_v7());
        let done = sqlx::query(
            // FROM_UNIXTIME, because the contract carries epoch SECONDS and the
            // column is a TIMESTAMP. Binding the integer directly makes MariaDB
            // read 1798761600 as a datetime literal — it does not error, it
            // stores something else, and the credential then expires at a time
            // nobody chose. Converting in SQL keeps the one representation the
            // column understands.
            "INSERT INTO iam_credential (id, user_id, token_hash, label, expires_at)
             SELECT ?, id, ?, ?, FROM_UNIXTIME(?) FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE",
        )
        .bind(&id)
        .bind(&r.token_hash)
        .bind(&r.label)
        .bind(r.expires_at.map(|t| t.seconds))
        .bind(&r.user_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        // Zero MATCHED rows is no live person, and `live_user` is here only to
        // say so as NOT_FOUND. `SetPassword` carries the full argument.
        if done.rows_affected() == 0 {
            live_user(&self.pool, &r.user_id).await?;
        }

        call.finish(Outcome {
            status: "OK",
            // STILL A LITERAL, and still honest: this statement inserts exactly
            // one row or none, and the none case has already returned above.
            // Only `SetPassword`'s upsert can report a number the constant does
            // not predict.
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateCredentialResponse {
            credential_id: id,
        }))
    }

    /// Revoke, and return who it belonged to.
    ///
    /// The `user_id` is returned so the caller can publish the cache
    /// invalidation event (D72) without a second read. A revocation whose event
    /// never fires is a credential that keeps working until its TTL expires,
    /// which is the failure the whole invalidation design exists to prevent.
    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "RevokeCredential", Kind::Write, tel(rid, ""));

        // A tombstone, not a delete (D26). Idempotent by the WHERE clause:
        // revoking twice leaves the first timestamp, so the record still says
        // when access actually ended rather than when someone last asked.
        let row = sqlx::query(
            "UPDATE iam_credential
                SET revoked_at = CURRENT_TIMESTAMP
              WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(&r.credential_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        let user_id: String = sqlx::query("SELECT user_id FROM iam_credential WHERE id = ?")
            .bind(&r.credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .map(|r| r.try_get::<String, _>("user_id"))
            .transpose()
            .map_err(db)?
            .ok_or_else(|| Status::not_found("no such credential"))?;

        call.finish(Outcome {
            status: "OK",
            rows: row.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(RevokeCredentialResponse { user_id }))
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "CreateUser", Kind::Write, tel(rid, ""));

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

    async fn add_team_member(
        &self,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "AddTeamMember", Kind::Write, tel(rid, &r.user_id));

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
            // anything. Zero is the remaining case and has already returned
            // NOT_FOUND above.
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

    /// Removing a member changes what that user can see, so the caller MUST
    /// publish the invalidation event afterwards (D72). Until it does, a cached
    /// resolve still lists the old team and the person keeps reading its records.
    async fn remove_team_member(
        &self,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "RemoveTeamMember",
            Kind::Write,
            tel(rid, &r.user_id),
        );

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

    async fn create_enrolment(
        &self,
        req: Request<CreateEnrolmentRequest>,
    ) -> Result<Response<CreateEnrolmentResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "CreateEnrolment",
            Kind::Write,
            tel(rid, &r.user_id),
        );

        // `idempotency` IS DISCARDED HERE, AND THIS RPC'S OWN CONTRACT SAYS IT
        // MUST NOT BE. `yadgar.iamdb.v1.CreateEnrolmentRequest` enumerates the
        // payload the key is compared on — `user_id`, `secret_hash` and
        // `expires_at` — and states that ADR-0519's refusal of a replayed key is
        // enforced HERE rather than in `iam`, because `iam` holds no store to
        // recognise a key it has seen. `iam` mints a fresh secret on every
        // attempt, so a redelivery arrives with a DIFFERING `secret_hash` and
        // this handler mints a SECOND enrolment where the contract requires
        // INVALID_ARGUMENT. See the module header for why the ledger that closes
        // this cannot land in this repository alone.
        //
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
        let done = sqlx::query(
            // FROM_UNIXTIME for the reason CreateCredential already carries: the
            // contract sends epoch SECONDS and the column is a TIMESTAMP.
            // Binding the integer directly does not error — MariaDB reads it as
            // a datetime literal and stores something else, and the enrolment
            // then expires at a time nobody chose.
            "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at)
             SELECT ?, id, ?, FROM_UNIXTIME(?) FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE",
        )
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
        }

        call.finish(Outcome {
            status: "OK",
            // A LITERAL FOR THE SAME REASON `CreateCredential`'s is: one row or
            // none, and none has already returned.
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateEnrolmentResponse { enrolment_id: id }))
    }

    async fn redeem_enrolment(
        &self,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "RedeemEnrolment", Kind::Write, tel(rid, ""));

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
        let key = r.idempotency.map(|i| i.key).unwrap_or_default();
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
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        if spent.rows_affected() == 0 {
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
            return Ok(Response::new(RedeemEnrolmentResponse {
                outcome: outcome as i32,
                ..Default::default()
            }));
        }

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

    /// The read behind `ListCredentials`, and the only arm returning a
    /// `Credential`.
    ///
    /// A revoked row is OMITTED rather than returned with its tombstone set, so
    /// `revoked_at` is absent on every row this hands back. The tombstones stay
    /// in the store — D26 keeps "which credential was used" answerable — they
    /// are simply not this RPC's answer.
    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "ListCredentials", Kind::Read, tel(rid, &r.user_id));

        let page_size = match r.page_size {
            n if n <= 0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };

        // KEYSET pagination on the id, never OFFSET. The ids are UUIDv7, so
        // ordering by id is ordering by creation time, and a credential created
        // or revoked between two pages cannot shift the window and make a row
        // appear twice or not at all.
        //
        // UNIX_TIMESTAMP, because this crate's sqlx carries neither the `chrono`
        // nor the `time` feature — nothing else on this boundary reads a
        // timestamp back — so no Rust type a TIMESTAMP column decodes into
        // exists here. The CAST pins the result to a BIGINT rather than the
        // DECIMAL a fractional-second argument would produce.
        let rows = sqlx::query(
            // The JOIN is the liveness check every other read on this boundary
            // carries. A soft-deleted person's credentials already stop
            // resolving, so listing them would show live-looking rows for an
            // account that can no longer authenticate with any of them.
            "SELECT c.id,
                    c.label,
                    CAST(UNIX_TIMESTAMP(c.created_at) AS SIGNED) AS created_at,
                    CAST(UNIX_TIMESTAMP(c.expires_at) AS SIGNED) AS expires_at
               FROM iam_credential c
               JOIN iam_user u ON u.id = c.user_id
              WHERE c.user_id = ?
                AND c.revoked_at IS NULL
                AND u.deleted_at IS NULL
                AND c.id > ?
              ORDER BY c.id
              LIMIT ?",
        )
        .bind(&r.user_id)
        .bind(&r.page_token)
        .bind(page_size)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;

        let mut credentials = Vec::with_capacity(rows.len());
        for row in &rows {
            credentials.push(Credential {
                id: row.try_get("id").map_err(db)?,
                user_id: r.user_id.clone(),
                label: row.try_get("label").map_err(db)?,
                created_at: row
                    .try_get::<Option<i64>, _>("created_at")
                    .map_err(db)?
                    .map(epoch),
                expires_at: row
                    .try_get::<Option<i64>, _>("expires_at")
                    .map_err(db)?
                    .map(epoch),
                // Always absent: a revoked row is not in this answer at all.
                revoked_at: None,
            });
        }

        // A token ONLY when the page filled. A short page is the last one, and
        // handing back a token for it costs the caller a round trip to learn
        // what this answer already told it.
        let next_page_token = match credentials.len() == page_size as usize {
            true => credentials.last().map(|c| c.id.clone()).unwrap_or_default(),
            false => String::new(),
        };

        call.finish(Outcome {
            status: "OK",
            rows: credentials.len() as u32,
            ..Default::default()
        });
        Ok(Response::new(ListCredentialsResponse {
            credentials,
            next_page_token,
        }))
    }

    async fn set_user_admin(
        &self,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "SetUserAdmin", Kind::Write, tel(rid, &r.user_id));

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

    async fn set_rate_limit_override(
        &self,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "SetRateLimitOverride",
            Kind::Write,
            tel(rid, &r.user_id),
        );

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
            // is the harm every other arm of this change is about.
            //
            // AND CLOSING IT WOULD COST SOMETHING REAL. Joining the predicate
            // into the DELETE makes a soft-deleted person's override
            // unclearable, which is `RemoveTeamMember`'s argument verbatim: a
            // guard that refuses the one call able to clean up after a deletion
            // is worse than the gap it closes. The unconditional `live_user`
            // that answers NOT_FOUND for an unknown person is this arm's
            // existing decision and is left as it was.
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

    /// Write ONE LEVEL of ADR-0522's inheritable setting.
    ///
    /// **THE WRITE HALF THAT ADR-0522 SHIPPED WITHOUT.** The organisation's
    /// value, the inheritance lock and every team override were changeable only
    /// by direct SQL until this existed, which is ADR-0524's own opening
    /// sentence. The two settings tables and their `CHECK (value IN (1, 2))`
    /// constraints have been here since migrations 10 and 11; what was missing
    /// was the verb, so this adds NO migration.
    ///
    /// **IT REFUSES THE CONTRACT'S CLAUSES ITSELF.** `yadgar.common.v1.SettingScope`
    /// states the validation once and says it is binding "here rather than
    /// summarised", so `check_inherited_setting` is a full port of it rather
    /// than a trust of the caller. `iam` refuses the same clauses one hop up and
    /// that is not a reason to skip them: a storage boundary whose correctness
    /// lives in the service above it is a boundary that is correct by
    /// arrangement.
    ///
    /// **IT WRITES THE INPUTS AND NEVER THE ANSWER.** Nothing here resolves
    /// anything. The resolution depends on the team of the ROW being read and
    /// happens where the reach is computed; this module does not even know which
    /// record is being asked about.
    ///
    /// **IDEMPOTENT BY SHAPE *AND* BY A LEDGER, AND THE LEDGER IS FOR THE OTHER
    /// HALF OF D9.** The verb states what the level should BE rather than how to
    /// change it, so an identical repeat converges on the same state — that is
    /// the property `SetUserAdmin` and `SetRateLimitOverride` get by with, and it
    /// is why neither of them has a ledger. What that shape cannot do is refuse a
    /// repeated key carrying a DIFFERENT request, which D9 as amended requires
    /// and which this RPC's own contract comment enumerates the fields of.
    /// Without somewhere to remember them, an operator retrying a lost call with
    /// a corrected value gets the correction applied and no way to know which of
    /// the two took effect.
    ///
    /// So `iam_inherited_setting_write` records what was asked for, and a
    /// replayed key RE-DERIVES the setting rather than writing again. Re-running
    /// the assignment would be harmless only if nothing else had changed the
    /// level in between; if something had, it would undo that change and report
    /// success. The outcome is re-derived rather than stored because this RPC is
    /// NOT in ADR-0519's single-use-secret carve-out — the store keeps the
    /// setting, so there is nothing spent to hand back.
    ///
    /// **ONE TRANSACTION (D5), AND THE READ-BACK IS INSIDE IT.** The response
    /// carries the setting WHOLE — the other level and every other team's
    /// override — so a read outside the write's transaction could answer with a
    /// concurrent writer's half-applied state.
    async fn set_inherited_setting(
        &self,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        // `tel`'s `user_id` STAYS EMPTY, and that is ADR-0534 rather than an
        // oversight. The only identity in this request is `unverified_actor`,
        // which is self-asserted; putting it where every other record in the
        // estate carries an ATTESTED `Scope.user_id` would make a dashboard join
        // an unverifiable string to a verified one.
        let call = Call::start(SERVICE, "SetInheritedSetting", Kind::Write, tel(rid, ""));

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
            }
            (SettingScope::Team, false) => {
                // THE FOREIGN KEY IS NOT THE ERROR MESSAGE. Left to fire, an
                // unknown team renders through `db()` as UNAVAILABLE — a
                // retryable status for a request that can never succeed. The
                // check is `SetRateLimitOverride`'s `live_user`, applied to the
                // team.
                live_team(&mut *tx, team_id_of(&r)).await?;
                sqlx::query(
                    "INSERT INTO iam_team_setting_override (name, team_id, value) VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE value = VALUES(value)",
                )
                .bind(&r.name)
                .bind(team_id_of(&r))
                .bind(r.value.expect("validated present unless clear is set"))
                .execute(&mut *tx)
                .await
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
        }
        .map_err(db)?;

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

/// What a `SetInheritedSetting` request ASKED FOR, which is what D9's amended
/// rule compares one idempotency key's two deliveries on.
///
/// **THE MEMBERSHIP IS THE CONTRACT'S, NOT A JUDGEMENT MADE HERE.**
/// `yadgar.iamdb.v1.SetInheritedSettingRequest` enumerates it: `scope`,
/// `team_id`, `name`, `value`, `locked` and `clear` — every field of the message
/// but two. `idempotency` carries the key the comparison is keyed on.
///
/// **`unverified_actor` IS EXCLUDED, AND THE EXCLUSION IS LOAD-BEARING.**
/// `yadgar.common.v1.UnverifiedActor` states it once for every RPC carrying the
/// field: including it would refuse, with INVALID_ARGUMENT, an IDENTICAL
/// operation stamped with a different actor — a second administrator picking up
/// a change the first one lost. The field would then decide whether a request
/// SUCCEEDS, and it is meant to be inert by construction.
///
/// **THE THREE `Option`s CARRY PRESENCE INTO THE COMPARISON.** Collapsing an
/// absent `value` onto a zero would make a request WITHDRAWING an override
/// compare equal to one setting it OFF, which is ADR-0524's distinction
/// destroyed at the one place it is checked rather than at the one place it is
/// written.
#[derive(Debug, PartialEq, Eq)]
struct Claim {
    key: String,
    scope: i32,
    team_id: Option<String>,
    name: String,
    value: Option<i32>,
    locked: Option<bool>,
    clear: bool,
}

impl Claim {
    fn of(r: &SetInheritedSettingRequest) -> Self {
        Self {
            // THE EMPTY STRING IS NOT A KEY, the rule `RedeemEnrolment` already
            // holds. Keying a ledger row on it would make two unrelated writes
            // collide on one row, so the second would be refused as a differing
            // payload under a key neither caller chose.
            key: r
                .idempotency
                .as_ref()
                .map(|i| i.key.clone())
                .unwrap_or_default(),
            scope: r.scope,
            team_id: r.team_id.clone(),
            name: r.name.clone(),
            value: r.value,
            locked: r.locked,
            clear: r.clear,
        }
    }

    /// Refuse a key that already recorded a DIFFERENT request (D9 as amended).
    ///
    /// Replaying it would hand the first request's outcome to a caller who sent
    /// a second: the operation actually asked for is silently discarded and the
    /// answer reports success. Refusing is the only response that never lies.
    fn agrees_with(&self, prior: &Claim) -> Result<(), Status> {
        // The key itself is what they were both found by, so it is never part of
        // the difference.
        match (
            self.scope,
            &self.team_id,
            &self.name,
            self.value,
            self.locked,
            self.clear,
        ) == (
            prior.scope,
            &prior.team_id,
            &prior.name,
            prior.value,
            prior.locked,
            prior.clear,
        ) {
            true => Ok(()),
            false => Err(Status::invalid_argument(
                "this idempotency key was used with a different request; a repeated key carrying \
                 a different payload is refused rather than replayed",
            )),
        }
    }

    async fn record(&self, tx: &mut sqlx::MySqlTransaction<'_>) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO iam_inherited_setting_write
                 (idempotency_key, scope, team_id, name, value, locked, clear_requested)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&self.key)
        .bind(self.scope)
        .bind(&self.team_id)
        .bind(&self.name)
        .bind(self.value)
        .bind(self.locked)
        .bind(self.clear)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

/// The request a key already recorded, or `None` if it has recorded nothing.
///
/// `Lock::No` is the ordinary pre-flight read; `Lock::Yes` is the re-check on
/// the branch where the INSERT found the row already there, where the row DOES
/// exist and a locking read is therefore a record lock rather than the gap lock
/// ADR-0513 forbids.
async fn recorded(
    tx: &mut sqlx::MySqlTransaction<'_>,
    key: &str,
    lock: Lock,
) -> Result<Option<Claim>, Status> {
    const BASE: &str = "SELECT scope, team_id, name, value, locked, clear_requested
                          FROM iam_inherited_setting_write
                         WHERE idempotency_key = ?";
    // AUDIT: both arms are literals in this file; `key` is bound, never
    // interpolated.
    let sql = match lock {
        Lock::No => BASE.to_string(),
        Lock::Yes => format!("{BASE} FOR UPDATE"),
    };

    let Some(row) = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
    else {
        return Ok(None);
    };

    Ok(Some(Claim {
        key: key.to_string(),
        scope: row.try_get("scope").map_err(db)?,
        team_id: row.try_get("team_id").map_err(db)?,
        name: row.try_get("name").map_err(db)?,
        value: row.try_get("value").map_err(db)?,
        locked: row.try_get("locked").map_err(db)?,
        clear: row.try_get("clear_requested").map_err(db)?,
    }))
}

/// The team this request names, after [`check_inherited_setting`] has proved one
/// is there and is not empty.
fn team_id_of(r: &SetInheritedSettingRequest) -> &str {
    r.team_id
        .as_deref()
        .expect("validated present and non-empty at team scope")
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

/// Both levels of one inheritable setting, unresolved.
///
/// The same two queries `ResolveCredential` makes, and deliberately the same
/// answers — including that an ABSENT organisation row is
/// SETTING_VALUE_UNSPECIFIED and never OFF. A store that states no policy must
/// reach the enforcing `-db` as a refusal rather than as this module quietly
/// choosing the strict one.
async fn read_inherited_setting(
    tx: &mut sqlx::MySqlTransaction<'_>,
    name: &str,
) -> Result<InheritedSetting, Status> {
    let org = sqlx::query("SELECT value, locked FROM iam_org_setting WHERE name = ?")
        .bind(name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
    let (org_value, org_locked) = match org {
        Some(row) => (
            row.try_get::<i32, _>("value").map_err(db)?,
            row.try_get::<bool, _>("locked").map_err(db)?,
        ),
        None => (SettingValue::Unspecified as i32, false),
    };

    // UNBOUNDED, on the same sparsity argument `ResolveCredential` states: at
    // most one row per team that says something, and a team says something only
    // when an operator writes one. A LIMIT would give the teams that fell off the
    // end a WRONG answer rather than a slow one.
    let team_override =
        sqlx::query("SELECT team_id, value FROM iam_team_setting_override WHERE name = ?")
            .bind(name)
            .fetch_all(&mut **tx)
            .await
            .map_err(db)?
            .into_iter()
            .map(|r| Ok((r.try_get("team_id")?, r.try_get("value")?)))
            .collect::<Result<_, sqlx::Error>>()
            .map_err(db)?;

    Ok(InheritedSetting {
        org_value,
        org_locked,
        team_override,
    })
}

/// Every clause `yadgar.common.v1.SettingScope` declares, and each one is
/// `INVALID_ARGUMENT`.
///
/// **A PORT OF THE CONTRACT, NOT A SUMMARY OF IT.** The normative text lives in
/// `common.proto` and says so; this is that text executed. `iam` holds an
/// identical function against its own request type, and the duplication is the
/// contract's own instruction — every boundary carrying this write refuses the
/// same clauses, because a boundary that trusts its caller is one whose
/// correctness lives somewhere else.
///
/// Returns the validated scope so the caller cannot re-derive it and disagree.
fn check_inherited_setting(r: &SetInheritedSettingRequest) -> Result<SettingScope, Status> {
    // proto3 enums are OPEN, so an unrecognised number arrives intact rather than
    // collapsing to the zero. A `match` with a fallthrough would write the
    // ORGANISATION's policy for a request that named neither level — the widest
    // write there is, answering a request nobody made.
    let scope = SettingScope::try_from(r.scope).map_err(|_| {
        Status::invalid_argument(
            "scope names no level this contract declares; there are two, an organisation and a \
             team",
        )
    })?;

    match scope {
        SettingScope::Unspecified => {
            return Err(Status::invalid_argument(
                "scope is required: a write addresses the organisation's level or one team's, and \
                 neither is the default",
            ));
        }
        SettingScope::Org => {
            // There is ONE organisation (D27), so a team id here is a caller that
            // meant TEAM — and ignoring it would write the organisation's policy
            // while the caller believed they wrote one team's.
            if r.team_id.is_some() {
                return Err(Status::invalid_argument(
                    "a team id at organisation scope is a request that meant team scope; there is \
                     one organisation and it is not named",
                ));
            }
            // Every default is wrong: false is the unsafe direction, true locks a
            // deployment that never asked, and keeping the stored value stops the
            // verb from stating a wanted result.
            if r.locked.is_none() {
                return Err(Status::invalid_argument(
                    "locked is required at organisation scope: it has no safe default, and an \
                     unstated lock is the permissive half of a policy nobody chose",
                ));
            }
            // The organisation always holds a value — the resolution's first step
            // refuses an unset one — so there is nothing there to clear.
            if r.clear {
                return Err(Status::invalid_argument(
                    "the organisation's value cannot be cleared: it always holds one, and a \
                     deployment changes it by stating the other value",
                ));
            }
        }
        SettingScope::Team => {
            // ABSENT and PRESENT-AND-EMPTY are two cases, and this boundary has
            // to refuse the second: an empty key in the override map is a row no
            // record's team will ever match.
            if !r.team_id.as_deref().is_some_and(|t| !t.is_empty()) {
                return Err(Status::invalid_argument(
                    "a team id is required at team scope: nothing else names the override to write",
                ));
            }
            // Meaningful at organisation scope only. `false` silently discarded
            // is exactly the case this refusal exists for, which is why the field
            // carries presence and this test is `is_some` rather than the value.
            if r.locked.is_some() {
                return Err(Status::invalid_argument(
                    "locked is meaningful at organisation scope only: a team cannot state whether \
                     teams may override",
                ));
            }
        }
    }

    // SENT EXPLICITLY, THE ZERO IS STILL A REFUSAL AND NEVER A CLEAR — at either
    // scope. It is what a caller that populated nothing sends, and reading it as
    // a withdrawal would let an unpopulated field destroy configuration silently.
    if r.value == Some(SettingValue::Unspecified as i32) {
        return Err(Status::invalid_argument(
            "value was sent unspecified: that is what an unpopulated field looks like, and it is \
             never read as a value or as a withdrawal",
        ));
    }

    // **AN OMITTED VALUE CAN NEVER BE READ AS A DELETION** (ADR-0524). This and
    // the clause above are two tests rather than one on purpose: they are the two
    // shapes that `value.unwrap_or_default()` collapses into a single case, and
    // one test cannot fail for both.
    if r.value.is_none() && !r.clear {
        return Err(Status::invalid_argument(
            "value is required unless clear is set: a request that states neither says nothing at \
             all",
        ));
    }

    // Two contradicting instructions, and neither is the obvious one to discard.
    if r.clear && r.value.is_some() {
        return Err(Status::invalid_argument(
            "clear and value contradict each other: withdraw the override or state one, never \
             both in the same request",
        ));
    }

    // A store that accepted free text would accrete settings nothing reads, and a
    // typo would be persisted as a new setting rather than refused at the call
    // that made it. Adding a member is a contract release, never a data change.
    if r.name != OWNER_READS_OWN_RECORD {
        return Err(Status::invalid_argument(
            "name is not a setting this contract declares; the vocabulary is closed and adding to \
             it is a contract release",
        ));
    }

    Ok(scope)
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

/// The original outcome of a redemption already recorded under `key`.
///
/// `Ok(None)` means this key has redeemed nothing yet. `Err(INVALID_ARGUMENT)`
/// means it redeemed a DIFFERENT secret: D9 as amended refuses a key carrying a
/// different request rather than replaying it, because replaying would answer a
/// request nobody made and report success. This boundary can make that
/// comparison only because the secret hash is deterministic — the same property
/// that lets an enrolment be found by it. It cannot make the equivalent
/// comparison on the password, so `iam` makes that one.
///
/// **THAT `INVALID_ARGUMENT` IS A STORE-INTERNAL DISTINCTION AND MUST NOT REACH
/// AN UNAUTHENTICATED CALLER.** The comparison precedes the lookup deliberately —
/// a refusal issued after it would report whether the presented secret exists —
/// but that ordering is also what lets somebody holding NO secret present any key
/// and read the answer off the status code. This boundary is right to tell the
/// cases apart, in the same way it tells NOT_FOUND from SPENT from EXPIRED; the
/// collapsing belongs to `iam`, which owes its caller one refusal for all of
/// them, and it now does it for this error too.
async fn replay(
    conn: &mut sqlx::MySqlConnection,
    key: &str,
    presented: &[u8],
    lock: Lock,
) -> Result<Option<RedeemEnrolmentResponse>, Status> {
    const BASE: &str = "SELECT secret_hash, enrolment_id, user_id
                          FROM iam_enrolment_redemption
                         WHERE idempotency_key = ?";
    // AUDIT: both arms are literals in this file; `key` is bound, never
    // interpolated.
    let sql = match lock {
        Lock::No => BASE.to_string(),
        Lock::Yes => format!("{BASE} FOR UPDATE"),
    };

    let prior = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(key)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db)?;
    let Some(prior) = prior else {
        return Ok(None);
    };

    let original: Vec<u8> = prior.try_get("secret_hash").map_err(db)?;
    if original != presented {
        return Err(Status::invalid_argument(
            "this idempotency key was used with a different enrolment secret",
        ));
    }

    let user_id: String = prior.try_get("user_id").map_err(db)?;
    let enrolment_id: String = prior.try_get("enrolment_id").map_err(db)?;
    // The username again, because recovering it is what the retry is FOR. Read
    // rather than stored a second time: duplicating personal data into this
    // ledger to answer a replay would put a second copy of it in the schema for
    // no gain.
    let external_id_ciphertext: Vec<u8> =
        sqlx::query_scalar("SELECT external_id_ciphertext FROM iam_user WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(db)?;

    Ok(Some(RedeemEnrolmentResponse {
        outcome: RedeemOutcome::Redeemed as i32,
        user_id,
        enrolment_id,
        external_id_ciphertext,
    }))
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

/// Why a redemption did not happen, decided by a SELECT rather than guessed.
///
/// Reached only when the check-and-spend UPDATE matched nothing, and it has to
/// tell three cases apart that the caller must be able to distinguish from a
/// broken store: the secret is unknown, it was already spent, or its deadline
/// has passed.
///
/// A SOFT-DELETED PERSON'S ENROLMENT IS `NOT_FOUND`. The join makes it so, and
/// the enum has no fourth arm to say anything else — as far as this boundary is
/// concerned there is no live enrolment for a live person, which is what
/// NOT_FOUND means.
async fn unredeemable<'e, E>(executor: E, secret_hash: &[u8]) -> Result<RedeemOutcome, Status>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let row = sqlx::query(
        "SELECT CAST(e.spent_at IS NOT NULL AS SIGNED) AS is_spent
           FROM iam_enrolment e JOIN iam_user u ON u.id = e.user_id
          WHERE e.secret_hash = ? AND u.deleted_at IS NULL",
    )
    .bind(secret_hash)
    .fetch_optional(executor)
    .await
    .map_err(db)?;

    let Some(row) = row else {
        return Ok(RedeemOutcome::NotFound);
    };
    match row.try_get::<i64, _>("is_spent").map_err(db)? {
        0 => Ok(RedeemOutcome::Expired),
        _ => Ok(RedeemOutcome::Spent),
    }
}

/// Epoch seconds back into the contract's timestamp.
fn epoch(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

/// A status name for the metric label, shared rather than re-spelled per service.
fn label(status: &Status) -> &'static str {
    status_name(status)
}
