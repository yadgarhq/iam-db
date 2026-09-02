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

use sqlx::{MySqlPool, Row};
use tonic::{Request, Response, Status};
use yadgar_telemetry::grpc::status_name;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::pb::yadgar::common::v1::Meta;
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

const SERVICE: &str = "iam-db";

/// What `ListCredentials` returns when the caller names no page size.
const DEFAULT_PAGE_SIZE: i32 = 50;
/// The ceiling, because `page_size` is a caller-supplied `int32`. Without it one
/// request asks for every credential in the table and the memory to hold them.
const MAX_PAGE_SIZE: i32 = 200;

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
        // ONE TRANSACTION for all three reads, because the contract says the
        // admin flag and the overrides are read in the SAME transaction as the
        // credential. Three separate pool queries would be three points in time,
        // and the window between them is one in which a withdrawn admin flag or
        // a tightened limit is already gone from the store and not yet in force
        // in the answer — cached, at the caller, for a whole cache lifetime.
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

        tx.commit().await.map_err(db)?;

        let resp = ResolveCredentialResponse {
            user_id,
            team_ids,
            credential_id,
            is_admin,
            rate_limit_overrides,
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

        sqlx::query(
            "INSERT INTO iam_password (user_id, argon2id_hash) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE argon2id_hash = VALUES(argon2id_hash)",
        )
        .bind(&r.user_id)
        .bind(&r.argon2id_hash)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: 1,
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

        let id = format!("yadgar:credential:{}", uuid::Uuid::now_v7());
        sqlx::query(
            // FROM_UNIXTIME, because the contract carries epoch SECONDS and the
            // column is a TIMESTAMP. Binding the integer directly makes MariaDB
            // read 1798761600 as a datetime literal — it does not error, it
            // stores something else, and the credential then expires at a time
            // nobody chose. Converting in SQL keeps the one representation the
            // column understands.
            "INSERT INTO iam_credential (id, user_id, token_hash, label, expires_at)
             VALUES (?, ?, ?, ?, FROM_UNIXTIME(?))",
        )
        .bind(&id)
        .bind(&r.user_id)
        .bind(&r.token_hash)
        .bind(&r.label)
        .bind(r.expires_at.map(|t| t.seconds))
        .execute(&self.pool)
        .await
        .map_err(db)?;

        call.finish(Outcome {
            status: "OK",
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

        // Idempotent (D9) by the composite primary key rather than by checking
        // first, which would be a race between the check and the insert.
        sqlx::query(
            "INSERT IGNORE INTO iam_team_member (team_id, user_id, added_by)
             VALUES (?, ?, 'system')",
        )
        .bind(&r.team_id)
        .bind(&r.user_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: 1,
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

        // Explicit, because the alternative is worse than a rejection. The
        // column is NOT NULL, so FROM_UNIXTIME(NULL) makes the engine refuse
        // under STRICT_TRANS_TABLES — and `db()` renders every engine error as
        // "storage unavailable", which would report a caller's mistake as this
        // service being down.
        let expires_at = r
            .expires_at
            .ok_or_else(|| Status::invalid_argument("an enrolment must carry an expiry"))?;

        // The FOREIGN KEY proves the user row EXISTS; it does not prove the
        // person is live. Without this an enrolment minted for a soft-deleted
        // account is accepted, reported OK, and is then permanently NOT_FOUND on
        // redeem — because the redemption path DOES check. An admin would be
        // told the enrolment was issued and the person could never use it.
        live_user(&self.pool, &r.user_id).await?;

        let id = format!("yadgar:enrolment:{}", uuid::Uuid::now_v7());
        sqlx::query(
            // FROM_UNIXTIME for the reason CreateCredential already carries: the
            // contract sends epoch SECONDS and the column is a TIMESTAMP.
            // Binding the integer directly does not error — MariaDB reads it as
            // a datetime literal and stores something else, and the enrolment
            // then expires at a time nobody chose.
            "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at)
             VALUES (?, ?, ?, FROM_UNIXTIME(?))",
        )
        .bind(&id)
        .bind(&r.user_id)
        .bind(&r.secret_hash)
        .bind(expires_at.seconds)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                Status::already_exists("that enrolment secret is already in use")
            }
            _ => db(e),
        })?;

        call.finish(Outcome {
            status: "OK",
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
        // DISAMBIGUATED RATHER THAN INFERRED FROM THE ROW COUNT, because the two
        // reasons for zero are not the same answer. MariaDB reports CHANGED rows,
        // not matched ones, so re-asserting a flag a user already has affects
        // zero rows — and treating that as NOT_FOUND would break the idempotence
        // this handler gets for free from assigning rather than toggling.
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
        live_user(&self.pool, &r.user_id).await?;

        let done = match &r.limit {
            // Upsert onto the composite primary key — the same structural
            // idempotence AddTeamMember gets from iam_team_member's.
            Some(limit) => {
                sqlx::query(
                    "INSERT INTO iam_rate_limit_override (user_id, module, kind, rate, burst)
                     VALUES (?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE rate = VALUES(rate), burst = VALUES(burst)",
                )
                .bind(&r.user_id)
                .bind(&r.module)
                .bind(r.kind)
                .bind(limit.rate)
                .bind(limit.burst)
                .execute(&self.pool)
                .await
            }
            // ABSENT DELETES, restoring the deployment's configured default for
            // this bucket. A stored zero would not: that is a denial.
            None => {
                sqlx::query(
                    "DELETE FROM iam_rate_limit_override
                      WHERE user_id = ? AND module = ? AND kind = ?",
                )
                .bind(&r.user_id)
                .bind(&r.module)
                .bind(r.kind)
                .execute(&self.pool)
                .await
            }
        }
        .map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: done.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(SetRateLimitOverrideResponse {}))
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

/// The original outcome of a redemption already recorded under `key`.
///
/// `Ok(None)` means this key has redeemed nothing yet. `Err(INVALID_ARGUMENT)`
/// means it redeemed a DIFFERENT secret: D9 as amended refuses a key carrying a
/// different request rather than replaying it, because replaying would answer a
/// request nobody made and report success. This boundary can make that
/// comparison only because the secret hash is deterministic — the same property
/// that lets an enrolment be found by it. It cannot make the equivalent
/// comparison on the password, so `iam` makes that one.
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
#[allow(dead_code)]
fn label(status: &Status) -> &'static str {
    status_name(status)
}
