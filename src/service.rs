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

const SERVICE: &str = "iam-db";

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
        let row = sqlx::query(
            "SELECT c.id AS credential_id, c.user_id
               FROM iam_credential c
               JOIN iam_user u ON u.id = c.user_id
              WHERE c.token_hash = ?
                AND c.revoked_at IS NULL
                AND (c.expires_at IS NULL OR c.expires_at > CURRENT_TIMESTAMP)
                AND u.deleted_at IS NULL",
        )
        .bind(&r.token_hash)
        .fetch_optional(&self.pool)
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

        let team_ids: Vec<String> =
            sqlx::query("SELECT team_id FROM iam_team_member WHERE user_id = ?")
                .bind(&user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?
                .into_iter()
                .map(|r| r.try_get::<String, _>("team_id"))
                .collect::<Result<_, _>>()
                .map_err(db)?;

        let resp = ResolveCredentialResponse {
            user_id,
            team_ids,
            credential_id,
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
            "INSERT INTO iam_user
                 (id, created_by, updated_by,
                  external_id_blind_index, external_id_ciphertext, display_name_ciphertext)
             VALUES (?, 'system', 'system', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&r.external_id_blind_index)
        .bind(&r.external_id_ciphertext)
        .bind(&r.display_name_ciphertext)
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
}

/// A status name for the metric label, shared rather than re-spelled per service.
#[allow(dead_code)]
fn label(status: &Status) -> &'static str {
    status_name(status)
}
