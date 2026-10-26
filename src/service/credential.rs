//! The five RPCs whose subject is a credential.
//!
//! `resolve` is the hot path and the reason this store exists: a token hash to
//! an identity, in one transaction, with liveness decided IN the queries. The
//! other four are the lifecycle around it — minting one (the child module
//! `mint`, epoch-checked under ADR-0972 (4)), tombstoning one, tombstoning every
//! one a person holds (the child module `all`, ADR-0945), and listing what a
//! person holds.
//!
//! They are one module because they are one table, and because the liveness
//! clauses that make `resolve` correct are the same clauses the other four must
//! not contradict.

use super::*;

mod all;
mod mint;

impl IamDb {
    pub(super) async fn resolve(
        &self,
        r: ResolveCredentialRequest,
        deadline: Deadline,
        call: Call,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
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
        let mut conn = self.acquire(deadline).await?;
        let mut tx = conn.begin(Isolation::Default).await?;

        let row = sqlx::query(
            // `expires_at` IN THIS STATEMENT (ADR-0972 (3)), so the expiry `iam`
            // clamps the gateway's cache to belongs to the very row that
            // matched. UNIX_TIMESTAMP for the reason `credential_page` gives.
            "SELECT c.id AS credential_id, c.user_id, u.is_admin,
                    CAST(UNIX_TIMESTAMP(c.expires_at) AS SIGNED) AS expires_at
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
        let column_admin: bool = row.try_get("is_admin").map_err(db)?;
        let expires_at = row
            .try_get::<Option<i64>, _>("expires_at")
            .map_err(db)?
            .map(epoch);

        let (team_ids, is_admin) =
            teams_and_admin(&mut tx, &user_id, r.admin_from_team, column_admin).await?;

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

        let owner_reads_own_record = owner_reads_own_record(&mut tx).await?;

        tx.commit().await.map_err(db)?;

        let resp = ResolveCredentialResponse {
            user_id,
            team_ids,
            credential_id,
            is_admin,
            rate_limit_overrides,
            owner_reads_own_record: Some(owner_reads_own_record),
            expires_at,
        };
        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    pub(super) async fn revoke(
        &self,
        r: RevokeCredentialRequest,
        deadline: Deadline,
        rid: &str,
        call: Call,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        // ADR-0534's RECORDING HALF. The target is the credential revoked.
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "RevokeCredential",
            &seg(&r.credential_id),
        );

        // ADR-0972 (2): THE OWNER IS REQUIRED. Refused after the record, which
        // logs the attempt (ADR-0534), and before any statement runs.
        if r.user_id.is_empty() {
            let refusal = Status::invalid_argument("a revoke must name the credential's user");
            call.fail(label(&refusal));
            return Err(refusal);
        }

        // A tombstone, not a delete (D26). Idempotent by the WHERE clause:
        // revoking twice leaves the first timestamp, so the record still says
        // when access actually ended rather than when someone last asked.
        //
        // MATCHED ON THE PAIR (ADR-0972 (2)), so an administrator naming one
        // person cannot revoke another person's credential by its id.
        let mut conn = self.acquire(deadline).await?;
        let row = sqlx::query(
            "UPDATE iam_credential
                SET revoked_at = CURRENT_TIMESTAMP
              WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
        )
        .bind(&r.credential_id)
        .bind(&r.user_id)
        .execute(&mut *conn)
        .await
        .map_err(db)?;

        // ZERO ROWS IS EITHER "ALREADY REVOKED, AND THIS USER'S" — OK, as it
        // always was — or "NO SUCH PAIR", which is NOT_FOUND whether the id is
        // unknown or belongs to somebody else. The two read the same to a
        // caller naming the wrong person, so the answer reveals nothing about
        // another person's credentials.
        if row.rows_affected() == 0 {
            let owned: Option<String> =
                sqlx::query_scalar("SELECT id FROM iam_credential WHERE id = ? AND user_id = ?")
                    .bind(&r.credential_id)
                    .bind(&r.user_id)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(db)?;
            if owned.is_none() {
                let refusal = Status::not_found("no such credential");
                call.fail(label(&refusal));
                return Err(refusal);
            }
        }

        call.finish(Outcome {
            status: "OK",
            rows: row.rows_affected() as u32,
            ..Default::default()
        });
        Ok(Response::new(RevokeCredentialResponse {
            user_id: r.user_id,
        }))
    }

    pub(super) async fn credential_page(
        &self,
        r: ListCredentialsRequest,
        deadline: Deadline,
        call: Call,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
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
        let mut conn = self.acquire(deadline).await?;
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
        .fetch_all(&mut *conn)
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
}

/// Epoch seconds back into the contract's timestamp.
fn epoch(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

/// The setting ADR-0522 puts in every `ResolveCredential` answer, at both levels
/// and unresolved.
///
/// Lifted out of [`IamDb::resolve`] whole, and it is one function because it is
/// one value: the organisation's row, its lock, and every team's override are
/// the three inputs the enforcing `-db` needs, and an answer carrying two of
/// them is not a smaller answer but a wrong one.
///
/// **STILL THIS MODULE'S OWN COPY, deliberately.** `setting::inherited` holds a
/// function that reads the same two rows for the write path's read-back, and the
/// duplication is what keeps a later change to that read-back from silently
/// changing what every credential resolution answers.
async fn owner_reads_own_record(
    tx: &mut sqlx::MySqlTransaction<'_>,
) -> Result<InheritedSetting, Status> {
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

/// The user's LIVE teams, and `is_admin` as the request asks for it.
async fn teams_and_admin(
    tx: &mut sqlx::MySqlTransaction<'_>,
    user_id: &str,
    admin_from_team: bool,
    column_admin: bool,
) -> Result<(Vec<String>, bool), Status> {
    // LIVE TEAMS ONLY (yaadgaar #303, plans/team-access.md §7). A member
    // row of an archived team (`deleted_at` set by `SyncTeams`) stays in
    // the store and is not reported: an archived team admits nobody.
    let team_ids: Vec<String> = sqlx::query(
        "SELECT m.team_id FROM iam_team_member m
               JOIN iam_team t ON t.id = m.team_id
              WHERE m.user_id = ? AND t.deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db)?
    .into_iter()
    .map(|r| r.try_get::<String, _>("team_id"))
    .collect::<Result<_, _>>()
    .map_err(db)?;

    // ADMIN FROM THE TEAM WHEN `iam` SAYS SO (IAM_ADMIN_FROM_TEAM, relayed
    // as `admin_from_team`): live membership of `administrators`, read from
    // the very `team_ids` this answer carries, so the two cannot disagree.
    // False or absent: the column, as before (plans/team-access.md §4).
    let is_admin = match admin_from_team {
        true => team_ids.iter().any(|t| t == super::team::ADMINISTRATORS),
        false => column_admin,
    };
    Ok((team_ids, is_admin))
}
