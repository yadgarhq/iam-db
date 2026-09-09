//! The four RPCs whose subject is a credential.
//!
//! `resolve` is the hot path and the reason this store exists: a token hash to
//! an identity, in one transaction, with liveness decided IN the queries. The
//! other three are the lifecycle around it — minting one, tombstoning one, and
//! listing what a person holds.
//!
//! They are one module because they are one table, and because the liveness
//! clauses that make `resolve` correct are the same clauses the other three must
//! not contradict.

use super::*;

impl IamDb {
    pub(super) async fn resolve(
        &self,
        r: ResolveCredentialRequest,
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

    pub(super) async fn mint_credential(
        &self,
        r: CreateCredentialRequest,
        call: Call,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
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
        //
        // THE BRANCH FALLS THROUGH IF THE RE-READ DISAGREES, AND THAT IS NEW
        // WITH LEDGER 695 RATHER THAN INHERITED. Before this change a zero row
        // count was impossible here; now `live_user` returning Ok after a zero
        // match sends this handler on to report OK with a `credential_id` for a
        // row it never inserted. Reaching it needs `deleted_at` to go set and
        // then back to NULL between two statements, and nothing in this estate
        // un-deletes a person — that column has no writer outside a test helper
        // that only ever sets it. `SetUserAdmin` has carried the identical
        // branch since it was written, and its exposure is milder only because
        // its response carries nothing to fabricate. THE HONEST FIX is to make a
        // zero-row write terminal whatever the re-read says. That is a change to
        // these three handlers AND to `SetUserAdmin`, so it belongs with the
        // argument for changing `SetUserAdmin` rather than smuggled in beside a
        // race fix. `CreateEnrolment` and `AddTeamMember` carry the same branch
        // and point here.
        if done.rows_affected() == 0 {
            live_user(&self.pool, &r.user_id).await?;
        }

        call.finish(Outcome {
            status: "OK",
            // STILL A LITERAL, AND THE REASON IS NARROWER THAN "THE NONE CASE
            // ALREADY RETURNED". This statement inserts exactly one row or none;
            // none returns NOT_FOUND unless the re-read above disagrees, which
            // is the fall-through that branch describes and which nothing can
            // currently cause. Only `SetPassword`'s upsert can report a number a
            // constant cannot predict.
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateCredentialResponse {
            credential_id: id,
        }))
    }

    pub(super) async fn revoke(
        &self,
        r: RevokeCredentialRequest,
        call: Call,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
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

    pub(super) async fn credential_page(
        &self,
        r: ListCredentialsRequest,
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
}

/// Epoch seconds back into the contract's timestamp.
fn epoch(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}
