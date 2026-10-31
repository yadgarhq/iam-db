//! Adoption: the marker recorded over a POPULATED store that holds none, on
//! `iam`'s proof that its key set encrypted the store's oldest rows (ADR-1089,
//! amending ADR-0765). Two arms: `ListKeyIdentityEvidence` serves the rows the
//! proof is made from, and `AdoptKeyIdentity` records.
//!
//! **THE PROOF IS `iam`'s AND THIS SERVICE NEVER MAKES IT** (D72): it holds no
//! key and sees no plaintext. What it checks is the SHAPE of the evidence —
//! that the ids are exactly the N oldest `iam_user` rows — and that check is
//! the INSERT's own predicate, so it holds even when `iam` regresses to
//! sampling in some other order.
//!
//! **ONE ORDER, SPELLED ONCE.** [`OLDEST_FIRST`] is the order the read serves
//! and the order the predicate checks against. Were they two strings, a change
//! to one would refuse every honest adoption or accept a dishonest one.

use std::collections::HashSet;

use super::*;

/// The order of the evidence: by creation, then by id. ASCENDING, and that is
/// the property ADR-1089 rests on. An `iam` that has not passed the check stays
/// Ready, so a pod holding the wrong key set can have written rows; they are
/// the NEWEST, and the oldest rows predate it.
///
/// `created_at` is the server's `DEFAULT CURRENT_TIMESTAMP` and no write path
/// sets it, so a caller cannot place a row at the front. Its second resolution
/// makes ties common; `id` breaks them.
///
/// SOFT-DELETED ROWS ARE NOT FILTERED, here or anywhere this is used.
/// `deleted_at` says nothing about which key encrypted a row, and
/// `SetKeyIdentity`'s emptiness predicate counts them too.
const OLDEST_FIRST: &str = "ORDER BY created_at, id";

/// The most evidence one adoption carries. A CONTRACT NUMBER (ADR-1089), not a
/// deployment knob: `iam` reads every row up to it and this service refuses
/// more.
const MAX_EVIDENCE: usize = 64; // ADR-0569-EXCEPTION(CB): ADR-1089's contract cap on AdoptKeyIdentity evidence, stated in iamdb.proto.

/// A keyset position: the last `(created_at, id)` served, with `created_at` as
/// epoch seconds. Before the first row it is `(-1, "")`, because every stored
/// epoch is at least 0.
///
/// **EPOCH SECONDS ON BOTH SIDES OF THE COMPARISON**, never `FROM_UNIXTIME(?)`
/// against the column: that converts through the session time zone, and in a
/// zone with daylight saving one wall-clock hour each autumn names two epochs.
struct Position {
    epoch: i64,
    id: String,
}

impl Position {
    /// The token is `<epoch>:<id>`. Opaque to the caller; an id holds `:`
    /// itself, so only the FIRST one separates.
    fn token(&self) -> String {
        format!("{}:{}", self.epoch, self.id)
    }

    fn parse(token: &str) -> Result<Self, Status> {
        if token.is_empty() {
            return Ok(Self {
                epoch: -1,
                id: String::new(),
            });
        }
        token
            .split_once(':')
            .and_then(|(epoch, id)| {
                Some(Self {
                    epoch: epoch.parse::<i64>().ok().filter(|e| *e >= 0)?,
                    id: id.into(),
                })
            })
            .ok_or_else(|| Status::invalid_argument("page_token is not one this service issued"))
    }
}

/// THE REQUEST RULES ADR-1089 PUTS ON THE EVIDENCE, and none of them reads the
/// store: empty, more than [`MAX_EVIDENCE`], or a repeated id is a malformed
/// request on any store.
///
/// A DUPLICATE IS REFUSED RATHER THAN COLLAPSED. The predicate counts distinct
/// matches against N, so `[oldest, oldest]` sent as N = 2 is already refused
/// there — but as FAILED_PRECONDITION, a statement about the store, when the
/// fault is in the request.
///
/// **A DUPLICATE IS JUDGED AS THE COLUMN JUDGES IT**, not byte for byte.
/// `iam_user.id` compares under `utf8mb4_uca1400_ai_ci`: case-insensitive, and
/// PAD SPACE, so trailing U+0020 is ignored and leading spaces are not. Two ids
/// differing only so are one row to the predicate, and byte-exact here would
/// pass them on to a FAILED_PRECONDITION. [`same_row`] folds those two.
/// ACCENT-INSENSITIVITY IS NOT EMULATED: a pair equal only by accent holds a
/// non-ASCII id, every id this store writes is `yadgar:user:` and a uuidv7,
/// so it still names no row and is refused FAILED_PRECONDITION with nothing
/// written.
fn evidence(ids: &[String]) -> Result<(), Status> {
    if ids.is_empty() {
        return Err(Status::invalid_argument(
            "evidence_user_ids is empty; an adoption with no evidence asserts a key identity on \
             none",
        ));
    }
    if ids.len() > MAX_EVIDENCE {
        return Err(Status::invalid_argument(
            "evidence_user_ids holds more than 64 ids",
        ));
    }
    let mut seen = HashSet::with_capacity(ids.len());
    match ids.iter().all(|id| seen.insert(same_row(id))) {
        true => Ok(()),
        false => Err(Status::invalid_argument("evidence_user_ids repeats an id")),
    }
}

/// The key under which two ids name the same `iam_user` row: see [`evidence`].
fn same_row(id: &str) -> String {
    id.trim_end_matches(' ').to_lowercase()
}

impl IamDb {
    /// The key-bearing columns of `iam_user`, [`OLDEST_FIRST`], paged by
    /// keyset. It consults no marker and refuses nothing about the store: an
    /// empty store answers OK with no rows.
    pub(in crate::service) async fn key_identity_evidence(
        &self,
        r: ListKeyIdentityEvidenceRequest,
        deadline: Deadline,
        call: Call,
    ) -> Result<Response<ListKeyIdentityEvidenceResponse>, Status> {
        match self.evidence_page(&r, deadline).await {
            Ok(page) => {
                call.finish(Outcome {
                    status: "OK",
                    rows: page.evidence.len() as u32,
                    ..Default::default()
                });
                Ok(Response::new(page))
            }
            Err(refusal) => {
                call.fail(label(&refusal));
                Err(refusal)
            }
        }
    }

    async fn evidence_page(
        &self,
        r: &ListKeyIdentityEvidenceRequest,
        deadline: Deadline,
    ) -> Result<ListKeyIdentityEvidenceResponse, Status> {
        let after = Position::parse(&r.page_token)?;
        let page_size = match r.page_size {
            n if n <= 0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };

        // KEYSET, NEVER OFFSET: a row created between two pages cannot shift
        // the window, so no row is served twice or skipped. Not sargable — no
        // index carries `created_at` — and the read is `iam`'s startup check,
        // not a hot path.
        //
        // AUDIT: `OLDEST_FIRST` is a literal in this file; nothing a caller
        // sent is interpolated.
        let sql = format!(
            "SELECT id, external_id_ciphertext, display_name_ciphertext,
                    external_id_blind_index,
                    CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_epoch
               FROM iam_user
              WHERE CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) > ?
                 OR (CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) = ? AND id > ?)
              {OLDEST_FIRST}
              LIMIT ?"
        );
        let mut conn = self.acquire(deadline).await?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(after.epoch)
            .bind(after.epoch)
            .bind(&after.id)
            .bind(page_size)
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?;

        let mut evidence = Vec::with_capacity(rows.len());
        let mut last = None;
        for row in &rows {
            let user_id: String = row.try_get("id").map_err(db)?;
            last = Some(Position {
                epoch: row.try_get("created_epoch").map_err(db)?,
                id: user_id.clone(),
            });
            evidence.push(KeyIdentityEvidence {
                user_id,
                external_id_ciphertext: row.try_get("external_id_ciphertext").map_err(db)?,
                display_name_ciphertext: row.try_get("display_name_ciphertext").map_err(db)?,
                external_id_blind_index: row.try_get("external_id_blind_index").map_err(db)?,
            });
        }

        // A token ONLY when the page filled, as `ListCredentials` does.
        let next_page_token = match evidence.len() == page_size as usize {
            true => last.map(|p| p.token()).unwrap_or_default(),
            false => String::new(),
        };
        Ok(ListKeyIdentityEvidenceResponse {
            evidence,
            next_page_token,
        })
    }

    /// Record the marker over a populated store with none, ONCE, on evidence
    /// that is exactly its N oldest rows. Where a marker is stored the answer
    /// is the comparison, never a write — `SetKeyIdentity`'s rules, through
    /// the same [`outcome_of`].
    pub(in crate::service) async fn adopt_marker(
        &self,
        r: AdoptKeyIdentityRequest,
        deadline: Deadline,
        call: Call,
    ) -> Result<Response<AdoptKeyIdentityResponse>, Status> {
        match self.record_adoption(&r, deadline).await {
            Ok(outcome) => {
                call.finish(Outcome {
                    status: "OK",
                    rows: u32::from(outcome == KeyIdentityOutcome::Recorded),
                    ..Default::default()
                });
                Ok(Response::new(AdoptKeyIdentityResponse {
                    outcome: outcome as i32,
                }))
            }
            Err(refusal) => {
                call.fail(label(&refusal));
                Err(refusal)
            }
        }
    }

    async fn record_adoption(
        &self,
        r: &AdoptKeyIdentityRequest,
        deadline: Deadline,
    ) -> Result<KeyIdentityOutcome, Status> {
        presented(&r.key_fingerprint, r.derivation_version)?;
        evidence(&r.evidence_user_ids)?;
        let key = key_of(&r.idempotency);
        let n = r.evidence_user_ids.len() as u64;

        let mut conn = self.acquire(deadline).await?;
        let mut tx = conn.begin(Isolation::Default).await?;

        // **THE EVIDENCE RULE RIDES IN THE WRITE (D5)**, for `SetKeyIdentity`'s
        // reason: a check followed by an INSERT is the same race with a longer
        // window. The derived table is the N oldest rows; the count is how many
        // of the presented ids are among them; equal to N means the ids ARE
        // those rows. A SET comparison, so the order of the ids is free. It is
        // false on an empty store, on an id nobody wrote, on a store with fewer
        // than N rows, and on any set that is not the oldest. MariaDB refuses
        // `LIMIT` inside `IN (SELECT ...)`, which is why the oldest rows are a
        // derived table and not an IN-subquery.
        //
        // **THIS INSERT IS THE TRANSACTION'S FIRST STATEMENT**, and
        // [`outcome_of`]'s duplicate-key branch is correct only while it is:
        // `record_key_identity` states the measured 1020 an earlier read
        // causes. No `ON DUPLICATE KEY UPDATE`, for write-once.
        //
        // AUDIT: `OLDEST_FIRST` is a literal and the IN list is N (at most 64)
        // placeholders; every caller value is bound.
        let placeholders = vec!["?"; r.evidence_user_ids.len()].join(", ");
        let sql = format!(
            "INSERT INTO iam_key_identity
                 (singleton, derivation_version, key_fingerprint, idempotency_key)
             SELECT 1, ?, ?, ? FROM DUAL
              WHERE (SELECT COUNT(*)
                       FROM (SELECT id FROM iam_user {OLDEST_FIRST} LIMIT ?) oldest
                      WHERE oldest.id IN ({placeholders})) = ?"
        );
        let mut insert = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(r.derivation_version)
            .bind(&r.key_fingerprint)
            .bind(&key)
            .bind(n);
        for id in &r.evidence_user_ids {
            insert = insert.bind(id);
        }
        let attempt = insert.bind(n).execute(&mut *tx).await;

        let p = Presented {
            fingerprint: &r.key_fingerprint,
            version: r.derivation_version,
            key: &key,
        };
        // NO MARKER AND NO WRITE: the ids are not the N oldest rows. Nothing
        // is written, so nothing is kept under the idempotency key either, and
        // a retry with corrected evidence is evaluated afresh.
        let outcome = outcome_of(attempt, &mut tx, &p).await?.ok_or_else(|| {
            Status::failed_precondition(
                "no marker is stored and evidence_user_ids are not exactly the oldest rows of \
                 this store; an adoption is recorded only on its oldest rows",
            )
        })?;

        tx.commit().await.map_err(db)?;
        Ok(outcome)
    }
}
