//! The key-identity marker: WHICH key set encrypted the rows in this store
//! (ADR-0764), and under WHICH derivation that fingerprint was produced
//! (ADR-0765).
//!
//! **THE MARKER IS THE PAIR, AND A COMPARISON IS ONLY EVER MADE WITHIN ONE
//! VERSION.** Same version and equal fingerprints is MATCH. Same version and
//! different fingerprints is MISMATCH, permanent, and `iam` exits. DIFFERENT
//! versions is DERIVATION_SKEW: no comparison is performed and nothing is
//! written, because two fingerprints from different functions differ for a
//! reason that says nothing about the key set.
//!
//! **THREE PROPERTIES HERE ARE ENFORCED BY NO COMPILER, NO LINT AND NO GATE IN
//! EITHER REPOSITORY.** Each has an implementation one character class away that
//! answers a legal member on every arm and is wrong, so each is stated where it
//! is implemented and each names the test that reddens when it breaks:
//!
//!  1. **RECORDING IS REFUSED WHEN THE STORE ALREADY HOLDS ROWS.** ABSENT says
//!     only that no marker is stored. It does NOT say the installation is
//!     empty, and only this service can tell the two apart — see
//!     [`IamDb::store_key_identity`]'s statement and
//!     `recording_is_refused_when_the_store_already_holds_rows`.
//!  2. **WRITE-ONCE.** The refusal to overwrite, not the enum, is what stops a
//!     pod holding the wrong key recording its own fingerprint and agreeing
//!     with itself for ever — see the INSERT and
//!     `two_concurrent_recordings_produce_exactly_one_recorded_and_one_mismatch`.
//!  3. **THE SINGLETON IS LOCATED AS THE SINGLETON.** Neither request field
//!     appears in any lookup — see [`marker`].
//!
//! **THE TWO CHANNELS ARE NOT INTERCHANGEABLE, AND ADR-0765 RULES THE
//! DISTINCTION RATHER THAN LEAVING IT TO TASTE.** `KeyIdentityOutcome` answers
//! what the comparison FOUND; a gRPC status answers that the comparison could
//! not be MADE. So a version skew is a member on an OK response, a populated
//! store is FAILED_PRECONDITION, and a caller branches on the channel before it
//! reaches a value.

use super::*;

/// `iam_key_identity.key_fingerprint` is `VARBINARY(255)`, counted in BYTES.
const MAX_KEY_FINGERPRINT: usize = 255;

/// The stored marker: the pair, and the idempotency key that wrote it.
///
/// It is read whole and NEVER returned. The comparison happens here, as the
/// contract requires: handing the marker back would put the ABSENT case on an
/// empty field, which is the shape `KeyIdentityOutcome` exists to delete.
struct Marker {
    derivation_version: u32,
    key_fingerprint: Vec<u8>,
    idempotency_key: String,
}

impl Marker {
    /// What a presented pair is, against this stored one.
    ///
    /// **THE VERSION IS CHECKED FIRST AND THE FINGERPRINTS ARE NOT COMPARED
    /// ACROSS VERSIONS.** A server that compared them anyway would answer
    /// MISMATCH to every `iam` in every installation on the day the derivation
    /// changed — each one correct about its keys, each one exiting. THE
    /// ASSERTION THAT REDDENS if this becomes a single fingerprint comparison:
    /// the two `DerivationSkew` assertions in
    /// `a_different_derivation_version_is_a_skew_on_both_arms_and_writes_nothing`.
    fn compared_with(&self, fingerprint: &[u8], version: u32) -> KeyIdentityOutcome {
        match self.derivation_version == version {
            false => KeyIdentityOutcome::DerivationSkew,
            true => match self.key_fingerprint == fingerprint {
                true => KeyIdentityOutcome::Match,
                false => KeyIdentityOutcome::Mismatch,
            },
        }
    }
}

/// THE TWO PRESENCE RULES, and they are the whole of what either arm validates
/// about the pair itself.
///
/// `bytes` and `uint32` have no presence in proto3, so a caller that populates
/// nothing sends empty and 0. Were empty storable it would be recorded as a
/// marker and then match itself for ever, with no key material involved at all;
/// were 0 storable, every caller that never learned of `derivation_version`
/// would agree with every other on a version none of them chose.
///
/// **NO LENGTH RULE AND NO FORMAT RULE ON THE FINGERPRINT**, deliberately: the
/// field is opaque so that `iam`'s derivation is not fixed into this contract.
/// The width check below is NOT such a rule — it is `fits_password_column`'s,
/// about what this column can HOLD. Letting the engine refuse instead renders
/// through `db()` as UNAVAILABLE, a retryable status for a request that can
/// never succeed, and under a non-strict `sql_mode` it does something worse: it
/// TRUNCATES, and a truncated marker matches a key set it was never derived
/// from. It is a fact about the request, which is the contract's own category
/// for INVALID_ARGUMENT on these arms.
fn presented(fingerprint: &[u8], version: u32) -> Result<(), Status> {
    if fingerprint.is_empty() {
        return Err(Status::invalid_argument(
            "key_fingerprint is empty; a marker with no key material would match itself for ever",
        ));
    }
    if fingerprint.len() > MAX_KEY_FINGERPRINT {
        return Err(Status::invalid_argument(
            "key_fingerprint is wider than the column can hold",
        ));
    }
    if version == 0 {
        return Err(Status::invalid_argument(
            "derivation_version is zero; versions start at 1",
        ));
    }
    Ok(())
}

/// THE SINGLETON, FOUND AS THE SINGLETON — obligation 3, and this function is
/// the whole of it.
///
/// **NEITHER REQUEST FIELD IS A PARAMETER HERE, AND THAT IS THE POINT.** The
/// row is read, and THEN compared. `WHERE key_fingerprint = ?` satisfies "one
/// marker" and "found without a join" and is still fatal: it finds nothing
/// whenever the key is wrong — the only case that matters — so that arm reports
/// ABSENT and can never answer MISMATCH. `WHERE derivation_version = ?` fails
/// the same way, reading a version skew as an empty store and earning it a
/// SECOND marker. `singleton` is a constant column the schema pins to 1, so
/// this WHERE clause references nothing a caller sent.
///
/// THE ASSERTIONS THAT REDDEN if either field reaches this clause:
/// `a_wrong_fingerprint_is_a_mismatch_and_never_absent` for the first, and
/// `a_different_derivation_version_is_a_skew_on_both_arms_and_writes_nothing`
/// for the second. Both read `Absent`.
///
/// `Lock::Yes` is the re-read inside [`IamDb::store_key_identity`]'s
/// transaction, and it is reached from BOTH arms of [`IamDb::outcome_of`]: the
/// duplicate-key arm, where the row exists and the read takes a record lock,
/// and the zero-matched-rows arm, where `iam_user` was non-empty and the marker
/// may be ABSENT — there the read finds nothing and takes a next-key lock over
/// an empty range, so ADR-0513 is NOT what licenses this lock and is no longer
/// cited as though it were. That second path runs on every test run, in
/// `recording_is_refused_when_the_store_already_holds_rows`, and it costs
/// nothing: the arm refuses, so nothing ever inserts into that range.
///
/// **`LOCK IN SHARE MODE`, NOT `FOR UPDATE`, AND THE DIFFERENCE IS MEASURED.**
/// A loser's refused INSERT already leaves a SHARED lock on the duplicate
/// primary-key row, so `FOR UPDATE` here asks to upgrade that share to an
/// exclusive, and with two or more losers holding the share the upgrade cycles.
/// Five callers, five fingerprints, one version, one fresh store: 1213 in 10
/// runs out of 10, raised HERE and never by the INSERT, and `db()` renders 1213
/// as the TRANSIENT UNAVAILABLE where the contract requires a permanent
/// MISMATCH. Re-requesting the share is granted at once, because the loser
/// already holds it: 0 deadlocks in 25 runs. RETRYING THE WHOLE TRANSACTION
/// ONCE ON 1213 WAS MEASURED FIRST AND IS NOT ENOUGH — the losers retry
/// together and cycle again, 13 runs in 25.
///
/// A locking read of EITHER kind is a CURRENT read, so the loser still sees the
/// winner's committed row at REPEATABLE READ. A snapshot re-read would use the
/// read view the INSERT established, miss that row, and answer
/// FAILED_PRECONDITION where the contract requires MISMATCH — which is why the
/// lock is weakened rather than dropped.
///
/// THE TEST THAT REDDENS:
/// `five_concurrent_recordings_answer_one_recorded_and_four_mismatch`.
/// `two_concurrent_recordings_produce_exactly_one_recorded_and_one_mismatch`
/// does NOT — one loser is one share, and one share has nothing to cycle with.
async fn marker<'e, E>(executor: E, lock: Lock) -> Result<Option<Marker>, Status>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    const BASE: &str = "SELECT derivation_version, key_fingerprint, idempotency_key
                          FROM iam_key_identity
                         WHERE singleton = 1";
    // AUDIT: both arms are literals in this file; nothing is interpolated.
    let sql = match lock {
        Lock::No => BASE.to_string(),
        Lock::Yes => format!("{BASE} LOCK IN SHARE MODE"),
    };

    let Some(row) = sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_optional(executor)
        .await
        .map_err(db)?
    else {
        return Ok(None);
    };

    Ok(Some(Marker {
        derivation_version: row.try_get("derivation_version").map_err(db)?,
        key_fingerprint: row.try_get("key_fingerprint").map_err(db)?,
        idempotency_key: row.try_get("idempotency_key").map_err(db)?,
    }))
}

/// D9 FIRST, THEN THE COMPARISON, and the order is the contract's.
///
/// A key replayed carrying a DIFFERENT value in EITHER field is two calls
/// claiming different key sets, or one key set under two derivations. Answering
/// the second with the first's outcome would report a marker this caller does
/// not hold, so it is refused rather than replayed. A replay carrying the SAME
/// payload returns the ORIGINAL outcome — RECORDED, not MATCH — which is D9's
/// ordinary rule and the reason this branch exists at all.
///
/// THE EMPTY STRING IS NOT A KEY (`RedeemEnrolment`'s rule), so an unkeyed call
/// never replays, and never collides with a marker that was written unkeyed.
fn replayed_or_compared(
    stored: &Marker,
    r: &SetKeyIdentityRequest,
    key: &str,
) -> Result<KeyIdentityOutcome, Status> {
    if key.is_empty() || key != stored.idempotency_key {
        return Ok(stored.compared_with(&r.key_fingerprint, r.derivation_version));
    }
    match stored.derivation_version == r.derivation_version
        && stored.key_fingerprint == r.key_fingerprint
    {
        true => Ok(KeyIdentityOutcome::Recorded),
        false => Err(Status::invalid_argument(
            "this idempotency key was used with a different key set or derivation; a repeated key \
             carrying a different payload is refused rather than replayed",
        )),
    }
}

impl IamDb {
    /// The read. It refuses NOTHING about the stored marker.
    ///
    /// A non-OK answer here is therefore never a finding: it is a malformed
    /// request, or a transport or deployment fault. Neither is a fact about
    /// what the store holds.
    pub(super) async fn key_identity(
        &self,
        r: GetKeyIdentityRequest,
        call: Call,
    ) -> Result<Response<GetKeyIdentityResponse>, Status> {
        if let Err(refusal) = presented(&r.key_fingerprint, r.derivation_version) {
            call.fail(label(&refusal));
            return Err(refusal);
        }

        // NO TRANSACTION AND NO LOCK. One statement reads one row, and there is
        // nothing to serialise against: this arm writes nothing on any answer.
        let outcome = match marker(&self.pool, Lock::No).await {
            Ok(Some(stored)) => stored.compared_with(&r.key_fingerprint, r.derivation_version),
            // ABSENT, AND IT MEANS ONLY THAT NO MARKER IS STORED. What the
            // CALLER may conclude from it is bounded by `store_key_identity`'s
            // refusal below, never by this line.
            Ok(None) => KeyIdentityOutcome::Absent,
            Err(refusal) => {
                call.fail(label(&refusal));
                return Err(refusal);
            }
        };

        call.finish(Outcome {
            status: "OK",
            // ZERO ON ABSENT, BECAUSE NO ROW WAS READ. `ResolveCredential`
            // records a miss as OK with no rows and this arm's miss is the same
            // event; a literal 1 here would be the false constant
            // `SetPassword`'s own comment was written to delete. No hook checks
            // a row count — `observe-coverage` says so in as many words — so it
            // is stated rather than enforced.
            rows: u32::from(outcome != KeyIdentityOutcome::Absent),
            ..Default::default()
        });
        Ok(Response::new(GetKeyIdentityResponse {
            outcome: outcome as i32,
        }))
    }

    /// The write, ONCE, and only where this store holds neither a marker nor
    /// any rows.
    ///
    /// **THE COMPARISON AND THE INSERT ARE ONE STATEMENT (D5).** A read
    /// followed by a write is the same race with a longer window, and the race
    /// here is two replicas rolling out under different key sets that BOTH read
    /// ABSENT before either writes. One must win and the other must be TOLD so.
    ///
    /// **THERE IS NO `ON DUPLICATE KEY UPDATE` CLAUSE, AND ITS ABSENCE IS THE
    /// WHOLE OF WRITE-ONCE.** A plain INSERT onto the singleton primary key
    /// cannot overwrite: a second marker raises a duplicate-key error, which is
    /// caught below and turned into a COMPARISON against the row already there.
    /// The mutation one clause away is `ON DUPLICATE KEY UPDATE key_fingerprint
    /// = VALUES(key_fingerprint)`, and it would hand a pod holding the wrong key
    /// the means to make itself pass — record its own fingerprint, agree with
    /// itself for ever, and leave the rows it cannot read behind an assertion
    /// that they are fine. THE ASSERTIONS THAT REDDEN under that mutation: the
    /// `stored_marker` read-back in
    /// `a_second_recording_under_a_different_fingerprint_does_not_overwrite` and
    /// the sorted-pair assertion in
    /// `two_concurrent_recordings_produce_exactly_one_recorded_and_one_mismatch`.
    ///
    /// **A NO-OP `ON DUPLICATE KEY UPDATE singleton = singleton` WAS TRIED AND
    /// IS WRONG HERE**, stated so nobody re-introduces it as a tidier form.
    /// `sqlx` connects with `CLIENT_FOUND_ROWS`, so that clause reports ONE
    /// matched row on a duplicate exactly as on an insert — `SetPassword`
    /// measured the same thing — and RECORDED becomes indistinguishable from
    /// MATCH, which the contract requires an implementation to preserve.
    ///
    /// **NO ISOLATION LEVEL IS SET**, unlike `RedeemEnrolment` and
    /// `SetInheritedSetting`. Every statement here inherits the server's, so the
    /// answer must hold at READ COMMITTED and at REPEATABLE READ alike — which
    /// is what the `LOCK IN SHARE MODE` re-read buys: duplicate detection and a
    /// locking read are both CURRENT reads, so the loser sees the winner's
    /// committed row at either level. A snapshot re-read would miss it and
    /// answer FAILED_PRECONDITION where the contract requires MISMATCH.
    pub(super) async fn store_key_identity(
        &self,
        r: SetKeyIdentityRequest,
        call: Call,
    ) -> Result<Response<SetKeyIdentityResponse>, Status> {
        match self.record_key_identity(&r).await {
            Ok(outcome) => {
                call.finish(Outcome {
                    status: "OK",
                    rows: u32::from(outcome == KeyIdentityOutcome::Recorded),
                    ..Default::default()
                });
                Ok(Response::new(SetKeyIdentityResponse {
                    outcome: outcome as i32,
                }))
            }
            Err(refusal) => {
                call.fail(label(&refusal));
                Err(refusal)
            }
        }
    }

    async fn record_key_identity(
        &self,
        r: &SetKeyIdentityRequest,
    ) -> Result<KeyIdentityOutcome, Status> {
        presented(&r.key_fingerprint, r.derivation_version)?;
        let key = r
            .idempotency
            .as_ref()
            .map(|i| i.key.clone())
            .unwrap_or_default();

        let mut tx = self.pool.begin().await.map_err(db)?;

        // **THE REFUSAL RIDES IN THE WRITE**, which is `SetPassword`'s shape and
        // ledger 695's rule: a separate emptiness check followed by an INSERT is
        // two statements with a round trip between them, and a user created
        // inside that window passes the check and gets a marker recorded over
        // them anyway. `NOT EXISTS (SELECT 1 FROM iam_user)` is the predicate,
        // evaluated by the INSERT's own SELECT.
        //
        // **`iam_user` IS THE PREDICATE, AND THE NARROWING IS ARGUED RATHER THAN
        // ASSUMED.** The contract says "already holds rows"; this store's
        // key-bearing rows are `iam_user`'s alone — `external_id_ciphertext`,
        // `display_name_ciphertext` and the `external_id_blind_index` are the
        // only columns in the schema derived from the key set, and every other
        // data table either cascades from `iam_user` or holds nothing a key
        // could have encrypted. A literal "any row in any table" reading would
        // also refuse EVERY first boot, because migration 12 seeds a row into
        // `iam_org_setting` before a caller can reach this arm at all.
        //
        // **THIS INSERT MUST STAY THIS TRANSACTION'S FIRST STATEMENT, AND THE
        // DUPLICATE-KEY BRANCH BELOW IS CORRECT ONLY WHILE IT IS.** Measured:
        // with a `SELECT 1 FROM iam_user LIMIT 1` placed before a plain INSERT,
        // the loser raised 1020 `ER_CHECKREAD` instead of 1062,
        // `is_unique_violation()` did not classify it, and the answer became
        // UNAVAILABLE — because at REPEATABLE READ any earlier read fixes the
        // read view, so ANY read added here first, for validation, telemetry or
        // a settings lookup, silently degrades the loser from the permanent
        // MISMATCH to a transient UNAVAILABLE it retries for ever.
        //
        // **THIS STATEMENT LOCKS `iam_user` AND BLOCKS CONCURRENT USER
        // CREATION, AND THAT IS THE MECHANISM HOLDING THE REFUSAL UP RATHER
        // THAN A COST TO BE TUNED AWAY**: `INSERT ... SELECT` takes shared
        // next-key locks on the source table, measured as a baseline `INSERT
        // INTO iam_user` of 0.07s against 4.09s while another transaction held
        // this statement open and releasing on that transaction's commit, and
        // those locks are what make the emptiness predicate atomic rather than
        // advisory.
        //
        // `FROM DUAL` because MariaDB requires a FROM when a WHERE is present.
        let attempt = sqlx::query(
            "INSERT INTO iam_key_identity
                 (singleton, derivation_version, key_fingerprint, idempotency_key)
             SELECT 1, ?, ?, ? FROM DUAL
              WHERE NOT EXISTS (SELECT 1 FROM iam_user)",
        )
        .bind(r.derivation_version)
        .bind(&r.key_fingerprint)
        .bind(&key)
        .execute(&mut *tx)
        .await;

        let outcome = self.outcome_of(attempt, &mut tx, r, &key).await?;

        tx.commit().await.map_err(db)?;
        Ok(outcome)
    }

    /// What the INSERT above decided, and the two ways it can decide nothing.
    ///
    /// Lifted out whole for the reason `setting::record_claim` gives: the
    /// duplicate-key branch is correct only together with the INSERT that
    /// raises it, so neither half is a function on its own.
    ///
    /// **THE ZERO AND THE DUPLICATE ARE DIFFERENT EVENTS AND ARE NEVER
    /// COLLAPSED.** A duplicate means the marker was already there. Zero matched
    /// rows means the INSERT's own SELECT found `iam_user` non-empty, so nothing
    /// was attempted. Both re-read, because a store can hold rows AND a marker —
    /// and where a marker exists the contract wants the COMPARISON, never the
    /// refusal: the refusal is about RECORDING alone. Answering
    /// FAILED_PRECONDITION from the zero without re-reading would refuse a split
    /// rollout that requires MISMATCH.
    async fn outcome_of(
        &self,
        attempt: Result<sqlx::mysql::MySqlQueryResult, sqlx::Error>,
        tx: &mut sqlx::MySqlTransaction<'_>,
        r: &SetKeyIdentityRequest,
        key: &str,
    ) -> Result<KeyIdentityOutcome, Status> {
        match attempt {
            Ok(done) if done.rows_affected() == 1 => Ok(KeyIdentityOutcome::Recorded),
            Ok(_) => self.against_the_stored_marker(tx, r, key).await,
            Err(e) => match e
                .as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                true => self.against_the_stored_marker(tx, r, key).await,
                false => Err(db(e)),
            },
        }
    }

    /// Compare against the marker that is there, or refuse to record over rows.
    async fn against_the_stored_marker(
        &self,
        tx: &mut sqlx::MySqlTransaction<'_>,
        r: &SetKeyIdentityRequest,
        key: &str,
    ) -> Result<KeyIdentityOutcome, Status> {
        match marker(&mut **tx, Lock::Yes).await? {
            Some(stored) => replayed_or_compared(&stored, r, key),
            // A POPULATED STORE WITH NO MARKER IS AN INCIDENT, NOT A FIRST
            // BOOT: its rows were encrypted under a key set nobody can now
            // name, and recording whichever fingerprint arrives first would
            // assert an identity about all of them on no evidence at all.
            // This is the ONLY refusal about the stored marker on this arm.
            None => Err(Status::failed_precondition(
                "this store already holds rows and no marker; recording one now would assert a \
                 key identity about rows it cannot be derived from",
            )),
        }
    }
}
