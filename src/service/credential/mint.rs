//! `CreateCredential`: minting one credential, checked against the person's
//! credential epoch when the caller sends one (ADR-0972 (4)).
//!
//! In a child file rather than in `credential.rs` because that file would cross
//! the 500-line ceiling with the epoch check.

use super::*;

/// The statement this handler always ran, for a request with no
/// `expected_credential_epoch`.
///
/// FROM_UNIXTIME, because the contract carries epoch SECONDS and the column is
/// a TIMESTAMP. Binding the integer directly makes MariaDB read 1798761600 as a
/// datetime literal — it does not error, it stores something else, and the
/// credential then expires at a time nobody chose. Converting in SQL keeps the
/// one representation the column understands.
const UNCHECKED: &str = "INSERT INTO iam_credential (id, user_id, token_hash, label, expires_at)
             SELECT ?, id, ?, ?, FROM_UNIXTIME(?) FROM iam_user
              WHERE id = ? AND deleted_at IS NULL
              LOCK IN SHARE MODE";

/// [`UNCHECKED`] with one more predicate on the user row: its epoch still
/// equals the one the caller read.
///
/// UNDER THE SAME SHARE LOCK, and the lock is what makes the check a check. A
/// bump holds the user row exclusively until its transaction commits, so this
/// read waits for that commit and then sees the new epoch. One more bind, last.
const CHECKED: &str = "INSERT INTO iam_credential (id, user_id, token_hash, label, expires_at)
             SELECT ?, id, ?, ?, FROM_UNIXTIME(?) FROM iam_user
              WHERE id = ? AND deleted_at IS NULL AND credential_epoch = ?
              LOCK IN SHARE MODE";

impl IamDb {
    pub(in crate::service) async fn mint_credential(
        &self,
        r: CreateCredentialRequest,
        deadline: Deadline,
        rid: &str,
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

        // ADR-0534's RECORDING HALF, AFTER the id on `CreateUser`'s argument:
        // minting it cannot fail, and the credential id is what joins this
        // record to a later `RevokeCredential`'s.
        let target = format!("{}/{}", seg(&r.user_id), id);
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "CreateCredential",
            &target,
        );

        // ADR-0972 (4): presence, not value, picks the statement (0 is an epoch).
        let expected = r.expected_credential_epoch;
        let sql = match expected {
            Some(_) => CHECKED,
            None => UNCHECKED,
        };
        let mut insert = sqlx::query(sql)
            .bind(&id)
            .bind(&r.token_hash)
            .bind(&r.label)
            .bind(r.expires_at.map(|t| t.seconds))
            .bind(&r.user_id);
        if let Some(epoch) = expected {
            insert = insert.bind(epoch);
        }
        let mut conn = self.acquire(deadline).await?;
        let done = insert.execute(&mut *conn).await.map_err(db)?;

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
            live_user(&mut *conn, &r.user_id).await?;

            // A live person and no row: the epoch moved. TERMINAL — see [`stale`].
            if expected.is_some() {
                return Err(stale(call));
            }
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
}

/// The refusal for a checked mint whose epoch moved (ADR-0972 (4)).
///
/// On [`CHECKED`], a live person with no row inserted is REACHABLE: a
/// password-setting redemption, `RevokeAllCredentials` or `SetPassword`
/// committed after the caller read the epoch. It is terminal whatever the
/// fall-through says for [`UNCHECKED`] — answering OK would hand back an id for
/// a row that was never written.
fn stale(call: Call) -> Status {
    let refusal =
        Status::failed_precondition("the account changed since this credential was asked for");
    call.fail(label(&refusal));
    refusal
}
