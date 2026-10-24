//! F2: the bootstrap `CreateUser` with a pre-minted `user_id` (ADR-0963 (5),
//! plans/team-access.md §6).
//!
//! The operator mints the first administrator's uuid before install and
//! declares it in `administrators`; `SyncTeams` stores it as PENDING because
//! no user row exists yet. This arm creates that user with exactly that id,
//! and only while `administrators` has no live member. A non-empty `user_id`
//! IS the demand: there is no separate flag.
//!
//! **THE PREDICATE, IN ORDER, IN ONE READ COMMITTED TRANSACTION.** Each
//! refusal writes nothing.
//!
//! 1. Format: `INVALID_ARGUMENT`, decided from the request before any read.
//! 2. The live `administrators` row, `FOR UPDATE` — the lock `SyncTeams` and
//!    the declared enrolment arm take too, so this serialises with both.
//! 3. No live member of `administrators`. This closes the arm for good after
//!    the first administrator, whoever the caller is.
//! 4. No `iam_user` row with that id, soft-deleted or not: `ALREADY_EXISTS`.
//! 5. A pending row (`administrators`, `user_id`).
//! 6. The writes: the user with `is_admin` false, its member row, and the
//!    deletion of every pending `administrators` row.
//!
//! **ONE SENTENCE FOR STEPS 2, 3 AND 5 (ADR-0657).** The step goes only to the
//! warn line and to [`BOOTSTRAP_CREATE_REFUSED`]'s closed label set, where the
//! operator reads it and a holder of the bootstrap token does not.

use crate::service::team::ADMINISTRATORS;
use crate::service::team::{canonical_user_id, live_administrators, lock_administrators};
use crate::service::*;

/// A bootstrap `CreateUser` was refused by the predicate, labelled `step`
/// from the closed set `{no_administrators_team, administrator_exists,
/// not_declared}`. Closed because the label reaches Prometheus (D67).
pub const BOOTSTRAP_CREATE_REFUSED: &str = "yadgar_iamdb_bootstrap_create_refused_total";

/// The one sentence of every refusal of steps 2, 3 and 5.
const REFUSAL: &str = "the bootstrap create-user predicate refused";

/// Step 4, and a primary-key race past it.
pub(super) const USER_ID_TAKEN: &str = "that user id is taken";

/// Which step refused.
#[derive(Clone, Copy)]
enum Step {
    NoAdministratorsTeam,
    AdministratorExists,
    NotDeclared,
}

impl Step {
    const fn label(self) -> &'static str {
        match self {
            Self::NoAdministratorsTeam => "no_administrators_team",
            Self::AdministratorExists => "administrator_exists",
            Self::NotDeclared => "not_declared",
        }
    }
}

impl IamDb {
    pub(super) async fn insert_declared_user(
        &self,
        r: CreateUserRequest,
        deadline: Deadline,
        rid: &str,
        call: Call,
    ) -> Result<Response<CreateUserResponse>, Status> {
        // ADR-0534's RECORDING HALF, first: the target is the id asked for.
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "CreateUser",
            &seg(&r.user_id),
        );

        if !canonical_user_id(&r.user_id) {
            call.fail("INVALID_ARGUMENT");
            return Err(Status::invalid_argument(
                "user_id must be \"yadgar:user:\" followed by a lowercase canonical uuidv7",
            ));
        }

        let mut conn = self.acquire(deadline).await?;
        let mut tx = conn.begin(Isolation::ReadCommitted).await?;

        if let Err(refusal) = predicate(&mut tx, &r.user_id).await? {
            drop(tx);
            return Err(refuse(refusal, &r.user_id, rid, call));
        }

        // STEP 6. `is_admin` is FALSE whatever the request carries: with
        // derivation on, admin is the membership written beside it, and a
        // true column would be a second source (ADR-0962's alternatives).
        sqlx::query(
            "INSERT INTO iam_user
                 (id, created_by, updated_by,
                  external_id_blind_index, external_id_ciphertext, display_name_ciphertext,
                  is_admin)
             VALUES (?, 'system', 'system', ?, ?, ?, 0)",
        )
        .bind(&r.user_id)
        .bind(&r.external_id_blind_index)
        .bind(&r.external_id_ciphertext)
        .bind(&r.display_name_ciphertext)
        .execute(&mut *tx)
        .await
        .map_err(super::user_conflict)?;
        sqlx::query(
            "INSERT INTO iam_team_member (team_id, user_id, added_by) VALUES (?, ?, 'system')",
        )
        .bind(ADMINISTRATORS)
        .bind(&r.user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM iam_team_member_pending WHERE team_id = ?")
            .bind(ADMINISTRATORS)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(CreateUserResponse {
            meta: Some(Meta {
                id: r.user_id,
                version: 1,
                ..Default::default()
            }),
        }))
    }
}

/// Steps 2 to 5 on `tx`. `Ok(Err(step))` is a predicate refusal; `Err` is
/// the store failing, or step 4's `ALREADY_EXISTS`.
async fn predicate(
    tx: &mut sqlx::MySqlTransaction<'_>,
    user_id: &str,
) -> Result<Result<(), Step>, Status> {
    if lock_administrators(tx).await? != Some(true) {
        return Ok(Err(Step::NoAdministratorsTeam));
    }
    if live_administrators(tx).await? > 0 {
        return Ok(Err(Step::AdministratorExists));
    }
    let taken: Option<String> = sqlx::query_scalar("SELECT id FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
    if taken.is_some() {
        return Err(Status::already_exists(USER_ID_TAKEN));
    }
    let declared: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM iam_team_member_pending WHERE team_id = ? AND user_id = ?",
    )
    .bind(ADMINISTRATORS)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    match declared {
        Some(_) => Ok(Ok(())),
        None => Ok(Err(Step::NotDeclared)),
    }
}

/// The warn line and the counter, then the one sentence.
fn refuse(step: Step, user_id: &str, rid: &str, call: Call) -> Status {
    tracing::warn!(
        request_id = rid,
        %user_id,
        step = step.label(),
        "the bootstrap create-user was refused"
    );
    metrics::counter!(BOOTSTRAP_CREATE_REFUSED, "step" => step.label()).increment(1);
    call.fail("PERMISSION_DENIED");
    Status::permission_denied(REFUSAL)
}
