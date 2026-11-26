//! Who exists.
//!
//! Finding a live person by blind index (`LookupUser`), and creating one, by a minted id or — on F2's bootstrap arm, the `bootstrap`
//! child — by the pre-minted id GitOps declares. Moving a person in and out of a
//! team was here too; `AddTeamMember` and `RemoveTeamMember` are retired
//! (ADR-0963 (7)) and refuse below, and `SyncTeams` (`team`) is the one writer
//! of membership.
//!
//! What a person is ALLOWED is next door in `policy`. The split is between the
//! rows that say somebody is here and the rows that say what applies to them.

use super::*;

mod bootstrap;
pub use bootstrap::BOOTSTRAP_CREATE_REFUSED;

/// A blind index is an HMAC-SHA256, so exactly this many bytes.
const BLIND_INDEX_BYTES: usize = 32;

impl IamDb {
    pub(super) async fn insert_user(
        &self,
        r: CreateUserRequest,
        deadline: Deadline,
        rid: &str,
        call: Call,
    ) -> Result<Response<CreateUserResponse>, Status> {
        // A NON-EMPTY `user_id` IS THE BOOTSTRAP CREATE-USER DEMAND (F2,
        // plans/team-access.md §6). It takes its own arm, whole; the minting
        // arm below is what every other caller has always reached.
        if !r.user_id.is_empty() {
            return self.insert_declared_user(r, deadline, rid, call).await;
        }

        // `idempotency` IS DISCARDED HERE, AND A RETRY IS NOT A REPLAY. The
        // UNIQUE below turns a redelivered CreateUser into ALREADY_EXISTS, so a
        // caller whose first response was lost never learns the `meta.id` that
        // attempt returned — `LookupUser` is the verb that finds it, by the
        // blind index, whether or not the user has a password row. `iam` forwards
        // a key on this hop today. See the module header.
        let id = format!("yadgar:user:{}", uuid::Uuid::now_v7());

        // ADR-0534's RECORDING HALF. AFTER the id rather than first, which is the
        // only ordering difference from the other verbs: this RPC is the one whose
        // target does not exist until it runs, and an attribution naming no object
        // answers half the question an incident asks. Generating the id cannot
        // fail, so nothing is recorded that the request did not reach.
        record_actor(rid, r.unverified_actor.as_ref(), "CreateUser", &id);
        let mut conn = self.acquire(deadline).await?;

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
        .execute(&mut *conn)
        .await
        .map_err(user_conflict)?;

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

    /// `LookupUser`: the id of the live person under a blind index (yaadgaar 270).
    ///
    /// A read. The actor is recorded first, as the attempt, with an empty target:
    /// no id exists yet, and the blind index is never logged in any form.
    pub(super) async fn find_user(
        &self,
        r: LookupUserRequest,
        deadline: Deadline,
        rid: &str,
        call: Call,
    ) -> Result<Response<LookupUserResponse>, Status> {
        record_actor(rid, r.unverified_actor.as_ref(), "LookupUser", "");
        if r.external_id_blind_index.len() != BLIND_INDEX_BYTES {
            let refusal = Status::invalid_argument("the blind index must be exactly 32 bytes");
            call.fail(label(&refusal));
            return Err(refusal);
        }
        let mut conn = self.acquire(deadline).await?;
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM iam_user WHERE external_id_blind_index = ? AND deleted_at IS NULL",
        )
        .bind(&r.external_id_blind_index)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db)?;
        let Some(user_id) = found else {
            let refusal = Status::not_found("no such live user");
            call.fail(label(&refusal));
            return Err(refusal);
        };
        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(LookupUserResponse { user_id }))
    }

    pub(super) async fn add_member(
        &self,
        r: AddTeamMemberRequest,
        rid: &str,
        call: Call,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        // ADR-0534's RECORDING HALF. The TARGET is the membership, team first.
        let target = format!("{}/{}", seg(&r.team_id), seg(&r.user_id));
        record_actor(rid, r.unverified_actor.as_ref(), "AddTeamMember", &target);

        Err(teams_are_declared(call))
    }

    pub(super) async fn remove_member(
        &self,
        r: RemoveTeamMemberRequest,
        rid: &str,
        call: Call,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        // ADR-0534's RECORDING HALF. The TARGET is the membership, team first.
        let target = format!("{}/{}", seg(&r.team_id), seg(&r.user_id));
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "RemoveTeamMember",
            &target,
        );

        Err(teams_are_declared(call))
    }
}

/// `AddTeamMember` and `RemoveTeamMember` (ADR-0963 (7)): the declaration in
/// GitOps is the one source of team membership, and `SyncTeams` its one
/// writer, so a runtime membership write is refused before any statement.
///
/// The actor is still recorded first: the record is of an ATTEMPT, never an
/// outcome (`record_actor`), and these two verbs still carry the field.
fn teams_are_declared(call: Call) -> Status {
    call.fail("FAILED_PRECONDITION");
    Status::failed_precondition(
        "teams are declared in GitOps: SyncTeams is the one writer of team \
         membership, and AddTeamMember and RemoveTeamMember are retired (ADR-0963 (7))",
    )
}

/// A failed `iam_user` insert, with a unique violation mapped BY CONSTRAINT
/// (plans/team-access.md §6 step 4).
///
/// The UNIQUE on the blind index is the name collision, and saying "already
/// exists" is safe: the caller supplied the index, so it learns nothing it did
/// not already know. The PRIMARY KEY is "that user id is taken", reachable only
/// on the F2 arm, where the caller chose the id. MariaDB names the key in the
/// message (`for key 'PRIMARY'`); sqlx-mysql exposes no constraint name.
fn user_conflict(e: sqlx::Error) -> Status {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            match d.message().contains("for key 'PRIMARY'") {
                true => Status::already_exists(bootstrap::USER_ID_TAKEN),
                false => Status::already_exists("a user with that name already exists"),
            }
        }
        _ => db(e),
    }
}
