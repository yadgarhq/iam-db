//! The bootstrap enrolment demand with team-derived admin on: ADR-0966's
//! break-glass arm, as ADR-1012 records it and ADR-1014 (accepted, ratifying
//! ADR-1010) amends ADR-0943 point 2 for it (plans/team-access.md §6).
//!
//! Reached ONLY when the request carries the demand
//! (`require_zero_credential_admin`) AND `admin_from_team`. Every other
//! request takes `demand.rs` or the ordinary arms, unchanged.
//!
//! **THE PREDICATE, IN ONE READ COMMITTED TRANSACTION WITH THE INSERT.**
//!
//! 1. The `administrators` row, locked `FOR UPDATE` as `SyncTeams` and the F2
//!    `CreateUser` lock it, so a sync removing the member cannot interleave.
//!    Absent or archived: `no_administrators_team`.
//! 2. The target has a LIVE `iam_user` row: `not_live_user` otherwise. An
//!    unknown id is refused with the same code as a non-member, unlike the
//!    derivation-off arm's NOT_FOUND, so the token holder cannot tell them
//!    apart. A pending uuid has no row and is refused here.
//! 3. The target has a member row in `administrators`: `not_declared_member`
//!    otherwise. The `is_admin` column is NOT read.
//! 4. Credentials are NOT counted: live, revoked or none, all admitted.
//! 5. `revoke_existing_credentials` MAY ride beside the demand, decided at
//!    issue time by the bootstrap caller and executed at redemption (ADR-0943
//!    points 3 to 5, ADR-1014 point 2).
//!
//! Every refusal is the demand's one sentence (ADR-0657); the conjunct goes to
//! the warn line and to `ENROLMENT_DEMAND_REFUSED`'s label. A re-enrolment of
//! an administrator who holds a LIVE credential is made visible on its own
//! warn line and on [`BOOTSTRAP_REENROLMENT`], labelled `revoke`.

use crate::service::team::{lock_administrators, ADMINISTRATORS};
use crate::service::*;

use super::demand::REFUSAL;
use super::{revoke, ORDINARY};

/// A bootstrap enrolment was ISSUED for an administrator who holds at least one
/// live credential, labelled `revoke` (`true` or `false`): whether the
/// redemption will revoke them. An alert on `revoke="false"` catches a
/// parallel credential minted without containment (ADR-1014 point 4).
pub const BOOTSTRAP_REENROLMENT: &str = "yadgar_iamdb_bootstrap_reenrolment_total";

/// Which conjunct refused, on this arm. The same counter as `demand.rs`'s two,
/// so the closed set of `conjunct` is the union of five (ADR-1012).
#[derive(Clone, Copy)]
enum Conjunct {
    NoAdministratorsTeam,
    NotLiveUser,
    NotDeclaredMember,
}

impl Conjunct {
    const fn label(self) -> &'static str {
        match self {
            Self::NoAdministratorsTeam => "no_administrators_team",
            Self::NotLiveUser => "not_live_user",
            Self::NotDeclaredMember => "not_declared_member",
        }
    }
}

/// The whole arm for `CreateEnrolment`: mint, and finish or fail the `Call`.
pub(super) async fn issue(
    pool: &MySqlPool,
    r: &CreateEnrolmentRequest,
    deadline: Deadline,
    expires_at: i64,
    rid: &str,
    call: Call,
) -> Result<Response<CreateEnrolmentResponse>, Status> {
    let id = format!("yadgar:enrolment:{}", uuid::Uuid::now_v7());
    if let Err(refusal) = mint(pool, r, deadline, &id, expires_at, rid).await {
        call.fail(label(&refusal));
        return Err(refusal);
    }
    call.finish(Outcome {
        status: "OK",
        rows: 1,
        ..Default::default()
    });
    Ok(Response::new(CreateEnrolmentResponse { enrolment_id: id }))
}

/// Mint the enrolment `id` on this arm, or refuse. `Ok(())` means written.
async fn mint(
    pool: &MySqlPool,
    r: &CreateEnrolmentRequest,
    deadline: Deadline,
    id: &str,
    expires_at: i64,
    rid: &str,
) -> Result<(), Status> {
    let mut conn = conn::acquire(pool, deadline).await?;
    let mut tx = conn.begin(Isolation::ReadCommitted).await?;

    let live_credentials = match predicate(&mut tx, &r.user_id).await? {
        Ok(n) => n,
        Err(conjunct) => {
            drop(tx);
            tracing::warn!(
                request_id = rid,
                user_id = %r.user_id,
                conjunct = conjunct.label(),
                "the bootstrap enrolment demand was refused"
            );
            metrics::counter!(ENROLMENT_DEMAND_REFUSED, "conjunct" => conjunct.label())
                .increment(1);
            return Err(Status::permission_denied(REFUSAL));
        }
    };

    // THE ORDINARY ARM'S STATEMENTS, with or without the instruction. Their
    // own `deleted_at IS NULL ... LOCK IN SHARE MODE` re-checks liveness in
    // the write, as every insert here does.
    let sql = match r.revoke_existing_credentials {
        true => revoke::INSERT,
        false => ORDINARY,
    };
    sqlx::query(sql)
        .bind(id)
        .bind(&r.secret_hash)
        .bind(expires_at)
        .bind(&r.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                Status::already_exists("that enrolment secret is already in use")
            }
            _ => db(e),
        })?;
    tx.commit().await.map_err(db)?;

    if live_credentials > 0 {
        let revoking = r.revoke_existing_credentials;
        tracing::warn!(
            request_id = rid,
            user_id = %r.user_id,
            revoke_existing_credentials = revoking,
            "a bootstrap enrolment was issued for an administrator who holds live credentials"
        );
        metrics::counter!(BOOTSTRAP_REENROLMENT, "revoke" => if revoking { "true" } else { "false" })
            .increment(1);
    }
    Ok(())
}

/// Steps 1 to 3 on `tx`; on admission, how many LIVE credentials the target
/// holds (not revoked, not expired), for the re-enrolment signal only.
async fn predicate(
    tx: &mut sqlx::MySqlTransaction<'_>,
    user_id: &str,
) -> Result<Result<i64, Conjunct>, Status> {
    if lock_administrators(tx).await? != Some(true) {
        return Ok(Err(Conjunct::NoAdministratorsTeam));
    }
    let live: Option<String> = sqlx::query_scalar(
        "SELECT id FROM iam_user WHERE id = ? AND deleted_at IS NULL LOCK IN SHARE MODE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    if live.is_none() {
        return Ok(Err(Conjunct::NotLiveUser));
    }
    let member: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM iam_team_member WHERE team_id = ? AND user_id = ?")
            .bind(ADMINISTRATORS)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    if member.is_none() {
        return Ok(Err(Conjunct::NotDeclaredMember));
    }
    let live_credentials: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam_credential
          WHERE user_id = ? AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    Ok(Ok(live_credentials))
}
