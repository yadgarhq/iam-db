//! `SyncTeams` — the organisation's whole team declaration, applied in ONE
//! transaction (D5), and the one writer of team membership (ADR-0963 (1), (7)).
//!
//! # The order
//!
//! 1. **The caller**, `iam`'s leaf only, in `caller::admitted` like every verb.
//! 2. **The whole request, validated**, before a connection is taken. A
//!    refusal names the team and writes nothing.
//! 3. **READ COMMITTED**, for this transaction only (ADR-0513): a read after a
//!    lock wait must see the winner's rows, not a snapshot from before it.
//! 4. **The sentinel lock** (`iam_team_sync_lock`, migration 20), so two syncs
//!    serialise — two first syncs into an empty store included.
//! 5. **The `administrators` row `FOR UPDATE`**, the lock the F2 `CreateUser`
//!    and the declared enrolment arm take, BEFORE anything counts live members
//!    or touches the pending set (plans/team-access.md §6, concurrency).
//! 6. **The plan**: what is stored, which declared members have a user row, and
//!    the lockout guard (ADR-0963 (6)), decided before a single write.
//! 7. **The writes**, then the commit.
//!
//! # No D9 key
//!
//! Idempotent by CONVERGENCE, as `SyncProjects` is: the same declaration twice
//! changes nothing the second time.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// One declared team, validated.
struct Declared {
    id: String,
    name: String,
    members: Vec<String>,
}

/// What a declared member id names in the store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Known {
    /// No `iam_user` row.
    Absent,
    /// A row with `deleted_at` set: stored as a member, never counted live.
    SoftDeleted,
    Live,
}

impl IamDb {
    pub(in crate::service) async fn sync_teams(
        &self,
        r: SyncTeamsRequest,
        deadline: Deadline,
        call: Call,
    ) -> Result<Response<SyncTeamsResponse>, Status> {
        let declared = match validate(&r.teams) {
            Ok(d) => d,
            Err(refusal) => {
                call.fail("INVALID_ARGUMENT");
                return Err(refusal);
            }
        };

        let mut conn = self.acquire(deadline).await?;
        let mut tx = conn.begin(Isolation::ReadCommitted).await?;
        sqlx::query("SELECT id FROM iam_team_sync_lock WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        lock_administrators(&mut tx).await?;

        let live_before = live_administrators(&mut tx).await?;
        let known = known_users(&mut tx, &declared).await?;
        let admins = declared.iter().find(|t| t.id == ADMINISTRATORS);
        let live_after = admins.map_or(0, |t| {
            t.members
                .iter()
                .filter(|m| known[*m] == Known::Live)
                .count()
        });

        // THE LOCKOUT GUARD (ADR-0963 (6), plans/team-access.md §7). It counts
        // LIVE members on both sides, so a declaration whose only administrator
        // is a uuid with no user row, or one that omits `administrators` (which
        // archives it), is the same lockout as an empty member list.
        if live_before > 0 && live_after == 0 {
            call.fail("FAILED_PRECONDITION");
            return Err(Status::failed_precondition(
                "the declaration would leave administrators with no live member \
                 (ADR-0963 (6) lockout guard); nothing was written",
            ));
        }

        let mut resp = SyncTeamsResponse {
            administrators_live_members: u32::try_from(live_after).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // F2's PENDING SET: a declared administrator with no user row, ONLY
        // while no administrator is live after this sync. Otherwise that id is
        // an unknown member like any other (plans/team-access.md §6).
        let pending: Vec<String> = match (admins, live_after) {
            (Some(t), 0) => t
                .members
                .iter()
                .filter(|m| known[*m] == Known::Absent)
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        for team in &declared {
            for m in &team.members {
                let is_pending = team.id == ADMINISTRATORS && pending.contains(m);
                if known[m] == Known::Absent
                    && !is_pending
                    && !resp.unknown_member_user_ids.contains(m)
                {
                    resp.unknown_member_user_ids.push(m.clone());
                }
            }
        }

        // EVERY USER WHOSE LIVE TEAM SET CHANGED, for `iam` to evict by exact
        // id after commit (`changed_user_ids`): only this transaction sees the
        // old set. A BTreeSet, so the answer is sorted and deduplicated.
        let mut changed = BTreeSet::new();
        let reactivated = write_teams(&mut tx, &declared, &mut resp, &mut changed).await?;
        for team in &declared {
            let whole = reactivated.contains(&team.id);
            write_members(&mut tx, team, &known, whole, &mut resp, &mut changed).await?;
        }
        replace_pending(&mut tx, &pending).await?;
        resp.pending_administrator_user_ids = pending;
        resp.changed_user_ids = changed.into_iter().collect();
        tx.commit().await.map_err(db)?;

        call.finish(Outcome {
            status: "OK",
            rows: resp.teams_inserted
                + resp.teams_archived
                + resp.teams_reactivated
                + resp.members_added
                + resp.members_removed,
            ..Default::default()
        });
        Ok(Response::new(resp))
    }
}

/// Step 2: names `^[a-z][a-z0-9-]{0,62}$` and unique, members canonical user
/// ids (the rule `canonical_user_id` states) and unique within their team.
fn validate(teams: &[DeclaredTeam]) -> Result<Vec<Declared>, Status> {
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(teams.len());
    for (i, t) in teams.iter().enumerate() {
        let name_ok = t.name.len() <= 63
            && t.name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase())
            && t.name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return Err(Status::invalid_argument(format!(
                "teams[{i}].name must match ^[a-z][a-z0-9-]{{0,62}}$"
            )));
        }
        if !names.insert(t.name.as_str()) {
            return Err(Status::invalid_argument(format!(
                "teams[{i}].name {:?} is declared twice",
                t.name
            )));
        }
        let mut seen = BTreeSet::new();
        for (j, m) in t.member_user_ids.iter().enumerate() {
            if !canonical_user_id(m) {
                return Err(Status::invalid_argument(format!(
                    "teams[{}].member_user_ids[{j}] must be \"yadgar:user:\" followed by \
                     a lowercase canonical uuidv7",
                    t.name
                )));
            }
            if !seen.insert(m.as_str()) {
                return Err(Status::invalid_argument(format!(
                    "teams[{}].member_user_ids[{j}] is declared twice",
                    t.name
                )));
            }
        }
        out.push(Declared {
            id: format!("{TEAM_PREFIX}{}", t.name),
            name: t.name.clone(),
            members: t.member_user_ids.clone(),
        });
    }
    Ok(out)
}

/// What every declared member id names in the store, one indexed read each.
async fn known_users(
    tx: &mut sqlx::MySqlTransaction<'_>,
    declared: &[Declared],
) -> Result<BTreeMap<String, Known>, Status> {
    let mut known = BTreeMap::new();
    for m in declared.iter().flat_map(|t| &t.members) {
        if known.contains_key(m) {
            continue;
        }
        let live: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(deleted_at IS NULL AS SIGNED) FROM iam_user WHERE id = ?",
        )
        .bind(m)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
        let k = match live {
            None => Known::Absent,
            Some(0) => Known::SoftDeleted,
            Some(_) => Known::Live,
        };
        known.insert(m.clone(), k);
    }
    Ok(known)
}

/// Insert the new teams, reactivate the archived declared ones, and archive
/// every live team the declaration omits. An archived team keeps its member
/// rows; `ResolveCredential` reads live teams only, so every one of those
/// members is `changed`. Answers the ids reactivated.
async fn write_teams(
    tx: &mut sqlx::MySqlTransaction<'_>,
    declared: &[Declared],
    resp: &mut SyncTeamsResponse,
    changed: &mut BTreeSet<String>,
) -> Result<BTreeSet<String>, Status> {
    let mut reactivated = BTreeSet::new();
    let stored: Vec<(String, i64)> =
        sqlx::query_as("SELECT id, CAST(deleted_at IS NOT NULL AS SIGNED) FROM iam_team")
            .fetch_all(&mut **tx)
            .await
            .map_err(db)?;
    let stored: BTreeMap<String, bool> = stored.into_iter().map(|(id, a)| (id, a != 0)).collect();

    for team in declared {
        match stored.get(&team.id) {
            None => {
                insert_team(tx, team).await?;
                resp.teams_inserted += 1;
            }
            Some(true) => {
                sqlx::query(
                    "UPDATE iam_team SET deleted_at = NULL, version = version + 1 WHERE id = ?",
                )
                .bind(&team.id)
                .execute(&mut **tx)
                .await
                .map_err(db)?;
                resp.teams_reactivated += 1;
                reactivated.insert(team.id.clone());
            }
            Some(false) => {}
        }
    }

    for (id, archived) in &stored {
        if *archived || declared.iter().any(|t| &t.id == id) {
            continue;
        }
        sqlx::query(
            "UPDATE iam_team SET deleted_at = CURRENT_TIMESTAMP, version = version + 1
              WHERE id = ?",
        )
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        resp.teams_archived += 1;
        let members: Vec<String> =
            sqlx::query_scalar("SELECT user_id FROM iam_team_member WHERE team_id = ?")
                .bind(id)
                .fetch_all(&mut **tx)
                .await
                .map_err(db)?;
        changed.extend(members);
    }
    Ok(reactivated)
}

async fn insert_team(tx: &mut sqlx::MySqlTransaction<'_>, team: &Declared) -> Result<(), Status> {
    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by)
         VALUES (?, ?, 'system', 'system')",
    )
    .bind(&team.id)
    .bind(&team.name)
    .execute(&mut **tx)
    .await
    .map_err(|e| match &e {
        // `uq_iam_team_name`: a row under ANOTHER id holds the name. Not a
        // retryable outage, so not `db()`'s UNAVAILABLE.
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            Status::failed_precondition(format!(
                "a team named {:?} exists under an id other than {:?}",
                team.name, team.id
            ))
        }
        _ => db(e),
    })?;
    Ok(())
}

/// Replace one declared team's member set with its declared members that have
/// a user row. Membership rows are deleted, not archived: a membership is not
/// a partition key (plans/team-access.md §7). Every member added or removed is
/// `changed`; for a team this sync reactivated (`whole`), every member is.
async fn write_members(
    tx: &mut sqlx::MySqlTransaction<'_>,
    team: &Declared,
    known: &BTreeMap<String, Known>,
    whole: bool,
    resp: &mut SyncTeamsResponse,
    changed: &mut BTreeSet<String>,
) -> Result<(), Status> {
    let current: BTreeSet<String> =
        sqlx::query_scalar("SELECT user_id FROM iam_team_member WHERE team_id = ?")
            .bind(&team.id)
            .fetch_all(&mut **tx)
            .await
            .map_err(db)?
            .into_iter()
            .collect();
    let desired: BTreeSet<&String> = team
        .members
        .iter()
        .filter(|m| known[*m] != Known::Absent)
        .collect();
    if whole {
        changed.extend(desired.iter().map(|d| (*d).clone()));
    }

    for gone in current.iter().filter(|c| !desired.contains(c)) {
        sqlx::query("DELETE FROM iam_team_member WHERE team_id = ? AND user_id = ?")
            .bind(&team.id)
            .bind(gone)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        resp.members_removed += 1;
        changed.insert(gone.clone());
    }
    for new in desired.into_iter().filter(|d| !current.contains(*d)) {
        sqlx::query(
            "INSERT INTO iam_team_member (team_id, user_id, added_by) VALUES (?, ?, 'system')",
        )
        .bind(&team.id)
        .bind(new)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        resp.members_added += 1;
        changed.insert(new.clone());
    }
    Ok(())
}

/// The pending set, replaced wholesale on every sync.
async fn replace_pending(
    tx: &mut sqlx::MySqlTransaction<'_>,
    pending: &[String],
) -> Result<(), Status> {
    sqlx::query("DELETE FROM iam_team_member_pending")
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    for p in pending {
        sqlx::query("INSERT INTO iam_team_member_pending (team_id, user_id) VALUES (?, ?)")
            .bind(ADMINISTRATORS)
            .bind(p)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
    }
    Ok(())
}
