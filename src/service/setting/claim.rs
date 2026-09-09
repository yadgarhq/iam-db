//! D9's ledger for `SetInheritedSetting`, and what one key's two deliveries are
//! compared on.
//!
//! `iam_inherited_setting_write` is one of the two tables in this schema a
//! caller's idempotency key reaches. A `Claim` is what a request ASKED FOR;
//! `recorded` is what a key already asked for, or nothing.

use crate::service::*;

/// What a `SetInheritedSetting` request ASKED FOR, which is what D9's amended
/// rule compares one idempotency key's two deliveries on.
///
/// **THE MEMBERSHIP IS THE CONTRACT'S, NOT A JUDGEMENT MADE HERE.**
/// `yadgar.iamdb.v1.SetInheritedSettingRequest` enumerates it: `scope`,
/// `team_id`, `name`, `value`, `locked` and `clear` — every field of the message
/// but two. `idempotency` carries the key the comparison is keyed on.
///
/// **`unverified_actor` IS EXCLUDED, AND THE EXCLUSION IS LOAD-BEARING.**
/// `yadgar.common.v1.UnverifiedActor` states it once for every RPC carrying the
/// field: including it would refuse, with INVALID_ARGUMENT, an IDENTICAL
/// operation stamped with a different actor — a second administrator picking up
/// a change the first one lost. The field would then decide whether a request
/// SUCCEEDS, and it is meant to be inert by construction.
///
/// **THE THREE `Option`s CARRY PRESENCE INTO THE COMPARISON.** Collapsing an
/// absent `value` onto a zero would make a request WITHDRAWING an override
/// compare equal to one setting it OFF, which is ADR-0524's distinction
/// destroyed at the one place it is checked rather than at the one place it is
/// written.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Claim {
    pub(super) key: String,
    scope: i32,
    team_id: Option<String>,
    name: String,
    value: Option<i32>,
    locked: Option<bool>,
    clear: bool,
}

impl Claim {
    pub(super) fn of(r: &SetInheritedSettingRequest) -> Self {
        Self {
            // THE EMPTY STRING IS NOT A KEY, the rule `RedeemEnrolment` already
            // holds. Keying a ledger row on it would make two unrelated writes
            // collide on one row, so the second would be refused as a differing
            // payload under a key neither caller chose.
            key: r
                .idempotency
                .as_ref()
                .map(|i| i.key.clone())
                .unwrap_or_default(),
            scope: r.scope,
            team_id: r.team_id.clone(),
            name: r.name.clone(),
            value: r.value,
            locked: r.locked,
            clear: r.clear,
        }
    }

    /// Refuse a key that already recorded a DIFFERENT request (D9 as amended).
    ///
    /// Replaying it would hand the first request's outcome to a caller who sent
    /// a second: the operation actually asked for is silently discarded and the
    /// answer reports success. Refusing is the only response that never lies.
    pub(super) fn agrees_with(&self, prior: &Claim) -> Result<(), Status> {
        // The key itself is what they were both found by, so it is never part of
        // the difference.
        match (
            self.scope,
            &self.team_id,
            &self.name,
            self.value,
            self.locked,
            self.clear,
        ) == (
            prior.scope,
            &prior.team_id,
            &prior.name,
            prior.value,
            prior.locked,
            prior.clear,
        ) {
            true => Ok(()),
            false => Err(Status::invalid_argument(
                "this idempotency key was used with a different request; a repeated key carrying \
                 a different payload is refused rather than replayed",
            )),
        }
    }

    pub(super) async fn record(
        &self,
        tx: &mut sqlx::MySqlTransaction<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO iam_inherited_setting_write
                 (idempotency_key, scope, team_id, name, value, locked, clear_requested)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&self.key)
        .bind(self.scope)
        .bind(&self.team_id)
        .bind(&self.name)
        .bind(self.value)
        .bind(self.locked)
        .bind(self.clear)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }
}

/// The request a key already recorded, or `None` if it has recorded nothing.
///
/// `Lock::No` is the ordinary pre-flight read; `Lock::Yes` is the re-check on
/// the branch where the INSERT found the row already there, where the row DOES
/// exist and a locking read is therefore a record lock rather than the gap lock
/// ADR-0513 forbids.
pub(super) async fn recorded(
    tx: &mut sqlx::MySqlTransaction<'_>,
    key: &str,
    lock: Lock,
) -> Result<Option<Claim>, Status> {
    const BASE: &str = "SELECT scope, team_id, name, value, locked, clear_requested
                          FROM iam_inherited_setting_write
                         WHERE idempotency_key = ?";
    // AUDIT: both arms are literals in this file; `key` is bound, never
    // interpolated.
    let sql = match lock {
        Lock::No => BASE.to_string(),
        Lock::Yes => format!("{BASE} FOR UPDATE"),
    };

    let Some(row) = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
    else {
        return Ok(None);
    };

    Ok(Some(Claim {
        key: key.to_string(),
        scope: row.try_get("scope").map_err(db)?,
        team_id: row.try_get("team_id").map_err(db)?,
        name: row.try_get("name").map_err(db)?,
        value: row.try_get("value").map_err(db)?,
        locked: row.try_get("locked").map_err(db)?,
        clear: row.try_get("clear_requested").map_err(db)?,
    }))
}
