//! What an inheritable-setting request MEANS, before anything is written.
//!
//! Every clause `yadgar.common.v1.SettingScope` declares, the team a request
//! names, and the read-back that returns both levels unresolved. None of it
//! writes; all of it decides.

use crate::service::*;

/// The team this request names, after [`check_inherited_setting`] has proved one
/// is there and is not empty.
pub(super) fn team_id_of(r: &SetInheritedSettingRequest) -> &str {
    r.team_id
        .as_deref()
        .expect("validated present and non-empty at team scope")
}

/// Both levels of one inheritable setting, unresolved.
///
/// The same two queries `ResolveCredential` makes, and deliberately the same
/// answers — including that an ABSENT organisation row is
/// SETTING_VALUE_UNSPECIFIED and never OFF. A store that states no policy must
/// reach the enforcing `-db` as a refusal rather than as this module quietly
/// choosing the strict one.
pub(super) async fn read_inherited_setting(
    tx: &mut sqlx::MySqlTransaction<'_>,
    name: &str,
) -> Result<InheritedSetting, Status> {
    let org = sqlx::query("SELECT value, locked FROM iam_org_setting WHERE name = ?")
        .bind(name)
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

    // UNBOUNDED, on the same sparsity argument `ResolveCredential` states: at
    // most one row per team that says something, and a team says something only
    // when an operator writes one. A LIMIT would give the teams that fell off the
    // end a WRONG answer rather than a slow one.
    let team_override =
        sqlx::query("SELECT team_id, value FROM iam_team_setting_override WHERE name = ?")
            .bind(name)
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

/// Every clause `yadgar.common.v1.SettingScope` declares, and each one is
/// `INVALID_ARGUMENT`.
///
/// **A PORT OF THE CONTRACT, NOT A SUMMARY OF IT.** The normative text lives in
/// `common.proto` and says so; this is that text executed. `iam` holds an
/// identical function against its own request type, and the duplication is the
/// contract's own instruction — every boundary carrying this write refuses the
/// same clauses, because a boundary that trusts its caller is one whose
/// correctness lives somewhere else.
///
/// Returns the validated scope so the caller cannot re-derive it and disagree.
pub(super) fn check_inherited_setting(
    r: &SetInheritedSettingRequest,
) -> Result<SettingScope, Status> {
    // proto3 enums are OPEN, so an unrecognised number arrives intact rather than
    // collapsing to the zero. A `match` with a fallthrough would write the
    // ORGANISATION's policy for a request that named neither level — the widest
    // write there is, answering a request nobody made.
    let scope = SettingScope::try_from(r.scope).map_err(|_| {
        Status::invalid_argument(
            "scope names no level this contract declares; there are two, an organisation and a \
             team",
        )
    })?;

    match scope {
        SettingScope::Unspecified => {
            return Err(Status::invalid_argument(
                "scope is required: a write addresses the organisation's level or one team's, and \
                 neither is the default",
            ));
        }
        SettingScope::Org => {
            // There is ONE organisation (D27), so a team id here is a caller that
            // meant TEAM — and ignoring it would write the organisation's policy
            // while the caller believed they wrote one team's.
            if r.team_id.is_some() {
                return Err(Status::invalid_argument(
                    "a team id at organisation scope is a request that meant team scope; there is \
                     one organisation and it is not named",
                ));
            }
            // Every default is wrong: false is the unsafe direction, true locks a
            // deployment that never asked, and keeping the stored value stops the
            // verb from stating a wanted result.
            if r.locked.is_none() {
                return Err(Status::invalid_argument(
                    "locked is required at organisation scope: it has no safe default, and an \
                     unstated lock is the permissive half of a policy nobody chose",
                ));
            }
            // The organisation always holds a value — the resolution's first step
            // refuses an unset one — so there is nothing there to clear.
            if r.clear {
                return Err(Status::invalid_argument(
                    "the organisation's value cannot be cleared: it always holds one, and a \
                     deployment changes it by stating the other value",
                ));
            }
        }
        SettingScope::Team => {
            // ABSENT and PRESENT-AND-EMPTY are two cases, and this boundary has
            // to refuse the second: an empty key in the override map is a row no
            // record's team will ever match.
            if !r.team_id.as_deref().is_some_and(|t| !t.is_empty()) {
                return Err(Status::invalid_argument(
                    "a team id is required at team scope: nothing else names the override to write",
                ));
            }
            // Meaningful at organisation scope only. `false` silently discarded
            // is exactly the case this refusal exists for, which is why the field
            // carries presence and this test is `is_some` rather than the value.
            if r.locked.is_some() {
                return Err(Status::invalid_argument(
                    "locked is meaningful at organisation scope only: a team cannot state whether \
                     teams may override",
                ));
            }
        }
    }

    // SENT EXPLICITLY, THE ZERO IS STILL A REFUSAL AND NEVER A CLEAR — at either
    // scope. It is what a caller that populated nothing sends, and reading it as
    // a withdrawal would let an unpopulated field destroy configuration silently.
    if r.value == Some(SettingValue::Unspecified as i32) {
        return Err(Status::invalid_argument(
            "value was sent unspecified: that is what an unpopulated field looks like, and it is \
             never read as a value or as a withdrawal",
        ));
    }

    // **AN OMITTED VALUE CAN NEVER BE READ AS A DELETION** (ADR-0524). This and
    // the clause above are two tests rather than one on purpose: they are the two
    // shapes that `value.unwrap_or_default()` collapses into a single case, and
    // one test cannot fail for both.
    if r.value.is_none() && !r.clear {
        return Err(Status::invalid_argument(
            "value is required unless clear is set: a request that states neither says nothing at \
             all",
        ));
    }

    // Two contradicting instructions, and neither is the obvious one to discard.
    if r.clear && r.value.is_some() {
        return Err(Status::invalid_argument(
            "clear and value contradict each other: withdraw the override or state one, never \
             both in the same request",
        ));
    }

    // A store that accepted free text would accrete settings nothing reads, and a
    // typo would be persisted as a new setting rather than refused at the call
    // that made it. Adding a member is a contract release, never a data change.
    if r.name != OWNER_READS_OWN_RECORD {
        return Err(Status::invalid_argument(
            "name is not a setting this contract declares; the vocabulary is closed and adding to \
             it is a contract release",
        ));
    }

    Ok(scope)
}
