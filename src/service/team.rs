//! Declared teams (plans/team-access.md, ADR-0962, ADR-0963).
//!
//! `SyncTeams` is the ONE writer of team membership: the seeder sends the
//! organisation's whole declaration through `iam`, and the `sync` child applies
//! it in one transaction. `AddTeamMember` and `RemoveTeamMember` answer
//! `FAILED_PRECONDITION` (ADR-0963 (7)).
//!
//! This file holds what the three readers of `administrators` share: the
//! sync, the F2 bootstrap `CreateUser` (`identity::bootstrap`) and the
//! derivation-on enrolment arm (`enrolment::declared`). All three take the
//! SAME lock, the `administrators` row `FOR UPDATE`, before they read its
//! members, and all three pin READ COMMITTED for that transaction only
//! (ADR-0513, through `conn::Conn::begin`), so a read after the lock wait sees
//! the winner's rows.

use super::*;

mod sync;

/// The team whose live members are this installation's administrators.
pub(in crate::service) const ADMINISTRATORS: &str = "yadgar:team:administrators";

/// A declared team named `name` has the id `TEAM_PREFIX + name`, so no call
/// returns an id a second call needs (plans/team-access.md §1).
pub(in crate::service) const TEAM_PREFIX: &str = "yadgar:team:";

/// A user id on the wire.
pub(in crate::service) const USER_PREFIX: &str = "yadgar:user:";

/// `yadgar:user:` followed by a lowercase canonical uuidv7: 36 characters,
/// `8-4-4-4-12` lowercase hex, version nibble `7`, RFC 4122 variant (`8`, `9`,
/// `a` or `b`). The nil uuid fails on its version nibble.
///
/// The one rule for a declared member and for F2's pre-minted `user_id`
/// (plans/team-access.md §2, §6 step 1). `iam` checks the same rule first;
/// this store checks again, because it is the store.
pub(in crate::service) fn canonical_user_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix(USER_PREFIX) else {
        return false;
    };
    let bytes = uuid.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let shape = bytes.iter().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => *b == b'-',
        _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
    });
    shape && bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Lock the `administrators` row `FOR UPDATE`, and say whether it is live.
///
/// `None`: no row. `Some(false)`: archived (`deleted_at` set). The lock is
/// taken on the row whichever it is, so every caller serialises on it.
pub(in crate::service) async fn lock_administrators(
    tx: &mut sqlx::MySqlTransaction<'_>,
) -> Result<Option<bool>, Status> {
    sqlx::query_scalar::<_, i64>(
        "SELECT CAST(deleted_at IS NULL AS SIGNED) FROM iam_team WHERE id = ? FOR UPDATE",
    )
    .bind(ADMINISTRATORS)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)
    .map(|live| live.map(|l| l != 0))
}

/// How many LIVE members `administrators` has: member rows whose `iam_user`
/// row has `deleted_at IS NULL`, in a team whose `deleted_at IS NULL`
/// (plans/team-access.md §7, the count the lockout guard and F2 step 3 read).
pub(in crate::service) async fn live_administrators(
    tx: &mut sqlx::MySqlTransaction<'_>,
) -> Result<i64, Status> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam_team_member m
           JOIN iam_team t ON t.id = m.team_id
           JOIN iam_user u ON u.id = m.user_id
          WHERE m.team_id = ? AND t.deleted_at IS NULL AND u.deleted_at IS NULL",
    )
    .bind(ADMINISTRATORS)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)
}

#[cfg(test)]
mod tests {
    use super::canonical_user_id;

    #[test]
    fn the_member_rule_admits_a_lowercase_uuidv7_and_nothing_else() {
        let good = "yadgar:user:0192f3c4-1a2b-7c3d-8e4f-0123456789ab";
        assert!(canonical_user_id(good));
        for bad in [
            "yadgar:user:0192F3C4-1A2B-7C3D-8E4F-0123456789AB",
            "yadgar:user:0192f3c4-1a2b-4c3d-8e4f-0123456789ab",
            "yadgar:user:0192f3c4-1a2b-7c3d-ce4f-0123456789ab",
            "0192f3c4-1a2b-7c3d-8e4f-0123456789ab",
            "yadgar:user:00000000-0000-0000-0000-000000000000",
            "yadgar:user:0192f3c4-1a2b-7c3d-8e4f-0123456789a",
        ] {
            assert!(!canonical_user_id(bad), "{bad}");
        }
    }
}
