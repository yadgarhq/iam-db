//! Migrations 19 to 21: what declared teams need beyond the team tables
//! migrations 3 and 4 already created (plans/team-access.md §6).

use yadgar_store::migrate::Migration;

pub(super) fn team_member_pending() -> Migration {
    Migration {
        version: 19,
        name: "create_team_member_pending".into(),
        // F2's PENDING ADMINISTRATOR (ADR-0963 (5)). `iam_team_member.user_id`
        // has a foreign key to `iam_user` (migration 4), so a declared member
        // whose user does not exist yet cannot be a member row. This table holds
        // a declared `administrators` member with no `iam_user` row, ONLY while
        // `administrators` has no live member; `SyncTeams` replaces the set on
        // every sync and the bootstrap `CreateUser` consumes it.
        //
        // NO FOREIGN KEY ON `user_id`, which is the whole point of the table.
        // NOTHING READS IT AT ATTEST TIME: `team_ids` and `is_admin` come from
        // `iam_team_member` only, so a pending row admits nobody.
        sql: "CREATE TABLE iam_team_member_pending (
                  team_id    VARCHAR(96) NOT NULL,
                  user_id    VARCHAR(96) NOT NULL,
                  added_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (team_id, user_id),
                  CONSTRAINT fk_iam_team_member_pending_team FOREIGN KEY (team_id)
                      REFERENCES iam_team (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

pub(super) fn team_sync_lock() -> Migration {
    Migration {
        version: 20,
        name: "create_team_sync_lock".into(),
        // THE SENTINEL `SyncTeams` LOCKS FIRST, `FOR UPDATE`, so two syncs
        // serialise — two first syncs into an empty store included, where no
        // team row exists yet to lock. The shape `project-db`'s
        // `project_sync_lock` takes for `SyncProjects`. One row, forever.
        sql: "CREATE TABLE iam_team_sync_lock (
                  id  TINYINT NOT NULL PRIMARY KEY,
                  CONSTRAINT ck_iam_team_sync_lock_one CHECK (id = 1)
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

pub(super) fn seed_team_sync_lock() -> Migration {
    Migration {
        version: 21,
        name: "seed_team_sync_lock".into(),
        // ITS OWN MIGRATION, because a migration's SQL is one statement
        // (`seed_owner_reads_own_record` says the same).
        sql: "INSERT INTO iam_team_sync_lock (id) VALUES (1)".into(),
    }
}
