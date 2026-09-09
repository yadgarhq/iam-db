//! The migrations that create the POLICY tables, as distinct from the tables an
//! identity is made of.
//!
//! Migrations 1-7 in the parent module create the things this store holds: a
//! user, a password, a team, a membership, a credential, an enrolment and the
//! ledger that records a redemption. The six here create what is DECIDED ABOUT
//! one: whether a person is an administrator, the limits that apply to them,
//! the organisation's setting and a team's override of it, the row that seeds
//! that setting, and the ledger keying an administrative write to an
//! idempotency key.
//!
//! **The split is by subject and it changes no version.** Every `version` is an
//! explicit field, and `MigrationSet::new` sorts on it rather than on the order
//! the parent lists them in, so which file a migration is written in cannot
//! move it in the sequence. The numbers 8 to 13 are the same numbers they were.
//!
//! `pub(super)` rather than `pub`: `schema::migrations` is the only caller, and
//! a migration reachable from outside this crate is one somebody can apply on
//! its own.

use yadgar_store::migrate::Migration;

pub(super) fn user_is_admin() -> Migration {
    Migration {
        version: 8,
        name: "add_user_is_admin".into(),
        // A NEW MIGRATION RATHER THAN AN EDIT TO version 1. Deployed databases
        // are already past 1 and `apply` runs only what is pending, so editing
        // the CREATE TABLE would change a fresh install and nothing else — and
        // the two schemas diverge with nothing to notice it.
        //
        // NOT encrypted, unlike every other fact about a person in iam_user. It
        // is a fact about authority rather than about the person, and it has to
        // be readable in a WHERE clause.
        //
        // DEFAULT 0, so every user that already exists is not an admin. D73's
        // first admin is created with the flag already set, because it has to
        // exist before anyone can log in to promote one.
        sql: "ALTER TABLE iam_user
                  ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0"
            .into(),
    }
}

pub(super) fn rate_limit_override() -> Migration {
    Migration {
        version: 9,
        name: "create_rate_limit_override".into(),
        // The composite primary key carries the idempotence, the same shape
        // iam_team_member uses: setting one override twice is an upsert onto one
        // row rather than a second row, so no SELECT is needed to tell a first
        // grant from a repeat before the write lands.
        //
        // THAT idempotence was never the same claim as "no race here", and the
        // gap it left is now closed (ledger 695). Both this table's writer and
        // iam_team_member's used to check the person is live in a SEPARATE
        // statement ahead of the upsert; both now carry the predicate in the
        // upsert's own SELECT, and re-read only to render a zero match as
        // NOT_FOUND. `SetRateLimitOverride`'s CLEAR arm is the one exception and
        // its handler says why.
        //
        // CLEARING AN OVERRIDE DELETES THE ROW. An absent row means "the
        // deployment's configured default governs this bucket"; a stored rate of
        // zero means "deny this bucket". Those are different instructions, so
        // there is deliberately no nullable rate column able to express the
        // ambiguity.
        //
        // `kind` is D67's enum stored as its INTEGER wire value. D74 keys the
        // bucket on that existing bounded dimension rather than on a second
        // taxonomy, and the integer is what the contract transmits.
        sql: "CREATE TABLE iam_rate_limit_override (
                  user_id     VARCHAR(96)     NOT NULL,
                  module      VARCHAR(255)    NOT NULL,
                  kind        INT             NOT NULL,
                  rate        DOUBLE          NOT NULL,
                  burst       INT UNSIGNED    NOT NULL,
                  updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                              ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (user_id, module, kind),
                  CONSTRAINT fk_iam_rate_limit_override_user FOREIGN KEY (user_id)
                      REFERENCES iam_user (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

pub(super) fn org_setting() -> Migration {
    Migration {
        version: 10,
        name: "create_org_setting".into(),
        // ADR-0522's inheritable setting, organisation half. THERE IS NO
        // ORGANISATION ID because a deployment IS an organisation (D27), so the
        // name alone identifies the row.
        //
        // KEYED BY NAME rather than a column per setting. ADR-0522 says a second
        // setting reuses this resolution rather than inventing another, and a
        // named row is what lets a second setting arrive without a migration —
        // A SECOND SETTING OF THIS SHAPE. `value INT` makes this a table of
        // `SettingValue`-typed settings, not a table of settings generally; one
        // whose value is a duration or a string still needs its own table. The
        // names are a closed set the code owns; nothing here validates one,
        // because a row nobody reads is inert.
        //
        // `value` is `yadgar.common.v1.SettingValue` as its INTEGER wire value,
        // the precedent `iam_rate_limit_override.kind` already sets. NOT a
        // boolean: the enum has three states and the third one, UNSPECIFIED, is
        // the refusal that keeps a deployment from being handed a policy it never
        // chose.
        //
        // NEITHER COLUMN HAS A DEFAULT, and the absence is the point. A DEFAULT 0
        // on `value` is SETTING_VALUE_UNSPECIFIED, so a row inserted without one
        // would state no policy while looking like a policy; a DEFAULT on
        // `locked` would let a write forget the half that carries the weight.
        // Both have to be said out loud.
        //
        // THE CHECK IS THE ONLY VALIDATION THERE IS. The contract adds no RPC
        // that sets this, so the column is written by direct SQL and no Rust
        // ever sees the write; without the constraint a 0 or a 7 is insertable
        // and reaches the wire verbatim. UNSPECIFIED is deliberately OUTSIDE the
        // domain: it is what an ABSENT row states, never a value a present row
        // may hold, and a present row holding 0 would be an absent row wearing a
        // disguise. Adding the constraint later means finding and fixing the
        // rows first, which is why it is here on the migration that creates the
        // table.
        sql: "CREATE TABLE iam_org_setting (
                  name        VARCHAR(64) NOT NULL PRIMARY KEY,
                  value       INT         NOT NULL,
                  locked      TINYINT(1)  NOT NULL,
                  updated_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
                  CONSTRAINT ck_iam_org_setting_value CHECK (value IN (1, 2))
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

pub(super) fn team_setting_override() -> Migration {
    Migration {
        version: 11,
        name: "create_team_setting_override".into(),
        // ADR-0522's inheritable setting, team half. ABSENCE IS "THIS TEAM STATES
        // NOTHING", so a team with no opinion has no row rather than a row
        // holding UNSPECIFIED — the same shape iam_rate_limit_override uses, and
        // for the same reason: two ways to say nothing is one way too many.
        //
        // The composite primary key carries the idempotence, so setting an
        // override twice is an upsert onto one row rather than a second row.
        // SetInheritedSetting's team arm now carries `deleted_at IS NULL` INSIDE
        // this table's INSERT, under `LOCK IN SHARE MODE` — it is an
        // `INSERT ... SELECT` from `iam_team` rather than an `INSERT ... VALUES`
        // after a `live_team` call.
        //
        // A SHARED TRANSACTION IS NOT WHAT CLOSES A LIVENESS RACE, WHICH IS THE
        // CORRECTION THIS COMMENT EXISTS FOR. It said first that the shared
        // transaction made this arm safe; ledger 695's review measured the
        // opposite, and ledger 704 then fixed the arm. A transaction buys
        // ATOMICITY. It does not make a read see a concurrent writer.
        //
        // `live_team` IS A PLAIN NON-LOCKING SELECT WHEREVER IT RUNS, inside a
        // transaction or not. This handler sets READ COMMITTED explicitly, and at
        // that level the check reported a team live, the upsert then blocked on
        // this table's foreign key while the deleter committed, and the override
        // landed for a team whose `deleted_at` was set — which the handler read
        // back and returned as in force. Measured red, then green, by
        // `a_team_soft_delete_landing_mid_call_still_refuses_an_inherited_setting_override`.
        //
        // THE REACHABILITY ARGUMENT THAT DEFERRED THIS WAS FALSE. It said
        // `iam_team.deleted_at` has NO writer anywhere, test helpers included.
        // `Withdraw::Team` in the contract test is one, and the AddTeamMember
        // race test already used it. What is true is that no RPC deletes a team
        // yet — the same latency the other five were fixed under.
        //
        // ON DELETE CASCADE, AND IT COVERS HARD DELETION ONLY. An override
        // outliving a team whose row is gone would be an entry in the answer
        // keyed on a team no record can belong to. But this estate SOFT-deletes:
        // `iam_team` carries `deleted_at`, and a soft delete is an UPDATE no
        // cascade can see. Nothing is broken today because no RPC deletes a team
        // at all. When one arrives it will set `deleted_at`, and clearing the
        // override it strands is that RPC's job — not this constraint's, and not
        // the read's below, because filtering soft-deleted teams out of the
        // answer would be this module resolving, which is the one thing it must
        // not do.
        //
        // `value IN (1, 2)` for the reason iam_org_setting gives: nothing writes
        // this column but direct SQL, so the constraint is the only validation
        // between a write and the wire.
        sql: "CREATE TABLE iam_team_setting_override (
                  name        VARCHAR(64) NOT NULL,
                  team_id     VARCHAR(96) NOT NULL,
                  value       INT         NOT NULL,
                  updated_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (name, team_id),
                  CONSTRAINT ck_iam_team_setting_override_value CHECK (value IN (1, 2)),
                  CONSTRAINT fk_iam_team_setting_override_team FOREIGN KEY (team_id)
                      REFERENCES iam_team (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

pub(super) fn seed_owner_reads_own_record() -> Migration {
    Migration {
        version: 12,
        name: "seed_owner_reads_own_record".into(),
        // THE SHIPPED DEFAULT, and it is a migration rather than a fallback in
        // code. ADR-0522 makes the value readable with the lock ENGAGED, so the
        // owner-always-reads behaviour is what every deployment gets until
        // somebody deliberately changes it — and a service that substituted that
        // value when the row was missing would be the silent default the refusal
        // on SETTING_VALUE_UNSPECIFIED exists to make unwritable.
        //
        // 2 is SETTING_VALUE_ON. The literal rather than the constant because a
        // migration is a historical record: it must go on meaning what it meant
        // the day it ran, whatever the enum is renamed to later.
        //
        // ITS OWN MIGRATION rather than a second statement on version 10, because
        // a migration's SQL is executed as one statement.
        sql: "INSERT INTO iam_org_setting (name, value, locked)
                  VALUES ('owner_reads_own_record', 2, 1)"
            .into(),
    }
}

pub(super) fn inherited_setting_write() -> Migration {
    Migration {
        version: 13,
        name: "create_inherited_setting_write".into(),
        // THE SECOND IDEMPOTENCY LEDGER IN THIS SCHEMA, and the first was
        // written believing there would be no second — `iam_enrolment_redemption`
        // says every other RPC here "gets by without one" because each is
        // naturally repeatable. `SetInheritedSetting` is naturally repeatable
        // too: it ASSIGNS a level rather than toggling it, so replaying the key
        // and re-running the write reach the same state. That is why this table
        // stores no outcome.
        //
        // IT EXISTS FOR THE OTHER HALF OF D9, THE AMENDED HALF. A repeated key
        // carrying a DIFFERENT request is a REFUSAL rather than a replay, and
        // `yadgar.iamdb.v1.SetInheritedSettingRequest` enumerates exactly which
        // fields that comparison is over: `scope`, `team_id`, `name`, `value`,
        // `locked` and `clear`. Without somewhere to remember them, the second of
        // two writes under one key silently overwrites the first — an operator
        // retrying a lost call with a corrected value would have the correction
        // applied and no way to know which of the two took effect.
        //
        // O21 records that no `*-db` store persists a request fingerprint. This
        // does, for one RPC, and it does it as COLUMNS rather than as a digest.
        // A digest would need a hash function, and this crate deliberately has
        // none: D72 keeps argon2, hmac and sha2 out of the process that must not
        // be able to compute them. Six columns need no primitive and are
        // readable by whoever is looking at a refusal.
        //
        // **THREE COLUMNS ARE NULLABLE, AND THAT IS THE WHOLE OF ADR-0524
        // WRITTEN INTO A TABLE.** `team_id`, `value` and `locked` carry PRESENCE
        // on the wire, and a comparison that could not tell "absent" from "sent
        // as the zero" would let a request withdrawing an override compare equal
        // to one setting it OFF. NOT NULL with a sentinel would collapse exactly
        // the distinction the RPC is built on. `clear` is NOT NULL because it is
        // a bare bool on the wire, for the reason ADR-0524 gives: its falsy zero
        // is the safe direction.
        //
        // NO FOREIGN KEY ON `team_id`, unlike iam_team_setting_override. This is
        // an audit of what was ASKED FOR; a cascade would delete the record of a
        // request when the team it named went away, and the ledger would then
        // stop refusing a key whose payload it had forgotten.
        //
        // The PRIMARY KEY is the whole mechanism: the INSERT that records a
        // claim takes a real record lock rather than a gap lock, so the loser of
        // a race blocks on it and reads the winner's row (ADR-0513).
        sql: "CREATE TABLE iam_inherited_setting_write (
                  idempotency_key  VARCHAR(255) NOT NULL PRIMARY KEY,
                  scope            INT          NOT NULL,
                  team_id          VARCHAR(96)  NULL DEFAULT NULL,
                  name             VARCHAR(64)  NOT NULL,
                  value            INT          NULL DEFAULT NULL,
                  locked           TINYINT(1)   NULL DEFAULT NULL,
                  clear_requested  TINYINT(1)   NOT NULL,
                  written_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}
