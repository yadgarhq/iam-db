//! This module's migrations. `yadgar-store` runs them; it never holds them (D7).
//!
//! Three rules from D72 shape every table here, and each is enforced by the
//! column types rather than by anyone remembering:
//!
//! - **No plaintext personal data.** Names are ciphertext. There is no column
//!   anywhere that a `SELECT *` could reveal a username from.
//! - **No plaintext secrets.** The password is an Argon2id hash; the credential
//!   is a SHA-256 hash of the token. Neither can be reversed into the thing a
//!   caller presented.
//! - **Lookup without decryption.** Every query this service needs runs against a
//!   hash or an index — never against a decrypted value — so the database can
//!   answer them without holding a key.
//!
//! The encryption and HMAC keys live in a Secret and are held by `iam`, never
//! here. A dump of this database, on its own, is opaque.

use yadgar_store::migrate::{Migration, MigrationError, MigrationSet};

pub fn migrations() -> Result<MigrationSet, MigrationError> {
    // One function per migration, because the set outgrew a single literal and
    // the complexity ceiling caught it. The seam is the natural one — a
    // migration is already a unit — rather than a cut made to satisfy a number.
    MigrationSet::new(vec![
        user(),
        password(),
        team(),
        team_member(),
        credential(),
        enrolment(),
        enrolment_redemption(),
        user_is_admin(),
        rate_limit_override(),
        org_setting(),
        team_setting_override(),
        seed_owner_reads_own_record(),
    ])
}

fn user() -> Migration {
    Migration {
        version: 1,
        name: "create_user".into(),
        // `external_id_blind_index` is HMAC-SHA256 of the username under a
        // key this service does not have. It is UNIQUE and it is what login
        // matches on.
        //
        // WHY NOT JUST ENCRYPT THE USERNAME AND QUERY THAT: AES-GCM is
        // randomised, so the same username encrypts to a different value
        // every time and equality can never match. The blind index is the
        // standard answer. It leaks equality — two identical usernames share
        // an index — which is precisely what a lookup key must leak, and it
        // reveals nothing about the value itself.
        //
        // BINARY(32), not VARCHAR: a fixed-width binary column compares
        // byte-for-byte with no collation involved. A hash stored in a
        // text column under a case-insensitive collation makes two different
        // hashes compare equal, which is a wrong answer rather than a slow
        // one.
        sql: "CREATE TABLE iam_user (
                  id                       VARCHAR(96)  NOT NULL PRIMARY KEY,
                  version                  BIGINT UNSIGNED NOT NULL DEFAULT 1,
                  project_id               VARCHAR(255) NOT NULL DEFAULT '',
                  owner_user_id            VARCHAR(64)  NOT NULL DEFAULT '',
                  team_id                  VARCHAR(64)  NOT NULL DEFAULT '',
                  visibility               TINYINT      NOT NULL DEFAULT 1,
                  created_by               VARCHAR(64)  NOT NULL,
                  updated_by               VARCHAR(64)  NOT NULL,
                  created_at               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  updated_at               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                        ON UPDATE CURRENT_TIMESTAMP,
                  deleted_at               TIMESTAMP    NULL DEFAULT NULL,
                  external_id_blind_index  BINARY(32)   NOT NULL,
                  external_id_ciphertext   VARBINARY(512) NOT NULL,
                  display_name_ciphertext  VARBINARY(512) NOT NULL,
                  UNIQUE KEY uq_iam_user_blind_index (external_id_blind_index)
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn password() -> Migration {
    Migration {
        version: 2,
        name: "create_password".into(),
        // A SEPARATE TABLE, not a column on iam_user, and the separation is
        // the point: no query that reads a user for display can pull the
        // password hash along with it by accident. `SELECT * FROM iam_user`
        // is safe here in a way it would not be otherwise.
        //
        // VARCHAR(255) holds the full PHC string —
        // `$argon2id$v=19$m=…,t=…,p=…$salt$hash` — which carries the
        // parameters and the per-password salt INSIDE it. So there is no
        // salt column to forget, and the cost parameters can be raised later
        // without a migration: an old hash still verifies against its own
        // recorded parameters, and is re-hashed on next successful login.
        sql: "CREATE TABLE iam_password (
                  user_id        VARCHAR(96)  NOT NULL PRIMARY KEY,
                  argon2id_hash  VARCHAR(255) NOT NULL,
                  updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                              ON UPDATE CURRENT_TIMESTAMP,
                  CONSTRAINT fk_iam_password_user FOREIGN KEY (user_id)
                      REFERENCES iam_user (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn team() -> Migration {
    Migration {
        version: 3,
        name: "create_team".into(),
        // Team NAMES are not encrypted. They are not personal data — a team
        // is an organisational unit, not a person — and encrypting them would
        // buy nothing while making them unsearchable. Stated because the
        // inconsistency with iam_user looks like an oversight otherwise.
        sql: "CREATE TABLE iam_team (
                  id          VARCHAR(96)  NOT NULL PRIMARY KEY,
                  version     BIGINT UNSIGNED NOT NULL DEFAULT 1,
                  name        VARCHAR(255) NOT NULL,
                  created_by  VARCHAR(64)  NOT NULL,
                  updated_by  VARCHAR(64)  NOT NULL,
                  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                           ON UPDATE CURRENT_TIMESTAMP,
                  deleted_at  TIMESTAMP    NULL DEFAULT NULL,
                  UNIQUE KEY uq_iam_team_name (name)
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn team_member() -> Migration {
    Migration {
        version: 4,
        name: "create_team_member".into(),
        // The composite primary key makes double-adding a member a no-op
        // rather than a duplicate row, which is what lets AddTeamMember be
        // idempotent (D9) without a separate existence check.
        //
        // Indexed BOTH ways deliberately. The primary key answers "is this
        // user in this team"; ix_user answers "which teams is this user in",
        // which is the question the credential resolve path asks on every
        // cache miss and the one that would otherwise scan.
        sql: "CREATE TABLE iam_team_member (
                  team_id    VARCHAR(96) NOT NULL,
                  user_id    VARCHAR(96) NOT NULL,
                  added_by   VARCHAR(64) NOT NULL,
                  added_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (team_id, user_id),
                  KEY ix_iam_team_member_user (user_id),
                  CONSTRAINT fk_iam_team_member_team FOREIGN KEY (team_id)
                      REFERENCES iam_team (id) ON DELETE CASCADE,
                  CONSTRAINT fk_iam_team_member_user FOREIGN KEY (user_id)
                      REFERENCES iam_user (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn credential() -> Migration {
    Migration {
        version: 5,
        name: "create_credential".into(),
        // token_hash is SHA-256 of the bearer token, and SHA-256 rather than
        // Argon2id is a deliberate difference from the password column.
        //
        // A password is low-entropy and chosen by a human, so a stolen hash
        // is guessable and must be made expensive to attack — that is what
        // Argon2id buys. A token is 256 bits of CSPRNG output: there is
        // nothing to guess, so a slow hash would buy no security and would
        // put a deliberately expensive computation on the hottest path in the
        // system, run on every cache miss of every request.
        //
        // UNIQUE, because it is the lookup key and because two credentials
        // hashing alike would mean one resolving to the wrong person.
        //
        // revoked_at is a TOMBSTONE, not a delete (D26): "which credential
        // was used" must stay answerable after it is withdrawn, and an audit
        // record pointing at a row that no longer exists answers nothing.
        sql: "CREATE TABLE iam_credential (
                  id          VARCHAR(96)  NOT NULL PRIMARY KEY,
                  user_id     VARCHAR(96)  NOT NULL,
                  token_hash  BINARY(32)   NOT NULL,
                  label       VARCHAR(255) NOT NULL DEFAULT '',
                  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  expires_at  TIMESTAMP    NULL DEFAULT NULL,
                  revoked_at  TIMESTAMP    NULL DEFAULT NULL,
                  UNIQUE KEY uq_iam_credential_token (token_hash),
                  KEY ix_iam_credential_user (user_id),
                  CONSTRAINT fk_iam_credential_user FOREIGN KEY (user_id)
                      REFERENCES iam_user (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn enrolment() -> Migration {
    Migration {
        version: 6,
        name: "create_enrolment".into(),
        // secret_hash is the LOOKUP KEY, and it is UNIQUE for the same two
        // reasons the credential token is: it is what a redemption is found by,
        // and two enrolments hashing alike would redeem the wrong person's
        // account. BINARY(32) rather than a text column, so the comparison is
        // byte-for-byte with no collation able to make two different hashes
        // compare equal.
        //
        // THERE IS DELIBERATELY NO UNIQUENESS TOUCHING user_id, and the absence
        // is load-bearing rather than an omission. A spent enrolment must block
        // no new one: a lost redemption response leaves a person locked out, and
        // an admin minting a FRESH enrolment is the documented way back in. A
        // `UNIQUE (user_id)` would make that recovery path fail with a duplicate
        // key, and the failure would be indistinguishable from the store being
        // broken. Liveness is `spent_at IS NULL AND expires_at > NOW()` — a
        // property of a ROW, evaluated in the WHERE clause — never a property of
        // the user.
        //
        // expires_at is NOT NULL, unlike the credential's. D73 gives an
        // enrolment 24 hours, and the deadline is written down at creation
        // rather than recomputed when the secret is presented — otherwise
        // changing the policy silently re-dates every live token. An enrolment
        // with no expiry is a permanent password-reset token, which is the thing
        // this table exists not to be.
        //
        // spent_at is a TOMBSTONE, not a delete (D26). "This secret was
        // presented again after it was used" stays answerable, and a replay is
        // precisely the event worth keeping.
        sql: "CREATE TABLE iam_enrolment (
                  id           VARCHAR(96) NOT NULL PRIMARY KEY,
                  user_id      VARCHAR(96) NOT NULL,
                  secret_hash  BINARY(32)  NOT NULL,
                  created_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  expires_at   TIMESTAMP   NOT NULL,
                  spent_at     TIMESTAMP   NULL DEFAULT NULL,
                  UNIQUE KEY uq_iam_enrolment_secret (secret_hash),
                  KEY ix_iam_enrolment_user (user_id),
                  CONSTRAINT fk_iam_enrolment_user FOREIGN KEY (user_id)
                      REFERENCES iam_user (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn enrolment_redemption() -> Migration {
    Migration {
        version: 7,
        name: "create_enrolment_redemption".into(),
        // THE ONLY IDEMPOTENCY LEDGER IN THIS SCHEMA, and every other RPC on
        // this boundary still gets by without one — AddTeamMember has a
        // composite primary key, RevokeCredential has a tombstone in its WHERE
        // clause, SetPassword is an upsert. Each of those is naturally
        // repeatable, so replaying the key and re-running the write give the
        // same answer.
        //
        // Redemption is the one that does not. Running it twice finds the secret
        // already spent and reports REDEEM_OUTCOME_SPENT — and reporting spent
        // to a caller that is merely retrying is what locks the person out, on
        // the one path D73 gives no resend. So the ORIGINAL outcome has to be
        // stored to be replayed, and this table is where.
        //
        // ONLY A REDEMPTION IS RECORDED HERE. A stored NOT_FOUND, SPENT or
        // EXPIRED would replay a stale failure to a caller retrying after a
        // transient error, and the contract's own words are "the one this key
        // originally SPENT" — which only a redemption did.
        //
        // secret_hash is stored so a key reused with a DIFFERENT secret is
        // refused rather than replayed (D9 as amended). This boundary can make
        // that comparison precisely because the hash is deterministic — the same
        // property that lets an enrolment be looked up by it. It cannot make the
        // equivalent comparison on the password: a fresh Argon2id salt makes two
        // hashes of one password differ, so that axis is checked in `iam`, the
        // only place the plaintext exists. O21 records the general version of
        // this gap — no `*-db` store persists a request fingerprint — so what is
        // here is the one comparison that happens to be possible, not a
        // mechanism another RPC can reuse.
        //
        // The FOREIGN KEY is what keeps a replay answerable. A replay must
        // return the user's `external_id_ciphertext`, which is read by joining
        // iam_user, and this cascade means a ledger row cannot outlive the row
        // that join needs.
        sql: "CREATE TABLE iam_enrolment_redemption (
                  idempotency_key  VARCHAR(255) NOT NULL PRIMARY KEY,
                  secret_hash      BINARY(32)   NOT NULL,
                  enrolment_id     VARCHAR(96)  NOT NULL,
                  user_id          VARCHAR(96)  NOT NULL,
                  redeemed_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  KEY ix_iam_enrolment_redemption_enrolment (enrolment_id),
                  CONSTRAINT fk_iam_enrolment_redemption_enrolment
                      FOREIGN KEY (enrolment_id)
                      REFERENCES iam_enrolment (id) ON DELETE CASCADE
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
}

fn user_is_admin() -> Migration {
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

fn rate_limit_override() -> Migration {
    Migration {
        version: 9,
        name: "create_rate_limit_override".into(),
        // The composite primary key carries the idempotence, the same shape
        // iam_team_member uses: setting one override twice is an upsert onto one
        // row rather than a second row, so nothing checks first and there is no
        // race between the check and the write.
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

fn org_setting() -> Migration {
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

fn team_setting_override() -> Migration {
    Migration {
        version: 11,
        name: "create_team_setting_override".into(),
        // ADR-0522's inheritable setting, team half. ABSENCE IS "THIS TEAM STATES
        // NOTHING", so a team with no opinion has no row rather than a row
        // holding UNSPECIFIED — the same shape iam_rate_limit_override uses, and
        // for the same reason: two ways to say nothing is one way too many.
        //
        // The composite primary key carries the idempotence, so setting an
        // override twice is an upsert onto one row and nothing checks first.
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

fn seed_owner_reads_own_record() -> Migration {
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
