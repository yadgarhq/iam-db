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
