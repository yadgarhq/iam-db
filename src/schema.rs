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

/// Migrations 8 to 13, which create what is DECIDED about an identity rather
/// than what one is made of. A child module rather than a second public one:
/// `migrations` below is the only caller either half has.
mod policy;

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
        policy::user_is_admin(),
        policy::rate_limit_override(),
        policy::org_setting(),
        policy::team_setting_override(),
        policy::seed_owner_reads_own_record(),
        policy::inherited_setting_write(),
        key_identity(),
    ])
}

fn key_identity() -> Migration {
    Migration {
        version: 14,
        name: "create_key_identity".into(),
        // ADR-0764's marker and ADR-0765's versioning of it: which key set
        // encrypted the rows in this store, so a regenerated `iam-keys` fails
        // loudly instead of starting healthy over rows it cannot read.
        //
        // ONE ROW FOR THE WHOLE INSTALLATION, AND THE ENGINE IS WHAT MAKES IT
        // ONE. `singleton` is a constant column whose only legal value is 1, so
        // the primary key admits exactly one row and the CHECK refuses any
        // attempt to open a second slot. A second marker is the failure this
        // table exists to prevent, and a UNIQUE on nothing in particular would
        // not prevent it; `iam_org_setting` keys on `name` for the same reason —
        // the discriminator is in the schema rather than in a convention.
        //
        // IT IS ALSO WHAT LETS THE ROW BE FOUND AS THE SINGLETON. The contract
        // states that neither `key_fingerprint` nor `derivation_version` may
        // appear in the lookup: `WHERE key_fingerprint = ?` finds nothing
        // whenever the key is wrong and reports ABSENT, so that arm can never
        // answer MISMATCH, and `WHERE derivation_version = ?` reads a version
        // skew as an empty store and earns it a second marker. `WHERE singleton
        // = 1` references nothing the caller sent.
        //
        // THE MARKER IS THE PAIR (ADR-0765), which is why the version is a
        // COLUMN here rather than a fact recovered from the fingerprint. A
        // marker without the version that produced it is the immortal,
        // unversioned derivation surface that entry exists to close: every
        // comparison this store makes is defined only WITHIN one version, and a
        // stored version it cannot read is a skew rather than a mismatch.
        //
        // VARBINARY, not BINARY, and not a text column. The fingerprint is
        // OPAQUE — the derivation is `iam`'s and this boundary reads no
        // structure in it — so a fixed width would fix a digest length into the
        // schema, which the contract refuses by name. Binary rather than text
        // for the reason `external_id_blind_index` gives: a byte-for-byte
        // comparison with no collation able to make two different fingerprints
        // compare equal.
        //
        // `idempotency_key` IS ON THE MARKER ROW RATHER THAN IN A LEDGER OF ITS
        // OWN. D9's amended half needs the prior REQUEST to refuse a repeated
        // key carrying a different payload, and on this arm the prior request IS
        // the stored marker — the two other columns are the whole payload. A
        // second table would hold a copy of them. It defaults to the empty
        // string because the empty string is not a key (`RedeemEnrolment`'s
        // rule), so a marker written without one never replays.
        sql: "CREATE TABLE iam_key_identity (
                  singleton           TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
                  derivation_version  INT UNSIGNED     NOT NULL,
                  key_fingerprint     VARBINARY(255)   NOT NULL,
                  idempotency_key     VARCHAR(255)     NOT NULL DEFAULT '',
                  recorded_at         TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  CONSTRAINT ck_iam_key_identity_singleton CHECK (singleton = 1)
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            .into(),
    }
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
