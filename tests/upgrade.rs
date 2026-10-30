//! A store an OLDER release migrated, meeting this release's image (yaadgaar
//! #245). Ported from project-db's `tests/upgrade.rs`.
//!
//! **EVERY OTHER SUITE HERE STARTS FROM AN EMPTY DATABASE**, so it can only see
//! the schema a NEW install gets. A migration edited in place after it shipped
//! reaches no store that already applied it: the ledger records the version,
//! never the SQL. project-db v0.7.0 shipped broken that way. This suite builds a
//! store the way the oldest release did, migrates it to this release, and
//! requires the result to match a fresh install.
//!
//! [`V0_1`] is v0.1.0's migration set, frozen VERBATIM. It is a literal, never
//! read from git at run time: it is history, and history does not change.
//! v0.3.0 (83faee1) re-indented migrations 1-5 when it split them into one
//! function each, so these literals are byte-different from today's and the
//! schema they build is identical. That is the case this suite proves.

mod db;

use db::*;
use yadgar_iam_db::schema;
use yadgar_store::migrate::{Migration, MigrationSet};

/// v0.1.0's migrations 1-5, SQL byte-for-byte as that tag carries it.
#[allow(non_snake_case)]
fn V0_1() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "create_user".into(),
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
        },
        Migration {
            version: 2,
            name: "create_password".into(),
            sql: "CREATE TABLE iam_password (
                      user_id        VARCHAR(96)  NOT NULL PRIMARY KEY,
                      argon2id_hash  VARCHAR(255) NOT NULL,
                      updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                  ON UPDATE CURRENT_TIMESTAMP,
                      CONSTRAINT fk_iam_password_user FOREIGN KEY (user_id)
                          REFERENCES iam_user (id) ON DELETE CASCADE
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
                .into(),
        },
        Migration {
            version: 3,
            name: "create_team".into(),
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
        },
        Migration {
            version: 4,
            name: "create_team_member".into(),
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
        },
        Migration {
            version: 5,
            name: "create_credential".into(),
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
        },
    ]
}

/// Every table, column, CHECK, index and foreign key a fresh install has, an
/// upgraded store has — with the same type, nullability, default, collation,
/// position and referential rules. A query is only right against the schema it
/// meets.
#[tokio::test]
async fn an_upgraded_store_has_exactly_the_schema_a_fresh_one_has() {
    let all = schema::migrations().expect("migrations");

    let fresh = empty("iam_db_upgrade_parity_fresh").await;
    migrate(&fresh, &all).await;

    let upgraded = empty("iam_db_upgrade_parity_old").await;
    migrate(&upgraded, &MigrationSet::new(V0_1()).expect("v0.1.0's set")).await;
    migrate(&upgraded, &all).await;

    assert_eq!(
        shape(&upgraded, "iam_db_upgrade_parity_old").await,
        shape(&fresh, "iam_db_upgrade_parity_fresh").await
    );
}

/// `(table, column, type, nullable, default, collation, position)`.
type Column = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    u64,
);

/// `(table, constraint, column, referenced table, referenced column, on update,
/// on delete)`.
type ForeignKey = (String, String, String, String, String, String, String);

type Shape = (
    Vec<(String, Option<String>, Option<String>)>,
    Vec<Column>,
    Vec<(String, String, String)>,
    Vec<(String, String, String, u64, i64)>,
    Vec<ForeignKey>,
);

/// `information_schema`'s view of one database: tables, columns, CHECKs,
/// indexes and foreign keys. project-db's original has no foreign keys to
/// compare; this schema has nine.
async fn shape(pool: &sqlx::MySqlPool, db: &str) -> Shape {
    let tables = sqlx::query_as(
        "SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
           FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?
          ORDER BY TABLE_NAME",
    )
    .bind(db)
    .fetch_all(pool)
    .await
    .expect("tables");
    let columns = sqlx::query_as(
        "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT,
                COLLATION_NAME, CAST(ORDINAL_POSITION AS UNSIGNED)
           FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ?
          ORDER BY TABLE_NAME, ORDINAL_POSITION",
    )
    .bind(db)
    .fetch_all(pool)
    .await
    .expect("columns");
    let checks = sqlx::query_as(
        "SELECT TABLE_NAME, CONSTRAINT_NAME, CHECK_CLAUSE
           FROM information_schema.CHECK_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ?
          ORDER BY TABLE_NAME, CONSTRAINT_NAME",
    )
    .bind(db)
    .fetch_all(pool)
    .await
    .expect("checks");
    let indexes = sqlx::query_as(
        "SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME,
                CAST(SEQ_IN_INDEX AS UNSIGNED), CAST(NON_UNIQUE AS SIGNED)
           FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ?
          ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
    )
    .bind(db)
    .fetch_all(pool)
    .await
    .expect("indexes");
    let foreign_keys = sqlx::query_as(
        "SELECT r.TABLE_NAME, r.CONSTRAINT_NAME, k.COLUMN_NAME,
                r.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME,
                r.UPDATE_RULE, r.DELETE_RULE
           FROM information_schema.REFERENTIAL_CONSTRAINTS r
           JOIN information_schema.KEY_COLUMN_USAGE k
             ON k.CONSTRAINT_SCHEMA = r.CONSTRAINT_SCHEMA
            AND k.TABLE_NAME = r.TABLE_NAME
            AND k.CONSTRAINT_NAME = r.CONSTRAINT_NAME
          WHERE r.CONSTRAINT_SCHEMA = ?
          ORDER BY r.TABLE_NAME, r.CONSTRAINT_NAME, k.ORDINAL_POSITION",
    )
    .bind(db)
    .fetch_all(pool)
    .await
    .expect("foreign keys");
    (tables, columns, checks, indexes, foreign_keys)
}
