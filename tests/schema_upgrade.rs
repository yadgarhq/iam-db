//! Migrations 16 and 17 (ADR-0972) applied to a store that already holds
//! rows, against a real MariaDB.
//!
//! A FRESH database proves the new columns exist; it does not prove what an
//! UPGRADE does to the rows already there. This applies migrations 1 to 15,
//! writes a person, a password and an enrolment the way the previous release
//! did, then applies the rest and asserts the old rows behave: the person's
//! epoch is 0, the enrolment is not voided and still redeems, and a Login
//! against that person mints under the epoch it read.

mod db;

use db::*;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::schema;
use yadgar_iam_db::service::IamDb;
use yadgar_store::migrate::MigrationSet;

/// The last version the previous release shipped.
const BEFORE: u64 = 15;

#[tokio::test]
async fn rows_written_before_the_epoch_and_void_migrations_keep_working() {
    let pool = empty("iam_db_upgrade_epoch_void").await;
    let all = schema::migrations().expect("migrations");
    let previous = MigrationSet::new(
        all.pending_after(0)
            .filter(|m| m.version <= BEFORE)
            .cloned()
            .collect(),
    )
    .expect("the previous release's set");
    migrate(&pool, &previous).await;

    // AUDIT: every value is a literal in this file.
    for stmt in [
        "INSERT INTO iam_user (id, created_by, updated_by, external_id_blind_index,
                               external_id_ciphertext, display_name_ciphertext)
         VALUES ('yadgar:user:old', 'test', 'test', REPEAT(CHAR(1), 32), 'c', 'd')",
        "INSERT INTO iam_password (user_id, argon2id_hash)
         VALUES ('yadgar:user:old', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA')",
        "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at)
         VALUES ('yadgar:enrolment:old', 'yadgar:user:old', REPEAT(CHAR(2), 32),
                 CURRENT_TIMESTAMP + INTERVAL 1 HOUR)",
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&pool)
            .await
            .expect("a row as the previous release wrote it");
    }

    migrate(&pool, &all).await;
    let svc = IamDb::new(pool);

    assert_eq!(stored_epoch(&svc, "yadgar:user:old").await, 0);
    assert_eq!(enrolment_state(&svc, 2).await, (false, false));

    let read = password_hash(&svc, 1).await;
    assert_eq!(read.user_id, "yadgar:user:old");
    assert_eq!(read.credential_epoch, 0);
    mint(&svc, "yadgar:user:old", 3, Some(read.credential_epoch))
        .await
        .expect("a Login against an upgraded person mints");

    let got = redeem(&svc, 2, OTHER_HASH, "").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(got.credential_epoch, 1);
}
