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
        // A redemption the previous release recorded, already spent.
        "INSERT INTO iam_enrolment (id, user_id, secret_hash, expires_at, spent_at)
         VALUES ('yadgar:enrolment:spent', 'yadgar:user:old', REPEAT(CHAR(4), 32),
                 CURRENT_TIMESTAMP + INTERVAL 1 HOUR, CURRENT_TIMESTAMP)",
        "INSERT INTO iam_enrolment_redemption
             (idempotency_key, secret_hash, enrolment_id, user_id)
         VALUES ('old-key', REPEAT(CHAR(4), 32), 'yadgar:enrolment:spent', 'yadgar:user:old')",
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

    // MIGRATION 18'S DEFAULT: a ledger row from before the upgrade replays
    // with epoch 0, which mints only while nothing has bumped the person since.
    let replayed = redeem(&svc, 4, OTHER_HASH, "old-key").await;
    assert_eq!(replayed.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(replayed.credential_epoch, 0);

    let got = redeem(&svc, 2, OTHER_HASH, "").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(got.credential_epoch, 1);
    let err = mint(&svc, "yadgar:user:old", 5, Some(replayed.credential_epoch))
        .await
        .expect_err("the pre-upgrade replay's epoch is stale after the bump");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

/// The last version the release before team access stage 2 shipped.
const BEFORE_TEAMS: u64 = 18;

/// Migrations 19 to 21 (team access stage 2) on a store that already holds a
/// column-admin person with a live credential, a team and a member row the
/// previous release could hold (migrations 3 and 4 created those tables).
#[tokio::test]
async fn a_populated_store_upgrades_to_declared_teams() {
    let pool = empty("iam_db_upgrade_teams").await;
    let all = schema::migrations().expect("migrations");
    let previous = MigrationSet::new(
        all.pending_after(0)
            .filter(|m| m.version <= BEFORE_TEAMS)
            .cloned()
            .collect(),
    )
    .expect("the previous release's set");
    migrate(&pool, &previous).await;

    let old = IamDb::new(pool.clone());
    let admin = person(&old, 1).await;
    make_admin(&old, &admin).await;
    mint(&old, &admin, 11, None).await.expect("mint");
    // AUDIT: literals and the id `person` returned, bound.
    sqlx::raw_sql(sqlx::AssertSqlSafe(
        "INSERT INTO iam_team (id, name, created_by, updated_by)
         VALUES ('yadgar:team:administrators', 'administrators', 'test', 'test')",
    ))
    .execute(&pool)
    .await
    .expect("a team row as the previous release could hold it");
    sqlx::query("INSERT INTO iam_team_member (team_id, user_id, added_by) VALUES (?, ?, 'test')")
        .bind("yadgar:team:administrators")
        .bind(&admin)
        .execute(&pool)
        .await
        .expect("a member row as the previous release could hold it");

    migrate(&pool, &all).await;
    let svc = IamDb::new(pool);

    let lock_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam_team_sync_lock")
        .fetch_one(svc.pool())
        .await
        .expect("the sentinel table");
    assert_eq!(lock_rows, 1);
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam_team_member_pending")
        .fetch_one(svc.pool())
        .await
        .expect("the pending table");
    assert_eq!(pending, 0);

    // Derivation off (absent): the column still decides, the member row shows.
    let got = resolve(&svc, 11).await;
    assert_eq!(got.user_id, admin);
    assert!(got.is_admin);
    assert_eq!(got.team_ids, vec!["yadgar:team:administrators"]);

    // A SyncTeams on the upgraded store converges on the stored rows.
    let synced = svc
        .sync_teams_as(
            Some(yadgar_iam_db::service::IAM_CALLER),
            tonic::Request::new(SyncTeamsRequest {
                scope: None,
                teams: vec![DeclaredTeam {
                    name: "administrators".into(),
                    member_user_ids: vec![admin.clone()],
                }],
            }),
        )
        .await
        .expect("a sync on the upgraded store")
        .into_inner();
    assert_eq!(synced.teams_inserted, 0);
    assert_eq!(synced.members_added, 0);
    assert_eq!(synced.members_removed, 0);
    assert_eq!(synced.administrators_live_members, 1);
}
