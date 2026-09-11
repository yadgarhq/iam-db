//! `IamDbService` against a real MariaDB.
//!
//! The contract test proto-contract-design.md places in each `-db` repo. It
//! panics rather than skips without an engine, for the reason D69 gives: a suite
//! that quietly passes with nothing behind it is the failure it exists to catch.
//!
//! **What these assert is deliberately narrow: the ways a credential must STOP
//! working.** Resolving a live credential is the easy case and would pass on a
//! naive implementation. Revoked, expired, and belonging-to-a-deleted-user are
//! the cases where a missing `AND` clause leaves someone authenticated after they
//! should not be, and none of them is visible in a happy-path test.
//!
//! **The deleted-user case was claimed by this very paragraph and not covered.**
//! Deleting `AND u.deleted_at IS NULL` from either query left all thirteen tests
//! green while every soft-deleted person authenticated indefinitely — and could
//! still log in and mint a FRESH credential. A module doc is not a test; the two
//! at the foot of this file are.

use sqlx::Connection;
use tonic::Request;
use yadgar_iam_db::pb::yadgar::common::v1::{
    Idempotency, SettingScope, SettingValue, UnverifiedActor,
};
use yadgar_iam_db::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbService as _;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::{schema, service::IamDb};

fn dsn() -> String {
    std::env::var("YADGAR_TEST_DSN")
        .expect("YADGAR_TEST_DSN is unset; these tests assert what a real MariaDB does")
}

async fn fresh(db: &str) -> IamDb {
    let mut root = sqlx::MySqlConnection::connect(&dsn())
        .await
        .expect("connect");
    for stmt in [
        format!("DROP DATABASE IF EXISTS {db}"),
        format!("CREATE DATABASE {db}"),
    ] {
        // AUDIT: `db` is a literal in this file.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("reset database");
    }
    // Strip the DSN's own database before appending ours.
    //
    // CI's DSN ends in a database name (`mysql://root:ci@127.0.0.1:3306/ci`), so
    // appending produced `.../ci/iam_db_test_x` and every test failed with
    // "Unknown database". It passed locally only because a local DSN usually has
    // no database component — which is exactly why this was not caught until CI
    // ran it, and why iam-db's first commit reaching main without a pull request
    // meant nobody found out.
    let base = dsn()
        .rsplit_once('/')
        .expect("dsn has a database component")
        .0
        .to_string();
    let pool = sqlx::MySqlPool::connect(&format!("{base}/{db}"))
        .await
        .expect("pool");
    yadgar_store::migrate::apply(&pool, &schema::migrations().expect("migrations"))
        .await
        .expect("migrate");
    IamDb::new(pool)
}

/// A user with one credential. Returns `(user_id, token_hash, credential_id)`.
async fn seed(svc: &IamDb, name: &[u8; 32], token: &[u8; 32]) -> (String, String) {
    let user = svc
        .create_user(Request::new(CreateUserRequest {
            external_id_blind_index: name.to_vec(),
            external_id_ciphertext: b"ciphertext".to_vec(),
            display_name_ciphertext: b"ciphertext".to_vec(),
            ..Default::default()
        }))
        .await
        .expect("create user")
        .into_inner();
    let user_id = user.meta.expect("meta").id;

    let cred = svc
        .create_credential(Request::new(CreateCredentialRequest {
            user_id: user_id.clone(),
            token_hash: token.to_vec(),
            label: "laptop".into(),
            ..Default::default()
        }))
        .await
        .expect("create credential")
        .into_inner();
    (user_id, cred.credential_id)
}

#[tokio::test]
async fn a_live_credential_resolves_to_its_user() {
    let svc = fresh("iam_db_test_live").await;
    let (user_id, cred_id) = seed(&svc, &[1u8; 32], &[9u8; 32]).await;

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![9u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert_eq!(got.user_id, user_id);
    assert_eq!(got.credential_id, cred_id);
}

#[tokio::test]
async fn an_unknown_token_is_an_empty_answer_and_not_an_error() {
    // The distinction this pins: a missing credential is a 401 at the edge, a
    // broken store is a 503. If this returned NOT_FOUND, a database outage and a
    // wrong password would be indistinguishable to the caller.
    let svc = fresh("iam_db_test_unknown").await;

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![7u8; 32],
        }))
        .await
        .expect("an unknown token must not be an error")
        .into_inner();

    assert!(got.user_id.is_empty());
}

#[tokio::test]
async fn a_revoked_credential_stops_resolving() {
    let svc = fresh("iam_db_test_revoked").await;
    let (_user, cred_id) = seed(&svc, &[2u8; 32], &[8u8; 32]).await;

    svc.revoke_credential(Request::new(RevokeCredentialRequest {
        credential_id: cred_id,
        ..Default::default()
    }))
    .await
    .expect("revoke");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![8u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert!(
        got.user_id.is_empty(),
        "a revoked credential must not authenticate anyone"
    );
}

#[tokio::test]
async fn revoke_returns_the_owner_so_the_cache_can_be_invalidated() {
    // Without this the caller needs a second read to know whose cache entry to
    // drop — and a revocation whose invalidation never fires is a credential
    // that keeps working until its TTL expires.
    let svc = fresh("iam_db_test_revoke_owner").await;
    let (user_id, cred_id) = seed(&svc, &[3u8; 32], &[7u8; 32]).await;

    let got = svc
        .revoke_credential(Request::new(RevokeCredentialRequest {
            credential_id: cred_id,
            ..Default::default()
        }))
        .await
        .expect("revoke")
        .into_inner();

    assert_eq!(got.user_id, user_id);
}

#[tokio::test]
async fn revoking_twice_is_accepted_and_keeps_the_first_timestamp() {
    // Idempotent (D9), and the timestamp must say when access actually ended
    // rather than when someone last asked.
    let svc = fresh("iam_db_test_revoke_twice").await;
    let (_user, cred_id) = seed(&svc, &[4u8; 32], &[6u8; 32]).await;

    for _ in 0..2 {
        svc.revoke_credential(Request::new(RevokeCredentialRequest {
            credential_id: cred_id.clone(),
            ..Default::default()
        }))
        .await
        .expect("revoking twice must not error");
    }
}

#[tokio::test]
async fn team_membership_comes_back_with_the_identity() {
    let svc = fresh("iam_db_test_teams").await;
    let (user_id, _cred) = seed(&svc, &[5u8; 32], &[5u8; 32]).await;

    // A team row has to exist for the foreign key to accept the membership.
    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind("yadgar:team:t1")
    .bind("platform")
    .execute(svc.pool())
    .await
    .expect("seed team");

    svc.add_team_member(Request::new(AddTeamMemberRequest {
        team_id: "yadgar:team:t1".into(),
        user_id: user_id.clone(),
        ..Default::default()
    }))
    .await
    .expect("add member");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![5u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert_eq!(got.team_ids, vec!["yadgar:team:t1".to_string()]);
}

#[tokio::test]
async fn adding_the_same_member_twice_is_a_no_op() {
    let svc = fresh("iam_db_test_member_twice").await;
    let (user_id, _cred) = seed(&svc, &[6u8; 32], &[4u8; 32]).await;

    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind("yadgar:team:t2")
    .bind("platform")
    .execute(svc.pool())
    .await
    .expect("seed team");

    for _ in 0..2 {
        svc.add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:t2".into(),
            user_id: user_id.clone(),
            ..Default::default()
        }))
        .await
        .expect("adding twice must not error");
    }

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![4u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert_eq!(got.team_ids.len(), 1, "membership must not duplicate");
}

#[tokio::test]
async fn removing_a_member_removes_the_team_from_the_identity() {
    let svc = fresh("iam_db_test_member_remove").await;
    let (user_id, _cred) = seed(&svc, &[10u8; 32], &[3u8; 32]).await;

    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind("yadgar:team:t3")
    .bind("platform")
    .execute(svc.pool())
    .await
    .expect("seed team");

    svc.add_team_member(Request::new(AddTeamMemberRequest {
        team_id: "yadgar:team:t3".into(),
        user_id: user_id.clone(),
        ..Default::default()
    }))
    .await
    .expect("add");

    svc.remove_team_member(Request::new(RemoveTeamMemberRequest {
        team_id: "yadgar:team:t3".into(),
        user_id: user_id.clone(),
        ..Default::default()
    }))
    .await
    .expect("remove");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![3u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert!(
        got.team_ids.is_empty(),
        "a removed member must lose the team's visibility"
    );
}

/// Seed one team row, which the foreign key requires and no RPC mints (D72).
async fn team(svc: &IamDb, id: &str) {
    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind(id)
    .bind("platform")
    .execute(svc.pool())
    .await
    .expect("seed team");
}

#[tokio::test]
async fn adding_a_member_to_a_team_that_does_not_exist_is_refused() {
    // MUTATION THIS CATCHES: `INSERT IGNORE`. IGNORE downgrades a FOREIGN KEY
    // violation to a WARNING, so an unknown team inserted nothing, raised
    // nothing, and this RPC answered OK. An operator was told the membership
    // landed; no read will ever return it, and no error was recorded anywhere.
    //
    // Every other team test seeds the team first, which is why thirteen of them
    // stayed green over a write that silently discarded its row.
    let svc = fresh("iam_db_test_member_unknown_team").await;
    let (user_id, _cred) = seed(&svc, &[57u8; 32], &[57u8; 32]).await;

    let err = svc
        .add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:never-existed".into(),
            user_id: user_id.clone(),
            ..Default::default()
        }))
        .await
        .expect_err("a membership in a team that does not exist must not report success");
    assert_eq!(err.code(), tonic::Code::NotFound);

    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_team_member WHERE user_id = ?",
            &user_id,
        )
        .await,
        0,
        "the refusal must not have written a row either"
    );
}

#[tokio::test]
async fn adding_a_member_who_does_not_exist_is_refused() {
    // The other half of the same swallowed constraint: `INSERT IGNORE` dropped
    // the user foreign key exactly as it dropped the team one.
    let svc = fresh("iam_db_test_member_unknown_user").await;
    team(&svc, "yadgar:team:t5").await;

    let err = svc
        .add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:t5".into(),
            user_id: "yadgar:user:never-existed".into(),
            ..Default::default()
        }))
        .await
        .expect_err("a membership for a person who does not exist must not report success");
    assert_eq!(err.code(), tonic::Code::NotFound);

    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_team_member WHERE team_id = ?",
            "yadgar:team:t5",
        )
        .await,
        0,
        "the refusal must not have written a row either"
    );
}

#[tokio::test]
async fn two_users_cannot_share_a_username() {
    // The UNIQUE on the blind index is the only thing preventing it, and a
    // duplicate would mean login resolving to whichever row the engine returned.
    let svc = fresh("iam_db_test_dupe").await;
    seed(&svc, &[11u8; 32], &[2u8; 32]).await;

    let err = svc
        .create_user(Request::new(CreateUserRequest {
            external_id_blind_index: vec![11u8; 32],
            external_id_ciphertext: b"other".to_vec(),
            display_name_ciphertext: b"other".to_vec(),
            ..Default::default()
        }))
        .await
        .expect_err("a duplicate username must be refused");

    assert_eq!(err.code(), tonic::Code::AlreadyExists);
}

#[tokio::test]
async fn a_password_hash_round_trips_and_is_found_by_blind_index() {
    let svc = fresh("iam_db_test_password").await;
    let (user_id, _cred) = seed(&svc, &[12u8; 32], &[1u8; 32]).await;

    svc.set_password(Request::new(SetPasswordRequest {
        user_id: user_id.clone(),
        argon2id_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        ..Default::default()
    }))
    .await
    .expect("set password");

    let got = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![12u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();

    assert_eq!(got.user_id, user_id);
    assert!(got.argon2id_hash.starts_with("$argon2id$"));
}

#[tokio::test]
async fn an_unknown_username_yields_an_empty_hash_rather_than_an_error() {
    // The caller must still do a dummy verification against this, or the
    // response time tells an attacker which usernames exist. The contract says
    // so; this pins the shape that makes it possible.
    let svc = fresh("iam_db_test_no_user").await;

    let got = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![99u8; 32],
            ..Default::default()
        }))
        .await
        .expect("an unknown user must not be an error")
        .into_inner();

    assert!(got.user_id.is_empty());
    assert!(got.argon2id_hash.is_empty());
}

#[tokio::test]
async fn an_expired_credential_stops_resolving() {
    // The bug this exists for was real: the contract carries epoch seconds and
    // the column is a TIMESTAMP, and binding the integer directly does not
    // error — MariaDB stores something else and the credential expires at a time
    // nobody chose. Nothing but a test that actually sets an expiry in the past
    // catches that.
    let svc = fresh("iam_db_test_expired").await;
    let user = svc
        .create_user(Request::new(CreateUserRequest {
            external_id_blind_index: vec![13u8; 32],
            external_id_ciphertext: b"c".to_vec(),
            display_name_ciphertext: b"c".to_vec(),
            ..Default::default()
        }))
        .await
        .expect("create user")
        .into_inner();

    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        - 3600;

    svc.create_credential(Request::new(CreateCredentialRequest {
        user_id: user.meta.expect("meta").id,
        token_hash: vec![14u8; 32],
        label: "already stale".into(),
        expires_at: Some(prost_types::Timestamp {
            seconds: past,
            nanos: 0,
        }),
        ..Default::default()
    }))
    .await
    .expect("create credential");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![14u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert!(
        got.user_id.is_empty(),
        "a credential whose expiry has passed must not authenticate anyone"
    );
}

#[tokio::test]
async fn a_credential_with_a_future_expiry_still_resolves() {
    // The other half: if FROM_UNIXTIME were wrong in the other direction, every
    // credential with an expiry would appear already expired and the previous
    // test would still pass.
    let svc = fresh("iam_db_test_future").await;
    let user = svc
        .create_user(Request::new(CreateUserRequest {
            external_id_blind_index: vec![15u8; 32],
            external_id_ciphertext: b"c".to_vec(),
            display_name_ciphertext: b"c".to_vec(),
            ..Default::default()
        }))
        .await
        .expect("create user")
        .into_inner();
    let user_id = user.meta.expect("meta").id;

    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        + 3600;

    svc.create_credential(Request::new(CreateCredentialRequest {
        user_id: user_id.clone(),
        token_hash: vec![16u8; 32],
        label: "valid for an hour".into(),
        expires_at: Some(prost_types::Timestamp {
            seconds: future,
            nanos: 0,
        }),
        ..Default::default()
    }))
    .await
    .expect("create credential");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![16u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert_eq!(got.user_id, user_id);
}

/// Soft-delete a user the way the module eventually will, since no RPC does yet.
///
/// Through `svc.pool()` for the same reason the team rows are seeded that way:
/// growing a `DeleteUser` endpoint that exists only so a test can reach a state
/// is worse than reaching the state directly.
async fn soft_delete(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft-delete the user");
}

#[tokio::test]
async fn a_soft_deleted_users_credential_stops_resolving() {
    // MUTATION THIS CATCHES: deleting `AND u.deleted_at IS NULL` from
    // ResolveCredential's query. Every other test in this file stays green,
    // because none of them has ever deleted a user — while every person removed
    // from the system keeps authenticating with the credentials nobody thought
    // to revoke, indefinitely and silently.
    //
    // The JOIN is what makes this reachable at all: a credential row carries no
    // deleted_at of its own, so liveness of the PERSON is a property only the
    // join can see.
    let svc = fresh("iam_db_test_deleted_resolve").await;
    let (user_id, _cred) = seed(&svc, &[20u8; 32], &[20u8; 32]).await;

    // Live first, so a query that never resolved anything cannot pass this.
    let before = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![20u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert_eq!(before.user_id, user_id);

    soft_delete(&svc, &user_id).await;

    let after = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![20u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert!(
        after.user_id.is_empty(),
        "a soft-deleted person must stop authenticating even with an un-revoked credential"
    );
}

#[tokio::test]
async fn a_soft_deleted_user_returns_no_password_hash() {
    // A SEPARATE clause in a SEPARATE query from the one above, and worse in its
    // consequence: resolving is what an existing credential does, but a password
    // hash is what lets a deleted person LOG IN AGAIN and mint a fresh
    // credential — one that no revocation sweep would know to look for.
    //
    // MUTATION THIS CATCHES: deleting `AND u.deleted_at IS NULL` from
    // GetPasswordHash's query.
    let svc = fresh("iam_db_test_deleted_password").await;
    let (user_id, _cred) = seed(&svc, &[21u8; 32], &[21u8; 32]).await;

    svc.set_password(Request::new(SetPasswordRequest {
        user_id: user_id.clone(),
        argon2id_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        ..Default::default()
    }))
    .await
    .expect("set password");

    let before = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![21u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();
    assert_eq!(before.user_id, user_id);

    soft_delete(&svc, &user_id).await;

    let after = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![21u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();
    assert!(
        after.user_id.is_empty() && after.argon2id_hash.is_empty(),
        "a soft-deleted person must not be able to log in again"
    );
}

#[tokio::test]
async fn changing_a_password_stops_the_old_hash_working() {
    // Only the INSERT half of the upsert was covered. MUTATION THIS CATCHES:
    // making `ON DUPLICATE KEY UPDATE` a no-op — writing
    // `argon2id_hash = argon2id_hash`, or dropping the clause for an INSERT
    // IGNORE. Setting a password then returns OK, the caller is told the change
    // took, and the OLD password keeps working forever. Nothing in a
    // set-then-read test can see it, because the first write is an insert.
    let svc = fresh("iam_db_test_password_change").await;
    let (user_id, _cred) = seed(&svc, &[22u8; 32], &[22u8; 32]).await;

    const OLD: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$b2xkaGFzaA";
    const NEW: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$bmV3aGFzaA";

    for hash in [OLD, NEW] {
        svc.set_password(Request::new(SetPasswordRequest {
            user_id: user_id.clone(),
            argon2id_hash: hash.into(),
            ..Default::default()
        }))
        .await
        .expect("setting a password twice must be accepted");
    }

    let got = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![22u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();

    assert_eq!(got.argon2id_hash, NEW, "the new password must take effect");
    assert_ne!(got.argon2id_hash, OLD, "the old password must stop working");
}

#[tokio::test]
async fn a_resolve_returns_only_that_users_teams() {
    // Every other team test uses ONE user, so `WHERE user_id = ?` can be deleted
    // from the membership query with all thirteen staying green — while every
    // user receives every team in the system, and D12's team visibility becomes
    // no boundary at all.
    //
    // MUTATION THIS CATCHES: dropping that WHERE clause.
    let svc = fresh("iam_db_test_team_isolation").await;
    let (mine, _c) = seed(&svc, &[23u8; 32], &[23u8; 32]).await;
    let (theirs, _c) = seed(&svc, &[24u8; 32], &[24u8; 32]).await;

    for (id, name) in [
        ("yadgar:team:mine", "mine"),
        ("yadgar:team:theirs", "theirs"),
    ] {
        sqlx::query(
            "INSERT INTO iam_team (id, name, created_by, updated_by) \
             VALUES (?, ?, 'system', 'system')",
        )
        .bind(id)
        .bind(name)
        .execute(svc.pool())
        .await
        .expect("seed team");
    }

    for (team, user) in [("yadgar:team:mine", &mine), ("yadgar:team:theirs", &theirs)] {
        svc.add_team_member(Request::new(AddTeamMemberRequest {
            team_id: team.into(),
            user_id: user.clone(),
            ..Default::default()
        }))
        .await
        .expect("add member");
    }

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![23u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert_eq!(
        got.team_ids,
        vec!["yadgar:team:mine".to_string()],
        "a resolve must never hand back another user's teams"
    );
}

#[tokio::test]
async fn revoking_an_unknown_credential_is_not_found() {
    // The error path nothing exercised. It matters because the SUCCESS path is
    // what publishes the cache invalidation, keyed on the user_id this call
    // returns — so "no such credential" must be an error rather than an OK
    // carrying an empty owner, which would publish an invalidation addressed to
    // nobody and look like it worked.
    //
    // MUTATION THIS CATCHES: replacing the `ok_or_else` with
    // `unwrap_or_default()`.
    let svc = fresh("iam_db_test_revoke_unknown").await;

    let err = svc
        .revoke_credential(Request::new(RevokeCredentialRequest {
            credential_id: "yadgar:credential:never-existed".into(),
            ..Default::default()
        }))
        .await
        .expect_err("revoking something that does not exist must not report success");

    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ---------------------------------------------------------------------------
// Enrolment (contract v1.6.0).
//
// What these assert is the same narrow thing the credential tests do: the ways a
// redemption must FAIL. Redeeming a live enrolment is the easy case and passes
// on an implementation that spends the secret and sets the password as two
// separate statements — which is the one shape D73 says must never ship, because
// a crash between them leaves a spent secret and an account with no password, on
// the one path with no resend.
// ---------------------------------------------------------------------------

/// A PHC string longer than `iam_password.argon2id_hash` can hold.
///
/// Both writers of that column refuse it up front as INVALID_ARGUMENT, so it
/// never reaches the engine — which is why it is NOT the lever the transaction
/// test pulls. See `narrow_password_column`.
fn oversized_hash() -> String {
    format!("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA${}", "A".repeat(300))
}

/// Retype `iam_password.argon2id_hash`, so the password half of a redemption
/// fails AT THE ENGINE.
///
/// The lever the transaction test pulls, and it has to be one that leaves the
/// REQUEST ordinary: an over-length hash is now refused before anything is
/// spent, so it can no longer reach the point where the two halves could come
/// apart. Narrowing the column instead makes a perfectly valid request fail in
/// the second statement, which is exactly the shape of a real storage failure.
///
/// FAIL-SAFE BY CONSTRUCTION, and worth stating because a test that silently
/// stops testing is worse than no test. If `STRICT_TRANS_TABLES` were not in
/// force the insert would TRUNCATE rather than error, the call would succeed,
/// and the `expect_err` in the test would panic. The test cannot quietly pass
/// for the wrong reason.
async fn narrow_password_column(svc: &IamDb, column_type: &str) {
    // AUDIT: `column_type` is a literal at both call sites in this file.
    let sql = format!("ALTER TABLE iam_password MODIFY argon2id_hash {column_type} NOT NULL");
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(svc.pool())
        .await
        .expect("retype the password column");
}

const GOOD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

/// Seconds from now, as the contract's epoch timestamp.
fn at(offset: i64) -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    prost_types::Timestamp {
        seconds: now + offset,
        nanos: 0,
    }
}

/// A user carrying a recognisable encrypted username, and no credential.
async fn enrolee(svc: &IamDb, blind: u8, ciphertext: &[u8]) -> String {
    svc.create_user(Request::new(CreateUserRequest {
        external_id_blind_index: vec![blind; 32],
        external_id_ciphertext: ciphertext.to_vec(),
        display_name_ciphertext: b"display".to_vec(),
        ..Default::default()
    }))
    .await
    .expect("create user")
    .into_inner()
    .meta
    .expect("meta")
    .id
}

async fn enrol(svc: &IamDb, user_id: &str, secret: u8, expires_in: i64) -> String {
    svc.create_enrolment(Request::new(CreateEnrolmentRequest {
        user_id: user_id.into(),
        secret_hash: vec![secret; 32],
        expires_at: Some(at(expires_in)),
        ..Default::default()
    }))
    .await
    .expect("create enrolment")
    .into_inner()
    .enrolment_id
}

async fn redeem(svc: &IamDb, secret: u8, hash: &str, key: &str) -> RedeemEnrolmentResponse {
    svc.redeem_enrolment(Request::new(RedeemEnrolmentRequest {
        secret_hash: vec![secret; 32],
        argon2id_hash: hash.into(),
        idempotency: match key.is_empty() {
            true => None,
            false => Some(yadgar_iam_db::pb::yadgar::common::v1::Idempotency { key: key.into() }),
        },
    }))
    .await
    .expect("redeem must not error")
    .into_inner()
}

async fn count(svc: &IamDb, sql: &'static str, bind: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(svc.pool())
        .await
        .expect("count")
}

#[tokio::test]
async fn a_live_enrolment_is_redeemed_and_hands_back_the_username() {
    // The username is the whole reason this response carries ciphertext. A
    // person enrolling on their first machine has no in-band way to learn it,
    // `iam` holds no store to have remembered it in (D4), and nothing else on
    // this boundary returns it — GetPasswordHash answers a blind index with a
    // hash, and the blind index is one-way by construction.
    let svc = fresh("iam_db_test_enrol_redeem").await;
    let user_id = enrolee(&svc, 30, b"encrypted-ada").await;
    let enrolment_id = enrol(&svc, &user_id, 30, 3600).await;

    let got = redeem(&svc, 30, GOOD_HASH, "").await;

    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(got.user_id, user_id);
    assert_eq!(got.enrolment_id, enrolment_id);
    assert_eq!(
        got.external_id_ciphertext,
        b"encrypted-ada".to_vec(),
        "the response must carry the encrypted username, or a retry cannot recover it"
    );

    let hash = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![30u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();
    assert_eq!(
        hash.argon2id_hash, GOOD_HASH,
        "redemption must have set the password, not merely spent the secret"
    );
}

#[tokio::test]
async fn a_redemption_that_fails_partway_spends_nothing_and_sets_no_password() {
    // THE TEST THIS RPC EXISTS FOR. Spending the secret and setting the password
    // are ONE transaction (D5), and the only way to see that is to make the
    // second half fail after the first has already run.
    //
    // MUTATION THIS CATCHES: running the two statements against `&self.pool`
    // rather than against one transaction. Every other test in this file stays
    // green, because none of them makes the password write fail — while in
    // production a crash between the two leaves a spent secret and no password,
    // D73 gives no resend, and the person is locked out of an account whose
    // password was never set.
    let svc = fresh("iam_db_test_enrol_atomic").await;
    let user_id = enrolee(&svc, 31, b"encrypted-bob").await;
    enrol(&svc, &user_id, 31, 3600).await;

    // The request below is ORDINARY — a valid hash, a live enrolment, nothing a
    // caller-side guard could reject. Only the column it lands in has been made
    // too small, so the failure happens in the second statement, after the spend
    // in the first.
    narrow_password_column(&svc, "VARCHAR(8)").await;

    let err = svc
        .redeem_enrolment(Request::new(RedeemEnrolmentRequest {
            secret_hash: vec![31u8; 32],
            argon2id_hash: GOOD_HASH.into(),
            ..Default::default()
        }))
        .await
        .expect_err("a password write the engine refuses must fail the call");
    assert_eq!(err.code(), tonic::Code::Unavailable);

    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_enrolment WHERE user_id = ? AND spent_at IS NOT NULL",
            &user_id,
        )
        .await,
        0,
        "a failed redemption must not leave the secret spent"
    );
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_password WHERE user_id = ?",
            &user_id,
        )
        .await,
        0,
        "a failed redemption must not leave a password behind either"
    );

    // The consequence, as an assertion rather than as a comment: the person is
    // NOT locked out, because the secret they hold still works.
    narrow_password_column(&svc, "VARCHAR(255)").await;
    let got = redeem(&svc, 31, GOOD_HASH, "").await;
    assert_eq!(
        got.outcome,
        RedeemOutcome::Redeemed as i32,
        "the enrolment must survive a failed attempt intact and still be redeemable"
    );
}

#[tokio::test]
async fn one_secret_is_redeemed_once() {
    let svc = fresh("iam_db_test_enrol_once").await;
    let user_id = enrolee(&svc, 32, b"c").await;
    enrol(&svc, &user_id, 32, 3600).await;

    assert_eq!(
        redeem(&svc, 32, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32
    );
    assert_eq!(
        redeem(&svc, 32, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Spent as i32,
        "a second presentation of one single-use secret must report SPENT"
    );
}

#[tokio::test]
async fn a_spent_enrolment_blocks_no_fresh_one() {
    // THE DOCUMENTED RECOVERY PATH. A client that dies after the transaction
    // commits but before it durably holds a credential is locked out, and the
    // way back in is an admin minting a FRESH enrolment for the same person.
    //
    // MUTATION THIS CATCHES: any uniqueness touching iam_enrolment.user_id — a
    // `UNIQUE KEY (user_id)`, or an index meant to enforce "one live enrolment
    // per user". Either makes this second CreateEnrolment fail with a duplicate
    // key, and that failure is indistinguishable from the store being broken.
    let svc = fresh("iam_db_test_enrol_fresh").await;
    let user_id = enrolee(&svc, 33, b"c").await;
    enrol(&svc, &user_id, 33, 3600).await;
    redeem(&svc, 33, GOOD_HASH, "").await;

    let second = enrol(&svc, &user_id, 34, 3600).await;
    assert!(!second.is_empty());

    let got = redeem(&svc, 34, GOOD_HASH, "").await;
    assert_eq!(
        got.outcome,
        RedeemOutcome::Redeemed as i32,
        "a spent enrolment is not live and must block no new one"
    );
    assert_eq!(got.user_id, user_id);
}

#[tokio::test]
async fn an_expired_enrolment_is_not_redeemable() {
    // The same FROM_UNIXTIME bug the credential tests pin, on a second column.
    // The contract sends epoch SECONDS and the column is a TIMESTAMP; binding
    // the integer does not error — MariaDB stores something else, and the
    // enrolment expires at a time nobody chose.
    let svc = fresh("iam_db_test_enrol_expired").await;
    let user_id = enrolee(&svc, 35, b"c").await;
    enrol(&svc, &user_id, 35, -3600).await;

    assert_eq!(
        redeem(&svc, 35, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Expired as i32,
        "an enrolment whose deadline has passed must not set a password"
    );
}

#[tokio::test]
async fn an_enrolment_with_a_future_expiry_still_redeems() {
    // The other direction: if FROM_UNIXTIME were wrong the other way, every
    // enrolment would read as already expired, the test above would still pass,
    // and nobody could ever enrol.
    let svc = fresh("iam_db_test_enrol_future").await;
    let user_id = enrolee(&svc, 36, b"c").await;
    enrol(&svc, &user_id, 36, 3600).await;

    assert_eq!(
        redeem(&svc, 36, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32
    );
}

#[tokio::test]
async fn an_unknown_secret_is_not_found_rather_than_an_error() {
    // The same distinction ResolveCredential draws: "no such enrolment" and "the
    // store is broken" are different outcomes, and `iam` collapses only the
    // first three into one UNAUTHENTICATED.
    let svc = fresh("iam_db_test_enrol_unknown").await;

    assert_eq!(
        redeem(&svc, 37, GOOD_HASH, "").await.outcome,
        RedeemOutcome::NotFound as i32
    );
}

#[test]
fn a_non_empty_idempotency_key_on_create_enrolment_trips_the_sensor() {
    // LEDGER 638/668's INTERIM SENSOR (`plans/create-enrolment-idempotency.md`
    // §4.2), executed. `create_enrolment` DISCARDS `r.idempotency` — see the
    // handler's own comment — and today nothing sends a key, so a counter
    // proved only by that silence proves nothing. This test sends one.
    //
    // A SYNC TEST BUILDING ITS OWN current_thread RUNTIME, the same shape
    // `gateway`'s `the_cache_counter_reports_a_miss_and_then_a_hit` uses: a
    // LOCAL recorder rather than `metrics::install()`, because a global one is
    // process-wide and this binary's tests run in parallel, which would race
    // every other test that emits a metric.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let svc = fresh("iam_db_test_enrol_idempotency_sensor").await;
            let user_id = enrolee(&svc, 60, b"c").await;

            svc.create_enrolment(Request::new(CreateEnrolmentRequest {
                user_id: user_id.clone(),
                secret_hash: vec![60u8; 32],
                expires_at: Some(at(3600)),
                idempotency: Some(Idempotency {
                    key: "k-enrol-sensor".into(),
                }),
                ..Default::default()
            }))
            .await
            .expect(
                "create enrolment must still succeed — the sensor observes, it does not refuse",
            );
        });
    });

    let emitted = snapshotter.snapshot().into_vec();
    let fired = emitted.iter().any(|(key, _, _, value)| {
        key.key().name() == yadgar_iam_db::service::ENROLMENT_IDEMPOTENCY_DISCARDED
            && matches!(
                value,
                metrics_util::debugging::DebugValue::Counter(n) if *n >= 1
            )
    });
    assert!(
        fired,
        "a non-empty idempotency key on CreateEnrolment must trip the sensor \
         — a counter proved only by production silence is not proved"
    );
}

#[test]
fn an_empty_idempotency_key_on_create_enrolment_does_not_trip_the_sensor() {
    // THE OTHER DIRECTION, so a counter that increments unconditionally cannot
    // pass the test above. TWO cases, not one: an ABSENT `idempotency` (every
    // caller of this RPC today — §7.0: nothing sends a key until `/admin`
    // lands) and a PRESENT-BUT-EMPTY key. The second is the boundary §7.0 is
    // most emphatic about — "sending an EMPTY idempotency key would suppress
    // the sensor and look like prudence" — and it is a DIFFERENT code path
    // through the handler's `is_some_and(|k| !k.key.is_empty())` guard than
    // the absent case is. Proved distinct by a mutation: `if
    // r.idempotency.is_some()` (firing on an empty-string key too) left a
    // version of this test that checked only the absent case GREEN.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let svc = fresh("iam_db_test_enrol_idempotency_sensor_quiet").await;

            // ABSENT.
            let user_id = enrolee(&svc, 61, b"c").await;
            enrol(&svc, &user_id, 61, 3600).await;

            // PRESENT AND EMPTY.
            let user_id = enrolee(&svc, 62, b"c").await;
            svc.create_enrolment(Request::new(CreateEnrolmentRequest {
                user_id,
                secret_hash: vec![62u8; 32],
                expires_at: Some(at(3600)),
                idempotency: Some(Idempotency { key: String::new() }),
                ..Default::default()
            }))
            .await
            .expect("create enrolment must still succeed on an empty key");
        });
    });

    let emitted = snapshotter.snapshot().into_vec();
    let fired = emitted.iter().any(|(key, _, _, _)| {
        key.key().name() == yadgar_iam_db::service::ENROLMENT_IDEMPOTENCY_DISCARDED
    });
    assert!(
        !fired,
        "an empty (or absent) idempotency key must not trip the sensor — a \
         one-directional counter that fires unconditionally proves nothing"
    );
}

#[test]
fn the_enrolment_idempotency_discarded_counter_is_named_the_thing_an_operator_queries() {
    // AS A LITERAL, never through the constant — ADR-0599, and the precedent
    // `gateway` sets for its own bespoke counters
    // (`attest.rs::the_cache_counter_is_named_the_thing_an_operator_queries`,
    // `limit.rs`'s equivalent for `DEGRADED`). Routing this assertion through
    // `ENROLMENT_IDEMPOTENCY_DISCARDED` would make a later edit to the
    // constant's VALUE pass every test while silently orphaning anything a
    // dashboard or alert already built on the old name.
    assert_eq!(
        yadgar_iam_db::service::ENROLMENT_IDEMPOTENCY_DISCARDED,
        "yadgar_iamdb_enrolment_idempotency_discarded_total"
    );
}

// ---------------------------------------------------------------------------
// THE BOOTSTRAP ENROLMENT PREDICATE (ADR-0655, amended by ADR-0656; refusal
// taxonomy ADR-0657).
//
// **WHAT MAKES THIS BLOCK DISCRIMINATING, AND WHY A HAPPY-PATH TEST WOULD NOT
// BE.** A suite that only enrols a fresh zero-credential administrator passes
// identically on ADR-0655's narrow grant and on a store with NO predicate at
// all. The discrimination is carried by the FIXTURES and by the conjunct label,
// and never by the message: ADR-0657 gives both conjuncts ONE code and ONE
// sentence deliberately, so no assertion on the response can tell them apart.
//
// Each test below is red on exactly one deletion from `demand::INSERT`:
//
//   - drop `p.user_id IS NULL`  → the password-holder test reds;
//   - drop the `iam_credential` join, or add `AND c.revoked_at IS NULL` to it
//     → the REVOKED-credential test reds, and only that one. On a fresh account
//     the rows-of-any-liveness reading and the live-rows widening agree, so
//     that test is the single place in this suite where they diverge. ADR-0656
//     demands it by name;
//   - drop `u.is_admin = 1`     → the non-administrator test reds;
//   - label every refusal the same → the two label assertions red, which is the
//     false green ADR-0657's consequences name.
// ---------------------------------------------------------------------------

/// An ADMINISTRATOR with no password and no credential of any liveness.
///
/// `is_admin` at creation rather than by a follow-up `SetUserAdmin`, which is
/// D73's own shape: the first administrator has to exist before anyone can log
/// in to promote one.
async fn admin(svc: &IamDb, blind: u8) -> String {
    svc.create_user(Request::new(CreateUserRequest {
        external_id_blind_index: vec![blind; 32],
        external_id_ciphertext: b"encrypted-admin".to_vec(),
        display_name_ciphertext: b"display".to_vec(),
        is_admin: true,
        ..Default::default()
    }))
    .await
    .expect("create an administrator")
    .into_inner()
    .meta
    .expect("meta")
    .id
}

/// `CreateEnrolment` CARRYING THE DEMAND — the only caller shape that reaches
/// the predicate. Every other test in this file leaves the field at proto3's
/// default and takes the ordinary path.
async fn demand(
    svc: &IamDb,
    user_id: &str,
    secret: u8,
) -> Result<CreateEnrolmentResponse, tonic::Status> {
    svc.create_enrolment(Request::new(CreateEnrolmentRequest {
        user_id: user_id.into(),
        secret_hash: vec![secret; 32],
        expires_at: Some(at(3600)),
        require_zero_credential_admin: true,
        ..Default::default()
    }))
    .await
    .map(tonic::Response::into_inner)
}

/// A local metrics recorder around a current-thread runtime, and the
/// `conjunct` labels the refusal counter recorded inside it.
///
/// LOCAL rather than `metrics::install()`, for the reason the idempotency sensor
/// test already gives: a global recorder is process-wide and this binary's tests
/// run in parallel, so installing one would race every other test that emits a
/// metric.
fn under_recorder<T>(body: impl FnOnce(&tokio::runtime::Runtime) -> T) -> (T, Vec<String>) {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let out = metrics::with_local_recorder(&recorder, || body(&rt));

    // THE LABEL, NOT MERELY THE NAME. A build that emitted this counter with no
    // `conjunct` label at all, or with one constant value for both conjuncts,
    // would satisfy every assertion on the metric's NAME — and that build is
    // exactly the one ADR-0657's consequences say a test must refuse, because
    // the label is the operator's only signal for which half of the predicate
    // refused.
    let emitted = snapshotter.snapshot().into_vec();
    let mut labels = Vec::new();
    for (key, _, _, value) in &emitted {
        let counted = key.key().name() == yadgar_iam_db::service::ENROLMENT_DEMAND_REFUSED
            && matches!(
                value,
                metrics_util::debugging::DebugValue::Counter(n) if *n >= 1
            );
        if counted {
            labels.extend(
                key.key()
                    .labels()
                    .filter(|l| l.key() == "conjunct")
                    .map(|l| l.value().to_string()),
            );
        }
    }
    (out, labels)
}

/// The ONE sentence, as a literal. ADR-0657 gives both conjuncts the same body,
/// so this is asserted on every refusal below and discriminates none of them —
/// which is the point of asserting it.
const DEMAND_REFUSAL: &str =
    "the bootstrap token may only enrol an administrator who has never held a credential";

fn assert_refused(err: &tonic::Status, rows_before: i64, rows_after: i64) {
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "the demand is refused with PERMISSION_DENIED (ADR-0655)"
    );
    assert_eq!(
        err.message(),
        DEMAND_REFUSAL,
        "ONE body for both conjuncts (ADR-0657) — a per-conjunct message is an \
         administrator-set enumeration oracle"
    );
    // AND IT WROTE NOTHING. A refusal that inserted the enrolment anyway would
    // pass a status assertion and still have handed out the grant.
    assert_eq!(
        rows_after, rows_before,
        "a refused demand must leave no new iam_enrolment row"
    );
}

const ENROLMENTS_OF: &str = "SELECT COUNT(*) FROM iam_enrolment WHERE user_id = ?";

#[tokio::test]
async fn a_zero_credential_administrator_is_enrolled_on_the_demand() {
    // THE POSITIVE HALF, and on its own it proves nothing about the predicate —
    // it passes identically on a store with no predicate at all. It is here
    // because without it the refusals below could all be satisfied by a store
    // that refuses everything, and because ADR-0655 exists to make exactly this
    // call succeed: it is the one that mints the first administrator's
    // enrolment.
    let svc = fresh("iam_db_test_demand_admin").await;
    let user_id = admin(&svc, 120).await;

    let minted = demand(&svc, &user_id, 120)
        .await
        .expect("a zero-credential administrator is what this grant is for");
    assert!(!minted.enrolment_id.is_empty());

    // AND IT REDEEMS. An enrolment the store reports and the person cannot spend
    // is the failure `CreateEnrolment`'s liveness predicate already exists to
    // prevent, and the demand arm is a second statement that could reintroduce
    // it.
    let got = redeem(&svc, 120, GOOD_HASH, "").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(got.user_id, user_id);
}

#[test]
fn an_administrator_who_already_holds_a_password_is_refused_the_demand() {
    // MUTATION THIS CATCHES: deleting `p.user_id IS NULL` from
    // `demand::INSERT`. `iam_password` is half of ADR-0656's definition and is
    // named separately from the credential table for a reason this fixture
    // reproduces: a redemption's write IS the password upsert, so a predicate
    // reading only `iam_credential` would not close the race ADR-0655 gives as
    // its own justification — and re-enrolling a person who has chosen a
    // password OVERWRITES it, which is takeover of an enrolled administrator
    // rather than the creation of a new one.
    let ((err, before, after), labels) = under_recorder(|rt| {
        rt.block_on(async {
            let svc = fresh("iam_db_test_demand_password").await;
            let user_id = admin(&svc, 121).await;
            enrol(&svc, &user_id, 121, 3600).await;
            redeem(&svc, 121, GOOD_HASH, "").await;

            let before = count(&svc, ENROLMENTS_OF, &user_id).await;
            let err = demand(&svc, &user_id, 122)
                .await
                .expect_err("an administrator holding a password has held a credential");
            let after = count(&svc, ENROLMENTS_OF, &user_id).await;
            (err, before, after)
        })
    });

    assert_refused(&err, before, after);
    assert_eq!(
        labels,
        vec!["held_credential".to_string()],
        "the conjunct reaches the operator through the label and nowhere else"
    );
}

#[test]
fn a_revoked_credential_still_refuses_the_bootstrap_demand() {
    // **THE ROW ADR-0656 DEMANDS BY NAME, AND THE ONLY TEST IN THIS FILE THAT
    // SEPARATES THIS BUILD FROM THE WIDENED ONE.** On a fresh account "no
    // credential row" and "no LIVE credential row" agree, so every other test
    // here passes under both readings. This one does not.
    //
    // MUTATION THIS CATCHES: adding `AND c.revoked_at IS NULL` to the credential
    // join — the tidy-up every other liveness predicate on this boundary invites,
    // and the reason ADR-0656 had to rule it a defect explicitly. Under that
    // reading an established administrator who revoked their own credential
    // presents as holding zero, the bootstrap token mints them an enrolment, and
    // redeeming it sets a password on an established account: account takeover
    // with an unattributable credential.
    //
    // `RevokeCredential` tombstones rather than deletes (D26), which is what
    // makes counting rows a PROPERTY of the predicate rather than a fact about
    // the estate — once a user has ever held a credential the row is there
    // forever, and no commit in another repository can take it away.
    let ((err, before, after), labels) = under_recorder(|rt| {
        rt.block_on(async {
            let svc = fresh("iam_db_test_demand_revoked").await;
            let user_id = admin(&svc, 123).await;
            let cred = svc
                .create_credential(Request::new(CreateCredentialRequest {
                    user_id: user_id.clone(),
                    token_hash: vec![123u8; 32],
                    label: "the laptop they no longer have".into(),
                    ..Default::default()
                }))
                .await
                .expect("create credential")
                .into_inner()
                .credential_id;
            svc.revoke_credential(Request::new(RevokeCredentialRequest {
                credential_id: cred,
                ..Default::default()
            }))
            .await
            .expect("revoke");

            // AND NO PASSWORD ROW, deliberately: this fixture isolates the
            // credential conjunct, so the refusal cannot be the password half
            // passing for it.
            assert_eq!(
                count(
                    &svc,
                    "SELECT COUNT(*) FROM iam_password WHERE user_id = ?",
                    &user_id
                )
                .await,
                0,
                "this fixture must hold a revoked credential and nothing else"
            );

            let before = count(&svc, ENROLMENTS_OF, &user_id).await;
            let err = demand(&svc, &user_id, 124)
                .await
                .expect_err("a revoked credential is a credential the person once held");
            let after = count(&svc, ENROLMENTS_OF, &user_id).await;
            (err, before, after)
        })
    });

    assert_refused(&err, before, after);
    assert_eq!(labels, vec!["held_credential".to_string()]);
}

#[test]
fn a_zero_credential_non_administrator_is_refused_the_demand() {
    // MUTATION THIS CATCHES: deleting `u.is_admin = 1`. Without it the bootstrap
    // token enrols any account nobody has logged into yet, which is the
    // unrestricted grant ADR-0492 refused and ADR-0655 narrowed rather than
    // opened.
    //
    // AND IT IS THE SECOND LABEL. Two conjuncts, two tests, two label values —
    // so a build that emitted one constant label, or no label, cannot pass both.
    let ((err, before, after), labels) = under_recorder(|rt| {
        rt.block_on(async {
            let svc = fresh("iam_db_test_demand_not_admin").await;
            let user_id = enrolee(&svc, 125, b"encrypted-ordinary").await;

            let before = count(&svc, ENROLMENTS_OF, &user_id).await;
            let err = demand(&svc, &user_id, 125)
                .await
                .expect_err("the demand admits administrators only");
            let after = count(&svc, ENROLMENTS_OF, &user_id).await;
            (err, before, after)
        })
    });

    assert_refused(&err, before, after);
    assert_eq!(labels, vec!["not_admin".to_string()]);
}

#[tokio::test]
async fn the_absent_demand_still_enrols_an_administrator_who_holds_a_password() {
    // THE INVERSE OF THE PASSWORD TEST, BESIDE IT SO THE PAIR CANNOT DRIFT
    // APART. Re-enrolment IS the documented recovery for a forgotten password
    // (`iam.proto`: a fresh enrolment for an existing user, redeemed, sets the
    // password unconditionally), and `a_spent_enrolment_blocks_no_fresh_one`
    // already guards it for an ordinary person. This guards it for an
    // ADMINISTRATOR, which is the account the predicate above refuses — so it is
    // the test that reds if the predicate ever leaks onto the absent-field arm.
    let svc = fresh("iam_db_test_demand_absent").await;
    let user_id = admin(&svc, 126).await;
    enrol(&svc, &user_id, 126, 3600).await;
    redeem(&svc, 126, GOOD_HASH, "").await;

    let second = enrol(&svc, &user_id, 127, 3600).await;
    assert!(
        !second.is_empty(),
        "the ordinary path is byte-identical to what it was before the demand \
         field existed — proto3 defaults the field to false for every caller \
         that predates it"
    );
    let got = redeem(&svc, 127, GOOD_HASH, "").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
}

#[test]
fn the_enrolment_demand_refused_counter_is_named_the_thing_an_operator_queries() {
    // AS A LITERAL, never through the constant — ADR-0599, the same argument the
    // idempotency sensor's name test above carries. This counter is load-bearing
    // in a way that one is not: ADR-0657 keeps the conjunct out of the response
    // entirely, so this series and the warn beside it are the operator's ONLY
    // path to which half of the predicate refused.
    assert_eq!(
        yadgar_iam_db::service::ENROLMENT_DEMAND_REFUSED,
        "yadgar_iamdb_enrolment_demand_refused_total"
    );
}

#[tokio::test]
async fn the_servers_default_isolation_is_repeatable_read() {
    // THE ASSUMPTION THE PROBE BELOW RESTS ON, PINNED RATHER THAN ASSUMED.
    // `mint_enrolment` runs autocommit on the pool and pins no isolation level,
    // so `demand::INSERT`'s locking read takes a next-key lock only because the
    // server's default is REPEATABLE READ. `deploy/infra/databases/iam-db.yaml`
    // runs `mariadb:11.8.8` with no configuration of its own and nothing in this
    // crate issues `SET SESSION`, so the engine default is what the deployment
    // gets. If a future server default changes, this reds and names the reason
    // rather than leaving the next test failing mysteriously.
    let svc = fresh("iam_db_test_demand_isolation").await;
    let level: String = sqlx::query_scalar("SELECT @@transaction_isolation")
        .fetch_one(svc.pool())
        .await
        .expect("read the isolation level");
    assert_eq!(
        level, "REPEATABLE-READ",
        "the demand statement's gap lock is what serialises it against a \
         concurrent redemption, and READ COMMITTED takes none"
    );
}

/// Insert the password row a redemption would write, on its own connection,
/// with a short lock wait so a block fails fast rather than sitting on
/// `innodb_lock_wait_timeout`'s 50 seconds.
async fn contend_for_the_password(
    pool: &sqlx::MySqlPool,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await.expect("a second connection");
    sqlx::query("SET SESSION innodb_lock_wait_timeout = 2")
        .execute(&mut *conn)
        .await
        .expect("shorten the wait");
    sqlx::query("INSERT INTO iam_password (user_id, argon2id_hash) VALUES (?, ?)")
        .bind(user_id)
        .bind(GOOD_HASH)
        .execute(&mut *conn)
        .await
        .map(|_| ())
}

/// One arm of the lock probe, start to finish: run `demand::INSERT` ITSELF in a
/// held transaction, contend for the password row while it is open, commit, and
/// contend again. Answers `(blocked while open, landed after the commit)`.
///
/// `read_committed` pins the level for this transaction only, the way ADR-0513
/// requires it to be pinned — `pool.acquire()` then `Acquire::begin`, never
/// `pool.begin()`, because `SET TRANSACTION` without SESSION applies to the next
/// transaction and then reverts, leaving a pooled connection clean for its next
/// borrower.
async fn probe_the_lock(
    pool: &sqlx::MySqlPool,
    user_id: &str,
    id: &str,
    secret: u8,
    read_committed: bool,
) -> (bool, bool) {
    let mut conn = pool.acquire().await.expect("the demand's connection");
    if read_committed {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *conn)
            .await
            .expect("pin READ COMMITTED for the next transaction only");
    }
    let mut tx = sqlx::Acquire::begin(&mut *conn).await.expect("begin");
    let done = sqlx::query(yadgar_iam_db::service::DEMAND_INSERT)
        .bind(id)
        .bind(vec![secret; 32])
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs() as i64
                + 3600,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .expect("the demand statement must run");
    assert_eq!(
        done.rows_affected(),
        1,
        "the probe's fixture is a zero-credential administrator, so the \
         statement must insert — a zero here would leave the lock untested"
    );

    let blocked = contend_for_the_password(pool, user_id).await.is_err();
    tx.commit().await.expect("commit the demand");
    // THE POSITIVE CONTROL. Only meaningful when the first attempt was blocked,
    // and asserted by the caller for that arm.
    let landed = match blocked {
        true => contend_for_the_password(pool, user_id).await.is_ok(),
        false => true,
    };
    (blocked, landed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_demand_statement_blocks_a_concurrent_password_insert() {
    // **THE LOAD-BEARING MEASUREMENT OF THIS WHOLE CHANGE, AND IT RUNS THE
    // HANDLER'S OWN SQL** (`service::DEMAND_INSERT`) rather than a copy. ADR-0655
    // bought "true at the moment it is used", and that is only true if the
    // locking read in that statement MATERIALISES a lock the concurrent
    // redemption's `iam_password` insert has to wait for. Whether it does is a
    // property of the engine and the isolation level, not of the SQL text, so it
    // is measured rather than argued.
    //
    // BOTH ARMS ARE HERE because the answer differs between them, and the
    // handler's arm is the first one: `mint_enrolment` runs autocommit on the
    // pool and pins nothing, so it inherits the server's default —
    // `the_servers_default_isolation_is_repeatable_read` above is what pins that
    // assumption, and `deploy/infra/databases/iam-db.yaml` runs `mariadb:11.8.8`
    // with no configuration of its own.
    //
    // MEASURED 2026-09-11 on MariaDB 11.8.9, the digest CI's `services:` block
    // pins; the deployment runs 11.8.8 of the same series:
    //
    //   - AT THE SERVER DEFAULT (REPEATABLE READ) the password insert BLOCKS and
    //     fails on the 2-second wait, then COMPLETES once the transaction
    //     commits. That is the shape the handler gets.
    //   - WITH THE DEMAND'S OWN TRANSACTION PINNED TO READ COMMITTED the insert
    //     LANDS IMMEDIATELY: no gap lock is taken, and the enrolment still
    //     commits — the one-statement-wide window §6.3 of
    //     `plans/the-bootstrap-enrolment-predicate.md` describes. Asserted here
    //     too, so a future engine that starts blocking at READ COMMITTED reds
    //     this and says so; the answer to that red is to re-measure the
    //     reasoning, never to "fix" the assertion.
    //
    // THE POSITIVE CONTROL IS WHAT MAKES THE FIRST ARM PROOF. A probe that
    // cannot tell "blocked by the lock" from "hung for an unrelated reason"
    // passes on a broken engine, a wrong DSN or a deadlock. Blocked-THEN-RELEASED
    // is the proof; blocked-forever is a red.
    let svc = fresh("iam_db_test_demand_lock").await;
    let user_id = admin(&svc, 128).await;

    let (blocked, landed) = probe_the_lock(
        svc.pool(),
        &user_id,
        "yadgar:enrolment:probe-rr",
        128,
        false,
    )
    .await;
    assert!(
        blocked,
        "at the server's default isolation a redemption's password insert must \
         WAIT on the demand statement's lock — if it lands, the predicate was \
         evaluated against a state that changed before the enrolment committed, \
         which is the race ADR-0655 put the predicate inside the write to close"
    );
    assert!(
        landed,
        "the control: the same insert, once the lock is released, must land — \
         blocked-forever would mean the assertion above passed for a reason with \
         nothing to do with the lock"
    );

    // THE SECOND ARM, on a second person so the first arm's password row is not
    // the thing being measured.
    let other = admin(&svc, 129).await;
    let (blocked_at_rc, _) =
        probe_the_lock(svc.pool(), &other, "yadgar:enrolment:probe-rc", 129, true).await;
    assert!(
        !blocked_at_rc,
        "READ COMMITTED takes no gap lock, so the insert lands while the demand \
         statement's transaction is still open. This is the measurement, not a \
         requirement: a red here means the engine's gap-lock behaviour changed, \
         so re-measure §6.3's reasoning rather than editing this assertion"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_demand_and_a_redemption_racing_never_enrol_a_person_who_gained_a_password() {
    // THE SMOKE OVER THE TOP OF THE PROBE ABOVE, and it is honestly the weaker
    // of the two: outcome assertions cannot distinguish the legal both-succeed
    // interleaving from the illegal one, which is exactly why the lock probe is
    // the load-bearing gate. What this catches is a demand arm that answers
    // something OTHER than success-or-the-one-refusal under contention — an
    // `ER_CHECKREAD` rendered as UNAVAILABLE, a deadlock, a duplicate-key error
    // — none of which any sequential test in this file can reach.
    let svc = std::sync::Arc::new(fresh("iam_db_test_demand_race").await);

    for round in 0..5u8 {
        let user_id = admin(&svc, 130 + round).await;
        let live = 140 + round;
        enrol(&svc, &user_id, live, 3600).await;

        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let minting = {
            let svc = std::sync::Arc::clone(&svc);
            let gate = std::sync::Arc::clone(&gate);
            let user_id = user_id.clone();
            tokio::spawn(async move {
                gate.wait().await;
                svc.create_enrolment(Request::new(CreateEnrolmentRequest {
                    user_id,
                    secret_hash: vec![150 + round; 32],
                    expires_at: Some(at(3600)),
                    require_zero_credential_admin: true,
                    ..Default::default()
                }))
                .await
            })
        };
        let redeeming = {
            let svc = std::sync::Arc::clone(&svc);
            let gate = std::sync::Arc::clone(&gate);
            tokio::spawn(async move {
                gate.wait().await;
                svc.redeem_enrolment(Request::new(RedeemEnrolmentRequest {
                    secret_hash: vec![live; 32],
                    argon2id_hash: GOOD_HASH.into(),
                    idempotency: None,
                }))
                .await
            })
        };

        let redeemed = redeeming
            .await
            .expect("the redemption task")
            .expect("the redemption must not error")
            .into_inner();
        assert_eq!(
            redeemed.outcome,
            RedeemOutcome::Redeemed as i32,
            "round {round}: the redemption holds a live secret and must succeed \
             whichever way the race falls"
        );

        // TWO OUTCOMES ARE LEGAL AND NOTHING ELSE IS. Either the demand
        // committed before the password existed, or it saw the password and
        // refused with ADR-0657's single sentence.
        match minting.await.expect("the minting task") {
            Ok(_) => {}
            Err(err) => {
                assert_eq!(
                    err.code(),
                    tonic::Code::PermissionDenied,
                    "round {round}: the only legal refusal here is the \
                     predicate's — UNAVAILABLE would be an ER_CHECKREAD or a \
                     deadlock reported as the store being broken"
                );
                assert_eq!(err.message(), DEMAND_REFUSAL);
            }
        }
    }
}

#[tokio::test]
async fn a_soft_deleted_persons_enrolment_is_not_redeemable() {
    // MUTATION THIS CATCHES: dropping the JOIN's `u.deleted_at IS NULL`. An
    // enrolment row carries no liveness of its own, so whether the PERSON still
    // exists is a property only the join can see — and redeeming one sets a
    // password for a removed account and lets it log in again.
    let svc = fresh("iam_db_test_enrol_deleted").await;
    let user_id = enrolee(&svc, 38, b"c").await;
    enrol(&svc, &user_id, 38, 3600).await;
    soft_delete(&svc, &user_id).await;

    assert_eq!(
        redeem(&svc, 38, GOOD_HASH, "").await.outcome,
        RedeemOutcome::NotFound as i32,
        "a removed person's enrolment must not set a password"
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_outcome_rather_than_spent() {
    // THE POINT OF THE IDEMPOTENCY KEY, and the failure it prevents is severe: a
    // retrying load balancer delivers the write twice, the second attempt finds
    // the secret spent, and reporting SPENT to a caller that was merely retrying
    // locks the person out on the one path with no resend.
    //
    // MUTATION THIS CATCHES: ignoring `idempotency` entirely. Every other
    // enrolment test passes no key, so none of them notices.
    let svc = fresh("iam_db_test_enrol_replay").await;
    let user_id = enrolee(&svc, 39, b"encrypted-carol").await;
    let enrolment_id = enrol(&svc, &user_id, 39, 3600).await;

    let first = redeem(&svc, 39, GOOD_HASH, "key-1").await;
    let replay = redeem(&svc, 39, GOOD_HASH, "key-1").await;

    assert_eq!(first.outcome, RedeemOutcome::Redeemed as i32);
    assert_eq!(
        replay.outcome,
        RedeemOutcome::Redeemed as i32,
        "a replayed key must return the ORIGINAL outcome, not SPENT"
    );
    assert_eq!(replay.user_id, user_id);
    assert_eq!(replay.enrolment_id, enrolment_id);
    assert_eq!(
        replay.external_id_ciphertext,
        b"encrypted-carol".to_vec(),
        "a replay must carry the username too — recovering it is what the retry is for"
    );
}

#[tokio::test]
async fn a_replay_does_not_re_apply_the_password() {
    // The contract is explicit: `argon2id_hash` is IGNORED on a replay, so the
    // password the first attempt set is the password that stands. `iam` refuses
    // a key reused with a different password before it ever reaches here,
    // because a fresh Argon2id salt makes two hashes of one password differ and
    // this boundary cannot tell them apart.
    const SECOND: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2Vjb25k";
    let svc = fresh("iam_db_test_enrol_replay_password").await;
    let user_id = enrolee(&svc, 40, b"c").await;
    enrol(&svc, &user_id, 40, 3600).await;

    redeem(&svc, 40, GOOD_HASH, "key-2").await;
    let replay = redeem(&svc, 40, SECOND, "key-2").await;
    assert_eq!(
        replay.outcome,
        RedeemOutcome::Redeemed as i32,
        "the replay must be a replay, not a SPENT that happens to write nothing"
    );

    let hash = svc
        .get_password_hash(Request::new(GetPasswordHashRequest {
            username_blind_index: vec![40u8; 32],
            ..Default::default()
        }))
        .await
        .expect("get hash")
        .into_inner();
    assert_eq!(
        hash.argon2id_hash, GOOD_HASH,
        "a replay must not overwrite the password the first attempt set"
    );
}

#[tokio::test]
async fn a_key_reused_with_a_different_secret_is_refused() {
    // D9 as amended: the same key carrying a DIFFERENT request is refused with
    // INVALID_ARGUMENT rather than replayed, because replaying it would answer a
    // request nobody made and report success.
    //
    // THIS boundary can make the comparison — the secret hash is deterministic,
    // the same property that lets an enrolment be looked up by it. O21 records
    // why the general case is not implementable: no `*-db` store persists a
    // request fingerprint.
    let svc = fresh("iam_db_test_enrol_key_reuse").await;
    let user_id = enrolee(&svc, 41, b"c").await;
    enrol(&svc, &user_id, 41, 3600).await;
    enrol(&svc, &user_id, 42, 3600).await;

    redeem(&svc, 41, GOOD_HASH, "key-3").await;

    let err = svc
        .redeem_enrolment(Request::new(RedeemEnrolmentRequest {
            secret_hash: vec![42u8; 32],
            argon2id_hash: GOOD_HASH.into(),
            idempotency: Some(yadgar_iam_db::pb::yadgar::common::v1::Idempotency {
                key: "key-3".into(),
            }),
        }))
        .await
        .expect_err("one key must not cover two different secrets");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // AND THE REFUSAL MUST NOT SPEND THE SECOND SECRET. The comparison precedes
    // the lookup, or the refusal itself reports whether that secret exists.
    assert_eq!(
        redeem(&svc, 42, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32,
        "a refused key reuse must leave the secret it named untouched"
    );
}

#[tokio::test]
async fn an_empty_key_is_no_idempotency_at_all() {
    // The empty string is not a key. Keying a ledger row on it makes two
    // unrelated redemptions collide on one row.
    //
    // WHAT THE COLLISION PRODUCES depends on which guard is missing, and it is
    // worth being exact. With the empty-key guards removed, the second
    // redemption is REFUSED with INVALID_ARGUMENT rather than answered wrongly:
    // the stored `secret_hash` belongs to the first person, the presented one
    // does not match it, and that comparison precedes the lookup. Handing back
    // the WRONG USERNAME needs both the empty-key guard and the hash comparison
    // gone. This test fails on either mutation, which is what it is for — the
    // sentence that used to be here named only the second one.
    let svc = fresh("iam_db_test_enrol_empty_key").await;
    let one = enrolee(&svc, 43, b"encrypted-one").await;
    let two = enrolee(&svc, 44, b"encrypted-two").await;
    enrol(&svc, &one, 45, 3600).await;
    enrol(&svc, &two, 46, 3600).await;

    let first = redeem(&svc, 45, GOOD_HASH, "").await;
    let second = redeem(&svc, 46, GOOD_HASH, "").await;

    assert_eq!(first.user_id, one);
    assert_eq!(
        second.user_id, two,
        "an empty key must not replay an unrelated redemption"
    );
    assert_eq!(second.external_id_ciphertext, b"encrypted-two".to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_deliveries_of_one_key_both_get_the_original_outcome() {
    // THE CASE THE IDEMPOTENCY KEY EXISTS FOR, and the one a sequential replay
    // test cannot reach. A retrying load balancer delivers a write more than
    // once; the two deliveries can be IN FLIGHT AT THE SAME TIME, not merely one
    // after the other.
    //
    // MUTATION THIS CATCHES: deleting the second ledger check on the spend's
    // no-op branch in `redeem_enrolment`. Both callers then pass the first
    // ledger check — it reads nothing, because neither has written yet — and one
    // wins the race for the enrolment row while the loser falls into
    // `unredeemable`, sees the winner's `spent_at`, and answers SPENT. Every
    // other test in this file stays green, because all of them are sequential.
    //
    // NOT FIXABLE BY LOCKING THE LEDGER FIRST. An InnoDB gap lock on a row that
    // does not exist is purely inhibitive: it blocks an INSERT into the gap and
    // does not exclude another transaction's gap lock on the same gap, so two
    // concurrent `SELECT ... FOR UPDATE` reads of one absent key both return
    // nothing and both proceed. Taking it also deadlocks the two ledger INSERTs
    // against each other. The enrolment row is the serialisation point.
    let svc = std::sync::Arc::new(fresh("iam_db_test_enrol_concurrent").await);

    // SEVERAL ROUNDS, because the interleaving is a race and a single round that
    // happens to serialise proves nothing. Each round is a fresh person, a fresh
    // secret and a fresh key.
    for round in 0..5u8 {
        let user_id = enrolee(&svc, 60 + round, b"encrypted-dana").await;
        let secret = 70 + round;
        let enrolment_id = enrol(&svc, &user_id, secret, 3600).await;
        let key = format!("concurrent-key-{round}");

        // A barrier, so both tasks enter the RPC together rather than whenever
        // the runtime happens to poll them.
        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut deliveries = Vec::new();
        for _ in 0..2 {
            let svc = std::sync::Arc::clone(&svc);
            let gate = std::sync::Arc::clone(&gate);
            let key = key.clone();
            deliveries.push(tokio::spawn(async move {
                gate.wait().await;
                svc.redeem_enrolment(Request::new(RedeemEnrolmentRequest {
                    secret_hash: vec![secret; 32],
                    argon2id_hash: GOOD_HASH.into(),
                    idempotency: Some(yadgar_iam_db::pb::yadgar::common::v1::Idempotency { key }),
                }))
                .await
                .expect("neither delivery may error")
                .into_inner()
            }));
        }

        for delivery in deliveries {
            let got = delivery.await.expect("delivery task");
            assert_eq!(
                got.outcome,
                RedeemOutcome::Redeemed as i32,
                "round {round}: both deliveries of one key must get REDEEMED — \
                 answering SPENT to a caller that was merely retrying is the lockout"
            );
            assert_eq!(got.user_id, user_id);
            assert_eq!(got.enrolment_id, enrolment_id);
            assert_eq!(
                got.external_id_ciphertext,
                b"encrypted-dana".to_vec(),
                "round {round}: the loser needs the username as much as the winner"
            );
        }

        // AND THE SECRET WAS SPENT ONCE. Both callers being told REDEEMED must
        // not mean both actually redeemed.
        assert_eq!(
            count(
                &svc,
                "SELECT COUNT(*) FROM iam_enrolment_redemption WHERE user_id = ?",
                &user_id,
            )
            .await,
            1,
            "round {round}: one key must leave exactly one ledger row"
        );
    }
}

#[tokio::test]
async fn a_hash_the_column_cannot_hold_is_the_callers_mistake() {
    // UNAVAILABLE is RETRYABLE and this request can never succeed, so a client
    // retries an unretryable mistake forever. `CreateEnrolment` already makes
    // this argument for a missing `expires_at`; it belongs to the adjacent field
    // and to the other writer of the same column.
    let svc = fresh("iam_db_test_long_hash").await;
    let user_id = enrolee(&svc, 54, b"c").await;
    enrol(&svc, &user_id, 54, 3600).await;

    let err = svc
        .redeem_enrolment(Request::new(RedeemEnrolmentRequest {
            secret_hash: vec![54u8; 32],
            argon2id_hash: oversized_hash(),
            ..Default::default()
        }))
        .await
        .expect_err("a hash the column cannot hold must be refused");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // AND IT MUST HAVE SPENT NOTHING. The guard precedes the spend, so a caller
    // that fixes the hash and retries still holds a usable secret.
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_enrolment WHERE user_id = ? AND spent_at IS NOT NULL",
            &user_id,
        )
        .await,
        0
    );
    assert_eq!(
        redeem(&svc, 54, GOOD_HASH, "").await.outcome,
        RedeemOutcome::Redeemed as i32
    );

    // SetPassword writes the same column and must answer the same way.
    let err = svc
        .set_password(Request::new(SetPasswordRequest {
            user_id,
            argon2id_hash: oversized_hash(),
            ..Default::default()
        }))
        .await
        .expect_err("the other writer of that column must refuse it too");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn administrative_writes_refuse_a_person_who_is_not_live() {
    // A RECURRING CLASS rather than three unrelated bugs: a FOREIGN KEY proves
    // the user row EXISTS and says nothing about whether the person is live,
    // while every READ on this boundary already carries `deleted_at IS NULL`.
    // Each of these used to report OK for a write that changed nothing an
    // operator could observe.
    //
    // CreateEnrolment was the worst of the three: the enrolment was accepted,
    // reported OK, and then permanently NOT_FOUND on redeem — because the
    // redemption path DOES check.
    //
    // CreateCredential and AddTeamMember ARRIVED LATE TO THIS TEST, and that is
    // the point of keeping the class in one place rather than in five files. The
    // sweep that added the three above walked the writes that take a `user_id`
    // and stopped one short of both: a credential minted for a removed person is
    // handed back with an id and resolves for nobody, and a team granted to one
    // is a membership `ResolveCredential`'s `deleted_at IS NULL` never returns.
    //
    // SetPassword ARRIVED LATER STILL, and it CLOSES this test rather than
    // merely extending it: the sweep that added CreateCredential and
    // AddTeamMember missed a third. Every write on this boundary that takes a
    // `user_id` is now guarded except `RemoveTeamMember`, and that one is out
    // for a reason its own handler argues at length — NOT because it revokes.
    // `SetUserAdmin` is here in BOTH directions and `SetRateLimitOverride`'s
    // absent-limit arm is a guarded DELETE, so revoking earns no exemption on
    // this boundary. The exemption is that `live_user` and `live_team` would
    // each refuse a removal that must stay possible, while catching none of the
    // mistake worth catching. SetPassword was missed because it HAS NO
    // PRODUCTION CALLER —
    // password rotation is outside the first cut (D73) and `iam` exposes no
    // `SetPassword` — so nothing in the estate could demonstrate the hole. That
    // is a reason to guard it BEFORE rotation lands, not after: the day a caller
    // appears, the write is already refused. `RedeemEnrolment` writes the same
    // column under `user_id IN (SELECT id FROM iam_user WHERE deleted_at IS
    // NULL)`, so the guard on one writer and not the other is exactly what
    // `fits_password_column` already refuses to allow on this pair.
    let svc = fresh("iam_db_test_live_writes").await;
    let (user_id, _cred) = seed(&svc, &[55u8; 32], &[55u8; 32]).await;
    team(&svc, "yadgar:team:t6").await;
    soft_delete(&svc, &user_id).await;

    let err = svc
        .create_credential(Request::new(CreateCredentialRequest {
            user_id: user_id.clone(),
            token_hash: vec![54u8; 32],
            label: "laptop".into(),
            ..Default::default()
        }))
        .await
        .expect_err("a credential for a removed person is one that authenticates nobody");
    assert_eq!(err.code(), tonic::Code::NotFound);

    let err = svc
        .add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:t6".into(),
            user_id: user_id.clone(),
            ..Default::default()
        }))
        .await
        .expect_err("a team granted to a removed person is one no read returns");
    assert_eq!(err.code(), tonic::Code::NotFound);

    let err = svc
        .create_enrolment(Request::new(CreateEnrolmentRequest {
            user_id: user_id.clone(),
            secret_hash: vec![55u8; 32],
            expires_at: Some(at(3600)),
            ..Default::default()
        }))
        .await
        .expect_err("an enrolment for a removed person is one nobody can ever redeem");
    assert_eq!(err.code(), tonic::Code::NotFound);

    let err = svc
        .set_user_admin(Request::new(SetUserAdminRequest {
            user_id: user_id.clone(),
            is_admin: true,
            ..Default::default()
        }))
        .await
        .expect_err("promoting a removed person must not report success");
    assert_eq!(err.code(), tonic::Code::NotFound);

    let err = svc
        .set_rate_limit_override(Request::new(SetRateLimitOverrideRequest {
            user_id: user_id.clone(),
            module: "recall".into(),
            kind: yadgar_iam_db::pb::yadgar::telemetry::v1::Kind::Read as i32,
            limit: Some(RateLimit {
                rate: 1.0,
                burst: 1,
            }),
            ..Default::default()
        }))
        .await
        .expect_err("a limit on a removed person is one an operator believes is in force");
    assert_eq!(err.code(), tonic::Code::NotFound);

    let err = svc
        .set_password(Request::new(SetPasswordRequest {
            user_id: user_id.clone(),
            argon2id_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            ..Default::default()
        }))
        .await
        .expect_err("a password set on a removed person is one no login will ever read");
    assert_eq!(err.code(), tonic::Code::NotFound);

    // AND THE ROW MUST NOT BE THERE. `iam_password` is an upsert onto a primary
    // key the FOREIGN KEY lets through, so a refusal that still wrote would
    // leave a hash behind for an account `GetPasswordHash` no longer answers
    // for — invisible to every read on this boundary and to this test's status
    // assertion alike.
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_password WHERE user_id = ?",
            &user_id,
        )
        .await,
        0,
        "the refusal must not have written a hash either"
    );
}
/// Which liveness the interleaved soft delete withdraws.
enum Withdraw {
    User,
    Team,
}

/// Run `call` with a soft delete COMMITTING WHILE THE WRITE IS IN FLIGHT.
///
/// **THIS IS THE INTERLEAVING, NOT A SEQUENTIAL DELETE.**
/// `administrative_writes_refuse_a_person_who_is_not_live` deletes FIRST and
/// then calls, so the handler's own liveness check sees the withdrawal and
/// refuses. That test passes whether the check and the write are one statement
/// or two. These put the delete BETWEEN them.
///
/// The lever is an InnoDB row lock rather than a sleep. The deleter's
/// transaction holds an exclusive lock on the person's (or the team's) row and
/// does not commit, so:
///
/// - a handler that checks liveness with a bare `SELECT` reads a consistent
///   snapshot, does not block, and passes the check;
/// - its write then blocks — on the foreign key's shared lock, or on the
///   liveness predicate's own — until the deleter commits;
/// - the deleter commits 300ms in, and the write resumes against a person who
///   is now gone.
///
/// A handler whose predicate lives in the write statement re-reads under that
/// lock and matches nothing. A handler that checked separately has nothing left
/// to re-read and writes anyway.
///
/// The timeout is named rather than left to `innodb_lock_wait_timeout`, which
/// is 50 seconds: a fix that deadlocks must fail as a deadlock, not as a stall.
async fn while_a_soft_delete_lands<T>(
    svc: &IamDb,
    withdraw: Withdraw,
    id: &str,
    call: impl std::future::Future<Output = T>,
) -> T {
    let sql = match withdraw {
        Withdraw::User => "UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?",
        Withdraw::Team => "UPDATE iam_team SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?",
    };
    let mut tx = svc
        .pool()
        .begin()
        .await
        .expect("open the deleter's transaction");
    sqlx::query(sql)
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("take the row's write lock");

    let lands = async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tx.commit().await.expect("commit the soft delete");
    };

    tokio::time::timeout(std::time::Duration::from_secs(20), async move {
        let (out, ()) = tokio::join!(call, lands);
        out
    })
    .await
    .expect("the write must not sit on the row lock until innodb_lock_wait_timeout")
}

/// The six writes below share one argument, stated once here. Five were fixed by
/// ledger 695 and the sixth — `SetInheritedSetting`'s team arm — by ledger 704,
/// which is the same defect one layer further in: that one guarded on the pool
/// and wrote inside a TRANSACTION, and the transaction was mistaken for a guard.
///
/// **THE RACE THE SIX GUARDED WRITES ALL CARRIED**, and the reason a guard on
/// the pool followed by a write on the pool is not a guard at all. Between
/// `live_user`'s SELECT and the INSERT that followed it there was a whole round
/// trip, and a person soft-deleted inside that window got the write anyway — a
/// password, a credential, an enrolment, a membership or a rate limit, all
/// belonging to an account every READ on this boundary already refuses to
/// return.
///
/// **LATENT WHEN THESE WERE WRITTEN.** Nothing in production sets
/// `iam_user.deleted_at` — there is no `DeleteUser` RPC, and the only writer
/// anywhere is `soft_delete` above, whose own comment says it exists to reach a
/// state no RPC creates. `iam_team.deleted_at` has no PRODUCTION writer either —
/// team creation and deletion are both outside the first cut — and its only
/// writer anywhere is `Withdraw::Team` in the helper above. So these tests drive
/// the delete themselves, and it is the arrival of those RPCs rather than any
/// change here that makes the defect reachable.
///
/// **MUTATION THESE CATCH:** moving any of the six predicates back out of its
/// write statement into a preceding `live_user` / `live_team` call. Every other
/// test in this file stays green when you do, including the sequential liveness
/// test above — which is how all five survived three sweeps, and how the sixth
/// survived the sweep that fixed the five.
///
/// **ONE TEST PER HANDLER, DELIBERATELY.** A single test asserting all six
/// stops at the first failure, so a regression in the fourth would be reported
/// as a defect in the first. These fail independently and name what broke.
#[tokio::test]
async fn a_soft_delete_landing_mid_call_still_refuses_a_password() {
    let svc = fresh("iam_db_test_race_password").await;
    let user = enrolee(&svc, 81, b"encrypted-pw").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::User,
        &user,
        svc.set_password(Request::new(SetPasswordRequest {
            user_id: user.clone(),
            argon2id_hash: GOOD_HASH.into(),
            ..Default::default()
        })),
    )
    .await
    .expect_err("a hash written for a person who left mid-call is one no login reads");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_password WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have written a hash either"
    );
}

#[tokio::test]
async fn a_soft_delete_landing_mid_call_still_refuses_a_credential() {
    // The foreign key is what made this one reachable: a soft delete leaves the
    // parent row in place, so `fk_iam_credential_user` was satisfied by an
    // account `ResolveCredential` will never return.
    let svc = fresh("iam_db_test_race_credential").await;
    let user = enrolee(&svc, 82, b"encrypted-cred").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::User,
        &user,
        svc.create_credential(Request::new(CreateCredentialRequest {
            user_id: user.clone(),
            token_hash: vec![82u8; 32],
            label: "laptop".into(),
            ..Default::default()
        })),
    )
    .await
    .expect_err("a credential minted mid-delete authenticates nobody for its whole lifetime");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_credential WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have minted a credential either"
    );
}

#[tokio::test]
async fn a_soft_delete_landing_mid_call_still_refuses_an_enrolment() {
    // The redemption path has always checked; only the creation path did not,
    // so what this one prevented was an enrolment reported OK and then
    // permanently NOT_FOUND on redeem.
    let svc = fresh("iam_db_test_race_enrolment").await;
    let user = enrolee(&svc, 83, b"encrypted-enrol").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::User,
        &user,
        svc.create_enrolment(Request::new(CreateEnrolmentRequest {
            user_id: user.clone(),
            secret_hash: vec![83u8; 32],
            expires_at: Some(at(3600)),
            ..Default::default()
        })),
    )
    .await
    .expect_err("an enrolment minted mid-delete is permanently NOT_FOUND on redeem");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_enrolment WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have minted an enrolment either"
    );
}

#[tokio::test]
async fn a_soft_delete_landing_mid_call_still_refuses_a_membership() {
    // AddTeamMember's USER predicate — one of the two it carries.
    let svc = fresh("iam_db_test_race_member_user").await;
    // `seed_team` rather than `team`, because `iam_team.name` is UNIQUE and the
    // team-side test seeds one of its own.
    seed_team(&svc, "yadgar:team:race").await;
    let user = enrolee(&svc, 84, b"encrypted-member").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::User,
        &user,
        svc.add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:race".into(),
            user_id: user.clone(),
            ..Default::default()
        })),
    )
    .await
    .expect_err("a membership granted mid-delete is one ResolveCredential never returns");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_team_member WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have granted the membership either"
    );
}

#[tokio::test]
async fn a_team_soft_delete_landing_mid_call_still_refuses_a_membership() {
    // AddTeamMember's TEAM predicate, one of the two places on this boundary
    // where a team's liveness races a write — `SetInheritedSetting`'s team arm
    // is the other, tested below. `Withdraw::Team` is the only writer of
    // `iam_team.deleted_at` anywhere, so both are latent until a team-deleting
    // RPC exists, and both are fixed anyway.
    let svc = fresh("iam_db_test_race_member_team").await;
    seed_team(&svc, "yadgar:team:racedoomed").await;
    let user = enrolee(&svc, 85, b"encrypted-joiner").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::Team,
        "yadgar:team:racedoomed",
        svc.add_team_member(Request::new(AddTeamMemberRequest {
            team_id: "yadgar:team:racedoomed".into(),
            user_id: user.clone(),
            ..Default::default()
        })),
    )
    .await
    .expect_err("a membership in a team that left mid-call is a grant into nothing");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_team_member WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have granted the membership either"
    );
}

#[tokio::test]
async fn a_soft_delete_landing_mid_call_still_refuses_a_rate_limit_override() {
    // THE SET ARM ONLY. `SetRateLimitOverride`'s CLEAR arm is deliberately not
    // tested here and deliberately still checks-then-writes: the write its
    // window lets through DELETES an override belonging to a person on their way
    // out, so there is no state an operator could be misled by. That is the
    // whole reason. Closing that arm would cost nothing either — the handler's
    // comment names both of the arguments that would wrongly say otherwise.
    let svc = fresh("iam_db_test_race_rate_limit").await;
    let user = enrolee(&svc, 86, b"encrypted-limited").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::User,
        &user,
        svc.set_rate_limit_override(Request::new(SetRateLimitOverrideRequest {
            user_id: user.clone(),
            module: "recall".into(),
            kind: yadgar_iam_db::pb::yadgar::telemetry::v1::Kind::Read as i32,
            limit: Some(RateLimit {
                rate: 1.0,
                burst: 1,
            }),
            ..Default::default()
        })),
    )
    .await
    .expect_err("a limit stored mid-delete is one an operator believes is in force");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_rate_limit_override WHERE user_id = ?",
            &user,
        )
        .await,
        0,
        "the refusal must not have stored a limit either"
    );
}

#[tokio::test]
async fn a_team_soft_delete_landing_mid_call_still_refuses_an_inherited_setting_override() {
    // THE SIXTH INSTANCE OF THE CLASS (ledger 704), and the one ledger 695 left
    // behind. `SetInheritedSetting`'s team arm called `live_team` and then wrote,
    // and the tree argued the shared TRANSACTION made that safe. It does not: a
    // transaction buys ATOMICITY, and `live_team` is a plain non-locking SELECT
    // wherever it runs. The handler pins READ COMMITTED by its own `SET
    // TRANSACTION` statement, so the check read a snapshot in which the team was
    // live, the upsert then blocked on `fk_iam_team_setting_override_team`'s
    // shared lock while the deleter committed, and the override landed for a team
    // whose `deleted_at` was set — which `read_inherited_setting` handed back as
    // in force.
    //
    // THE REACHABILITY ARGUMENT THE TREE MADE WAS ALSO STALE. Migration 11 and
    // the handler both said `iam_team.deleted_at` has no writer anywhere, "test
    // helpers included". `Withdraw::Team` above is one, and the membership test
    // below already used it — the claim was self-contradictory before this test
    // existed. What remains true is that no RPC deletes a team yet, which is the
    // same latency the five siblings were fixed under.
    //
    // MUTATION THIS CATCHES: moving the predicate back out of the INSERT into a
    // preceding `live_team` call. Measured red against the pre-fix statement —
    // status OK, one override row for a soft-deleted team.
    //
    // THE CLEAR ARM IS DELIBERATELY NOT TESTED HERE and deliberately still checks
    // nothing: a clear names a ROW TO REMOVE rather than a team to write to, and
    // migration 11 leaves the override a soft-deleted team strands to be cleared
    // by exactly that call.
    let svc = fresh("iam_db_test_race_inherited_setting").await;
    seed_team(&svc, "yadgar:team:racesetting").await;

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::Team,
        "yadgar:team:racesetting",
        svc.set_inherited_setting(Request::new(team_request("yadgar:team:racesetting"))),
    )
    .await
    .expect_err("an override stored mid-delete is one an operator believes is in force");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "NOT_FOUND rather than UNAVAILABLE: an `INSERT ... SELECT` without \
         `LOCK IN SHARE MODE` raises ER_CHECKREAD (1020) at READ COMMITTED, which \
         `db()` renders as a retryable status for a request that can never succeed"
    );
    assert_eq!(
        overrides_for(&svc, "yadgar:team:racesetting").await,
        0,
        "the refusal must not have stored an override either"
    );
}

#[tokio::test]
async fn a_team_soft_delete_landing_after_the_idempotency_read_still_refuses_an_inherited_setting_override(
) {
    // LEDGER 722. The test above pins the race `live_team` closes when it is
    // the FIRST read in the transaction — there, `recorded()` is skipped
    // because the request carries no idempotency key, so the `INSERT ...
    // SELECT ... LOCK IN SHARE MODE` is what opens the transaction's first
    // read, and a locking read always sees the latest COMMITTED row regardless
    // of isolation level. That test would pass at REPEATABLE READ too, and
    // proves nothing about the isolation pin.
    //
    // THIS TEST PUTS A PLAIN READ FIRST. Keying the request runs `recorded()`
    // — an ordinary, non-locking `SELECT` against `iam_inherited_setting_write`
    // — before anything touches the team row. At REPEATABLE READ that FIRST
    // read is what fixes the transaction's snapshot, so the snapshot forms
    // while the team is still live.
    //
    // MEASURED, AND IT CORRECTS WHAT THE HANDLER'S OWN COMMENT PREDICTS FOR
    // THIS LINE ("OK with rows: 0"). Mutating `READ COMMITTED` to `REPEATABLE
    // READ` here does not make the write silently succeed. It makes the
    // `INSERT ... SELECT ... LOCK IN SHARE MODE` against `iam_team` raise
    // MariaDB error 1020, ER_CHECKREAD ("Record has changed since last read
    // in table 'iam_team'"): that statement is now the SECOND read against a
    // row covered by a snapshot `recorded()` already fixed, and a locking
    // read finding its row changed since the snapshot was established is the
    // same failure class the pin's original, first job (on the ledger's own
    // table) exists to prevent — just landing on `iam_team` instead. `db()`
    // renders it UNAVAILABLE, so the caller retries a write that can never
    // succeed against a team that is gone: wrong, but visibly so, rather than
    // the silent OK the comment predicts. This test asserts NOT_FOUND, which
    // is what the SHIPPED statement (READ COMMITTED) actually returns, so it
    // fails on the mutant regardless of which wrong status the mutant
    // produces.
    //
    // MUTATION THIS CATCHES: `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`
    // becoming `... REPEATABLE READ` on the statement above. Measured red
    // against that one-word change — `svc.set_inherited_setting` returns
    // UNAVAILABLE (1020 on `iam_team`) rather than NOT_FOUND. Restored after
    // measuring. The sibling test above stays GREEN under the identical
    // mutation — its request carries no idempotency key, so its first read is
    // the locking `INSERT ... SELECT` itself, which always reads the latest
    // committed row regardless of isolation level — which is the coverage gap
    // this test exists to close.
    let svc = fresh("iam_db_test_race_inherited_setting_keyed").await;
    seed_team(&svc, "yadgar:team:racesettingkeyed").await;

    let req = keyed(
        "k-racesetting-keyed",
        team_request("yadgar:team:racesettingkeyed"),
    );

    let err = while_a_soft_delete_lands(
        &svc,
        Withdraw::Team,
        "yadgar:team:racesettingkeyed",
        svc.set_inherited_setting(Request::new(req)),
    )
    .await
    .expect_err(
        "an override stored — or silently reported as stored — for a team gone \
         before the write is one an operator believes is in force",
    );
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "NOT_FOUND: the isolation pin is what lets live_team's re-read see the \
         committed delete rather than the idempotency read's earlier snapshot. \
         At REPEATABLE READ this is UNAVAILABLE instead (measured: MariaDB 1020 \
         ER_CHECKREAD on iam_team), never a silent OK"
    );
    assert_eq!(
        overrides_for(&svc, "yadgar:team:racesettingkeyed").await,
        0,
        "the refusal must not have stored an override either"
    );
}

#[tokio::test]
async fn setting_a_password_for_a_user_who_does_not_exist_is_not_found_rather_than_unavailable() {
    // THE FOREIGN KEY IS NOT THE ERROR MESSAGE, on the argument
    // `an_override_for_a_team_that_does_not_exist_is_not_found_rather_than_unavailable`
    // already makes for `SetInheritedSetting`. Left to fire,
    // `fk_iam_password_user` renders through `db()` as UNAVAILABLE — a retryable
    // status for a request that can never succeed, so a client retries a typo
    // forever and the record says this service was down.
    //
    // MUTATION THIS CATCHES: deleting `live_user` from `SetPassword`. The
    // soft-delete arm above cannot catch it on its own, because the FOREIGN KEY
    // is satisfied for a soft-deleted person and unsatisfied for an unknown one:
    // one arm proves the guard runs, the other proves what it replaces.
    let svc = fresh("iam_db_test_password_unknown").await;

    let err = svc
        .set_password(Request::new(SetPasswordRequest {
            user_id: "yadgar:user:never-existed".into(),
            argon2id_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            ..Default::default()
        }))
        .await
        .expect_err("a password for a person who does not exist must not report success");
    assert_eq!(err.code(), tonic::Code::NotFound);

    assert_eq!(
        count(
            &svc,
            "SELECT COUNT(*) FROM iam_password WHERE user_id = ?",
            "yadgar:user:never-existed",
        )
        .await,
        0,
        "the refusal must not have written a hash either"
    );
}

#[tokio::test]
async fn promoting_an_unknown_user_is_not_found_but_re_asserting_a_flag_is_not() {
    // `sqlx-mysql` reports MATCHED rows, not CHANGED ones, so re-asserting a
    // flag the user already has still MATCHES that row and affects one, never
    // zero — reading a match as NOT_FOUND would break the idempotence this RPC
    // gets from assigning rather than toggling. A mistyped id, which matches
    // nothing, must still be refused.
    let svc = fresh("iam_db_test_admin_unknown").await;
    let (user_id, _cred) = seed(&svc, &[56u8; 32], &[56u8; 32]).await;

    let err = svc
        .set_user_admin(Request::new(SetUserAdminRequest {
            user_id: "yadgar:user:never-existed".into(),
            is_admin: true,
            ..Default::default()
        }))
        .await
        .expect_err("a mistyped id promotes nobody and must not report success");
    assert_eq!(err.code(), tonic::Code::NotFound);

    for _ in 0..2 {
        svc.set_user_admin(Request::new(SetUserAdminRequest {
            user_id: user_id.clone(),
            is_admin: true,
            ..Default::default()
        }))
        .await
        .expect("setting the same flag twice must stay idempotent");
    }
}

#[tokio::test]
async fn a_removed_persons_credentials_stop_being_listed() {
    // MUTATION THIS CATCHES: dropping the JOIN's `u.deleted_at IS NULL` from
    // ListCredentials. Every other read on this boundary carries that clause;
    // this one showed live-looking rows for an account that can no longer
    // authenticate with any of them.
    let svc = fresh("iam_db_test_list_deleted").await;
    let (user_id, _cred) = seed(&svc, &[57u8; 32], &[57u8; 32]).await;

    let before = svc
        .list_credentials(Request::new(ListCredentialsRequest {
            user_id: user_id.clone(),
            ..Default::default()
        }))
        .await
        .expect("list")
        .into_inner();
    assert_eq!(before.credentials.len(), 1);

    soft_delete(&svc, &user_id).await;

    let after = svc
        .list_credentials(Request::new(ListCredentialsRequest {
            user_id,
            ..Default::default()
        }))
        .await
        .expect("list")
        .into_inner();
    assert!(
        after.credentials.is_empty(),
        "a removed person's credentials must not be listed as live"
    );
}

// ---------------------------------------------------------------------------
// The rest of contract v1.6.0. Vendoring the tag adds FIVE RPCs to the service
// trait, not the two enrolment needs, so these cover what the same commit had to
// build to compile at all.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_admin_flag_travels_with_the_identity() {
    // Read in the SAME transaction as the credential, which the contract
    // requires — so a withdrawn flag cannot be one read behind and stay in force
    // for a whole cache lifetime at the caller.
    let svc = fresh("iam_db_test_admin").await;
    let user = svc
        .create_user(Request::new(CreateUserRequest {
            external_id_blind_index: vec![50u8; 32],
            external_id_ciphertext: b"c".to_vec(),
            display_name_ciphertext: b"c".to_vec(),
            is_admin: true,
            ..Default::default()
        }))
        .await
        .expect("create admin")
        .into_inner();
    let user_id = user.meta.expect("meta").id;

    svc.create_credential(Request::new(CreateCredentialRequest {
        user_id: user_id.clone(),
        token_hash: vec![50u8; 32],
        ..Default::default()
    }))
    .await
    .expect("create credential");

    let before = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![50u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert!(before.is_admin, "an admin must resolve as one");

    svc.set_user_admin(Request::new(SetUserAdminRequest {
        user_id,
        is_admin: false,
        ..Default::default()
    }))
    .await
    .expect("demote");

    let after = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![50u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert!(
        !after.is_admin,
        "a withdrawn admin flag must stop resolving as one"
    );
}

#[tokio::test]
async fn clearing_a_rate_limit_override_deletes_it_rather_than_storing_zero() {
    // An ABSENT limit means "the deployment's configured default governs this
    // bucket". A stored rate of zero means "deny this bucket". Collapsing the
    // first into the second denies every call the override existed to relax.
    let svc = fresh("iam_db_test_rate_limit").await;
    let (user_id, _cred) = seed(&svc, &[51u8; 32], &[51u8; 32]).await;

    let read = yadgar_iam_db::pb::yadgar::telemetry::v1::Kind::Read as i32;

    svc.set_rate_limit_override(Request::new(SetRateLimitOverrideRequest {
        user_id: user_id.clone(),
        module: "recall".into(),
        kind: read,
        limit: Some(RateLimit {
            rate: 12.5,
            burst: 30,
        }),
        ..Default::default()
    }))
    .await
    .expect("set override");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![51u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert_eq!(got.rate_limit_overrides.len(), 1);
    assert_eq!(
        got.rate_limit_overrides[0].limit,
        Some(RateLimit {
            rate: 12.5,
            burst: 30
        })
    );

    svc.set_rate_limit_override(Request::new(SetRateLimitOverrideRequest {
        user_id: user_id.clone(),
        module: "recall".into(),
        kind: read,
        limit: None,
        ..Default::default()
    }))
    .await
    .expect("clear override");

    let after = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![51u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert!(
        after.rate_limit_overrides.is_empty(),
        "clearing must delete the row, not store a zero that denies the bucket"
    );
}

#[tokio::test]
async fn re_setting_a_rate_limit_override_replaces_both_columns() {
    // THE UPSERT'S UPDATE ARM, WHICH NOTHING ELSE READS BACK. Ledger 695 moved
    // this handler's liveness predicate into the statement, and that turned
    // `ON DUPLICATE KEY UPDATE rate = VALUES(rate), burst = VALUES(burst)` into
    // `rate = ?, burst = ?` — because `VALUES()` names the row of an
    // `INSERT ... VALUES` and this is now an `INSERT ... SELECT`. The column
    // names used to carry the mapping; two positional binds do not.
    //
    // MUTATION THIS CATCHES: transposing those two binds. `rate` is a DOUBLE and
    // `burst` an INT, so a swap stores 5 and 1 rather than 1.0 and 5, raises
    // nothing, and every other test stays green — the first write goes through
    // the SELECT list, which has its own binds and its own coverage in
    // `clearing_a_rate_limit_override_deletes_it_rather_than_storing_zero`.
    //
    // BOTH COLUMNS DIFFER FROM THE FIRST WRITE AND FROM EACH OTHER, which is
    // what makes this pin the assignment rather than the insert.
    let svc = fresh("iam_db_test_rate_limit_replace").await;
    let (user_id, _cred) = seed(&svc, &[52u8; 32], &[52u8; 32]).await;

    let read = yadgar_iam_db::pb::yadgar::telemetry::v1::Kind::Read as i32;
    for limit in [
        RateLimit {
            rate: 12.5,
            burst: 30,
        },
        RateLimit {
            rate: 3.25,
            burst: 7,
        },
    ] {
        svc.set_rate_limit_override(Request::new(SetRateLimitOverrideRequest {
            user_id: user_id.clone(),
            module: "recall".into(),
            kind: read,
            limit: Some(limit),
            ..Default::default()
        }))
        .await
        .expect("set override");
    }

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![52u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();
    assert_eq!(
        got.rate_limit_overrides.len(),
        1,
        "the composite primary key must make the second write an upsert"
    );
    assert_eq!(
        got.rate_limit_overrides[0].limit,
        Some(RateLimit {
            rate: 3.25,
            burst: 7
        }),
        "both columns must carry the second write's values, each in its own column"
    );
}

#[tokio::test]
async fn listing_credentials_omits_the_revoked_ones() {
    // MUTATION THIS CATCHES: dropping `revoked_at IS NULL`. The list is what a
    // person is shown of their own credentials, and a revoked one presented as
    // live is one they believe still works.
    let svc = fresh("iam_db_test_list").await;
    let (user_id, cred_id) = seed(&svc, &[52u8; 32], &[52u8; 32]).await;

    svc.create_credential(Request::new(CreateCredentialRequest {
        user_id: user_id.clone(),
        token_hash: vec![53u8; 32],
        label: "desktop".into(),
        ..Default::default()
    }))
    .await
    .expect("second credential");

    let all = svc
        .list_credentials(Request::new(ListCredentialsRequest {
            user_id: user_id.clone(),
            ..Default::default()
        }))
        .await
        .expect("list")
        .into_inner();
    assert_eq!(all.credentials.len(), 2);
    assert!(
        all.credentials.iter().all(|c| c.revoked_at.is_none()),
        "no row this returns carries a tombstone"
    );

    svc.revoke_credential(Request::new(RevokeCredentialRequest {
        credential_id: cred_id,
        ..Default::default()
    }))
    .await
    .expect("revoke");

    let live = svc
        .list_credentials(Request::new(ListCredentialsRequest {
            user_id,
            ..Default::default()
        }))
        .await
        .expect("list")
        .into_inner();
    assert_eq!(live.credentials.len(), 1);
    assert_eq!(live.credentials[0].label, "desktop");
    assert!(
        live.credentials[0].created_at.is_some(),
        "a listed credential must carry the time it was made"
    );
}

/// ADR-0522's setting, as it is stored: the organisation's value and lock, and
/// every team that states something else.
///
/// The name is the same literal `service.rs` binds, spelled out here rather than
/// imported so a rename of the constant cannot rename the row underneath these
/// assertions without one of them failing.
const OWNER_READS_OWN_RECORD: &str = "owner_reads_own_record";

#[tokio::test]
async fn the_shipped_default_is_readable_with_the_lock_engaged() {
    // ADR-0522 ships the organisation's value ON and the lock ENGAGED, so the
    // owner-always-reads behaviour is what a fresh deployment gets and is not
    // quietly overridable. A migration that created the tables and seeded no row
    // would leave every deployment's value UNSPECIFIED, which an enforcing -db
    // refuses — an outage that no test creating its own row would see.
    let svc = fresh("iam_db_test_setting_default").await;
    seed(&svc, &[60u8; 32], &[60u8; 32]).await;

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![60u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    let setting = got
        .owner_reads_own_record
        .expect("the setting travels with the identity");
    assert_eq!(setting.org_value, SettingValue::On as i32);
    assert!(setting.org_locked, "the shipped lock is engaged");
    assert!(setting.team_override.is_empty());
}

#[tokio::test]
async fn every_team_override_comes_back_including_teams_the_caller_is_not_in() {
    // THE TEAM IS THE RECORD'S, NEVER THE CALLER'S. The failure ADR-0522 exists
    // to fix is an owner who LEFT the team their record is shared with, so an
    // override keyed on the teams the caller currently belongs to would evaporate
    // in exactly the case it is for. The surrounding queries in this RPC all
    // filter by `user_id`; this one must not, and that is what this pins.
    //
    // It also pins that this module RESOLVES NOTHING: the organisation is locked,
    // which makes the override inert, and the override still comes back. The
    // resolution happens where the reach is computed, against the team of the row
    // being read, which neither this module nor its caller knows.
    let svc = fresh("iam_db_test_setting_override").await;
    seed(&svc, &[61u8; 32], &[61u8; 32]).await;

    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind("yadgar:team:left")
    .bind("the team the owner left")
    .execute(svc.pool())
    .await
    .expect("seed team");

    sqlx::query("INSERT INTO iam_team_setting_override (name, team_id, value) VALUES (?, ?, ?)")
        .bind(OWNER_READS_OWN_RECORD)
        .bind("yadgar:team:left")
        .bind(SettingValue::Off as i32)
        .execute(svc.pool())
        .await
        .expect("seed override");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![61u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    assert!(
        got.team_ids.is_empty(),
        "the caller is in no team, which is the whole point"
    );
    let setting = got
        .owner_reads_own_record
        .expect("the setting travels with the identity");
    assert!(setting.org_locked, "a locked organisation makes it inert");
    assert_eq!(
        setting.team_override.get("yadgar:team:left"),
        Some(&(SettingValue::Off as i32)),
        "an override for a team the caller is not in must still be returned"
    );
}

#[tokio::test]
async fn an_absent_organisation_row_is_unspecified_and_never_off() {
    // SETTING_VALUE_UNSPECIFIED IS NOT A DEFAULT AND IS NEVER A VALUE. A store
    // with no row states no policy, and the enforcing -db refuses rather than
    // choosing one. Answering OFF here would be this module choosing the strict
    // policy for a deployment that never asked for it — silently, since an unset
    // enum is falsy in every generated language.
    //
    // The message stays PRESENT. An absent message and a present one holding
    // UNSPECIFIED are one case to the receiver, and both are refused alike, so
    // sending it costs nothing and keeps one shape on the wire.
    let svc = fresh("iam_db_test_setting_absent").await;
    seed(&svc, &[62u8; 32], &[62u8; 32]).await;

    sqlx::query("DELETE FROM iam_org_setting WHERE name = ?")
        .bind(OWNER_READS_OWN_RECORD)
        .execute(svc.pool())
        .await
        .expect("delete the organisation's row");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![62u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    let setting = got
        .owner_reads_own_record
        .expect("the message is sent even when the organisation states nothing");
    assert_eq!(
        setting.org_value,
        SettingValue::Unspecified as i32,
        "no row means no policy, and never means OFF"
    );
    assert!(!setting.org_locked);
}

#[tokio::test]
async fn an_unlocked_organisation_comes_back_verbatim() {
    // THE UNLOCKED ARM, which nothing else in this file ever stores. Every other
    // test reads the seeded `(ON, locked)` row or a deleted one, so each column
    // was only ever observed at one value and a read that ignored the row
    // entirely still passed: hard-coding `locked` to `true`, or `value` to
    // SETTING_VALUE_ON, left all forty-one green. Measured, not conjectured.
    //
    // ADR-0522 hangs the whole team-override mechanism on the lock being CLEAR —
    // a locked organisation makes every override inert — so the one arm the
    // overrides exist for was the one arm never written.
    //
    // Both columns differ from the seed AT ONCE, which is what makes this pin
    // the read rather than the seed.
    let svc = fresh("iam_db_test_setting_unlocked").await;
    seed(&svc, &[63u8; 32], &[63u8; 32]).await;

    sqlx::query("UPDATE iam_org_setting SET value = ?, locked = 0 WHERE name = ?")
        .bind(SettingValue::Off as i32)
        .bind(OWNER_READS_OWN_RECORD)
        .execute(svc.pool())
        .await
        .expect("store the unlocked arm");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![63u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner();

    let setting = got
        .owner_reads_own_record
        .expect("the setting travels with the identity");
    assert_eq!(
        setting.org_value,
        SettingValue::Off as i32,
        "the stored value comes back, never the seeded one"
    );
    assert!(
        !setting.org_locked,
        "a cleared lock comes back cleared, which is what makes an override consultable"
    );
}

// ---------------------------------------------------------------------------
// SetInheritedSetting — the WRITE half of ADR-0522's setting.
//
// **THE READ HALF ABOVE SHIPPED WITHOUT ONE.** ADR-0524 opens on exactly that:
// the organisation's value, the inheritance lock and every team override were
// changeable only by direct SQL, so half of ADR-0522's ruling could not be met.
// Everything below this line is the verb that closes it.
//
// **WHAT THESE ASSERT IS DELIBERATELY THE REFUSALS AND THE WITHDRAWAL.** Writing
// a value and reading it back is the easy case and passes on a naive
// implementation. The cases that matter are the ones where a supplied byte would
// otherwise be silently discarded, and the one where an OMITTED byte would
// destroy configuration — ADR-0524's whole subject.
//
// **EVERY ASSERTION ABOUT ABSENCE IS ON PRESENCE, NEVER ON A VALUE.** prost makes
// every field of `InheritedSetting::default()` equal the field of an absent
// message, so `assert_eq!(setting.org_value, UNSPECIFIED)` goes green whether or
// not the code tells the two apart. The clear-versus-absent tests below assert
// `Option::is_some`/`is_none`, `HashMap::contains_key` and a `SELECT COUNT(*)`
// against the row itself — three things a collapsed distinction cannot satisfy.
// ---------------------------------------------------------------------------

/// A team row, which no RPC mints (D72 puts team creation outside the first cut).
async fn seed_team(svc: &IamDb, id: &str) {
    sqlx::query(
        "INSERT INTO iam_team (id, name, created_by, updated_by) VALUES (?, ?, 'system', 'system')",
    )
    .bind(id)
    // The name is UNIQUE, so it is the id rather than a literal: two teams in
    // one test would otherwise collide on the constraint rather than on anything
    // the test is about.
    .bind(id)
    .execute(svc.pool())
    .await
    .expect("seed team");
}

/// How many override rows this team holds. The SQL rather than the response,
/// because the response is what a collapsed implementation could still get right.
async fn overrides_for(svc: &IamDb, team_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam_team_setting_override WHERE name = ? AND team_id = ?",
    )
    .bind(OWNER_READS_OWN_RECORD)
    .bind(team_id)
    .fetch_one(svc.pool())
    .await
    .expect("count overrides")
}

/// A request that is valid at organisation scope, for a test to spoil one field
/// of. Never used unmodified: a helper that IS the happy path hides which field
/// each refusal is about.
fn org_request() -> SetInheritedSettingRequest {
    SetInheritedSettingRequest {
        scope: SettingScope::Org as i32,
        name: OWNER_READS_OWN_RECORD.into(),
        value: Some(SettingValue::Off as i32),
        locked: Some(false),
        ..Default::default()
    }
}

/// The same, at team scope.
fn team_request(team_id: &str) -> SetInheritedSettingRequest {
    SetInheritedSettingRequest {
        scope: SettingScope::Team as i32,
        team_id: Some(team_id.into()),
        name: OWNER_READS_OWN_RECORD.into(),
        value: Some(SettingValue::Off as i32),
        ..Default::default()
    }
}

async fn refused(svc: &IamDb, req: SetInheritedSettingRequest) -> tonic::Status {
    svc.set_inherited_setting(Request::new(req))
        .await
        .expect_err("this request must be refused")
}

#[tokio::test]
async fn the_organisations_value_and_lock_are_both_written() {
    // BOTH COLUMNS AT ONCE AND AWAY FROM THE SEED. Migration 12 ships
    // `(ON, locked)`, so a handler that wrote only the value — or only the lock —
    // would still be read back as correct against a request that asked for either
    // one of them alone. `(OFF, unlocked)` differs in both.
    let svc = fresh("iam_db_test_set_org").await;

    let got = svc
        .set_inherited_setting(Request::new(org_request()))
        .await
        .expect("write the organisation's level")
        .into_inner();

    let setting = got.setting.expect("the answer carries the setting whole");
    assert_eq!(setting.org_value, SettingValue::Off as i32);
    assert!(!setting.org_locked);

    // The ROW, not the echo. D48 is why the response is not proof of the write.
    let row: (i32, bool) =
        sqlx::query_as("SELECT value, locked FROM iam_org_setting WHERE name = ?")
            .bind(OWNER_READS_OWN_RECORD)
            .fetch_one(svc.pool())
            .await
            .expect("read the row back");
    assert_eq!(row, (SettingValue::Off as i32, false));

    // AND BACK, because a lock that can only be cleared is not a lock. The verb
    // states a wanted RESULT, so the reverse write must land the same way.
    let back = svc
        .set_inherited_setting(Request::new(SetInheritedSettingRequest {
            value: Some(SettingValue::On as i32),
            locked: Some(true),
            ..org_request()
        }))
        .await
        .expect("state the other value")
        .into_inner()
        .setting
        .expect("setting");
    assert_eq!(back.org_value, SettingValue::On as i32);
    assert!(back.org_locked);
}

#[tokio::test]
async fn a_team_override_is_written_and_comes_back_in_the_answer() {
    let svc = fresh("iam_db_test_set_team").await;
    seed_team(&svc, "yadgar:team:a").await;

    let setting = svc
        .set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("write one team's override")
        .into_inner()
        .setting
        .expect("setting");

    assert_eq!(
        setting.team_override.get("yadgar:team:a"),
        Some(&(SettingValue::Off as i32))
    );
    assert_eq!(overrides_for(&svc, "yadgar:team:a").await, 1);
    // STILL THE INPUTS, NEVER THE ANSWER: the seeded organisation is locked, so
    // this override is inert — and it is stored and returned anyway.
    assert!(setting.org_locked);
    assert_eq!(setting.org_value, SettingValue::On as i32);
}

#[tokio::test]
async fn re_stating_a_team_override_replaces_the_value_and_never_reports_not_found() {
    // **THE ORDINARY PATH THE RACE TEST CANNOT SEE.** Ledger 704 moved the team
    // predicate into the INSERT, and a zero match now means "no live team" and
    // renders NOT_FOUND. So the one way that change breaks a request nobody was
    // worried about is a LIVE team whose upsert reports zero — and that is a
    // question about row counts rather than about liveness.
    //
    // `sqlx-mysql` hardcodes `Capabilities::FOUND_ROWS` (`connection/stream.rs`)
    // with no `MySqlConnectOptions` knob to turn it off, so every statement here
    // reports MATCHED rows rather than CHANGED ones: a fresh insert is 1, an
    // `ON DUPLICATE KEY UPDATE` that CHANGES the value is 2, and one that changes
    // nothing is still 1. Never 0 for a team that is there. Asserted through the
    // handler in all three shapes rather than by reading the number back, because
    // the number is the code's own output and the refusal is what a caller sees.
    let svc = fresh("iam_db_test_reset_team").await;
    seed_team(&svc, "yadgar:team:a").await;

    // Fresh insert, identical repeat, then a CHANGED value — the three counts
    // FOUND_ROWS tells apart, and the middle one is the case a naive
    // `rows_affected() == 0` check would have refused.
    for (n, value) in [
        (1, SettingValue::Off),
        (2, SettingValue::Off),
        (3, SettingValue::On),
    ] {
        let setting = svc
            .set_inherited_setting(Request::new(SetInheritedSettingRequest {
                value: Some(value as i32),
                ..team_request("yadgar:team:a")
            }))
            .await
            .unwrap_or_else(|e| panic!("call {n} states an override for a LIVE team: {e:?}"))
            .into_inner()
            .setting
            .expect("setting");
        assert_eq!(
            setting.team_override.get("yadgar:team:a"),
            Some(&(value as i32)),
            "call {n} must leave the value it stated in force"
        );
    }

    assert_eq!(
        overrides_for(&svc, "yadgar:team:a").await,
        1,
        "three calls upsert onto one row rather than accreting three"
    );
}

#[tokio::test]
async fn clearing_a_team_override_deletes_the_row_rather_than_storing_a_value() {
    // ADR-0524's WITHDRAWAL, and the assertion is on PRESENCE at three levels:
    // the row is gone from the table, the key is gone from the map, and the map
    // is empty. A handler that stored SETTING_VALUE_UNSPECIFIED instead of
    // deleting would satisfy none of them, and one that returned a default-built
    // message would fail the count.
    let svc = fresh("iam_db_test_clear_team").await;
    seed_team(&svc, "yadgar:team:a").await;

    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("state an override to withdraw");
    assert_eq!(overrides_for(&svc, "yadgar:team:a").await, 1);

    let setting = svc
        .set_inherited_setting(Request::new(SetInheritedSettingRequest {
            value: None,
            clear: true,
            ..team_request("yadgar:team:a")
        }))
        .await
        .expect("withdraw the override")
        .into_inner()
        .setting
        .expect("setting");

    assert_eq!(
        overrides_for(&svc, "yadgar:team:a").await,
        0,
        "clearing removes the row; storing UNSPECIFIED would leave one"
    );
    assert!(
        !setting.team_override.contains_key("yadgar:team:a"),
        "a withdrawn override is ABSENT from the map, never present holding a zero"
    );
    assert!(setting.team_override.is_empty());
}

#[tokio::test]
async fn an_absent_value_without_clear_is_refused_rather_than_read_as_a_deletion() {
    // **THE ONE ADR-0524 EXISTS FOR.** With `value` optional and nothing else,
    // the request that simply OMITS the value is the DESTRUCTIVE one — so the
    // most likely accident destroys configuration. This asserts the refusal AND
    // that the row survived it, because a refusal reported after the delete would
    // pass an assertion on the status code alone.
    let svc = fresh("iam_db_test_absent_value").await;
    seed_team(&svc, "yadgar:team:a").await;
    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("state an override");

    for scope in [SettingScope::Org, SettingScope::Team] {
        let req = match scope {
            SettingScope::Team => SetInheritedSettingRequest {
                value: None,
                ..team_request("yadgar:team:a")
            },
            _ => SetInheritedSettingRequest {
                value: None,
                ..org_request()
            },
        };
        assert_eq!(
            refused(&svc, req).await.code(),
            tonic::Code::InvalidArgument,
            "an omitted value states nothing at all, at {scope:?} scope"
        );
    }

    assert_eq!(
        overrides_for(&svc, "yadgar:team:a").await,
        1,
        "the refused request destroyed nothing"
    );
}

#[tokio::test]
async fn an_explicitly_unspecified_value_is_a_refusal_and_never_a_withdrawal() {
    // SENT EXPLICITLY, THE ZERO IS STILL A REFUSAL. It is what a caller that
    // populated nothing sends, and reading it as "remove this team's override"
    // would let an unpopulated field destroy configuration silently.
    //
    // THIS IS THE OTHER HALF OF THE MUTATION ABOVE. `value.unwrap_or_default()`
    // collapses `None` and `Some(UNSPECIFIED)` into one case, which kills that
    // test and this one together — so they are written as two, against the two
    // shapes the collapse merges.
    let svc = fresh("iam_db_test_explicit_zero").await;
    seed_team(&svc, "yadgar:team:a").await;
    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("state an override");

    let req = SetInheritedSettingRequest {
        value: Some(SettingValue::Unspecified as i32),
        ..team_request("yadgar:team:a")
    };
    assert_eq!(
        refused(&svc, req).await.code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        overrides_for(&svc, "yadgar:team:a").await,
        1,
        "an explicit zero is refused, and refusing it destroys nothing"
    );
}

#[tokio::test]
async fn clearing_an_override_that_is_not_there_succeeds_and_changes_nothing() {
    // A STATE-SETTER THAT REFUSED TO STATE A RESULT ALREADY HELD would make the
    // retry of a lost-but-successful clear read as a failure (ADR-0524).
    let svc = fresh("iam_db_test_clear_absent").await;
    seed_team(&svc, "yadgar:team:a").await;

    let setting = svc
        .set_inherited_setting(Request::new(SetInheritedSettingRequest {
            value: None,
            clear: true,
            ..team_request("yadgar:team:a")
        }))
        .await
        .expect("clearing nothing is not an error")
        .into_inner()
        .setting
        .expect("setting");

    assert_eq!(overrides_for(&svc, "yadgar:team:a").await, 0);
    assert!(setting.team_override.is_empty());
}

#[tokio::test]
async fn clear_and_a_value_together_are_refused() {
    // Two contradicting instructions, and neither is the obvious one to discard.
    let svc = fresh("iam_db_test_clear_and_value").await;
    seed_team(&svc, "yadgar:team:a").await;

    let req = SetInheritedSettingRequest {
        clear: true,
        ..team_request("yadgar:team:a")
    };
    assert_eq!(
        refused(&svc, req).await.code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn the_organisations_value_cannot_be_cleared() {
    // There is no state in which the organisation holds no value — the
    // resolution's FIRST step refuses an unset org_value — so "clear the
    // organisation's value" names a state this setting does not have.
    let svc = fresh("iam_db_test_clear_org").await;

    let req = SetInheritedSettingRequest {
        value: None,
        clear: true,
        ..org_request()
    };
    assert_eq!(
        refused(&svc, req).await.code(),
        tonic::Code::InvalidArgument
    );

    let value: i32 = sqlx::query_scalar("SELECT value FROM iam_org_setting WHERE name = ?")
        .bind(OWNER_READS_OWN_RECORD)
        .fetch_one(svc.pool())
        .await
        .expect("the seeded row is still there");
    assert_eq!(value, SettingValue::On as i32);
}

#[tokio::test]
async fn a_scope_that_names_no_level_is_refused_rather_than_defaulted() {
    // proto3 enums are OPEN, so an unrecognised number arrives intact rather than
    // collapsing to the zero. A `match` whose fallthrough wrote the ORGANISATION's
    // policy would answer a request that named neither level with the widest
    // write there is.
    let svc = fresh("iam_db_test_scope").await;

    for scope in [SettingScope::Unspecified as i32, 7] {
        let req = SetInheritedSettingRequest {
            scope,
            ..org_request()
        };
        assert_eq!(
            refused(&svc, req).await.code(),
            tonic::Code::InvalidArgument,
            "scope {scope} names no level this contract declares"
        );
    }
}

#[tokio::test]
async fn a_team_id_is_required_at_team_scope_and_refused_at_organisation_scope() {
    // ABSENT and PRESENT-AND-EMPTY are two cases at team scope, and this boundary
    // has to refuse the second: an empty key in the override map is a row no
    // record's team will ever match.
    //
    // At ORG scope a team id is a caller that meant TEAM (D27: one organisation),
    // and ignoring it would write the organisation's policy while the caller
    // believed they wrote one team's.
    let svc = fresh("iam_db_test_team_id").await;

    for team_id in [None, Some(String::new())] {
        let req = SetInheritedSettingRequest {
            team_id,
            ..team_request("unused")
        };
        assert_eq!(
            refused(&svc, req).await.code(),
            tonic::Code::InvalidArgument
        );
    }

    let req = SetInheritedSettingRequest {
        team_id: Some("yadgar:team:a".into()),
        ..org_request()
    };
    assert_eq!(
        refused(&svc, req).await.code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn the_lock_is_required_at_organisation_scope_and_refused_at_team_scope() {
    // AT TEAM SCOPE, BOTH VALUES. A bare bool could only ever refuse `true`,
    // because `false` is indistinguishable from unset — and a team sending
    // `locked: false` would have its instruction silently discarded, which is
    // precisely the case the refusal exists for.
    let svc = fresh("iam_db_test_lock").await;
    seed_team(&svc, "yadgar:team:a").await;

    let req = SetInheritedSettingRequest {
        locked: None,
        ..org_request()
    };
    assert_eq!(
        refused(&svc, req).await.code(),
        tonic::Code::InvalidArgument,
        "an unstated lock is the permissive half of a policy nobody chose"
    );

    for locked in [Some(true), Some(false)] {
        let req = SetInheritedSettingRequest {
            locked,
            ..team_request("yadgar:team:a")
        };
        assert_eq!(
            refused(&svc, req).await.code(),
            tonic::Code::InvalidArgument,
            "a team cannot state whether teams may override, not even by saying false"
        );
    }
}

#[tokio::test]
async fn a_name_outside_the_vocabulary_is_refused_rather_than_stored() {
    // A store that accepted free text would accrete settings nothing reads, and a
    // typo would be persisted as a new setting instead of being refused at the
    // call that made it.
    let svc = fresh("iam_db_test_name").await;

    for name in ["", "owner_reads_own_recrod", "some_other_setting"] {
        let req = SetInheritedSettingRequest {
            name: name.into(),
            ..org_request()
        };
        assert_eq!(
            refused(&svc, req).await.code(),
            tonic::Code::InvalidArgument
        );
    }

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam_org_setting")
        .fetch_one(svc.pool())
        .await
        .expect("count");
    assert_eq!(stored, 1, "only the seeded row exists; nothing accreted");
}

#[tokio::test]
async fn the_answer_carries_the_other_level_and_every_other_teams_override() {
    // NOT THE ECHO D48 REFUSES. The caller sent ONE level; what comes back is the
    // other level and every OTHER team's override, which the caller did not send
    // and has no other way to read on this boundary.
    let svc = fresh("iam_db_test_whole_answer").await;
    seed_team(&svc, "yadgar:team:a").await;
    seed_team(&svc, "yadgar:team:b").await;

    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("team a");

    let setting = svc
        .set_inherited_setting(Request::new(SetInheritedSettingRequest {
            value: Some(SettingValue::On as i32),
            ..team_request("yadgar:team:b")
        }))
        .await
        .expect("team b")
        .into_inner()
        .setting
        .expect("setting");

    assert_eq!(
        setting.team_override.get("yadgar:team:a"),
        Some(&(SettingValue::Off as i32)),
        "a team the caller did not name comes back too"
    );
    assert_eq!(
        setting.team_override.get("yadgar:team:b"),
        Some(&(SettingValue::On as i32))
    );
    assert_eq!(setting.org_value, SettingValue::On as i32);
    assert!(setting.org_locked, "the OTHER level travels back as well");
}

#[tokio::test]
async fn the_write_is_visible_to_the_read_the_credential_path_makes() {
    // ONE SETTING, TWO ARMS. A write that landed in a table `ResolveCredential`
    // does not read would pass every assertion above and change nothing anybody
    // sees.
    let svc = fresh("iam_db_test_write_then_resolve").await;
    seed(&svc, &[70u8; 32], &[70u8; 32]).await;
    seed_team(&svc, "yadgar:team:a").await;

    svc.set_inherited_setting(Request::new(SetInheritedSettingRequest {
        value: Some(SettingValue::Off as i32),
        locked: Some(false),
        ..org_request()
    }))
    .await
    .expect("organisation");
    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("team");

    let got = svc
        .resolve_credential(Request::new(ResolveCredentialRequest {
            token_hash: vec![70u8; 32],
        }))
        .await
        .expect("resolve")
        .into_inner()
        .owner_reads_own_record
        .expect("the setting travels with the identity");

    assert_eq!(got.org_value, SettingValue::Off as i32);
    assert!(!got.org_locked);
    assert_eq!(
        got.team_override.get("yadgar:team:a"),
        Some(&(SettingValue::Off as i32))
    );
}

#[tokio::test]
async fn an_unverified_actor_changes_what_is_recorded_and_never_what_happens() {
    // ADR-0534. The field is INERT BY CONSTRUCTION: it is self-asserted, this
    // boundary cannot verify it, and it MUST NOT be an authorisation input.
    //
    // The property a test can hold is that it decides NOTHING — the same request
    // stamped with an actor, with an empty actor, and with none at all reaches the
    // same state and the same answer. A handler that read it into a WHERE clause,
    // or refused a request lacking it, dies here.
    let svc = fresh("iam_db_test_actor").await;
    seed_team(&svc, "yadgar:team:a").await;

    let mut answers = Vec::new();
    for actor in [
        None,
        Some(UnverifiedActor::default()),
        Some(UnverifiedActor {
            user_id: "yadgar:user:nobody-real".into(),
        }),
    ] {
        answers.push(
            svc.set_inherited_setting(Request::new(SetInheritedSettingRequest {
                unverified_actor: actor,
                ..team_request("yadgar:team:a")
            }))
            .await
            .expect("an actor decides nothing, including whether this succeeds")
            .into_inner()
            .setting
            .expect("setting"),
        );
    }

    assert!(
        answers.windows(2).all(|w| w[0] == w[1]),
        "who the gateway believed was calling must not change the answer"
    );
    assert_eq!(overrides_for(&svc, "yadgar:team:a").await, 1);
}

#[tokio::test]
async fn an_override_for_a_team_that_does_not_exist_is_not_found_rather_than_unavailable() {
    // THE FOREIGN KEY IS NOT THE ERROR MESSAGE. Left to fire, `iam_team_setting_override`'s
    // constraint renders through `db()` as UNAVAILABLE — a retryable status for a
    // request that can never succeed, which is the same defect
    // `SetRateLimitOverride` fixes with `live_user`.
    let svc = fresh("iam_db_test_unknown_team").await;

    let refusal = refused(&svc, team_request("yadgar:team:never-created")).await;
    assert_eq!(refusal.code(), tonic::Code::NotFound);

    // A CLEAR IS NOT REFUSED THE SAME WAY, and the asymmetry is the point: a
    // clear names a row to REMOVE rather than a team to write to, so there is no
    // foreign key to satisfy — and migration 11 leaves the override a
    // soft-deleted team strands to be cleared by exactly this call.
    svc.set_inherited_setting(Request::new(SetInheritedSettingRequest {
        value: None,
        clear: true,
        ..team_request("yadgar:team:never-created")
    }))
    .await
    .expect("clearing an override for a team that is gone is not an error");
}

// ---------------------------------------------------------------------------
// D9's key on SetInheritedSetting, in both halves.
//
// **THE SECOND HALF IS THE ONE THAT NEEDED A LEDGER.** The verb ASSIGNS a level
// rather than toggling it, so an identical retry converges on the same state
// with or without a key — which is why `SetUserAdmin` and `SetRateLimitOverride`
// need no ledger at all. What that shape cannot do is refuse a repeated key
// carrying a DIFFERENT request, and D9 as amended says a differing payload is a
// refusal rather than a replay: replaying it hands the first request's outcome
// to a caller who sent a second, and reports success.
//
// The membership of the comparison is the contract's, not this file's: `scope`,
// `team_id`, `name`, `value`, `locked` and `clear` — and NOT `unverified_actor`,
// which is inert by construction (ADR-0534).
// ---------------------------------------------------------------------------

fn keyed(key: &str, req: SetInheritedSettingRequest) -> SetInheritedSettingRequest {
    SetInheritedSettingRequest {
        idempotency: Some(Idempotency { key: key.into() }),
        ..req
    }
}

async fn org_value(svc: &IamDb) -> i32 {
    sqlx::query_scalar("SELECT value FROM iam_org_setting WHERE name = ?")
        .bind(OWNER_READS_OWN_RECORD)
        .fetch_one(svc.pool())
        .await
        .expect("read the organisation's value")
}

#[tokio::test]
async fn a_replayed_key_re_derives_the_setting_and_writes_nothing() {
    // **THE REPLAY MUST NOT RE-APPLY THE WRITE.** A state-setter re-run reaches
    // the same state only if nothing else changed the level in between — and if
    // something did, re-running would UNDO a legitimate change and report
    // success. The lever here is a direct SQL change made between the two
    // deliveries: a handler that ignored the ledger and simply wrote again would
    // put OFF back.
    let svc = fresh("iam_db_test_setting_replay").await;

    svc.set_inherited_setting(Request::new(keyed("k-replay", org_request())))
        .await
        .expect("the first delivery");
    assert_eq!(org_value(&svc).await, SettingValue::Off as i32);

    sqlx::query("UPDATE iam_org_setting SET value = ? WHERE name = ?")
        .bind(SettingValue::On as i32)
        .bind(OWNER_READS_OWN_RECORD)
        .execute(svc.pool())
        .await
        .expect("somebody else changes the level");

    let setting = svc
        .set_inherited_setting(Request::new(keyed("k-replay", org_request())))
        .await
        .expect("a replayed key is not an error")
        .into_inner()
        .setting
        .expect("setting");

    assert_eq!(
        org_value(&svc).await,
        SettingValue::On as i32,
        "the replay wrote nothing; re-running the assignment would have put OFF back"
    );
    assert_eq!(
        setting.org_value,
        SettingValue::On as i32,
        "the outcome is RE-DERIVED rather than replayed from a stored copy"
    );
}

#[tokio::test]
async fn a_key_reused_with_a_different_request_is_refused_rather_than_replayed() {
    // D9 AS AMENDED. Replaying it would hand the first request's outcome to a
    // caller who sent a second: the operation actually asked for is silently
    // discarded and the answer reports success. The caller cannot tell.
    //
    // Each case differs from the first delivery in exactly ONE field of the
    // contract's enumeration, so a comparison that dropped that field passes
    // every other case and fails this one.
    let svc = fresh("iam_db_test_setting_differs").await;
    seed_team(&svc, "yadgar:team:a").await;
    seed_team(&svc, "yadgar:team:b").await;

    svc.set_inherited_setting(Request::new(keyed("k-diff", team_request("yadgar:team:a"))))
        .await
        .expect("the first delivery");

    let differing = [
        (
            "value",
            SetInheritedSettingRequest {
                value: Some(SettingValue::On as i32),
                ..team_request("yadgar:team:a")
            },
        ),
        (
            "team_id",
            SetInheritedSettingRequest {
                ..team_request("yadgar:team:b")
            },
        ),
        (
            "scope and locked",
            SetInheritedSettingRequest { ..org_request() },
        ),
        (
            // PRESENCE, NOT VALUE. A withdrawal states no value at all; a
            // comparison that read an absent value as the zero would call this
            // the same request as one setting the override to UNSPECIFIED — a
            // value the contract refuses outright.
            "clear and an absent value",
            SetInheritedSettingRequest {
                value: None,
                clear: true,
                ..team_request("yadgar:team:a")
            },
        ),
    ];

    for (what, req) in differing {
        let refusal = svc
            .set_inherited_setting(Request::new(keyed("k-diff", req)))
            .await
            .expect_err(&format!(
                "a key reused with a different {what} must be refused"
            ));
        assert_eq!(refusal.code(), tonic::Code::InvalidArgument, "{what}");
    }

    assert_eq!(
        overrides_for(&svc, "yadgar:team:a").await,
        1,
        "the first delivery's override still stands"
    );
    assert_eq!(
        overrides_for(&svc, "yadgar:team:b").await,
        0,
        "and a refused delivery wrote nothing of its own"
    );
}

#[tokio::test]
async fn an_unverified_actor_is_never_part_of_the_payload_comparison() {
    // **ADR-0534's `INERT BY CONSTRUCTION`, AT THE ONE PLACE IT COULD STOP BEING
    // TRUE.** Including the actor in the comparison would refuse, with
    // INVALID_ARGUMENT, an IDENTICAL operation stamped by a different person —
    // a second administrator picking up a change the first one lost. The field
    // would then decide whether a request SUCCEEDS, which is a behavioural input
    // the four MUST NOTs exist to deny it.
    let svc = fresh("iam_db_test_setting_actor_key").await;
    seed_team(&svc, "yadgar:team:a").await;

    svc.set_inherited_setting(Request::new(keyed(
        "k-actor",
        SetInheritedSettingRequest {
            unverified_actor: Some(UnverifiedActor {
                user_id: "yadgar:user:first".into(),
            }),
            ..team_request("yadgar:team:a")
        },
    )))
    .await
    .expect("the first administrator");

    svc.set_inherited_setting(Request::new(keyed(
        "k-actor",
        SetInheritedSettingRequest {
            unverified_actor: Some(UnverifiedActor {
                user_id: "yadgar:user:second".into(),
            }),
            ..team_request("yadgar:team:a")
        },
    )))
    .await
    .expect("a second administrator retrying the SAME operation must not be refused");
}

#[tokio::test]
async fn an_empty_key_is_no_idempotency_at_all_for_a_setting_write() {
    // The empty string is not a key. Recording a ledger row on it would make two
    // unrelated writes collide on one row, and the second — differing, as
    // unrelated writes do — would be REFUSED under a key neither caller chose.
    let svc = fresh("iam_db_test_setting_empty_key").await;
    seed_team(&svc, "yadgar:team:a").await;

    svc.set_inherited_setting(Request::new(team_request("yadgar:team:a")))
        .await
        .expect("the first unkeyed write");
    svc.set_inherited_setting(Request::new(SetInheritedSettingRequest {
        value: Some(SettingValue::On as i32),
        ..team_request("yadgar:team:a")
    }))
    .await
    .expect("an unkeyed write must never be read as a replay of an unrelated one");

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam_inherited_setting_write")
        .fetch_one(svc.pool())
        .await
        .expect("count");
    assert_eq!(stored, 0, "no ledger row is keyed on the empty string");
}

#[tokio::test]
async fn a_refused_request_records_no_claim() {
    // A ledger row written for a request that was REFUSED would spend the key: a
    // caller correcting the mistake and retrying under the same key would then be
    // told their corrected request differs from one that never happened.
    let svc = fresh("iam_db_test_setting_refusal_key").await;

    let bad = SetInheritedSettingRequest {
        locked: None,
        ..org_request()
    };
    assert_eq!(
        refused(&svc, keyed("k-refused", bad)).await.code(),
        tonic::Code::InvalidArgument
    );

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam_inherited_setting_write")
        .fetch_one(svc.pool())
        .await
        .expect("count");
    assert_eq!(
        stored, 0,
        "a refusal leaves no ledger row, no row and no key spent"
    );

    svc.set_inherited_setting(Request::new(keyed("k-refused", org_request())))
        .await
        .expect("the corrected request may reuse the key it never spent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_deliveries_of_one_setting_key_agree() {
    // THE CASE A SEQUENTIAL TEST CANNOT REACH. A retrying load balancer delivers
    // a write more than once, and the two deliveries can be IN FLIGHT AT THE SAME
    // TIME rather than one after the other.
    //
    // MUTATION THIS CATCHES: recording the claim with a plain
    // `INSERT … ON DUPLICATE KEY UPDATE`, or dropping the re-check on the
    // duplicate branch. Both deliveries then pass the first ledger read — neither
    // has written yet — and the loser's DIFFERING payload is applied and recorded
    // over the winner's. Every other test in this file is sequential and stays
    // green.
    //
    // NOT FIXABLE BY LOCKING THE LEDGER FIRST (ADR-0513): an InnoDB gap lock on
    // an absent row does not exclude another transaction's gap lock on the same
    // gap, and it DOES block the other's INSERT — so it turns the race into a
    // deadlock. The serialisation point is the INSERT itself, which takes a real
    // record lock.
    let svc = std::sync::Arc::new(fresh("iam_db_test_setting_race").await);
    seed_team(&svc, "yadgar:team:a").await;

    for round in 0..8 {
        let key = format!("k-race-{round}");
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

        // TWO DIFFERENT PAYLOADS UNDER ONE KEY, which is the shape that has an
        // answer a race can get wrong. Exactly one must win; the other must be
        // refused rather than silently applied over the winner.
        let mut handles = Vec::new();
        for value in [SettingValue::Off, SettingValue::On] {
            let svc = svc.clone();
            let barrier = barrier.clone();
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                svc.set_inherited_setting(Request::new(keyed(
                    &key,
                    SetInheritedSettingRequest {
                        value: Some(value as i32),
                        ..team_request("yadgar:team:a")
                    },
                )))
                .await
                .map(|r| r.into_inner())
            }));
        }

        let mut outcomes = Vec::new();
        for h in handles {
            outcomes.push(h.await.expect("no handler may panic"));
        }

        let winners = outcomes.iter().filter(|o| o.is_ok()).count();
        assert_eq!(
            winners, 1,
            "round {round}: exactly one delivery may win; the other carried a different \
             payload under the same key and must be refused"
        );
        for refusal in outcomes.iter().filter_map(|o| o.as_ref().err()) {
            assert_eq!(
                refusal.code(),
                tonic::Code::InvalidArgument,
                "round {round}"
            );
        }

        // AND THE STORE AGREES WITH THE WINNER. One ledger row, one override, and
        // the override holds what the ledger says was asked for — a loser that
        // wrote and then failed to record would break this even with the counts
        // right.
        let recorded: (i32, bool) = sqlx::query_as(
            "SELECT value, clear_requested FROM iam_inherited_setting_write
              WHERE idempotency_key = ?",
        )
        .bind(&key)
        .fetch_one(svc.pool())
        .await
        .expect("exactly one claim is recorded under this key");
        assert!(!recorded.1);

        let stored: i32 = sqlx::query_scalar(
            "SELECT value FROM iam_team_setting_override WHERE name = ? AND team_id = ?",
        )
        .bind(OWNER_READS_OWN_RECORD)
        .bind("yadgar:team:a")
        .fetch_one(svc.pool())
        .await
        .expect("the override");
        assert_eq!(
            stored, recorded.0,
            "round {round}: the stored override must be the one the recorded claim asked for"
        );
    }
}
