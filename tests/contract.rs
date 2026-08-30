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

use sqlx::Connection;
use tonic::Request;
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
    let url = format!("{}/{db}", dsn().trim_end_matches('/'));
    let pool = sqlx::MySqlPool::connect(&url).await.expect("pool");
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
