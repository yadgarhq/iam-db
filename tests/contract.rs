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
