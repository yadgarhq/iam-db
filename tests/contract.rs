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
use yadgar_iam_db::pb::yadgar::common::v1::SettingValue;
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
    let svc = fresh("iam_db_test_live_writes").await;
    let (user_id, _cred) = seed(&svc, &[55u8; 32], &[55u8; 32]).await;
    soft_delete(&svc, &user_id).await;

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
            user_id,
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
}

#[tokio::test]
async fn promoting_an_unknown_user_is_not_found_but_re_asserting_a_flag_is_not() {
    // TWO REASONS FOR ZERO AFFECTED ROWS, and they are not the same answer.
    // MariaDB reports CHANGED rows rather than matched ones, so re-asserting a
    // flag the user already has affects nothing — and reading that as NOT_FOUND
    // would break the idempotence this RPC gets from assigning rather than
    // toggling. A mistyped id must still be refused.
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
