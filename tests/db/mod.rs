//! The real-MariaDB fixture shared by the ADR-0972 test targets
//! (`credential_epoch`, `enrolment_void`, `revoke_and_resolve`).
//!
//! A COPY OF `tests/contract.rs`'s own `fresh` and its handful of call helpers,
//! not a move: `contract.rs` is one target of nearly seven thousand lines, and
//! these three targets exist so ADR-0972's tests are read together rather than
//! appended to it. Like that file, this panics rather than skips without an
//! engine (D69).

// Each test target compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use sqlx::Connection;
use tonic::Request;
use yadgar_iam_db::pb::yadgar::common::v1::Idempotency;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::schema;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};
use yadgar_store::migrate::{LockOptions, MigrationSet};

pub const GOOD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
pub const OTHER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$b3RoZXI";

pub fn dsn() -> String {
    std::env::var("YADGAR_TEST_DSN")
        .expect("YADGAR_TEST_DSN is unset; these tests assert what a real MariaDB does")
}

/// An empty database named `db`, and a pool on it. Nothing is migrated.
pub async fn empty(db: &str) -> sqlx::MySqlPool {
    let mut root = sqlx::MySqlConnection::connect(&dsn())
        .await
        .expect("connect");
    for stmt in [
        format!("DROP DATABASE IF EXISTS {db}"),
        format!("CREATE DATABASE {db}"),
    ] {
        // AUDIT: `db` is a literal at every call site.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("reset database");
    }
    // Strip the DSN's own database before appending ours (see `contract.rs`).
    let base = dsn()
        .rsplit_once('/')
        .expect("dsn has a database component")
        .0
        .to_string();
    sqlx::MySqlPool::connect(&format!("{base}/{db}"))
        .await
        .expect("pool")
}

/// Apply `set` with the chart's shipped lock wait.
pub async fn migrate(pool: &sqlx::MySqlPool, set: &MigrationSet) {
    let lock = LockOptions::new(60).expect("60 seconds is a wait");
    yadgar_store::migrate::apply(pool, set, &lock)
        .await
        .expect("migrate");
}

/// A fresh, fully migrated store.
pub async fn fresh(db: &str) -> IamDb {
    let pool = empty(db).await;
    migrate(&pool, &schema::migrations().expect("migrations")).await;
    IamDb::new(pool)
}

/// Seconds from now, as the contract's epoch timestamp.
pub fn at(offset: i64) -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    prost_types::Timestamp {
        seconds: now + offset,
        nanos: 0,
    }
}

/// A person with no credential and no password, under blind index `[blind; 32]`.
pub async fn person(svc: &IamDb, blind: u8) -> String {
    svc.create_user_as(
        Some(IAM_CALLER),
        Request::new(CreateUserRequest {
            external_id_blind_index: vec![blind; 32],
            external_id_ciphertext: b"ciphertext".to_vec(),
            display_name_ciphertext: b"display".to_vec(),
            ..Default::default()
        }),
    )
    .await
    .expect("create user")
    .into_inner()
    .meta
    .expect("meta")
    .id
}

pub async fn set_password(svc: &IamDb, user_id: &str, hash: &str) {
    svc.set_password_as(
        Some(IAM_CALLER),
        Request::new(SetPasswordRequest {
            user_id: user_id.into(),
            argon2id_hash: hash.into(),
            ..Default::default()
        }),
    )
    .await
    .expect("set password");
}

/// What a Login reads: the hash and the epoch, for blind index `[blind; 32]`.
pub async fn password_hash(svc: &IamDb, blind: u8) -> GetPasswordHashResponse {
    svc.get_password_hash_as(
        Some(IAM_CALLER),
        Request::new(GetPasswordHashRequest {
            username_blind_index: vec![blind; 32],
            ..Default::default()
        }),
    )
    .await
    .expect("get password hash")
    .into_inner()
}

/// `CreateCredential` under token hash `[token; 32]`, checked against
/// `expected` when it is `Some`.
pub async fn mint(
    svc: &IamDb,
    user_id: &str,
    token: u8,
    expected: Option<u64>,
) -> Result<String, tonic::Status> {
    svc.create_credential_as(
        Some(IAM_CALLER),
        Request::new(CreateCredentialRequest {
            user_id: user_id.into(),
            token_hash: vec![token; 32],
            label: "laptop".into(),
            expected_credential_epoch: expected,
            ..Default::default()
        }),
    )
    .await
    .map(|r| r.into_inner().credential_id)
}

/// An enrolment for `user_id` under secret `[secret; 32]`, revoking or not.
pub async fn enrol(svc: &IamDb, user_id: &str, secret: u8, revoking: bool, expires_in: i64) {
    svc.create_enrolment_as(
        Some(IAM_CALLER),
        Request::new(CreateEnrolmentRequest {
            user_id: user_id.into(),
            secret_hash: vec![secret; 32],
            expires_at: Some(at(expires_in)),
            revoke_existing_credentials: revoking,
            ..Default::default()
        }),
    )
    .await
    .expect("create enrolment");
}

/// The bootstrap demand's enrolment (ADR-0655) for an administrator who has
/// never held a credential.
pub async fn enrol_bootstrap(svc: &IamDb, user_id: &str, secret: u8) {
    svc.create_enrolment_as(
        Some(IAM_CALLER),
        Request::new(CreateEnrolmentRequest {
            user_id: user_id.into(),
            secret_hash: vec![secret; 32],
            expires_at: Some(at(3600)),
            require_zero_credential_admin: true,
            ..Default::default()
        }),
    )
    .await
    .expect("create the bootstrap enrolment");
}

pub async fn make_admin(svc: &IamDb, user_id: &str) {
    svc.set_user_admin_as(
        Some(IAM_CALLER),
        Request::new(SetUserAdminRequest {
            user_id: user_id.into(),
            is_admin: true,
            ..Default::default()
        }),
    )
    .await
    .expect("set admin");
}

pub async fn redeem(svc: &IamDb, secret: u8, hash: &str, key: &str) -> RedeemEnrolmentResponse {
    svc.redeem_enrolment_as(
        Some(IAM_CALLER),
        Request::new(RedeemEnrolmentRequest {
            secret_hash: vec![secret; 32],
            argon2id_hash: hash.into(),
            idempotency: match key.is_empty() {
                true => None,
                false => Some(Idempotency { key: key.into() }),
            },
        }),
    )
    .await
    .expect("redeem must not error")
    .into_inner()
}

pub async fn revoke_all(
    svc: &IamDb,
    user_id: &str,
) -> Result<RevokeAllCredentialsResponse, tonic::Status> {
    svc.revoke_all_credentials_as(
        Some(IAM_CALLER),
        Request::new(RevokeAllCredentialsRequest {
            user_id: user_id.into(),
            ..Default::default()
        }),
    )
    .await
    .map(|r| r.into_inner())
}

/// Who `[token; 32]` resolves to; empty means no live credential matched.
pub async fn resolve(svc: &IamDb, token: u8) -> ResolveCredentialResponse {
    svc.resolve_credential_as(
        Some(IAM_CALLER),
        Request::new(ResolveCredentialRequest {
            token_hash: vec![token; 32],
            ..Default::default()
        }),
    )
    .await
    .expect("resolve must not error")
    .into_inner()
}

/// The stored epoch, read straight from the column.
pub async fn stored_epoch(svc: &IamDb, user_id: &str) -> u64 {
    sqlx::query_scalar("SELECT credential_epoch FROM iam_user WHERE id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("read the epoch")
}

/// How many credential rows `user_id` has, of any liveness.
pub async fn credential_rows(svc: &IamDb, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM iam_credential WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(svc.pool())
        .await
        .expect("count credentials")
}

/// The enrolment under `[secret; 32]`: `(spent, voided)`.
pub async fn enrolment_state(svc: &IamDb, secret: u8) -> (bool, bool) {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT CAST(spent_at IS NOT NULL AS SIGNED), CAST(voided_at IS NOT NULL AS SIGNED)
           FROM iam_enrolment WHERE secret_hash = ?",
    )
    .bind(vec![secret; 32])
    .fetch_one(svc.pool())
    .await
    .expect("read the enrolment");
    (row.0 != 0, row.1 != 0)
}

/// The stored password hash of `user_id`.
pub async fn stored_hash(svc: &IamDb, user_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT argon2id_hash FROM iam_password WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(svc.pool())
        .await
        .expect("read the password")
}

/// Wait long enough for a spawned statement to reach its lock.
pub async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}
