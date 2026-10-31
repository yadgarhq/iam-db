//! ADR-1019 (yaadgaar #337): an RPC bounds its pool acquire by the caller's
//! `grpc-timeout`, and the pool's `acquire_timeout` stays the ceiling.
//!
//! Real MariaDB named by `YADGAR_TEST_DSN` (D69: panics rather than skips).
//! Each case builds a ONE-connection pool on a fresh, migrated database and
//! holds that connection, so the RPC under test can only wait.
//!
//! `ResolveCredential` is the subject of the ceiling cases: its first store
//! step is the bounded acquire (`service::conn`), and it is the login hot path
//! a wedged store stalls first. Below them, ONE CASE PER SEAM that reaches the
//! store: each goes red when that seam's `Deadline::of` is replaced by
//! `Deadline::none()`, because the handler then waits the 5 s ceiling. The `grpc-timeout` header reaches the handler as it does
//! here: tonic's server builds the request's metadata from the HTTP headers
//! unchanged (`Request::from_http_parts`, tonic 0.14.6).

mod db;

use std::time::{Duration, Instant};

use sqlx::mysql::MySqlPoolOptions;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::common::v1::{SettingScope, SettingValue};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::schema;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

/// A migrated store whose pool holds ONE connection and waits at most
/// `acquire_timeout` for it.
async fn one_connection_store(name: &str, acquire_timeout: Duration) -> IamDb {
    let migrated = db::empty(name).await;
    db::migrate(&migrated, &schema::migrations().expect("migrations")).await;
    migrated.close().await;
    let base = db::dsn()
        .rsplit_once('/')
        .expect("dsn has a database component")
        .0
        .to_string();
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(acquire_timeout)
        .connect(&format!("{base}/{name}"))
        .await
        .expect("pool");
    IamDb::new(pool)
}

/// **A 300 MS CALLER AGAINST A 5 S CEILING: DEADLINE_EXCEEDED, BEFORE THE
/// CALLER GIVES UP.** Without the bound the handler waits the full 5 s for a
/// connection, long after the caller has gone.
#[tokio::test]
async fn an_exhausted_pool_answers_deadline_exceeded_before_the_callers_deadline() {
    let svc = one_connection_store("iamdb_deadline_bound", Duration::from_secs(5)).await;
    let _held = svc
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");

    let mut req = Request::new(ResolveCredentialRequest::default());
    req.set_timeout(Duration::from_millis(300));
    let started = Instant::now();
    let refused = svc
        .resolve_credential_as(Some(IAM_CALLER), req)
        .await
        .expect_err("no connection was free");
    let took = started.elapsed();

    assert_eq!(refused.code(), Code::DeadlineExceeded, "{refused:?}");
    assert!(
        took < Duration::from_millis(300),
        "answered after the caller's deadline: {took:?}"
    );
}

/// **NO DEADLINE: THE CEILING STILL HOLDS.** A caller that sends no
/// `grpc-timeout` waits the pool's own `acquire_timeout`, and gets the
/// UNAVAILABLE an exhausted pool has always answered.
#[tokio::test]
async fn without_a_deadline_the_acquire_fails_at_the_configured_ceiling() {
    let ceiling = Duration::from_millis(500);
    let svc = one_connection_store("iamdb_deadline_ceiling", ceiling).await;
    let _held = svc
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");

    let started = Instant::now();
    let refused = svc
        .resolve_credential_as(
            Some(IAM_CALLER),
            Request::new(ResolveCredentialRequest::default()),
        )
        .await
        .expect_err("no connection was free");
    let took = started.elapsed();

    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
    assert!(took >= ceiling, "gave up before the ceiling: {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}

/// **A DEADLINE LONGER THAN THE CEILING CHANGES NOTHING.** The ceiling is
/// never raised to meet the caller: a 30 s caller against a 500 ms ceiling
/// still gets the pool's UNAVAILABLE at 500 ms.
#[tokio::test]
async fn a_deadline_longer_than_the_ceiling_does_not_raise_it() {
    let ceiling = Duration::from_millis(500);
    let svc = one_connection_store("iamdb_deadline_no_raise", ceiling).await;
    let _held = svc
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");

    let mut req = Request::new(ResolveCredentialRequest::default());
    req.set_timeout(Duration::from_secs(30));
    let started = Instant::now();
    let refused = svc
        .resolve_credential_as(Some(IAM_CALLER), req)
        .await
        .expect_err("no connection was free");
    let took = started.elapsed();

    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
    assert!(took >= ceiling, "took {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}

/// A user id that passes `canonical_user_id`: lowercase uuidv7.
const DECLARED_USER: &str = "yadgar:user:0192f3c4-1a2b-7c3d-8e4f-0123456789ab";

/// Seconds from now, as the contract's epoch timestamp.
fn in_an_hour() -> prost_types::Timestamp {
    db::at(3600)
}

/// One seam against an exhausted pool: a 300 ms caller, a 5 s ceiling.
/// `$svc` is bound to the store and `$req` wraps a message in a request that
/// carries the 300 ms `grpc-timeout`; `$call` is the seam invocation.
macro_rules! bounded {
    ($db:literal, |$svc:ident, $req:ident| $call:expr) => {{
        let $svc = one_connection_store($db, Duration::from_secs(5)).await;
        let _held = $svc
            .pool()
            .acquire()
            .await
            .expect("hold the only connection");
        fn $req<T>(message: T) -> Request<T> {
            let mut req = Request::new(message);
            req.set_timeout(Duration::from_millis(300));
            req
        }
        let started = Instant::now();
        let refused = $call.await.expect_err("no connection was free");
        let took = started.elapsed();
        assert_eq!(refused.code(), Code::DeadlineExceeded, "{refused:?}");
        assert!(
            took < Duration::from_millis(300),
            "answered after the caller's deadline: {took:?}"
        );
    }};
}

#[tokio::test]
async fn get_password_hash_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_password_hash", |svc, timed| svc
        .get_password_hash_as(
            Some(IAM_CALLER),
            timed(GetPasswordHashRequest::default())
        ));
}

#[tokio::test]
async fn set_password_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_set_password", |svc, timed| svc.set_password_as(
        Some(IAM_CALLER),
        timed(SetPasswordRequest {
            user_id: DECLARED_USER.into(),
            argon2id_hash: db::GOOD_HASH.into(),
            ..Default::default()
        })
    ));
}

#[tokio::test]
async fn create_credential_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_create_credential", |svc, timed| svc
        .create_credential_as(
            Some(IAM_CALLER),
            timed(CreateCredentialRequest::default())
        ));
}

#[tokio::test]
async fn revoke_credential_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_revoke_credential", |svc, timed| svc
        .revoke_credential_as(
            Some(IAM_CALLER),
            timed(RevokeCredentialRequest {
                user_id: DECLARED_USER.into(),
                credential_id: "yadgar:credential:x".into(),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn revoke_all_credentials_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_revoke_all", |svc, timed| svc
        .revoke_all_credentials_as(
            Some(IAM_CALLER),
            timed(RevokeAllCredentialsRequest {
                user_id: DECLARED_USER.into(),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn create_user_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_create_user", |svc, timed| svc.create_user_as(
        Some(IAM_CALLER),
        timed(CreateUserRequest::default())
    ));
}

#[tokio::test]
async fn the_bootstrap_create_user_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_create_user_declared", |svc, timed| svc
        .create_user_as(
            Some(IAM_CALLER),
            timed(CreateUserRequest {
                user_id: DECLARED_USER.into(),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn create_enrolment_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_create_enrolment", |svc, timed| svc
        .create_enrolment_as(
            Some(IAM_CALLER),
            timed(CreateEnrolmentRequest {
                user_id: DECLARED_USER.into(),
                secret_hash: vec![7; 32],
                expires_at: Some(in_an_hour()),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn the_declared_create_enrolment_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_create_enrolment_declared", |svc, timed| svc
        .create_enrolment_as(
            Some(IAM_CALLER),
            timed(CreateEnrolmentRequest {
                user_id: DECLARED_USER.into(),
                secret_hash: vec![8; 32],
                expires_at: Some(in_an_hour()),
                require_zero_credential_admin: true,
                admin_from_team: true,
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn redeem_enrolment_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_redeem", |svc, timed| svc.redeem_enrolment_as(
        Some(IAM_CALLER),
        timed(RedeemEnrolmentRequest {
            secret_hash: vec![9; 32],
            argon2id_hash: db::GOOD_HASH.into(),
            ..Default::default()
        })
    ));
}

#[tokio::test]
async fn list_credentials_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_list_credentials", |svc, timed| svc
        .list_credentials_as(
            Some(IAM_CALLER),
            timed(ListCredentialsRequest {
                user_id: DECLARED_USER.into(),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn set_user_admin_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_set_user_admin", |svc, timed| svc
        .set_user_admin_as(
            Some(IAM_CALLER),
            timed(SetUserAdminRequest {
                user_id: DECLARED_USER.into(),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn set_rate_limit_override_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_set_rate_limit", |svc, timed| svc
        .set_rate_limit_override_as(
            Some(IAM_CALLER),
            timed(SetRateLimitOverrideRequest {
                user_id: DECLARED_USER.into(),
                module: "task".into(),
                kind: yadgar_iam_db::pb::yadgar::telemetry::v1::Kind::Read as i32,
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn set_inherited_setting_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_set_setting", |svc, timed| svc
        .set_inherited_setting_as(
            Some(IAM_CALLER),
            timed(SetInheritedSettingRequest {
                scope: SettingScope::Org as i32,
                name: "owner_reads_own_record".into(),
                value: Some(SettingValue::Off as i32),
                locked: Some(false),
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn sync_teams_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_sync_teams", |svc, timed| svc.sync_teams_as(
        Some(IAM_CALLER),
        timed(SyncTeamsRequest::default())
    ));
}

#[tokio::test]
async fn get_key_identity_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_get_key_identity", |svc, timed| svc
        .get_key_identity_as(
            Some(IAM_CALLER),
            timed(GetKeyIdentityRequest {
                key_fingerprint: vec![1; 32],
                derivation_version: 1,
            })
        ));
}

#[tokio::test]
async fn set_key_identity_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_set_key_identity", |svc, timed| svc
        .set_key_identity_as(
            Some(IAM_CALLER),
            timed(SetKeyIdentityRequest {
                key_fingerprint: vec![1; 32],
                derivation_version: 1,
                ..Default::default()
            })
        ));
}

#[tokio::test]
async fn list_key_identity_evidence_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_list_key_evidence", |svc, timed| svc
        .list_key_identity_evidence_as(
            Some(IAM_CALLER),
            timed(ListKeyIdentityEvidenceRequest::default())
        ));
}

#[tokio::test]
async fn adopt_key_identity_is_bounded_by_the_callers_deadline() {
    bounded!("iamdb_dl_adopt_key_identity", |svc, timed| svc
        .adopt_key_identity_as(
            Some(IAM_CALLER),
            timed(AdoptKeyIdentityRequest {
                key_fingerprint: vec![1; 32],
                derivation_version: 1,
                evidence_user_ids: vec!["yadgar:user:x".into()],
                ..Default::default()
            })
        ));
}

/// The connection id the next borrower of `svc`'s one-connection pool gets.
async fn next_connection_id(svc: &IamDb) -> u64 {
    let mut conn = tokio::time::timeout(Duration::from_secs(5), svc.pool().acquire())
        .await
        .expect("a connection within 5 s")
        .expect("acquire");
    sqlx::query_scalar("SELECT CONNECTION_ID()")
        .fetch_one(&mut *conn)
        .await
        .expect("connection id")
}

/// **A COMPLETED RPC GIVES ITS CONNECTION BACK.** Close-on-cancel must not
/// become close-always: an RPC that runs to the end, here with an error
/// answer, leaves the same connection in the pool.
#[tokio::test]
async fn a_completed_rpc_returns_its_connection_to_the_pool() {
    let svc = one_connection_store("iamdb_deadline_reuse", Duration::from_secs(5)).await;
    let before = next_connection_id(&svc).await;
    let refused = svc
        .set_user_admin_as(
            Some(IAM_CALLER),
            Request::new(SetUserAdminRequest {
                user_id: DECLARED_USER.into(),
                ..Default::default()
            }),
        )
        .await
        .expect_err("no such user");
    assert_eq!(refused.code(), Code::NotFound, "{refused:?}");
    assert_eq!(
        next_connection_id(&svc).await,
        before,
        "the RPC's connection went back to the pool"
    );
}
