//! ADR-0972 (2) and (3) on this boundary, against a real MariaDB: a
//! per-credential revoke checks the credential belongs to the named user, and
//! `ResolveCredential` returns the credential's `expires_at` read in the same
//! statement.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

async fn revoke(
    svc: &IamDb,
    credential_id: &str,
    user_id: &str,
) -> Result<RevokeCredentialResponse, tonic::Status> {
    svc.revoke_credential_as(
        Some(IAM_CALLER),
        Request::new(RevokeCredentialRequest {
            credential_id: credential_id.into(),
            user_id: user_id.into(),
            ..Default::default()
        }),
    )
    .await
    .map(|r| r.into_inner())
}

/// The stored `revoked_at` of a credential, as epoch seconds.
async fn revoked_at(svc: &IamDb, credential_id: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT CAST(UNIX_TIMESTAMP(revoked_at) AS SIGNED) FROM iam_credential WHERE id = ?",
    )
    .bind(credential_id)
    .fetch_one(svc.pool())
    .await
    .expect("read revoked_at")
}

#[tokio::test]
async fn revoking_another_users_credential_is_not_found_and_writes_nothing() {
    let svc = fresh("iam_db_revoke_other").await;
    let owner = person(&svc, 1).await;
    let other = person(&svc, 2).await;
    let credential = mint(&svc, &owner, 1, None).await.expect("mint");

    let err = revoke(&svc, &credential, &other)
        .await
        .expect_err("a credential of another user must not be revoked");

    assert_eq!(
        err.code(),
        Code::NotFound,
        "it reads exactly as an unknown id"
    );
    assert_eq!(revoked_at(&svc, &credential).await, None, "nothing written");
    assert_eq!(resolve(&svc, 1).await.user_id, owner, "still resolves");
}

#[tokio::test]
async fn revoking_an_already_revoked_own_credential_is_ok_with_zero_rows() {
    let svc = fresh("iam_db_revoke_again").await;
    let owner = person(&svc, 3).await;
    let credential = mint(&svc, &owner, 3, None).await.expect("mint");
    sqlx::query("UPDATE iam_credential SET revoked_at = '2001-02-03 04:05:06' WHERE id = ?")
        .bind(&credential)
        .execute(svc.pool())
        .await
        .expect("an earlier revocation");
    let before = revoked_at(&svc, &credential).await;

    let got = revoke(&svc, &credential, &owner)
        .await
        .expect("an already-revoked credential of this user is OK");

    assert_eq!(got.user_id, owner);
    assert_eq!(
        revoked_at(&svc, &credential).await,
        before,
        "the first revocation's timestamp stands"
    );
}

#[tokio::test]
async fn revoking_an_already_revoked_credential_of_another_user_is_not_found() {
    // The already-revoked OK is for THAT user only; for anybody else the pair
    // does not exist, and the answer must not reveal the row's state.
    let svc = fresh("iam_db_revoke_other_revoked").await;
    let owner = person(&svc, 4).await;
    let other = person(&svc, 5).await;
    let credential = mint(&svc, &owner, 4, None).await.expect("mint");
    revoke(&svc, &credential, &owner).await.expect("revoke");

    let err = revoke(&svc, &credential, &other)
        .await
        .expect_err("another user's credential is NOT_FOUND, revoked or not");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn a_revoke_without_a_user_id_is_invalid_argument_and_writes_nothing() {
    let svc = fresh("iam_db_revoke_no_user").await;
    let owner = person(&svc, 6).await;
    let credential = mint(&svc, &owner, 6, None).await.expect("mint");

    let err = revoke(&svc, &credential, "")
        .await
        .expect_err("user_id is required");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(revoked_at(&svc, &credential).await, None, "nothing written");
}

#[tokio::test]
async fn revoking_an_own_live_credential_stops_it_resolving_and_names_the_owner() {
    let svc = fresh("iam_db_revoke_own").await;
    let owner = person(&svc, 7).await;
    let credential = mint(&svc, &owner, 7, None).await.expect("mint");

    let got = revoke(&svc, &credential, &owner).await.expect("revoke");

    assert_eq!(got.user_id, owner);
    assert!(resolve(&svc, 7).await.user_id.is_empty());
}

#[tokio::test]
async fn resolve_returns_the_credentials_expiry() {
    let svc = fresh("iam_db_resolve_expiry").await;
    let owner = person(&svc, 8).await;
    let expires = at(7200);
    svc.create_credential_as(
        Some(IAM_CALLER),
        Request::new(CreateCredentialRequest {
            user_id: owner.clone(),
            token_hash: vec![8u8; 32],
            label: "laptop".into(),
            expires_at: Some(expires),
            ..Default::default()
        }),
    )
    .await
    .expect("mint with an expiry");

    let got = resolve(&svc, 8).await;

    assert_eq!(got.user_id, owner);
    assert_eq!(
        got.expires_at.map(|t| t.seconds),
        Some(expires.seconds),
        "the expiry the mint stored comes back on the resolve"
    );
}

#[tokio::test]
async fn resolve_returns_no_expiry_for_a_credential_minted_without_one() {
    // A legacy row: no backfill (ADR-0972 (3)), so absent means no expiry.
    let svc = fresh("iam_db_resolve_no_expiry").await;
    let owner = person(&svc, 9).await;
    mint(&svc, &owner, 9, None).await.expect("mint");

    let got = resolve(&svc, 9).await;

    assert_eq!(got.user_id, owner);
    assert_eq!(got.expires_at, None);
}

#[tokio::test]
async fn a_miss_carries_no_expiry() {
    let svc = fresh("iam_db_resolve_miss").await;
    let got = resolve(&svc, 10).await;
    assert!(got.user_id.is_empty());
    assert_eq!(got.expires_at, None);
}
