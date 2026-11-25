//! `LookupUser` answers `NOT_FOUND`, never `OK` with an empty `user_id`, when no
//! live `iam_user` row carries the 32-byte blind index (yaadgaar 270), against a
//! real MariaDB.
//!
//! Four ways to find nothing: an unknown index, an index one byte off, an empty
//! store and a soft-deleted user. Each has a triangulating case with other
//! inputs, and one table test pins the property over a spread of indexes.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

/// `LookupUser` as the admitted caller, for the blind index `blind`.
async fn lookup(svc: &IamDb, blind: Vec<u8>) -> Result<LookupUserResponse, tonic::Status> {
    svc.lookup_user_as(
        Some(IAM_CALLER),
        Request::new(LookupUserRequest {
            external_id_blind_index: blind,
            unverified_actor: None,
        }),
    )
    .await
    .map(|r| r.into_inner())
}

#[tokio::test]
async fn an_unknown_blind_index_is_not_found() {
    // AC3: a store with one person at vec![9u8; 32], lookup vec![3u8; 32].
    let svc = fresh("iam_db_lookup_nf_unknown").await;
    let _ = person(&svc, 9).await;

    let err = lookup(&svc, vec![3u8; 32])
        .await
        .expect_err("no row carries this index");
    assert_eq!(err.code(), Code::NotFound);

    // AC3: triangulation, another unknown index in the same store.
    let err = lookup(&svc, vec![200u8; 32])
        .await
        .expect_err("no row carries this index either");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn an_index_one_byte_off_is_not_found() {
    // AC3: a person at vec![9u8; 32], lookup 31 bytes of 9 followed by one byte 10.
    let svc = fresh("iam_db_lookup_nf_one_off").await;
    let _ = person(&svc, 9).await;

    let mut last_byte_off = vec![9u8; 31];
    last_byte_off.push(10);
    let err = lookup(&svc, last_byte_off)
        .await
        .expect_err("the last byte differs");
    assert_eq!(err.code(), Code::NotFound);

    // AC3: triangulation, the first byte differs instead.
    let mut first_byte_off = vec![9u8; 32];
    first_byte_off[0] = 10;
    let err = lookup(&svc, first_byte_off)
        .await
        .expect_err("the first byte differs");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn an_empty_migrated_store_is_not_found() {
    // AC3: an empty migrated store, lookup vec![1u8; 32].
    let svc = fresh("iam_db_lookup_nf_empty").await;

    let err = lookup(&svc, vec![1u8; 32])
        .await
        .expect_err("nobody is stored");
    assert_eq!(err.code(), Code::NotFound);

    // AC3: triangulation, another index on the same empty store.
    let err = lookup(&svc, vec![77u8; 32])
        .await
        .expect_err("nobody is stored");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn a_soft_deleted_user_is_not_found() {
    // AC3: a person at vec![12u8; 32], found by lookup, then soft-deleted.
    let svc = fresh("iam_db_lookup_nf_deleted").await;
    let id = person(&svc, 12).await;
    let live = lookup(&svc, vec![12u8; 32])
        .await
        .expect("a live person is found first");
    assert_eq!(live.user_id, id);

    sqlx::query("UPDATE iam_user SET deleted_at = NOW() WHERE id = ?")
        .bind(&id)
        .execute(svc.pool())
        .await
        .expect("soft-delete the person");

    let err = lookup(&svc, vec![12u8; 32])
        .await
        .expect_err("a soft-deleted row is not found");
    assert_eq!(err.code(), Code::NotFound);

    // AC3: triangulation, a second person, soft-deleted the same way, while a
    // third stays live and is still found under its own id.
    let gone = person(&svc, 13).await;
    let kept = person(&svc, 14).await;
    sqlx::query("UPDATE iam_user SET deleted_at = NOW() WHERE id = ?")
        .bind(&gone)
        .execute(svc.pool())
        .await
        .expect("soft-delete the second person");
    let err = lookup(&svc, vec![13u8; 32])
        .await
        .expect_err("the second soft-deleted row is not found");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(
        lookup(&svc, vec![14u8; 32]).await.expect("live").user_id,
        kept
    );
}

#[tokio::test]
async fn no_miss_is_ever_ok_with_an_empty_user_id() {
    // AC3: property, never Ok with an empty user_id, over a table of misses.
    let svc = fresh("iam_db_lookup_nf_property").await;
    let _ = person(&svc, 9).await;
    let deleted = person(&svc, 12).await;
    sqlx::query("UPDATE iam_user SET deleted_at = NOW() WHERE id = ?")
        .bind(&deleted)
        .execute(svc.pool())
        .await
        .expect("soft-delete");

    let mut one_off = vec![9u8; 31];
    one_off.push(10);
    let misses: Vec<Vec<u8>> = vec![
        vec![0u8; 32],
        vec![1u8; 32],
        vec![3u8; 32],
        vec![255u8; 32],
        vec![12u8; 32],
        one_off,
    ];
    for blind in misses {
        match lookup(&svc, blind.clone()).await {
            Ok(_) => panic!("a miss answered OK for {blind:?}"),
            Err(e) => assert_eq!(e.code(), Code::NotFound, "index {blind:?}"),
        }
    }
}
