//! AC2: `LookupUser`, called by the iam caller with a 32-byte
//! `external_id_blind_index`, answers the `user_id` of the live `iam_user` row
//! with that blind index, whether or not the user has an `iam_password` row, and
//! writes nothing. Against a real MariaDB; row counts are read by SQL on the pool.

mod db;

use db::*;
use tonic::Request;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

/// `LookupUser` as the iam caller, for blind index `blind`; the answered id.
async fn lookup(svc: &IamDb, blind: Vec<u8>) -> String {
    svc.lookup_user_as(
        Some(IAM_CALLER),
        Request::new(LookupUserRequest {
            external_id_blind_index: blind,
            ..Default::default()
        }),
    )
    .await
    .expect("lookup_user must succeed for a live user")
    .into_inner()
    .user_id
}

async fn count(svc: &IamDb, table: &str) -> i64 {
    // AUDIT: `table` is a literal at every call site.
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM {table}"
    )))
    .fetch_one(svc.pool())
    .await
    .expect("count rows")
}

/// Every column of `iam_user`, rendered, in id order: any write shows up here.
async fn user_dump(svc: &IamDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT CONCAT_WS('|', id, HEX(external_id_blind_index), \
         CAST(version AS SIGNED), UNIX_TIMESTAMP(updated_at), IFNULL(deleted_at, 'live')) \
         FROM iam_user ORDER BY id",
    )
    .fetch_all(svc.pool())
    .await
    .expect("dump iam_user")
}

#[tokio::test]
async fn user_with_password_is_found_by_blind_index() {
    let svc = fresh("iam_db_lookup_with_password").await;
    let a = person(&svc, 7).await;
    set_password(&svc, &a, GOOD_HASH).await;

    // AC2: user A under [7; 32] with a password answers A's id.
    assert_eq!(lookup(&svc, vec![7; 32]).await, a);
}

#[tokio::test]
async fn user_without_password_is_found_by_blind_index() {
    let svc = fresh("iam_db_lookup_no_password").await;
    let a = person(&svc, 7).await;
    set_password(&svc, &a, GOOD_HASH).await;
    let b = person(&svc, 8).await;

    // AC2: user B [8; 32] has no iam_password row and is still found.
    assert_eq!(count(&svc, "iam_password").await, 1);
    assert_eq!(lookup(&svc, vec![8; 32]).await, b);
}

#[tokio::test]
async fn each_user_answers_its_own_id() {
    let svc = fresh("iam_db_lookup_two_users").await;
    let a = person(&svc, 7).await;
    let b = person(&svc, 8).await;

    let first = lookup(&svc, vec![7; 32]).await;
    let second = lookup(&svc, vec![8; 32]).await;

    // AC2: [7; 32] answers A, [8; 32] answers B, and the two differ.
    assert_eq!(first, a);
    assert_eq!(second, b);
    assert_ne!(first, second);
}

#[tokio::test]
async fn lookup_writes_nothing_and_repeats_the_same_answer() {
    let svc = fresh("iam_db_lookup_writes_nothing").await;
    let a = person(&svc, 7).await;
    let _b = person(&svc, 8).await;
    set_password(&svc, &a, GOOD_HASH).await;
    // AC2: two users exist before the reads.
    assert_eq!(count(&svc, "iam_user").await, 2);
    let users_before = user_dump(&svc).await;
    let passwords_before = count(&svc, "iam_password").await;

    for _ in 0..3 {
        // AC2: each repeated lookup of [7; 32] answers A's id.
        assert_eq!(lookup(&svc, vec![7; 32]).await, a);
    }

    // AC2: iam_user still holds two rows, and no row of either table changed.
    assert_eq!(count(&svc, "iam_user").await, 2);
    assert_eq!(user_dump(&svc).await, users_before);
    assert_eq!(count(&svc, "iam_password").await, passwords_before);
}

#[tokio::test]
async fn boundary_byte_values_each_answer_their_own_user() {
    let svc = fresh("iam_db_lookup_boundary_bytes").await;
    let mut created = Vec::new();
    for blind in [0u8, 1, 9, 255] {
        created.push((blind, person(&svc, blind).await));
    }

    for (blind, id) in &created {
        // AC2: [0; 32], [1; 32], [9; 32] and [255; 32] each answer the id of
        // the user created under that index.
        assert_eq!(&lookup(&svc, vec![*blind; 32]).await, id);
    }
}

#[tokio::test]
async fn other_indexes_answer_the_user_created_under_them() {
    // AC2: triangulation, so a hardcoded answer fails. Indexes 42 and 43 differ
    // from every literal above, and the mixed-byte index is not a repeated byte.
    let svc = fresh("iam_db_lookup_triangulate").await;
    let a = person(&svc, 42).await;
    let b = person(&svc, 43).await;
    let c = svc
        .create_user_as(
            Some(IAM_CALLER),
            Request::new(CreateUserRequest {
                external_id_blind_index: (0u8..32).collect(),
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
        .id;

    assert_eq!(lookup(&svc, vec![43; 32]).await, b);
    assert_eq!(lookup(&svc, vec![42; 32]).await, a);
    assert_eq!(lookup(&svc, (0u8..32).collect()).await, c);
}
