//! ADR-1089 (yaadgaar #344): a populated store with no marker acquires one
//! through `AdoptKeyIdentity`, on evidence that is EXACTLY the N oldest
//! `iam_user` rows, and `ListKeyIdentityEvidence` serves those rows oldest
//! first. Real MariaDB named by `YADGAR_TEST_DSN` (D69: panics rather than
//! skips).
//!
//! A SEPARATE TARGET FROM `contract.rs` for the reason `tests/db` gives: that
//! file is one target of nearly seven thousand lines. `SetKeyIdentity`'s own
//! tests stay there; this file holds the two arms ADR-1089 adds.
//!
//! CREATION ORDER IS SET BY HAND. `created_at` is a TIMESTAMP at second
//! resolution and every test creates its rows within one second, so each test
//! writes the `created_at` it needs with [`created`] instead of relying on the
//! clock. Each test names the assertion that reddens when its property breaks.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::common::v1::Idempotency;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

fn fingerprint(tag: u8) -> Vec<u8> {
    vec![tag; 32]
}

/// Pin a row's creation time to `2026-01-01 00:00:00` plus `seconds`.
async fn created(svc: &IamDb, user_id: &str, seconds: i64) {
    sqlx::query(
        "UPDATE iam_user
            SET created_at = TIMESTAMPADD(SECOND, ?, TIMESTAMP '2026-01-01 00:00:00')
          WHERE id = ?",
    )
    .bind(seconds)
    .bind(user_id)
    .execute(svc.pool())
    .await
    .expect("pin created_at");
}

async fn soft_delete(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft delete");
}

/// `n` people, the first-created pinned OLDEST, so the returned order is the
/// oldest-first order.
async fn people(svc: &IamDb, n: u8) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let id = person(svc, 100 + i).await;
        created(svc, &id, i64::from(i) * 10).await;
        ids.push(id);
    }
    ids
}

/// `n` rows written straight into `iam_user` by MariaDB's sequence engine, for
/// the cases that need more rows than is reasonable through `CreateUser`. The
/// ids sort in creation order and every row shares one `created_at`, so the
/// id is the tie-break. Returned oldest first.
async fn bulk(svc: &IamDb, n: u32) -> Vec<String> {
    // AUDIT: `n` is a u32 the test chose; nothing else is interpolated.
    let sql = format!(
        "INSERT INTO iam_user (id, created_by, updated_by, created_at,
                               external_id_blind_index, external_id_ciphertext,
                               display_name_ciphertext)
         SELECT CONCAT('yadgar:user:bulk-', LPAD(seq, 5, '0')), 'test', 'test',
                TIMESTAMP '2026-01-01 00:00:00',
                UNHEX(SHA2(seq, 256)), 'c', 'd'
           FROM seq_1_to_{n}"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(svc.pool())
        .await
        .expect("bulk insert");
    (1..=n)
        .map(|i| format!("yadgar:user:bulk-{i:05}"))
        .collect()
}

async fn evidence_page(
    svc: &IamDb,
    page_size: i32,
    token: &str,
) -> ListKeyIdentityEvidenceResponse {
    svc.list_key_identity_evidence_as(
        Some(IAM_CALLER),
        Request::new(ListKeyIdentityEvidenceRequest {
            page_size,
            page_token: token.into(),
        }),
    )
    .await
    .expect("the evidence read refuses nothing about the store")
    .into_inner()
}

/// Every page, walked to the end, as user ids.
async fn every_evidence_id(svc: &IamDb, page_size: i32) -> Vec<String> {
    let mut ids = Vec::new();
    let mut token = String::new();
    loop {
        let page = evidence_page(svc, page_size, &token).await;
        ids.extend(page.evidence.into_iter().map(|e| e.user_id));
        if page.next_page_token.is_empty() {
            return ids;
        }
        token = page.next_page_token;
    }
}

fn adopt_request(fp: &[u8], version: u32, ids: &[String], key: &str) -> AdoptKeyIdentityRequest {
    AdoptKeyIdentityRequest {
        idempotency: match key.is_empty() {
            true => None,
            false => Some(Idempotency { key: key.into() }),
        },
        key_fingerprint: fp.to_vec(),
        derivation_version: version,
        evidence_user_ids: ids.to_vec(),
    }
}

async fn adopt(
    svc: &IamDb,
    req: AdoptKeyIdentityRequest,
) -> Result<KeyIdentityOutcome, tonic::Status> {
    svc.adopt_key_identity_as(Some(IAM_CALLER), Request::new(req))
        .await
        .map(|r| r.into_inner().outcome())
}

async fn get_marker(svc: &IamDb, fp: &[u8], version: u32) -> KeyIdentityOutcome {
    svc.get_key_identity_as(
        Some(IAM_CALLER),
        Request::new(GetKeyIdentityRequest {
            key_fingerprint: fp.to_vec(),
            derivation_version: version,
        }),
    )
    .await
    .expect("GetKeyIdentity refuses nothing about the marker")
    .into_inner()
    .outcome()
}

async fn set_marker(
    svc: &IamDb,
    fp: &[u8],
    version: u32,
) -> Result<KeyIdentityOutcome, tonic::Status> {
    svc.set_key_identity_as(
        Some(IAM_CALLER),
        Request::new(SetKeyIdentityRequest {
            idempotency: None,
            key_fingerprint: fp.to_vec(),
            derivation_version: version,
        }),
    )
    .await
    .map(|r| r.into_inner().outcome())
}

async fn stored_marker(svc: &IamDb) -> Option<(u32, Vec<u8>)> {
    sqlx::query_as::<_, (u32, Vec<u8>)>(
        "SELECT derivation_version, key_fingerprint FROM iam_key_identity",
    )
    .fetch_optional(svc.pool())
    .await
    .expect("read the marker back")
}

fn refused(got: Result<KeyIdentityOutcome, tonic::Status>, code: Code, what: &str) {
    let err = got.expect_err(what);
    assert_eq!(err.code(), code, "{what}: {err:?}");
}

// --- ListKeyIdentityEvidence ------------------------------------------------

#[tokio::test]
async fn evidence_is_listed_oldest_first_including_soft_deleted_rows() {
    // THE ORDER IS THE LOAD-BEARING PROPERTY: rows a wrong-key pod wrote are
    // the NEWEST, so a newest-first or unordered read hands it its own rows.
    // Creation order here is the REVERSE of the ids' order, so an `ORDER BY id`
    // reddens the `assert_eq!` on the ids. The oldest row is soft-deleted, so a
    // `deleted_at IS NULL` filter reddens it too.
    let svc = fresh("iamdb_evidence_order").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let c = person(&svc, 3).await;
    created(&svc, &c, 0).await;
    created(&svc, &b, 10).await;
    created(&svc, &a, 20).await;
    soft_delete(&svc, &c).await;

    let page = evidence_page(&svc, 0, "").await;
    let ids: Vec<&str> = page.evidence.iter().map(|e| e.user_id.as_str()).collect();
    assert_eq!(ids, [c.as_str(), b.as_str(), a.as_str()]);
    assert_eq!(page.next_page_token, "", "one short page is the last page");

    // The three key-derived columns, exactly as stored.
    let oldest = &page.evidence[0];
    assert_eq!(oldest.external_id_blind_index, vec![3u8; 32]);
    assert_eq!(oldest.external_id_ciphertext, b"ciphertext");
    assert_eq!(oldest.display_name_ciphertext, b"display");
}

#[tokio::test]
async fn an_empty_store_lists_no_evidence() {
    let svc = fresh("iamdb_evidence_empty").await;
    let page = evidence_page(&svc, 0, "").await;
    assert!(page.evidence.is_empty());
    assert_eq!(page.next_page_token, "");
}

#[tokio::test]
async fn evidence_pages_by_keyset_and_a_row_created_mid_walk_does_not_shift_the_window() {
    // FIVE ROWS SHARING ONE `created_at`, so the id tie-break decides the
    // order, then a page size of two. Between the first and second page an
    // OLDER row arrives: a keyset walk never sees it and serves each original
    // row once, where an OFFSET walk serves the second page's first row twice.
    // THE ASSERTION THAT REDDENS under OFFSET paging: the walked `assert_eq!`.
    let svc = fresh("iamdb_evidence_paging").await;
    let rows = bulk(&svc, 5).await;

    let first = evidence_page(&svc, 2, "").await;
    let first_ids: Vec<String> = first.evidence.iter().map(|e| e.user_id.clone()).collect();
    assert_eq!(first_ids, rows[..2]);
    assert!(
        !first.next_page_token.is_empty(),
        "a full page carries a token"
    );

    let late = person(&svc, 77).await;
    created(&svc, &late, -3600).await;

    let mut walked = first_ids;
    let mut token = first.next_page_token;
    while !token.is_empty() {
        let page = evidence_page(&svc, 2, &token).await;
        walked.extend(page.evidence.into_iter().map(|e| e.user_id));
        token = page.next_page_token;
    }
    assert_eq!(
        walked, rows,
        "every row once, in order, and no shifted window"
    );

    // A fresh walk sees the late row first, because it IS the oldest.
    assert_eq!(every_evidence_id(&svc, 2).await[0], late);
}

#[tokio::test]
async fn evidence_rows_on_different_seconds_page_across_the_boundary() {
    // THE TOKEN CARRIES BOTH HALVES OF THE POSITION. Rows on two seconds, a
    // page boundary between them: a token of the id alone skips or repeats
    // rows here, because the ids do not sort in creation order.
    let svc = fresh("iamdb_evidence_two_seconds").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let c = person(&svc, 3).await;
    created(&svc, &c, 0).await;
    created(&svc, &b, 0).await;
    created(&svc, &a, 5).await;
    let mut tied = [b.clone(), c.clone()];
    tied.sort();

    assert_eq!(
        every_evidence_id(&svc, 1).await,
        [tied[0].clone(), tied[1].clone(), a]
    );
}

#[tokio::test]
async fn a_page_size_above_the_ceiling_is_capped_and_zero_takes_the_default() {
    let svc = fresh("iamdb_evidence_page_size").await;
    bulk(&svc, 201).await;

    let capped = evidence_page(&svc, 10_000, "").await;
    assert_eq!(
        capped.evidence.len(),
        200,
        "MAX_PAGE_SIZE caps a caller's page"
    );
    assert!(!capped.next_page_token.is_empty());

    let default = evidence_page(&svc, 0, "").await;
    assert_eq!(
        default.evidence.len(),
        50,
        "DEFAULT_PAGE_SIZE applies at zero"
    );

    assert_eq!(every_evidence_id(&svc, 0).await.len(), 201);
}

#[tokio::test]
async fn a_malformed_page_token_is_invalid_argument() {
    let svc = fresh("iamdb_evidence_bad_token").await;
    let got = svc
        .list_key_identity_evidence_as(
            Some(IAM_CALLER),
            Request::new(ListKeyIdentityEvidenceRequest {
                page_size: 0,
                page_token: "not-a-position".into(),
            }),
        )
        .await
        .expect_err("a token this service never issued");
    assert_eq!(got.code(), Code::InvalidArgument, "{got:?}");
}

// --- AdoptKeyIdentity -------------------------------------------------------

#[tokio::test]
async fn adoption_on_a_populated_store_with_no_marker_records_and_then_matches() {
    // THE PATH ADR-1089 OPENS. Set refuses this store; Adopt with the oldest
    // rows records, and Get then answers MATCH.
    let svc = fresh("iamdb_adopt_records").await;
    let ids = people(&svc, 3).await;
    refused(
        set_marker(&svc, &fingerprint(1), 1).await,
        Code::FailedPrecondition,
        "Set still refuses the populated store",
    );

    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, ""))
            .await
            .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
    assert_eq!(stored_marker(&svc).await, Some((1, fingerprint(1))));
    assert_eq!(
        get_marker(&svc, &fingerprint(1), 1).await,
        KeyIdentityOutcome::Match
    );
}

#[tokio::test]
async fn adoption_where_a_marker_exists_compares_and_never_overwrites() {
    // WRITE-ONCE ON THIS ARM TOO. A stored marker answers the COMPARISON —
    // even to evidence that would be refused — and is never replaced.
    // THE ASSERTION THAT REDDENS under an upsert: `stored_marker`.
    let svc = fresh("iamdb_adopt_compares").await;
    assert_eq!(
        set_marker(&svc, &fingerprint(1), 1)
            .await
            .expect("empty store records"),
        KeyIdentityOutcome::Recorded
    );
    let ids = people(&svc, 2).await;

    for (fp, version, evidence, want) in [
        (fingerprint(2), 1, ids.clone(), KeyIdentityOutcome::Mismatch),
        (fingerprint(1), 1, ids.clone(), KeyIdentityOutcome::Match),
        (
            fingerprint(2),
            2,
            ids.clone(),
            KeyIdentityOutcome::DerivationSkew,
        ),
        (
            fingerprint(2),
            1,
            vec!["yadgar:user:nobody".into()],
            KeyIdentityOutcome::Mismatch,
        ),
        (
            fingerprint(1),
            1,
            vec![ids[1].clone()],
            KeyIdentityOutcome::Match,
        ),
    ] {
        assert_eq!(
            adopt(&svc, adopt_request(&fp, version, &evidence, ""))
                .await
                .expect("compare"),
            want,
            "{fp:?} v{version} {evidence:?}"
        );
    }
    assert_eq!(stored_marker(&svc).await, Some((1, fingerprint(1))));
}

#[tokio::test]
async fn adoption_on_an_empty_store_is_refused() {
    let svc = fresh("iamdb_adopt_empty").await;
    refused(
        adopt(
            &svc,
            adopt_request(&fingerprint(1), 1, &["yadgar:user:x".into()], ""),
        )
        .await,
        Code::FailedPrecondition,
        "an empty store records through SetKeyIdentity, never by adoption",
    );
    assert_eq!(stored_marker(&svc).await, None);
}

#[tokio::test]
async fn an_evidence_id_naming_no_row_is_refused() {
    let svc = fresh("iamdb_adopt_unknown").await;
    let ids = people(&svc, 2).await;
    for evidence in [
        vec![ids[0].clone(), "yadgar:user:nobody".into()],
        vec![ids[0].clone(), ids[1].clone(), "yadgar:user:nobody".into()],
    ] {
        refused(
            adopt(&svc, adopt_request(&fingerprint(1), 1, &evidence, "")).await,
            Code::FailedPrecondition,
            "an id nobody wrote is no evidence",
        );
    }
    assert_eq!(stored_marker(&svc).await, None);
}

#[tokio::test]
async fn evidence_that_is_not_the_oldest_rows_is_refused() {
    // THE RULE ADR-1089 MOVES INTO THIS SERVICE. Each set below names rows
    // that exist; none is the N oldest. THE ASSERTION THAT REDDENS when the
    // predicate checks existence only: every `refused` in the loop.
    let svc = fresh("iamdb_adopt_not_oldest").await;
    let ids = people(&svc, 4).await;
    for evidence in [
        vec![ids[3].clone()],
        vec![ids[1].clone()],
        vec![ids[2].clone(), ids[3].clone()],
        vec![ids[0].clone(), ids[2].clone()],
        vec![ids[1].clone(), ids[2].clone(), ids[3].clone()],
    ] {
        refused(
            adopt(&svc, adopt_request(&fingerprint(1), 1, &evidence, "")).await,
            Code::FailedPrecondition,
            "evidence that is not the oldest rows",
        );
    }
    assert_eq!(stored_marker(&svc).await, None);

    // The oldest prefix of ANY length is accepted.
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids[..2], ""))
            .await
            .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn the_oldest_rows_are_chosen_by_creation_and_not_by_id() {
    // CREATION ORDER IS THE REVERSE OF ID ORDER, and N is less than the row
    // count, so the id-ordered prefix and the creation-ordered prefix are
    // different sets. THE ASSERTION THAT REDDENS when the INSERT's predicate
    // orders by `id` alone: the `refused` on the id-ordered prefix.
    let svc = fresh("iamdb_adopt_creation_not_id").await;
    let mut by_id = [
        person(&svc, 1).await,
        person(&svc, 2).await,
        person(&svc, 3).await,
    ];
    by_id.sort();
    created(&svc, &by_id[2], 0).await;
    created(&svc, &by_id[1], 10).await;
    created(&svc, &by_id[0], 20).await;

    refused(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &by_id[..2], "")).await,
        Code::FailedPrecondition,
        "the lowest ids are not the oldest rows",
    );
    assert_eq!(stored_marker(&svc).await, None);
    assert_eq!(
        adopt(
            &svc,
            adopt_request(
                &fingerprint(1),
                1,
                &[by_id[2].clone(), by_id[1].clone()],
                ""
            )
        )
        .await
        .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn ids_equal_under_the_column_collation_are_a_duplicate() {
    // `iam_user.id` compares under `utf8mb4_uca1400_ai_ci`: case-insensitive
    // and PAD SPACE. Two ids that differ only in case or in trailing spaces
    // are ONE row to the predicate, so they are a duplicate in the request,
    // INVALID_ARGUMENT, and not a statement about the store.
    let svc = fresh("iamdb_adopt_collation_dup").await;
    let ids = people(&svc, 2).await;
    for evidence in [
        vec![ids[0].clone(), ids[0].to_uppercase()],
        vec![ids[0].clone(), format!("{}  ", ids[0])],
    ] {
        refused(
            adopt(&svc, adopt_request(&fingerprint(1), 1, &evidence, "")).await,
            Code::InvalidArgument,
            "a duplicate under the column's collation",
        );
    }
    assert_eq!(stored_marker(&svc).await, None);
}

#[tokio::test]
async fn soft_deleted_rows_count_as_evidence() {
    // The oldest row is soft-deleted. Leaving it out is NOT the oldest set;
    // including it is. A `deleted_at IS NULL` in the predicate reddens both.
    let svc = fresh("iamdb_adopt_soft_deleted").await;
    let ids = people(&svc, 3).await;
    soft_delete(&svc, &ids[0]).await;

    refused(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids[1..], "")).await,
        Code::FailedPrecondition,
        "the live rows alone are not the oldest rows",
    );
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, ""))
            .await
            .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn the_evidence_is_a_set_so_its_order_does_not_matter() {
    let svc = fresh("iamdb_adopt_shuffled").await;
    let ids = people(&svc, 3).await;
    let shuffled = vec![ids[2].clone(), ids[0].clone(), ids[1].clone()];
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &shuffled, ""))
            .await
            .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn sixty_four_ids_are_accepted_and_sixty_five_are_invalid() {
    let svc = fresh("iamdb_adopt_cap").await;
    let rows = bulk(&svc, 65).await;
    refused(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &rows, "")).await,
        Code::InvalidArgument,
        "more than 64 ids",
    );
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &rows[..64], ""))
            .await
            .expect("64"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn a_malformed_adoption_is_invalid_argument_and_writes_nothing() {
    let svc = fresh("iamdb_adopt_invalid").await;
    let ids = people(&svc, 2).await;
    let dup = vec![ids[0].clone(), ids[0].clone()];
    for (fp, version, evidence, what) in [
        (Vec::new(), 1u32, ids.clone(), "an empty fingerprint"),
        (
            vec![1u8; 256],
            1,
            ids.clone(),
            "a fingerprint wider than the column",
        ),
        (fingerprint(1), 0, ids.clone(), "a zero version"),
        (fingerprint(1), 1, Vec::new(), "no evidence"),
        (fingerprint(1), 1, dup, "a duplicate id"),
    ] {
        refused(
            adopt(&svc, adopt_request(&fp, version, &evidence, "")).await,
            Code::InvalidArgument,
            what,
        );
    }
    assert_eq!(stored_marker(&svc).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_adoptions_answer_one_recorded_and_one_match() {
    // Two replicas holding the same key set both prove and both adopt. One
    // writes; the other is told the marker matches. A loser answered on the
    // status channel (a 1213 or 1020 rendered UNAVAILABLE) reddens the
    // `expect`s; a double write reddens the sorted pair.
    let svc = fresh("iamdb_adopt_concurrent").await;
    let ids = people(&svc, 3).await;
    let (one, two) = tokio::join!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "pod-one")),
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "pod-two")),
    );
    let mut outcomes = [
        one.expect("a concurrent adoption is an outcome"),
        two.expect("a concurrent adoption is an outcome"),
    ];
    outcomes.sort_by_key(|o| *o as i32);
    assert_eq!(
        outcomes,
        [KeyIdentityOutcome::Match, KeyIdentityOutcome::Recorded]
    );
    assert_eq!(stored_marker(&svc).await, Some((1, fingerprint(1))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_concurrent_adoptions_answer_one_recorded_and_four_match() {
    // FIVE, because two do not exercise the share-upgrade cycle the marker's
    // `LOCK IN SHARE MODE` re-read was chosen against (see `marker`): one
    // loser is one share, and one share has nothing to cycle with. A 1213
    // rendered UNAVAILABLE reddens the `expect`.
    let svc = fresh("iamdb_adopt_concurrent_five").await;
    let ids = people(&svc, 3).await;
    let req = |key: &str| adopt_request(&fingerprint(1), 1, &ids, key);
    let (a, b, c, d, e) = tokio::join!(
        adopt(&svc, req("pod-1")),
        adopt(&svc, req("pod-2")),
        adopt(&svc, req("pod-3")),
        adopt(&svc, req("pod-4")),
        adopt(&svc, req("pod-5")),
    );
    let mut outcomes = Vec::new();
    for got in [a, b, c, d, e] {
        outcomes.push(got.expect("a concurrent adoption is an outcome"));
    }
    outcomes.sort_by_key(|o| *o as i32);
    assert_eq!(
        outcomes,
        [
            KeyIdentityOutcome::Match,
            KeyIdentityOutcome::Match,
            KeyIdentityOutcome::Match,
            KeyIdentityOutcome::Match,
            KeyIdentityOutcome::Recorded
        ]
    );
}

#[tokio::test]
async fn a_replayed_adoption_answers_recorded_and_a_changed_payload_is_refused() {
    // D9: the replay returns the ORIGINAL outcome, RECORDED and not MATCH. The
    // payload is the fingerprint and the version; the evidence is not part of
    // it, so a replay carrying other (still valid) evidence is a replay.
    let svc = fresh("iamdb_adopt_replay").await;
    let ids = people(&svc, 3).await;
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "k1"))
            .await
            .expect("adopt"),
        KeyIdentityOutcome::Recorded
    );
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "k1"))
            .await
            .expect("replay"),
        KeyIdentityOutcome::Recorded
    );
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids[..1], "k1"))
            .await
            .expect("replay"),
        KeyIdentityOutcome::Recorded
    );
    for (fp, version) in [(fingerprint(2), 1), (fingerprint(1), 2)] {
        refused(
            adopt(&svc, adopt_request(&fp, version, &ids, "k1")).await,
            Code::InvalidArgument,
            "a repeated key carrying a different payload",
        );
    }
    assert_eq!(stored_marker(&svc).await, Some((1, fingerprint(1))));
}

#[tokio::test]
async fn a_key_recorded_by_set_replays_as_recorded_on_adopt() {
    // THE KEY IS SHARED ACROSS THE TWO WRITING ARMS, by design: the marker
    // keeps one `idempotency_key` and the payload is the pair. Set records on
    // the empty store; rows arrive; Adopt under the same key with the same
    // pair is a replay and answers the ORIGINAL outcome. Harmless: the marker
    // already holds exactly that pair.
    let svc = fresh("iamdb_adopt_cross_arm_replay").await;
    svc.set_key_identity_as(
        Some(IAM_CALLER),
        Request::new(SetKeyIdentityRequest {
            idempotency: Some(Idempotency { key: "k1".into() }),
            key_fingerprint: fingerprint(1),
            derivation_version: 1,
        }),
    )
    .await
    .expect("empty store records");
    let ids = people(&svc, 2).await;
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "k1"))
            .await
            .expect("replay"),
        KeyIdentityOutcome::Recorded
    );
    assert_eq!(stored_marker(&svc).await, Some((1, fingerprint(1))));
}

#[tokio::test]
async fn a_refusal_is_not_recorded_under_the_idempotency_key() {
    // A refused call writes nothing, so a retry under the SAME key with
    // corrected evidence is evaluated afresh and records.
    let svc = fresh("iamdb_adopt_refusal_not_keyed").await;
    let ids = people(&svc, 3).await;
    refused(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids[1..], "k1")).await,
        Code::FailedPrecondition,
        "not the oldest rows",
    );
    assert_eq!(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids, "k1"))
            .await
            .expect("retry"),
        KeyIdentityOutcome::Recorded
    );
}

#[tokio::test]
async fn set_still_refuses_a_populated_store_after_a_refused_adoption() {
    // The adoption arm opens no side door in Set's refusal.
    let svc = fresh("iamdb_adopt_set_unchanged").await;
    let ids = people(&svc, 2).await;
    refused(
        adopt(&svc, adopt_request(&fingerprint(1), 1, &ids[1..], "")).await,
        Code::FailedPrecondition,
        "not the oldest rows",
    );
    refused(
        set_marker(&svc, &fingerprint(1), 1).await,
        Code::FailedPrecondition,
        "Set over a populated store",
    );
    assert_eq!(stored_marker(&svc).await, None);
}
