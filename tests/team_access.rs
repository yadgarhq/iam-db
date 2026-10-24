//! Team access, stage 2 (plans/team-access.md "Stage 2 — iam-db"), against a
//! real MariaDB. Each test is named after the plan's red case it carries.
//!
//! `changed_user_ids` (proto#49 at 87cf893, added after the plan was written)
//! is asserted inside reds 1 to 5: exactly the added, removed, archived-team
//! and reactivated-team members, and empty on the no-op sync of red 2.
//!
//! Red 8 (a caller whose leaf is not `iam`'s is refused before a transaction
//! opens) lives in `tests/caller_gate.rs`, where `SyncTeams` joins the list of
//! every RPC and the counting store proves no connection was opened.

mod db;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use db::*;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use tonic::{Code, Request, Status};
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

const ADMINS: &str = "yadgar:team:administrators";
const OTHER: &str = "yadgar:team:other";

/// The one sentence every bootstrap create-user refusal carries.
const CREATE_REFUSAL: &str = "the bootstrap create-user predicate refused";
/// The one sentence every bootstrap enrolment refusal carries (ADR-0657).
const DEMAND_REFUSAL: &str =
    "the bootstrap token may only enrol an administrator who has never held a credential";

fn uuid7() -> String {
    format!("yadgar:user:{}", uuid::Uuid::now_v7())
}

fn with_rid<T>(body: T, rid: &str) -> Request<T> {
    let mut req = Request::new(body);
    req.metadata_mut()
        .insert("x-yadgar-request-id", rid.parse().expect("an ascii id"));
    req
}

/// `SyncTeams` with `teams` as `(name, members)`.
async fn sync(svc: &IamDb, teams: &[(&str, &[&str])]) -> Result<SyncTeamsResponse, Status> {
    svc.sync_teams_as(
        Some(IAM_CALLER),
        Request::new(SyncTeamsRequest {
            scope: None,
            teams: teams
                .iter()
                .map(|(name, members)| DeclaredTeam {
                    name: (*name).into(),
                    member_user_ids: members.iter().map(|m| (*m).to_string()).collect(),
                })
                .collect(),
        }),
    )
    .await
    .map(tonic::Response::into_inner)
}

/// What `[token; 32]` resolves to, with derivation `on` or off.
async fn resolve_with(svc: &IamDb, token: u8, on: bool) -> ResolveCredentialResponse {
    svc.resolve_credential_as(
        Some(IAM_CALLER),
        Request::new(ResolveCredentialRequest {
            token_hash: vec![token; 32],
            admin_from_team: on,
        }),
    )
    .await
    .expect("resolve must not error")
    .into_inner()
}

/// The F2 `CreateUser` with a pre-minted `user_id`, blind index `[blind; 32]`.
async fn create_declared(
    svc: &IamDb,
    user_id: &str,
    blind: u8,
    rid: &str,
) -> Result<String, Status> {
    svc.create_user_as(
        Some(IAM_CALLER),
        with_rid(
            CreateUserRequest {
                external_id_blind_index: vec![blind; 32],
                external_id_ciphertext: b"ciphertext".to_vec(),
                display_name_ciphertext: b"display".to_vec(),
                user_id: user_id.into(),
                ..Default::default()
            },
            rid,
        ),
    )
    .await
    .map(|r| r.into_inner().meta.expect("meta").id)
}

/// The bootstrap demand, with `admin_from_team` as `on`.
async fn demand_with(
    svc: &IamDb,
    user_id: &str,
    secret: u8,
    on: bool,
    revoking: bool,
    rid: &str,
) -> Result<CreateEnrolmentResponse, Status> {
    svc.create_enrolment_as(
        Some(IAM_CALLER),
        with_rid(
            CreateEnrolmentRequest {
                user_id: user_id.into(),
                secret_hash: vec![secret; 32],
                expires_at: Some(at(3600)),
                require_zero_credential_admin: true,
                revoke_existing_credentials: revoking,
                admin_from_team: on,
                ..Default::default()
            },
            rid,
        ),
    )
    .await
    .map(tonic::Response::into_inner)
}

async fn count(svc: &IamDb, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(svc.pool())
        .await
        .expect("count")
}

async fn users(svc: &IamDb) -> i64 {
    count(svc, "SELECT COUNT(*) FROM iam_user").await
}

async fn pending(svc: &IamDb) -> Vec<String> {
    sqlx::query_scalar("SELECT user_id FROM iam_team_member_pending ORDER BY user_id")
        .fetch_all(svc.pool())
        .await
        .expect("pending rows")
}

async fn members(svc: &IamDb, team: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT user_id FROM iam_team_member WHERE team_id = ? ORDER BY user_id")
        .bind(team)
        .fetch_all(svc.pool())
        .await
        .expect("member rows")
}

async fn enrolments(svc: &IamDb) -> i64 {
    count(svc, "SELECT COUNT(*) FROM iam_enrolment").await
}

async fn soft_delete_user(svc: &IamDb, user_id: &str) {
    sqlx::query("UPDATE iam_user SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(user_id)
        .execute(svc.pool())
        .await
        .expect("soft-delete the user");
}

async fn archive_team(svc: &IamDb, team: &str) {
    sqlx::query("UPDATE iam_team SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(team)
        .execute(svc.pool())
        .await
        .expect("archive the team");
}

async fn revoke_one(svc: &IamDb, user_id: &str, credential_id: &str) {
    svc.revoke_credential_as(
        Some(IAM_CALLER),
        Request::new(RevokeCredentialRequest {
            credential_id: credential_id.into(),
            user_id: user_id.into(),
            ..Default::default()
        }),
    )
    .await
    .expect("revoke");
}

/// Every count field of a sync answer, in order.
fn counts(r: &SyncTeamsResponse) -> [u32; 5] {
    [
        r.teams_inserted,
        r.teams_archived,
        r.teams_reactivated,
        r.members_added,
        r.members_removed,
    ]
}

/// Sorted.
fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// A local recorder and a thread-local log, around a current-thread runtime.
// The same two rigs `tests/contract.rs` uses, for the same reasons: a global
// recorder or subscriber would race every other test in this binary.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The counters `body` emitted, as `name{label=value}` to count, and the log
/// it wrote.
struct Observed {
    counters: BTreeMap<String, u64>,
    log: String,
}

fn observed<T>(body: impl FnOnce(&tokio::runtime::Runtime) -> T) -> (T, Observed) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(Capture(buf.clone()))
        .finish();
    let out = tracing::subscriber::with_default(subscriber, || {
        metrics::with_local_recorder(&recorder, || body(&rt))
    });
    let mut counters = BTreeMap::new();
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let labels: Vec<String> = key
            .key()
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        if let DebugValue::Counter(n) = value {
            counters.insert(format!("{}{{{}}}", key.key().name(), labels.join(",")), n);
        }
    }
    let log = String::from_utf8(buf.lock().expect("buffer").clone()).expect("utf-8");
    (out, Observed { counters, log })
}

const DEMAND_REFUSED: &str = "yadgar_iamdb_enrolment_demand_refused_total";
const CREATE_REFUSED: &str = "yadgar_iamdb_bootstrap_create_refused_total";
const REENROLMENT: &str = "yadgar_iamdb_bootstrap_reenrolment_total";

/// Only the series of `name`, as `{labels} -> count`.
fn series(o: &Observed, name: &str) -> BTreeMap<String, u64> {
    o.counters
        .iter()
        .filter_map(|(k, v)| k.strip_prefix(name).map(|l| (l.to_string(), *v)))
        .collect()
}

fn one(label: &str) -> BTreeMap<String, u64> {
    BTreeMap::from([(format!("{{{label}}}"), 1)])
}

// ---------------------------------------------------------------------------
// SyncTeams
// ---------------------------------------------------------------------------

#[tokio::test]
async fn red_01_an_empty_store_takes_administrators_with_two_members() {
    let svc = fresh("iam_db_ta_red_01").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    mint(&svc, &a, 11, None).await.expect("mint");
    mint(&svc, &b, 12, None).await.expect("mint");

    let got = sync(&svc, &[("administrators", &[&a, &b])])
        .await
        .expect("sync");
    assert_eq!(counts(&got), [1, 0, 0, 2, 0]);
    assert_eq!(got.changed_user_ids, sorted(vec![a.clone(), b.clone()]));
    assert_eq!(got.administrators_live_members, 2);
    assert!(got.unknown_member_user_ids.is_empty());
    assert!(got.pending_administrator_user_ids.is_empty());
    for token in [11, 12] {
        assert_eq!(
            resolve_with(&svc, token, false).await.team_ids,
            vec![ADMINS]
        );
    }
}

#[tokio::test]
async fn red_02_the_same_declaration_again_counts_nothing() {
    let svc = fresh("iam_db_ta_red_02").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let decl: &[(&str, &[&str])] = &[("administrators", &[&a, &b]), ("other", &[&b])];
    sync(&svc, decl).await.expect("first sync");
    let again = sync(&svc, decl).await.expect("second sync");
    assert_eq!(counts(&again), [0; 5]);
    assert!(
        again.changed_user_ids.is_empty(),
        "a no-op sync changes nobody"
    );
    assert_eq!(again.administrators_live_members, 2);
}

#[tokio::test]
async fn red_03_a_removed_member_loses_the_team() {
    let svc = fresh("iam_db_ta_red_03").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    mint(&svc, &b, 12, None).await.expect("mint");
    sync(&svc, &[("administrators", &[&a, &b])])
        .await
        .expect("sync");

    let got = sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    assert_eq!(counts(&got), [0, 0, 0, 0, 1]);
    assert_eq!(got.changed_user_ids, vec![b.clone()]);
    assert!(resolve_with(&svc, 12, false).await.team_ids.is_empty());
}

/// Also yaadgaar #303: the `team_ids` query keeps live teams only.
#[tokio::test]
async fn red_04_an_archived_team_leaves_team_ids_and_keeps_its_member_rows() {
    let svc = fresh("iam_db_ta_red_04").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    mint(&svc, &b, 12, None).await.expect("mint");
    sync(&svc, &[("administrators", &[&a]), ("other", &[&b])])
        .await
        .expect("sync");
    assert_eq!(resolve_with(&svc, 12, false).await.team_ids, vec![OTHER]);

    let got = sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    assert_eq!(got.teams_archived, 1);
    assert_eq!(counts(&got), [0, 1, 0, 0, 0]);
    assert_eq!(
        got.changed_user_ids,
        vec![b.clone()],
        "every member of the archived team"
    );
    assert!(resolve_with(&svc, 12, false).await.team_ids.is_empty());
    assert_eq!(members(&svc, OTHER).await, vec![b]);
}

#[tokio::test]
async fn red_05_a_re_declared_team_is_reactivated_with_the_declared_members() {
    let svc = fresh("iam_db_ta_red_05").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let c = person(&svc, 3).await;
    sync(&svc, &[("administrators", &[&a]), ("other", &[&b])])
        .await
        .expect("sync");
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("archive");

    let got = sync(&svc, &[("administrators", &[&a]), ("other", &[&a, &c])])
        .await
        .expect("re-declare");
    assert_eq!(got.teams_reactivated, 1);
    assert_eq!(counts(&got), [0, 0, 1, 2, 1]);
    // Reactivated: every member it now has, and the one it lost.
    assert_eq!(
        got.changed_user_ids,
        sorted(vec![a.clone(), b.clone(), c.clone()])
    );
    assert_eq!(members(&svc, OTHER).await, sorted(vec![a, c]));
}

#[tokio::test]
async fn red_06_an_unknown_member_is_skipped_listed_and_never_pending() {
    let svc = fresh("iam_db_ta_red_06").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let ghost = uuid7();
    let ghost2 = uuid7();
    let got = sync(
        &svc,
        &[("administrators", &[&a, &ghost]), ("other", &[&b, &ghost2])],
    )
    .await
    .expect("sync");
    assert_eq!(got.unknown_member_user_ids, vec![ghost, ghost2]);
    assert!(got.pending_administrator_user_ids.is_empty());
    assert!(pending(&svc).await.is_empty());
    assert_eq!(members(&svc, ADMINS).await, vec![a]);
    assert_eq!(members(&svc, OTHER).await, vec![b]);
    assert_eq!(got.administrators_live_members, 1);
}

async fn row_counts(svc: &IamDb) -> [i64; 3] {
    [
        count(svc, "SELECT COUNT(*) FROM iam_team").await,
        count(svc, "SELECT COUNT(*) FROM iam_team_member").await,
        count(svc, "SELECT COUNT(*) FROM iam_team_member_pending").await,
    ]
}

#[tokio::test]
async fn red_07_the_lockout_guard_counts_live_administrators() {
    let svc = fresh("iam_db_ta_red_07").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    let before = row_counts(&svc).await;

    // Zero members.
    let err = sync(&svc, &[("administrators", &[])])
        .await
        .expect_err("guard");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(row_counts(&svc).await, before);

    // The only member is a uuid with no user row: no pending row either.
    let ghost = uuid7();
    let err = sync(&svc, &[("administrators", &[&ghost])])
        .await
        .expect_err("guard");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(row_counts(&svc).await, before);
    assert!(pending(&svc).await.is_empty());

    // `administrators` omitted, another team declared: not archived.
    let err = sync(&svc, &[("other", &[&b])]).await.expect_err("guard");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(row_counts(&svc).await, before);
    let archived = count(
        &svc,
        "SELECT COUNT(*) FROM iam_team WHERE id = 'yadgar:team:administrators'
            AND deleted_at IS NOT NULL",
    )
    .await;
    assert_eq!(archived, 0);

    // Zero live members: a pending-only declaration is accepted.
    let cold = fresh("iam_db_ta_red_07_cold").await;
    let got = sync(&cold, &[("administrators", &[&ghost])])
        .await
        .expect("a pending-only first sync");
    assert_eq!(got.pending_administrator_user_ids, vec![ghost]);
}

#[tokio::test]
async fn red_08_a_caller_that_is_not_iam_is_refused() {
    let svc = fresh("iam_db_ta_red_08").await;
    let err = svc
        .sync_teams_as(
            Some("seeder-caller"),
            Request::new(SyncTeamsRequest::default()),
        )
        .await
        .expect_err("refused");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(row_counts(&svc).await, [0, 0, 0]);
}

#[tokio::test]
async fn red_09_is_admin_is_derived_from_membership_when_asked() {
    let svc = fresh("iam_db_ta_red_09").await;
    let member = person(&svc, 1).await;
    let flagged = person(&svc, 2).await;
    make_admin(&svc, &flagged).await;
    mint(&svc, &member, 11, None).await.expect("mint");
    mint(&svc, &flagged, 12, None).await.expect("mint");
    sync(&svc, &[("administrators", &[&member])])
        .await
        .expect("sync");

    assert!(resolve_with(&svc, 11, true).await.is_admin);
    assert!(!resolve_with(&svc, 12, true).await.is_admin);
    // Derivation off: the column decides.
    assert!(!resolve_with(&svc, 11, false).await.is_admin);
    assert!(resolve_with(&svc, 12, false).await.is_admin);
}

// ---------------------------------------------------------------------------
// Red 10: the bootstrap enrolment predicate, derivation on (ADR-0966)
// ---------------------------------------------------------------------------

#[test]
fn red_10_a_declared_administrator_is_admitted_whatever_credentials_they_hold() {
    let (_, seen) = observed(|rt| {
        rt.block_on(async {
            let svc = fresh("iam_db_ta_red_10_admit").await;
            let live = person(&svc, 1).await;
            let zero = person(&svc, 2).await;
            let revoked = person(&svc, 3).await;
            mint(&svc, &live, 11, None).await.expect("mint");
            let gone = mint(&svc, &revoked, 13, None).await.expect("mint");
            revoke_one(&svc, &revoked, &gone).await;
            sync(&svc, &[("administrators", &[&live, &zero, &revoked])])
                .await
                .expect("sync");

            demand_with(&svc, &live, 21, true, false, "rid-live")
                .await
                .expect("live");
            demand_with(&svc, &live, 22, true, true, "rid-live-r")
                .await
                .expect("revoking");
            demand_with(&svc, &zero, 23, true, false, "rid-zero")
                .await
                .expect("zero");
            demand_with(&svc, &revoked, 24, true, false, "rid-revoked")
                .await
                .expect("revoked");
            assert_eq!(enrolments(&svc).await, 4);
        })
    });
    assert_eq!(
        series(&seen, REENROLMENT),
        BTreeMap::from([
            ("{revoke=false}".to_string(), 1),
            ("{revoke=true}".to_string(), 1)
        ]),
        "only the member holding a LIVE credential is counted"
    );
    let warn = "a bootstrap enrolment was issued for an administrator who holds live credentials";
    assert_eq!(seen.log.matches(warn).count(), 2, "{}", seen.log);
    assert!(seen.log.contains("rid-live"));
    assert!(series(&seen, DEMAND_REFUSED).is_empty());
}

/// One refusal, observed: (code, message, refused-counter series, log).
fn refused(
    db_name: &'static str,
    setup: impl for<'a> FnOnce(
        &'a IamDb,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + 'a>>,
    rid: &'static str,
) -> (Code, String, BTreeMap<String, u64>, String, i64) {
    let ((code, message, written), seen) = observed(|rt| {
        rt.block_on(async {
            let svc = fresh(db_name).await;
            let target = setup(&svc).await;
            let before = enrolments(&svc).await;
            let err = demand_with(&svc, &target, 30, true, false, rid)
                .await
                .expect_err("refused");
            (
                err.code(),
                err.message().to_string(),
                enrolments(&svc).await - before,
            )
        })
    });
    let s = series(&seen, DEMAND_REFUSED);
    (code, message, s, seen.log, written)
}

fn assert_refused(
    got: (Code, String, BTreeMap<String, u64>, String, i64),
    conjunct: &str,
    rid: &str,
) {
    let (code, message, s, log, written) = got;
    assert_eq!(code, Code::PermissionDenied);
    assert_eq!(message, DEMAND_REFUSAL, "the one sentence, byte-identical");
    assert_eq!(
        s,
        one(&format!("conjunct={conjunct}")),
        "exactly one increment"
    );
    assert_eq!(written, 0, "nothing written");
    let line = log
        .lines()
        .find(|l| l.contains("the bootstrap enrolment demand was refused"))
        .unwrap_or_else(|| panic!("the warn line: {log}"));
    assert!(
        line.contains(rid),
        "the warn line carries the request id: {line}"
    );
    assert!(line.contains(conjunct), "{line}");
}

#[test]
fn red_10_an_undeclared_user_with_the_column_true_is_not_a_declared_member() {
    let got = refused(
        "iam_db_ta_red_10_undeclared",
        |svc| {
            Box::pin(async move {
                let a = person(svc, 1).await;
                let flagged = person(svc, 2).await;
                make_admin(svc, &flagged).await;
                mint(svc, &flagged, 12, None).await.expect("mint");
                sync(svc, &[("administrators", &[&a])]).await.expect("sync");
                flagged
            })
        },
        "rid-undeclared",
    );
    assert_refused(got, "not_declared_member", "rid-undeclared");
}

#[test]
fn red_10_a_non_member_with_zero_credentials_is_not_a_declared_member() {
    let got = refused(
        "iam_db_ta_red_10_nonmember",
        |svc| {
            Box::pin(async move {
                let a = person(svc, 1).await;
                let n = person(svc, 2).await;
                sync(svc, &[("administrators", &[&a])]).await.expect("sync");
                n
            })
        },
        "rid-nonmember",
    );
    assert_refused(got, "not_declared_member", "rid-nonmember");
}

#[test]
fn red_10_a_pending_uuid_is_not_a_live_user() {
    let got = refused(
        "iam_db_ta_red_10_pending",
        |svc| {
            Box::pin(async move {
                let ghost = uuid7();
                sync(svc, &[("administrators", &[&ghost])])
                    .await
                    .expect("sync");
                ghost
            })
        },
        "rid-pending",
    );
    assert_refused(got, "not_live_user", "rid-pending");
}

#[test]
fn red_10_a_soft_deleted_declared_member_is_not_a_live_user() {
    let got = refused(
        "iam_db_ta_red_10_deleted",
        |svc| {
            Box::pin(async move {
                let a = person(svc, 1).await;
                let d = person(svc, 2).await;
                sync(svc, &[("administrators", &[&a, &d])])
                    .await
                    .expect("sync");
                soft_delete_user(svc, &d).await;
                d
            })
        },
        "rid-deleted",
    );
    assert_refused(got, "not_live_user", "rid-deleted");
}

#[test]
fn red_10_an_archived_administrators_team_is_no_administrators_team() {
    let got = refused(
        "iam_db_ta_red_10_archived",
        |svc| {
            Box::pin(async move {
                let a = person(svc, 1).await;
                sync(svc, &[("administrators", &[&a])]).await.expect("sync");
                archive_team(svc, ADMINS).await;
                a
            })
        },
        "rid-archived",
    );
    assert_refused(got, "no_administrators_team", "rid-archived");
}

#[test]
fn red_10_an_absent_administrators_team_is_no_administrators_team() {
    let got = refused(
        "iam_db_ta_red_10_absent",
        |svc| Box::pin(async move { person(svc, 1).await }),
        "rid-absent",
    );
    assert_refused(got, "no_administrators_team", "rid-absent");
}

#[tokio::test]
async fn red_10_the_revoke_instruction_rides_the_declared_arm_and_redemption_revokes() {
    let svc = fresh("iam_db_ta_red_10_revoke").await;
    let m = person(&svc, 1).await;
    mint(&svc, &m, 11, None).await.expect("mint");
    mint(&svc, &m, 12, None).await.expect("mint");
    sync(&svc, &[("administrators", &[&m])])
        .await
        .expect("sync");

    demand_with(&svc, &m, 40, true, true, "rid-revoke")
        .await
        .expect("admitted with the instruction");
    let stored: i64 = sqlx::query_scalar(
        "SELECT CAST(revoke_existing_credentials AS SIGNED) FROM iam_enrolment
          WHERE secret_hash = ?",
    )
    .bind(vec![40u8; 32])
    .fetch_one(svc.pool())
    .await
    .expect("the enrolment row");
    assert_eq!(stored, 1);

    let got = redeem(&svc, 40, GOOD_HASH, "").await;
    assert_eq!(got.outcome, RedeemOutcome::Redeemed as i32);
    assert!(resolve_with(&svc, 11, true).await.user_id.is_empty());
    assert!(resolve_with(&svc, 12, true).await.user_id.is_empty());
}

#[test]
fn red_10_derivation_off_keeps_todays_predicate() {
    let ((), seen) = observed(|rt| {
        rt.block_on(async {
            let svc = fresh("iam_db_ta_red_10_off").await;
            let admin = person(&svc, 1).await;
            make_admin(&svc, &admin).await;
            demand_with(&svc, &admin, 21, false, false, "rid-a")
                .await
                .expect("column true, zero credentials");

            let held = person(&svc, 2).await;
            make_admin(&svc, &held).await;
            let c = mint(&svc, &held, 12, None).await.expect("mint");
            revoke_one(&svc, &held, &c).await;
            let err = demand_with(&svc, &held, 22, false, false, "rid-b")
                .await
                .expect_err("held");
            assert_eq!(err.code(), Code::PermissionDenied);
            assert_eq!(err.message(), DEMAND_REFUSAL);

            let plain = person(&svc, 3).await;
            let err = demand_with(&svc, &plain, 23, false, false, "rid-c")
                .await
                .expect_err("not admin");
            assert_eq!(err.code(), Code::PermissionDenied);

            let before = enrolments(&svc).await;
            let err = demand_with(&svc, &admin, 24, false, true, "rid-d")
                .await
                .expect_err("the pair");
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(enrolments(&svc).await, before);
        })
    });
    assert_eq!(
        series(&seen, DEMAND_REFUSED),
        BTreeMap::from([
            ("{conjunct=held_credential}".to_string(), 1),
            ("{conjunct=not_admin}".to_string(), 1),
        ])
    );
    assert!(series(&seen, REENROLMENT).is_empty());
}

// ---------------------------------------------------------------------------
// F2: the pre-minted first administrator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn red_11_the_first_sync_stores_a_declared_administrator_as_pending() {
    let svc = fresh("iam_db_ta_red_11").await;
    let a = uuid7();
    let got = sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    assert_eq!(got.teams_inserted, 1);
    assert_eq!(got.members_added, 0);
    assert_eq!(got.pending_administrator_user_ids, vec![a.clone()]);
    assert_eq!(got.administrators_live_members, 0);
    assert!(got.unknown_member_user_ids.is_empty());
    assert_eq!(pending(&svc).await, vec![a]);

    let other = fresh("iam_db_ta_red_11_other").await;
    let b = uuid7();
    let elsewhere = uuid7();
    let got = sync(
        &other,
        &[("administrators", &[&b]), ("other", &[&elsewhere])],
    )
    .await
    .expect("sync");
    assert_eq!(got.pending_administrator_user_ids, vec![b]);
    assert_eq!(got.unknown_member_user_ids, vec![elsewhere]);
}

#[tokio::test]
async fn red_12_the_declared_pending_id_is_created_and_is_an_administrator() {
    let svc = fresh("iam_db_ta_red_12").await;
    let a = uuid7();
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");

    let id = create_declared(&svc, &a, 1, "rid-12")
        .await
        .expect("created");
    assert_eq!(id, a);
    mint(&svc, &a, 11, None).await.expect("mint");
    let got = resolve_with(&svc, 11, true).await;
    assert_eq!(got.team_ids, vec![ADMINS]);
    assert!(got.is_admin);
    assert!(
        !resolve_with(&svc, 11, false).await.is_admin,
        "the column stays false"
    );
    assert!(pending(&svc).await.is_empty());

    let again = sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    assert_eq!((again.members_added, again.members_removed), (0, 0));
    assert_eq!(again.administrators_live_members, 1);
}

#[tokio::test]
async fn red_13_a_malformed_user_id_is_invalid_and_writes_nothing() {
    let svc = fresh("iam_db_ta_red_13").await;
    let a = uuid7();
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    let (u, p) = (users(&svc).await, pending(&svc).await);
    for bad in [
        "yadgar:user:0192F3C4-1A2B-7C3D-8E4F-0123456789AB",
        "yadgar:user:0192f3c4-1a2b-4c3d-8e4f-0123456789ab",
        "yadgar:user:0192f3c4-1a2b-7c3d-ce4f-0123456789ab",
        "0192f3c4-1a2b-7c3d-8e4f-0123456789ab",
        "yadgar:user:00000000-0000-0000-0000-000000000000",
        "yadgar:user:0192f3c4-1a2b-7c3d-8e4f-0123456789a",
    ] {
        let err = create_declared(&svc, bad, 1, "rid-13")
            .await
            .expect_err(bad);
        assert_eq!(err.code(), Code::InvalidArgument, "{bad}");
    }
    assert_eq!(users(&svc).await, u);
    assert_eq!(pending(&svc).await, p);
}

#[tokio::test]
async fn red_14_a_taken_user_id_is_already_exists_and_not_the_name_message() {
    let svc = fresh("iam_db_ta_red_14").await;
    let s = person(&svc, 1).await;
    soft_delete_user(&svc, &s).await;
    let p = uuid7();
    let got = sync(&svc, &[("administrators", &[&s, &p])])
        .await
        .expect("sync");
    assert_eq!(got.pending_administrator_user_ids, vec![p.clone()]);
    assert_eq!(members(&svc, ADMINS).await, vec![s.clone()]);
    let u = users(&svc).await;

    let err = create_declared(&svc, &s, 2, "rid-14")
        .await
        .expect_err("taken");
    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(err.message(), "that user id is taken");
    assert_eq!(users(&svc).await, u);

    // A colliding blind index with a fresh pending id: the name message.
    let err = create_declared(&svc, &p, 1, "rid-14b")
        .await
        .expect_err("name");
    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(err.message(), "a user with that name already exists");
    assert_eq!(users(&svc).await, u);
    assert_eq!(pending(&svc).await, vec![p]);
}

/// One F2 refusal, observed: the status, the counter series and the log.
fn create_refused(
    db_name: &'static str,
    setup: impl for<'a> FnOnce(
        &'a IamDb,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + 'a>>,
    rid: &'static str,
) -> (Status, BTreeMap<String, u64>, String) {
    let (err, seen) = observed(|rt| {
        rt.block_on(async {
            let svc = fresh(db_name).await;
            let target = setup(&svc).await;
            let (u, p, m) = (
                users(&svc).await,
                pending(&svc).await,
                members(&svc, ADMINS).await,
            );
            let err = create_declared(&svc, &target, 9, rid)
                .await
                .expect_err("refused");
            assert_eq!(users(&svc).await, u, "nothing written");
            assert_eq!(pending(&svc).await, p, "nothing written");
            assert_eq!(members(&svc, ADMINS).await, m, "nothing written");
            err
        })
    });
    (err, series(&seen, CREATE_REFUSED), seen.log)
}

fn assert_create_refused(got: (Status, BTreeMap<String, u64>, String), step: &str, rid: &str) {
    let (err, s, log) = got;
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), CREATE_REFUSAL, "byte-identical across steps");
    assert_eq!(
        s,
        one(&format!("step={step}")),
        "one increment, no other label"
    );
    let line = log
        .lines()
        .find(|l| l.contains("the bootstrap create-user was refused"))
        .unwrap_or_else(|| panic!("the warn line: {log}"));
    assert!(line.contains(rid), "{line}");
    assert!(line.contains(step), "{line}");
}

#[test]
fn red_15_an_undeclared_user_id_is_refused_not_declared() {
    let got = create_refused(
        "iam_db_ta_red_15",
        |svc| {
            Box::pin(async move {
                sync(svc, &[("administrators", &[&uuid7()])])
                    .await
                    .expect("sync");
                uuid7()
            })
        },
        "rid-15",
    );
    assert_create_refused(got, "not_declared", "rid-15");
}

#[test]
fn red_16_once_an_administrator_exists_every_user_id_is_refused() {
    for (name, second) in [("iam_db_ta_red_16_b", true), ("iam_db_ta_red_16_a", false)] {
        let got = create_refused(
            name,
            move |svc| {
                Box::pin(async move {
                    let a = uuid7();
                    let b = uuid7();
                    sync(svc, &[("administrators", &[&a, &b])])
                        .await
                        .expect("sync");
                    create_declared(svc, &a, 1, "rid-first")
                        .await
                        .expect("first");
                    match second {
                        true => b,
                        false => a,
                    }
                })
            },
            "rid-16",
        );
        assert_create_refused(got, "administrator_exists", "rid-16");
    }
}

#[test]
fn red_17_no_administrators_team_refuses_before_any_sync_and_when_archived() {
    let got = create_refused(
        "iam_db_ta_red_17_none",
        |_| Box::pin(async move { uuid7() }),
        "rid-17",
    );
    assert_create_refused(got, "no_administrators_team", "rid-17");

    let got = create_refused(
        "iam_db_ta_red_17_archived",
        |svc| {
            Box::pin(async move {
                let a = uuid7();
                sync(svc, &[("administrators", &[&a])]).await.expect("sync");
                archive_team(svc, ADMINS).await;
                a
            })
        },
        "rid-17b",
    );
    assert_create_refused(got, "no_administrators_team", "rid-17b");
}

#[test]
fn red_18_concurrent_creates_admit_exactly_one() {
    for (name, same) in [
        ("iam_db_ta_red_18_same", true),
        ("iam_db_ta_red_18_diff", false),
    ] {
        let ((), seen) = observed(|rt| {
            rt.block_on(async {
                let svc = fresh(name).await;
                let a = uuid7();
                let b = uuid7();
                sync(&svc, &[("administrators", &[&a, &b])])
                    .await
                    .expect("sync");
                let other = if same { a.clone() } else { b.clone() };
                let (x, y) = tokio::join!(
                    create_declared(&svc, &a, 1, "rid-x"),
                    create_declared(&svc, &other, 2, "rid-y"),
                );
                let oks = [x.is_ok(), y.is_ok()].iter().filter(|o| **o).count();
                assert_eq!(oks, 1, "{x:?} {y:?}");
                let err = x.err().or(y.err()).expect("one refusal");
                assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
                assert_eq!(users(&svc).await, 1);
            })
        });
        assert_eq!(
            series(&seen, CREATE_REFUSED),
            one("step=administrator_exists")
        );
    }
}

#[tokio::test]
async fn red_19_an_empty_user_id_mints_as_today() {
    let svc = fresh("iam_db_ta_red_19").await;
    let id = person(&svc, 1).await;
    let uuid = id.strip_prefix("yadgar:user:").expect("the prefix");
    let parsed = uuid::Uuid::parse_str(uuid).expect("a uuid");
    assert_eq!(parsed.get_version_num(), 7);
    assert_eq!(users(&svc).await, 1);
    assert!(pending(&svc).await.is_empty());
}

#[tokio::test]
async fn red_20_two_concurrent_first_syncs_end_in_one_declarations_state() {
    let svc = fresh("iam_db_ta_red_20").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    let c = person(&svc, 3).await;
    let x: &[(&str, &[&str])] = &[("administrators", &[&a])];
    let y: &[(&str, &[&str])] = &[("administrators", &[&b]), ("other", &[&c])];
    let (rx, ry) = tokio::join!(sync(&svc, x), sync(&svc, y));
    rx.expect("x");
    ry.expect("y");

    let live: Vec<String> =
        sqlx::query_scalar("SELECT id FROM iam_team WHERE deleted_at IS NULL ORDER BY id")
            .fetch_all(svc.pool())
            .await
            .expect("teams");
    let admins = members(&svc, ADMINS).await;
    let x_state = live == vec![ADMINS.to_string()] && admins == vec![a.clone()];
    let y_state = live == vec![ADMINS.to_string(), OTHER.to_string()]
        && admins == vec![b.clone()]
        && members(&svc, OTHER).await == vec![c.clone()];
    assert!(
        x_state ^ y_state,
        "teams {live:?}, administrators {admins:?}"
    );
}

/// A REPEATABLE READ connection holding a locking read — a gap lock on an
/// absent key, or the row lock on a present one — so the first transaction of
/// red 21 stalls on its next write after its FOR UPDATE.
async fn gap_lock(svc: &IamDb, sql: &'static str, binds: &[&str]) -> sqlx::MySqlConnection {
    use sqlx::Connection;
    let mut conn = sqlx::MySqlConnection::connect_with(&svc.pool().connect_options())
        .await
        .expect("a connection of its own");
    sqlx::query("BEGIN")
        .execute(&mut conn)
        .await
        .expect("begin");
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.fetch_optional(&mut conn).await.expect("the gap lock");
    conn
}

async fn release(mut conn: sqlx::MySqlConnection) {
    sqlx::query("ROLLBACK")
        .execute(&mut conn)
        .await
        .expect("rollback");
}

/// CreateUser first: it holds the row and stalls on its user insert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn red_21_create_first_then_the_sync_is_refused_by_the_lockout_guard() {
    let svc = Arc::new(fresh("iam_db_ta_red_21_create").await);
    let a = uuid7();
    let b = uuid7();
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("pending A");
    let held = gap_lock(
        &svc,
        "SELECT id FROM iam_user WHERE id = ? FOR UPDATE",
        &[&a],
    )
    .await;
    let create = {
        let (svc, a) = (svc.clone(), a.clone());
        tokio::spawn(async move { create_declared(&svc, &a, 1, "rid-21").await })
    };
    settle().await;
    let syncing = {
        let (svc, b) = (svc.clone(), b.clone());
        tokio::spawn(async move { sync(&svc, &[("administrators", &[&b])]).await })
    };
    settle().await;
    release(held).await;
    let created = create.await.expect("join");
    let synced = syncing.await.expect("join");
    assert_eq!(created.expect("CreateUser wins"), a);
    assert_eq!(
        synced.expect_err("the lockout guard refuses B").code(),
        Code::FailedPrecondition
    );
    assert!(pending(&svc).await.is_empty());
    assert_eq!(members(&svc, ADMINS).await, vec![a]);
}

/// SyncTeams first: it holds the row and stalls on its pending delete, before
/// any foreign-key check could take a parent-row lock that would serialise the
/// two by accident (measured: a barrier on the pending INSERT does).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn red_21_sync_first_then_the_create_is_not_declared() {
    let svc = Arc::new(fresh("iam_db_ta_red_21_sync").await);
    let a = uuid7();
    let b = uuid7();
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("pending A");
    let held = gap_lock(
        &svc,
        "SELECT user_id FROM iam_team_member_pending
          WHERE team_id = ? AND user_id = ? FOR UPDATE",
        &[ADMINS, &a],
    )
    .await;
    let syncing = {
        let (svc, b) = (svc.clone(), b.clone());
        tokio::spawn(async move { sync(&svc, &[("administrators", &[&b])]).await })
    };
    settle().await;
    let create = {
        let (svc, a) = (svc.clone(), a.clone());
        tokio::spawn(async move { create_declared(&svc, &a, 1, "rid-21b").await })
    };
    settle().await;
    release(held).await;
    let synced = syncing.await.expect("join");
    let created = create.await.expect("join");
    assert_eq!(
        synced
            .expect("the sync wins")
            .pending_administrator_user_ids,
        vec![b.clone()]
    );
    let err = created.expect_err("A is no longer declared");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    assert_eq!(pending(&svc).await, vec![b]);
    assert_eq!(users(&svc).await, 0);
}

#[tokio::test]
async fn red_22_a_pending_uuid_can_be_replaced_while_no_administrator_is_live() {
    let svc = fresh("iam_db_ta_red_22").await;
    let a = uuid7();
    let b = uuid7();
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("pending A");
    let got = sync(&svc, &[("administrators", &[&b])])
        .await
        .expect("A -> B");
    assert_eq!(got.pending_administrator_user_ids, vec![b.clone()]);
    assert_eq!(pending(&svc).await, vec![b]);
    let err = create_declared(&svc, &a, 1, "rid-22").await.expect_err("A");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), CREATE_REFUSAL);
}

#[tokio::test]
async fn red_23_the_runtime_team_verbs_are_refused() {
    let svc = fresh("iam_db_ta_red_23").await;
    let a = person(&svc, 1).await;
    let b = person(&svc, 2).await;
    sync(&svc, &[("administrators", &[&a]), ("other", &[&b])])
        .await
        .expect("sync");
    let before = row_counts(&svc).await;

    let err = svc
        .add_team_member_as(
            Some(IAM_CALLER),
            Request::new(AddTeamMemberRequest {
                team_id: OTHER.into(),
                user_id: a.clone(),
                ..Default::default()
            }),
        )
        .await
        .expect_err("refused");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("teams are declared in GitOps"),
        "{err:?}"
    );

    let err = svc
        .remove_team_member_as(
            Some(IAM_CALLER),
            Request::new(RemoveTeamMemberRequest {
                team_id: OTHER.into(),
                user_id: b.clone(),
                ..Default::default()
            }),
        )
        .await
        .expect_err("refused");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("teams are declared in GitOps"),
        "{err:?}"
    );
    assert_eq!(row_counts(&svc).await, before);
}

#[tokio::test]
async fn red_24_an_absent_admin_from_team_keeps_the_column() {
    let svc = fresh("iam_db_ta_red_24").await;
    let a = person(&svc, 1).await;
    mint(&svc, &a, 11, None).await.expect("mint");
    sync(&svc, &[("administrators", &[&a])])
        .await
        .expect("sync");
    let got = resolve(&svc, 11).await;
    assert_eq!(got.team_ids, vec![ADMINS]);
    assert!(!got.is_admin);
}
