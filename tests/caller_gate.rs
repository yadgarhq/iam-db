//! The caller gate on every `IamDbService` verb (ledger 1629, ADR-0972 (1)).
//!
//! iam-db admits ONE caller: the client leaf whose common name is
//! [`IAM_CALLER`]. mTLS alone says "one of ours", because every module's leaf
//! verifies against the same internal authority. The gate says "which one".
//!
//! **NO DATABASE, AND THAT IS THE ZERO-CALL ASSERTION.** The service runs on a
//! pool that points at a [`CountingStore`]: a TCP listener that counts every
//! connection and answers none. A refused call must come back
//! `PERMISSION_DENIED` with the count still zero. A gate that ran after the
//! store work, or no gate at all, opens a connection and comes back with some
//! other code. This is the iam-db form of the FakeDb zero-call check the plan
//! asks for (memory 535727): a refusal that still reached the store is not a
//! refusal.
//!
//! **A SYNC TEST BUILDING ITS OWN current_thread RUNTIME**, as `contract.rs`
//! does for its counters: a LOCAL metrics recorder rather than a global one,
//! because this binary's tests run in parallel.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use sqlx::mysql::MySqlPoolOptions;
use tonic::{Code, Request, Status};
use yadgar_iam_db::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbService as _;
use yadgar_iam_db::pb::yadgar::iamdb::v1::*;
use yadgar_iam_db::service::{IamDb, CALLER_REFUSED, IAM_CALLER};

/// A listener standing where the database would be. It accepts, counts and
/// drops every connection, so a call that reaches the store fails fast and
/// leaves a mark.
struct CountingStore {
    port: u16,
    connections: Arc<AtomicUsize>,
}

impl CountingStore {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a local port");
        let port = listener.local_addr().expect("a local address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// The service under test, on a LAZY pool aimed at this listener. Nothing
    /// connects until a handler asks the pool for a connection.
    fn service(&self) -> IamDb {
        let pool = MySqlPoolOptions::new()
            .acquire_timeout(Duration::from_millis(300))
            .connect_lazy(&format!("mysql://gate:gate@127.0.0.1:{}/gate", self.port))
            .expect("a lazy pool");
        IamDb::new(pool)
    }
}

/// Run `body` on a current-thread runtime under a local recorder, and return
/// its result with the `caller` label of every `CALLER_REFUSED` count.
fn under_recorder<T>(
    body: impl FnOnce(&tokio::runtime::Runtime) -> T,
) -> (T, BTreeMap<String, u64>) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let out = metrics::with_local_recorder(&recorder, || body(&rt));

    let mut refused = BTreeMap::new();
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        if key.key().name() != CALLER_REFUSED {
            continue;
        }
        let caller = key
            .key()
            .labels()
            .find(|l| l.key() == "caller")
            .map(|l| l.value().to_string())
            .unwrap_or_else(|| "<no caller label>".to_string());
        if let DebugValue::Counter(n) = value {
            *refused.entry(caller).or_insert(0) += n;
        }
    }
    (out, refused)
}

/// The outcome of one RPC, reduced to what the gate decides.
type Outcome = (&'static str, Result<(), Status>);

/// EVERY `IamDbService` RPC, driven through its `_as` seam as `caller`, each
/// with a default request.
async fn every_rpc_as(svc: &IamDb, caller: Option<&str>) -> Vec<Outcome> {
    macro_rules! call {
        ($name:literal, $method:ident, $req:ty) => {
            (
                $name,
                svc.$method(caller, Request::new(<$req>::default()))
                    .await
                    .map(|_| ()),
            )
        };
    }
    vec![
        call!(
            "ResolveCredential",
            resolve_credential_as,
            ResolveCredentialRequest
        ),
        call!(
            "GetPasswordHash",
            get_password_hash_as,
            GetPasswordHashRequest
        ),
        call!("SetPassword", set_password_as, SetPasswordRequest),
        call!(
            "CreateCredential",
            create_credential_as,
            CreateCredentialRequest
        ),
        call!(
            "RevokeCredential",
            revoke_credential_as,
            RevokeCredentialRequest
        ),
        call!(
            "RevokeAllCredentials",
            revoke_all_credentials_as,
            RevokeAllCredentialsRequest
        ),
        call!("CreateUser", create_user_as, CreateUserRequest),
        call!("AddTeamMember", add_team_member_as, AddTeamMemberRequest),
        call!(
            "RemoveTeamMember",
            remove_team_member_as,
            RemoveTeamMemberRequest
        ),
        call!(
            "CreateEnrolment",
            create_enrolment_as,
            CreateEnrolmentRequest
        ),
        call!(
            "RedeemEnrolment",
            redeem_enrolment_as,
            RedeemEnrolmentRequest
        ),
        call!(
            "ListCredentials",
            list_credentials_as,
            ListCredentialsRequest
        ),
        call!("SetUserAdmin", set_user_admin_as, SetUserAdminRequest),
        call!(
            "SetRateLimitOverride",
            set_rate_limit_override_as,
            SetRateLimitOverrideRequest
        ),
        call!(
            "SetInheritedSetting",
            set_inherited_setting_as,
            SetInheritedSettingRequest
        ),
        call!("GetKeyIdentity", get_key_identity_as, GetKeyIdentityRequest),
        call!("SetKeyIdentity", set_key_identity_as, SetKeyIdentityRequest),
    ]
}

/// EVERY RPC through the TRAIT METHOD, with a bare request: no TLS crossed, so
/// there is no client-certificate name. This is the path a cleartext listener
/// or a `clientAuth: "off"` listener hands the service.
async fn every_rpc_via_the_trait(svc: &IamDb) -> Vec<Outcome> {
    macro_rules! call {
        ($name:literal, $method:ident, $req:ty) => {
            (
                $name,
                svc.$method(Request::new(<$req>::default()))
                    .await
                    .map(|_| ()),
            )
        };
    }
    vec![
        call!(
            "ResolveCredential",
            resolve_credential,
            ResolveCredentialRequest
        ),
        call!("GetPasswordHash", get_password_hash, GetPasswordHashRequest),
        call!("SetPassword", set_password, SetPasswordRequest),
        call!(
            "CreateCredential",
            create_credential,
            CreateCredentialRequest
        ),
        call!(
            "RevokeCredential",
            revoke_credential,
            RevokeCredentialRequest
        ),
        call!(
            "RevokeAllCredentials",
            revoke_all_credentials,
            RevokeAllCredentialsRequest
        ),
        call!("CreateUser", create_user, CreateUserRequest),
        call!("AddTeamMember", add_team_member, AddTeamMemberRequest),
        call!(
            "RemoveTeamMember",
            remove_team_member,
            RemoveTeamMemberRequest
        ),
        call!("CreateEnrolment", create_enrolment, CreateEnrolmentRequest),
        call!("RedeemEnrolment", redeem_enrolment, RedeemEnrolmentRequest),
        call!("ListCredentials", list_credentials, ListCredentialsRequest),
        call!("SetUserAdmin", set_user_admin, SetUserAdminRequest),
        call!(
            "SetRateLimitOverride",
            set_rate_limit_override,
            SetRateLimitOverrideRequest
        ),
        call!(
            "SetInheritedSetting",
            set_inherited_setting,
            SetInheritedSettingRequest
        ),
        call!("GetKeyIdentity", get_key_identity, GetKeyIdentityRequest),
        call!("SetKeyIdentity", set_key_identity, SetKeyIdentityRequest),
    ]
}

/// Every outcome that is NOT a `PERMISSION_DENIED`, by RPC name.
fn not_refused(outcomes: &[Outcome]) -> Vec<String> {
    outcomes
        .iter()
        .filter(|(_, r)| !matches!(r, Err(s) if s.code() == Code::PermissionDenied))
        .map(|(name, r)| format!("{name}: {:?}", r.as_ref().map_err(Status::code)))
        .collect()
}

/// **THE LISTS ABOVE ARE THE WHOLE CONTRACT, AND THIS KEEPS THEM SO.** An RPC
/// added to `iamdb.proto` and not to the lists would be a verb no test gates.
#[test]
fn the_rpc_lists_name_every_rpc_on_the_contract() {
    let proto = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/proto/yadgar/iamdb/v1/iamdb.proto"
    ))
    .expect("the vendored contract");
    let on_the_contract = proto
        .lines()
        .filter(|l| l.trim_start().starts_with("rpc "))
        .count();

    let ((as_seam, via_trait), _) = under_recorder(|rt| {
        rt.block_on(async {
            let store = CountingStore::start().await;
            let svc = store.service();
            (
                every_rpc_as(&svc, None).await.len(),
                every_rpc_via_the_trait(&svc).await.len(),
            )
        })
    });
    assert_eq!(as_seam, on_the_contract);
    assert_eq!(via_trait, on_the_contract);
}

/// A leaf that verifies but names ANOTHER module is refused on every verb, and
/// no verb reaches the store.
#[test]
fn every_rpc_from_a_non_iam_leaf_is_refused_before_any_store_call() {
    for caller in ["task-caller", "gateway-caller", "IAM-CALLER", "iam-caller "] {
        let ((outcomes, connections), _) = under_recorder(|rt| {
            rt.block_on(async {
                let store = CountingStore::start().await;
                let svc = store.service();
                let outcomes = every_rpc_as(&svc, Some(caller)).await;
                (outcomes, store.connections())
            })
        });
        assert_eq!(
            not_refused(&outcomes),
            Vec::<String>::new(),
            "every RPC from {caller:?} must be PERMISSION_DENIED"
        );
        assert_eq!(
            connections, 0,
            "a refused call from {caller:?} must reach no store"
        );
    }
}

/// No client-certificate name — no TLS, `clientAuth: "off"`, or no leaf — is a
/// refusal on every verb, through the seam AND through the trait method.
#[test]
fn every_rpc_with_no_client_certificate_name_is_refused() {
    let ((as_seam, via_trait, connections), _) = under_recorder(|rt| {
        rt.block_on(async {
            let store = CountingStore::start().await;
            let svc = store.service();
            let as_seam = every_rpc_as(&svc, None).await;
            let via_trait = every_rpc_via_the_trait(&svc).await;
            (as_seam, via_trait, store.connections())
        })
    });
    assert_eq!(not_refused(&as_seam), Vec::<String>::new());
    assert_eq!(not_refused(&via_trait), Vec::<String>::new());
    assert_eq!(connections, 0, "a refused call must reach no store");
}

/// THE POSITIVE CONTROL. `iam`'s leaf is admitted on every verb, so a gate that
/// refuses everyone cannot pass the two cases above alone.
///
/// Admitted means "not refused by the gate": each call then fails on the dead
/// store or on its own validation, and that is the answer this test expects.
#[test]
fn the_iam_leaf_is_admitted_on_every_rpc() {
    let ((outcomes, connections), refused) = under_recorder(|rt| {
        rt.block_on(async {
            let store = CountingStore::start().await;
            let svc = store.service();
            let outcomes = every_rpc_as(&svc, Some(IAM_CALLER)).await;
            (outcomes, store.connections())
        })
    });
    let denied: Vec<&str> = outcomes
        .iter()
        .filter(|(_, r)| matches!(r, Err(s) if s.code() == Code::PermissionDenied))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(denied, Vec::<&str>::new(), "iam's leaf must pass the gate");
    assert!(
        refused.is_empty(),
        "an admitted call counts no refusal: {refused:?}"
    );
    assert!(connections > 0, "an admitted call must go on to the store");
}

/// The gate's own counter, labelled with the PRESENTED name, or `none`.
///
/// `PERMISSION_DENIED` alone is not a usable signal: the bootstrap-demand path
/// already returns it (`service/enrolment/demand.rs`).
#[test]
fn a_gate_refusal_increments_caller_refused_with_the_presented_name() {
    let (_, refused) = under_recorder(|rt| {
        rt.block_on(async {
            let store = CountingStore::start().await;
            let svc = store.service();
            let _ = svc
                .get_key_identity_as(
                    Some("task-caller"),
                    Request::new(GetKeyIdentityRequest::default()),
                )
                .await;
            let _ = svc
                .get_key_identity(Request::new(GetKeyIdentityRequest::default()))
                .await;
            let _ = svc
                .get_key_identity_as(
                    Some(IAM_CALLER),
                    Request::new(GetKeyIdentityRequest::default()),
                )
                .await;
        })
    });
    assert_eq!(
        refused,
        BTreeMap::from([("none".to_string(), 1), ("task-caller".to_string(), 1)]),
        "one count per refusal, labelled with the presented name or `none`, \
         and none for the admitted call"
    );
}

/// The refusal names the one admitted caller and what was presented, so the
/// operator reading iam's log sees the cause.
#[test]
fn the_refusal_names_the_admitted_caller_and_the_presented_one() {
    let (status, _) = under_recorder(|rt| {
        rt.block_on(async {
            let store = CountingStore::start().await;
            store
                .service()
                .resolve_credential_as(
                    Some("task-caller"),
                    Request::new(ResolveCredentialRequest::default()),
                )
                .await
                .expect_err("a non-iam leaf must be refused")
        })
    });
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(
        status.message().contains(IAM_CALLER) && status.message().contains("task-caller"),
        "the refusal must name {IAM_CALLER:?} and the presented name: {}",
        status.message()
    );
}
