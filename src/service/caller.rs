//! The caller gate on every `IamDbService` verb (ledger 1629, ADR-0972 (1)).
//!
//! **mTLS SAYS "ONE OF OURS", NOT "WHICH ONE".** Every module's client leaf
//! (`gateway-caller`, `iam-caller`, `task-caller`, `project-caller`,
//! `seeder-caller`) verifies against the same internal authority. Before this
//! gate, any pod that held one of those leaves and passed the NetworkPolicy
//! could call `SetUserAdmin`, `CreateUser` or `RevokeAllCredentials` here. The
//! NetworkPolicy selects pods by a label, so it is not an identity.
//!
//! So every verb reads the common name off the verified client leaf
//! (`yadgar_lifecycle::serve_tls::caller_common_name`) and admits
//! [`IAM_CALLER`] only. `GetKeyIdentity` and `SetKeyIdentity` are included:
//! `iam` calls them on the same channel, with the same leaf.
//!
//! **NO NAME IS A REFUSAL.** A cleartext listener, a `clientAuth: "off"`
//! listener, a caller that presents no leaf, and a leaf with no single common
//! name all give `None`. The gate fails closed on all of them.
//!
//! **THE GATE RUNS BEFORE ANY STORE WORK**, right after the `Call` starts. So a
//! refused call opens no connection, and its telemetry record still says
//! `PERMISSION_DENIED` (D67).

use tonic::Status;
use yadgar_telemetry::observe::Call;

/// The one caller this service admits: the common name on `iam`'s client leaf
/// (`iam-client-tls`, issued by `platform`).
///
/// Compared EXACTLY. The name `platform` writes is lower-case, and a leaf
/// spelled otherwise is not that leaf.
pub const IAM_CALLER: &str = "iam-caller";

/// Every refusal by the gate, labelled `caller` with the PRESENTED common name,
/// or `none` when the request carried no name.
///
/// **WHY A COUNTER OF ITS OWN.** `PERMISSION_DENIED` on the call record is not
/// a usable signal for the gate: the bootstrap-demand path on `CreateEnrolment`
/// already returns it (see `ENROLMENT_DEMAND_REFUSED`). This series moves only
/// when the gate refuses. The operator's wrong-name probe after a roll expects
/// it to rise by exactly the probe's own calls.
///
/// **THE LABEL IS BOUNDED, SO D67 ALLOWS IT.** D67 forbids a label minted from
/// caller-influenced data. This value is not free text from the request: it is
/// the common name of a leaf the configured internal authority signed, because
/// an unverified leaf never completes the handshake. The set is the leaves
/// `platform` issues, plus `none`.
pub const CALLER_REFUSED: &str = "yadgar_iamdb_caller_refused_total";

/// The label value for a request that carried no client-certificate name.
const NO_CALLER: &str = "none";

/// Admit `caller` and hand the `Call` back, or refuse.
///
/// A refusal counts [`CALLER_REFUSED`], finishes the `Call` as
/// `PERMISSION_DENIED`, and returns that status. The message names the one
/// admitted caller and the presented one, because iam logs it and the
/// operator reads that log first.
pub(super) fn admitted(caller: Option<&str>, call: Call) -> Result<Call, Status> {
    if caller == Some(IAM_CALLER) {
        return Ok(call);
    }
    metrics::counter!(CALLER_REFUSED, "caller" => caller.unwrap_or(NO_CALLER).to_string())
        .increment(1);
    call.fail("PERMISSION_DENIED");
    Err(Status::permission_denied(format!(
        "iam-db admits only iam (ADR-0972): the client certificate must name \
         {IAM_CALLER:?}, and this call {}. Every module's leaf verifies against the \
         same authority, so verification alone admits nobody here",
        caller.map_or_else(
            || "carries no client-certificate name".to_string(),
            |c| format!("names {c:?}")
        )
    )))
}
