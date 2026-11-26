//! AC5: `LookupUser` writes exactly one actor record per call, BEFORE the
//! request is validated, naming `rpc="LookupUser"`, an empty `target`, the
//! call's request id, and the actor (or `<unattributed>`). The record is an
//! attempt, never an outcome. The actor never changes the answer, and the blind
//! index is never rendered in the log in any form. Against a real MariaDB.
//!
//! The log is read through ONE process-wide subscriber, installed once, whose
//! writer appends to a buffer only the calling thread can see and only while
//! its guard lives (per-test `set_default` rebuilds tracing's callsite cache and
//! loses records under parallel tests, as in yaadgaar 610), so lines from other
//! tests in this binary cannot reach the buffer.

mod db;

use db::*;
use tonic::{Code, Request};
use yadgar_iam_db::pb::yadgar::common::v1::UnverifiedActor;
use yadgar_iam_db::service::{IamDb, IAM_CALLER};

type Sink = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

thread_local! {
    /// The buffer of the capture that is live on THIS thread, if any.
    static SINK: std::cell::RefCell<Option<Sink>> = const { std::cell::RefCell::new(None) };
}

/// Writes each log line to the calling thread's live capture, or drops it.
#[derive(Clone)]
struct Capture;

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        SINK.with(|sink| {
            if let Some(sink) = sink.borrow().as_ref() {
                sink.lock()
                    .expect("the capture buffer")
                    .extend_from_slice(buf);
            }
        });
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

/// Ends this thread's capture when dropped.
struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        SINK.with(|sink| *sink.borrow_mut() = None);
    }
}

/// Collect this thread's `tracing` output while the guard lives. ONE
/// process-wide subscriber is installed once and never replaced, so no test
/// rebuilds tracing's callsite interest while another test logs; each thread
/// writes only to its own buffer, and only while its guard lives.
fn capturing() -> (CaptureGuard, Sink) {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(Capture)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global subscriber in this test binary");
    });
    let buf: Sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(buf.clone()));
    (CaptureGuard, buf)
}

fn rendered(buf: &Sink) -> String {
    String::from_utf8(buf.lock().expect("the capture buffer").clone()).expect("the log is utf-8")
}

fn actor(id: &str) -> Option<UnverifiedActor> {
    Some(UnverifiedActor {
        user_id: id.to_string(),
    })
}

/// One `LookupUser` call with `blind` as the blind index, the given actor and
/// (when non-empty) request id. Returns the result and everything logged
/// around that one call.
async fn lookup(
    svc: &IamDb,
    blind: Vec<u8>,
    unverified_actor: Option<UnverifiedActor>,
    request_id: &str,
) -> (Result<String, tonic::Status>, String) {
    use yadgar_iam_db::pb::yadgar::iamdb::v1::LookupUserRequest;
    let mut req = Request::new(LookupUserRequest {
        external_id_blind_index: blind,
        unverified_actor,
    });
    if !request_id.is_empty() {
        req.metadata_mut().insert(
            "x-yadgar-request-id",
            request_id.parse().expect("an ascii request id"),
        );
    }
    let (_guard, buf) = capturing();
    let answer = svc
        .lookup_user_as(Some(IAM_CALLER), req)
        .await
        .map(|r| r.into_inner().user_id);
    let log = rendered(&buf);
    (answer, log)
}

/// The `LookupUser` record lines in `log`.
fn records(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|l| l.contains(r#"rpc="LookupUser""#))
        .collect()
}

/// The one `LookupUser` record in `log`.
fn the_record(log: &str) -> &str {
    let lines = records(log);
    assert_eq!(lines.len(), 1, "exactly one LookupUser record: {log}");
    lines[0]
}

#[tokio::test]
async fn an_attributed_lookup_writes_one_record_naming_actor_request_and_no_target() {
    let svc = fresh("iam_db_test_lookup_actor_main").await;
    let first = person(&svc, 21).await;
    let second = person(&svc, 22).await;

    // AC5: a person at [21; 32], an actor and a request id -> Ok with the id and
    // exactly one record carrying all three.
    let (answer, log) = lookup(
        &svc,
        vec![21u8; 32],
        actor("yadgar:user:admin-one"),
        "rid-lookup-1",
    )
    .await;
    assert_eq!(answer.expect("lookup"), first);
    let line = the_record(&log);
    assert!(
        line.contains(r#"unverified_actor="yadgar:user:admin-one""#),
        "the actor must reach the record: {line}"
    );
    assert!(
        line.contains(r#"target="""#),
        "the target is the empty string: {line}"
    );
    assert!(
        line.contains(r#"request_id="rid-lookup-1""#),
        "the call's request id must be on the record: {line}"
    );

    // AC5: triangulation, another person, actor and request id.
    let (answer, log) = lookup(
        &svc,
        vec![22u8; 32],
        actor("yadgar:user:admin-two"),
        "rid-lookup-2",
    )
    .await;
    assert_eq!(answer.expect("lookup"), second);
    let line = the_record(&log);
    assert!(
        line.contains(r#"unverified_actor="yadgar:user:admin-two""#),
        "the second actor must reach the record: {line}"
    );
    assert!(line.contains(r#"target="""#), "empty target: {line}");
    assert!(
        line.contains(r#"request_id="rid-lookup-2""#),
        "the second request id must be on the record: {line}"
    );
    assert!(
        !line.contains("yadgar:user:admin-one") && !line.contains("rid-lookup-1"),
        "the record belongs to this call only: {line}"
    );
}

#[tokio::test]
async fn an_absent_or_empty_actor_is_recorded_as_unattributed() {
    let svc = fresh("iam_db_test_lookup_actor_unattributed").await;
    person(&svc, 21).await;
    person(&svc, 22).await;

    // AC5: no actor, then an actor holding the empty string: each call writes
    // one record, both unattributed, never an actor whose id is "".
    for (blind, given) in [
        (21u8, None),
        (21u8, Some(UnverifiedActor::default())),
        (22u8, None),
        (
            22u8,
            Some(UnverifiedActor {
                user_id: String::new(),
            }),
        ),
    ] {
        let (answer, log) = lookup(&svc, vec![blind; 32], given, "rid-unattributed").await;
        answer.expect("lookup");
        let line = the_record(&log);
        assert!(
            line.contains(r#"unverified_actor="<unattributed>""#),
            "an absent or empty actor is unattributed: {line}"
        );
        assert!(
            !line.contains(r#"unverified_actor="""#),
            "an empty actor id must never be recorded as an actor: {line}"
        );
    }
}

#[tokio::test]
async fn a_malformed_blind_index_is_refused_after_one_record_was_written() {
    let svc = fresh("iam_db_test_lookup_actor_invalid").await;
    person(&svc, 21).await;

    // AC5: 5 bytes and an actor -> InvalidArgument and exactly one record, so the
    // record is written before the length check.
    let (answer, log) = lookup(
        &svc,
        vec![21u8; 5],
        actor("yadgar:user:admin-one"),
        "rid-invalid",
    )
    .await;
    assert_eq!(answer.expect_err("5 bytes").code(), Code::InvalidArgument);
    let line = the_record(&log);
    assert!(
        line.contains(r#"unverified_actor="yadgar:user:admin-one""#),
        "the refused attempt still names its actor: {line}"
    );

    // AC5: triangulation, other wrong lengths, each also one record.
    for blind in [Vec::new(), vec![21u8; 31], vec![21u8; 33]] {
        let len = blind.len();
        let (answer, log) =
            lookup(&svc, blind, actor("yadgar:user:admin-two"), "rid-invalid-2").await;
        assert_eq!(
            answer.expect_err("wrong length").code(),
            Code::InvalidArgument,
            "{len} bytes"
        );
        let line = the_record(&log);
        assert!(
            line.contains(r#"unverified_actor="yadgar:user:admin-two""#),
            "{len} bytes: the refused attempt names its actor: {line}"
        );
    }
}

#[tokio::test]
async fn a_lookup_that_finds_nobody_still_writes_one_record() {
    let svc = fresh("iam_db_test_lookup_actor_not_found").await;

    // AC5: an empty store, a well-formed index and an actor -> NotFound and one
    // record, so the record is an attempt and not an outcome.
    let (answer, log) = lookup(
        &svc,
        vec![40u8; 32],
        actor("yadgar:user:admin-one"),
        "rid-not-found",
    )
    .await;
    assert_eq!(answer.expect_err("empty store").code(), Code::NotFound);
    let line = the_record(&log);
    assert!(
        line.contains(r#"unverified_actor="yadgar:user:admin-one""#),
        "the unanswered attempt names its actor: {line}"
    );
    assert!(line.contains(r#"target="""#), "empty target: {line}");

    // AC5: triangulation, another index, another actor.
    let (answer, log) = lookup(
        &svc,
        vec![41u8; 32],
        actor("yadgar:user:admin-two"),
        "rid-not-found-2",
    )
    .await;
    assert_eq!(answer.expect_err("empty store").code(), Code::NotFound);
    let line = the_record(&log);
    assert!(
        line.contains(r#"unverified_actor="yadgar:user:admin-two""#),
        "the second unanswered attempt names its actor: {line}"
    );
}

#[tokio::test]
async fn the_actor_never_changes_the_answer() {
    let svc = fresh("iam_db_test_lookup_actor_decides_nothing").await;
    let first = person(&svc, 21).await;
    let second = person(&svc, 22).await;

    // AC5: no actor, the admin actor and an unrelated actor all answer the
    // same user id.
    for (blind, expected) in [(21u8, &first), (22u8, &second)] {
        for given in [
            None,
            actor("yadgar:user:admin-one"),
            actor("someone-else"),
            actor(expected),
        ] {
            let (answer, _log) = lookup(&svc, vec![blind; 32], given, "rid-decides").await;
            assert_eq!(
                &answer.expect("lookup"),
                expected,
                "the actor must not change who is found"
            );
        }
    }
}

/// Standard and URL-safe base64 of `bytes`, padded and unpadded.
fn base64_forms(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for alphabet in [
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ] {
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..=chunk.len() {
                s.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out.push(s.clone());
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        out.push(s);
    }
    out
}

/// Every way the logging stack could render `bytes`, as substrings.
fn renderings(bytes: &[u8]) -> Vec<String> {
    let decimal: Vec<String> = bytes.iter().map(u8::to_string).collect();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut all = vec![
        format!("{bytes:?}"),
        format!("[{}]", decimal.join(",")),
        decimal.join(", "),
        decimal.join(","),
        hex.clone(),
        hex.to_uppercase(),
    ];
    all.extend(base64_forms(bytes));
    all
}

#[tokio::test]
async fn the_blind_index_is_never_rendered_in_the_log() {
    let svc = fresh("iam_db_test_lookup_actor_no_blind_index").await;
    person(&svc, 21).await;
    person(&svc, 171).await;

    // AC5: a person at [21; 32], looked up -> the captured log holds no decimal
    // list, lowercase or uppercase hex, or base64 rendering of the 32 bytes.
    // AC5: triangulation with 171 (0xAB), whose hex has letters in both cases.
    for blind in [21u8, 171u8] {
        let bytes = vec![blind; 32];
        let (answer, log) = lookup(
            &svc,
            bytes.clone(),
            actor("yadgar:user:admin-one"),
            "rid-secret",
        )
        .await;
        answer.expect("lookup");
        // The record must exist, or "nothing rendered" proves nothing.
        the_record(&log);
        for rendering in renderings(&bytes) {
            assert!(
                !log.contains(&rendering),
                "the blind index must never be rendered; found `{rendering}` in: {log}"
            );
        }
    }

    // AC5: the same holds on the refusal and not-found paths, which log too.
    let bytes = vec![40u8; 32];
    let (answer, log) = lookup(
        &svc,
        bytes.clone(),
        actor("yadgar:user:admin-one"),
        "rid-secret",
    )
    .await;
    assert_eq!(answer.expect_err("unknown").code(), Code::NotFound);
    the_record(&log);
    for rendering in renderings(&bytes) {
        assert!(
            !log.contains(&rendering),
            "the blind index must never be rendered; found `{rendering}` in: {log}"
        );
    }
}
