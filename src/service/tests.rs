//! The cap's marker, held to the transport it has to cross (ledger 1248).

use tonic::Request;

use super::{capped, request_id_of, ACTOR_RECORD_CAP};

/// **A CAPPED REQUEST ID SURVIVES A HOP, AND READS BACK AS THE SAME STRING.**
///
/// `iam` caps `x-yadgar-request-id` with a copy of [`capped`] and forwards the
/// CAPPED value here (iam#88), so the wire is bounded. That only joins if the
/// value can be read back: [`request_id_of`] reads with `to_str()`, which
/// refuses any non-ASCII byte. A non-ASCII marker such as `…` is accepted into
/// metadata and then read back as `""`, so the join is lost exactly where the
/// cap fired. And capping an already-capped value must change nothing, or the
/// two hops' records still differ.
#[test]
fn a_capped_request_id_round_trips_through_metadata_unchanged() {
    let cut = capped(&"z".repeat(1000)).into_owned();
    assert!(
        cut.is_ascii(),
        "the marker must be ASCII to cross a header: {cut}"
    );
    assert!(cut.starts_with(&"z".repeat(ACTOR_RECORD_CAP)));

    let mut req = Request::new(());
    req.metadata_mut()
        .insert("x-yadgar-request-id", cut.parse().expect("a header value"));
    assert_eq!(
        request_id_of(&req),
        cut,
        "the twin reads back the identical capped string iam forwarded"
    );
}
