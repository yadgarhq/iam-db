//! The cap's marker, held to the transport it has to cross (ledger 1248).

use tonic::Request;

use yadgar_telemetry::request_id::{capped, CAP, CUT_MARKER};

use super::request_id_of;

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
    assert!(cut.starts_with(&"z".repeat(CAP)));

    let mut req = Request::new(());
    req.metadata_mut()
        .insert("x-yadgar-request-id", cut.parse().expect("a header value"));
    assert_eq!(
        request_id_of(&req),
        cut,
        "the twin reads back the identical capped string iam forwarded"
    );
}

/// **THE SHARED CAP IS BYTE-IDENTICAL TO THE COPY THIS SERVICE HELD** (ledger
/// 1255): the bound is 256, the marker is the ASCII
/// `...`, 256 characters pass untouched, 257 are cut, and
/// the cut falls on a character boundary.
#[test]
fn the_shared_cap_keeps_the_bound_the_marker_and_the_char_boundary() {
    assert_eq!((CAP, CUT_MARKER), (256, "..."));
    let at_cap = "a".repeat(256);
    assert_eq!(capped(&at_cap), at_cap);
    assert_eq!(capped(&"a".repeat(257)), format!("{at_cap}..."));
    assert_eq!(capped(&"é".repeat(257)), format!("{}...", "é".repeat(256)));
}
