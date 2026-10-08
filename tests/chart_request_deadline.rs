//! `database.acquireTimeoutSeconds`'s schema bound is pinned BELOW the
//! CALLER's own dial request deadline, and this is where that pin stops
//! being a comment (card C-DB2, M-audit-C).
//!
//! **WHY THE POOL'S ACQUIRE WAIT MUST STAY SHORTER THAN THE CALLER'S WHOLE
//! REQUEST.** This binary never dials out — it is a `-db` twin, served over
//! by `iam`, not a caller of anything — so the budget `acquireTimeoutSeconds`
//! has to stay under is `iam`'s own dial deadline for the `iam` -> `iam-db`
//! hop, not a deadline this process sets for itself. `yadgar_dial`'s
//! `REQUEST_TIMEOUT` (30s, read back here as [`default_request_timeout`]) is
//! that budget. `chart/values.schema.json` bounds `acquireTimeoutSeconds` at
//! 29 — one second under — and `chart/values.yaml` ships 25, a further
//! margin, so a stalled acquire can always be the first thing to report on
//! THAT hop.
//!
//! **THIS IS ONE HOP OF A LONGER CHAIN, AND OTHER HOPS BOUND THEMSELVES THE
//! SAME WAY, INDEPENDENTLY.** `gateway`'s own `AUTH_DEADLINE` (10s) and
//! `RESOLVE_DEADLINE` (5s) apply to a DIFFERENT pair of hops — `gateway` ->
//! `iam`, never `iam` -> `iam-db` — and bound a different outer budget
//! (`gateway`'s own HTTP deadline, not `yadgar_dial`'s `REQUEST_TIMEOUT`).
//! They are the same PATTERN (an inner step stays shorter than the budget it
//! runs inside), not the same chain: on a request that reaches `iam-db`
//! through `gateway` and `iam`, `AUTH_DEADLINE` or `RESOLVE_DEADLINE` fires
//! first, well before this pool's 25s acquire wait is ever reached, and
//! `acquireTimeoutSeconds` only becomes the binding deadline for a caller
//! that dials `iam-db` directly within `iam`'s own 30s budget.
//!
//! **THIS TEST REDS WHEN EITHER NUMBER MOVES AWAY FROM THE OTHER**, not when
//! somebody edits `yadgar-dial`'s own `main`: a schema bound in THIS
//! repository and a constant in a crate THIS repository pins by tag
//! (ADR-0526) are the two things that can drift, and the relation between
//! them is the one property this file exists to hold.
//!
//! **EVERY NUMBER IS PINNED BY A LITERAL (ADR-0599).** The schema's own
//! `maximum` and `chart/values.yaml`'s shipped value are read out of their
//! files rather than restated as a second literal that could silently drift
//! from the first — reading the real files is the whole point — but each is
//! then checked against a literal, and the relation (`shipped <= maximum <
//! dial's default`) is asserted last.

use std::path::PathBuf;

use yadgar_dial::default_request_timeout;

const CHART_KEY: &str = "acquireTimeoutSeconds";

/// `chart/values.schema.json`'s `database.acquireTimeoutSeconds.maximum`.
///
/// **A MISSING KEY PANICS RATHER THAN DEFAULTING**, the same reasoning
/// `tests/chart_grace_period.rs`'s own `chart_scalar` gives for its YAML
/// reads: a parse that answers a fallback when it finds nothing is a test
/// that passes after somebody deletes the bound.
fn schema_acquire_timeout_maximum() -> u64 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));
    let schema: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|why| panic!("{} must be valid JSON: {why}", path.display()));

    schema
        .get("properties")
        .and_then(|v| v.get("database"))
        .and_then(|v| v.get("properties"))
        .and_then(|v| v.get(CHART_KEY))
        .and_then(|v| v.get("maximum"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "{}: properties.database.properties.{CHART_KEY}.maximum must be an integer",
                path.display()
            )
        })
}

/// The value of a TOP-LEVEL scalar NESTED one level under `database:` in
/// `chart/values.yaml` — ANCHORED AT EXACTLY TWO LEADING SPACES, because
/// `database:` is the only block this chart nests a scalar one level inside,
/// and a leading-`#` comment naming the same key cannot match a two-space
/// prefix the way `tests/chart_grace_period.rs`'s own unindented
/// `chart_scalar` guards against a comment matching a bare prefix.
fn shipped_acquire_timeout_seconds() -> u64 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.yaml");
    let values = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let prefix = format!("  {CHART_KEY}:");
    let found: Vec<&str> = values
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|rest| rest.split('#').next().unwrap_or_default().trim())
        .collect();

    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{prefix}` in {}, found {}: {found:?}",
        path.display(),
        found.len()
    );

    found[0].parse().unwrap_or_else(|why| {
        panic!(
            "`{CHART_KEY}: {}` in {} must be a whole number of seconds: {why}",
            found[0],
            path.display()
        )
    })
}

#[test]
fn the_acquire_timeout_schema_bound_stays_below_the_dial_request_timeout() {
    let maximum = schema_acquire_timeout_maximum();
    let dial_timeout = default_request_timeout().as_secs();

    assert!(
        maximum < dial_timeout,
        "chart/values.schema.json's database.acquireTimeoutSeconds.maximum ({maximum}) is no \
         longer below yadgar_dial::default_request_timeout() ({dial_timeout}s): a pool acquire \
         could then run as long as a caller's whole request, which can never be the deadline \
         that fires first. Lower the schema's maximum, or raise it only alongside a raised dial \
         timeout, deliberately."
    );
}

#[test]
fn the_shipped_acquire_timeout_stays_at_or_below_its_own_schema_bound() {
    let shipped = shipped_acquire_timeout_seconds();
    let maximum = schema_acquire_timeout_maximum();

    assert!(
        shipped <= maximum,
        "chart/values.yaml ships database.acquireTimeoutSeconds: {shipped}, which is above its \
         own schema maximum ({maximum}) — every render of the shipped defaults would then \
         refuse at `helm template`."
    );
}

#[test]
fn the_literals_this_file_pins_have_not_silently_drifted() {
    // ADR-0599: every number a reader of this file would want to see is
    // checked against a literal here, not only through the functions above
    // that read it back out of the files.
    assert_eq!(
        schema_acquire_timeout_maximum(),
        29,
        "chart/values.schema.json's database.acquireTimeoutSeconds.maximum moved; re-derive the \
         margin against yadgar_dial::default_request_timeout() and update this literal with it"
    );
    assert_eq!(
        shipped_acquire_timeout_seconds(),
        25,
        "chart/values.yaml's shipped database.acquireTimeoutSeconds moved; update this literal \
         with it"
    );
    assert_eq!(
        default_request_timeout().as_secs(),
        30,
        "yadgar_dial's default_request_timeout() moved; this module pins yadgar-dial by tag \
         (ADR-0526), so re-derive database.acquireTimeoutSeconds's schema maximum against the \
         new value and update both together"
    );
}
