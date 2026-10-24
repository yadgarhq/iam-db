//! The chart's `server.limits` defaults and bounds are pinned against the
//! ranges `yadgar-lifecycle` enforces (ADR-1006; yaadgaar #218).
//!
//! **THE LIBRARY OWNS THE RANGES AND THE CHART OWNS THE DEFAULTS** (ADR-0569).
//! `yadgar_lifecycle::serve_tls::ServerLimits` refuses to boot on an absent or
//! out-of-range value, and `chart/values.schema.json` repeats each range so a
//! bad value is refused at render instead. Two copies of a range drift. This
//! file reds when a bump of the library pin moves a range the schema still
//! states, or when a default leaves the range it must sit in.
//!
//! **EVERY DEFAULT IS A LITERAL (ADR-0599).** The shipped values are checked
//! against the numbers ADR-1006 ruled, not only against the library consts, so
//! a deliberate change to a default has to change this file too.
//!
//! **A MISSING KEY PANICS RATHER THAN DEFAULTING**, as in
//! `tests/chart_grace_period.rs`: a parse that answers a fallback when it finds
//! nothing is a test that passes after somebody deletes the field.

use std::ops::RangeInclusive;
use std::path::PathBuf;

use yadgar_iam_db::serve::{ServerLimits, LIMITS_CHART_KEY, LISTEN};

/// Chart key, environment variable suffix, ADR-1006 default, library range.
fn limits() -> [(&'static str, &'static str, u64, RangeInclusive<u64>); 4] {
    [
        (
            "maxConcurrentStreams",
            "MAX_CONCURRENT_STREAMS",
            256,
            ServerLimits::MAX_CONCURRENT_STREAMS,
        ),
        (
            "keepaliveIntervalSeconds",
            "KEEPALIVE_INTERVAL_SECS",
            30,
            ServerLimits::KEEPALIVE_INTERVAL_SECS,
        ),
        (
            "keepaliveTimeoutSeconds",
            "KEEPALIVE_TIMEOUT_SECS",
            10,
            ServerLimits::KEEPALIVE_TIMEOUT_SECS,
        ),
        (
            "maxHeaderListBytes",
            "MAX_HEADER_LIST_BYTES",
            16384,
            ServerLimits::MAX_HEADER_LIST_BYTES,
        ),
    ]
}

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

/// The shipped value of `server.limits.<key>` in `chart/values.yaml`: the line
/// is anchored at exactly four leading spaces under `server:` / `  limits:`, so
/// a comment naming the key cannot match.
fn shipped(key: &str) -> u64 {
    let values = read("chart/values.yaml");
    let mut lines = values.lines();
    assert!(
        lines.any(|l| l == "server:"),
        "chart/values.yaml must declare a top-level `server:`"
    );
    assert!(
        lines.any(|l| l == "  limits:"),
        "chart/values.yaml must declare `  limits:` under `server:`"
    );
    let prefix = format!("    {key}:");
    let found: Vec<&str> = lines
        .take_while(|l| l.is_empty() || l.starts_with("    ") || l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(&prefix))
        .map(|rest| rest.split('#').next().unwrap_or_default().trim())
        .collect();
    assert_eq!(found.len(), 1, "expected exactly one `{prefix}`: {found:?}");
    found[0]
        .parse()
        .unwrap_or_else(|why| panic!("`{key}: {}` must be a whole number: {why}", found[0]))
}

fn schema(key: &str, bound: &str) -> u64 {
    let schema: serde_json::Value = serde_json::from_str(&read("chart/values.schema.json"))
        .expect("chart/values.schema.json must be valid JSON");
    schema["properties"]["server"]["properties"]["limits"]["properties"][key][bound]
        .as_u64()
        .unwrap_or_else(|| panic!("server.limits.{key}.{bound} must be an integer in the schema"))
}

#[test]
fn the_shipped_defaults_are_the_adr_1006_numbers() {
    for (key, _, default, _) in limits() {
        assert_eq!(
            shipped(key),
            default,
            "server.limits.{key} moved from ADR-1006's default"
        );
    }
}

#[test]
fn every_shipped_default_sits_inside_the_librarys_range() {
    for (key, _, _, range) in limits() {
        let value = shipped(key);
        assert!(
            range.contains(&value),
            "server.limits.{key} ships {value}, outside the library's {range:?}"
        );
    }
}

#[test]
fn the_schema_bounds_are_the_librarys_range() {
    for (key, _, _, range) in limits() {
        assert_eq!(
            schema(key, "minimum"),
            *range.start(),
            "server.limits.{key}: schema minimum is not the library's"
        );
        assert_eq!(
            schema(key, "maximum"),
            *range.end(),
            "server.limits.{key}: schema maximum is not the library's"
        );
    }
}

#[test]
fn the_shipped_keepalive_timeout_is_below_its_interval() {
    assert!(shipped("keepaliveTimeoutSeconds") < shipped("keepaliveIntervalSeconds"));
}

/// The chart's own variable names, fed to the library: if the chart renders a
/// name the library does not read (or the reverse), this refuses.
#[test]
fn the_shipped_defaults_are_accepted_by_the_library_under_the_charts_variable_names() {
    let accepted = ServerLimits::from_lookup(LISTEN, LIMITS_CHART_KEY, |var| {
        limits()
            .iter()
            .find(|(_, suffix, _, _)| var == format!("{LISTEN}_{suffix}"))
            .map(|(key, ..)| shipped(key).to_string())
    });
    assert!(accepted.is_ok(), "{accepted:?}");
}

#[test]
fn the_deployment_renders_each_variable_from_its_chart_value() {
    let template = read("chart/templates/deployment.yaml");
    for (key, suffix, _, _) in limits() {
        let expected = format!(
            "- name: {LISTEN}_{suffix}\n              value: {{{{ .Values.server.limits.{key} | int64 | quote }}}}"
        );
        assert!(
            template.contains(&expected),
            "deployment.yaml must render {LISTEN}_{suffix} from server.limits.{key}"
        );
    }
}
