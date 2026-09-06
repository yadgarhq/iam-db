//! The chart's `terminationGracePeriodSeconds` is DERIVED, and this is where
//! the derivation stops being a comment.
//!
//! `chart/values.yaml` renders `35` and explains it as `5` (the `preStop`
//! sleep) plus `25` (`yadgar_lifecycle::DRAIN_BUDGET`) plus `5` (the slack that
//! constant's docstring reserves to log the drain's outcome and exit). Nothing
//! held the third term to the constant it names. Raise `DRAIN_BUDGET` in
//! `yadgarhq/lifecycle`, bump the pin in `Cargo.toml`, and this pod gets a
//! grace period SHORTER than the drain its own binary will attempt: SIGKILL
//! lands mid-drain, nothing fails, nothing warns, and the only symptom is
//! requests cut off on a rolling update.
//!
//! **THIS TEST REDS WHEN THIS MODULE BUMPS ITS PIN, not when somebody edits
//! `lifecycle`'s `main`.** That is the correct moment and the correct place.
//! The chart must agree with the BINARY THAT SHIPS, and the binary that ships
//! is the one this repository pins by tag (ADR-0526) — so the check belongs
//! beside the two numbers it compares, both of which are in this repository.
//! `lifecycle` cannot do it: its own `drain.rs` says so, because the charts
//! live in six other repositories it cannot read.
//!
//! **EVERY NUMBER IS PINNED BY A LITERAL (ADR-0599).** A bound another
//! component's configuration must respect is asserted against the literal, never
//! only through the constant that carries it — a test routing both sides through
//! `DRAIN_BUDGET` would stay green through any change to it, which is the whole
//! defect. So the chart's `35` and `5` are read out of the YAML and checked
//! against literals, `DRAIN_BUDGET` is checked against `25`, and the derivation
//! is asserted last as the relation that must survive a deliberate change to all
//! of them.

use std::path::PathBuf;

use yadgar_lifecycle::DRAIN_BUDGET;

/// What `yadgar_lifecycle::DRAIN_BUDGET`'s docstring reserves for the process to
/// log what became of the drain and exit after the budget expires.
///
/// Spelled here rather than imported because `lifecycle` does not export it, and
/// deliberately: it is not a knob and not a bound any caller sets, it is the
/// slack inside one inequality. A literal is also what ADR-0599 asks for.
const EXIT_MARGIN_SECS: u64 = 5;

/// The value of a TOP-LEVEL scalar in `chart/values.yaml`.
///
/// **ANCHORED AT THE START OF THE LINE, and that is not a detail.** Both keys
/// this file reads are also NAMED in the prose comments above their own
/// definitions, so any search that merely CONTAINS the key finds a comment
/// first and reads a number out of English. A leading-`#` comment cannot match
/// `strip_prefix(key)`, and an indented key under some other map cannot either.
///
/// **A MISSING KEY PANICS RATHER THAN DEFAULTING.** A parse that answers a
/// fallback when it finds nothing is a test that passes after somebody deletes
/// the field — the exact silence this file exists to break.
fn chart_scalar(key: &str) -> u64 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.yaml");
    let values = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let found: Vec<&str> = values
        .lines()
        .filter_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(|rest| rest.split('#').next().unwrap_or_default().trim())
        .collect();

    assert_eq!(
        found.len(),
        1,
        "expected exactly one top-level `{key}:` in {}, found {}: {found:?} — a duplicate key \
         means Helm reads the last one and this test would read the first",
        path.display(),
        found.len()
    );

    found[0].parse().unwrap_or_else(|why| {
        panic!(
            "`{key}: {}` in {} must be a whole number of seconds: {why}",
            found[0],
            path.display()
        )
    })
}

/// The chart's grace period is the sleep, the drain budget and the exit margin,
/// and it is asserted rather than only explained in a comment beside itself.
///
/// Kubelet runs `preStop` BEFORE it sends SIGTERM and spends that time inside
/// `terminationGracePeriodSeconds` rather than adding to it, so all three terms
/// share one clock and the sum is the whole of a pod's death.
#[test]
fn the_charts_grace_period_is_the_drain_budget_this_binary_pins() {
    let prestop = chart_scalar("preStopSleepSeconds");
    let grace = chart_scalar("terminationGracePeriodSeconds");

    assert_eq!(
        prestop, 5,
        "the `preStop` sleep this chart renders moved; it is the first term of \
         `terminationGracePeriodSeconds` and that value must move with it"
    );
    assert_eq!(
        grace, 35,
        "the grace period this chart renders moved; it is 5 (preStop) + 25 \
         (`yadgar_lifecycle::DRAIN_BUDGET`) + {EXIT_MARGIN_SECS} (the exit margin), and every \
         term is pinned below"
    );
    assert_eq!(
        DRAIN_BUDGET.as_secs(),
        25,
        "the drain budget this module pins by tag is no longer 25s, so \
         `chart/values.yaml`'s `terminationGracePeriodSeconds` is now derived from a number \
         that does not exist: re-derive it as {prestop} + {} + {EXIT_MARGIN_SECS} and change \
         both together",
        DRAIN_BUDGET.as_secs()
    );

    assert_eq!(
        grace,
        prestop + DRAIN_BUDGET.as_secs() + EXIT_MARGIN_SECS,
        "this pod's grace period does not cover the drain its own binary will attempt: kubelet \
         sends SIGKILL {grace}s after deletion begins, and the process wants {prestop}s of \
         preStop plus a {}s drain plus {EXIT_MARGIN_SECS}s to report what became of it",
        DRAIN_BUDGET.as_secs()
    );
}
