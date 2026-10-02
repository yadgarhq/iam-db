use super::*;

fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// The refusal for `value`, which must name the variable, the chart key and
/// the value it was given.
fn refused(value: &str) -> String {
    let pairs = [(MIGRATION_LOCK_TIMEOUT_KEY, value)];
    let err = migration_lock(env_of(&pairs)).expect_err("must refuse");
    assert!(
        matches!(err, BootError::MigrationLockWait { .. }),
        "{value:?} is a value, not an absence: {err:?}"
    );
    let message = err.to_string();
    // `store`'s own refusal ends in a full stop; a template that appends one
    // after it prints "..".
    assert!(!message.contains(".."), "a doubled full stop: {message}");
    // THE SCHEMA IS THE ONE SOURCE OF THE BOUND. A number repeated here drifts
    // the day chart/values.schema.json changes and this sentence does not.
    assert!(
        !message.contains("590"),
        "the bound restated outside the schema: {message}"
    );
    assert!(message.contains("values.schema.json"), "{message}");
    for needle in [
        MIGRATION_LOCK_TIMEOUT_KEY,
        MIGRATION_LOCK_TIMEOUT_CHART_KEY,
        value,
    ] {
        assert!(
            message.contains(needle),
            "{needle:?} missing from: {message}"
        );
    }
    message
}

/// THE DEFECT THIS MODULE EXISTS FOR. Up to store v0.2.13 an unstated wait was
/// 60 seconds nobody chose; it must be a refusal now.
#[test]
fn an_absent_wait_refuses_naming_the_variable_and_the_chart_key() {
    let err = migration_lock(env_of(&[])).expect_err("no default behind the read");
    assert!(matches!(err, BootError::Missing(_)), "{err:?}");
    let message = err.to_string();
    assert!(message.contains("NOT SET"), "{message}");
    assert!(message.contains(MIGRATION_LOCK_TIMEOUT_KEY), "{message}");
    assert!(
        message.contains(MIGRATION_LOCK_TIMEOUT_CHART_KEY),
        "{message}"
    );
}

/// Helm renders a nulled value as `""`, so this is the case an operator hits.
#[test]
fn an_empty_wait_refuses_with_its_own_message() {
    let pairs = [(MIGRATION_LOCK_TIMEOUT_KEY, "")];
    let err = migration_lock(env_of(&pairs)).expect_err("empty is not a wait");
    let message = err.to_string();
    assert!(message.contains("EMPTY"), "{message}");
    assert!(
        message.contains(MIGRATION_LOCK_TIMEOUT_CHART_KEY),
        "{message}"
    );
}

/// Zero never waits for the other replica, so the second of two fails its boot
/// on every rollout that migrates.
#[test]
fn a_zero_wait_refuses() {
    refused("0");
}

#[test]
fn a_negative_wait_refuses() {
    refused("-5");
}

/// Larger than an `i32`, which is what `GET_LOCK` is bound with.
#[test]
fn a_wait_that_does_not_fit_refuses() {
    refused("99999999999");
}

#[test]
fn a_wait_that_is_not_a_number_refuses() {
    refused("sixty");
}

/// 45, not 60: a fixture repeating the deleted default would pass against an
/// implementation that still had it.
#[test]
fn a_stated_wait_is_carried_through_on_the_one_shared_lock() {
    let pairs = [(MIGRATION_LOCK_TIMEOUT_KEY, "45")];
    let lock = migration_lock(env_of(&pairs)).expect("45 seconds is a wait");
    assert_eq!(lock.timeout_secs(), 45);
    assert_eq!(lock.name(), "yadgar_migrate");
}
