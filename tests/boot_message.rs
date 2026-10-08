//! What an operator reads when the boot refuses.
//!
//! `main` used to return `Result<(), Box<dyn Error>>`, and Rust prints a `main`
//! that returns `Err` with DEBUG: a `BootError` came out as its variant name —
//! `ObsoleteRequireTls`, `MigrationLockWait { .. }` — and even a sentence came
//! out quoted and escaped. `main` now calls `run()` and prints `Error: {e}` with
//! Display, which is what these tests hold: the sentence names the knob and says
//! what to set, which is the whole of what ADR-0569 asks a refusal to carry. `boot`'s unit tests prove the sentences
//! exist; only running the BINARY proves they reach the operator.
//!
//! No engine is needed: every case here is refused before anything connects.

use std::process::Command;

/// Run the real binary with exactly `vars` in its environment, and return what
/// it printed to stderr. It must exit non-zero: these are all refusals.
fn refusal(vars: &[(&str, &str)]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_yadgar-iam-db"))
        .env_clear()
        .envs(vars.iter().copied())
        .output()
        .expect("the test rig could not start the binary");
    assert!(
        !out.status.success(),
        "a refused boot must exit non-zero: {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // PLAIN DISPLAY, NOT DEBUG OF A STRING. Rust prints `main`'s `Err` with
    // Debug, so even a refusal converted to its sentence arrived wrapped in
    // quotes with every inner quote escaped: `Error: "… is \"0\" …"`.
    let line = stderr
        .lines()
        .rfind(|l| l.starts_with("Error: "))
        .unwrap_or_else(|| panic!("no `Error: ` line on stderr: {stderr}"));
    assert!(
        !line.starts_with("Error: \"") && !line.contains("\\\""),
        "the refusal was printed as a Debug string: {line}"
    );
    stderr
}

/// `pool_config` refuses this key before reading any other, so nothing else
/// needs to be set. Its variant has no fields: Debug prints the bare name.
#[test]
fn the_obsolete_tls_key_is_refused_with_its_sentence_not_its_variant_name() {
    let stderr = refusal(&[("DB_REQUIRE_TLS", "true")]);
    assert!(
        stderr.contains("Set DB_SSL_MODE"),
        "the refusal must tell the operator what to set: {stderr}"
    );
    assert!(
        !stderr.contains("ObsoleteRequireTls"),
        "the operator got the Debug variant name, not the sentence: {stderr}"
    );
}

/// The migration lock's wait is read right after the pool's knobs, so a full
/// pool environment plus an unusable wait reaches that refusal and nothing
/// later. Its variant carries fields: Debug would print `MigrationLockWait {
/// value: "0", .. }` and name neither the variable nor the chart key.
///
/// The four C-DB2 knobs are part of the pool's own knobs now, so this
/// fixture states them too (card C-DB2) — otherwise `pool_config` would
/// refuse on one of them before the migration lock's wait is even read.
#[test]
fn an_unusable_migration_lock_wait_is_refused_naming_the_variable_and_the_chart_key() {
    let stderr = refusal(&[
        ("DB_HOST", "engine.example.invalid"),
        ("DB_PORT", "13306"),
        ("DB_NAME", "iam_fixture"),
        ("DB_USER", "iam_fixture_user"),
        ("DB_MAX_CONNECTIONS", "4"),
        ("REPLICAS", "3"),
        ("DB_ENGINE_MAX_CONNECTIONS", "200"),
        ("DB_ENGINE_OPERATOR_RESERVE", "5"),
        ("DB_ACQUIRE_TIMEOUT_SECONDS", "25"),
        ("DB_IDLE_TIMEOUT_SECONDS", "600"),
        ("DB_MAX_LIFETIME_SECONDS", "1800"),
        ("DB_SSL_MODE", "verify-identity"),
        ("DB_MIGRATION_LOCK_TIMEOUT_SECONDS", "0"),
    ]);
    assert!(
        stderr.contains("DB_MIGRATION_LOCK_TIMEOUT_SECONDS is"),
        "the refusal must name the variable: {stderr}"
    );
    assert!(
        stderr.contains("database.migrationLockTimeoutSeconds"),
        "the refusal must name the chart key: {stderr}"
    );
    assert!(
        !stderr.contains("MigrationLockWait"),
        "the operator got the Debug variant, not the sentence: {stderr}"
    );
}

/// EVERY KNOB `pool_config` AND `migration_lock` NEED, stated as a VALID
/// pool and a VALID wait — so a case layering one bad value on top reaches
/// exactly that refusal and nothing earlier in the boot order. The four
/// card-C-DB2 knobs are part of the pool's own knobs now (`yadgar-store`
/// v0.4.0, ADR-0837, ADR-0849).
const FULL_POOL_ENV: &[(&str, &str)] = &[
    ("DB_HOST", "engine.example.invalid"),
    ("DB_PORT", "13306"),
    ("DB_NAME", "iam_fixture"),
    ("DB_USER", "iam_fixture_user"),
    ("DB_MAX_CONNECTIONS", "4"),
    ("REPLICAS", "3"),
    ("DB_ENGINE_MAX_CONNECTIONS", "200"),
    ("DB_ENGINE_OPERATOR_RESERVE", "5"),
    ("DB_ACQUIRE_TIMEOUT_SECONDS", "25"),
    ("DB_IDLE_TIMEOUT_SECONDS", "600"),
    ("DB_MAX_LIFETIME_SECONDS", "1800"),
    ("DB_SSL_MODE", "verify-identity"),
    ("DB_MIGRATION_LOCK_TIMEOUT_SECONDS", "60"),
];

/// Ledger 1257: a present-but-not-numeric pool knob is refused naming the
/// variable, the chart key AND the value — `DB_HOST` alone is enough,
/// because `pool_config`'s struct literal evaluates `host` before `port` and
/// a `?` on the second short-circuits before `database`, `username` or
/// anything after it is even read.
#[test]
fn a_non_numeric_db_port_is_refused_naming_the_variable_the_chart_key_and_the_value() {
    let stderr = refusal(&[("DB_HOST", "engine.example.invalid"), ("DB_PORT", "abc")]);
    assert!(stderr.contains("DB_PORT is \"abc\""), "{stderr}");
    assert!(stderr.contains("database.port"), "{stderr}");
    assert!(
        !stderr.contains("Unparsable"),
        "the operator got the Debug variant: {stderr}"
    );
}

/// `DB_ENGINE_OPERATOR_RESERVE` is one of the four knobs card C-DB2 adds
/// (ADR-0837, ADR-0849): `yadgar-store` v0.4.0 deleted the `5` it used to
/// compile in, so an absent value here must refuse the boot naming both the
/// variable and the chart key — not silently reach for the old constant,
/// which no longer exists to reach for.
#[test]
fn an_unset_db_engine_operator_reserve_names_the_variable_and_the_chart_key() {
    let stderr = refusal(&[
        ("DB_HOST", "engine.example.invalid"),
        ("DB_PORT", "13306"),
        ("DB_NAME", "iam_fixture"),
        ("DB_USER", "iam_fixture_user"),
        ("DB_MAX_CONNECTIONS", "4"),
        ("REPLICAS", "3"),
        ("DB_ENGINE_MAX_CONNECTIONS", "200"),
    ]);
    assert!(
        stderr.contains("DB_ENGINE_OPERATOR_RESERVE"),
        "the refusal must name the variable: {stderr}"
    );
    assert!(
        stderr.contains("database.engineOperatorReserve"),
        "the refusal must name the chart key: {stderr}"
    );
}

/// `DB_ACQUIRE_TIMEOUT_SECONDS` is read right after `DB_ENGINE_OPERATOR_RESERVE`,
/// so a value that IS there but unparsable reaches its own refusal with only
/// the knobs ahead of it set (card C-DB2).
#[test]
fn a_malformed_db_acquire_timeout_seconds_names_the_variable_and_the_chart_key() {
    let stderr = refusal(&[
        ("DB_HOST", "engine.example.invalid"),
        ("DB_PORT", "13306"),
        ("DB_NAME", "iam_fixture"),
        ("DB_USER", "iam_fixture_user"),
        ("DB_MAX_CONNECTIONS", "4"),
        ("REPLICAS", "3"),
        ("DB_ENGINE_MAX_CONNECTIONS", "200"),
        ("DB_ENGINE_OPERATOR_RESERVE", "5"),
        ("DB_ACQUIRE_TIMEOUT_SECONDS", "abc"),
    ]);
    assert!(
        stderr.contains("DB_ACQUIRE_TIMEOUT_SECONDS is \"abc\""),
        "{stderr}"
    );
    assert!(
        stderr.contains("database.acquireTimeoutSeconds"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Unparsable"),
        "the operator got the Debug variant, not the sentence: {stderr}"
    );
}

/// Ledger 1257: `LISTEN` and `METRICS_LISTEN` are now parsed BEFORE the probe
/// (see `main.rs`'s module documentation), so a bad address is reachable
/// here with NO engine behind it — this file's own promise. Before that
/// hoist this case could not be expressed at all: the boot would have hung
/// trying to reach `engine.example.invalid` first.
#[test]
fn a_bad_listen_address_is_refused_naming_the_variable_with_no_engine_needed() {
    let mut vars: Vec<(&str, &str)> = FULL_POOL_ENV.to_vec();
    vars.push(("LISTEN_TLS_ENABLED", "0"));
    vars.push(("LISTEN_TLS_CLIENT_AUTH", "off"));
    vars.push(("LISTEN", "notanaddr"));
    let stderr = refusal(&vars);
    assert!(stderr.contains("LISTEN is \"notanaddr\""), "{stderr}");
    assert!(
        !stderr.contains("METRICS_LISTEN"),
        "the refusal must name LISTEN, not METRICS_LISTEN: {stderr}"
    );
}

/// ADR-0845 / H1: `LISTEN_TLS_ENABLED` has no compiled-in default and no
/// chart default either — an absent flag refuses rather than silently
/// binding the plaintext listener it used to.
#[test]
fn an_absent_tls_flag_is_refused_naming_the_variable_and_the_chart_key() {
    let stderr = refusal(FULL_POOL_ENV);
    assert!(stderr.contains("LISTEN_TLS_ENABLED"), "{stderr}");
    assert!(stderr.contains("tls.enabled"), "{stderr}");
}

/// X-ADR-1 (extends ADR-0845), card B-U5: `LISTEN_TLS_CLIENT_AUTH` has no
/// default either, and it is read WHETHER OR NOT TLS is on — so a cleartext
/// deployment that never states it refuses too, naming the variable and the
/// chart key the operator edits. Everything after the transport is left
/// unset on purpose: a binary that ignored the variable would refuse on
/// `LISTEN` instead, and this assertion would see that.
#[test]
fn an_absent_client_auth_mode_is_refused_naming_the_variable_and_the_chart_key() {
    let mut vars: Vec<(&str, &str)> = FULL_POOL_ENV.to_vec();
    vars.push(("LISTEN_TLS_ENABLED", "0"));
    let stderr = refusal(&vars);
    assert!(stderr.contains("LISTEN_TLS_CLIENT_AUTH"), "{stderr}");
    assert!(stderr.contains("tls.clientAuth"), "{stderr}");
    assert!(
        !stderr.contains("ClientAuthMissing"),
        "the operator got the Debug variant, not the sentence: {stderr}"
    );
}

/// The three modes are EXACT. `on`, `Required` and `true` are how a typo
/// becomes a posture, so each refuses naming the variable and the chart key.
#[test]
fn a_client_auth_mode_outside_the_three_is_refused_naming_the_variable_and_the_chart_key() {
    for value in ["on", "Required", "true"] {
        let mut vars: Vec<(&str, &str)> = FULL_POOL_ENV.to_vec();
        vars.push(("LISTEN_TLS_ENABLED", "0"));
        vars.push(("LISTEN_TLS_CLIENT_AUTH", value));
        let stderr = refusal(&vars);
        assert!(
            stderr.contains("LISTEN_TLS_CLIENT_AUTH"),
            "{value}: {stderr}"
        );
        assert!(stderr.contains("tls.clientAuth"), "{value}: {stderr}");
    }
}
