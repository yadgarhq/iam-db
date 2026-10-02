//! What an operator reads when the boot refuses.
//!
//! `main` returns `Box<dyn Error>`, and Rust prints that with DEBUG. A
//! `BootError` handed to it with a bare `?` therefore prints its variant name —
//! `ObsoleteRequireTls`, `MigrationLockWait { .. }` — and drops the sentence
//! that names the knob and says what to set, which is the whole of what
//! ADR-0569 asks a refusal to carry. `boot`'s unit tests prove the sentences
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
    String::from_utf8_lossy(&out.stderr).into_owned()
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
