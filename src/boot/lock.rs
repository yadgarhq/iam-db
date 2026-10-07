//! The migration lock's wait — a knob with ONE source and no default.
//!
//! `yadgar-store` v0.3.0 deleted the compiled-in 60 seconds `migrate::apply`
//! used to wait for another replica's migration (ledger 814, ADR-0569). The wait
//! now comes from this module's own chart: `database.migrationLockTimeoutSeconds`
//! renders `DB_MIGRATION_LOCK_TIMEOUT_SECONDS`, which this function reads with no
//! fallback (ADR-0837 — a boot-only, single-reader, per-module knob may be an
//! environment variable rendered from the module's own chart).
//!
//! **EVERY REFUSAL NAMES BOTH THE VARIABLE AND THE CHART KEY.** ADR-0569 asks a
//! refusal to name the knob and where it was looked for. The variable is what
//! this process read; the chart key is the line an operator edits. A message
//! naming only one sends them looking in the wrong place.

use yadgar_store::migrate::LockOptions;

use super::{env_required, BootError};

/// What this process reads.
pub const MIGRATION_LOCK_TIMEOUT_KEY: &str = "DB_MIGRATION_LOCK_TIMEOUT_SECONDS";

/// What renders it: the value in `chart/values.yaml`, bounded by
/// `chart/values.schema.json`.
pub const MIGRATION_LOCK_TIMEOUT_CHART_KEY: &str = "database.migrationLockTimeoutSeconds";

/// The migration lock, waiting as long as the chart says.
///
/// # Errors
///
/// - absent or empty: [`BootError::Missing`], with [`env_required`]'s own
///   sentence, which already names [`MIGRATION_LOCK_TIMEOUT_CHART_KEY`];
/// - not a whole number of seconds that fits an `i32`, or below one second (the
///   refusal `LockOptions::new` makes, measured on MariaDB 11.8.9 — a negative
///   wait never takes the lock and zero never waits):
///   [`BootError::MigrationLockWait`].
pub fn migration_lock(env: impl Fn(&str) -> Option<String>) -> Result<LockOptions, BootError> {
    let raw = env_required(
        &env,
        MIGRATION_LOCK_TIMEOUT_KEY,
        MIGRATION_LOCK_TIMEOUT_CHART_KEY,
    )
    .map_err(BootError::Missing)?;
    let refuse = |reason: String| BootError::MigrationLockWait {
        value: raw.clone(),
        reason,
    };
    let seconds: i32 = raw
        .parse()
        .map_err(|e: std::num::ParseIntError| refuse(e.to_string()))?;
    LockOptions::new(seconds).map_err(|e| refuse(e.to_string()))
}

#[cfg(test)]
mod tests;
