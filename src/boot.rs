//! What `main` decides before it opens anything — in a place a test can reach.
//!
//! `main` is a binary entry point, so nothing in it is reachable from a test.
//! That is fine for wiring and not fine for decisions, and two decisions here
//! are exactly the kind that fail silently: which transport mode the connections
//! use, and what happens to an environment key that no longer means anything.
//! Both now live in this module, and both have a test.
//!
//! **The connection options are the point.** D7's capability probe runs on a
//! connection of its own, before the pool exists. This binary used to build that
//! connection by `format!`-ing `mysql://user:pass@host:port/db`, with no
//! `ssl-mode` in it — so it inherited sqlx's default, `Preferred`, which sqlx
//! documents as falling back to an unencrypted connection when an encrypted one
//! cannot be established, while the pool beside it was on `Required`. Two code
//! paths that must agree about TLS was the bug; one path is the fix, and
//! [`probe_connect_options`] is the seam that keeps it one.

use std::path::PathBuf;
use std::time::Duration;

use sqlx::mysql::MySqlConnectOptions;
use yadgar_store::credentials::Secret;
use yadgar_store::pool::{parse_ssl_mode, PoolConfig, PoolError};

/// The key this module used to read, and no longer does.
///
/// Named as a constant because it appears in the refusal below and nowhere else
/// — the only remaining reason this string exists is to be refused.
const OBSOLETE_TLS_KEY: &str = "DB_REQUIRE_TLS";

/// The key that replaced it.
const SSL_MODE_KEY: &str = "DB_SSL_MODE";

/// The key naming the authority the verifying modes check the engine against.
///
/// **`DB_SSL_*` rather than `DB_TLS_*`, and the difference is deliberate.** The
/// estate spells a gRPC dial's authority `<UPSTREAM>_TLS_CA_FILE` — `iam`
/// carries `IAM_DB_TLS_CA_FILE` for the hop INTO this module. That family is
/// gated by a boolean `_TLS_ENABLED`. This dial has no such flag: it is gated by
/// five-valued [`SSL_MODE_KEY`], and this file is meaningful under two of those
/// values and inert under three. A `DB_TLS_CA_FILE` read beside a `DB_SSL_MODE`
/// in this same function would be two words for one concept inside one pair of
/// keys, which is the defect the estate's naming rule exists to prevent rather
/// than an instance of it. `SSL` also names what it fills: sqlx's `ssl_ca`, on
/// [`yadgar_store::pool::PoolConfig::ssl_ca`].
const SSL_CA_KEY: &str = "DB_SSL_CA_FILE";

/// One configuration knob, read from its ONE source, with no compiled-in
/// default behind it (ADR-0569).
///
/// This replaced `env_or(env, key, default)`, and the deletion is the point
/// rather than the rename: while the helper took a `default` argument, every
/// knob in this configuration had somewhere for a fallback to live, and a
/// fallback is invisible at the point of use, survives an upgrade unnoticed, and
/// makes the effective setting depend on which layer a reader happens to
/// inspect.
///
/// AN EMPTY VALUE REFUSES TOO, and with its own message. A set-but-empty
/// variable and an absent one collapsing into a single branch is a defect this
/// estate found three separate times in one week: Helm renders an unset value as
/// `""`, so the empty case is what a nulled chart value actually produces, and it
/// is the one an operator is most likely to hit. [`SSL_CA_KEY`] below is the one
/// value here that does NOT go through this helper, and its own comment says why
/// — for an `Option`, empty and absent legitimately mean the same thing.
///
/// It keeps the INJECTED LOOKUP the whole module is built around, so a test can
/// state an environment without mutating the process.
///
/// **`chart_key` NAMES WHERE AN OPERATOR EDITS, not merely that a chart
/// renders the variable.** The message used to say "The chart renders it."
/// with no key attached, so an operator reading a crash loop learned THAT a
/// chart was responsible and had to go find WHICH line. ADR-0569 asks a
/// refusal to say where the knob is set; this is that.
fn env_required(
    env: &impl Fn(&str) -> Option<String>,
    key: &str,
    chart_key: &str,
) -> Result<String, String> {
    match env(key) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it as {chart_key}; a values override \
             that nulls it produces exactly this."
        )),
        None => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it as {chart_key}."
        )),
    }
}

/// A required knob that must also PARSE, read and converted in one place so
/// every numeric knob below reports the same two failures the same way:
/// absent or empty is [`BootError::Missing`] (from [`env_required`]), and
/// present-but-not-a-number is [`BootError::Unparsable`], which names the
/// variable, the chart key, the value it was given and `source` — never a
/// bare `#[from] ParseIntError`, which named none of them.
fn parse_required<T>(
    env: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    chart_key: &'static str,
) -> Result<T, BootError>
where
    T: std::str::FromStr<Err = std::num::ParseIntError>,
{
    let value = env_required(env, key, chart_key).map_err(BootError::Missing)?;
    value.parse::<T>().map_err(|source| BootError::Unparsable {
        key,
        chart_key,
        value,
        source,
    })
}

/// `REPLICAS` has no single chart key: `templates/deployment.yaml` renders it
/// as `autoscaling.maxReplicas` when `autoscaling.enabled` and as
/// `replicaCount` otherwise, from the SAME expression gateway's
/// `YADGAR_MAX_REPLICAS` uses. A refusal naming only one of the two would be
/// wrong for whichever mode the deployment is not in.
const REPLICAS_CHART_KEY: &str =
    "autoscaling.maxReplicas (when autoscaling.enabled) or replicaCount (otherwise)";

/// `yadgar-store` v0.4.0 deleted the four `PoolConfig` fields read below from
/// its own compiled-in defaults (ADR-0837, ADR-0849, card C-DB2): sqlx's own
/// 30s/600s/1800s acquire-timeout/idle-timeout/max-lifetime, and the `5` this
/// crate's headroom check used to hard-code as `operator_reserve`. Read and
/// named here the same way the eight knobs above already are.
const OPERATOR_RESERVE_KEY: &str = "DB_ENGINE_OPERATOR_RESERVE";
const OPERATOR_RESERVE_CHART_KEY: &str = "database.engineOperatorReserve";

/// Bounded above by `chart/values.schema.json`'s `maximum: 29` — below the
/// CALLER's own dial `REQUEST_TIMEOUT` (30s; this binary never dials out, so
/// the budget it has to stay under is `iam`'s, not its own), so this pool's
/// own acquire wait can never be the deadline a caller's whole request runs
/// against. `tests/chart_request_deadline.rs` pins the two together.
const ACQUIRE_TIMEOUT_KEY: &str = "DB_ACQUIRE_TIMEOUT_SECONDS";
const ACQUIRE_TIMEOUT_CHART_KEY: &str = "database.acquireTimeoutSeconds";
const IDLE_TIMEOUT_KEY: &str = "DB_IDLE_TIMEOUT_SECONDS";
const IDLE_TIMEOUT_CHART_KEY: &str = "database.idleTimeoutSeconds";
const MAX_LIFETIME_KEY: &str = "DB_MAX_LIFETIME_SECONDS";
const MAX_LIFETIME_CHART_KEY: &str = "database.maxLifetimeSeconds";

/// Read the pool configuration, refusing rather than guessing.
///
/// Takes the environment as a lookup rather than reading it directly, so a test
/// can state a whole environment without mutating the process — `std::env` is
/// global and `cargo test` runs threads in parallel.
pub fn pool_config(env: impl Fn(&str) -> Option<String>) -> Result<PoolConfig, BootError> {
    // FIRST, before anything else can fail. An operator who set DB_REQUIRE_TLS
    // to tighten transport security and got a numeric parse error about some
    // other key would fix the other key and never learn that this one is inert.
    if env(OBSOLETE_TLS_KEY).is_some() {
        return Err(BootError::ObsoleteRequireTls);
    }

    // EVERY VALUE BELOW IS REQUIRED, and each is rendered by this repository's
    // chart. `map_err` rather than a wider signature: `BootError` is what
    // `main` already prints, and a helper returning `String` keeps the sentence
    // an operator reads intact through the `#[error("{0}")]` variant.
    Ok(PoolConfig {
        host: env_required(&env, "DB_HOST", "database.host").map_err(BootError::Missing)?,
        port: parse_required(&env, "DB_PORT", "database.port")?,
        database: env_required(&env, "DB_NAME", "database.name").map_err(BootError::Missing)?,
        username: env_required(&env, "DB_USER", "database.user").map_err(BootError::Missing)?,
        max_connections: parse_required(&env, "DB_MAX_CONNECTIONS", "database.maxConnections")?,
        replicas: parse_required(&env, "REPLICAS", REPLICAS_CHART_KEY)?,
        engine_max_connections: parse_required(
            &env,
            "DB_ENGINE_MAX_CONNECTIONS",
            "database.engineMaxConnections",
        )?,
        // THE OTHER HALF OF D4's ARITHMETIC (ADR-0849). It used to be `5`,
        // compiled into `store`, and the right number depends on the engine
        // an adopter runs and on what else connects to it — a deployment
        // fact, same as `engine_max_connections` beside it.
        operator_reserve: parse_required(&env, OPERATOR_RESERVE_KEY, OPERATOR_RESERVE_CHART_KEY)?,
        // THE THREE POOL DURATIONS `store` used to inherit from sqlx's own
        // defaults (30s/600s/1800s) rather than state. Read as whole seconds,
        // like `database.migrationLockTimeoutSeconds` below, and converted
        // once here rather than asking `store` to parse a unit it does not
        // own.
        acquire_timeout: Duration::from_secs(parse_required(
            &env,
            ACQUIRE_TIMEOUT_KEY,
            ACQUIRE_TIMEOUT_CHART_KEY,
        )?),
        idle_timeout: Duration::from_secs(parse_required(
            &env,
            IDLE_TIMEOUT_KEY,
            IDLE_TIMEOUT_CHART_KEY,
        )?),
        max_lifetime: Duration::from_secs(parse_required(
            &env,
            MAX_LIFETIME_KEY,
            MAX_LIFETIME_CHART_KEY,
        )?),
        ssl_mode: parse_ssl_mode(
            &env_required(&env, SSL_MODE_KEY, "database.sslMode").map_err(BootError::Missing)?,
        )?,
        // TRIMMED AND EMPTY-FILTERED, unlike every value above, because this one
        // is an `Option` and Helm renders an unset value as `""`. Without the
        // filter that empty string becomes `Some(PathBuf::new())` — a path sqlx
        // opens and cannot, so a deployment that never asked for certificate
        // verification fails to boot. Absent and empty must mean the same thing:
        // no authority named, which is what `None` is.
        ssl_ca: env(SSL_CA_KEY)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    })
}

/// The options D7's capability probe connects with.
///
/// It is `store`'s own [`yadgar_store::pool::connect_options`] and deliberately
/// nothing else — the same call the pool makes, given the same config. This
/// function adds no behaviour; it exists so that the probe's description of a
/// connection and the pool's cannot drift apart again, and so that a test can
/// say which one the probe got.
///
/// **IT RETURNS A `Result` BECAUSE `store` REFUSES A MODE HERE, and forwarding
/// that refusal unchanged is the whole of what this adds.** `verify_ca` names a
/// check sqlx does not perform — the trust store is seeded with the public web
/// roots before the configured authority is appended, and every mode but
/// `verify_identity` skips the hostname check — so it accepts any
/// publicly-trusted certificate for any name. `store` places the refusal where
/// the probe and the pool meet, which is why the probe cannot route around it by
/// building its own options. No variant is added for it: [`BootError::Pool`] is
/// `#[error(transparent)]` over `PoolError` and already carries the sentence an
/// operator reads.
pub fn probe_connect_options(
    config: &PoolConfig,
    secret: &Secret,
) -> Result<MySqlConnectOptions, BootError> {
    Ok(yadgar_store::pool::connect_options(config, secret)?)
}

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// **THIS MESSAGE HAS BEEN WRONG IN BOTH DIRECTIONS, so the rule for editing
    /// it is: say what is reachable TODAY, and name the key that reaches it.** It
    /// once ended "verify_ca and verify_identity are why it is gone", which
    /// promised a verification nothing configured; that was corrected to say the
    /// authority could not be configured at all. [`SSL_CA_KEY`] is what makes the
    /// second statement obsolete in turn — the authority is now a value, so the
    /// message names it rather than describing an absence.
    ///
    /// The reason the boolean had to go is unchanged by any of that and is the
    /// half that stays: it could not tell `preferred` from `required`, and that
    /// difference is whether a failed handshake falls back to cleartext.
    ///
    /// All five modes stay listed, because a message that hid two of the values
    /// the parser takes would be its own wrong description.
    #[error(
        "DB_REQUIRE_TLS is set and this binary no longer reads it. Set DB_SSL_MODE \
         instead — one of: disabled, preferred, required, verify_ca, verify_identity. \
         Refusing at boot rather than ignoring the key, because \
         an operator who set it is asking for a transport guarantee, and silently \
         substituting a default is the one outcome worse than stopping. \
         DB_REQUIRE_TLS was a boolean: it could not tell 'encrypt, and connect in \
         cleartext if that fails' from 'encrypt or refuse to connect', which is \
         preferred against required, and that is why it is gone. \
         verify_ca and verify_identity check the engine's certificate against the \
         certificate authority named by DB_SSL_CA_FILE. With no DB_SSL_CA_FILE set \
         they check against the PUBLIC WEB ROOTS instead, which sign no \
         operator-issued engine certificate — so a private-CA engine is refused \
         and, under verify_ca, any publicly-trusted certificate for any name is \
         accepted. Set both keys together or neither."
    )]
    ObsoleteRequireTls,

    /// A knob with no compiled-in default is absent, or is set and empty
    /// (ADR-0569).
    ///
    /// **ONE VARIANT, TWO MESSAGES, and that is the point.** The sentence comes
    /// from [`env_required`], which distinguishes absent from set-but-empty
    /// because Helm renders a nulled value as `""` — so the variant carries the
    /// message rather than reconstructing it, and `{0}` prints exactly what the
    /// helper wrote. NO `#[from] String`: a blanket conversion from `String`
    /// would swallow any other stringly error a future line in this module
    /// produces and label it a missing knob.
    #[error("{0}")]
    Missing(String),

    /// The migration lock's wait is set and unusable (ledger 814, ADR-0837).
    /// Absent and empty are [`BootError::Missing`]; this is a value that is
    /// there and cannot be a wait. It names the variable AND the chart key,
    /// because ADR-0569 asks a refusal to say where the knob is set. The
    /// reason goes LAST, since `store`'s ends in a full stop and a parse error's
    /// does not, and the bound is NOT restated: chart/values.schema.json is its
    /// one source.
    #[error(
        "DB_MIGRATION_LOCK_TIMEOUT_SECONDS is {value:?}, which is not a usable migration \
         lock wait. Set the chart value database.migrationLockTimeoutSeconds to a whole \
         number of seconds, at least 1, within the bound chart/values.schema.json sets. \
         Why: {reason}"
    )]
    MigrationLockWait { value: String, reason: String },

    #[error(transparent)]
    Pool(#[from] PoolError),

    /// A knob that IS set is not a whole number, read through
    /// [`parse_required`]. The deleted `#[error(transparent)]
    /// Int(#[from] ParseIntError)` this replaced named neither the variable
    /// nor the chart key nor the value given — just sqlx's own "invalid
    /// digit found in string", which an operator cannot act on without
    /// already knowing which of the eight numeric knobs produced it.
    #[error(
        "{key} is {value:?}, which is not a whole number ({source}). Set the chart value \
         {chart_key} to a whole number."
    )]
    Unparsable {
        key: &'static str,
        chart_key: &'static str,
        value: String,
        source: std::num::ParseIntError,
    },
}

mod lock;
pub use lock::{migration_lock, MIGRATION_LOCK_TIMEOUT_CHART_KEY, MIGRATION_LOCK_TIMEOUT_KEY};

#[cfg(test)]
mod tests;
