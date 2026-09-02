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

use sqlx::mysql::MySqlConnectOptions;
use yadgar_store::credentials::Secret;
use yadgar_store::pool::{parse_ssl_mode, PoolConfig, PoolError, DEFAULT_SSL_MODE};

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

fn env_or(env: &impl Fn(&str) -> Option<String>, key: &str, default: &str) -> String {
    env(key).unwrap_or_else(|| default.to_string())
}

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

    Ok(PoolConfig {
        host: env_or(&env, "DB_HOST", "127.0.0.1"),
        port: env_or(&env, "DB_PORT", "3306").parse()?,
        database: env_or(&env, "DB_NAME", "iam"),
        username: env_or(&env, "DB_USER", "iam"),
        max_connections: env_or(&env, "DB_MAX_CONNECTIONS", "8").parse()?,
        replicas: env_or(&env, "REPLICAS", "2").parse()?,
        engine_max_connections: env_or(&env, "DB_ENGINE_MAX_CONNECTIONS", "151").parse()?,
        ssl_mode: parse_ssl_mode(&env_or(&env, SSL_MODE_KEY, DEFAULT_SSL_MODE))?,
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
pub fn probe_connect_options(config: &PoolConfig, secret: &Secret) -> MySqlConnectOptions {
    yadgar_store::pool::connect_options(config, secret)
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
         instead — one of: disabled, preferred, required, verify_ca, verify_identity \
         (default: required). Refusing at boot rather than ignoring the key, because \
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

    #[error(transparent)]
    Pool(#[from] PoolError),

    #[error(transparent)]
    Int(#[from] std::num::ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadgar_store::pool::MySqlSslMode;

    /// An environment stating only what a test cares about.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// `verify_identity` throughout, and never `required`.
    ///
    /// `required` is what this module defaults to and what the old boolean
    /// selected, so an implementation that ignored the configuration entirely
    /// would pass a test fixed on it. `verify_identity` is a mode neither this
    /// code nor sqlx would ever arrive at on its own.
    fn config_with(mode: MySqlSslMode) -> PoolConfig {
        PoolConfig {
            host: "engine.example.invalid".to_string(),
            port: 13306,
            database: "iam_fixture".to_string(),
            username: "iam_fixture_user".to_string(),
            max_connections: 4,
            replicas: 2,
            engine_max_connections: 151,
            ssl_mode: mode,
            ssl_ca: None,
        }
    }

    #[test]
    fn the_probe_connects_with_the_configured_mode_not_a_mode_of_its_own() {
        let config = config_with(MySqlSslMode::VerifyIdentity);
        let options = probe_connect_options(&config, &Secret::new("fixture".to_string()));

        // The whole defect was a probe that described its connection itself. Had
        // it kept doing so — hardcoding Required, or falling back to sqlx's
        // Preferred — this is the assertion that would not hold.
        assert!(
            matches!(options.get_ssl_mode(), MySqlSslMode::VerifyIdentity),
            "the probe did not take the configured ssl-mode"
        );

        // The rest of the connection comes from the same place, so a probe
        // pointed at a different host or database would be caught here too.
        // NO DSN in any message: an assert that interpolates one puts a username
        // into CI output.
        assert_eq!(options.get_host(), "engine.example.invalid");
        assert_eq!(options.get_port(), 13306);
        assert_eq!(options.get_username(), "iam_fixture_user");
        assert_eq!(options.get_database(), Some("iam_fixture"));
    }

    #[test]
    fn a_set_but_obsolete_db_require_tls_refuses_the_boot() {
        // `true` deliberately: the value an operator sets to ASK for TLS. Under
        // the old expression it was the one spelling that worked, so it is the
        // value most likely to be sitting in a deployment right now — and the
        // one whose silent removal changes nothing visible while removing the
        // guarantee the operator wrote down.
        let err = pool_config(env_of(&[("DB_REQUIRE_TLS", "true")]))
            .expect_err("a set DB_REQUIRE_TLS must refuse the boot");

        assert!(matches!(err, BootError::ObsoleteRequireTls));
        let message = err.to_string();
        assert!(message.contains("DB_SSL_MODE"), "{message}");
    }

    #[test]
    fn the_refusal_names_the_key_that_makes_the_verifying_modes_work() {
        // THIS TEST REPLACES ONE THAT ASSERTED THE OPPOSITE. Its predecessor
        // pinned the message's admission that the certificate authority "cannot
        // be configured yet", and said in its own comment that the day it became
        // configurable this test was what had to change deliberately rather than
        // let the message drift back on its own. `DB_SSL_CA_FILE` is that day.
        //
        // A PROSE CONTRACT ADMITS ONLY A PROSE ASSERTION, the same shape the
        // `DB_SSL_MODE` check above already uses. What a future editor must keep
        // is the SUBSTANCE: name the distinction the boolean could not express,
        // list every mode the parser takes, and — because naming the verifying
        // modes without naming what they verify against is what made this message
        // wrong twice — name the key that supplies the authority.
        let err = pool_config(env_of(&[("DB_REQUIRE_TLS", "true")]))
            .expect_err("a set DB_REQUIRE_TLS must refuse the boot");
        let message = err.to_string();

        assert!(
            message.contains("preferred") && message.contains("required"),
            "the refusal must name the distinction the boolean could not express: {message}"
        );
        assert!(
            message.contains("verify_ca") && message.contains("verify_identity"),
            "the refusal must still list every mode DB_SSL_MODE accepts: {message}"
        );
        assert!(
            message.contains(SSL_CA_KEY),
            "the refusal offers verify_ca and verify_identity, so it must name the \
             key that supplies the authority they check against: {message}"
        );
    }

    #[test]
    fn the_obsolete_key_is_refused_before_any_other_value_is_parsed() {
        // The refusal must win against a second, unrelated fault. Otherwise the
        // operator fixes the port, boots, and never learns the key is inert.
        let err = pool_config(env_of(&[
            ("DB_REQUIRE_TLS", "true"),
            ("DB_PORT", "not-a-port"),
        ]))
        .expect_err("must refuse");

        assert!(matches!(err, BootError::ObsoleteRequireTls), "{err}");
    }

    #[test]
    fn the_verifying_modes_reach_the_configuration() {
        // WHAT THIS ASSERTS IS PARSING, NOT VERIFICATION. `verify_ca` and
        // `verify_identity` travel from the environment into `PoolConfig` — worth
        // pinning on its own, because a mode silently downgraded on the way
        // through would be the fail-open this module exists to prevent. The
        // authority they check against travels separately and is pinned by
        // `the_configured_certificate_authority_reaches_the_pool`.
        //
        // The hyphen spelling is the one a chart writes; sqlx writes the
        // underscore.
        let config = pool_config(env_of(&[("DB_SSL_MODE", "verify-identity")])).expect("config");
        assert!(matches!(config.ssl_mode, MySqlSslMode::VerifyIdentity));

        let config = pool_config(env_of(&[("DB_SSL_MODE", "VERIFY_CA")])).expect("config");
        assert!(matches!(config.ssl_mode, MySqlSslMode::VerifyCa));
    }

    #[test]
    fn an_unrecognised_ssl_mode_refuses_the_boot_rather_than_falling_back() {
        // `yes` is not arbitrary. Under the expression this replaces —
        // `env_or("DB_REQUIRE_TLS", "true") == "true"` — it evaluated FALSE and
        // selected an unencrypted connection, silently. Failing open on a
        // transport question is the class of bug, not one spelling of it.
        let err = pool_config(env_of(&[("DB_SSL_MODE", "yes")]))
            .expect_err("an unrecognised mode must refuse the boot");

        assert!(
            matches!(err, BootError::Pool(PoolError::UnknownSslMode { .. })),
            "{err}"
        );
    }

    /// A SENTINEL: nothing in this module or in `store` could produce this
    /// path, so a test that sees it saw it travel from the environment.
    const SENTINEL_CA: &str = "/etc/yadgar/pangolin-7c21/engine-authority.pem";

    #[test]
    fn the_configured_certificate_authority_reaches_the_pool() {
        // THE HALF THAT WAS MISSING. `verify_ca` and `verify_identity` check a
        // chain, and until this key existed there was no value naming the
        // authority to check it against — so sqlx used the public web roots,
        // which sign no operator-issued engine certificate.
        let config = pool_config(env_of(&[("DB_SSL_CA_FILE", SENTINEL_CA)])).expect("config");

        assert_eq!(
            config.ssl_ca.as_deref(),
            Some(std::path::Path::new(SENTINEL_CA)),
            "the configured authority did not reach the pool configuration"
        );
    }

    #[test]
    fn an_unset_or_empty_authority_is_no_authority_rather_than_an_empty_path() {
        // UNSET is the shipped deployment and must stay `None`: `Some` here
        // would name a file sqlx then fails to open, and a default CA path is a
        // policy this module has no business inventing — an Azure MySQL engine
        // whose authority IS a public root legitimately configures none.
        assert_eq!(pool_config(env_of(&[])).expect("config").ssl_ca, None);

        // EMPTY is the same statement written by a chart. Helm renders an unset
        // value as "", so a naive read turns "no authority" into `PathBuf::new()`
        // — a path sqlx opens and cannot, failing the boot of every deployment
        // that never asked for verification at all.
        for value in ["", " ", "\t", "\n"] {
            assert_eq!(
                pool_config(env_of(&[("DB_SSL_CA_FILE", value)]))
                    .expect("config")
                    .ssl_ca,
                None,
                "{value:?} must mean no authority, not an unopenable path"
            );
        }
    }

    #[test]
    fn the_default_encrypts_and_does_not_fall_back() {
        // An empty environment is the shipped deployment. `Preferred` here would
        // mean the fix reintroduced the defect through the default.
        let config = pool_config(env_of(&[])).expect("config");
        assert!(
            matches!(config.ssl_mode, MySqlSslMode::Required),
            "the default ssl-mode must encrypt without falling back"
        );
    }
}
