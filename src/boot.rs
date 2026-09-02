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
    /// **THE LAST SENTENCE USED TO NAME A CAPABILITY THAT DOES NOT EXIST.** It
    /// read "verify_ca and verify_identity are why it is gone", which told an
    /// operator reading a boot failure that certificate verification was the
    /// reward for the migration. Nothing configures a certificate authority for
    /// the engine's certificate: [`yadgar_store::pool::PoolConfig`] has no field
    /// for one, `connect_options` never calls sqlx's `ssl_ca`, and no chart
    /// mounts a bundle. Under `tls-rustls-ring` — with `webpki-roots` the only
    /// root source in this binary's lock file — `sqlx-core` builds its trust
    /// store from `webpki_roots::TLS_SERVER_ROOTS`, the PUBLIC web roots, which
    /// sign no operator-issued MariaDB certificate. So both verifying modes fail
    /// closed and the two modes that connect verify nothing.
    ///
    /// The reason the boolean had to go survives intact and is the half that
    /// stays: it could not tell `preferred` from `required`, and that difference
    /// is whether a failed handshake falls back to cleartext.
    ///
    /// The modes are still ACCEPTED — `parse_ssl_mode` recognises all five and
    /// this message must go on listing them, because a message that hid two of
    /// the values the parser takes would be a second wrong description. What
    /// changed is that it no longer offers them as working.
    #[error(
        "DB_REQUIRE_TLS is set and this binary no longer reads it. Set DB_SSL_MODE \
         instead — one of: disabled, preferred, required, verify_ca, verify_identity \
         (default: required). Refusing at boot rather than ignoring the key, because \
         an operator who set it is asking for a transport guarantee, and silently \
         substituting a default is the one outcome worse than stopping. \
         DB_REQUIRE_TLS was a boolean: it could not tell 'encrypt, and connect in \
         cleartext if that fails' from 'encrypt or refuse to connect', which is \
         preferred against required, and that is why it is gone. \
         USE required. verify_ca and verify_identity are accepted and DO NOT WORK \
         YET: nothing here configures the certificate authority that signed the \
         engine's certificate, so both verify against the public web roots and \
         refuse every connection to an engine whose certificate an operator issued."
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
    fn the_refusal_does_not_offer_a_verification_this_binary_cannot_perform() {
        // THE MESSAGE USED TO END "verify_ca and verify_identity are why it is
        // gone", and that named a capability that does not exist. Nothing sets
        // sqlx's `ssl_ca`: `PoolConfig` has no field for a certificate authority,
        // `yadgar_store::pool::connect_options` never calls the setter, and no
        // chart mounts one. Under `tls-rustls-ring` with webpki-roots — the only
        // root source in this binary's lock file — `sqlx-core` builds its trust
        // store from `webpki_roots::TLS_SERVER_ROOTS`, which is the PUBLIC web
        // roots. An operator-issued MariaDB certificate is signed by none of
        // them, so both verifying modes fail closed and the two modes that do
        // connect verify nothing.
        //
        // The reason the boolean had to go is still real and is the half that
        // stays: `DB_REQUIRE_TLS` could not tell `preferred` from `required`, and
        // that difference is whether a failed handshake falls back to cleartext.
        //
        // A PROSE CONTRACT ADMITS ONLY A PROSE ASSERTION, which is the same shape
        // the `DB_SSL_MODE` check above already uses. What a future editor must
        // keep is the SUBSTANCE, not the words: name the two verifying modes, and
        // say the certificate authority they would need is not configurable. When
        // it becomes configurable, this test is the thing that must be changed
        // deliberately rather than the message drifting back on its own.
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
            message.contains("certificate authority"),
            "the refusal names verify_ca and verify_identity, so it must also say \
             the certificate authority they need cannot be configured yet: {message}"
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
    fn the_verifying_modes_reach_the_configuration_even_though_they_cannot_connect() {
        // WHAT THIS ASSERTS IS PARSING, NOT VERIFICATION, and its old name said
        // the second. `verify_ca` and `verify_identity` travel from the
        // environment into `PoolConfig` — that much is real and worth pinning,
        // because a mode silently downgraded on the way through would be the
        // fail-open this module exists to prevent. Neither mode CONNECTS today:
        // nothing configures a certificate authority for the engine's
        // certificate, so sqlx checks against the public web roots and refuses.
        // See `BootError::ObsoleteRequireTls`.
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
