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
fn env_required(env: &impl Fn(&str) -> Option<String>, key: &str) -> Result<String, String> {
    match env(key) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it; a values override that nulls it \
             produces exactly this."
        )),
        None => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it."
        )),
    }
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

    // EVERY VALUE BELOW IS REQUIRED, and each is rendered by this repository's
    // chart. `map_err` rather than a wider signature: `BootError` is what
    // `main` already prints, and a helper returning `String` keeps the sentence
    // an operator reads intact through the `#[error("{0}")]` variant.
    Ok(PoolConfig {
        host: env_required(&env, "DB_HOST").map_err(BootError::Missing)?,
        port: env_required(&env, "DB_PORT")
            .map_err(BootError::Missing)?
            .parse()?,
        database: env_required(&env, "DB_NAME").map_err(BootError::Missing)?,
        username: env_required(&env, "DB_USER").map_err(BootError::Missing)?,
        max_connections: env_required(&env, "DB_MAX_CONNECTIONS")
            .map_err(BootError::Missing)?
            .parse()?,
        replicas: env_required(&env, "REPLICAS")
            .map_err(BootError::Missing)?
            .parse()?,
        engine_max_connections: env_required(&env, "DB_ENGINE_MAX_CONNECTIONS")
            .map_err(BootError::Missing)?
            .parse()?,
        ssl_mode: parse_ssl_mode(&env_required(&env, SSL_MODE_KEY).map_err(BootError::Missing)?)?,
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
    ///
    /// Still here, and still correct, for the tests whose subject is refused
    /// BEFORE the configuration is assembled: [`OBSOLETE_TLS_KEY`] is checked
    /// first, so those tests never reach a required knob.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// EVERY KNOB THIS MODULE REQUIRES, and the value each is stated as.
    ///
    /// **NOT ONE OF THESE VALUES IS THE DEFAULT THAT WAS DELETED.** The old
    /// `env_or` calls read `127.0.0.1`, `3306`, `iam`, `iam`, `8`, `2`, `151` and
    /// `required`; every value below differs. A test whose fixture repeated a
    /// deleted default would pass identically against an implementation that
    /// still had the default behind the read, which is the whole failure this
    /// conversion is guarding against.
    const RENDERED: [(&str, &str); 8] = [
        ("DB_HOST", "engine.example.invalid"),
        ("DB_PORT", "13306"),
        ("DB_NAME", "iam_fixture"),
        ("DB_USER", "iam_fixture_user"),
        ("DB_MAX_CONNECTIONS", "4"),
        ("REPLICAS", "3"),
        ("DB_ENGINE_MAX_CONNECTIONS", "200"),
        (SSL_MODE_KEY, "verify-identity"),
    ];

    /// The full rendered environment, with `overrides` layered over it.
    ///
    /// It OWNS its strings and moves them into the closure, unlike [`env_of`],
    /// because a base-plus-overrides environment is built from a temporary that
    /// a borrowing closure would outlive.
    fn env_with(overrides: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut pairs: Vec<(String, String)> = RENDERED
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        for (key, value) in overrides {
            match pairs.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = (*value).to_string(),
                None => pairs.push(((*key).to_string(), (*value).to_string())),
            }
        }
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v.clone())
        }
    }

    /// The full rendered environment with exactly one knob NOT RENDERED.
    ///
    /// Absence and emptiness are different states, so this cannot be expressed
    /// as an override to `""` — that is [`env_with`]'s job and a different test.
    fn env_without(missing: &str) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = RENDERED
            .iter()
            .filter(|(k, _)| *k != missing)
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v.clone())
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
        let options =
            probe_connect_options(&config, &Secret::new("fixture".to_string())).expect("options");

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
        // THE PARSE IS STILL THE WHOLE OF WHAT THIS ASSERTS FOR `verify_ca`,
        // and that is deliberate rather than left over. `store` now refuses the
        // mode when a connection is built, not when a value is read — so a
        // configuration carrying it is still assembled without complaint, and
        // rewriting this into a refusal would assert something `pool_config`
        // does not do. The refusal has its own test below.
        //
        // The hyphen spelling is the one a chart writes; sqlx writes the
        // underscore.
        let config = pool_config(env_with(&[(SSL_MODE_KEY, "verify-identity")])).expect("config");
        assert!(matches!(config.ssl_mode, MySqlSslMode::VerifyIdentity));

        let config = pool_config(env_with(&[(SSL_MODE_KEY, "VERIFY_CA")])).expect("config");
        assert!(matches!(config.ssl_mode, MySqlSslMode::VerifyCa));
    }

    #[test]
    fn verify_ca_is_refused_when_the_connection_options_are_built() {
        // `verify_ca` NAMES A CHECK NOTHING PERFORMS, which is why `store`
        // refuses it outright rather than documenting it. Measured in sqlx 0.9:
        // `sqlx-core`'s `net/tls/tls_rustls.rs` seeds the trust store with the
        // public web roots BEFORE appending the configured `ssl_ca`, so naming
        // an authority WIDENS trust and never restricts it; `sqlx-mysql`'s
        // `connection/tls.rs` then routes every mode but `VerifyIdentity`
        // through `NoHostnameTlsVerifier`, which maps a name mismatch to a
        // verified assertion. The pair accepts ANY publicly-trusted certificate
        // for ANY name, with a CA file or without one.
        //
        // THE PROBE IS THE CALLER THIS PINS, and that is the point. The probe
        // opens its own connection before the pool exists, so a refusal that
        // lived only in `connect` would let the probe connect first — under the
        // very verifier being refused. `store` puts the check where both callers
        // meet, and this asserts the probe inherits it rather than routing
        // around it.
        let config = config_with(MySqlSslMode::VerifyCa);
        let err = probe_connect_options(&config, &Secret::new("fixture".to_string()))
            .expect_err("verify_ca must be refused before any connection is opened");

        assert!(
            matches!(err, BootError::Pool(PoolError::SslModeCannotVerify { .. })),
            "{err}"
        );

        // An operator reads this in a crash loop, so it has to name the mode
        // that WORKS. A refusal that only says no leaves them guessing between
        // three remaining values, two of which verify nothing either.
        let message = err.to_string();
        assert!(
            message.contains("verify_identity"),
            "the refusal must name the mode that does bind the engine's identity: {message}"
        );
    }

    #[test]
    fn an_unrecognised_ssl_mode_refuses_the_boot_rather_than_falling_back() {
        // `yes` is not arbitrary. Under the boolean expression this replaces —
        // a `DB_REQUIRE_TLS` read compared against the string `"true"` — it
        // evaluated FALSE and selected an unencrypted connection, silently.
        // Failing open on a transport question is the class of bug, not one
        // spelling of it.
        let err = pool_config(env_with(&[(SSL_MODE_KEY, "yes")]))
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
        let config = pool_config(env_with(&[(SSL_CA_KEY, SENTINEL_CA)])).expect("config");

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
        //
        // THIS KEY IS THE ONE EXCEPTION TO ADR-0569 IN THIS FUNCTION, and it is
        // not a fallback: `None` is not a value nobody chose, it is the STATE
        // "no authority named", and the chart renders `DB_SSL_CA_FILE` only when
        // a Secret supplies one. Every other knob goes through `env_required`.
        assert_eq!(pool_config(env_with(&[])).expect("config").ssl_ca, None);

        // EMPTY is the same statement written by a chart. Helm renders an unset
        // value as "", so a naive read turns "no authority" into `PathBuf::new()`
        // — a path sqlx opens and cannot, failing the boot of every deployment
        // that never asked for verification at all.
        for value in ["", " ", "\t", "\n"] {
            assert_eq!(
                pool_config(env_with(&[(SSL_CA_KEY, value)]))
                    .expect("config")
                    .ssl_ca,
                None,
                "{value:?} must mean no authority, not an unopenable path"
            );
        }
    }

    /// **THE TEST THAT PROVES THE STATED VALUE IS USED**, and the one a
    /// conversion like this most easily omits. An assertion that `pool_config`
    /// merely SUCCEEDS passes just as happily against an implementation that
    /// kept every compiled-in default behind the read; only comparing each field
    /// to a value that is not the deleted default can tell the two apart.
    #[test]
    fn every_rendered_value_reaches_the_configuration_verbatim() {
        let config = pool_config(env_with(&[])).expect("config");

        assert_eq!(config.host, "engine.example.invalid");
        assert_eq!(config.port, 13306);
        assert_eq!(config.database, "iam_fixture");
        assert_eq!(config.username, "iam_fixture_user");
        assert_eq!(config.max_connections, 4);
        assert_eq!(config.replicas, 3);
        assert_eq!(config.engine_max_connections, 200);
        assert!(
            matches!(config.ssl_mode, MySqlSslMode::VerifyIdentity),
            "the stated ssl-mode did not reach the configuration"
        );
    }

    /// Every knob, one at a time, and the loop is deliberate: a hand-written
    /// test per knob is a list somebody adds a field to and forgets.
    #[test]
    fn each_required_knob_refuses_the_boot_when_it_is_not_rendered() {
        for (key, _) in RENDERED {
            // A `match` rather than `expect_err`, because `PoolConfig` carries
            // no `Debug` — and the `Ok` arm panics with the knob's name, so a
            // configuration that assembled without it fails LOUDLY here rather
            // than passing an assertion that was never reached.
            let err = match pool_config(env_without(key)) {
                Ok(_) => panic!("{key} is not rendered and the boot was NOT refused"),
                Err(e) => e,
            };

            assert!(
                matches!(err, BootError::Missing(_)),
                "{key} must refuse as a missing knob: {err}"
            );
            assert!(
                err.to_string().contains(key),
                "the refusal must name the knob: {err}"
            );
        }
    }

    /// **THE CASE THAT DISCRIMINATES.** Helm renders a nulled value as `""`, so
    /// set-but-empty is what a values override actually produces — it is not the
    /// same state as a variable the chart never rendered. An implementation
    /// collapsing the two into one branch is a defect this estate found three
    /// separate times in one week, so the messages are asserted to DIFFER rather
    /// than merely to exist.
    #[test]
    fn an_empty_knob_refuses_with_a_message_of_its_own() {
        for (key, _) in RENDERED {
            let absent = pool_config(env_without(key)).expect_err("absent must refuse");
            let empty = pool_config(env_with(&[(key, "")])).expect_err("empty must refuse");

            let absent = absent.to_string();
            let empty = empty.to_string();

            assert!(
                absent.contains(key),
                "the refusal must name the knob: {absent}"
            );
            assert!(
                empty.contains(key),
                "the refusal must name the knob: {empty}"
            );
            assert!(absent.contains("NOT SET"), "{absent}");
            assert!(empty.contains("set but EMPTY"), "{empty}");
            assert_ne!(
                absent, empty,
                "{key}: an absent knob and an empty one must not share one message"
            );
        }
    }

    #[test]
    fn an_unrendered_ssl_mode_refuses_rather_than_encrypting_on_a_mode_nobody_chose() {
        // THIS TEST REPLACES `the_default_encrypts_and_does_not_fall_back`,
        // which asserted that an empty environment yielded `Required`. That
        // assertion cannot survive ADR-0569 — there is no default to assert —
        // but its ARGUMENT survives unchanged and is what this keeps: a
        // transport question must never fail open. It used to fail open through
        // sqlx's `Preferred`; it would now fail open through whatever value the
        // deleted `DEFAULT_SSL_MODE` happened to hold on the day somebody
        // shipped a chart that stopped rendering the key. Refusing is the only
        // outcome that cannot silently downgrade the connection.
        let err = pool_config(env_without(SSL_MODE_KEY))
            .expect_err("an unrendered ssl-mode must refuse the boot");

        assert!(matches!(err, BootError::Missing(_)), "{err}");
        let message = err.to_string();
        assert!(message.contains(SSL_MODE_KEY), "{message}");
    }
}
