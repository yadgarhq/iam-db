//! The ADOPTION, asserted through this repository's own wiring: `from_lookup`
//! here passes [`LISTEN`] and [`CHART_KEY`], and every refusal an operator
//! reads must name the variable AND the chart key that renders it. The
//! reading itself is `yadgar_lifecycle::serve_tls`'s and is tested there;
//! what only this repository can get wrong is the chart key it hands over.
//!
//! STATIC ASSERTION MESSAGES, deliberately. The error enum has variants named
//! after certificates and keys, and an assertion message that interpolates it
//! is what CodeQL reads as cleartext logging of key material.

use std::path::Path;

use super::*;

/// The values below are SENTINELS: nothing in `serve.rs` could produce
/// either of them, so a test that sees one saw it travel from the lookup.
const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/server.pem";
const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/server-key.pem";
const SENTINEL_CA: &str = "/etc/yadgar/pangolin-7c21/client-ca.pem";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

fn refusal_of(pairs: &[(&'static str, &'static str)]) -> String {
    match from_lookup(lookup(pairs)) {
        Ok(_) => panic!("this configuration must be refused"),
        Err(e) => e.to_string(),
    }
}

/// ADR-0845: an absent `LISTEN_TLS_ENABLED` refuses, naming the variable and
/// `tls.enabled` — the chart key this repository passes, not one the crate
/// guessed.
#[test]
fn an_absent_tls_flag_refuses_naming_the_variable_and_the_chart_key() {
    let message = refusal_of(&[("LISTEN_TLS_CLIENT_AUTH", "off")]);
    assert!(
        message.contains("LISTEN_TLS_ENABLED"),
        "the refusal must name LISTEN_TLS_ENABLED"
    );
    assert!(
        message.contains("`tls.enabled`"),
        "the refusal must name the chart key tls.enabled"
    );
}

/// X-ADR-1 (extends ADR-0845): an absent `LISTEN_TLS_CLIENT_AUTH` refuses
/// WHETHER OR NOT TLS is on. The cleartext case is the one a narrower reading
/// would let through, so it is the one asserted.
#[test]
fn an_absent_client_auth_mode_refuses_even_in_cleartext() {
    let message = refusal_of(&[("LISTEN_TLS_ENABLED", "0")]);
    assert!(
        message.contains("LISTEN_TLS_CLIENT_AUTH"),
        "the refusal must name LISTEN_TLS_CLIENT_AUTH"
    );
    assert!(
        message.contains("`tls.clientAuth`"),
        "the refusal must name the chart key tls.clientAuth"
    );
}

/// The three modes are exact. Each wrong spelling refuses naming the chart
/// key, rather than choosing a posture nobody wrote.
#[test]
fn a_mode_outside_the_three_refuses_naming_the_chart_key() {
    for value in ["on", "Required", "true", "OFF"] {
        let pairs = [
            ("LISTEN_TLS_ENABLED", "0"),
            ("LISTEN_TLS_CLIENT_AUTH", value),
        ];
        let message = refusal_of(&pairs);
        assert!(
            message.contains("`tls.clientAuth`"),
            "a mode outside off, optional and required must refuse naming tls.clientAuth"
        );
    }
}

/// A STATED cleartext listener is still the reverted state: `0` with `off`
/// binds plaintext, and a certificate left beside it is how a cut-over is
/// pulled back.
#[test]
fn explicit_zero_with_client_auth_off_is_the_cleartext_listener() {
    let pairs = [
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert!(
        matches!(from_lookup(lookup(&pairs)), Ok(None)),
        "an explicit 0 with clientAuth off must be the cleartext listener"
    );
}

/// A verifying mode beside a cleartext listener names a check that cannot
/// run, so it refuses naming both chart keys.
#[test]
fn a_verifying_mode_with_tls_off_refuses_naming_both_chart_keys() {
    for mode in ["optional", "required"] {
        let pairs = [
            ("LISTEN_TLS_ENABLED", "0"),
            ("LISTEN_TLS_CLIENT_AUTH", mode),
            ("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CA),
        ];
        let message = refusal_of(&pairs);
        assert!(
            message.contains("`tls.enabled`") && message.contains("`tls.clientAuth`"),
            "a verifying mode with TLS off must name tls.enabled and tls.clientAuth"
        );
    }
}

/// A verifying mode with no authority to verify against refuses naming
/// `tls.clientCaSecret`, the chart key that mounts one.
#[test]
fn a_verifying_mode_without_a_client_ca_refuses_naming_the_chart_key() {
    for mode in ["optional", "required"] {
        let pairs = [
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ("LISTEN_TLS_CLIENT_AUTH", mode),
        ];
        let message = refusal_of(&pairs);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_CA_FILE"),
            "the refusal must name LISTEN_TLS_CLIENT_CA_FILE"
        );
        assert!(
            message.contains("`tls.clientCaSecret`"),
            "the refusal must name the chart key tls.clientCaSecret"
        );
    }
}

/// Every path reaches the settings, proved with names the module could not
/// have chosen for itself — the client CA included, which is the half this
/// repository never read before.
#[test]
fn every_path_and_the_mode_arrive() {
    let pairs = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ("LISTEN_TLS_CLIENT_AUTH", "required"),
        ("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CA),
    ];
    let Ok(Some(tls)) = from_lookup(lookup(&pairs)) else {
        panic!("a complete required configuration must enable TLS");
    };
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
    assert_eq!(tls.client_auth(), ClientAuth::Required);
    assert_eq!(tls.client_ca_file(), Some(Path::new(SENTINEL_CA)));
}
