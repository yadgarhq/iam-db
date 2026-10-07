use super::*;

/// The values below are SENTINELS: nothing in `serve.rs` could produce
/// either of them, so a test that sees one saw it travel from the lookup.
const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/server.pem";
const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/server-key.pem";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// H1 (ADR-0845): ABSENCE NO LONGER MEANS CLEARTEXT. It used to; this is the
/// property the whole change replaces, and the red-first case for it: today
/// this was `Ok(None)`.
#[test]
fn nothing_configured_refuses_naming_the_flag() {
    let err = ServerTls::from_lookup(LISTEN, lookup(&[])).unwrap_err();
    assert!(
        matches!(err, ServerTlsError::EnabledInvalid { prefix: LISTEN, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("LISTEN_TLS_ENABLED"), "{err}");
    assert!(err.to_string().contains("tls.enabled"), "{err}");
}

/// Paths with no flag at all refuse too — H1 does not carve out an exception
/// for "a certificate is configured", because the failure it exists to stop
/// is exactly a chart that failed to render the flag, and that chart can
/// just as easily have rendered the certificate paths beside it.
#[test]
fn a_certificate_alone_with_no_flag_still_refuses() {
    let vars = [
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    let err = ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap_err();
    assert!(
        matches!(err, ServerTlsError::EnabledInvalid { .. }),
        "{err}"
    );
}

/// Explicit "0" is still the REVERTED state, not an error, and a certificate
/// left in place beside it is still how the lever gets pulled back — that
/// half of the behaviour is unchanged by H1, which narrows what counts as
/// "off" to a STATED "0" rather than widening what counts as an error.
#[test]
fn explicit_zero_with_a_certificate_still_disables_tls() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
}

/// Exactly "1" or "0" and nothing else, in either direction. A permissive
/// parse is how a setting meant to be off ends up on, and the reverse
/// mistake is worse: nothing here, including "" and " ", degrades to the
/// old default of cleartext any more — every one of them is now a named
/// refusal, not a silent choice.
#[test]
fn anything_but_one_and_zero_refuses() {
    for value in ["false", "no", "true", "yes", "", " "] {
        let vars = [
            ("LISTEN_TLS_ENABLED", value),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        let err = ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap_err();
        assert!(
            matches!(err, ServerTlsError::EnabledInvalid { .. }),
            "{value:?} must refuse, not silently choose a transport: {err}"
        );
    }
}

/// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
/// certificate is a deployment mistake, and the answer to it is an error
/// rather than a plaintext listener.
#[test]
fn asking_for_tls_without_a_certificate_is_an_error() {
    for vars in [
        vec![("LISTEN_TLS_ENABLED", "1")],
        vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "")],
        vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "   ")],
    ] {
        assert!(
            matches!(
                ServerTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServerTlsError::NoCertFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// And the same for the key, separately — a certificate with no key serves
/// nothing, and half a configuration is not a reason to serve cleartext.
#[test]
fn asking_for_tls_without_a_key_is_an_error() {
    for vars in [
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ],
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", "  "),
        ],
    ] {
        assert!(
            matches!(
                ServerTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServerTlsError::NoKeyFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// Both paths reach the settings, proved with names the module could not
/// have chosen for itself.
#[test]
fn both_paths_arrive() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    let tls = ServerTls::from_lookup(LISTEN, lookup(&vars))
        .unwrap()
        .expect("a flag, a certificate and a key enable TLS");
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
}

/// The prefix is what selects the variables, so a value meant for something
/// else cannot configure the listener. `LISTEN_TLS_ENABLED` itself is still
/// absent here, so this refuses exactly as the no-variables case does — the
/// property under test is that it refuses NAMING "LISTEN", never "TLS",
/// "SERVER_TLS" or "IAM_DB_TLS", which would mean one of the wrong-prefix
/// variables was read instead.
#[test]
fn variables_under_another_prefix_do_not_configure_the_listener() {
    let vars = [
        ("TLS_ENABLED", "1"),
        ("SERVER_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_ENABLED", "1"),
        ("TLS_CERT_FILE", SENTINEL_CERT),
    ];
    let err = ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap_err();
    assert!(
        matches!(err, ServerTlsError::EnabledInvalid { prefix: LISTEN, .. }),
        "{err}"
    );
}

/// A CONFIGURATION error and a FILE error are different failures, and only
/// the first is decided here. `from_lookup` never touches the filesystem, so
/// a path that does not exist is still a complete configuration — the
/// refusal comes from `builder`, which is what `tests/serve_tls.rs` proves.
#[test]
fn from_lookup_does_not_read_the_files() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert!(ServerTls::from_lookup(LISTEN, lookup(&vars)).is_ok());
}
