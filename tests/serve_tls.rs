//! The serving TLS seam, proved by real handshakes.
//!
//! **A test that only shows "TLS was configured" passes against the broken
//! version of this change**, so nothing here inspects a `ServerTlsConfig`. Every
//! case stands the real listener up through [`yadgar_iam_db::serve::builder`],
//! dials it, and asserts on whether a request survived the transport.
//!
//! **The configuration travels the whole way.** Each case builds its
//! [`ServerTls`] through `from_lookup`, so the same reading of
//! `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE` that a deployment performs
//! is what ends up on the wire — not a struct assembled by the test.
//!
//! **ALPN is verified by consequence, and that is worth stating plainly.** tonic
//! pushes `h2` onto the server's ALPN list itself
//! (`tonic/src/transport/server/service/tls.rs`), and its channel connector
//! REFUSES a connection whose negotiated protocol is not `h2` unless
//! `assume_http2` was asked for — `tonic/src/transport/channel/service/tls.rs`,
//! the `H2NotNegotiated` arm. Nothing here sets `assume_http2`. So a gRPC
//! request that comes back `Unimplemented` over TLS is proof that `h2` was
//! negotiated: without it the client would have refused the connection. No
//! mutation of THIS repository's code can turn that assertion red, because the
//! server's ALPN list is tonic's; the assertion is a guard against a tonic
//! upgrade that drops it, not against a local mistake.
//!
//! CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
//! a secret committed to the repository, and it expires on a date nobody is
//! watching.
//!
//! NOTE ON `localhost`: it is the one name that resolves without touching
//! `/etc/hosts`, and on this machine it resolves to BOTH `::1` and `127.0.0.1`.
//! `serve` therefore binds every address the name resolves to, on one port, so a
//! client that picks the other one is not talking to a closed port. That is a
//! property of the test rig, not of the service.

use std::collections::HashSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

use yadgar_iam_db::serve::{self, ServerTls, ServerTlsError};

/// The name the test certificates are issued for, and the name the rig listens
/// on.
const SERVED_NAME: &str = "localhost";

/// A name NOTHING in `serve.rs` could have chosen for itself, used where the
/// question is whether the certificate on the wire came from the configured
/// FILE rather than from somewhere inside the implementation.
const SENTINEL_NAME: &str = "iam-db-served-this-and-nothing-else.invalid";

/// A certificate authority and one certificate it issued.
struct Pki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Mint a CA and a server certificate whose ONLY subject alternative name is
/// `san` — a DNS name, with no IP SAN.
fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-iam-db test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A file that deletes itself, so a certificate and a key can be handed over as
/// PATHS — which is the only shape [`ServerTls`] accepts, and the reason it
/// accepts it (D80).
struct TempPem(PathBuf);

/// One reading of the clock per PROCESS, so two runs that the OS gave the same
/// recycled pid do not name the same files. It varies per run and never within
/// one, which is what leaves [`unique_name`] with exactly one varying part.
fn run_id() -> u128 {
    static RUN: OnceLock<u128> = OnceLock::new();
    *RUN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    })
}

/// The name of one temporary PEM, unique within this process by CONSTRUCTION.
///
/// **THE CLOCK IS NOT A UNIQUENESS SOURCE ACROSS THREADS, and this is measured
/// on this tree rather than assumed.** The name used to be `pid` plus a fresh
/// nanosecond reading. Every test in this binary shares the pid and they run on
/// threads, so two concurrent calls collide whenever both readings land on the
/// same nanosecond — and then one `TempPem`'s `Drop` deletes a path a sibling
/// test is still reading. A clock is a timestamp, not a nonce (ledger 681).
///
/// The counter is the ONLY part that varies within a run, which is what makes
/// the property assertable rather than merely likely.
fn unique_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "yadgar-iam-db-{}-{}-{}.pem",
        std::process::id(),
        run_id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// The SEQUENTIAL property, and it is a mutation guard rather than a
/// reproduction — stated plainly because the distinction was measured. It
/// PASSES against the clock-based name this change replaces: same-thread
/// readings advance by tens of nanoseconds and never repeat, so a sequential
/// assertion cannot see the defect.
///
/// MUTATION: replace `fetch_add(1, ..)` with `load(..)` and this fails on every
/// run.
#[test]
fn two_temporary_names_are_never_the_same_name() {
    assert_ne!(unique_name(), unique_name());

    let many: HashSet<String> = (0..1000).map(|_| unique_name()).collect();
    assert_eq!(many.len(), 1000, "1000 names must be 1000 distinct names");
}

/// THE CONCURRENT PROPERTY, which is the one that reproduces the defect, and it
/// is the failing test this fix was written against. Cross-thread readings of
/// `SystemTime::now()` repeat constantly; same-thread ones do not, which is why
/// only a threaded assertion can see it.
#[test]
fn concurrent_names_are_all_distinct() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 2000;

    let start = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                (0..PER_THREAD).map(|_| unique_name()).collect::<Vec<_>>()
            })
        })
        .collect();

    let all: Vec<String> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let distinct: HashSet<&String> = all.iter().collect();
    assert_eq!(
        distinct.len(),
        THREADS * PER_THREAD,
        "{} of {} names collided across {THREADS} threads",
        THREADS * PER_THREAD - distinct.len(),
        THREADS * PER_THREAD
    );
}

impl TempPem {
    fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name());
        // `create_new`, not `fs::write`. Silence is what made the old collision
        // expensive: two tests shared a path, one deleted it, and the other
        // failed somewhere else entirely — as a missing file, or as a negative
        // fixture that had been overwritten with valid material. If a name is
        // ever reused, this panics and names the file instead.
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{} already exists or cannot be made: {e}", path.display()));
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build the settings the way a DEPLOYMENT builds them — out of the three
/// variables — rather than by assembling the struct directly. A test that
/// bypassed `from_lookup` would leave the reading of those names unproven.
fn configured(cert: &Path, key: &Path) -> ServerTls {
    let vars: Vec<(String, String)> = vec![
        ("LISTEN_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "LISTEN_TLS_CERT_FILE".to_string(),
            cert.display().to_string(),
        ),
        ("LISTEN_TLS_KEY_FILE".to_string(), key.display().to_string()),
    ];
    ServerTls::from_lookup(serve::LISTEN, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a flag, a certificate and a key are a complete configuration")
    .expect("the flag is set, so this is the TLS path")
}

/// Stand the service's own listener up on every address `SERVED_NAME` resolves
/// to, and return the shared port.
///
/// `Routes::default()` answers every method with `Unimplemented`, which is all
/// that is needed: the question each test asks is whether a request reached the
/// server at all.
async fn serve(tls: Option<&ServerTls>) -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");

    let (port, listeners) = bind_one_port_on_every_address(&addrs).await;
    for listener in listeners {
        spawn(listener, tls);
    }

    ready(port).await;
    port
}

/// How many ports to try before giving up on finding one free everywhere. The
/// count is NAMED rather than inlined so the panic below can state it; the
/// number is unchanged, because lowering it is a behaviour change with no
/// measurement behind it.
const BIND_ATTEMPTS: usize = 50;

/// One ephemeral port, bound on EVERY address the name resolves to.
///
/// **THE KERNEL PICKS THE PORT FOR ONE ADDRESS AND PROMISES NOTHING ABOUT THE
/// OTHERS.** Asking for an ephemeral port on `127.0.0.1` and then demanding that
/// same number on `::1` fails whenever a concurrently running test in this
/// binary was handed it there first — `EADDRINUSE` on the second bind, which the
/// old code turned into `.expect(..)`. It is a second, independent race in the
/// same rig, and it was measured firing on this tree, so fixing only the filed
/// defect would have left the suite flaky.
///
/// So the whole SET is acquired before anything is spawned, and a partial
/// acquisition is dropped and retried with a fresh port. Retrying is honest
/// here: the failure is another process holding a number, which the next number
/// does not have.
///
/// **RETRYING IS ONLY HONEST FOR A PORT SOMEBODY ELSE HOLDS.** Every other bind
/// error is permanent, so retrying one spends fifty ports to learn nothing and
/// then blames port exhaustion for it. The case that makes this concrete: on a
/// host with IPv6 disabled where `localhost` still resolves `::1`, every bind on
/// `::1` returns `EADDRNOTAVAIL`. So `AddrInUse` is retried and every other
/// error names the address it happened on — the form `yadgar-dial`'s
/// `tests/common/mod.rs` already carries, which this rig cited as its precedent
/// and then did not adopt (ledger 708).
async fn bind_one_port_on_every_address(addrs: &[SocketAddr]) -> (u16, Vec<TcpListener>) {
    for _ in 0..BIND_ATTEMPTS {
        let first = TcpListener::bind(addrs[0])
            .await
            .unwrap_or_else(|e| panic!("no free port on {}: {e}", addrs[0].ip()));
        let port = first.local_addr().unwrap().port();

        let mut listeners = vec![first];
        for addr in &addrs[1..] {
            match TcpListener::bind(SocketAddr::new(addr.ip(), port)).await {
                Ok(listener) => listeners.push(listener),
                // Dropping `listeners` releases the port on every address it was
                // taken on, so the next attempt starts from nothing held.
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => break,
                Err(e) => panic!("binding {} on port {port}: {e}", addr.ip()),
            }
        }
        if listeners.len() == addrs.len() {
            return (port, listeners);
        }
    }
    panic!(
        "no ephemeral port was free on all {} addresses in {BIND_ATTEMPTS} attempts",
        addrs.len()
    );
}

/// A PERMANENT bind failure on a LATER address names that address, rather than
/// being spent as one of [`BIND_ATTEMPTS`] retries.
///
/// The failure is a real one rather than a mocked one: `192.0.2.0/24` is
/// TEST-NET-1, reserved for documentation and assigned to no interface, so
/// binding it returns `EADDRNOTAVAIL`. Against the `Err(_) => break` this
/// replaces, the case panicked with "no ephemeral port was free on all 2
/// addresses" — port exhaustion, which is the wrong diagnosis and the whole of
/// ledger 708.
#[tokio::test]
#[should_panic(expected = "binding 192.0.2.1")]
async fn a_permanent_failure_on_a_later_address_is_reported_not_retried() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 0)),
        SocketAddr::from(([192, 0, 2, 1], 0)),
    ];
    bind_one_port_on_every_address(&addrs).await;
}

/// The same property on the FIRST address, which is a SEPARATE path through the
/// same function and the likelier one to meet a disabled address family:
/// `localhost` resolves `::1` AHEAD of `127.0.0.1` on this machine, so a host
/// with IPv6 off fails on `addrs[0]` before the loop is ever reached. That bind
/// used to carry `.expect("an ephemeral port on the first address")`, which
/// named no address and reported the wrong cause just as the loop did.
#[tokio::test]
#[should_panic(expected = "no free port on 192.0.2.1")]
async fn a_permanent_failure_on_the_first_address_is_reported_not_retried() {
    let addrs = [SocketAddr::from(([192, 0, 2, 1], 0))];
    bind_one_port_on_every_address(&addrs).await;
}

fn spawn(listener: TcpListener, tls: Option<&ServerTls>) {
    let mut server = serve::builder(tls).expect("a usable certificate and key");
    let router = server.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// Wait until the port accepts a TCP connection, rather than sleeping a guessed
/// interval.
async fn ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((SERVED_NAME, port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}

/// Send one gRPC request at `port` and report whether it ARRIVED.
///
/// `Ok` means the transport carried it: the handshake completed and the server
/// answered — with `Unimplemented`, which is a perfectly good answer to this
/// question. `Err` means it never got there, whether the connection or the
/// request is where it stopped.
async fn reach(port: u16, tls: Option<ClientTlsConfig>) -> Result<(), String> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{SERVED_NAME}:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5));
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(tls).map_err(|e| format!("{e}"))?;
    }
    // LAZY, so there is exactly one place a failure can be observed. An eager
    // `connect` would report a refused handshake from a different call than the
    // one reporting a refused request, and every case here asks the same
    // question of both.
    let mut channel = endpoint.connect_lazy();

    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!(
            "{scheme}://{SERVED_NAME}/yadgar.iamdb.v1.IamDbService/Probe"
        ))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{e}")),
    }
}

fn trusting(ca_pem: &str, domain: &str) -> ClientTlsConfig {
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(domain)
}

/// THE PROPERTY THE WHOLE CAR EXISTS FOR: the listener speaks TLS, and a gRPC
/// request crosses it.
///
/// It is also the ALPN assertion. The client refuses any connection that does
/// not negotiate `h2` (`H2NotNegotiated`), and nothing here asks it to assume
/// HTTP/2 — so a server that offered no ALPN, or offered something else, would
/// fail this rather than serve a connection that answers nothing useful.
#[tokio::test]
async fn a_tls_client_reaches_a_server_built_with_tls() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME))).await,
        Ok(())
    );
}

/// THE OTHER HALF of "it really is TLS". A cleartext client must not reach a
/// TLS listener — otherwise the case above could pass while the server had
/// quietly started in the clear and the client had quietly stopped verifying.
#[tokio::test]
async fn a_cleartext_client_cannot_reach_a_tls_server() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert!(
        reach(port, None).await.is_err(),
        "cleartext against a TLS listener must fail"
    );
}

/// THE DEFAULT, unchanged. Nothing configured means the plaintext listener this
/// service has always had, and a client that expects one still finds it.
#[tokio::test]
async fn a_cleartext_client_reaches_a_server_built_without_tls() {
    let port = serve(None).await;
    assert_eq!(reach(port, None).await, Ok(()));
}

/// And the default really is plaintext, so the pair above cannot both start
/// passing because everything became TLS.
#[tokio::test]
async fn a_tls_client_cannot_reach_a_server_built_without_tls() {
    let p = pki(SERVED_NAME);
    let port = serve(None).await;

    assert!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME)))
            .await
            .is_err(),
        "TLS against a cleartext listener must fail"
    );
}

/// THE CERTIFICATE ON THE WIRE IS THE ONE AT THE CONFIGURED PATH, proved with a
/// name the implementation could not have chosen: the certificate is issued for
/// a sentinel, the client verifies against that sentinel, and only a server
/// presenting THAT FILE can satisfy it.
#[tokio::test]
async fn the_certificate_served_is_the_one_at_the_configured_path() {
    let p = pki(SENTINEL_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SENTINEL_NAME))).await,
        Ok(())
    );
}

/// A certificate from an authority the caller does not trust is what an impostor
/// presents. The connection has to fail, which is also what proves the client
/// side of every case above is doing real verification.
#[tokio::test]
async fn a_certificate_from_an_untrusted_authority_is_refused() {
    let served = pki(SERVED_NAME);
    let cert = TempPem::with(&served.cert_pem);
    let key = TempPem::with(&served.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    // A second authority, which issued nothing the server holds.
    let stranger = pki(SERVED_NAME);
    assert!(
        reach(port, Some(trusting(&stranger.ca_pem, SERVED_NAME)))
            .await
            .is_err(),
        "a certificate signed by an authority that is not trusted must be refused"
    );
}

/// THE FAILURE THAT MUST NOT DEGRADE, in the form an operator actually produces:
/// the mount did not happen, so the path names nothing.
///
/// `builder` must return an error naming the file. It must NOT return a server —
/// a server returned here is a PLAINTEXT listener carrying a TLS configuration
/// that failed, which is the whole defect this car removes.
#[tokio::test]
async fn a_certificate_path_that_cannot_be_read_is_an_error() {
    let missing = std::env::temp_dir().join("yadgar-iam-db-no-such-cert-6a17d4.pem");
    let key = TempPem::with("irrelevant, the certificate is checked first");
    let tls = configured(&missing, key.path());

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServerTlsError::CertUnreadable { .. })),
        "a certificate path that does not exist must be refused, not served in cleartext"
    );
    assert!(
        outcome.err().unwrap().to_string().contains(
            missing
                .to_str()
                .expect("the temporary directory is valid UTF-8")
        ),
        "the message must name the file the operator has to fix"
    );
}

/// The same for the key, and separately — an operator who mounted one and not
/// the other must be told WHICH.
#[tokio::test]
async fn a_key_path_that_cannot_be_read_is_an_error() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let missing = std::env::temp_dir().join("yadgar-iam-db-no-such-key-6a17d4.pem");
    let tls = configured(cert.path(), &missing);

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServerTlsError::KeyUnreadable { .. })),
        "a key path that does not exist must be refused, not served in cleartext"
    );
    assert!(
        outcome
            .err()
            .unwrap()
            .to_string()
            .contains(missing.to_str().unwrap()),
        "the message must name the file the operator has to fix"
    );
}

/// A file that exists and holds no certificate. The PEM reader returns an EMPTY
/// LIST rather than an error for this, so "parsed successfully" can mean "parsed
/// nothing" — and a listener with no certificate is not a listener.
#[tokio::test]
async fn a_certificate_file_with_no_certificate_in_it_is_an_error() {
    let p = pki(SERVED_NAME);
    let key = TempPem::with(&p.key_pem);

    for contents in ["", "   ", "\n", "there is no certificate in this file\n"] {
        let cert = TempPem::with(contents);
        let tls = configured(cert.path(), key.path());
        let outcome = serve::builder(Some(&tls));
        assert!(
            matches!(outcome, Err(ServerTlsError::CertEmpty { .. })),
            "a certificate file containing {contents:?} must be refused"
        );
    }
}

/// A key file that decodes to nothing. Same shape, and the message has to name
/// the key rather than the certificate.
#[tokio::test]
async fn a_key_file_with_no_key_in_it_is_an_error() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);

    for contents in ["", "   ", "\n", "there is no private key in this file\n"] {
        let key = TempPem::with(contents);
        let tls = configured(cert.path(), key.path());
        let outcome = serve::builder(Some(&tls));
        assert!(
            matches!(outcome, Err(ServerTlsError::KeyUnparsable { .. })),
            "a key file containing {contents:?} must be refused"
        );
    }
}

/// THE MISMATCH. Two independent authorities, each with its own leaf: the
/// certificate of one paired with the private key of the other. Both files are
/// individually valid PEM, so nothing short of checking them TOGETHER notices —
/// and a listener whose key does not match its certificate completes no
/// handshake at all.
#[tokio::test]
async fn a_certificate_and_a_key_that_do_not_match_are_an_error() {
    let one = pki(SERVED_NAME);
    let other = pki(SERVED_NAME);
    let cert = TempPem::with(&one.cert_pem);
    let key = TempPem::with(&other.key_pem);
    let tls = configured(cert.path(), key.path());

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServerTlsError::Rejected { .. })),
        "a key that does not match the certificate must be refused at boot"
    );
    let message = outcome.err().unwrap().to_string();
    assert!(
        message.contains(cert.path().to_str().unwrap())
            && message.contains(key.path().to_str().unwrap()),
        "the message must name BOTH files, because either could be the wrong one: {message}"
    );
}

/// THE REFUSAL ABOVE HAS TO SAY WHAT WAS WRONG, and the case above cannot tell.
///
/// It asserts the variant and the two PATHS, which are `serve.rs`'s own fields —
/// so it passes whether `detail` was built by walking the error's `source()`
/// chain or by a bare `e.to_string()`. On that one property it is a certifying
/// fixture, green under both, and that is the exact defect telemetry#12
/// corrected in the shared unit `serve::builder` now calls.
///
/// **TWO LAYERS AND ONE `source()` HOP, read out of the dependencies rather than
/// inferred from rendered output.** The head is `tonic::transport::Error`: its
/// `Display` is `f.write_str(self.description())` (tonic 0.14.6
/// `src/transport/error.rs:79-83`), and `description()` returns the literal
/// `"transport error"` for `Kind::Transport` (`:52-54`) without ever consulting
/// the source. One hop down is `rustls::Error`, which is a LEAF — `impl
/// std::error::Error for Error {}`, the default `source()` returning `None`
/// (rustls 0.23.43 `src/error.rs:1022`) — and whose `InconsistentKeys` arm
/// renders `keys may not be consistent: {why:?}` (`:1003-1005`).
///
/// **`KeyMismatch` IS NOT A THIRD LAYER, and an earlier version of this comment
/// said it was.** It is the `{why:?}` INSIDE rustls's single `Display` string —
/// the `Debug` of a `#[non_exhaustive]`, `Copy` enum (`:121-133`). The colon in
/// front of it is rustls's own punctuation, not a join this walk performed.
/// Reading a layer boundary out of a colon in rendered output is exactly the
/// mistake ADR-0591 exists to stop, and the correction came from reading the two
/// crates rather than from anything CI reported.
///
/// So the assertion below is on the DELIBERATE `Display` string and NOT on that
/// `Debug`: a `#[non_exhaustive]` enum's `Debug` is the least stable text in the
/// chain, and pinning it would redden five repositories at once for a change
/// that is not a defect. Both spellings discriminate identically — neither
/// appears anywhere in tonic's two words — so nothing is given up by choosing
/// the stable one.
///
/// A `detail` carrying `keys may not be consistent` therefore crossed the one
/// hop and cannot have come from the head alone. Reverting the call site to
/// `e.to_string()` leaves `detail` as exactly `transport error` and turns this
/// red.
#[tokio::test]
async fn the_refusal_names_the_reason_rather_than_just_transport_error() {
    let one = pki(SERVED_NAME);
    let other = pki(SERVED_NAME);
    let cert = TempPem::with(&one.cert_pem);
    let key = TempPem::with(&other.key_pem);
    let tls = configured(cert.path(), key.path());

    let Err(ServerTlsError::Rejected { detail, .. }) = serve::builder(Some(&tls)) else {
        panic!("a key that does not match the certificate must be refused at boot");
    };

    assert!(
        detail.contains("keys may not be consistent"),
        "the detail must carry the layer UNDER tonic's `transport error`, which is \
         the only part naming what was wrong; got: {detail:?}"
    );
    assert_ne!(
        detail.trim(),
        "transport error",
        "the head of the chain alone says nothing an operator can act on"
    );
}
