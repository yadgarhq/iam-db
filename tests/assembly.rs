//! WHICH FILES THIS DEPLOYMENT WATCHES — the half of ADR-0523's rotation
//! watcher that is this repository's own.
//!
//! The watcher's BEHAVIOUR is `yadgar-lifecycle`'s and is tested there, against
//! the atomic `..data` swap kubelet really performs: that a change ends the
//! watch, that an identical-bytes swap does not, that an unreadable mount is
//! survived, that the leaf rather than the issuer is what the gauge reports.
//! None of that is repeated here. What is here is the claim only this repository
//! can make: **an `iam-db` configured this way reads exactly these files, so
//! exactly these files are watched.**
//!
//! **THE MUTANT THIS FILE EXISTS TO KILL.** The watch set is one call in
//! `main.rs`, and no test in this repository spawns the binary — so a member
//! deleted from the list would compile, pass the whole suite, and ship a process
//! that would never notice that file rotating. Every case below goes through
//! [`yadgar_iam_db::rotate::watch_set`], the SAME function `main.rs` calls.
//!
//! **TWO OF THE THREE MATERIALS ARE NOT TRANSPORT.** The database password is
//! not a certificate and the engine's CA is not one this process presents; both
//! are read once at boot out of mounts that rotate, and ADR-0523's rule is about
//! provenance rather than payload. A watch set admitting only TLS files would be
//! EMPTY in the cleartext deployment this estate runs today.
//!
//! CERTIFICATES ARE MINTED PER RUN, for the reason `tests/serve_tls.rs` gives: a
//! fixture key in the repository is a secret in the repository, and it expires
//! on a date nobody is watching.
//!
//! **NO METRICS RECORDER HERE, DELIBERATELY.** The gauge NAMES belong to
//! `yadgar-lifecycle` and are asserted there. What this file needs of the leaf
//! is that the RIGHT certificate was parsed, and `Inputs::not_after` answers
//! that without a recorder — so the metric is proved by the value it would
//! carry rather than by a second dev-dependency.

use std::path::{Path, PathBuf};

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

use yadgar_iam_db::rotate::{self, Presented};
use yadgar_iam_db::serve::{self, ServerTls};

/// The leaf's expiry, and the issuing authority's — DELIBERATELY DIFFERENT and
/// deliberately a decade apart. cert-manager writes the leaf first and the chain
/// after it, so an implementation that parsed the LAST certificate in the file
/// would report an expiry ten years out.
const LEAF_NOT_AFTER: i64 = 1_813_017_600; // 2027-06-15T00:00:00Z

/// A directory that deletes itself, standing in for the mount.
struct Mount(PathBuf);

impl Mount {
    fn new(files: &[(&str, String)]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "yadgar-iam-db-assembly-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        for (name, contents) in files {
            std::fs::write(path.join(name), contents).unwrap();
        }
        Self(path)
    }

    fn at(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Everything a fully configured `iam-db` reads at boot.
///
/// `tls.pem` holds the leaf FOLLOWED BY the authority that issued it, which is
/// the shape cert-manager writes.
fn mount() -> Mount {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = date_time_ymd(2037, 6, 15);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-iam-db assembly test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["iam-db".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_after = date_time_ymd(2027, 6, 15);
    params.distinguished_name.push(DnType::CommonName, "iam-db");
    let leaf = params.signed_by(&key, &ca).unwrap();

    Mount::new(&[
        ("tls.pem", format!("{}{}", leaf.pem(), ca.pem())),
        ("tls-key.pem", key.serialize_pem()),
        ("db-ca.pem", ca.pem()),
        // NOT A CERTIFICATE, and in the set for exactly the reason ADR-0523
        // gives: the process read it at boot, the chart mounts it as a DIRECTORY
        // so it can rotate, and it is baked into a pool that outlives every
        // reconnect. A TRAILING NEWLINE, because `kubectl create secret
        // --from-file` keeps the one an editor added.
        ("password", "sentinel-database-password\n".to_string()),
    ])
}

/// The listener's transport built the way a DEPLOYMENT builds it — out of the
/// three variables — rather than by assembling the struct. A test that bypassed
/// `from_lookup` would leave the reading of those names unproven.
fn listener(mount: &Mount) -> ServerTls {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1".to_string()),
        (
            "LISTEN_TLS_CERT_FILE",
            mount.at("tls.pem").display().to_string(),
        ),
        (
            "LISTEN_TLS_KEY_FILE",
            mount.at("tls-key.pem").display().to_string(),
        ),
    ];
    ServerTls::from_lookup(serve::LISTEN, |key| {
        vars.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    })
    .expect("the listener's transport")
    .expect("TLS is enabled in this fixture")
}

fn watched(inputs: &rotate::Inputs) -> Vec<String> {
    let mut names: Vec<String> = inputs
        .watched()
        .into_iter()
        .map(|p| {
            Path::new(p)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn a_fully_configured_iam_db_watches_every_file_it_read() {
    let mount = mount();
    let listener = listener(&mount);

    let inputs = rotate::watch_set(
        Some(&listener),
        &mount.at("password"),
        Some(&mount.at("db-ca.pem")),
    );

    assert_eq!(
        watched(&inputs),
        vec!["db-ca.pem", "password", "tls-key.pem", "tls.pem"],
        "four files were read at boot, so four files are watched"
    );
    assert!(
        inputs.unread_at_boot().is_empty(),
        "every member of the set was readable when it was hashed"
    );
}

#[test]
fn the_private_key_is_watched_beside_its_certificate() {
    // BOTH HALVES, OR THE PAIR ROTATES HALF-WATCHED. kubelet swaps a mount
    // atomically, so a set holding only the certificate still fires on an
    // ordinary rotation — but a deployment that rewrites the key alone would
    // pass unnoticed, and this is the assertion that says so out loud.
    let mount = mount();
    let listener = listener(&mount);

    let inputs = rotate::watch_set(Some(&listener), &mount.at("password"), None);

    assert!(watched(&inputs).contains(&"tls-key.pem".to_string()));
    assert!(watched(&inputs).contains(&"tls.pem".to_string()));
}

#[test]
fn the_leaf_is_what_the_expiry_gauge_would_carry_and_never_the_issuer() {
    // cert-manager writes the leaf FIRST and the chain after it. An
    // implementation that parsed the last certificate in the file would report an
    // expiry a decade out — a plausible number, and the wrong one.
    let mount = mount();
    let listener = listener(&mount);

    let inputs = rotate::watch_set(Some(&listener), &mount.at("password"), None);

    assert_eq!(
        inputs.not_after(Presented::Serving),
        Some(LEAF_NOT_AFTER),
        "the served leaf's expiry, not the authority's"
    );
}

#[test]
fn a_cleartext_iam_db_still_watches_its_database_password() {
    // **THE DEPLOYMENT THIS ESTATE ACTUALLY RUNS.** The listener's TLS is opt-in
    // and off by every chart default, so a watch set admitting only transport
    // material would be EMPTY here — and an empty set means `rotate::watch` never
    // resolves and nothing is watched at all.
    //
    // The password is the member with no other signal: it is read once and baked
    // into a pool that outlives every reconnect, so a rotated Secret breaks
    // nothing until some later reconnect, in a pod nobody is looking at.
    let mount = mount();

    let inputs = rotate::watch_set(None, &mount.at("password"), None);

    assert_eq!(watched(&inputs), vec!["password"]);
    assert!(
        !inputs.is_empty(),
        "a cleartext deployment must still be watching something"
    );
}

#[test]
fn an_unconfigured_engine_authority_contributes_nothing_rather_than_a_missing_file() {
    // `DB_SSL_CA_FILE` is optional — a deployment trusting the public web roots
    // names none. `Option<&Path>: Material` folds an absent one to nothing, so
    // there is no branch at the call site and no phantom path in the set.
    let mount = mount();

    let with = rotate::watch_set(None, &mount.at("password"), Some(&mount.at("db-ca.pem")));
    let without = rotate::watch_set(None, &mount.at("password"), None);

    assert_eq!(watched(&with), vec!["db-ca.pem", "password"]);
    assert_eq!(watched(&without), vec!["password"]);
}
