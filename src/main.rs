//! Boot order is the decision here, not the wiring.
//!
//! Probe, migrate, then serve — and the service does not report ready until all
//! three have succeeded. D7 makes a capability gap a boot failure, and D69 puts
//! the probe before the pool is declared ready precisely so a failure is a
//! crash-loop rather than a pod that accepts traffic and fails queries. Under
//! D68 the second shape is actively harmful: a pod that starts and then errors is
//! one the HPA adds replicas around.
//!
//! **The listener's TRANSPORT is decided first, before the probe.** It is a
//! deployment mistake rather than an outage — the same class as an engine that
//! cannot satisfy D7 — so it fails the boot, and it fails it before a migration
//! runs, so an operator who mounted the wrong Secret is told at once. Nothing
//! here falls back to a plaintext listener when TLS was asked for: a service that
//! did would look healthy while carrying every credential in the module across
//! the pod network in the clear, which is exactly the failure nobody can see.
//!
//! TLS is OPT-IN and OFF by default, so with nothing configured this is the same
//! plaintext listener it has always bound.

use std::net::SocketAddr;

use sqlx::Connection;
use yadgar_store::capability::{Capability, CapabilitySet};
use yadgar_store::credentials::{CredentialSource, Secret};
use yadgar_store::{migrate, probe};

use yadgar_iam_db::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbServiceServer;
use yadgar_iam_db::{boot, schema, serve, service::IamDb};

/// What this module needs of its engine (D69). Addressed, not ranked — so no
/// vector search and no full-text (D10). Requiring either would make this module
/// refuse to boot on an engine that serves it perfectly well.
fn required() -> CapabilitySet {
    CapabilitySet::from([Capability::Transactions, Capability::RowLocking])
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        // A DEFAULT, because from_default_env() with RUST_LOG unset enables
        // NOTHING — the service runs silently and its boot sequence, its
        // capability probe result and its errors all vanish. Found by deploying:
        // two replicas were Running and `kubectl logs` returned nothing at all,
        // so the only way to see why one had restarted was the previous
        // container's exit output.
        //
        // A service nobody can observe is one D67 cannot measure either.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Every default, every refusal and the transport mode live in `boot`, which
    // a test can reach. This line is the whole of the configuration decision.
    let config = boot::pool_config(|key| std::env::var(key).ok())?;

    // 0. THE TRANSPORT THIS SERVICE LISTENS ON, before anything else runs. A
    //    missing certificate, an unreadable one, a file holding no certificate
    //    at all and a key belonging to a different certificate are all refused
    //    HERE — never downgraded to the plaintext listener, because a listener
    //    that quietly stayed in the clear is the one failure an operator who
    //    asked for TLS cannot see.
    //
    //    `.to_string()` on the way out, and not decoration: `main` returns
    //    `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` would
    //    put `CertUnreadable { .. }` on the operator's terminal instead of the
    //    sentence naming the file and saying why cleartext is not the answer.
    let listen_tls = serve::ServerTls::from_env(serve::LISTEN).map_err(|e| e.to_string())?;
    let mut server = serve::builder(listen_tls.as_ref()).map_err(|e| e.to_string())?;

    // The credential never arrives as an environment variable — it is a mounted
    // Secret the operator issued (D58), read through the seam so this module has
    // no idea which deployment target it is on.
    let secret: Secret = CredentialSource::SecretFile(
        env_or("DB_PASSWORD_FILE", "/var/run/secrets/iam-db/password").into(),
    )
    .resolve()?;

    // 1. PROBE, on a connection of its own and before the pool exists. Refusing
    //    here is the whole point of D7.
    //
    //    Its own CONNECTION, never its own connection OPTIONS. This used to be a
    //    `format!`-ed DSN with no `ssl-mode` in it, so the probe ran on sqlx's
    //    `Preferred` default — which falls back to an unencrypted connection —
    //    while the pool three lines down was on `Required`. The options come
    //    from the same function the pool uses, so the two cannot disagree.
    //
    //    `.to_string()` for the same reason the listener's refusals carry it:
    //    building these options REFUSES `verify_ca`, and that refusal is a
    //    paragraph naming the mode to use instead. A bare `?` would Debug-print
    //    `SslModeCannotVerify { .. }` into the crash loop and throw the sentence
    //    away.
    let options = boot::probe_connect_options(&config, &secret).map_err(|e| e.to_string())?;
    let mut conn = sqlx::MySqlConnection::connect_with(&options).await?;
    let report = probe::run(&mut conn).await?;
    report.satisfies(&required())?;
    conn.close().await?;
    tracing::info!("engine satisfies the required capabilities");

    // 2. MIGRATE. Refuses outright if the database is ahead of this binary.
    let pool = yadgar_store::pool::connect(&config, &secret).await?;
    let applied = migrate::apply(&pool, &schema::migrations()?).await?;
    tracing::info!(applied, "schema at migration {applied}");

    // 3. SERVE. Only now.
    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    let metrics_addr: SocketAddr = env_or("METRICS_LISTEN", "0.0.0.0:9090").parse()?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:50051").parse()?;
    // `tls` is recorded because "is this listener encrypted?" must be answerable
    // from the boot log rather than inferred from which variables somebody
    // believes they set.
    tracing::info!(%addr, tls = listen_tls.is_some(), "iam-db listening");

    // ARMED BEFORE THE SERVER IS SPAWNED, and that ordering is the fix rather
    // than an accident of where the line sits. `serve::shutdown` installs both
    // signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let shutdown = serve::shutdown().map_err(|e| {
        format!(
            "the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a \
             server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one"
        )
    })?;

    server
        .add_service(IamDbServiceServer::new(IamDb::new(pool)))
        .serve_with_shutdown(addr, shutdown)
        .await?;

    Ok(())
}
