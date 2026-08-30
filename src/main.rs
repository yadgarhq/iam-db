//! Boot order is the decision here, not the wiring.
//!
//! Probe, migrate, then serve — and the service does not report ready until all
//! three have succeeded. D7 makes a capability gap a boot failure, and D69 puts
//! the probe before the pool is declared ready precisely so a failure is a
//! crash-loop rather than a pod that accepts traffic and fails queries. Under
//! D68 the second shape is actively harmful: a pod that starts and then errors is
//! one the HPA adds replicas around.

use std::net::SocketAddr;

use sqlx::Connection;
use yadgar_store::capability::{Capability, CapabilitySet};
use yadgar_store::credentials::{CredentialSource, Secret};
use yadgar_store::pool::PoolConfig;
use yadgar_store::{migrate, probe};

use yadgar_iam_db::pb::yadgar::iamdb::v1::iam_db_service_server::IamDbServiceServer;
use yadgar_iam_db::{schema, service::IamDb};

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

    let config = PoolConfig {
        host: env_or("DB_HOST", "127.0.0.1"),
        port: env_or("DB_PORT", "3306").parse()?,
        database: env_or("DB_NAME", "iam"),
        username: env_or("DB_USER", "iam"),
        max_connections: env_or("DB_MAX_CONNECTIONS", "8").parse()?,
        replicas: env_or("REPLICAS", "2").parse()?,
        engine_max_connections: env_or("DB_ENGINE_MAX_CONNECTIONS", "151").parse()?,
        require_tls: env_or("DB_REQUIRE_TLS", "true") == "true",
    };

    // The credential never arrives as an environment variable — it is a mounted
    // Secret the operator issued (D58), read through the seam so this module has
    // no idea which deployment target it is on.
    let secret: Secret = CredentialSource::SecretFile(
        env_or("DB_PASSWORD_FILE", "/var/run/secrets/iam-db/password").into(),
    )
    .resolve()?;

    // 1. PROBE, on a connection of its own and before the pool exists. Refusing
    //    here is the whole point of D7.
    let mut conn = sqlx::MySqlConnection::connect(&format!(
        "mysql://{}:{}@{}:{}/{}",
        config.username,
        secret.expose(),
        config.host,
        config.port,
        config.database
    ))
    .await?;
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
    tracing::info!(%addr, "iam-db listening");
    tonic::transport::Server::builder()
        .add_service(IamDbServiceServer::new(IamDb::new(pool)))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}
