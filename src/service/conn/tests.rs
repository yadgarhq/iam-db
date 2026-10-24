//! The cancel-safety of [`Conn`], on the real engine named by
//! `YADGAR_TEST_DSN` (D69: panics rather than skips without one).
//!
//! Each case runs on a pool of ONE connection, so the borrower after the drop
//! gets either the same connection back or, when the guard closed it, a fresh
//! one. Both cases then ask the engine what that borrower inherited.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Connection, MySqlPool};

use super::{acquire, store_work, Isolation};
use yadgar_dial::Deadline;

fn dsn() -> String {
    std::env::var("YADGAR_TEST_DSN")
        .expect("YADGAR_TEST_DSN is unset; these tests assert what a real MariaDB does")
}

/// A one-connection pool on a fresh database `db`, holding one InnoDB table so
/// a transaction has something to read.
async fn one_connection_pool(db: &str) -> MySqlPool {
    let mut root = sqlx::MySqlConnection::connect(&dsn())
        .await
        .expect("connect");
    for stmt in [
        format!("DROP DATABASE IF EXISTS {db}"),
        format!("CREATE DATABASE {db}"),
        format!("CREATE TABLE {db}.probe (id INT PRIMARY KEY) ENGINE=InnoDB"),
    ] {
        // AUDIT: `db` is a literal at every call site.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("reset database");
    }
    let base = dsn()
        .rsplit_once('/')
        .expect("dsn has a database component")
        .0
        .to_string();
    MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&format!("{base}/{db}"))
        .await
        .expect("pool")
}

/// What the next borrower inherits: whether it is already inside a server
/// transaction, and the isolation level a transaction it starts runs at.
///
/// The level is read from `information_schema.innodb_trx` after one InnoDB
/// write, NOT from `@@transaction_isolation`: a pending `SET TRANSACTION` does
/// not show in the session variable (measured on MariaDB 11.8).
async fn next_borrower(pool: &MySqlPool) -> (i64, String) {
    let mut conn = tokio::time::timeout(Duration::from_secs(10), pool.acquire())
        .await
        .expect("the next borrower got a connection within 10 s")
        .expect("acquire");
    let in_transaction: i64 = sqlx::query_scalar("SELECT CAST(@@in_transaction AS SIGNED)")
        .fetch_one(&mut *conn)
        .await
        .expect("read @@in_transaction");
    let mut tx = sqlx::Acquire::begin(&mut *conn).await.expect("begin");
    // A WRITE, rolled back below: InnoDB lists a read-write transaction in
    // `innodb_trx` reliably, and a plain read-only one not always.
    sqlx::query("INSERT INTO probe (id) VALUES (-1)")
        .execute(&mut *tx)
        .await
        .expect("an InnoDB write, so the transaction is registered");
    // `innodb_trx` is served from a cache that InnoDB refreshes only when it
    // has been IDLE for 100 ms since its last read (`can_cache_be_updated`), so
    // a transaction this new can be missing from it, and polling faster than
    // that keeps the cache stale forever. Each wait is longer than the idle
    // window.
    let mut level = None;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        level = sqlx::query_scalar(
            "SELECT trx_isolation_level FROM information_schema.innodb_trx \
              WHERE trx_mysql_thread_id = CONNECTION_ID()",
        )
        .fetch_optional(&mut *tx)
        .await
        .expect("read the transaction's isolation level");
        if level.is_some() {
            break;
        }
    }
    let level: String = level.expect("the transaction appeared in innodb_trx within 1.5 s");
    tx.rollback().await.expect("rollback");
    (in_transaction, level)
}

/// **DROPPED AFTER `SET TRANSACTION`, BEFORE `BEGIN`: THE NEXT BORROWER DOES
/// NOT INHERIT READ COMMITTED.** The window tonic opens when the caller's
/// deadline expires inside `redeem`, `store_setting` or the three team arms
/// (`sync_teams`, the bootstrap `CreateUser`, the declared enrolment).
#[tokio::test]
async fn a_drop_between_set_transaction_and_begin_leaves_no_pending_isolation_level() {
    let pool = one_connection_pool("iamdb_conn_cancel_set").await;

    // Inside a request that then completes normally, so only the `begin`
    // guard decides: the request's own cancellation flag stays clear.
    store_work(async {
        let mut conn = acquire(&pool, Deadline::none()).await.expect("acquire");
        let stopped = tokio::time::timeout(
            Duration::from_millis(200),
            conn.begin_after(Isolation::ReadCommitted, std::future::pending()),
        )
        .await
        .is_err();
        assert!(stopped, "the sequence was cut in the window");
    })
    .await;

    let (in_transaction, level) = next_borrower(&pool).await;
    assert_eq!(in_transaction, 0);
    assert_eq!(
        level, "REPEATABLE READ",
        "the next borrower's transaction must run at the session default"
    );
}

/// **DROPPED WHILE `BEGIN` IS IN FLIGHT: THE NEXT BORROWER IS NOT INSIDE A
/// SERVER TRANSACTION.** The begin future is polled exactly once, which sends
/// `BEGIN` and leaves it waiting for the reply; then the future is dropped.
#[tokio::test]
async fn a_drop_while_begin_is_in_flight_leaves_no_open_transaction() {
    let pool = one_connection_pool("iamdb_conn_cancel_begin").await;

    // Inside a request that completes normally: only the `begin` guard decides.
    store_work(async {
        let mut conn = acquire(&pool, Deadline::none()).await.expect("acquire");
        let mut begin = std::pin::pin!(conn.begin(Isolation::Default));
        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(begin.as_mut().poll(cx).is_pending()))
                .await;
        assert!(
            first,
            "BEGIN answered inside one poll, so this run did not reach the window"
        );
    })
    .await;

    let (in_transaction, level) = next_borrower(&pool).await;
    assert_eq!(
        in_transaction, 0,
        "the next borrower must not start inside the dropped BEGIN's transaction"
    );
    assert_eq!(level, "REPEATABLE READ");
}

/// **A SEQUENCE THAT RUNS TO `BEGIN` IS POOLED AS USUAL.** The guard disarms
/// once the transaction has started; sqlx's own rollback-on-drop covers the
/// rest, and the connection is reused rather than closed.
#[tokio::test]
async fn a_started_transaction_dropped_unfinished_returns_a_clean_reused_connection() {
    let pool = one_connection_pool("iamdb_conn_cancel_started").await;

    let first = store_work(async {
        let mut conn = acquire(&pool, Deadline::none()).await.expect("acquire");
        let first: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .expect("connection id");
        let mut tx = conn.begin(Isolation::ReadCommitted).await.expect("begin");
        sqlx::query("INSERT INTO probe (id) VALUES (1)")
            .execute(&mut *tx)
            .await
            .expect("insert");
        // Dropped without commit: sqlx queues the ROLLBACK.
        first
    })
    .await;

    let mut again = tokio::time::timeout(Duration::from_secs(10), pool.acquire())
        .await
        .expect("reacquired within 10 s")
        .expect("acquire");
    let second: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
        .fetch_one(&mut *again)
        .await
        .expect("connection id");
    assert_eq!(first, second, "a disarmed connection goes back to the pool");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM probe")
        .fetch_one(&mut *again)
        .await
        .expect("count");
    assert_eq!(rows, 0, "the unfinished transaction was rolled back");
    drop(again);

    let (in_transaction, level) = next_borrower(&pool).await;
    assert_eq!(in_transaction, 0);
    assert_eq!(level, "REPEATABLE READ");
}

/// **THE ACQUIRE WAITS NO LONGER THAN THE CALLER CAN.** One connection, held;
/// a 300 ms deadline against a 5 s `acquire_timeout` answers
/// DEADLINE_EXCEEDED before the deadline, not UNAVAILABLE at the ceiling.
#[tokio::test]
async fn an_exhausted_pool_answers_deadline_exceeded_inside_the_callers_deadline() {
    let pool = one_connection_pool("iamdb_conn_bound").await;
    let _held = pool.acquire().await.expect("hold the only connection");

    let started = std::time::Instant::now();
    let refused = acquire(&pool, Deadline::after(Duration::from_millis(300)))
        .await
        .err()
        .expect("no connection was free");
    let took = started.elapsed();
    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded);
    assert!(took < Duration::from_millis(300), "took {took:?}");
    assert!(took >= Duration::from_millis(200), "took {took:?}");
}

/// A deadline already inside the margin refuses at once, without waiting.
#[tokio::test]
async fn a_deadline_inside_the_margin_refuses_without_waiting() {
    let pool = one_connection_pool("iamdb_conn_spent").await;
    let started = std::time::Instant::now();
    let refused = acquire(&pool, Deadline::after(Duration::from_millis(10)))
        .await
        .err()
        .expect("no time left");
    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_millis(50));
}

/// **A CONNECTION USED ONLY FOR PLAIN STATEMENTS IS POOLED AS USUAL.** The
/// connection is closed only when its request is CANCELLED, so a request that
/// completes keeps its connection.
#[tokio::test]
async fn a_connection_used_only_for_plain_statements_is_reused() {
    let pool = one_connection_pool("iamdb_conn_plain").await;

    let first: u64 = store_work(async {
        let mut conn = acquire(&pool, Deadline::none()).await.expect("acquire");
        sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .expect("connection id")
    })
    .await;

    let mut again = tokio::time::timeout(Duration::from_secs(10), pool.acquire())
        .await
        .expect("reacquired within 10 s")
        .expect("acquire");
    let second: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
        .fetch_one(&mut *again)
        .await
        .expect("connection id");
    assert_eq!(
        first, second,
        "a plain-statement connection goes back to the pool"
    );
}

/// A TCP relay in front of the engine that can stall the server's reply part
/// way through, so a test cuts a statement at an exact byte of its reply
/// rather than at a guessed time.
struct Relay {
    addr: std::net::SocketAddr,
    /// `Some(n)`: forward the next `n` reply bytes, then hold the rest.
    stall_after: Arc<std::sync::Mutex<Option<usize>>>,
    resume: Arc<tokio::sync::Notify>,
}

impl Relay {
    async fn start(upstream: String) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind relay");
        let addr = listener.local_addr().expect("relay address");
        let stall_after = Arc::new(std::sync::Mutex::new(None::<usize>));
        let resume = Arc::new(tokio::sync::Notify::new());
        let (stall, wake) = (Arc::clone(&stall_after), Arc::clone(&resume));
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = tokio::net::TcpStream::connect(&upstream)
                    .await
                    .expect("relay reaches the engine");
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
                });
                let (stall, wake) = (Arc::clone(&stall), Arc::clone(&wake));
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = match server_read.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let left = stall.lock().expect("relay state").take();
                        let mut chunk = &buf[..n];
                        if let Some(left) = left {
                            if left < chunk.len() {
                                let (now, later) = chunk.split_at(left);
                                if client_write.write_all(now).await.is_err() {
                                    return;
                                }
                                wake.notified().await;
                                chunk = later;
                            } else {
                                *stall.lock().expect("relay state") = Some(left - chunk.len());
                            }
                        }
                        if client_write.write_all(chunk).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            stall_after,
            resume,
        }
    }
}

/// **A PLAIN STATEMENT CANCELLED MID-REPLY DOES NOT LEAK ITS POOL SLOT.**
///
/// sqlx-mysql 0.9.0's `recv_packet_part` reads a packet's 4-byte header, then
/// awaits its payload. A cancel between the two loses the header. The pool's
/// release `ping` (no timeout, sqlx-core `pool/connection.rs`) then reads
/// payload bytes `xxxx` as a header, a length of 0x787878 (7.9 MB), more than
/// is left of this 4 MB reply, and waits for ever: the slot is held until the
/// server's `wait_timeout`.
///
/// DETERMINISTIC: the [`Relay`] forwards 1.5 MB of the reply, which is part
/// way through the second row's payload, and holds the rest. The request is
/// cancelled there, the relay then forwards everything, and the next acquire on
/// this one-connection pool must succeed.
#[tokio::test]
async fn a_plain_statement_cancelled_mid_reply_does_not_leak_its_pool_slot() {
    one_connection_pool("iamdb_conn_cancel_reply").await;
    let dsn = dsn();
    let (base, _ci_database) = dsn.rsplit_once('/').expect("dsn has a database component");
    let (credentials, upstream) = base.rsplit_once('@').expect("dsn has user@host");
    let relay = Relay::start(upstream.to_string()).await;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&format!(
            "{credentials}@{}/iamdb_conn_cancel_reply",
            relay.addr
        ))
        .await
        .expect("pool through the relay");

    const ROWS: &str =
        "WITH RECURSIVE s (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 4) \
                        SELECT REPEAT('x', 1000000) FROM s";
    let work = store_work(async {
        let mut conn = acquire(&pool, Deadline::none()).await.expect("acquire");
        *relay.stall_after.lock().expect("relay state") = Some(1_500_000);
        sqlx::query_scalar::<_, String>(ROWS)
            .fetch_all(&mut *conn)
            .await
            .map(|rows| rows.len())
    });
    let cut = tokio::time::timeout(Duration::from_millis(500), work).await;
    assert!(
        cut.is_err(),
        "the relay held the reply, so the request was cut"
    );
    relay.resume.notify_one();

    let next = tokio::time::timeout(Duration::from_secs(3), pool.acquire()).await;
    assert!(
        matches!(next, Ok(Ok(_))),
        "the slot leaked: the next acquire did not get a connection in 3 s"
    );
}
