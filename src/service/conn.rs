//! Every pool acquire and every transaction start on a request path
//! (ADR-1019, yaadgaar #337). No handler runs a statement on `&self.pool`
//! directly: each one acquires a [`Conn`] here and runs its statements on it.
//!
//! Two jobs, both about a caller that gives up.
//!
//! **THE ACQUIRE IS BOUNDED BY THE CALLER'S DEADLINE.** [`IamDb::acquire`]
//! waits at most `Deadline::bound(acquire_timeout)`: the caller's remaining
//! time less `DEADLINE_MARGIN`, never more than the pool's own
//! `acquire_timeout` (the chart's `database.acquireTimeoutSeconds`). So an
//! exhausted pool makes this -db answer DEADLINE_EXCEEDED itself, before tonic
//! drops the handler at the caller's deadline. A request with no deadline
//! waits the full `acquire_timeout`, as before. The ceiling comes from the pool
//! (`PoolOptions::get_acquire_timeout`), so nothing new is configured.
//!
//! **A CONNECTION WHOSE REQUEST IS CANCELLED IS CLOSED, NOT POOLED.** tonic's
//! server drops a handler future at the caller's deadline, wherever it is
//! awaiting. sqlx 0.9.0 returns the connection to the pool after a release
//! `ping` with no timeout (sqlx-core `pool/connection.rs` `return_to_pool`),
//! and three cuts leave that connection dirty or unusable:
//!
//!   - Mid-reply on ANY statement. sqlx-mysql 0.9.0's `recv_packet_part`
//!     reads a packet's 4-byte header, then awaits its payload. A drop between
//!     the two loses the header, so the release `ping` parses payload bytes as
//!     a header and can wait for ever. The pool slot is then held until the
//!     server's `wait_timeout` (measured on MariaDB 11.8, and by review on
//!     iam-db#107: a plain statement leaks; with `close_on_drop` none does).
//!   - After `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`, before `BEGIN`.
//!     The statement applies to the session's NEXT transaction, and MariaDB
//!     11.8 keeps it pending across autocommit statements until an explicit
//!     transaction starts (measured). The next borrower's transaction then runs
//!     at READ COMMITTED without asking for it.
//!   - While `BEGIN` is in flight. sqlx's `Transaction::begin` holds the
//!     transaction with `open: true`, but `MySqlTransactionManager::begin`
//!     increments `transaction_depth` only after the server's OK arrives, and
//!     `start_rollback` does nothing at depth 0 (sqlx-mysql 0.9.0
//!     `transaction.rs`). The release `ping` flushes the queued `BEGIN` and
//!     drains its OK, so the connection goes back with an open server
//!     transaction, and the next borrower's autocommit write runs inside it
//!     and never commits. `pool.begin()` has the same window, so every
//!     transaction start goes through [`Conn::begin`].
//!
//! [`store_work`] wraps one request's store work (every `seam.rs` twin). If
//! that future is dropped before it completes, it marks the request CANCELLED
//! before its inner future, and so every [`Conn`] the work holds, is dropped.
//! A [`Conn`] dropped from a cancelled request calls
//! `PoolConnection::close_on_drop`, which makes the pool close the connection
//! instead of pinging it back into use. A request that runs to completion, Ok
//! or Err, drops its [`Conn`] while the flag is still clear, and the
//! connection goes back to the pool as before. `close_on_drop` is a one-way
//! setter, so the decision is made only in `Conn`'s own `Drop`.
//!
//! [`Conn::begin`] adds one more reason to close: it is ARMED from the start of
//! the `SET` / `BEGIN` sequence until `BEGIN` returns `Ok`, so a sequence that
//! FAILED half-way, on a request that then returns normally, does not put that
//! connection back either. Once `begin` has returned, sqlx's own drop path for
//! the transaction is sound: at depth 1 its `Drop` queues a `ROLLBACK`.
//!
//! A [`Conn`] acquired outside [`store_work`] has no request to ask, and is
//! always closed on drop: the safe default for a caller that forgot the wrap.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use sqlx::pool::PoolConnection;
use sqlx::{MySql, MySqlTransaction};
use tonic::Status;
use yadgar_dial::Deadline;

use super::{db, IamDb};

/// Which isolation level the transaction [`Conn::begin`] starts runs at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::service) enum Isolation {
    /// The session default (REPEATABLE READ on MariaDB).
    Default,
    /// READ COMMITTED for this one transaction only (ADR-0513).
    ReadCommitted,
}

tokio::task_local! {
    /// Set once the request's [`store_work`] is dropped before it completed.
    static CANCELLED: Arc<AtomicBool>;
}

/// A pooled connection that is closed, not pooled, when its request is
/// cancelled or its `SET` / `BEGIN` sequence did not finish. See the module
/// header.
pub(in crate::service) struct Conn {
    conn: PoolConnection<MySql>,
    armed: bool,
    /// The request's cancellation flag; `None` outside [`store_work`].
    cancelled: Option<Arc<AtomicBool>>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        let cancelled = self
            .cancelled
            .as_ref()
            .is_none_or(|c| c.load(Ordering::Acquire));
        if self.armed || cancelled {
            self.conn.close_on_drop();
        }
    }
}

/// One request's store work: completes as `work` does, and marks the request
/// cancelled if dropped first. See the module header.
pub(in crate::service) fn store_work<F: Future>(work: F) -> StoreWork<F> {
    let cancelled = Arc::new(AtomicBool::new(false));
    StoreWork {
        work: Box::pin(CANCELLED.scope(Arc::clone(&cancelled), work)),
        cancelled,
        done: false,
    }
}

/// The future [`store_work`] returns.
pub(in crate::service) struct StoreWork<F: Future> {
    work: Pin<Box<tokio::task::futures::TaskLocalFuture<Arc<AtomicBool>, F>>>,
    cancelled: Arc<AtomicBool>,
    done: bool,
}

impl<F: Future> Future for StoreWork<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        let out = this.work.as_mut().poll(cx);
        if out.is_ready() {
            this.done = true;
        }
        out
    }
}

impl<F: Future> Drop for StoreWork<F> {
    /// Runs BEFORE the `work` field is dropped, so every `Conn` inside it sees
    /// the flag set.
    fn drop(&mut self) {
        if !self.done {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

impl IamDb {
    /// A connection from the pool, waiting no longer than the caller can.
    ///
    /// DEADLINE_EXCEEDED when the caller's remaining time, less the margin,
    /// runs out first. UNAVAILABLE (through `db`) when the pool's own
    /// `acquire_timeout` does.
    pub(in crate::service) async fn acquire(&self, deadline: Deadline) -> Result<Conn, Status> {
        acquire(&self.pool, deadline).await
    }
}

/// [`IamDb::acquire`] for a free function that holds only the pool.
pub(in crate::service) async fn acquire(
    pool: &sqlx::MySqlPool,
    deadline: Deadline,
) -> Result<Conn, Status> {
    let ceiling = pool.options().get_acquire_timeout();
    let bound = deadline.bound(ceiling);
    if bound.is_zero() {
        return Err(out_of_time());
    }
    // NOT WRAPPED WHEN THE BOUND IS THE CEILING. The pool's own timer fires at
    // the same instant, and it is the one that means "the pool is exhausted"
    // (UNAVAILABLE) rather than "the caller ran out" (DEADLINE_EXCEEDED).
    let conn = if bound < ceiling {
        tokio::time::timeout(bound, pool.acquire())
            .await
            .map_err(|_| out_of_time())?
    } else {
        pool.acquire().await
    }
    .map_err(db)?;
    Ok(Conn {
        conn,
        armed: false,
        cancelled: CANCELLED.try_with(Arc::clone).ok(),
    })
}

fn out_of_time() -> Status {
    Status::deadline_exceeded("the caller's deadline left no time to reach the store")
}

/// The connection itself, for a plain statement outside a transaction.
impl std::ops::Deref for Conn {
    type Target = sqlx::MySqlConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for Conn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl Conn {
    /// Start a transaction at `isolation` on this connection, and disarm.
    pub(in crate::service) async fn begin(
        &mut self,
        isolation: Isolation,
    ) -> Result<MySqlTransaction<'_>, Status> {
        self.begin_after(isolation, std::future::ready(())).await
    }

    /// [`Self::begin`], awaiting `between` after the `SET TRANSACTION` and
    /// before the `BEGIN`. Production passes a ready future; the cancellation
    /// test passes one that never completes, to drop the sequence exactly in
    /// that window.
    async fn begin_after(
        &mut self,
        isolation: Isolation,
        between: impl Future<Output = ()>,
    ) -> Result<MySqlTransaction<'_>, Status> {
        let Self { conn, armed, .. } = self;
        *armed = true;
        if isolation == Isolation::ReadCommitted {
            // `SET TRANSACTION` WITHOUT `SESSION` OR `GLOBAL` applies to the
            // NEXT transaction only. That is why the statement and the
            // transaction it configures share this connection rather than
            // going through `pool.begin()`.
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut **conn)
                .await
                .map_err(db)?;
        }
        between.await;
        let tx = sqlx::Acquire::begin(&mut **conn).await.map_err(db)?;
        *armed = false;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests;
