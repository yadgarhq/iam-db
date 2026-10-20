//! `RevokeAllCredentials` (ADR-0945): every live credential one person holds,
//! tombstoned in one transaction, and how many.
//!
//! **THE STATEMENT IS NOT HERE.** It is [`revoke::all`], the one ADR-0943's
//! revoking redemption runs, so the user-row lock that makes it race-safe
//! against `CreateCredential` is the same lock in both places. This file owns
//! only what the standalone verb adds: its own transaction, the NOT_FOUND, and
//! the count.
//!
//! In a child file rather than in `credential.rs` because that file would cross
//! the 500-line ceiling with it.

use super::*;
use crate::service::enrolment::revoke;

impl IamDb {
    pub(in crate::service) async fn revoke_all(
        &self,
        r: RevokeAllCredentialsRequest,
        rid: &str,
        call: Call,
    ) -> Result<Response<RevokeAllCredentialsResponse>, Status> {
        // ADR-0534's RECORDING HALF, before anything can refuse. The target is
        // the person whose credentials are revoked.
        record_actor(
            rid,
            r.unverified_actor.as_ref(),
            "RevokeAllCredentials",
            &seg(&r.user_id),
        );

        // NOT `live_user`, which filters `deleted_at`. A soft-deleted person's
        // credentials are tombstoned and counted; only a person with no row at
        // all is NOT_FOUND (the contract's own words). `revoke::all` reads the
        // user row under its lock with no such filter, and says `None` for that
        // case before its UPDATE runs, so nothing is written.
        let mut tx = self.pool.begin().await.map_err(db)?;
        let Some(rows) = revoke::all(&mut tx, &r.user_id).await? else {
            let refusal = Status::not_found("no such user");
            call.fail(label(&refusal));
            return Err(refusal);
        };
        tx.commit().await.map_err(db)?;

        // THIS DELIVERY'S COUNT AND NOTHING ELSE. `iam-db` does not honour the
        // idempotency key (ledger 668), so a redelivery re-runs the statement
        // and reports what it changed, usually 0. The contract says so on the
        // request; zero is a success. Saturated rather than truncated: a person
        // with more than `u32::MAX` credentials is not a case, but a wrapped
        // count would be a wrong answer rather than a capped one.
        let revoked = u32::try_from(rows).unwrap_or(u32::MAX);
        call.finish(Outcome {
            status: "OK",
            rows: revoked,
            ..Default::default()
        });
        Ok(Response::new(RevokeAllCredentialsResponse {
            revoked,
            voided_enrolments: 0,
        }))
    }
}
