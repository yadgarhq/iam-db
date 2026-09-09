//! `IamDbService`, and nothing else.
//!
//! ONE MECHANICAL RULE DECIDES WHAT IS IN THIS FILE, so a reader never guesses
//! and a later change never negotiates: a trait method here turns a `Request`
//! into a `Call` and hands the work to the operation next door. What it keeps is
//! what differs per RPC and per RPC only — the name on every telemetry record,
//! D67's `Kind`, and which identity the record is scoped to. What it hands over
//! is every statement that touches the store.
//!
//! **THE `Call` IS PASSED IN RATHER THAN WRAPPED AROUND.** An operation finishes
//! or fails its own `Call`, at the point it knows the outcome, which is what lets
//! `ResolveCredential` record a miss as OK with no rows and a broken store as
//! UNAVAILABLE. A combinator round the whole operation would have to derive that
//! distinction from a return type that does not carry it.
//!
//! The operations, by module: `credential` resolves, mints, revokes and lists;
//! `password` reads and writes the stored hash; `identity` creates a person and
//! moves one in and out of a team; `policy` sets what applies to a person;
//! `enrolment` mints and spends; `setting` writes the inheritable ones.

use super::*;

#[tonic::async_trait]
impl IamDbService for IamDb {
    /// The hot path: a token hash to an identity.
    ///
    /// Called by `iam` on a cache miss, which under D72 is rare — but it is still
    /// the query that stands between every request and its answer, so it is one
    /// round trip and one index lookup.
    async fn resolve_credential(
        &self,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "ResolveCredential", Kind::Read, tel(rid, ""));
        self.resolve(r, call).await
    }

    /// Return the stored hash for `iam` to verify against.
    ///
    /// The password never comes here. `iam` hashes and compares; this service
    /// only stores. That keeps a plaintext password out of a second process and
    /// out of anything that process might log.
    async fn get_password_hash(
        &self,
        req: Request<GetPasswordHashRequest>,
    ) -> Result<Response<GetPasswordHashResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "GetPasswordHash", Kind::Read, tel(rid, ""));
        self.password_hash(r, call).await
    }

    async fn set_password(
        &self,
        req: Request<SetPasswordRequest>,
    ) -> Result<Response<SetPasswordResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "SetPassword", Kind::Write, tel(rid, &r.user_id));
        self.store_password(r, call).await
    }

    async fn create_credential(
        &self,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "CreateCredential",
            Kind::Write,
            tel(rid, &r.user_id),
        );
        self.mint_credential(r, call).await
    }

    /// Revoke, and return who it belonged to.
    ///
    /// The `user_id` is returned so the caller can publish the cache
    /// invalidation event (D72) without a second read. A revocation whose event
    /// never fires is a credential that keeps working until its TTL expires,
    /// which is the failure the whole invalidation design exists to prevent.
    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "RevokeCredential", Kind::Write, tel(rid, ""));
        self.revoke(r, call).await
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "CreateUser", Kind::Write, tel(rid, ""));
        self.insert_user(r, call).await
    }

    async fn add_team_member(
        &self,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "AddTeamMember", Kind::Write, tel(rid, &r.user_id));
        self.add_member(r, call).await
    }

    /// Removing a member changes what that user can see, so the caller MUST
    /// publish the invalidation event afterwards (D72). Until it does, a cached
    /// resolve still lists the old team and the person keeps reading its records.
    async fn remove_team_member(
        &self,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "RemoveTeamMember",
            Kind::Write,
            tel(rid, &r.user_id),
        );
        self.remove_member(r, call).await
    }

    async fn create_enrolment(
        &self,
        req: Request<CreateEnrolmentRequest>,
    ) -> Result<Response<CreateEnrolmentResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "CreateEnrolment",
            Kind::Write,
            tel(rid, &r.user_id),
        );
        self.mint_enrolment(r, call).await
    }

    async fn redeem_enrolment(
        &self,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "RedeemEnrolment", Kind::Write, tel(rid, ""));
        self.redeem(r, call).await
    }

    /// The read behind `ListCredentials`, and the only arm returning a
    /// `Credential`.
    ///
    /// A revoked row is OMITTED rather than returned with its tombstone set, so
    /// `revoked_at` is absent on every row this hands back. The tombstones stay
    /// in the store — D26 keeps "which credential was used" answerable — they
    /// are simply not this RPC's answer.
    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "ListCredentials", Kind::Read, tel(rid, &r.user_id));
        self.credential_page(r, call).await
    }

    async fn set_user_admin(
        &self,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(SERVICE, "SetUserAdmin", Kind::Write, tel(rid, &r.user_id));
        self.set_admin(r, call).await
    }

    async fn set_rate_limit_override(
        &self,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        let call = Call::start(
            SERVICE,
            "SetRateLimitOverride",
            Kind::Write,
            tel(rid, &r.user_id),
        );
        self.set_rate_limit(r, call).await
    }

    /// Write ONE LEVEL of ADR-0522's inheritable setting.
    ///
    /// **THE WRITE HALF THAT ADR-0522 SHIPPED WITHOUT.** The organisation's
    /// value, the inheritance lock and every team override were changeable only
    /// by direct SQL until this existed, which is ADR-0524's own opening
    /// sentence. The two settings tables and their `CHECK (value IN (1, 2))`
    /// constraints have been here since migrations 10 and 11; what was missing
    /// was the verb, so this adds NO migration.
    ///
    /// **IT REFUSES THE CONTRACT'S CLAUSES ITSELF.** `yadgar.common.v1.SettingScope`
    /// states the validation once and says it is binding "here rather than
    /// summarised", so `check_inherited_setting` is a full port of it rather
    /// than a trust of the caller. `iam` refuses the same clauses one hop up and
    /// that is not a reason to skip them: a storage boundary whose correctness
    /// lives in the service above it is a boundary that is correct by
    /// arrangement.
    ///
    /// **IT WRITES THE INPUTS AND NEVER THE ANSWER.** Nothing here resolves
    /// anything. The resolution depends on the team of the ROW being read and
    /// happens where the reach is computed; this module does not even know which
    /// record is being asked about.
    ///
    /// **IDEMPOTENT BY SHAPE *AND* BY A LEDGER, AND THE LEDGER IS FOR THE OTHER
    /// HALF OF D9.** The verb states what the level should BE rather than how to
    /// change it, so an identical repeat converges on the same state — that is
    /// the property `SetUserAdmin` and `SetRateLimitOverride` get by with, and it
    /// is why neither of them has a ledger. What that shape cannot do is refuse a
    /// repeated key carrying a DIFFERENT request, which D9 as amended requires
    /// and which this RPC's own contract comment enumerates the fields of.
    /// Without somewhere to remember them, an operator retrying a lost call with
    /// a corrected value gets the correction applied and no way to know which of
    /// the two took effect.
    ///
    /// So `iam_inherited_setting_write` records what was asked for, and a
    /// replayed key RE-DERIVES the setting rather than writing again. Re-running
    /// the assignment would be harmless only if nothing else had changed the
    /// level in between; if something had, it would undo that change and report
    /// success. The outcome is re-derived rather than stored because this RPC is
    /// NOT in ADR-0519's single-use-secret carve-out — the store keeps the
    /// setting, so there is nothing spent to hand back.
    ///
    /// **ONE TRANSACTION (D5), AND THE READ-BACK IS INSIDE IT.** The response
    /// carries the setting WHOLE — the other level and every other team's
    /// override — so a read outside the write's transaction could answer with a
    /// concurrent writer's half-applied state.
    async fn set_inherited_setting(
        &self,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        let rid = request_id_of(&req);
        let r = req.into_inner();
        // `tel`'s `user_id` STAYS EMPTY, and that is ADR-0534 rather than an
        // oversight. The only identity in this request is `unverified_actor`,
        // which is self-asserted; putting it where every other record in the
        // estate carries an ATTESTED `Scope.user_id` would make a dashboard join
        // an unverifiable string to a verified one.
        let call = Call::start(SERVICE, "SetInheritedSetting", Kind::Write, tel(rid, ""));
        self.store_setting(r, call).await
    }
}
