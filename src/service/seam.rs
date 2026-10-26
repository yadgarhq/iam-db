//! The `_as` twin of every `IamDbService` trait method (ledger 1629, ADR-0972).
//!
//! A trait method in `handlers` reads the caller's client-certificate name
//! before the request is consumed, then calls its twin here. The twin opens the
//! `Call` as its FIRST statement, so the record exists on every path, passes the
//! `Call` through the caller gate (`caller::admitted`) before any store work,
//! and only then consumes the request and hands it to the operation.
//!
//! A test drives the twin with the name it means. Only the gate tests drive the
//! trait method itself, which is how the rest of the suite keeps reaching the
//! store without a TLS handshake and without a test-only bypass in the gate.

use super::*;

impl IamDb {
    /// `resolve_credential` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn resolve_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "ResolveCredential",
            Kind::Read,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.resolve(r, deadline, call)).await
    }

    /// `get_password_hash` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn get_password_hash_as(
        &self,
        caller: Option<&str>,
        req: Request<GetPasswordHashRequest>,
    ) -> Result<Response<GetPasswordHashResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "GetPasswordHash",
            Kind::Read,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.password_hash(r, deadline, call)).await
    }

    /// `set_password` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn set_password_as(
        &self,
        caller: Option<&str>,
        req: Request<SetPasswordRequest>,
    ) -> Result<Response<SetPasswordResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetPassword",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.store_password(r, deadline, call)).await
    }

    /// `create_credential` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn create_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "CreateCredential",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.mint_credential(r, deadline, &rid, call)).await
    }

    /// `revoke_credential` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn revoke_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RevokeCredential",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.revoke(r, deadline, &rid, call)).await
    }

    /// `revoke_all_credentials` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn revoke_all_credentials_as(
        &self,
        caller: Option<&str>,
        req: Request<RevokeAllCredentialsRequest>,
    ) -> Result<Response<RevokeAllCredentialsResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RevokeAllCredentials",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.revoke_all(r, deadline, &rid, call)).await
    }

    /// `create_user` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn create_user_as(
        &self,
        caller: Option<&str>,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "CreateUser",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.insert_user(r, deadline, &rid, call)).await
    }

    /// `add_team_member` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn add_team_member_as(
        &self,
        caller: Option<&str>,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "AddTeamMember",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let r = req.into_inner();
        conn::store_work(self.add_member(r, &rid, call)).await
    }

    /// `remove_team_member` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn remove_team_member_as(
        &self,
        caller: Option<&str>,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RemoveTeamMember",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let r = req.into_inner();
        conn::store_work(self.remove_member(r, &rid, call)).await
    }

    /// `create_enrolment` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn create_enrolment_as(
        &self,
        caller: Option<&str>,
        req: Request<CreateEnrolmentRequest>,
    ) -> Result<Response<CreateEnrolmentResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "CreateEnrolment",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.mint_enrolment(r, deadline, &rid, call)).await
    }

    /// `redeem_enrolment` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn redeem_enrolment_as(
        &self,
        caller: Option<&str>,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RedeemEnrolment",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.redeem(r, deadline, call)).await
    }

    /// `list_credentials` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn list_credentials_as(
        &self,
        caller: Option<&str>,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "ListCredentials",
            Kind::Read,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.credential_page(r, deadline, call)).await
    }

    /// `set_user_admin` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn set_user_admin_as(
        &self,
        caller: Option<&str>,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetUserAdmin",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.set_admin(r, deadline, &rid, call)).await
    }

    /// `set_rate_limit_override` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn set_rate_limit_override_as(
        &self,
        caller: Option<&str>,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetRateLimitOverride",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.set_rate_limit(r, deadline, &rid, call)).await
    }

    /// `set_inherited_setting` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn set_inherited_setting_as(
        &self,
        caller: Option<&str>,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        // `tel`'s `user_id` STAYS EMPTY, and that is ADR-0534 rather than an
        // oversight. The only identity in this request is `unverified_actor`,
        // which is self-asserted; putting it where every other record in the
        // estate carries an ATTESTED `Scope.user_id` would make a dashboard join
        // an unverifiable string to a verified one.
        let call = Call::start(
            SERVICE,
            "SetInheritedSetting",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let rid = request_id_of(&req);
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.store_setting(r, deadline, &rid, call)).await
    }

    /// `sync_teams` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn sync_teams_as(
        &self,
        caller: Option<&str>,
        req: Request<SyncTeamsRequest>,
    ) -> Result<Response<SyncTeamsResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SyncTeams",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.sync_teams(r, deadline, call)).await
    }

    /// `get_key_identity` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn get_key_identity_as(
        &self,
        caller: Option<&str>,
        req: Request<GetKeyIdentityRequest>,
    ) -> Result<Response<GetKeyIdentityResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "GetKeyIdentity",
            Kind::Read,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.key_identity(r, deadline, call)).await
    }

    /// `set_key_identity` as the named `caller`, through the gate in `caller::admitted`.
    pub async fn set_key_identity_as(
        &self,
        caller: Option<&str>,
        req: Request<SetKeyIdentityRequest>,
    ) -> Result<Response<SetKeyIdentityResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetKeyIdentity",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        let deadline = Deadline::of(&req);
        let r = req.into_inner();
        conn::store_work(self.store_key_identity(r, deadline, call)).await
    }
}
