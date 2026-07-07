use super::*;
use crate::device::*;
use crate::iam::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionBootstrapRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub observed_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub session: VerifiedOidcSession,
    pub device_ref: Option<DeviceRef>,
    pub app_attest_assertion: Option<VerifiedAppAttestAssertion>,
    pub assurance_policy: OidcAssurancePolicy,
}

impl AccountSessionBootstrapRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        authored_by: Author,
        observed_at: Timestamp,
        session: VerifiedOidcSession,
        device_ref: Option<DeviceRef>,
        assurance_policy: OidcAssurancePolicy,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        let fact_count = account_session_bootstrap_fact_count(&session);
        Self {
            subject_id,
            authored_by,
            observed_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, fact_count),
            session,
            device_ref,
            app_attest_assertion: None,
            assurance_policy,
        }
    }

    pub fn with_generated_ids_and_app_attest(
        subject_id: SubjectId,
        authored_by: Author,
        observed_at: Timestamp,
        session: VerifiedOidcSession,
        app_attest_assertion: VerifiedAppAttestAssertion,
        assurance_policy: OidcAssurancePolicy,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        let fact_count = account_session_bootstrap_fact_count_with_device(&session, true);
        Self {
            subject_id,
            authored_by,
            observed_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, fact_count),
            session,
            device_ref: Some(app_attest_assertion.device_ref.clone()),
            app_attest_assertion: Some(app_attest_assertion),
            assurance_policy,
        }
    }

    pub fn fixture(subject_id: SubjectId, authored_by: Author, observed_at: Timestamp) -> Self {
        let session = VerifiedOidcSession::keycloak(
            "https://id.example.test/realms/fen",
            "keycloak-user-123",
            "fen-identity",
            "keycloak-session-123",
            Timestamp("2026-05-29T00:00:00Z".to_string()),
            Timestamp("2026-05-29T01:00:00Z".to_string()),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("patient@example.test");

        Self {
            subject_id,
            authored_by,
            observed_at,
            id_plan: WorkflowIdPlan::deterministic(
                "account-session",
                ProblemEpisodeId("episode-account-session".to_string()),
                account_session_bootstrap_fact_count(&session),
            ),
            session,
            device_ref: Some("iphone-passkey-device".to_string()),
            app_attest_assertion: None,
            assurance_policy: OidcAssurancePolicy::default(),
        }
    }
}

pub fn account_session_bootstrap_fact_count(session: &VerifiedOidcSession) -> usize {
    account_session_bootstrap_fact_count_with_device(session, false)
}

pub fn account_session_bootstrap_fact_count_with_device(
    session: &VerifiedOidcSession,
    has_device_attestation: bool,
) -> usize {
    let mut count = if session.verified_email().is_some() {
        3
    } else {
        2
    };
    if has_device_attestation {
        count += 1;
    }
    count
}

pub fn account_session_bootstrap_slice_from_request(
    request: AccountSessionBootstrapRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let subject_id = request.subject_id.clone();
    let episode = identity_provider_account_episode(
        request.id_plan.episode_id.clone(),
        subject_id.clone(),
        request.authored_by.clone(),
        request.observed_at.clone(),
        request.session.provider_name.clone(),
    );
    let source_system = Some(request.session.source_system());
    let external_refs = request.session.identity_provider_external_refs();
    let credential_evidence = request.assurance_policy.classify(&request.session);

    let mut credential = translator.credential_assertion(
        subject_id.clone(),
        request.observed_at.clone(),
        credential_evidence.authenticator_type,
        request.device_ref,
        CredentialAssertionResult::Succeeded,
        credential_evidence.assurance_level,
        source_system.clone(),
    );
    credential.external_refs = external_refs.clone();

    let mut portal_witness = translator.identity_witness_recorded(
        subject_id.clone(),
        request.observed_at.clone(),
        IdentityWitnessType::PatientPortalLoginProof,
        subject_id.clone(),
        credential_evidence.assurance_level,
        None,
        Some(request.session.expires_at.clone()),
        source_system.clone(),
    );
    portal_witness.external_refs = external_refs.clone();

    let mut drafts = vec![credential, portal_witness];
    let mut roles = vec![FactRole::IdentityWitness, FactRole::IdentityWitness];

    if let Some(email) = request.session.verified_email() {
        let mut email_attribute = translator.identity_attribute_asserted(
            subject_id.clone(),
            request.observed_at.clone(),
            IdentityAttribute::Email,
            IdentityAttributeValue::StringValue(email.to_string()),
            MatchConfidence::Medium,
            source_system,
        );
        email_attribute.external_refs = external_refs;
        drafts.push(email_attribute);
        roles.push(FactRole::IdentityWitness);
    }

    if let Some(app_attest_assertion) = request.app_attest_assertion {
        let source_system = app_attest_assertion.source_system();
        let external_refs = app_attest_assertion.external_refs();
        let mut device_binding = translator.device_binding_established(
            subject_id,
            request.observed_at.clone(),
            app_attest_assertion.device_ref,
            AuthenticatorType::Other("apple_app_attest".to_string()),
            app_attest_assertion.assurance_level,
            Some(source_system),
        );
        device_binding.external_refs = external_refs;
        drafts.push(device_binding);
        roles.push(FactRole::DeviceBinding);
    }

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        roles,
        request.authored_by,
        request.observed_at,
        &request.id_plan,
    )
}

pub fn identity_provider_account_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
    provider_name: String,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::IdentityVerificationWorkflow,
        label: format!("{provider_name} account session"),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: Some("Identity provider login evidence; not a source of identity truth".to_string()),
    }
}
