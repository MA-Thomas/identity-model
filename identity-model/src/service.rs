use crate::continuity::*;
use crate::device::*;
use crate::fen::*;
use crate::flows::*;
use crate::iam::*;
use crate::identity::*;
use crate::ids::*;
use crate::materialized::*;
use crate::persistence::*;
use crate::policy::*;
use crate::provider::*;
use crate::translation::*;
use crate::workflows::*;

mod outcomes;
use outcomes::{
    fact_ids_matching, first_fact_id_matching, required_fact_id_matching, workflow_outcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityWorkflowService {
    pub translator: FenTranslator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowOutcome {
    pub slice: IdentityWorkflowSlice,
    pub projection: MaterializedIdentityState,
    pub narrative: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryBackedWorkflowOutcome {
    pub workflow: WorkflowOutcome,
    pub replayed_projection: MaterializedIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryBackedCoreIdentityOnboardingOutcome {
    pub onboarding: CoreIdentityOnboardingOutcome,
    pub replayed_projection: MaterializedIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryBackedAccountSessionBootstrapOutcome {
    pub bootstrap: AccountSessionBootstrapOutcome,
    pub replayed_projection: MaterializedIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreIdentityOnboardingRequest {
    pub subject_id: Option<SubjectId>,
    pub subject_id_prefix: String,
    pub id_namespace: String,
    pub authored_by: Author,
    pub registered_at: Timestamp,
    pub device_bound_at: Timestamp,
    pub continuity_enrolled_at: Timestamp,
    pub subject_kind: SubjectKind,
    pub stable_profile: StableIdentityProfile,
    pub device_ref: DeviceRef,
    pub authenticator_type: AuthenticatorType,
    pub device_assurance_level: AssuranceLevel,
    pub device_source_system: Option<String>,
    pub modality: BiometricModality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreIdentityOnboardingOutcome {
    pub subject_id: SubjectId,
    pub parent_episode: ProblemEpisode,
    pub registration: SubjectRegistrationOutcome,
    pub device_binding: DeviceBindingOutcome,
    pub continuity_enrollment: ContinuityEnrollmentOutcome,
    pub episode_relations: Vec<EpisodeRelation>,
    pub projection: MaterializedIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionBootstrapOutcome {
    pub workflow: WorkflowOutcome,
    pub credential_fact_id: FactId,
    pub portal_login_witness_fact_id: FactId,
    pub verified_email_attribute_fact_id: Option<FactId>,
    pub device_binding_fact_id: Option<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTokenBootstrapRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub observed_at: Timestamp,
    pub id_namespace: String,
    pub token: String,
    pub oidc_config: OidcClientConfig,
    pub device_ref: Option<DeviceRef>,
    pub assurance_policy: OidcAssurancePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTokenWithAppAttestBootstrapRequest {
    pub account: AccountTokenBootstrapRequest,
    pub app_attest: AppAttestAssertionVerificationRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTokenBootstrapError {
    Verification(OidcSessionVerificationError),
    Repository(RepositoryError),
}

impl From<OidcSessionVerificationError> for AccountTokenBootstrapError {
    fn from(error: OidcSessionVerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<RepositoryError> for AccountTokenBootstrapError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTokenWithAppAttestBootstrapError {
    Verification(OidcSessionVerificationError),
    AppAttest(AppAttestAssertionVerificationError),
    DeviceRefMismatch,
    Repository(RepositoryError),
}

impl From<OidcSessionVerificationError> for AccountTokenWithAppAttestBootstrapError {
    fn from(error: OidcSessionVerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<AppAttestAssertionVerificationError> for AccountTokenWithAppAttestBootstrapError {
    fn from(error: AppAttestAssertionVerificationError) -> Self {
        Self::AppAttest(error)
    }
}

impl From<RepositoryError> for AccountTokenWithAppAttestBootstrapError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAuthorizationOutcome {
    pub workflow: WorkflowOutcome,
    pub policy_evaluation: PolicyEvaluation,
    pub access_decision_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingOutcome {
    pub workflow: WorkflowOutcome,
    pub subject_fact_id: FactId,
    pub device_binding_fact_id: FactId,
    pub identity_witness_fact_id: FactId,
    pub enrollment_fact_id: FactId,
    pub clinical_link_fact_id: FactId,
    pub payer_link_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectRegistrationOutcome {
    pub workflow: WorkflowOutcome,
    pub subject_id: SubjectId,
    pub subject_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBindingOutcome {
    pub workflow: WorkflowOutcome,
    pub device_binding_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityEnrollmentOutcome {
    pub workflow: WorkflowOutcome,
    pub enrollment_fact_id: FactId,
    pub enrollment_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentityLinkOutcome {
    pub workflow: WorkflowOutcome,
    pub provider_link_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayerIdentityLinkOutcome {
    pub workflow: WorkflowOutcome,
    pub payer_link_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub workflow: WorkflowOutcome,
    pub path: RecoveryPath,
    pub recovery_event_fact_ids: Vec<FactId>,
    pub access_decision_fact_id: Option<FactId>,
    pub device_revocation_fact_ids: Vec<FactId>,
    pub device_establishment_fact_ids: Vec<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationOutcome {
    pub workflow: WorkflowOutcome,
    pub authority_fact_id: Option<FactId>,
    pub access_decision_fact_id: Option<FactId>,
    pub revocation_fact_id: Option<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDisputeOutcome {
    pub workflow: WorkflowOutcome,
    pub kind: IdentityDisputeResolutionKind,
    pub dispute_evidence_fact_ids: Vec<FactId>,
    pub institutional_link_fact_ids: Vec<FactId>,
    pub subject_graph_correction_fact_id: Option<FactId>,
    pub witness_supersession_fact_id: Option<FactId>,
    pub access_decision_fact_id: Option<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityChallengeRequest {
    pub challenge_id: ChallengeId,
    pub subject_id: SubjectId,
    pub enrollment_ref: String,
    pub nonce: Nonce,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub intended_action: Option<SensitiveAction>,
}

impl ContinuityChallengeRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        enrollment_ref: String,
        issued_at: Timestamp,
        expires_at: Timestamp,
        intended_action: Option<SensitiveAction>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            challenge_id: id_generator.next_challenge_id(&format!("challenge-{id_namespace}")),
            subject_id,
            enrollment_ref,
            nonce: id_generator
                .next_fact_id(&format!("nonce-{id_namespace}"))
                .0,
            issued_at,
            expires_at,
            intended_action,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityAssertionVerificationAuditRequest {
    pub subject_id: SubjectId,
    pub rejected_fact_id: FactId,
    pub verified_at: Timestamp,
}

impl ContinuityAssertionVerificationAuditRequest {
    pub fn with_generated_id(
        subject_id: SubjectId,
        verified_at: Timestamp,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            rejected_fact_id: id_generator.next_fact_id(&format!("fact-{id_namespace}")),
            verified_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityAssertionVerificationOutcome {
    pub verification: ContinuityAssertionVerificationResult,
    pub rejection_fact: Option<Fact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveActionEvaluationRequest {
    pub policy: ActionPolicy,
    pub evidence: EvidenceSummary,
    pub context: PolicyEvaluationContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveActionPolicyArtifactEvaluationRequest {
    pub policy_artifact: PolicyArtifact,
    pub evidence: EvidenceSummary,
    pub context: PolicyEvaluationContext,
}

impl IdentityWorkflowService {
    pub fn new(translator: FenTranslator) -> Self {
        Self { translator }
    }

    pub fn append_workflow_and_replay(
        &self,
        workflow: WorkflowOutcome,
        repository: &mut impl IdentityWorkflowRepository,
    ) -> Result<RepositoryBackedWorkflowOutcome, RepositoryError> {
        let subject_id = workflow.slice.episode.subject_id.clone();
        repository.append_workflow_slice(workflow.slice.clone())?;
        let replayed_projection = replay_identity_state_from_repository(subject_id, repository);

        Ok(RepositoryBackedWorkflowOutcome {
            workflow,
            replayed_projection,
        })
    }

    pub fn append_core_onboarding_and_replay(
        &self,
        onboarding: CoreIdentityOnboardingOutcome,
        repository: &mut impl IdentityWorkflowRepository,
    ) -> Result<RepositoryBackedCoreIdentityOnboardingOutcome, RepositoryError> {
        let subject_id = onboarding.subject_id.clone();
        repository.append_episode_composition(
            onboarding.parent_episode.clone(),
            vec![
                onboarding.registration.workflow.slice.clone(),
                onboarding.device_binding.workflow.slice.clone(),
                onboarding.continuity_enrollment.workflow.slice.clone(),
            ],
            onboarding.episode_relations.clone(),
        )?;
        let replayed_projection = replay_identity_state_from_repository(subject_id, repository);

        Ok(RepositoryBackedCoreIdentityOnboardingOutcome {
            onboarding,
            replayed_projection,
        })
    }

    pub fn enroll_subject(
        &self,
        request: OnboardingRequest,
        provider: &impl ContinuityVaultProvider,
    ) -> Result<WorkflowOutcome, VerticalSliceError> {
        let subject_id = request.subject_id.clone();
        let slice = onboarding_vertical_slice_from_request(request, provider, &self.translator)?;
        Ok(workflow_outcome(subject_id, slice))
    }

    pub fn enroll_subject_detailed(
        &self,
        request: OnboardingRequest,
        provider: &impl ContinuityVaultProvider,
    ) -> Result<OnboardingOutcome, VerticalSliceError> {
        let workflow = self.enroll_subject(request, provider)?;

        Ok(OnboardingOutcome {
            subject_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::SubjectCreated { .. })
            }),
            device_binding_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::DeviceBindingEstablished { .. })
            }),
            identity_witness_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::IdentityWitnessRecorded { .. })
            }),
            enrollment_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::BiometricEnrollmentReferenceAdded { .. }
                )
            }),
            clinical_link_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::ClinicalIdentityLinkEstablished { .. })
            }),
            payer_link_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::PayerIdentityLinkEstablished { .. })
            }),
            workflow,
        })
    }

    pub fn onboard_core_identity(
        &self,
        request: CoreIdentityOnboardingRequest,
        provider: &impl ContinuityVaultProvider,
        id_generator: &mut impl IdGenerator,
    ) -> Result<CoreIdentityOnboardingOutcome, VerticalSliceError> {
        let subject_id = request
            .subject_id
            .unwrap_or_else(|| id_generator.next_subject_id(&request.subject_id_prefix));
        let register_namespace = format!("{}-register-subject", request.id_namespace);
        let device_namespace = format!("{}-bind-device", request.id_namespace);
        let continuity_namespace = format!("{}-enroll-continuity", request.id_namespace);
        let relation_namespace = format!("relation-{}", request.id_namespace);
        let parent_episode = parent_onboarding_episode(
            id_generator.next_episode_id(&format!("episode-{}-parent", request.id_namespace)),
            subject_id.clone(),
            request.authored_by.clone(),
            request.registered_at.clone(),
        );

        let registration = self.register_subject(RegisterSubjectRequest::with_generated_ids(
            subject_id.clone(),
            request.authored_by.clone(),
            request.registered_at,
            request.subject_kind,
            request.stable_profile,
            &register_namespace,
            id_generator,
        ));
        let device_binding = self.bind_device(BindDeviceRequest::with_generated_ids(
            subject_id.clone(),
            request.authored_by.clone(),
            request.device_bound_at,
            request.device_ref,
            request.authenticator_type,
            request.device_assurance_level,
            request.device_source_system,
            &device_namespace,
            id_generator,
        ));
        let continuity_enrollment = self.enroll_continuity_reference(
            EnrollContinuityRequest::with_generated_ids(
                subject_id.clone(),
                request.authored_by.clone(),
                request.continuity_enrolled_at,
                request.modality,
                &continuity_namespace,
                id_generator,
            ),
            provider,
        )?;
        let episode_relations = vec![
            episode_relation(
                id_generator.next_relation_id(&relation_namespace),
                registration.workflow.slice.episode.id.clone(),
                parent_episode.id.clone(),
                EpisodeRelationType::PartOf,
                request.authored_by.clone(),
                registration.workflow.slice.episode.authored_at.clone(),
            ),
            episode_relation(
                id_generator.next_relation_id(&relation_namespace),
                device_binding.workflow.slice.episode.id.clone(),
                parent_episode.id.clone(),
                EpisodeRelationType::PartOf,
                request.authored_by.clone(),
                device_binding.workflow.slice.episode.authored_at.clone(),
            ),
            episode_relation(
                id_generator.next_relation_id(&relation_namespace),
                continuity_enrollment.workflow.slice.episode.id.clone(),
                parent_episode.id.clone(),
                EpisodeRelationType::PartOf,
                request.authored_by,
                continuity_enrollment
                    .workflow
                    .slice
                    .episode
                    .authored_at
                    .clone(),
            ),
        ];

        let mut facts = Vec::new();
        facts.extend(registration.workflow.slice.facts.clone());
        facts.extend(device_binding.workflow.slice.facts.clone());
        facts.extend(continuity_enrollment.workflow.slice.facts.clone());
        let projection = materialize_identity_state(subject_id.clone(), &facts);

        Ok(CoreIdentityOnboardingOutcome {
            subject_id,
            parent_episode,
            registration,
            device_binding,
            continuity_enrollment,
            episode_relations,
            projection,
        })
    }

    pub fn register_subject(&self, request: RegisterSubjectRequest) -> SubjectRegistrationOutcome {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id.clone(),
            register_subject_slice_from_request(request, &self.translator),
        );
        let subject_fact_id = first_fact_id_matching(&workflow.slice, |payload| {
            matches!(payload, FactPayload::SubjectCreated { .. })
        })
        .expect("subject registration workflow should include a SubjectCreated fact");

        SubjectRegistrationOutcome {
            workflow,
            subject_id,
            subject_fact_id,
        }
    }

    pub fn register_new_subject(
        &self,
        request: RegisterNewSubjectRequest,
        id_generator: &mut impl IdGenerator,
    ) -> SubjectRegistrationOutcome {
        let subject_id = id_generator.next_subject_id(&request.subject_id_prefix);
        self.register_subject(RegisterSubjectRequest::with_generated_ids(
            subject_id,
            request.authored_by,
            request.started_at,
            request.subject_kind,
            request.stable_profile,
            &request.id_namespace,
            id_generator,
        ))
    }

    pub fn bind_device(&self, request: BindDeviceRequest) -> DeviceBindingOutcome {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id,
            bind_device_slice_from_request(request, &self.translator),
        );
        let device_binding_fact_id = first_fact_id_matching(&workflow.slice, |payload| {
            matches!(payload, FactPayload::DeviceBindingEstablished { .. })
        })
        .expect("device binding workflow should include a DeviceBindingEstablished fact");

        DeviceBindingOutcome {
            workflow,
            device_binding_fact_id,
        }
    }

    pub fn accept_account_session(
        &self,
        request: AccountSessionBootstrapRequest,
    ) -> AccountSessionBootstrapOutcome {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id,
            account_session_bootstrap_slice_from_request(request, &self.translator),
        );

        AccountSessionBootstrapOutcome {
            credential_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::CredentialAssertion { .. })
            }),
            portal_login_witness_fact_id: required_fact_id_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::IdentityWitnessRecorded {
                        witness_type: IdentityWitnessType::PatientPortalLoginProof,
                        ..
                    }
                )
            }),
            verified_email_attribute_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::IdentityAttributeAsserted {
                        attribute: IdentityAttribute::Email,
                        ..
                    }
                )
            }),
            device_binding_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::DeviceBindingEstablished { .. })
            }),
            workflow,
        }
    }

    pub fn accept_account_token(
        &self,
        request: AccountTokenBootstrapRequest,
        verifier: &impl OidcSessionVerifier,
        id_generator: &mut impl IdGenerator,
    ) -> Result<AccountSessionBootstrapOutcome, AccountTokenBootstrapError> {
        let session =
            verifier.verify_session(&request.token, &request.oidc_config, &request.observed_at)?;

        Ok(
            self.accept_account_session(AccountSessionBootstrapRequest::with_generated_ids(
                request.subject_id,
                request.authored_by,
                request.observed_at,
                session,
                request.device_ref,
                request.assurance_policy,
                &request.id_namespace,
                id_generator,
            )),
        )
    }

    pub fn accept_account_token_with_app_attest(
        &self,
        request: AccountTokenWithAppAttestBootstrapRequest,
        verifier: &impl OidcSessionVerifier,
        app_attest_verifier: &impl AppAttestAssertionVerifier,
        id_generator: &mut impl IdGenerator,
    ) -> Result<AccountSessionBootstrapOutcome, AccountTokenWithAppAttestBootstrapError> {
        let session = verifier.verify_session(
            &request.account.token,
            &request.account.oidc_config,
            &request.account.observed_at,
        )?;
        let app_attest_assertion = app_attest_verifier
            .verify_app_attest_assertion(&request.app_attest, &request.account.observed_at)?;
        if request
            .account
            .device_ref
            .as_ref()
            .is_some_and(|device_ref| device_ref != &app_attest_assertion.device_ref)
        {
            return Err(AccountTokenWithAppAttestBootstrapError::DeviceRefMismatch);
        }

        Ok(self.accept_account_session(
            AccountSessionBootstrapRequest::with_generated_ids_and_app_attest(
                request.account.subject_id,
                request.account.authored_by,
                request.account.observed_at,
                session,
                app_attest_assertion,
                request.account.assurance_policy,
                &request.account.id_namespace,
                id_generator,
            ),
        ))
    }

    pub fn accept_account_token_with_app_attest_append_and_replay(
        &self,
        request: AccountTokenWithAppAttestBootstrapRequest,
        verifier: &impl OidcSessionVerifier,
        app_attest_verifier: &impl AppAttestAssertionVerifier,
        id_generator: &mut impl IdGenerator,
        repository: &mut impl IdentityWorkflowRepository,
    ) -> Result<
        RepositoryBackedAccountSessionBootstrapOutcome,
        AccountTokenWithAppAttestBootstrapError,
    > {
        let bootstrap = self.accept_account_token_with_app_attest(
            request,
            verifier,
            app_attest_verifier,
            id_generator,
        )?;
        let subject_id = bootstrap.workflow.slice.episode.subject_id.clone();
        repository.append_workflow_slice(bootstrap.workflow.slice.clone())?;
        let replayed_projection = replay_identity_state_from_repository(subject_id, repository);

        Ok(RepositoryBackedAccountSessionBootstrapOutcome {
            bootstrap,
            replayed_projection,
        })
    }

    pub fn accept_account_token_append_and_replay(
        &self,
        request: AccountTokenBootstrapRequest,
        verifier: &impl OidcSessionVerifier,
        id_generator: &mut impl IdGenerator,
        repository: &mut impl IdentityWorkflowRepository,
    ) -> Result<RepositoryBackedAccountSessionBootstrapOutcome, AccountTokenBootstrapError> {
        let bootstrap = self.accept_account_token(request, verifier, id_generator)?;
        let subject_id = bootstrap.workflow.slice.episode.subject_id.clone();
        repository.append_workflow_slice(bootstrap.workflow.slice.clone())?;
        let replayed_projection = replay_identity_state_from_repository(subject_id, repository);

        Ok(RepositoryBackedAccountSessionBootstrapOutcome {
            bootstrap,
            replayed_projection,
        })
    }

    pub fn enroll_continuity_reference(
        &self,
        request: EnrollContinuityRequest,
        provider: &impl ContinuityVaultProvider,
    ) -> Result<ContinuityEnrollmentOutcome, VerticalSliceError> {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id,
            enroll_continuity_slice_from_request(request, provider, &self.translator)?,
        );
        let (enrollment_fact_id, enrollment_ref) = workflow
            .slice
            .facts
            .iter()
            .find_map(|fact| match &fact.payload {
                FactPayload::BiometricEnrollmentReferenceAdded { enrollment_ref, .. } => {
                    Some((fact.id.clone(), enrollment_ref.clone()))
                }
                _ => None,
            })
            .expect(
                "continuity enrollment workflow should include a BiometricEnrollmentReferenceAdded fact",
            );

        Ok(ContinuityEnrollmentOutcome {
            workflow,
            enrollment_fact_id,
            enrollment_ref,
        })
    }

    pub fn link_provider_identity(
        &self,
        request: LinkProviderIdentityRequest,
    ) -> ProviderIdentityLinkOutcome {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id,
            link_provider_identity_slice_from_request(request, &self.translator),
        );
        let provider_link_fact_id = first_fact_id_matching(&workflow.slice, |payload| {
            matches!(payload, FactPayload::ClinicalIdentityLinkEstablished { .. })
        })
        .expect(
            "provider identity link workflow should include a ClinicalIdentityLinkEstablished fact",
        );

        ProviderIdentityLinkOutcome {
            workflow,
            provider_link_fact_id,
        }
    }

    pub fn link_payer_identity(
        &self,
        request: LinkPayerIdentityRequest,
    ) -> PayerIdentityLinkOutcome {
        let subject_id = request.subject_id.clone();
        let workflow = workflow_outcome(
            subject_id,
            link_payer_identity_slice_from_request(request, &self.translator),
        );
        let payer_link_fact_id = first_fact_id_matching(&workflow.slice, |payload| {
            matches!(payload, FactPayload::PayerIdentityLinkEstablished { .. })
        })
        .expect("payer identity link workflow should include a PayerIdentityLinkEstablished fact");

        PayerIdentityLinkOutcome {
            workflow,
            payer_link_fact_id,
        }
    }

    pub fn authorize_complete_record_export_step_up(
        &self,
        request: CompleteRecordExportStepUpRequest,
        provider: &impl ContinuityVaultProvider,
        nonce_lifecycle: &mut InMemoryNonceLifecycle,
        signature_verifier: &impl ContinuitySignatureVerifier,
        assurance_mapper: &impl ContinuityAssuranceMapper,
    ) -> Result<WorkflowOutcome, VerticalSliceError> {
        let subject_id = request.subject_id.clone();
        let slice = complete_record_export_step_up_slice_from_request(
            request,
            provider,
            nonce_lifecycle,
            signature_verifier,
            assurance_mapper,
            &self.translator,
        )?;
        Ok(workflow_outcome(subject_id, slice))
    }

    pub fn authorize_complete_record_export_step_up_detailed(
        &self,
        request: CompleteRecordExportStepUpRequest,
        provider: &impl ContinuityVaultProvider,
        nonce_lifecycle: &mut InMemoryNonceLifecycle,
        signature_verifier: &impl ContinuitySignatureVerifier,
        assurance_mapper: &impl ContinuityAssuranceMapper,
    ) -> Result<AccessAuthorizationOutcome, VerticalSliceError> {
        let subject_id = request.subject_id.clone();
        let outcome = complete_record_export_step_up_outcome_from_request(
            request,
            provider,
            nonce_lifecycle,
            signature_verifier,
            assurance_mapper,
            &self.translator,
        )?;

        Ok(AccessAuthorizationOutcome {
            workflow: workflow_outcome(subject_id, outcome.slice),
            policy_evaluation: outcome.policy_evaluation,
            access_decision_fact_id: outcome.access_decision_fact_id,
        })
    }

    pub fn recover_account(&self, request: RecoveryRequest) -> WorkflowOutcome {
        let subject_id = request.subject_id.clone();
        workflow_outcome(
            subject_id,
            recovery_slice_from_request(request, &self.translator),
        )
    }

    pub fn recover_account_detailed(&self, request: RecoveryRequest) -> RecoveryOutcome {
        let path = request.path;
        let workflow = self.recover_account(request);

        RecoveryOutcome {
            recovery_event_fact_ids: fact_ids_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::AccountRecoveryEvent { .. })
            }),
            access_decision_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::AccessDecision { .. })
            }),
            device_revocation_fact_ids: fact_ids_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::DeviceBindingRevoked { .. })
            }),
            device_establishment_fact_ids: fact_ids_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::DeviceBindingEstablished { .. })
            }),
            workflow,
            path,
        }
    }

    pub fn delegate_authority(&self, request: DelegationRequest) -> WorkflowOutcome {
        let subject_id = request.target_subject_id.clone();
        workflow_outcome(
            subject_id,
            delegation_vertical_slice_from_request(request, &self.translator),
        )
    }

    pub fn delegate_authority_detailed(&self, request: DelegationRequest) -> DelegationOutcome {
        let workflow = self.delegate_authority(request);

        DelegationOutcome {
            authority_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::AuthorityRelationshipEstablished { .. }
                )
            }),
            access_decision_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::AccessDecision { .. })
            }),
            revocation_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::AuthorityRelationshipRevoked { .. })
            }),
            workflow,
        }
    }

    pub fn resolve_identity_dispute(
        &self,
        request: IdentityDisputeResolutionRequest,
    ) -> WorkflowOutcome {
        let subject_id = request.subject_id.clone();
        workflow_outcome(
            subject_id,
            identity_dispute_resolution_slice_from_request(request, &self.translator),
        )
    }

    pub fn resolve_identity_dispute_detailed(
        &self,
        request: IdentityDisputeResolutionRequest,
    ) -> IdentityDisputeOutcome {
        let kind = request.kind.clone();
        let workflow = self.resolve_identity_dispute(request);

        IdentityDisputeOutcome {
            dispute_evidence_fact_ids: fact_ids_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::ClinicalIdentityLinkContested { .. }
                        | FactPayload::PayerIdentityLinkContested { .. }
                        | FactPayload::ClinicalIdentityLinkDisputeResolved { .. }
                        | FactPayload::PayerIdentityLinkDisputeResolved { .. }
                        | FactPayload::IdentityWitnessRecorded { .. }
                        | FactPayload::IdentityWitnessSuperseded { .. }
                )
            }),
            institutional_link_fact_ids: fact_ids_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::ClinicalIdentityLinkEstablished { .. }
                        | FactPayload::PayerIdentityLinkEstablished { .. }
                )
            }),
            subject_graph_correction_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(
                    payload,
                    FactPayload::DuplicateSubjectMergeRecorded { .. }
                        | FactPayload::IncorrectMergeSplitRecorded { .. }
                )
            }),
            witness_supersession_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::IdentityWitnessSuperseded { .. })
            }),
            access_decision_fact_id: first_fact_id_matching(&workflow.slice, |payload| {
                matches!(payload, FactPayload::AccessDecision { .. })
            }),
            workflow,
            kind,
        }
    }

    pub fn issue_continuity_challenge(
        &self,
        request: ContinuityChallengeRequest,
        nonce_lifecycle: &mut InMemoryNonceLifecycle,
    ) -> Result<ContinuityChallenge, ContinuityAssertionRejectionReason> {
        nonce_lifecycle.issue_challenge(ContinuityChallenge {
            challenge_id: request.challenge_id,
            subject_id: request.subject_id,
            enrollment_ref: request.enrollment_ref,
            nonce: request.nonce,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            intended_action: request.intended_action,
        })
    }

    pub fn verify_continuity_assertion(
        &self,
        signed_assertion: SignedContinuityAssertion,
        nonce_lifecycle: &mut InMemoryNonceLifecycle,
        signature_verifier: &impl ContinuitySignatureVerifier,
        assurance_mapper: &impl ContinuityAssuranceMapper,
        verified_at: Timestamp,
    ) -> ContinuityAssertionVerificationResult {
        verify_signed_continuity_assertion(
            signed_assertion,
            nonce_lifecycle,
            signature_verifier,
            assurance_mapper,
            verified_at,
        )
    }

    pub fn verify_continuity_assertion_with_audit(
        &self,
        signed_assertion: SignedContinuityAssertion,
        audit_request: ContinuityAssertionVerificationAuditRequest,
        nonce_lifecycle: &mut InMemoryNonceLifecycle,
        signature_verifier: &impl ContinuitySignatureVerifier,
        assurance_mapper: &impl ContinuityAssuranceMapper,
    ) -> ContinuityAssertionVerificationOutcome {
        let verification = self.verify_continuity_assertion(
            signed_assertion.clone(),
            nonce_lifecycle,
            signature_verifier,
            assurance_mapper,
            audit_request.verified_at.clone(),
        );
        let rejection_fact = match &verification {
            ContinuityAssertionVerificationResult::Rejected { reason } => Some(
                self.translator
                    .continuity_verification_rejected(
                        audit_request.subject_id,
                        audit_request.verified_at,
                        &signed_assertion,
                        *reason,
                    )
                    .into_fact(audit_request.rejected_fact_id),
            ),
            ContinuityAssertionVerificationResult::Verified { .. } => None,
        };

        ContinuityAssertionVerificationOutcome {
            verification,
            rejection_fact,
        }
    }

    pub fn evaluate_sensitive_action(
        &self,
        request: SensitiveActionEvaluationRequest,
    ) -> PolicyEvaluation {
        evaluate_action_policy_with_context(&request.policy, &request.evidence, &request.context)
    }

    pub fn evaluate_sensitive_action_policy_artifact(
        &self,
        request: SensitiveActionPolicyArtifactEvaluationRequest,
    ) -> PolicyEvaluation {
        evaluate_policy_artifact_with_context(
            &request.policy_artifact,
            &request.evidence,
            &request.context,
        )
    }
}
