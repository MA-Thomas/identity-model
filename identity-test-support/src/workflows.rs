use crate::support::slice_from_drafts_with_id_plan;
use identity_model::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingRequest {
    pub subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub stable_profile: StableIdentityProfile,
    pub modality: BiometricModality,
    pub device_ref: DeviceRef,
    pub provider_org: OrganizationRef,
    pub external_patient_ref: ExternalRef,
    pub payer: String,
    pub member_ref: String,
}

impl OnboardingRequest {
    pub fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "onboarding",
                ProblemEpisodeId("episode-onboarding".to_string()),
                6,
            ),
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
            modality: BiometricModality::Face,
            device_ref: "device-passkey-1".to_string(),
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-123".to_string(),
                uri: None,
            },
            payer: "Example Payer".to_string(),
            member_ref: "member-123".to_string(),
        }
    }
}

pub fn onboarding_vertical_slice_from_request(
    request: OnboardingRequest,
    provider: &impl ContinuityVaultProvider,
    translator: &FenTranslator,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    let episode = identity_verification_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    let enrollment = provider.enroll(ContinuityEnrollmentRequest {
        subject_id: request.subject_id.clone(),
        modality: request.modality.clone(),
        requested_at: request.started_at.clone(),
    })?;

    let drafts = vec![
        translator.subject_created(
            request.subject_id.clone(),
            SubjectKind::HumanPerson,
            request.stable_profile,
            request.started_at.clone(),
        ),
        translator.device_binding_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.device_ref,
            AuthenticatorType::Passkey,
            AssuranceLevel::Medium,
            Some("AccountBootstrap".to_string()),
        ),
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::GovernmentIdVerification,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("government-id-document".to_string()),
            None,
            Some("IdentityProofingVendor".to_string()),
        ),
        translator.biometric_enrollment_added(enrollment, request.started_at.clone()),
        translator.clinical_identity_link_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.provider_org,
            request.external_patient_ref,
            MatchConfidence::High,
            Some("FHIRLinker".to_string()),
        ),
        translator.payer_identity_link_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.payer,
            request.member_ref,
            None,
            Some("PayerLinker".to_string()),
        ),
    ];

    let fact_roles = vec![
        FactRole::IdentityAnchor,
        FactRole::DeviceBinding,
        FactRole::IdentityWitness,
        FactRole::ContinuityWitness,
        FactRole::InstitutionalLink,
        FactRole::InstitutionalLink,
    ];

    Ok(slice_from_drafts_with_id_plan(
        episode,
        drafts,
        fact_roles,
        request.authored_by,
        request.started_at,
        &request.id_plan,
    ))
}

pub fn onboarding_vertical_slice(
    subject_id: SubjectId,
    provider: &impl ContinuityVaultProvider,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> Result<IdentityWorkflowSlice, VerticalSliceError> {
    onboarding_vertical_slice_from_request(
        OnboardingRequest::fixture(subject_id, authored_by, started_at),
        provider,
        translator,
    )
}
pub trait RegisterSubjectRequestFixture: Sized {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self;
}
impl RegisterSubjectRequestFixture for RegisterSubjectRequest {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "register-subject",
                ProblemEpisodeId("episode-register-subject".to_string()),
                1,
            ),
            subject_kind: SubjectKind::HumanPerson,
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
        }
    }
}
pub trait RegisterNewSubjectRequestFixture: Sized {
    fn fixture(authored_by: Author, started_at: Timestamp) -> Self;
}
impl RegisterNewSubjectRequestFixture for RegisterNewSubjectRequest {
    fn fixture(authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            authored_by,
            started_at,
            subject_id_prefix: "subject".to_string(),
            id_namespace: "register-subject".to_string(),
            subject_kind: SubjectKind::HumanPerson,
            stable_profile: StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: Some(Date("1990-01-01".to_string())),
                demographic_attributes: Vec::new(),
            },
        }
    }
}
pub trait BindDeviceRequestFixture: Sized {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self;
}
impl BindDeviceRequestFixture for BindDeviceRequest {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "bind-device",
                ProblemEpisodeId("episode-bind-device".to_string()),
                1,
            ),
            device_ref: "device-passkey-1".to_string(),
            authenticator_type: AuthenticatorType::Passkey,
            assurance_level: AssuranceLevel::Medium,
            source_system: Some("AccountBootstrap".to_string()),
        }
    }
}
pub trait EnrollContinuityRequestFixture: Sized {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self;
}
impl EnrollContinuityRequestFixture for EnrollContinuityRequest {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "enroll-continuity",
                ProblemEpisodeId("episode-enroll-continuity".to_string()),
                1,
            ),
            modality: BiometricModality::Face,
        }
    }
}
pub trait LinkProviderIdentityRequestFixture: Sized {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self;
}
impl LinkProviderIdentityRequestFixture for LinkProviderIdentityRequest {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "link-provider",
                ProblemEpisodeId("episode-link-provider".to_string()),
                1,
            ),
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-123".to_string(),
                uri: None,
            },
            match_confidence: MatchConfidence::High,
            source_system: Some("FHIRLinker".to_string()),
        }
    }
}
pub trait LinkPayerIdentityRequestFixture: Sized {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self;
}
impl LinkPayerIdentityRequestFixture for LinkPayerIdentityRequest {
    fn fixture(subject_id: SubjectId, authored_by: Author, started_at: Timestamp) -> Self {
        Self {
            subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "link-payer",
                ProblemEpisodeId("episode-link-payer".to_string()),
                1,
            ),
            payer: "Example Payer".to_string(),
            member_ref: "member-123".to_string(),
            effective_period: None,
            source_system: Some("PayerLinker".to_string()),
        }
    }
}
pub trait CompleteRecordExportStepUpRequestFixture: Sized {
    fn fixture(
        subject_id: SubjectId,
        enrollment_ref: String,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self;
}
impl CompleteRecordExportStepUpRequestFixture for CompleteRecordExportStepUpRequest {
    fn fixture(
        subject_id: SubjectId,
        enrollment_ref: String,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id,
            enrollment_ref,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic_with_fact_overrides(
                "export",
                ProblemEpisodeId("episode-export-step-up".to_string()),
                4,
                vec![
                    (0, FactId("fact-export-credential".to_string())),
                    (1, FactId("fact-export-continuity".to_string())),
                    (2, FactId("fact-export-risk".to_string())),
                    (3, FactId("fact-export-access-decision".to_string())),
                ],
            )
            .with_challenge(
                ChallengeId("challenge-export-step-up".to_string()),
                "nonce-export-step-up".to_string(),
            ),
            challenge_expires_at: Timestamp("2026-05-29T00:10:00Z".to_string()),
            policy_ref: PolicyRef("complete-record-export-policy".to_string()),
            device_ref: Some("device-passkey-1".to_string()),
        }
    }
}
