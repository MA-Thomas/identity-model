use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPath {
    ManualReview,
    ApprovedGovernmentIdAndLiveness,
    DeniedProviderAttestation,
    TrustedDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub subject_id: SubjectId,
    pub path: RecoveryPath,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
}

impl RecoveryRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        path: RecoveryPath,
        authored_by: Author,
        started_at: Timestamp,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            subject_id,
            path,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, path.fact_count()),
        }
    }

    pub fn manual_review(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self::fixture(
            subject_id,
            RecoveryPath::ManualReview,
            authored_by,
            started_at,
            "recovery",
            "episode-recovery",
            3,
        )
    }

    pub fn approved_government_id_and_liveness(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self::fixture(
            subject_id,
            RecoveryPath::ApprovedGovernmentIdAndLiveness,
            authored_by,
            started_at,
            "recovery-approved",
            "episode-recovery-approved",
            5,
        )
    }

    pub fn denied_provider_attestation(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self::fixture(
            subject_id,
            RecoveryPath::DeniedProviderAttestation,
            authored_by,
            started_at,
            "recovery-denied",
            "episode-recovery-denied",
            3,
        )
    }

    pub fn trusted_device(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self::fixture(
            subject_id,
            RecoveryPath::TrustedDevice,
            authored_by,
            started_at,
            "recovery-trusted-device",
            "episode-recovery-trusted-device",
            3,
        )
    }

    fn fixture(
        subject_id: SubjectId,
        path: RecoveryPath,
        authored_by: Author,
        started_at: Timestamp,
        id_namespace: &str,
        episode_id: &str,
        fact_count: usize,
    ) -> Self {
        Self {
            subject_id,
            path,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                id_namespace,
                ProblemEpisodeId(episode_id.to_string()),
                fact_count,
            ),
        }
    }
}

impl RecoveryPath {
    fn fact_count(self) -> usize {
        match self {
            RecoveryPath::ManualReview => 3,
            RecoveryPath::ApprovedGovernmentIdAndLiveness => 5,
            RecoveryPath::DeniedProviderAttestation => 3,
            RecoveryPath::TrustedDevice => 3,
        }
    }
}

pub fn recovery_slice_from_request(
    request: RecoveryRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = account_recovery_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    let (drafts, roles) = match request.path {
        RecoveryPath::ManualReview => manual_review_recovery_drafts(&request, translator),
        RecoveryPath::ApprovedGovernmentIdAndLiveness => {
            approved_recovery_drafts(&request, translator)
        }
        RecoveryPath::DeniedProviderAttestation => denied_recovery_drafts(&request, translator),
        RecoveryPath::TrustedDevice => trusted_device_recovery_drafts(&request, translator),
    };

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        roles,
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn manual_review_recovery_slice(
    subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    recovery_slice_from_request(
        RecoveryRequest::manual_review(subject_id, authored_by, started_at),
        translator,
    )
}

pub fn approved_recovery_slice(
    subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    recovery_slice_from_request(
        RecoveryRequest::approved_government_id_and_liveness(subject_id, authored_by, started_at),
        translator,
    )
}

pub fn denied_recovery_slice(
    subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    recovery_slice_from_request(
        RecoveryRequest::denied_provider_attestation(subject_id, authored_by, started_at),
        translator,
    )
}

pub fn trusted_device_recovery_slice(
    subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    recovery_slice_from_request(
        RecoveryRequest::trusted_device(subject_id, authored_by, started_at),
        translator,
    )
}

fn manual_review_recovery_drafts(
    request: &RecoveryRequest,
    translator: &FenTranslator,
) -> (Vec<FactDraft>, Vec<FactRole>) {
    let drafts = vec![
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::ProviderAttestation,
            request.subject_id.clone(),
            AssuranceLevel::Medium,
            Some("provider-attestation-document".to_string()),
            None,
            Some("ClinicStaff".to_string()),
        ),
        translator.account_recovery_event(
            request.subject_id.clone(),
            request.started_at.clone(),
            RecoveryMethod::ManualReview,
            RecoveryResult::PendingManualReview,
            AssuranceLevel::Medium,
        ),
        translator.device_binding_revoked(
            request.subject_id.clone(),
            request.started_at.clone(),
            "device-passkey-1".to_string(),
            Some("device lost during recovery".to_string()),
        ),
    ];

    (
        drafts,
        vec![
            FactRole::RecoveryEvidence,
            FactRole::RecoveryEvidence,
            FactRole::DeviceBinding,
        ],
    )
}

fn approved_recovery_drafts(
    request: &RecoveryRequest,
    translator: &FenTranslator,
) -> (Vec<FactDraft>, Vec<FactRole>) {
    let drafts = vec![
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::GovernmentIdVerification,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("recovery-government-id".to_string()),
            None,
            Some("IdentityProofingVendor".to_string()),
        ),
        translator.account_recovery_event(
            request.subject_id.clone(),
            request.started_at.clone(),
            RecoveryMethod::GovernmentIdAndLiveness,
            RecoveryResult::Approved,
            AssuranceLevel::High,
        ),
        translator.device_binding_revoked(
            request.subject_id.clone(),
            request.started_at.clone(),
            "device-passkey-lost".to_string(),
            Some("replaced after approved recovery".to_string()),
        ),
        translator.device_binding_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            "device-passkey-replacement".to_string(),
            AuthenticatorType::Passkey,
            AssuranceLevel::Medium,
            Some("FENRecovery".to_string()),
        ),
        translator.access_decision(
            request.subject_id.clone(),
            request.started_at.clone(),
            SensitiveAction::ChangeRecoveryMethod,
            AccessDecisionResult::Allowed,
            vec![request.id_plan.fact_id(0), request.id_plan.fact_id(1)],
            vec![PolicyRef("recovery-method-change-policy".to_string())],
        ),
    ];

    (
        drafts,
        vec![
            FactRole::RecoveryEvidence,
            FactRole::RecoveryEvidence,
            FactRole::DeviceBinding,
            FactRole::DeviceBinding,
            FactRole::AccessDecisionEvidence,
        ],
    )
}

fn denied_recovery_drafts(
    request: &RecoveryRequest,
    translator: &FenTranslator,
) -> (Vec<FactDraft>, Vec<FactRole>) {
    let drafts = vec![
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::ProviderAttestation,
            request.subject_id.clone(),
            AssuranceLevel::Low,
            Some("failed-provider-attestation".to_string()),
            None,
            Some("ClinicStaff".to_string()),
        ),
        translator.account_recovery_event(
            request.subject_id.clone(),
            request.started_at.clone(),
            RecoveryMethod::ProviderAttestation,
            RecoveryResult::Denied,
            AssuranceLevel::Low,
        ),
        translator.access_decision(
            request.subject_id.clone(),
            request.started_at.clone(),
            SensitiveAction::ChangeRecoveryMethod,
            AccessDecisionResult::Denied,
            vec![request.id_plan.fact_id(0), request.id_plan.fact_id(1)],
            vec![PolicyRef("recovery-method-change-policy".to_string())],
        ),
    ];

    (
        drafts,
        vec![
            FactRole::RecoveryEvidence,
            FactRole::RecoveryEvidence,
            FactRole::AccessDecisionEvidence,
        ],
    )
}

fn trusted_device_recovery_drafts(
    request: &RecoveryRequest,
    translator: &FenTranslator,
) -> (Vec<FactDraft>, Vec<FactRole>) {
    let drafts = vec![
        translator.credential_assertion(
            request.subject_id.clone(),
            request.started_at.clone(),
            AuthenticatorType::Passkey,
            Some("device-passkey-trusted".to_string()),
            CredentialAssertionResult::Succeeded,
            AssuranceLevel::Medium,
            Some("AccountSession".to_string()),
        ),
        translator.account_recovery_event(
            request.subject_id.clone(),
            request.started_at.clone(),
            RecoveryMethod::ExistingTrustedDevice,
            RecoveryResult::Approved,
            AssuranceLevel::Medium,
        ),
        translator.access_decision(
            request.subject_id.clone(),
            request.started_at.clone(),
            SensitiveAction::ChangeRecoveryMethod,
            AccessDecisionResult::Allowed,
            vec![request.id_plan.fact_id(0), request.id_plan.fact_id(1)],
            vec![PolicyRef("trusted-device-recovery-policy".to_string())],
        ),
    ];

    (
        drafts,
        vec![
            FactRole::IdentityWitness,
            FactRole::RecoveryEvidence,
            FactRole::AccessDecisionEvidence,
        ],
    )
}
