use super::*;

pub(super) fn postgres_fact_status_parts(
    status: &FactStatus,
) -> (&'static str, PostgresFactStatusPayload) {
    match status {
        FactStatus::Active => ("active", PostgresFactStatusPayload::Active),
        FactStatus::Superseded {
            superseded_by,
            superseded_at,
            replaced_by,
            reason,
        } => (
            "superseded",
            PostgresFactStatusPayload::Superseded {
                superseded_by: PostgresAuthorRecord::from_author(superseded_by),
                superseded_at: PostgresTemporalAnchorRecord::from_temporal_anchor(superseded_at),
                replaced_by: replaced_by.as_ref().map(|fact_id| fact_id.0.clone()),
                reason: postgres_supersession_reason(reason).to_string(),
            },
        ),
        FactStatus::EnteredInError {
            corrected_by,
            corrected_at,
            replaced_by,
        } => (
            "entered_in_error",
            PostgresFactStatusPayload::EnteredInError {
                corrected_by: PostgresAuthorRecord::from_author(corrected_by),
                corrected_at: PostgresTemporalAnchorRecord::from_temporal_anchor(corrected_at),
                replaced_by: replaced_by.as_ref().map(|fact_id| fact_id.0.clone()),
            },
        ),
    }
}

pub(super) fn postgres_episode_status_parts(
    status: &EpisodeStatus,
) -> (&'static str, PostgresEpisodeStatusPayload) {
    match status {
        EpisodeStatus::Active => ("active", PostgresEpisodeStatusPayload::Active),
        EpisodeStatus::Dormant => ("dormant", PostgresEpisodeStatusPayload::Dormant),
        EpisodeStatus::Resolved(resolution) => (
            "resolved",
            PostgresEpisodeStatusPayload::Resolved {
                at: resolution
                    .at
                    .as_ref()
                    .map(PostgresApproximateDateRecord::from_approximate_date),
            },
        ),
    }
}

pub(super) fn episode_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresEpisodeStatusPayload,
) -> Result<EpisodeStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresEpisodeStatusPayload::Active) => Ok(EpisodeStatus::Active),
        ("dormant", PostgresEpisodeStatusPayload::Dormant) => Ok(EpisodeStatus::Dormant),
        ("resolved", PostgresEpisodeStatusPayload::Resolved { at }) => {
            Ok(EpisodeStatus::Resolved(ResolutionInfo {
                at: at
                    .map(PostgresApproximateDateRecord::try_into_approximate_date)
                    .transpose()?,
            }))
        }
        ("active" | "dormant" | "resolved", _) => {
            Err(PostgresAdapterError::InvalidEpisodeStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownEpisodeStatusKind(
            status_kind.to_string(),
        )),
    }
}

pub(super) fn postgres_membership_status_parts(
    status: &MembershipStatus,
) -> (&'static str, PostgresMembershipStatusPayload) {
    match status {
        MembershipStatus::Active => ("active", PostgresMembershipStatusPayload::Active),
        MembershipStatus::Retracted {
            retracted_by,
            retracted_at,
        } => (
            "retracted",
            PostgresMembershipStatusPayload::Retracted {
                retracted_by: PostgresAuthorRecord::from_author(retracted_by),
                retracted_at: PostgresTemporalAnchorRecord::from_temporal_anchor(retracted_at),
            },
        ),
    }
}

pub(super) fn membership_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresMembershipStatusPayload,
) -> Result<MembershipStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresMembershipStatusPayload::Active) => Ok(MembershipStatus::Active),
        (
            "retracted",
            PostgresMembershipStatusPayload::Retracted {
                retracted_by,
                retracted_at,
            },
        ) => Ok(MembershipStatus::Retracted {
            retracted_by: retracted_by.try_into_author()?,
            retracted_at: retracted_at.try_into_temporal_anchor()?,
        }),
        ("active" | "retracted", _) => Err(PostgresAdapterError::InvalidMembershipStatusPayload),
        _ => Err(PostgresAdapterError::UnknownMembershipStatusKind(
            status_kind.to_string(),
        )),
    }
}

pub(super) fn postgres_episode_relation_status_parts(
    status: &EpisodeRelationStatus,
) -> (&'static str, PostgresEpisodeRelationStatusPayload) {
    match status {
        EpisodeRelationStatus::Active => ("active", PostgresEpisodeRelationStatusPayload::Active),
        EpisodeRelationStatus::Retracted {
            retracted_by,
            retracted_at,
        } => (
            "retracted",
            PostgresEpisodeRelationStatusPayload::Retracted {
                retracted_by: PostgresAuthorRecord::from_author(retracted_by),
                retracted_at: PostgresTemporalAnchorRecord::from_temporal_anchor(retracted_at),
            },
        ),
    }
}

pub(super) fn episode_relation_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresEpisodeRelationStatusPayload,
) -> Result<EpisodeRelationStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresEpisodeRelationStatusPayload::Active) => {
            Ok(EpisodeRelationStatus::Active)
        }
        (
            "retracted",
            PostgresEpisodeRelationStatusPayload::Retracted {
                retracted_by,
                retracted_at,
            },
        ) => Ok(EpisodeRelationStatus::Retracted {
            retracted_by: retracted_by.try_into_author()?,
            retracted_at: retracted_at.try_into_temporal_anchor()?,
        }),
        ("active" | "retracted", _) => {
            Err(PostgresAdapterError::InvalidEpisodeRelationStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownEpisodeRelationStatusKind(
            status_kind.to_string(),
        )),
    }
}

pub(super) fn fact_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresFactStatusPayload,
) -> Result<FactStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresFactStatusPayload::Active) => Ok(FactStatus::Active),
        (
            "superseded",
            PostgresFactStatusPayload::Superseded {
                superseded_by,
                superseded_at,
                replaced_by,
                reason,
            },
        ) => Ok(FactStatus::Superseded {
            superseded_by: superseded_by.try_into_author()?,
            superseded_at: superseded_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(FactId),
            reason: supersession_reason_from_postgres(&reason)?,
        }),
        (
            "entered_in_error",
            PostgresFactStatusPayload::EnteredInError {
                corrected_by,
                corrected_at,
                replaced_by,
            },
        ) => Ok(FactStatus::EnteredInError {
            corrected_by: corrected_by.try_into_author()?,
            corrected_at: corrected_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(FactId),
        }),
        ("active" | "superseded" | "entered_in_error", _) => {
            Err(PostgresAdapterError::InvalidFactStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownFactStatusKind(
            status_kind.to_string(),
        )),
    }
}

impl PostgresAuthorRecord {
    pub(super) fn from_author(author: &Author) -> Self {
        Self {
            author_type: postgres_author_type(&author.author_type).to_string(),
            author_id: author
                .author_id
                .as_ref()
                .map(|author_id| author_id.0.clone()),
            display_name: author.display_name.clone(),
        }
    }

    pub(super) fn try_into_author(self) -> Result<Author, PostgresAdapterError> {
        Ok(Author {
            author_type: author_type_from_postgres(&self.author_type)?,
            author_id: self.author_id.map(AuthorId),
            display_name: self.display_name,
        })
    }
}

pub(super) fn postgres_workflow_transaction_kind(
    kind: PostgresWorkflowTransactionKind,
) -> &'static str {
    match kind {
        PostgresWorkflowTransactionKind::WorkflowSlice => "workflow_slice",
        PostgresWorkflowTransactionKind::EpisodeComposition => "episode_composition",
    }
}

pub(super) fn workflow_transaction_kind_from_postgres(
    value: &str,
) -> Result<PostgresWorkflowTransactionKind, PostgresAdapterError> {
    match value {
        "workflow_slice" => Ok(PostgresWorkflowTransactionKind::WorkflowSlice),
        "episode_composition" => Ok(PostgresWorkflowTransactionKind::EpisodeComposition),
        _ => Err(PostgresAdapterError::UnknownWorkflowTransactionKind(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_app_attest_environment(environment: AppAttestEnvironment) -> &'static str {
    match environment {
        AppAttestEnvironment::Development => "development",
        AppAttestEnvironment::Production => "production",
    }
}

pub(super) fn app_attest_environment_from_postgres(
    value: &str,
) -> Result<AppAttestEnvironment, PostgresAdapterError> {
    match value {
        "development" => Ok(AppAttestEnvironment::Development),
        "production" => Ok(AppAttestEnvironment::Production),
        _ => Err(PostgresAdapterError::UnknownAppAttestEnvironment(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_app_attest_key_status(status: AppAttestKeyStateStatus) -> &'static str {
    match status {
        AppAttestKeyStateStatus::Active => "active",
        AppAttestKeyStateStatus::Revoked => "revoked",
    }
}

pub(super) fn app_attest_key_status_from_postgres(
    value: &str,
) -> Result<AppAttestKeyStateStatus, PostgresAdapterError> {
    match value {
        "active" => Ok(AppAttestKeyStateStatus::Active),
        "revoked" => Ok(AppAttestKeyStateStatus::Revoked),
        _ => Err(PostgresAdapterError::UnknownAppAttestKeyStatus(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_live_presence_challenge_workflow(
    workflow: LivePresenceChallengeWorkflow,
) -> &'static str {
    match workflow {
        LivePresenceChallengeWorkflow::MobileIdentityOnboarding => "mobile_identity_onboarding",
        LivePresenceChallengeWorkflow::AccountRecovery => "account_recovery",
        LivePresenceChallengeWorkflow::SensitiveActionStepUp => "sensitive_action_step_up",
    }
}

pub(super) fn live_presence_challenge_workflow_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeWorkflow, PostgresAdapterError> {
    match value {
        "mobile_identity_onboarding" => Ok(LivePresenceChallengeWorkflow::MobileIdentityOnboarding),
        "account_recovery" => Ok(LivePresenceChallengeWorkflow::AccountRecovery),
        "sensitive_action_step_up" => Ok(LivePresenceChallengeWorkflow::SensitiveActionStepUp),
        _ => Err(PostgresAdapterError::UnknownLivePresenceChallengeWorkflow(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_live_presence_challenge_status_parts(
    status: &LivePresenceChallengeStatus,
) -> (&'static str, PostgresLivePresenceChallengeStatusPayload) {
    match status {
        LivePresenceChallengeStatus::Issued => {
            ("issued", PostgresLivePresenceChallengeStatusPayload::Issued)
        }
        LivePresenceChallengeStatus::Used {
            used_at,
            provider_event_id,
        } => (
            "used",
            PostgresLivePresenceChallengeStatusPayload::Used {
                used_at: used_at.0.clone(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
        LivePresenceChallengeStatus::Expired { expired_at } => (
            "expired",
            PostgresLivePresenceChallengeStatusPayload::Expired {
                expired_at: expired_at.0.clone(),
            },
        ),
        LivePresenceChallengeStatus::Failed {
            failed_at,
            reason,
            provider_event_id,
        } => (
            "failed",
            PostgresLivePresenceChallengeStatusPayload::Failed {
                failed_at: failed_at.0.clone(),
                reason: postgres_live_presence_failure_reason(*reason).to_string(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
        LivePresenceChallengeStatus::ManualReview {
            referred_at,
            reason,
            provider_event_id,
        } => (
            "manual_review",
            PostgresLivePresenceChallengeStatusPayload::ManualReview {
                referred_at: referred_at.0.clone(),
                reason: postgres_live_presence_manual_review_reason(*reason).to_string(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
    }
}

pub(super) fn live_presence_challenge_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresLivePresenceChallengeStatusPayload,
) -> Result<LivePresenceChallengeStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("issued", PostgresLivePresenceChallengeStatusPayload::Issued) => {
            Ok(LivePresenceChallengeStatus::Issued)
        }
        (
            "used",
            PostgresLivePresenceChallengeStatusPayload::Used {
                used_at,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::Used {
            used_at: Timestamp(used_at),
            provider_event_id,
        }),
        ("expired", PostgresLivePresenceChallengeStatusPayload::Expired { expired_at }) => {
            Ok(LivePresenceChallengeStatus::Expired {
                expired_at: Timestamp(expired_at),
            })
        }
        (
            "failed",
            PostgresLivePresenceChallengeStatusPayload::Failed {
                failed_at,
                reason,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::Failed {
            failed_at: Timestamp(failed_at),
            reason: live_presence_failure_reason_from_postgres(&reason)?,
            provider_event_id,
        }),
        (
            "manual_review",
            PostgresLivePresenceChallengeStatusPayload::ManualReview {
                referred_at,
                reason,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::ManualReview {
            referred_at: Timestamp(referred_at),
            reason: live_presence_manual_review_reason_from_postgres(&reason)?,
            provider_event_id,
        }),
        ("issued" | "used" | "expired" | "failed" | "manual_review", _) => {
            Err(PostgresAdapterError::InvalidLivePresenceChallengeStatusPayload)
        }
        _ => Err(
            PostgresAdapterError::UnknownLivePresenceChallengeStatusKind(status_kind.to_string()),
        ),
    }
}

pub(super) fn postgres_live_presence_failure_reason(
    reason: LivePresenceChallengeFailureReason,
) -> &'static str {
    match reason {
        LivePresenceChallengeFailureReason::LivenessFailed => "liveness_failed",
        LivePresenceChallengeFailureReason::PresentationAttackDetected => {
            "presentation_attack_detected"
        }
        LivePresenceChallengeFailureReason::ChallengeMismatch => "challenge_mismatch",
        LivePresenceChallengeFailureReason::SubjectMismatch => "subject_mismatch",
        LivePresenceChallengeFailureReason::DeviceMismatch => "device_mismatch",
        LivePresenceChallengeFailureReason::AppContextMismatch => "app_context_mismatch",
        LivePresenceChallengeFailureReason::ProviderRejected => "provider_rejected",
    }
}

pub(super) fn live_presence_failure_reason_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeFailureReason, PostgresAdapterError> {
    match value {
        "liveness_failed" => Ok(LivePresenceChallengeFailureReason::LivenessFailed),
        "presentation_attack_detected" => {
            Ok(LivePresenceChallengeFailureReason::PresentationAttackDetected)
        }
        "challenge_mismatch" => Ok(LivePresenceChallengeFailureReason::ChallengeMismatch),
        "subject_mismatch" => Ok(LivePresenceChallengeFailureReason::SubjectMismatch),
        "device_mismatch" => Ok(LivePresenceChallengeFailureReason::DeviceMismatch),
        "app_context_mismatch" => Ok(LivePresenceChallengeFailureReason::AppContextMismatch),
        "provider_rejected" => Ok(LivePresenceChallengeFailureReason::ProviderRejected),
        _ => {
            Err(PostgresAdapterError::UnknownLivePresenceChallengeFailureReason(value.to_string()))
        }
    }
}

pub(super) fn postgres_live_presence_manual_review_reason(
    reason: LivePresenceChallengeManualReviewReason,
) -> &'static str {
    match reason {
        LivePresenceChallengeManualReviewReason::LivenessInconclusive => "liveness_inconclusive",
        LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive => {
            "presentation_attack_inconclusive"
        }
        LivePresenceChallengeManualReviewReason::RetryOrReviewPolicy => "retry_or_review_policy",
    }
}

pub(super) fn live_presence_manual_review_reason_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeManualReviewReason, PostgresAdapterError> {
    match value {
        "liveness_inconclusive" => {
            Ok(LivePresenceChallengeManualReviewReason::LivenessInconclusive)
        }
        "presentation_attack_inconclusive" => {
            Ok(LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive)
        }
        "retry_or_review_policy" => {
            Ok(LivePresenceChallengeManualReviewReason::RetryOrReviewPolicy)
        }
        _ => Err(
            PostgresAdapterError::UnknownLivePresenceChallengeManualReviewReason(value.to_string()),
        ),
    }
}

pub(super) fn postgres_episode_kind(kind: EpisodeKind) -> &'static str {
    match kind {
        EpisodeKind::ClinicalProblem => "clinical_problem",
        EpisodeKind::AdministrativeWorkflow => "administrative_workflow",
        EpisodeKind::IdentityVerificationWorkflow => "identity_verification_workflow",
        EpisodeKind::AccountRecoveryWorkflow => "account_recovery_workflow",
        EpisodeKind::DelegationWorkflow => "delegation_workflow",
        EpisodeKind::AccessAuthorizationWorkflow => "access_authorization_workflow",
        EpisodeKind::DataSharingWorkflow => "data_sharing_workflow",
        EpisodeKind::DisputeResolutionWorkflow => "dispute_resolution_workflow",
    }
}

pub(super) fn episode_kind_from_postgres(value: &str) -> Result<EpisodeKind, PostgresAdapterError> {
    match value {
        "clinical_problem" => Ok(EpisodeKind::ClinicalProblem),
        "administrative_workflow" => Ok(EpisodeKind::AdministrativeWorkflow),
        "identity_verification_workflow" => Ok(EpisodeKind::IdentityVerificationWorkflow),
        "account_recovery_workflow" => Ok(EpisodeKind::AccountRecoveryWorkflow),
        "delegation_workflow" => Ok(EpisodeKind::DelegationWorkflow),
        "access_authorization_workflow" => Ok(EpisodeKind::AccessAuthorizationWorkflow),
        "data_sharing_workflow" => Ok(EpisodeKind::DataSharingWorkflow),
        "dispute_resolution_workflow" => Ok(EpisodeKind::DisputeResolutionWorkflow),
        _ => Err(PostgresAdapterError::UnknownEpisodeKind(value.to_string())),
    }
}

pub(super) fn postgres_date_precision(precision: DatePrecision) -> &'static str {
    match precision {
        DatePrecision::Day => "day",
        DatePrecision::Month => "month",
        DatePrecision::Year => "year",
        DatePrecision::Approximate => "approximate",
    }
}

pub(super) fn date_precision_from_postgres(
    value: &str,
) -> Result<DatePrecision, PostgresAdapterError> {
    match value {
        "day" => Ok(DatePrecision::Day),
        "month" => Ok(DatePrecision::Month),
        "year" => Ok(DatePrecision::Year),
        "approximate" => Ok(DatePrecision::Approximate),
        _ => Err(PostgresAdapterError::UnknownDatePrecision(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_coding_system(system: &CodingSystem) -> &'static str {
    match system {
        CodingSystem::Snomed => "snomed",
        CodingSystem::Icd10 => "icd10",
        CodingSystem::Loinc => "loinc",
        CodingSystem::RxNorm => "rxnorm",
        CodingSystem::Cpt => "cpt",
        CodingSystem::Hcpcs => "hcpcs",
        CodingSystem::Ndc => "ndc",
        CodingSystem::Carc => "carc",
        CodingSystem::Local => "local",
    }
}

pub(super) fn coding_system_from_postgres(
    value: &str,
) -> Result<CodingSystem, PostgresAdapterError> {
    match value {
        "snomed" => Ok(CodingSystem::Snomed),
        "icd10" => Ok(CodingSystem::Icd10),
        "loinc" => Ok(CodingSystem::Loinc),
        "rxnorm" => Ok(CodingSystem::RxNorm),
        "cpt" => Ok(CodingSystem::Cpt),
        "hcpcs" => Ok(CodingSystem::Hcpcs),
        "ndc" => Ok(CodingSystem::Ndc),
        "carc" => Ok(CodingSystem::Carc),
        "local" => Ok(CodingSystem::Local),
        _ => Err(PostgresAdapterError::UnknownCodingSystem(value.to_string())),
    }
}

pub(super) fn postgres_fact_role(role: &FactRole) -> &'static str {
    match role {
        FactRole::TriggeringSymptom => "triggering_symptom",
        FactRole::DiagnosticTest => "diagnostic_test",
        FactRole::Treatment => "treatment",
        FactRole::OutcomeMeasure => "outcome_measure",
        FactRole::Monitoring => "monitoring",
        FactRole::Complication => "complication",
        FactRole::Referral => "referral",
        FactRole::Administrative => "administrative",
        FactRole::InsuranceAction => "insurance_action",
        FactRole::IdentityAnchor => "identity_anchor",
        FactRole::IdentityWitness => "identity_witness",
        FactRole::ContinuityWitness => "continuity_witness",
        FactRole::DeviceBinding => "device_binding",
        FactRole::InstitutionalLink => "institutional_link",
        FactRole::AuthorityEvidence => "authority_evidence",
        FactRole::RecoveryEvidence => "recovery_evidence",
        FactRole::RiskSignal => "risk_signal",
        FactRole::AccessDecisionEvidence => "access_decision_evidence",
        FactRole::DisputeEvidence => "dispute_evidence",
        FactRole::Other => "other",
    }
}

pub(super) fn fact_role_from_postgres(value: &str) -> Result<FactRole, PostgresAdapterError> {
    match value {
        "triggering_symptom" => Ok(FactRole::TriggeringSymptom),
        "diagnostic_test" => Ok(FactRole::DiagnosticTest),
        "treatment" => Ok(FactRole::Treatment),
        "outcome_measure" => Ok(FactRole::OutcomeMeasure),
        "monitoring" => Ok(FactRole::Monitoring),
        "complication" => Ok(FactRole::Complication),
        "referral" => Ok(FactRole::Referral),
        "administrative" => Ok(FactRole::Administrative),
        "insurance_action" => Ok(FactRole::InsuranceAction),
        "identity_anchor" => Ok(FactRole::IdentityAnchor),
        "identity_witness" => Ok(FactRole::IdentityWitness),
        "continuity_witness" => Ok(FactRole::ContinuityWitness),
        "device_binding" => Ok(FactRole::DeviceBinding),
        "institutional_link" => Ok(FactRole::InstitutionalLink),
        "authority_evidence" => Ok(FactRole::AuthorityEvidence),
        "recovery_evidence" => Ok(FactRole::RecoveryEvidence),
        "risk_signal" => Ok(FactRole::RiskSignal),
        "access_decision_evidence" => Ok(FactRole::AccessDecisionEvidence),
        "dispute_evidence" => Ok(FactRole::DisputeEvidence),
        "other" => Ok(FactRole::Other),
        _ => Err(PostgresAdapterError::UnknownFactRole(value.to_string())),
    }
}

pub(super) fn postgres_episode_relation_type(relation_type: EpisodeRelationType) -> &'static str {
    match relation_type {
        EpisodeRelationType::PartOf => "part_of",
    }
}

pub(super) fn episode_relation_type_from_postgres(
    value: &str,
) -> Result<EpisodeRelationType, PostgresAdapterError> {
    match value {
        "part_of" => Ok(EpisodeRelationType::PartOf),
        _ => Err(PostgresAdapterError::UnknownEpisodeRelationType(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_author_type(author_type: &AuthorType) -> &'static str {
    match author_type {
        AuthorType::Patient => "patient",
        AuthorType::Clinician => "clinician",
        AuthorType::System => "system",
        AuthorType::AiAssisted => "ai_assisted",
    }
}

pub(super) fn author_type_from_postgres(value: &str) -> Result<AuthorType, PostgresAdapterError> {
    match value {
        "patient" => Ok(AuthorType::Patient),
        "clinician" => Ok(AuthorType::Clinician),
        "system" => Ok(AuthorType::System),
        "ai_assisted" => Ok(AuthorType::AiAssisted),
        _ => Err(PostgresAdapterError::UnknownAuthorType(value.to_string())),
    }
}

pub(super) fn postgres_supersession_reason(reason: &SupersessionReason) -> &'static str {
    match reason {
        SupersessionReason::AiEnrichment => "ai_enrichment",
        SupersessionReason::ClinicalRefinement => "clinical_refinement",
        SupersessionReason::StrongerIdentityEvidence => "stronger_identity_evidence",
        SupersessionReason::AdministrativeCorrection => "administrative_correction",
        SupersessionReason::RuleReEvaluation => "rule_re_evaluation",
    }
}

pub(super) fn supersession_reason_from_postgres(
    value: &str,
) -> Result<SupersessionReason, PostgresAdapterError> {
    match value {
        "ai_enrichment" => Ok(SupersessionReason::AiEnrichment),
        "clinical_refinement" => Ok(SupersessionReason::ClinicalRefinement),
        "stronger_identity_evidence" => Ok(SupersessionReason::StrongerIdentityEvidence),
        "administrative_correction" => Ok(SupersessionReason::AdministrativeCorrection),
        "rule_re_evaluation" => Ok(SupersessionReason::RuleReEvaluation),
        _ => Err(PostgresAdapterError::UnknownSupersessionReason(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_audit_outcome(outcome: FactMaterializationAuditOutcome) -> &'static str {
    match outcome {
        FactMaterializationAuditOutcome::Attempted => "attempted",
        FactMaterializationAuditOutcome::PolicyDenied => "policy_denied",
        FactMaterializationAuditOutcome::KeyAccessAttempted => "key_access_attempted",
        FactMaterializationAuditOutcome::KeyAccessSucceeded => "key_access_succeeded",
        FactMaterializationAuditOutcome::KeyAccessFailed => "key_access_failed",
        FactMaterializationAuditOutcome::DecryptionAttempted => "decryption_attempted",
        FactMaterializationAuditOutcome::DecryptionFailed => "decryption_failed",
        FactMaterializationAuditOutcome::Succeeded => "succeeded",
    }
}

pub(super) fn audit_outcome_from_postgres(
    value: &str,
) -> Result<FactMaterializationAuditOutcome, PostgresAdapterError> {
    match value {
        "attempted" => Ok(FactMaterializationAuditOutcome::Attempted),
        "policy_denied" => Ok(FactMaterializationAuditOutcome::PolicyDenied),
        "key_access_attempted" => Ok(FactMaterializationAuditOutcome::KeyAccessAttempted),
        "key_access_succeeded" => Ok(FactMaterializationAuditOutcome::KeyAccessSucceeded),
        "key_access_failed" => Ok(FactMaterializationAuditOutcome::KeyAccessFailed),
        "decryption_attempted" => Ok(FactMaterializationAuditOutcome::DecryptionAttempted),
        "decryption_failed" => Ok(FactMaterializationAuditOutcome::DecryptionFailed),
        "succeeded" => Ok(FactMaterializationAuditOutcome::Succeeded),
        _ => Err(PostgresAdapterError::UnknownMaterializationAuditOutcome(
            value.to_string(),
        )),
    }
}

pub(super) fn postgres_materialization_error(error: FactMaterializationError) -> &'static str {
    match error {
        FactMaterializationError::PolicyDenied => "policy_denied",
        FactMaterializationError::MaterializationPolicyRefsNotSatisfied => {
            "materialization_policy_refs_not_satisfied"
        }
        FactMaterializationError::MissingKey => "missing_key",
        FactMaterializationError::RetiredKey => "retired_key",
        FactMaterializationError::AuthenticationFailed => "authentication_failed",
        FactMaterializationError::PlaintextDecodeFailed => "plaintext_decode_failed",
        FactMaterializationError::UnsupportedAlgorithm => "unsupported_algorithm",
        FactMaterializationError::InvalidKeyMaterial => "invalid_key_material",
        FactMaterializationError::InvalidNonce => "invalid_nonce",
    }
}

pub(super) fn materialization_error_from_postgres(
    value: &str,
) -> Result<FactMaterializationError, PostgresAdapterError> {
    match value {
        "policy_denied" => Ok(FactMaterializationError::PolicyDenied),
        "materialization_policy_refs_not_satisfied" => {
            Ok(FactMaterializationError::MaterializationPolicyRefsNotSatisfied)
        }
        "missing_key" => Ok(FactMaterializationError::MissingKey),
        "retired_key" => Ok(FactMaterializationError::RetiredKey),
        "authentication_failed" => Ok(FactMaterializationError::AuthenticationFailed),
        "plaintext_decode_failed" => Ok(FactMaterializationError::PlaintextDecodeFailed),
        "unsupported_algorithm" => Ok(FactMaterializationError::UnsupportedAlgorithm),
        "invalid_key_material" => Ok(FactMaterializationError::InvalidKeyMaterial),
        "invalid_nonce" => Ok(FactMaterializationError::InvalidNonce),
        _ => Err(PostgresAdapterError::UnknownMaterializationError(
            value.to_string(),
        )),
    }
}
