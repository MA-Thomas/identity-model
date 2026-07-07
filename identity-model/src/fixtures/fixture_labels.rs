//! Presentation labels for fixture and narrative rendering only.
//!
//! These mappings should not be used by policy, workflow, projection, or
//! translation logic. Core identity code carries typed enums; strings are only
//! emitted here because fixture text and demo narratives are external artifacts.

use super::*;

pub(super) fn fact_status_name(status: &FactStatus) -> &'static str {
    match status {
        FactStatus::Active => "active",
        FactStatus::Superseded { .. } => "superseded",
        FactStatus::EnteredInError { .. } => "entered_in_error",
    }
}

pub(super) fn episode_status_name(status: &EpisodeStatus) -> &'static str {
    match status {
        EpisodeStatus::Active => "active",
        EpisodeStatus::Dormant => "dormant",
        EpisodeStatus::Resolved(_) => "resolved",
    }
}

pub(super) fn membership_status_name(status: &MembershipStatus) -> &'static str {
    match status {
        MembershipStatus::Active => "active",
        MembershipStatus::Retracted { .. } => "retracted",
    }
}

pub(super) fn episode_kind_name(kind: EpisodeKind) -> &'static str {
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

pub(super) fn fact_role_name(role: &FactRole) -> &'static str {
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

pub(super) fn subject_kind_name(kind: &SubjectKind) -> &'static str {
    match kind {
        SubjectKind::HumanPerson => "human_person",
        SubjectKind::Organization => "organization",
        SubjectKind::Device => "device",
        SubjectKind::SystemAgent => "system_agent",
    }
}

pub(super) fn assurance_level_name(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Low => "low",
        AssuranceLevel::Medium => "medium",
        AssuranceLevel::High => "high",
        AssuranceLevel::VeryHigh => "very_high",
    }
}

pub(super) fn identity_attribute_name(attribute: &IdentityAttribute) -> &str {
    match attribute {
        IdentityAttribute::LegalName => "legal_name",
        IdentityAttribute::DateOfBirth => "date_of_birth",
        IdentityAttribute::Address => "address",
        IdentityAttribute::PhoneNumber => "phone_number",
        IdentityAttribute::Email => "email",
        IdentityAttribute::SexAdministrative => "sex_administrative",
        IdentityAttribute::Other(value) => value.as_str(),
    }
}

pub(super) fn witness_type_name(witness_type: &IdentityWitnessType) -> &'static str {
    match witness_type {
        IdentityWitnessType::GovernmentIdVerification => "government_id_verification",
        IdentityWitnessType::SelfieLivenessCheck => "selfie_liveness_check",
        IdentityWitnessType::BiometricContinuityCheck => "biometric_continuity_check",
        IdentityWitnessType::PatientPortalLoginProof => "patient_portal_login_proof",
        IdentityWitnessType::ProviderAttestation => "provider_attestation",
        IdentityWitnessType::InPersonClinicVerification => "in_person_clinic_verification",
        IdentityWitnessType::PayerVerification => "payer_verification",
        IdentityWitnessType::InsuranceCardVerification => "insurance_card_verification",
        IdentityWitnessType::DemographicMatch => "demographic_match",
        IdentityWitnessType::DeviceBoundPasskeyAssertion => "device_bound_passkey_assertion",
        IdentityWitnessType::RecoveryKeyPresentation => "recovery_key_presentation",
        IdentityWitnessType::LegalDocument => "legal_document",
    }
}

pub(super) fn modality_name(modality: &BiometricModality) -> &'static str {
    match modality {
        BiometricModality::Face => "face",
        BiometricModality::Fingerprint => "fingerprint",
        BiometricModality::Voice => "voice",
        BiometricModality::Palm => "palm",
        BiometricModality::Other => "other",
    }
}

pub(super) fn authenticator_type_name(authenticator_type: &AuthenticatorType) -> &str {
    match authenticator_type {
        AuthenticatorType::Passkey => "passkey",
        AuthenticatorType::PlatformBiometric => "platform_biometric",
        AuthenticatorType::HardwareSecurityKey => "hardware_security_key",
        AuthenticatorType::AppPushMfa => "app_push_mfa",
        AuthenticatorType::RecoveryKey => "recovery_key",
        AuthenticatorType::Password => "password",
        AuthenticatorType::Other(value) => value.as_str(),
    }
}

pub(super) fn continuity_result_name(result: ContinuityCheckResult) -> &'static str {
    match result {
        ContinuityCheckResult::Passed => "passed",
        ContinuityCheckResult::Failed => "failed",
        ContinuityCheckResult::Inconclusive => "inconclusive",
    }
}

pub(super) fn continuity_rejection_reason_name(
    reason: ContinuityVerificationRejectionReason,
) -> &'static str {
    match reason {
        ContinuityVerificationRejectionReason::InvalidSignature => "invalid_signature",
        ContinuityVerificationRejectionReason::UnknownVerificationKey => "unknown_verification_key",
        ContinuityVerificationRejectionReason::KeyNotAuthorizedForProvider => {
            "key_not_authorized_for_provider"
        }
        ContinuityVerificationRejectionReason::UnknownNonce => "unknown_nonce",
        ContinuityVerificationRejectionReason::ExpiredNonce => "expired_nonce",
        ContinuityVerificationRejectionReason::ReusedNonce => "reused_nonce",
        ContinuityVerificationRejectionReason::EnrollmentReferenceMismatch => {
            "enrollment_reference_mismatch"
        }
        ContinuityVerificationRejectionReason::TimestampOutsideAllowedWindow => {
            "timestamp_outside_allowed_window"
        }
        ContinuityVerificationRejectionReason::ModalityNotAllowed => "modality_not_allowed",
        ContinuityVerificationRejectionReason::PolicyRejectedAssuranceMapping => {
            "policy_rejected_assurance_mapping"
        }
        ContinuityVerificationRejectionReason::MalformedAssertion => "malformed_assertion",
    }
}

pub(super) fn credential_result_name(result: CredentialAssertionResult) -> &'static str {
    match result {
        CredentialAssertionResult::Succeeded => "succeeded",
        CredentialAssertionResult::Failed => "failed",
        CredentialAssertionResult::Inconclusive => "inconclusive",
    }
}

pub(super) fn match_confidence_name(confidence: MatchConfidence) -> &'static str {
    match confidence {
        MatchConfidence::Low => "low",
        MatchConfidence::Medium => "medium",
        MatchConfidence::High => "high",
        MatchConfidence::Exact => "exact",
        MatchConfidence::Ambiguous => "ambiguous",
        MatchConfidence::Conflicting => "conflicting",
    }
}

pub(super) fn dispute_outcome_name(outcome: DisputeResolutionOutcome) -> &'static str {
    match outcome {
        DisputeResolutionOutcome::Confirmed => "confirmed",
        DisputeResolutionOutcome::Rejected => "rejected",
        DisputeResolutionOutcome::Inconclusive => "inconclusive",
    }
}

pub(super) fn authority_type_name(authority_type: &AuthorityType) -> &'static str {
    match authority_type {
        AuthorityType::SelfAuthority => "self_authority",
        AuthorityType::CaregiverDelegation => "caregiver_delegation",
        AuthorityType::ParentGuardian => "parent_guardian",
        AuthorityType::LegalProxy => "legal_proxy",
        AuthorityType::PowerOfAttorney => "power_of_attorney",
        AuthorityType::AttorneyClientRepresentative => "attorney_client_representative",
        AuthorityType::EmergencyAccess => "emergency_access",
        AuthorityType::ProviderTreatmentAuthority => "provider_treatment_authority",
        AuthorityType::OrganizationAgentAuthority => "organization_agent_authority",
    }
}

pub(super) fn authorized_action_name(action: &AuthorizedAction) -> &'static str {
    match action {
        AuthorizedAction::ViewRecord => "view_record",
        AuthorizedAction::UploadDocument => "upload_document",
        AuthorizedAction::ShareRecord => "share_record",
        AuthorizedAction::ScheduleCare => "schedule_care",
        AuthorizedAction::ManageBilling => "manage_billing",
        AuthorizedAction::LinkProvider => "link_provider",
        AuthorizedAction::ExportRecord => "export_record",
        AuthorizedAction::AuthorizeDataTransaction => "authorize_data_transaction",
        AuthorizedAction::DelegateAuthority => "delegate_authority",
        AuthorizedAction::RevokeAuthority => "revoke_authority",
    }
}

pub(super) fn recovery_method_name(method: &RecoveryMethod) -> &'static str {
    match method {
        RecoveryMethod::ExistingTrustedDevice => "existing_trusted_device",
        RecoveryMethod::RecoveryKey => "recovery_key",
        RecoveryMethod::GovernmentIdAndLiveness => "government_id_and_liveness",
        RecoveryMethod::ProviderAttestation => "provider_attestation",
        RecoveryMethod::PayerVerification => "payer_verification",
        RecoveryMethod::ManualReview => "manual_review",
    }
}

pub(super) fn recovery_result_name(result: RecoveryResult) -> &'static str {
    match result {
        RecoveryResult::Approved => "approved",
        RecoveryResult::Denied => "denied",
        RecoveryResult::PendingManualReview => "pending_manual_review",
    }
}

pub(super) fn sensitive_action_name(action: SensitiveAction) -> &'static str {
    match action {
        SensitiveAction::ViewRecord => "view_record",
        SensitiveAction::ShareRecord => "share_record",
        SensitiveAction::ExportCompleteRecord => "export_complete_record",
        SensitiveAction::LinkProvider => "link_provider",
        SensitiveAction::LinkPayer => "link_payer",
        SensitiveAction::ChangeRecoveryMethod => "change_recovery_method",
        SensitiveAction::DelegateAuthority => "delegate_authority",
        SensitiveAction::RevokeAuthority => "revoke_authority",
        SensitiveAction::AuthorizeDataTransaction => "authorize_data_transaction",
        SensitiveAction::EmergencyAccess => "emergency_access",
    }
}

pub(super) fn risk_result_name(result: RiskEvaluationResult) -> &'static str {
    match result {
        RiskEvaluationResult::Passed => "passed",
        RiskEvaluationResult::Failed => "failed",
        RiskEvaluationResult::RequiresStepUp => "requires_step_up",
        RiskEvaluationResult::RequiresManualReview => "requires_manual_review",
    }
}

pub(super) fn access_decision_name(decision: AccessDecisionResult) -> &'static str {
    match decision {
        AccessDecisionResult::Allowed => "allowed",
        AccessDecisionResult::Denied => "denied",
        AccessDecisionResult::StepUpRequired => "step_up_required",
        AccessDecisionResult::ManualReviewRequired => "manual_review_required",
    }
}
