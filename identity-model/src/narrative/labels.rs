use super::*;

pub(crate) fn risk_result_name(result: RiskEvaluationResult) -> &'static str {
    match result {
        RiskEvaluationResult::Passed => "passed",
        RiskEvaluationResult::Failed => "failed",
        RiskEvaluationResult::RequiresStepUp => "requires_step_up",
        RiskEvaluationResult::RequiresManualReview => "requires_manual_review",
    }
}

pub(crate) fn match_confidence_name(confidence: MatchConfidence) -> &'static str {
    match confidence {
        MatchConfidence::Low => "low",
        MatchConfidence::Medium => "medium",
        MatchConfidence::High => "high",
        MatchConfidence::Exact => "exact",
        MatchConfidence::Ambiguous => "ambiguous",
        MatchConfidence::Conflicting => "conflicting",
    }
}

pub(crate) fn credential_result_name(result: CredentialAssertionResult) -> &'static str {
    match result {
        CredentialAssertionResult::Succeeded => "succeeded",
        CredentialAssertionResult::Failed => "failed",
        CredentialAssertionResult::Inconclusive => "inconclusive",
    }
}

pub(crate) fn continuity_rejection_reason_name(
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

pub(crate) fn continuity_result_name(result: ContinuityCheckResult) -> &'static str {
    match result {
        ContinuityCheckResult::Passed => "passed",
        ContinuityCheckResult::Failed => "failed",
        ContinuityCheckResult::Inconclusive => "inconclusive",
    }
}

pub(crate) fn authenticator_type_name(authenticator_type: &AuthenticatorType) -> &str {
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

pub(crate) fn modality_name(modality: &BiometricModality) -> &'static str {
    match modality {
        BiometricModality::Face => "face",
        BiometricModality::Fingerprint => "fingerprint",
        BiometricModality::Voice => "voice",
        BiometricModality::Palm => "palm",
        BiometricModality::Other => "other",
    }
}

pub(crate) fn witness_type_name(witness_type: &IdentityWitnessType) -> &'static str {
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

pub(crate) fn identity_attribute_name(attribute: &IdentityAttribute) -> &str {
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

pub(crate) fn subject_kind_name(kind: &SubjectKind) -> &'static str {
    match kind {
        SubjectKind::HumanPerson => "human_person",
        SubjectKind::Organization => "organization",
        SubjectKind::Device => "device",
        SubjectKind::SystemAgent => "system_agent",
    }
}

pub(crate) fn authorized_action_name(action: &AuthorizedAction) -> &'static str {
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

pub(crate) fn access_decision_name(decision: AccessDecisionResult) -> &'static str {
    match decision {
        AccessDecisionResult::Allowed => "allowed",
        AccessDecisionResult::Denied => "denied",
        AccessDecisionResult::StepUpRequired => "step_up_required",
        AccessDecisionResult::ManualReviewRequired => "manual_review_required",
    }
}

pub(crate) fn sensitive_action_name(action: SensitiveAction) -> &'static str {
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

pub(crate) fn recovery_result_name(result: RecoveryResult) -> &'static str {
    match result {
        RecoveryResult::Approved => "approved",
        RecoveryResult::Denied => "denied",
        RecoveryResult::PendingManualReview => "pending_manual_review",
    }
}

pub(crate) fn recovery_method_name(method: &RecoveryMethod) -> &'static str {
    match method {
        RecoveryMethod::ExistingTrustedDevice => "existing_trusted_device",
        RecoveryMethod::RecoveryKey => "recovery_key",
        RecoveryMethod::GovernmentIdAndLiveness => "government_id_and_liveness",
        RecoveryMethod::ProviderAttestation => "provider_attestation",
        RecoveryMethod::PayerVerification => "payer_verification",
        RecoveryMethod::ManualReview => "manual_review",
    }
}

pub(crate) fn authority_type_name(authority_type: &AuthorityType) -> &'static str {
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

pub(crate) fn dispute_outcome_name(outcome: DisputeResolutionOutcome) -> &'static str {
    match outcome {
        DisputeResolutionOutcome::Confirmed => "confirmed",
        DisputeResolutionOutcome::Rejected => "rejected",
        DisputeResolutionOutcome::Inconclusive => "inconclusive",
    }
}

pub(crate) fn assurance_level_name(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Low => "low",
        AssuranceLevel::Medium => "medium",
        AssuranceLevel::High => "high",
        AssuranceLevel::VeryHigh => "very_high",
    }
}
