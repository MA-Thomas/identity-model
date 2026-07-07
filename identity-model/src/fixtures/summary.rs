use super::*;

pub(super) fn fact_payload_summary(payload: &FactPayload) -> String {
    match payload {
        FactPayload::SubjectCreated { subject_kind, .. } => {
            format!("SubjectCreated kind={}", subject_kind_name(subject_kind))
        }
        FactPayload::IdentityAttributeAsserted {
            attribute,
            confidence,
            ..
        } => format!(
            "IdentityAttributeAsserted attribute={} confidence={}",
            identity_attribute_name(attribute),
            match_confidence_name(*confidence)
        ),
        FactPayload::IdentityWitnessRecorded {
            witness_type,
            target_subject_id,
            assurance_level,
            ..
        } => format!(
            "IdentityWitnessRecorded type={} target={} assurance={}",
            witness_type_name(witness_type),
            target_subject_id.0,
            assurance_level_name(*assurance_level)
        ),
        FactPayload::BiometricEnrollmentReferenceAdded {
            biometric_system,
            enrollment_ref,
            modality,
        } => format!(
            "BiometricEnrollmentReferenceAdded system={} enrollment={} modality={}",
            biometric_system,
            enrollment_ref,
            modality_name(modality)
        ),
        FactPayload::BiometricContinuityCheck {
            biometric_system,
            enrollment_ref,
            result,
            assurance_level,
        } => format!(
            "BiometricContinuityCheck system={} enrollment={} result={} assurance={}",
            biometric_system,
            enrollment_ref,
            continuity_result_name(*result),
            assurance_level_name(*assurance_level)
        ),
        FactPayload::ContinuityVerificationRejected {
            biometric_system,
            enrollment_ref,
            reason,
            ..
        } => format!(
            "ContinuityVerificationRejected system={} enrollment={} reason={}",
            biometric_system.as_deref().unwrap_or("unknown"),
            enrollment_ref,
            continuity_rejection_reason_name(*reason)
        ),
        FactPayload::DeviceBindingEstablished {
            device_ref,
            authenticator_type,
            assurance_level,
        } => format!(
            "DeviceBindingEstablished device={} authenticator={} assurance={}",
            device_ref,
            authenticator_type_name(authenticator_type),
            assurance_level_name(*assurance_level)
        ),
        FactPayload::DeviceBindingRevoked { device_ref, .. } => {
            format!("DeviceBindingRevoked device={device_ref}")
        }
        FactPayload::CredentialAssertion {
            authenticator_type,
            result,
            assurance_level,
            ..
        } => format!(
            "CredentialAssertion authenticator={} result={} assurance={}",
            authenticator_type_name(authenticator_type),
            credential_result_name(*result),
            assurance_level_name(*assurance_level)
        ),
        FactPayload::ClinicalIdentityLinkEstablished {
            provider_org,
            external_patient_ref,
            match_confidence,
        } => format!(
            "ClinicalIdentityLinkEstablished org={} external={} confidence={}",
            provider_org,
            external_patient_ref.resource_id,
            match_confidence_name(*match_confidence)
        ),
        FactPayload::ClinicalIdentityLinkContested { link_fact_id, .. } => {
            format!("ClinicalIdentityLinkContested link={}", link_fact_id.0)
        }
        FactPayload::ClinicalIdentityLinkDisputeResolved {
            link_fact_id,
            outcome,
            ..
        } => format!(
            "ClinicalIdentityLinkDisputeResolved link={} outcome={}",
            link_fact_id.0,
            dispute_outcome_name(*outcome)
        ),
        FactPayload::PayerIdentityLinkEstablished {
            payer, member_ref, ..
        } => {
            format!("PayerIdentityLinkEstablished payer={payer} member={member_ref}")
        }
        FactPayload::PayerIdentityLinkContested { link_fact_id, .. } => {
            format!("PayerIdentityLinkContested link={}", link_fact_id.0)
        }
        FactPayload::PayerIdentityLinkDisputeResolved {
            link_fact_id,
            outcome,
            ..
        } => format!(
            "PayerIdentityLinkDisputeResolved link={} outcome={}",
            link_fact_id.0,
            dispute_outcome_name(*outcome)
        ),
        FactPayload::DuplicateSubjectMergeRecorded {
            surviving_subject_id,
            merged_subject_ids,
            ..
        } => format!(
            "DuplicateSubjectMergeRecorded surviving={} merged={}",
            surviving_subject_id.0,
            join_ids(merged_subject_ids)
        ),
        FactPayload::IncorrectMergeSplitRecorded {
            prior_subject_id,
            restored_subject_ids,
            ..
        } => format!(
            "IncorrectMergeSplitRecorded prior={} restored={}",
            prior_subject_id.0,
            join_ids(restored_subject_ids)
        ),
        FactPayload::IdentityWitnessSuperseded {
            superseded_witness_fact_id,
            replacement_witness_fact_id,
            ..
        } => format!(
            "IdentityWitnessSuperseded old={} replacement={}",
            superseded_witness_fact_id.0, replacement_witness_fact_id.0
        ),
        FactPayload::AuthorityRelationshipEstablished {
            actor_subject_id,
            target_subject_id,
            authority_type,
            ..
        } => format!(
            "AuthorityRelationshipEstablished actor={} target={} type={}",
            actor_subject_id.0,
            target_subject_id.0,
            authority_type_name(authority_type)
        ),
        FactPayload::AuthorityRelationshipRevoked {
            relationship_fact_id,
            ..
        } => format!(
            "AuthorityRelationshipRevoked relationship={}",
            relationship_fact_id.0
        ),
        FactPayload::AccountRecoveryEvent {
            method,
            result,
            assurance_level,
        } => format!(
            "AccountRecoveryEvent method={} result={} assurance={}",
            recovery_method_name(method),
            recovery_result_name(*result),
            assurance_level_name(*assurance_level)
        ),
        FactPayload::RiskEvaluationEvent {
            action,
            result,
            required_assurance,
        } => format!(
            "RiskEvaluationEvent action={} result={} required_assurance={}",
            sensitive_action_name(*action),
            risk_result_name(*result),
            assurance_level_name(*required_assurance)
        ),
        FactPayload::AccessDecision {
            action, decision, ..
        } => format!(
            "AccessDecision action={} decision={}",
            sensitive_action_name(*action),
            access_decision_name(*decision)
        ),
        FactPayload::Measurement => "Measurement".to_string(),
        FactPayload::Prescription => "Prescription".to_string(),
        FactPayload::Procedure => "Procedure".to_string(),
        FactPayload::Diagnosis => "Diagnosis".to_string(),
        FactPayload::Document => "Document".to_string(),
        FactPayload::Coverage => "Coverage".to_string(),
        FactPayload::Claim => "Claim".to_string(),
    }
}
