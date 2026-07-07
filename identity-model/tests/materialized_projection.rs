use identity_model::*;

mod common;
use common::*;

#[test]
fn materialized_state_excludes_revoked_devices_and_contested_links() {
    let subject_id: SubjectId = id("subject-1");
    let clinical_link_id = id("clinical-link");
    let device_ref = "device-1".to_string();
    let facts = vec![
        fact(
            "device-binding",
            subject_id.clone(),
            FactPayload::DeviceBindingEstablished {
                device_ref: device_ref.clone(),
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: AssuranceLevel::Medium,
            },
        ),
        fact(
            "device-revocation",
            subject_id.clone(),
            FactPayload::DeviceBindingRevoked {
                device_ref,
                reason: Some("lost".to_string()),
            },
        ),
        fact(
            "clinical-link",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkEstablished {
                provider_org: "provider-a".to_string(),
                external_patient_ref: ExternalRef {
                    system: ExternalSystem::Fhir,
                    resource_type: Some("Patient".to_string()),
                    resource_id: "patient-1".to_string(),
                    uri: None,
                },
                match_confidence: MatchConfidence::High,
            },
        ),
        fact(
            "clinical-link-contested",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id: clinical_link_id,
                reason: Some("possible wrong patient".to_string()),
            },
        ),
    ];

    let state = materialize_identity_state(subject_id, &facts);

    assert!(state.active_devices.is_empty());
    assert!(state.active_clinical_links.is_empty());
    assert_eq!(state.unresolved_disputes, vec![id("clinical-link")]);
}

#[test]
fn materialized_state_respects_validity_witness_expiration_and_continuity_outcomes() {
    let subject_id: SubjectId = id("subject-materialized");
    let facts = vec![
        fact(
            "expired-witness",
            subject_id.clone(),
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::GovernmentIdVerification,
                target_subject_id: subject_id.clone(),
                assurance_level: AssuranceLevel::High,
                evidence_ref: None,
                expires_at: Some(ts("2026-01-01T00:00:00Z")),
                context: IdentityWitnessContext::default(),
            },
        ),
        fact(
            "failed-continuity",
            subject_id.clone(),
            FactPayload::BiometricContinuityCheck {
                biometric_system: "MockPhase1Vault".to_string(),
                enrollment_ref: "enrollment-1".to_string(),
                result: ContinuityCheckResult::Failed,
                assurance_level: AssuranceLevel::High,
            },
        ),
        fact(
            "active-payer",
            subject_id.clone(),
            FactPayload::PayerIdentityLinkEstablished {
                payer: "Example Payer".to_string(),
                member_ref: "member-1".to_string(),
                effective_period: Some(TimeInterval {
                    start: ts("2026-01-01T00:00:00Z"),
                    end: ts("2026-12-31T23:59:59Z"),
                }),
            },
        ),
        fact(
            "latest-access",
            subject_id.clone(),
            FactPayload::AccessDecision {
                action: SensitiveAction::ExportCompleteRecord,
                decision: AccessDecisionResult::StepUpRequired,
                relied_on_facts: vec![id("failed-continuity")],
                policy_refs: vec![id("complete-record-export-policy")],
            },
        ),
    ];

    let state = materialize_identity_state_at(subject_id, &facts, &ts("2026-06-01T00:00:00Z"));

    assert_eq!(state.assurance_level, AssuranceLevel::Low);
    assert_eq!(state.active_payer_links.len(), 1);
    assert_eq!(state.last_continuity_check, Some(id("failed-continuity")));
    assert_eq!(state.last_successful_continuity_check, None);
    assert_eq!(
        state.latest_access_decisions[0].decision,
        AccessDecisionResult::StepUpRequired
    );
}

#[test]
fn materialized_state_deduplicates_replayed_active_views() {
    let subject_id: SubjectId = id("subject-materialized-dedupe");
    let device_ref = "device-dedupe".to_string();
    let clinical_link = fact(
        "clinical-link-dedupe",
        subject_id.clone(),
        FactPayload::ClinicalIdentityLinkEstablished {
            provider_org: "provider-a".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-dedupe".to_string(),
                uri: None,
            },
            match_confidence: MatchConfidence::High,
        },
    );
    let active_clinical_link = fact(
        "clinical-link-active-dedupe",
        subject_id.clone(),
        FactPayload::ClinicalIdentityLinkEstablished {
            provider_org: "provider-b".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-active-dedupe".to_string(),
                uri: None,
            },
            match_confidence: MatchConfidence::High,
        },
    );
    let facts = vec![
        fact(
            "device-binding-dedupe-a",
            subject_id.clone(),
            FactPayload::DeviceBindingEstablished {
                device_ref: device_ref.clone(),
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: AssuranceLevel::Medium,
            },
        ),
        fact(
            "device-binding-dedupe-b",
            subject_id.clone(),
            FactPayload::DeviceBindingEstablished {
                device_ref: device_ref.clone(),
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: AssuranceLevel::Medium,
            },
        ),
        clinical_link.clone(),
        clinical_link,
        active_clinical_link.clone(),
        active_clinical_link,
        fact(
            "clinical-link-contested-dedupe-a",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id: id("clinical-link-dedupe"),
                reason: Some("possible wrong patient".to_string()),
            },
        ),
        fact(
            "clinical-link-contested-dedupe-b",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id: id("clinical-link-dedupe"),
                reason: Some("possible wrong patient".to_string()),
            },
        ),
    ];

    let state = materialize_identity_state(subject_id, &facts);

    assert_eq!(state.active_devices, vec![device_ref]);
    assert_eq!(state.active_clinical_links.len(), 1);
    assert_eq!(
        state.active_clinical_links[0].source_fact_id,
        id("clinical-link-active-dedupe")
    );
    assert_eq!(state.unresolved_disputes, vec![id("clinical-link-dedupe")]);
}
