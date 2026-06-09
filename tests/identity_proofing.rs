use identity_model::*;

mod common;
use common::*;

#[test]
fn persona_provider_verifies_normalized_identity_proofing_evidence() {
    let provider = PersonaIdentityProofingProvider::new();
    let request = persona_identity_proofing_request("provider-boundary");

    let verified = provider
        .verify_identity_proofing(&request, &ts("2026-05-29T00:05:30Z"))
        .expect("Persona-normalized proofing evidence should verify");

    assert_eq!(verified.provider_name, PERSONA_PROVIDER_NAME);
    assert_eq!(verified.workflow_id, "persona-workflow-provider-boundary");
    assert_eq!(
        verified.identity_witness_type(),
        IdentityWitnessType::GovernmentIdVerification
    );
    assert!(verified
        .passed_at(&ts("2026-05-29T00:05:30Z"))
        .expect("timestamp should parse"));
    assert_eq!(verified.asserted_attributes.len(), 2);
    assert!(verified.external_refs().iter().any(|external_ref| {
        external_ref.resource_type.as_deref() == Some("identity_proofing_audit")
            && external_ref.resource_id == "persona-audit-provider-boundary"
    }));
}

#[test]
fn persona_provider_rejects_wrong_provider_and_future_verification_time() {
    let provider = PersonaIdentityProofingProvider::new();
    let mut wrong_provider = persona_identity_proofing_request("wrong-provider");
    wrong_provider.provider_name = "OtherProofingVendor".to_string();
    assert_eq!(
        provider.verify_identity_proofing(&wrong_provider, &ts("2026-05-29T00:05:30Z")),
        Err(IdentityProofingVerificationError::ProviderMismatch)
    );

    let mut future = persona_identity_proofing_request("future-proofing");
    future.verified_at = ts("2026-05-29T00:07:00Z");
    assert_eq!(
        provider.verify_identity_proofing(&future, &ts("2026-05-29T00:05:30Z")),
        Err(IdentityProofingVerificationError::FutureVerificationTimestamp)
    );
}

#[test]
fn expired_or_policy_affecting_identity_proofing_requires_manual_review() {
    let provider = PersonaIdentityProofingProvider::new();
    let mut expired = persona_identity_proofing_request("expired-proofing");
    expired.expires_at = Some(ts("2026-05-29T00:05:00Z"));
    let verified_expired = provider
        .verify_identity_proofing(&expired, &ts("2026-05-29T00:05:30Z"))
        .expect("expired proofing evidence should remain auditable");
    assert!(verified_expired
        .requires_manual_review_at(&ts("2026-05-29T00:05:30Z"))
        .expect("timestamp should parse"));

    let mut risky = persona_identity_proofing_request("risky-proofing");
    risky.risk_signals.push(IdentityProofingRiskSignal {
        signal_type: "document_tamper_risk".to_string(),
        action: SensitiveAction::AuthorizeDataTransaction,
        result: RiskEvaluationResult::RequiresManualReview,
        required_assurance: AssuranceLevel::High,
        affects_policy: true,
    });
    let verified_risky = provider
        .verify_identity_proofing(&risky, &ts("2026-05-29T00:05:30Z"))
        .expect("risk proofing evidence should verify into manual review");
    assert!(verified_risky.risk_requires_manual_review());
    assert_eq!(verified_risky.mapped_fact_count(), 4);
}
