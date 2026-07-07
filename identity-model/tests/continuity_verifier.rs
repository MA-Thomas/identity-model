use identity_model::*;

mod common;
use common::*;

#[test]
fn verified_continuity_assertion_translates_to_canonical_fact_payload() {
    let subject_id: SubjectId = id("subject-1");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let assertion = ContinuityAssertion {
        enrollment_ref: "enrollment-1".to_string(),
        challenge_nonce: "nonce-1".to_string(),
        timestamp: ts("2026-05-29T01:00:00Z"),
        result: ContinuityCheckResult::Passed,
        derived_assurance: AssuranceLevel::High,
        modality: BiometricModality::Face,
        model_version: Some("model-a".to_string()),
        pad_result: PresentationAttackDetectionResult::Passed,
        provider_metadata: ContinuityProviderMetadata {
            provider_name: "VendorVault".to_string(),
            provider_event_id: Some("event-1".to_string()),
            provider_subject_ref: Some("vendor-subject-1".to_string()),
            sdk_or_api_version: Some("v1".to_string()),
        },
    };

    let draft = translator
        .verified_continuity_assertion(
            subject_id,
            ContinuityAssertionVerificationResult::Verified {
                assertion,
                assurance_level: AssuranceLevel::High,
            },
        )
        .expect("verified assertion should produce a fact draft");

    assert_eq!(
        draft.payload,
        FactPayload::BiometricContinuityCheck {
            biometric_system: "VendorVault".to_string(),
            enrollment_ref: "enrollment-1".to_string(),
            result: ContinuityCheckResult::Passed,
            assurance_level: AssuranceLevel::High,
        }
    );
    assert_eq!(draft.external_refs.len(), 2);
}

#[test]
fn continuity_nonce_lifecycle_rejects_unknown_expired_reused_and_mismatched_assertions() {
    let subject_id: SubjectId = id("subject-1");
    let provider = MockPhase1ContinuityProvider::successful();
    let verifier = provider.signature_verifier();
    let mapper = ResultBasedAssuranceMapper;
    let mut lifecycle = InMemoryNonceLifecycle::new();
    let challenge = ContinuityChallenge {
        challenge_id: id("challenge-1"),
        subject_id: subject_id.clone(),
        enrollment_ref: "enrollment-1".to_string(),
        nonce: "nonce-1".to_string(),
        issued_at: ts("2026-05-29T00:00:00Z"),
        expires_at: ts("2026-05-29T00:10:00Z"),
        intended_action: Some(SensitiveAction::ExportCompleteRecord),
    };

    lifecycle
        .issue_challenge(challenge.clone())
        .expect("challenge should issue");
    let signed = provider
        .signed_assertion(challenge.clone())
        .expect("mock assertion should be available");
    let mut mismatched = signed.clone();
    mismatched.assertion.enrollment_ref = "wrong-enrollment".to_string();

    assert_eq!(
        verify_signed_continuity_assertion(
            mismatched,
            &mut lifecycle,
            &verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::EnrollmentReferenceMismatch
        }
    );

    assert!(matches!(
        verify_signed_continuity_assertion(
            signed.clone(),
            &mut lifecycle,
            &verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Verified { .. }
    ));
    assert_eq!(
        lifecycle.status(&"nonce-1".to_string()),
        Some(&NonceStatus::Used {
            used_at: ts("2026-05-29T00:01:00Z")
        })
    );
    assert_eq!(
        verify_signed_continuity_assertion(
            signed,
            &mut lifecycle,
            &verifier,
            &mapper,
            ts("2026-05-29T00:02:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::ReusedNonce
        }
    );

    let unknown = SignedContinuityAssertion {
        assertion: ContinuityAssertion {
            enrollment_ref: "enrollment-unknown".to_string(),
            challenge_nonce: "unknown-nonce".to_string(),
            timestamp: ts("2026-05-29T00:00:00Z"),
            result: ContinuityCheckResult::Passed,
            derived_assurance: AssuranceLevel::High,
            modality: BiometricModality::Face,
            model_version: None,
            pad_result: PresentationAttackDetectionResult::Passed,
            provider_metadata: ContinuityProviderMetadata {
                provider_name: "MockPhase1Vault".to_string(),
                provider_event_id: None,
                provider_subject_ref: None,
                sdk_or_api_version: None,
            },
        },
        signature: provider.signature.clone(),
        key_id: provider.key_id.clone(),
    };
    assert_eq!(
        verify_signed_continuity_assertion(
            unknown,
            &mut lifecycle,
            &verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::UnknownNonce
        }
    );

    let expired_challenge = ContinuityChallenge {
        challenge_id: id("challenge-expired"),
        subject_id,
        enrollment_ref: "enrollment-expired".to_string(),
        nonce: "nonce-expired".to_string(),
        issued_at: ts("2026-05-29T00:00:00Z"),
        expires_at: ts("2026-05-29T00:01:00Z"),
        intended_action: None,
    };
    lifecycle
        .issue_challenge(expired_challenge.clone())
        .expect("expired challenge should issue before it expires");
    let expired_signed = provider
        .signed_assertion(expired_challenge)
        .expect("mock assertion should be available");
    assert_eq!(
        verify_signed_continuity_assertion(
            expired_signed,
            &mut lifecycle,
            &verifier,
            &mapper,
            ts("2026-05-29T00:02:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::ExpiredNonce
        }
    );
}

#[test]
fn registry_backed_signature_verifier_handles_key_rotation_and_replay() {
    let subject_id: SubjectId = id("subject-registry");
    let assertion = ContinuityAssertion {
        enrollment_ref: "enrollment-registry".to_string(),
        challenge_nonce: "nonce-registry".to_string(),
        timestamp: ts("2026-05-29T00:01:00Z"),
        result: ContinuityCheckResult::Passed,
        derived_assurance: AssuranceLevel::High,
        modality: BiometricModality::Face,
        model_version: Some("model-a".to_string()),
        pad_result: PresentationAttackDetectionResult::Passed,
        provider_metadata: ContinuityProviderMetadata {
            provider_name: "RegistryVault".to_string(),
            provider_event_id: Some("event-1".to_string()),
            provider_subject_ref: Some("subject-ref".to_string()),
            sdk_or_api_version: Some("v1".to_string()),
        },
    };
    let active_key = VerificationKey {
        key_id: "registry-key-active".to_string(),
        provider_name: "RegistryVault".to_string(),
        key_material: b"active-key-material".to_vec(),
        status: VerificationKeyStatus::Active,
    };
    let retired_key = VerificationKey {
        key_id: "registry-key-retired".to_string(),
        provider_name: "RegistryVault".to_string(),
        key_material: b"retired-key-material".to_vec(),
        status: VerificationKeyStatus::Retired,
    };
    let wrong_provider_key = VerificationKey {
        key_id: "registry-key-wrong-provider".to_string(),
        provider_name: "OtherVault".to_string(),
        key_material: b"active-key-material".to_vec(),
        status: VerificationKeyStatus::Active,
    };
    let mut registry = VerificationKeyRegistry::new();
    registry.register(active_key.clone());
    registry.register(retired_key);
    registry.register(wrong_provider_key);
    let verifier = RegistryBackedSignatureVerifier {
        key_registry: registry,
    };
    let signed = SignedContinuityAssertion {
        assertion: assertion.clone(),
        signature: deterministic_signature_for_test(&assertion, &active_key.key_material),
        key_id: active_key.key_id.clone(),
    };

    assert!(canonical_continuity_assertion_bytes(&assertion)
        .expect("assertion should serialize")
        .starts_with(b"profile=24:fen-continuity-assertion\nprofile_version=2:v1\n"));
    let mut lifecycle = InMemoryNonceLifecycle::new();
    lifecycle
        .issue_challenge(ContinuityChallenge {
            challenge_id: id("challenge-registry"),
            subject_id,
            enrollment_ref: assertion.enrollment_ref.clone(),
            nonce: assertion.challenge_nonce.clone(),
            issued_at: ts("2026-05-29T00:00:00Z"),
            expires_at: ts("2026-05-29T00:10:00Z"),
            intended_action: Some(SensitiveAction::ExportCompleteRecord),
        })
        .expect("challenge should issue");

    assert!(matches!(
        verify_signed_continuity_assertion(
            signed.clone(),
            &mut lifecycle,
            &verifier,
            &ResultBasedAssuranceMapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Verified { .. }
    ));
    assert_eq!(
        verify_signed_continuity_assertion(
            signed,
            &mut lifecycle,
            &verifier,
            &ResultBasedAssuranceMapper,
            ts("2026-05-29T00:02:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::ReusedNonce
        }
    );

    for (key_id, signature, reason) in [
        (
            "missing-key".to_string(),
            deterministic_signature_for_test(&assertion, &active_key.key_material),
            ContinuityAssertionRejectionReason::UnknownVerificationKey,
        ),
        (
            "registry-key-retired".to_string(),
            deterministic_signature_for_test(&assertion, b"retired-key-material"),
            ContinuityAssertionRejectionReason::UnknownVerificationKey,
        ),
        (
            "registry-key-wrong-provider".to_string(),
            deterministic_signature_for_test(&assertion, &active_key.key_material),
            ContinuityAssertionRejectionReason::KeyNotAuthorizedForProvider,
        ),
        (
            active_key.key_id.clone(),
            b"wrong-signature".to_vec(),
            ContinuityAssertionRejectionReason::InvalidSignature,
        ),
        (
            active_key.key_id.clone(),
            Vec::new(),
            ContinuityAssertionRejectionReason::MalformedAssertion,
        ),
    ] {
        let verifier_result = verifier.verify_signature(&SignedContinuityAssertion {
            assertion: assertion.clone(),
            signature,
            key_id,
        });
        assert_eq!(verifier_result, Err(reason));
    }
}

#[cfg(feature = "ed25519-dalek-verifier")]
#[test]
fn ed25519_strict_verifier_checks_canonical_profile_and_key_registry() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let verification_key = VerificationKey {
        key_id: "ed25519-key-active".to_string(),
        provider_name: "Ed25519Vault".to_string(),
        key_material: signing_key.verifying_key().to_bytes().to_vec(),
        status: VerificationKeyStatus::Active,
    };
    let mut registry = VerificationKeyRegistry::new();
    registry.register(verification_key.clone());
    registry.register(VerificationKey {
        key_id: "ed25519-key-retired".to_string(),
        provider_name: "Ed25519Vault".to_string(),
        key_material: signing_key.verifying_key().to_bytes().to_vec(),
        status: VerificationKeyStatus::Retired,
    });
    registry.register(VerificationKey {
        key_id: "ed25519-key-wrong-provider".to_string(),
        provider_name: "OtherVault".to_string(),
        key_material: signing_key.verifying_key().to_bytes().to_vec(),
        status: VerificationKeyStatus::Active,
    });
    registry.register(VerificationKey {
        key_id: "ed25519-key-malformed".to_string(),
        provider_name: "Ed25519Vault".to_string(),
        key_material: vec![1, 2, 3],
        status: VerificationKeyStatus::Active,
    });

    let assertion = ContinuityAssertion {
        enrollment_ref: "ed25519-enrollment".to_string(),
        challenge_nonce: "ed25519-nonce".to_string(),
        timestamp: ts("2026-05-29T00:01:00Z"),
        result: ContinuityCheckResult::Passed,
        derived_assurance: AssuranceLevel::High,
        modality: BiometricModality::Face,
        model_version: Some("model-ed25519".to_string()),
        pad_result: PresentationAttackDetectionResult::Passed,
        provider_metadata: ContinuityProviderMetadata {
            provider_name: "Ed25519Vault".to_string(),
            provider_event_id: Some("event-ed25519".to_string()),
            provider_subject_ref: Some("subject-ed25519".to_string()),
            sdk_or_api_version: Some("v1".to_string()),
        },
    };
    let canonical = canonical_continuity_assertion_bytes(&assertion)
        .expect("assertion should serialize for signing");
    let signature = signing_key.sign(&canonical).to_bytes().to_vec();
    let signed = SignedContinuityAssertion {
        assertion: assertion.clone(),
        signature: signature.clone(),
        key_id: verification_key.key_id.clone(),
    };
    let verifier = Ed25519StrictSignatureVerifier {
        key_registry: registry,
    };

    assert_eq!(verifier.verify_signature(&signed), Ok(()));

    let mut tampered = signed.clone();
    tampered.assertion.challenge_nonce = "tampered-nonce".to_string();
    assert_eq!(
        verifier.verify_signature(&tampered),
        Err(ContinuityAssertionRejectionReason::InvalidSignature)
    );

    for (key_id, signature, reason) in [
        (
            "missing-key".to_string(),
            signature.clone(),
            ContinuityAssertionRejectionReason::UnknownVerificationKey,
        ),
        (
            "ed25519-key-retired".to_string(),
            signature.clone(),
            ContinuityAssertionRejectionReason::UnknownVerificationKey,
        ),
        (
            "ed25519-key-wrong-provider".to_string(),
            signature.clone(),
            ContinuityAssertionRejectionReason::KeyNotAuthorizedForProvider,
        ),
        (
            "ed25519-key-malformed".to_string(),
            signature.clone(),
            ContinuityAssertionRejectionReason::MalformedAssertion,
        ),
        (
            verification_key.key_id.clone(),
            vec![1, 2, 3],
            ContinuityAssertionRejectionReason::MalformedAssertion,
        ),
        (
            verification_key.key_id.clone(),
            [42; 64].to_vec(),
            ContinuityAssertionRejectionReason::InvalidSignature,
        ),
    ] {
        assert_eq!(
            verifier.verify_signature(&SignedContinuityAssertion {
                assertion: assertion.clone(),
                signature,
                key_id,
            }),
            Err(reason)
        );
    }
}
