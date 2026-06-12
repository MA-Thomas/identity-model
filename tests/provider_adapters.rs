use identity_model::*;

mod common;
use common::*;

#[test]
fn provider_swap_preserves_canonical_continuity_and_policy_shape() {
    let subject_id: SubjectId = id("subject-provider-swap");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let phase1_provider = MockPhase1ContinuityProvider::successful();
    let hosted_provider = MockHostedContinuityProvider::successful();

    let mut phase1_lifecycle = InMemoryNonceLifecycle::new();
    let phase1_slice = complete_record_export_step_up_slice(
        subject_id.clone(),
        "enrollment-provider-swap".to_string(),
        &phase1_provider,
        &mut phase1_lifecycle,
        &phase1_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("phase 1 provider should drive step-up");

    let mut hosted_lifecycle = InMemoryNonceLifecycle::new();
    let hosted_slice = complete_record_export_step_up_slice(
        subject_id,
        "enrollment-provider-swap".to_string(),
        &hosted_provider,
        &mut hosted_lifecycle,
        &hosted_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("hosted provider should drive the same step-up shape");

    let phase1_continuity = continuity_result_shape(&phase1_slice.facts);
    let hosted_continuity = continuity_result_shape(&hosted_slice.facts);
    assert_eq!(phase1_continuity, hosted_continuity);
    assert_eq!(
        access_decision_shape(&phase1_slice.facts),
        access_decision_shape(&hosted_slice.facts)
    );
}

#[test]
fn scripted_hosted_adapter_maps_provider_shapes_without_changing_fen_facts() {
    let subject_id: SubjectId = id("subject-scripted-hosted");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let mock_provider = MockPhase1ContinuityProvider::successful();
    let hosted_adapter = ScriptedHostedContinuityAdapter::successful("ScriptedHostedVault");

    let enrollment = hosted_adapter
        .enroll(ContinuityEnrollmentRequest {
            subject_id: subject_id.clone(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        })
        .expect("hosted enrollment should map");
    assert_eq!(enrollment.enrollment_ref, "hosted-enrollment-demo");
    assert_eq!(
        hosted_adapter.enrollment_request(&ContinuityEnrollmentRequest {
            subject_id: subject_id.clone(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        }),
        HostedEnrollmentRequest {
            external_subject_ref: "fen-subject-subject-scripted-hosted".to_string(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        }
    );

    let mut mock_lifecycle = InMemoryNonceLifecycle::new();
    let mock_slice = complete_record_export_step_up_slice(
        subject_id.clone(),
        "hosted-enrollment-demo".to_string(),
        &mock_provider,
        &mut mock_lifecycle,
        &mock_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("mock provider should drive step-up");

    let mut hosted_lifecycle = InMemoryNonceLifecycle::new();
    let hosted_slice = complete_record_export_step_up_slice(
        subject_id,
        "hosted-enrollment-demo".to_string(),
        &hosted_adapter,
        &mut hosted_lifecycle,
        &hosted_adapter.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("scripted hosted provider should drive step-up");

    assert_eq!(
        continuity_result_shape(&mock_slice.facts),
        continuity_result_shape(&hosted_slice.facts)
    );
    assert_eq!(
        access_decision_shape(&mock_slice.facts),
        access_decision_shape(&hosted_slice.facts)
    );
}

#[cfg(feature = "ed25519-dalek-verifier")]
#[test]
fn fen_native_ed25519_hosted_adapter_drives_service_step_up() {
    let subject_id: SubjectId = id("subject-ed25519-provider");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let provider = FenNativeEd25519HostedContinuityAdapter::successful(
        "FenNativeHostedVault",
        "fen-native-key-1",
        [11; 32],
    );
    let verifier = provider.signature_verifier();
    let mut lifecycle = InMemoryNonceLifecycle::new();

    let slice = complete_record_export_step_up_slice(
        subject_id,
        "hosted-enrollment-demo".to_string(),
        &provider,
        &mut lifecycle,
        &verifier,
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("FEN-native Ed25519 provider should drive step-up");

    assert_eq!(
        verifier
            .key_registry
            .active_keys_for_provider("FenNativeHostedVault")
            .len(),
        1
    );
    assert!(verifier
        .key_registry
        .retired_keys_for_provider("FenNativeHostedVault")
        .is_empty());
    assert!(slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::BiometricContinuityCheck {
            biometric_system,
            result: ContinuityCheckResult::Passed,
            assurance_level: AssuranceLevel::High,
            ..
        } if biometric_system == "FenNativeHostedVault"
    )));
    assert!(slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::AccessDecision {
            decision: AccessDecisionResult::Allowed,
            ..
        }
    )));
}

#[cfg(feature = "ed25519-dalek-verifier")]
#[test]
fn fen_native_ed25519_rotation_and_nonce_failures_remain_typed() {
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: system_author(),
    });
    let mapper = ResultBasedAssuranceMapper;
    let original_provider = FenNativeEd25519HostedContinuityAdapter::successful(
        "FenNativeRotatingVault",
        "fen-native-key-old",
        [12; 32],
    );
    let rotated_provider = original_provider
        .clone()
        .with_rotated_signing_key("fen-native-key-new", [13; 32]);
    let rotated_verifier = rotated_provider.signature_verifier();
    assert_eq!(
        rotated_verifier
            .key_registry
            .active_keys_for_provider("FenNativeRotatingVault")
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>(),
        vec!["fen-native-key-new".to_string()]
    );
    assert_eq!(
        rotated_verifier
            .key_registry
            .retired_keys_for_provider("FenNativeRotatingVault")
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>(),
        vec!["fen-native-key-old".to_string()]
    );

    let mut lifecycle = InMemoryNonceLifecycle::new();
    let challenge = service
        .issue_continuity_challenge(
            ContinuityChallengeRequest {
                challenge_id: id("challenge-ed25519-retired-key"),
                subject_id: id("subject-ed25519-retired-key"),
                enrollment_ref: "hosted-enrollment-demo".to_string(),
                nonce: "nonce-export-step-up".to_string(),
                issued_at: ts("2026-05-29T00:00:00Z"),
                expires_at: ts("2026-05-29T00:10:00Z"),
                intended_action: Some(SensitiveAction::ExportCompleteRecord),
            },
            &mut lifecycle,
        )
        .expect("challenge should issue");
    let signed_with_retired_key = original_provider
        .signed_assertion(challenge)
        .expect("original provider should sign with retired key");

    assert_eq!(
        service.verify_continuity_assertion(
            signed_with_retired_key.clone(),
            &mut lifecycle,
            &rotated_verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::UnknownVerificationKey
        }
    );

    let mut wrong_key_lifecycle = InMemoryNonceLifecycle::new();
    wrong_key_lifecycle
        .issue_challenge(ContinuityChallenge {
            challenge_id: id("challenge-ed25519-wrong-key"),
            subject_id: id("subject-ed25519-wrong-key"),
            enrollment_ref: "hosted-enrollment-demo".to_string(),
            nonce: "nonce-export-step-up".to_string(),
            issued_at: ts("2026-05-29T00:00:00Z"),
            expires_at: ts("2026-05-29T00:10:00Z"),
            intended_action: Some(SensitiveAction::ExportCompleteRecord),
        })
        .expect("challenge should issue");
    let mut wrong_key_assertion = signed_with_retired_key.clone();
    wrong_key_assertion.key_id = "fen-native-key-new".to_string();
    assert_eq!(
        service.verify_continuity_assertion(
            wrong_key_assertion,
            &mut wrong_key_lifecycle,
            &rotated_verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::InvalidSignature
        }
    );

    let active_provider = FenNativeEd25519HostedContinuityAdapter::successful(
        "FenNativeNonceVault",
        "fen-native-key-active",
        [14; 32],
    );
    let active_verifier = active_provider.signature_verifier();
    let mut replay_lifecycle = InMemoryNonceLifecycle::new();
    let replay_challenge = service
        .issue_continuity_challenge(
            ContinuityChallengeRequest {
                challenge_id: id("challenge-ed25519-replay"),
                subject_id: id("subject-ed25519-replay"),
                enrollment_ref: "hosted-enrollment-demo".to_string(),
                nonce: "nonce-export-step-up".to_string(),
                issued_at: ts("2026-05-29T00:00:00Z"),
                expires_at: ts("2026-05-29T00:10:00Z"),
                intended_action: Some(SensitiveAction::ExportCompleteRecord),
            },
            &mut replay_lifecycle,
        )
        .expect("challenge should issue");
    let replay_assertion = active_provider
        .signed_assertion(replay_challenge)
        .expect("active provider should sign");
    assert!(matches!(
        service.verify_continuity_assertion(
            replay_assertion.clone(),
            &mut replay_lifecycle,
            &active_verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Verified { .. }
    ));
    assert_eq!(
        service.verify_continuity_assertion(
            replay_assertion,
            &mut replay_lifecycle,
            &active_verifier,
            &mapper,
            ts("2026-05-29T00:02:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::ReusedNonce
        }
    );

    let mut expired_lifecycle = InMemoryNonceLifecycle::new();
    let expired_challenge = service
        .issue_continuity_challenge(
            ContinuityChallengeRequest {
                challenge_id: id("challenge-ed25519-expired"),
                subject_id: id("subject-ed25519-expired"),
                enrollment_ref: "hosted-enrollment-demo".to_string(),
                nonce: "nonce-export-step-up".to_string(),
                issued_at: ts("2026-05-29T00:00:00Z"),
                expires_at: ts("2026-05-29T00:00:30Z"),
                intended_action: Some(SensitiveAction::ExportCompleteRecord),
            },
            &mut expired_lifecycle,
        )
        .expect("challenge should issue");
    let expired_assertion = active_provider
        .signed_assertion(expired_challenge)
        .expect("active provider should sign");
    assert_eq!(
        service.verify_continuity_assertion(
            expired_assertion,
            &mut expired_lifecycle,
            &active_verifier,
            &mapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::ExpiredNonce
        }
    );
}
