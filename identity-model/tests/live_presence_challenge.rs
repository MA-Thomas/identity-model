use identity_model::*;

mod common;
use common::*;

#[test]
fn live_presence_challenge_consumes_passed_ceremony_once() {
    let subject_id: SubjectId = id("subject-live-presence");
    let evidence = mobile_evidence_fixture(
        "live-presence",
        "live-presence-token",
        "live-presence-app-attest",
        "iphone-live-presence",
    );
    let app_attest = verified_app_attest(&evidence);
    let ceremony = liveness_ceremony(
        "live-presence",
        &evidence,
        IdentityWitnessResult::Passed,
        PresentationAttackDetectionResult::Passed,
        AssuranceLevel::High,
    );
    let store = InMemoryLivePresenceChallengeStore::new();
    store
        .issue_live_presence_challenge(onboarding_challenge(
            "challenge-live-presence",
            &subject_id,
            &evidence,
            ts("2026-05-29T00:04:55Z"),
            ts("2026-05-29T00:06:00Z"),
        ))
        .expect("challenge should issue");

    let consumed = store
        .consume_verified_live_presence_challenge(
            &ceremony,
            &app_attest,
            &subject_id,
            &ts("2026-05-29T00:05:30Z"),
        )
        .expect("passed ceremony should consume challenge");

    assert!(matches!(
        consumed.status,
        LivePresenceChallengeStatus::Used {
            used_at,
            provider_event_id: Some(ref provider_event_id),
        } if used_at == ts("2026-05-29T00:05:30Z")
            && provider_event_id == "liveness-event-live-presence"
    ));
    assert_eq!(
        store.consume_verified_live_presence_challenge(
            &ceremony,
            &app_attest,
            &subject_id,
            &ts("2026-05-29T00:05:31Z"),
        ),
        Err(LivePresenceChallengeError::ChallengeAlreadyConsumed)
    );
}

#[test]
fn liveness_provider_callback_verifier_maps_normalized_result_without_raw_media() {
    let verifier = StaticLivenessProviderCallbackVerifier::new(
        "MockLivePresenceProvider",
        "valid-callback-assertion",
    );

    let verified = verifier
        .verify_liveness_provider_callback(
            LivenessProviderCallbackVerificationRequest {
                provider_metadata: ContinuityProviderMetadata {
                    provider_name: "MockLivePresenceProvider".to_string(),
                    provider_event_id: Some("callback-event-1".to_string()),
                    provider_subject_ref: Some("callback-subject-1".to_string()),
                    sdk_or_api_version: Some("mock-live-presence-v1".to_string()),
                },
                assertion: "valid-callback-assertion".to_string(),
                challenge_nonce: "callback-nonce-1".to_string(),
                device_ref: "iphone-callback-device".to_string(),
                observed_at: ts("2026-05-29T00:05:10Z"),
                expires_at: ts("2026-05-29T00:06:00Z"),
                result: IdentityWitnessResult::Inconclusive,
                assurance_level: AssuranceLevel::Medium,
                pad_result: PresentationAttackDetectionResult::Inconclusive,
                retention_policy_refs: vec![id("live-presence-retention@v1")],
            },
            &ts("2026-05-29T00:05:30Z"),
        )
        .expect("normalized callback evidence should verify");

    assert_eq!(verified.challenge_nonce, "callback-nonce-1");
    assert_eq!(verified.device_ref, "iphone-callback-device");
    assert_eq!(verified.result, IdentityWitnessResult::Inconclusive);
    assert_eq!(
        verified.pad_result,
        PresentationAttackDetectionResult::Inconclusive
    );
    assert_eq!(
        verified.external_refs(),
        vec![
            ExternalRef {
                system: ExternalSystem::ContinuityProvider,
                resource_type: Some("liveness_ceremony_event".to_string()),
                resource_id: "callback-event-1".to_string(),
                uri: None,
            },
            ExternalRef {
                system: ExternalSystem::ContinuityProvider,
                resource_type: Some("liveness_provider_subject".to_string()),
                resource_id: "callback-subject-1".to_string(),
                uri: None,
            },
        ]
    );
}

#[test]
fn live_presence_challenge_records_expiry_and_wrong_device_failures() {
    let subject_id: SubjectId = id("subject-live-presence-expiry");
    let evidence = mobile_evidence_fixture(
        "live-presence-expiry",
        "live-presence-expiry-token",
        "live-presence-expiry-app-attest",
        "iphone-live-presence-expiry",
    );
    let app_attest = verified_app_attest(&evidence);
    let ceremony = liveness_ceremony(
        "live-presence-expiry",
        &evidence,
        IdentityWitnessResult::Passed,
        PresentationAttackDetectionResult::Passed,
        AssuranceLevel::High,
    );
    let store = InMemoryLivePresenceChallengeStore::new();
    store
        .issue_live_presence_challenge(onboarding_challenge(
            "challenge-live-presence-expired",
            &subject_id,
            &evidence,
            ts("2026-05-29T00:04:00Z"),
            ts("2026-05-29T00:05:00Z"),
        ))
        .expect("challenge should issue");

    assert_eq!(
        store.consume_verified_live_presence_challenge(
            &ceremony,
            &app_attest,
            &subject_id,
            &ts("2026-05-29T00:05:30Z"),
        ),
        Err(LivePresenceChallengeError::ChallengeExpired)
    );
    let expired = store
        .live_presence_challenge_by_nonce(&evidence.app_attest_challenge_nonce)
        .expect("lookup should work")
        .expect("challenge should remain");
    assert!(matches!(
        expired.status,
        LivePresenceChallengeStatus::Expired { expired_at }
            if expired_at == ts("2026-05-29T00:05:30Z")
    ));

    let wrong_device_evidence = mobile_evidence_fixture(
        "live-presence-wrong-device",
        "live-presence-wrong-device-token",
        "live-presence-wrong-device-app-attest",
        "iphone-live-presence-wrong-device",
    );
    let wrong_device_app_attest = verified_app_attest(&wrong_device_evidence);
    let wrong_device_ceremony = liveness_ceremony(
        "live-presence-wrong-device",
        &wrong_device_evidence,
        IdentityWitnessResult::Passed,
        PresentationAttackDetectionResult::Passed,
        AssuranceLevel::High,
    );
    let mut challenge = onboarding_challenge(
        "challenge-live-presence-wrong-device",
        &subject_id,
        &wrong_device_evidence,
        ts("2026-05-29T00:04:55Z"),
        ts("2026-05-29T00:06:00Z"),
    );
    challenge.expected_device_ref = Some("different-iphone".to_string());
    store
        .issue_live_presence_challenge(challenge)
        .expect("wrong-device challenge should issue");

    assert_eq!(
        store.consume_verified_live_presence_challenge(
            &wrong_device_ceremony,
            &wrong_device_app_attest,
            &subject_id,
            &ts("2026-05-29T00:05:30Z"),
        ),
        Err(LivePresenceChallengeError::DeviceMismatch)
    );
    let failed = store
        .live_presence_challenge_by_nonce(&wrong_device_evidence.app_attest_challenge_nonce)
        .expect("lookup should work")
        .expect("challenge should remain");
    assert!(matches!(
        failed.status,
        LivePresenceChallengeStatus::Failed {
            reason: LivePresenceChallengeFailureReason::DeviceMismatch,
            ..
        }
    ));
}

#[test]
fn live_presence_challenge_records_failed_and_manual_review_ceremonies() {
    let subject_id: SubjectId = id("subject-live-presence-results");
    for (label, result, pad_result, expected_status) in [
        (
            "live-presence-failed",
            IdentityWitnessResult::Failed,
            PresentationAttackDetectionResult::Failed,
            "failed",
        ),
        (
            "live-presence-inconclusive",
            IdentityWitnessResult::Inconclusive,
            PresentationAttackDetectionResult::Inconclusive,
            "manual_review",
        ),
    ] {
        let evidence = mobile_evidence_fixture(
            label,
            &format!("{label}-token"),
            &format!("{label}-app-attest"),
            &format!("iphone-{label}"),
        );
        let app_attest = verified_app_attest(&evidence);
        let ceremony = liveness_ceremony(label, &evidence, result, pad_result, AssuranceLevel::Low);
        let store = InMemoryLivePresenceChallengeStore::new();
        store
            .issue_live_presence_challenge(onboarding_challenge(
                &format!("challenge-{label}"),
                &subject_id,
                &evidence,
                ts("2026-05-29T00:04:55Z"),
                ts("2026-05-29T00:06:00Z"),
            ))
            .expect("challenge should issue");

        let consumed = store
            .consume_verified_live_presence_challenge(
                &ceremony,
                &app_attest,
                &subject_id,
                &ts("2026-05-29T00:05:30Z"),
            )
            .expect("verified failed/inconclusive ceremony should consume challenge");

        match (expected_status, consumed.status) {
            (
                "failed",
                LivePresenceChallengeStatus::Failed {
                    reason: LivePresenceChallengeFailureReason::PresentationAttackDetected,
                    ..
                },
            ) => {}
            (
                "manual_review",
                LivePresenceChallengeStatus::ManualReview {
                    reason: LivePresenceChallengeManualReviewReason::LivenessInconclusive,
                    ..
                },
            ) => {}
            (_, status) => panic!("unexpected challenge status: {status:?}"),
        }
    }
}

fn onboarding_challenge(
    challenge_id: &str,
    subject_id: &SubjectId,
    evidence: &MobileEvidenceFixture,
    issued_at: Timestamp,
    expires_at: Timestamp,
) -> LivePresenceChallenge {
    let mut challenge = LivePresenceChallenge::onboarding(
        id(challenge_id),
        evidence.app_attest_challenge_nonce.clone(),
        Some(subject_id.clone()),
        Some(evidence.device_ref.clone()),
        Some(LivePresenceExpectedAppContext::from_app_attest_config(
            &evidence.app_attest_config,
        )),
        issued_at,
        expires_at,
    );
    challenge.retry_policy_refs = vec![id("live-presence-retry@v1")];
    challenge.manual_review_policy_refs = vec![id("live-presence-manual-review@v1")];
    challenge.retention_policy_refs = vec![id("live-presence-retention@v1")];
    challenge
}

fn verified_app_attest(evidence: &MobileEvidenceFixture) -> VerifiedAppAttestAssertion {
    evidence
        .app_attest_verifier
        .verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: evidence.app_attest_assertion.clone(),
                challenge_nonce: evidence.app_attest_challenge_nonce.clone(),
                config: evidence.app_attest_config.clone(),
            },
            &ts("2026-05-29T00:05:30Z"),
        )
        .expect("fixture app attest should verify")
}

fn liveness_ceremony(
    label: &str,
    evidence: &MobileEvidenceFixture,
    result: IdentityWitnessResult,
    pad_result: PresentationAttackDetectionResult,
    assurance_level: AssuranceLevel,
) -> VerifiedLivenessCeremony {
    VerifiedLivenessCeremony {
        provider_metadata: ContinuityProviderMetadata {
            provider_name: "MockLivePresenceProvider".to_string(),
            provider_event_id: Some(format!("liveness-event-{label}")),
            provider_subject_ref: Some(format!("liveness-subject-{label}")),
            sdk_or_api_version: Some("mock-live-presence-v1".to_string()),
        },
        challenge_nonce: evidence.app_attest_challenge_nonce.clone(),
        device_ref: evidence.device_ref.clone(),
        observed_at: ts("2026-05-29T00:05:20Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        result,
        assurance_level,
        pad_result,
        retention_policy_refs: vec![id("live-presence-retention@v1")],
    }
}
