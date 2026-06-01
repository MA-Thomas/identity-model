use identity_model::*;

mod common;
use common::*;

#[test]
fn stateful_app_attest_verifier_records_key_state_and_rejects_replayed_challenge() {
    let config = app_attest_config();
    let assertion = verified_assertion(
        &config,
        "iphone-stateful-device",
        "key-stateful",
        "nonce-1",
        7,
    );
    let store = InMemoryAppAttestKeyStateStore::new();
    let verifier = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new("assertion-1", assertion.clone()),
        store.clone(),
    );
    let request = AppAttestAssertionVerificationRequest {
        assertion: "assertion-1".to_string(),
        challenge_nonce: "nonce-1".to_string(),
        config: config.clone(),
    };

    let verified = verifier
        .verify_app_attest_assertion(&request, &ts("2026-05-29T00:05:30Z"))
        .expect("first verified assertion should record key state");
    assert_eq!(verified, assertion);

    let state = store
        .app_attest_key_state("key-stateful")
        .expect("state lookup should succeed")
        .expect("verified key should have state");
    assert_eq!(state.device_ref, "iphone-stateful-device");
    assert_eq!(state.last_sign_count, 7);
    assert_eq!(state.last_challenge_nonce, Some("nonce-1".to_string()));
    assert!(store
        .app_attest_challenge_nonce_seen("key-stateful", "nonce-1")
        .expect("nonce lookup should succeed"));

    assert_eq!(
        verifier.verify_app_attest_assertion(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::ChallengeReplay)
    );
}

#[test]
fn stateful_app_attest_verifier_requires_monotonic_sign_count_and_stable_key_context() {
    let config = app_attest_config();
    let store = InMemoryAppAttestKeyStateStore::new();
    let first = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new(
            "assertion-1",
            verified_assertion(
                &config,
                "iphone-stateful-device",
                "key-stateful",
                "nonce-1",
                7,
            ),
        ),
        store.clone(),
    );
    first
        .verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: "assertion-1".to_string(),
                challenge_nonce: "nonce-1".to_string(),
                config: config.clone(),
            },
            &ts("2026-05-29T00:05:30Z"),
        )
        .expect("first assertion should register state");

    let repeated_sign_count = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new(
            "assertion-2",
            verified_assertion(
                &config,
                "iphone-stateful-device",
                "key-stateful",
                "nonce-2",
                7,
            ),
        ),
        store.clone(),
    );
    assert_eq!(
        repeated_sign_count.verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: "assertion-2".to_string(),
                challenge_nonce: "nonce-2".to_string(),
                config: config.clone(),
            },
            &ts("2026-05-29T00:05:30Z"),
        ),
        Err(AppAttestAssertionVerificationError::SignCountNotAdvanced)
    );

    let changed_device = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new(
            "assertion-3",
            verified_assertion(&config, "different-device", "key-stateful", "nonce-3", 8),
        ),
        store,
    );
    assert_eq!(
        changed_device.verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: "assertion-3".to_string(),
                challenge_nonce: "nonce-3".to_string(),
                config,
            },
            &ts("2026-05-29T00:05:30Z"),
        ),
        Err(AppAttestAssertionVerificationError::KeyContextMismatch)
    );
}

#[test]
fn stateful_app_attest_verifier_rejects_revoked_keys() {
    let config = app_attest_config();
    let store = InMemoryAppAttestKeyStateStore::new();
    let first = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new(
            "assertion-1",
            verified_assertion(
                &config,
                "iphone-stateful-device",
                "key-stateful",
                "nonce-1",
                7,
            ),
        ),
        store.clone(),
    );
    first
        .verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: "assertion-1".to_string(),
                challenge_nonce: "nonce-1".to_string(),
                config: config.clone(),
            },
            &ts("2026-05-29T00:05:30Z"),
        )
        .expect("first assertion should register state");
    store
        .revoke_app_attest_key("key-stateful")
        .expect("registered key should be revocable");

    let after_revoke = StatefulAppAttestAssertionVerifier::new(
        StaticAppAttestAssertionVerifier::new(
            "assertion-2",
            verified_assertion(
                &config,
                "iphone-stateful-device",
                "key-stateful",
                "nonce-2",
                8,
            ),
        ),
        store,
    );
    assert_eq!(
        after_revoke.verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: "assertion-2".to_string(),
                challenge_nonce: "nonce-2".to_string(),
                config,
            },
            &ts("2026-05-29T00:05:30Z"),
        ),
        Err(AppAttestAssertionVerificationError::KeyRevoked)
    );
}

fn app_attest_config() -> AppAttestClientConfig {
    AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    )
}

fn verified_assertion(
    config: &AppAttestClientConfig,
    device_ref: &str,
    key_id: &str,
    challenge_nonce: &str,
    sign_count: u64,
) -> VerifiedAppAttestAssertion {
    VerifiedAppAttestAssertion {
        team_id: config.team_id.clone(),
        bundle_id: config.bundle_id.clone(),
        app_id: config.app_id.clone(),
        environment: config.environment,
        device_ref: device_ref.to_string(),
        key_id: key_id.to_string(),
        challenge_nonce: challenge_nonce.to_string(),
        sign_count,
        asserted_at: ts("2026-05-29T00:05:00Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        assurance_level: AssuranceLevel::Medium,
    }
}
