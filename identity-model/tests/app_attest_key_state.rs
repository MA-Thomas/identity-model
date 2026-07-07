use identity_model::*;
#[cfg(feature = "production-crypto")]
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};

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

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_assertion_verifier_accepts_signed_challenge_bound_assertion() {
    let config = app_attest_config();
    let (request, public_key_bytes) = signed_apple_app_attest_request(
        &config,
        "iphone-real-device",
        "apple-key-real",
        "server-challenge-real",
        23,
    );
    let verifier = AppleAppAttestAssertionVerifier::with_static_public_key(
        config.clone(),
        "apple-key-real",
        public_key_bytes,
    );

    let verified = verifier
        .verify_app_attest_assertion(&request, &ts("2026-05-29T00:05:30Z"))
        .expect("signed Apple App Attest assertion should verify");

    assert_eq!(verified.device_ref, "iphone-real-device");
    assert_eq!(verified.key_id, "apple-key-real");
    assert_eq!(verified.challenge_nonce, "server-challenge-real");
    assert_eq!(verified.sign_count, 23);
    assert_eq!(verified.app_id, config.app_id);
    assert_eq!(verified.assurance_level, AssuranceLevel::Medium);
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_assertion_verifier_rejects_tampered_challenge_and_signature() {
    let config = app_attest_config();
    let (mut request, public_key_bytes) = signed_apple_app_attest_request(
        &config,
        "iphone-real-device",
        "apple-key-real",
        "server-challenge-real",
        23,
    );
    let verifier = AppleAppAttestAssertionVerifier::with_static_public_key(
        config.clone(),
        "apple-key-real",
        public_key_bytes.clone(),
    );

    request.challenge_nonce = "different-server-challenge".to_string();
    assert_eq!(
        verifier.verify_app_attest_assertion(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::ClientDataHashMismatch)
    );

    let (request, _) = signed_apple_app_attest_request(
        &config,
        "iphone-real-device",
        "apple-key-real",
        "server-challenge-real",
        23,
    );
    let mut evidence = AppleAppAttestAssertionEvidence::from_compact_assertion(&request.assertion)
        .expect("test assertion should decode");
    evidence.signature_der[0] ^= 0x01;
    let tampered_request = AppAttestAssertionVerificationRequest {
        assertion: evidence.to_compact_assertion(),
        ..request
    };

    assert_eq!(
        verifier.verify_app_attest_assertion(&tampered_request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::InvalidSignature)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_assertion_verifier_accepts_raw_cbor_assertion_object_envelope() {
    let config = app_attest_config();
    let (request, public_key_bytes) = signed_apple_app_attest_request(
        &config,
        "iphone-real-device",
        "apple-key-real",
        "server-challenge-real",
        23,
    );
    let evidence = AppleAppAttestAssertionEvidence::from_compact_assertion(&request.assertion)
        .expect("test compact assertion should decode");
    let raw_object_request = AppAttestAssertionVerificationRequest {
        assertion: evidence.to_assertion_object_envelope(),
        ..request
    };
    let verifier = AppleAppAttestAssertionVerifier::with_static_public_key(
        config.clone(),
        "apple-key-real",
        public_key_bytes,
    );

    let verified = verifier
        .verify_app_attest_assertion(&raw_object_request, &ts("2026-05-29T00:05:30Z"))
        .expect("raw assertion object envelope should verify");

    assert_eq!(verified.device_ref, "iphone-real-device");
    assert_eq!(verified.key_id, "apple-key-real");
    assert_eq!(verified.sign_count, 23);
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_assertion_verifier_rejects_malformed_raw_cbor_assertion_object() {
    let config = app_attest_config();
    let malformed_assertion = [
        "apple-app-attest-assertion-object-v1".to_string(),
        test_hex_encode(b"apple-key-real"),
        test_hex_encode(b"iphone-real-device"),
        "a0".to_string(),
        test_hex_encode(b"2026-05-29T00:05:00Z"),
        test_hex_encode(b"2026-05-29T00:06:00Z"),
        "medium".to_string(),
    ]
    .join("|");
    let verifier = AppleAppAttestAssertionVerifier::with_static_public_key(
        config.clone(),
        "apple-key-real",
        vec![4, 1, 2, 3],
    );

    assert_eq!(
        verifier.verify_app_attest_assertion(
            &AppAttestAssertionVerificationRequest {
                assertion: malformed_assertion,
                challenge_nonce: "server-challenge-real".to_string(),
                config,
            },
            &ts("2026-05-29T00:05:30Z")
        ),
        Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_assertion_verifier_rejects_app_id_hash_mismatch() {
    let config = app_attest_config();
    let wrong_app_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.other",
        AppAttestEnvironment::Development,
    );
    let (pkcs8, public_key_bytes) = test_app_attest_key_pair();
    let request = signed_apple_app_attest_request_with_authenticator_config(
        &wrong_app_config,
        &config,
        "iphone-real-device",
        "apple-key-real",
        "server-challenge-real",
        23,
        &pkcs8,
    );
    let verifier = AppleAppAttestAssertionVerifier::with_static_public_key(
        config.clone(),
        "apple-key-real",
        public_key_bytes,
    );

    assert_eq!(
        verifier.verify_app_attest_assertion(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::AppIdHashMismatch)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_records_public_key_for_assertions() {
    let config = app_attest_config();
    let (pkcs8, public_key_bytes) = test_app_attest_key_pair();
    let key_id = "apple-key-registered";
    let fixture = apple_app_attest_key_registration_fixture(
        &config,
        key_id,
        "iphone-registered-device",
        "registration-challenge",
        &public_key_bytes,
    );
    let verifier = test_app_attest_key_registration_verifier(&config, &fixture);

    let registration = verifier
        .verify_app_attest_key_registration(&fixture.request, &ts("2026-05-29T00:05:30Z"))
        .expect("decoded App Attest registration should verify");
    assert_eq!(registration.key_id, key_id);
    assert_eq!(registration.public_key_bytes, public_key_bytes);
    assert_eq!(
        registration.attestation_challenge_nonce,
        "registration-challenge"
    );

    let store = InMemoryAppAttestKeyStateStore::new();
    store
        .record_app_attest_key_registration(&registration)
        .expect("registration should record trusted key");
    let assertion_verifier = AppleAppAttestAssertionVerifier::new(config.clone(), store);
    let assertion_request = signed_apple_app_attest_request_with_key(
        &config,
        "iphone-registered-device",
        key_id,
        "assertion-challenge",
        3,
        &pkcs8,
    );

    let verified = assertion_verifier
        .verify_app_attest_assertion(&assertion_request, &ts("2026-05-29T00:05:30Z"))
        .expect("assertion should resolve trusted key from registration store");
    assert_eq!(verified.key_id, key_id);
    assert_eq!(verified.sign_count, 3);
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_accepts_attestation_object_envelope() {
    let config = app_attest_config();
    let (_, public_key_bytes) = test_app_attest_key_pair();
    let fixture = apple_app_attest_key_registration_fixture(
        &config,
        "apple-key-native",
        "iphone-native-device",
        "registration-challenge",
        &public_key_bytes,
    );
    let envelope = fixture.request.to_attestation_object_envelope();
    let verifier = test_app_attest_key_registration_verifier(&config, &fixture);
    let request =
        AppleAppAttestKeyRegistrationVerificationRequest::from_attestation_object_envelope(
            &envelope, config,
        )
        .expect("native attestation-object envelope should parse");

    let registration = verifier
        .verify_app_attest_key_registration(&request, &ts("2026-05-29T00:05:30Z"))
        .expect("native App Attest registration should verify");

    assert_eq!(registration.key_id, "apple-key-native");
    assert_eq!(registration.device_ref, "iphone-native-device");
    assert_eq!(registration.public_key_bytes, public_key_bytes);
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_rejects_certificate_key_mismatch() {
    let config = app_attest_config();
    let (_, public_key_bytes) = test_app_attest_key_pair();
    let (_, different_public_key_bytes) = test_app_attest_key_pair();
    let fixture = apple_app_attest_key_registration_fixture(
        &config,
        "apple-key-registered",
        "iphone-registered-device",
        "registration-challenge",
        &public_key_bytes,
    );
    let verifier = test_app_attest_key_registration_verifier(&config, &fixture);
    let mut request = fixture.request;
    request.public_key_bytes = different_public_key_bytes;

    assert_eq!(
        verifier.verify_app_attest_key_registration(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::InvalidSignature)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_rejects_bad_certificate_nonce_and_untrusted_root() {
    let config = app_attest_config();
    let (_, public_key_bytes) = test_app_attest_key_pair();
    let fixture = apple_app_attest_key_registration_fixture(
        &config,
        "apple-key-registered",
        "iphone-registered-device",
        "registration-challenge",
        &public_key_bytes,
    );
    let verifier = test_app_attest_key_registration_verifier(&config, &fixture);
    let mut bad_nonce_request = fixture.request.clone();
    let (bad_nonce_chain, _) = test_certificate_chain(&public_key_bytes, b"not-the-right-nonce");
    bad_nonce_request.certificate_chain_der = bad_nonce_chain;
    assert_eq!(
        verifier
            .verify_app_attest_key_registration(&bad_nonce_request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::CertificateNonceMismatch)
    );

    let untrusted_fixture = apple_app_attest_key_registration_fixture(
        &config,
        "apple-key-registered",
        "iphone-registered-device",
        "registration-challenge",
        &public_key_bytes,
    );
    assert_eq!(
        verifier.verify_app_attest_key_registration(
            &untrusted_fixture.request,
            &ts("2026-05-29T00:05:30Z")
        ),
        Err(AppAttestAssertionVerificationError::CertificateChainMismatch)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_rejects_mismatched_credential_and_challenge() {
    let config = app_attest_config();
    let (_, public_key_bytes) = test_app_attest_key_pair();
    let fixture = apple_app_attest_key_registration_fixture(
        &config,
        "apple-key-registered",
        "iphone-registered-device",
        "registration-challenge",
        &public_key_bytes,
    );
    let verifier = test_app_attest_key_registration_verifier(&config, &fixture);
    let mut request = fixture.request.clone();
    request.credential_id = b"different-key-id".to_vec();
    assert_eq!(
        verifier.verify_app_attest_key_registration(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::CredentialIdMismatch)
    );

    let mut request = fixture.request;
    request.challenge_nonce = "different-registration-challenge".to_string();
    assert_eq!(
        verifier.verify_app_attest_key_registration(&request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::ClientDataHashMismatch)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn stateful_apple_app_attest_verifier_keeps_durable_replay_and_counter_guards() {
    let config = app_attest_config();
    let (pkcs8, public_key_bytes) = test_app_attest_key_pair();
    let first_request = signed_apple_app_attest_request_with_key(
        &config,
        "iphone-real-device",
        "apple-key-real-stateful",
        "server-challenge-1",
        7,
        &pkcs8,
    );
    let verifier = StatefulAppAttestAssertionVerifier::with_in_memory_store(
        AppleAppAttestAssertionVerifier::with_static_public_key(
            config.clone(),
            "apple-key-real-stateful",
            public_key_bytes.clone(),
        ),
    );

    verifier
        .verify_app_attest_assertion(&first_request, &ts("2026-05-29T00:05:30Z"))
        .expect("first signed assertion should register key state");
    assert_eq!(
        verifier.verify_app_attest_assertion(&first_request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::ChallengeReplay)
    );

    let stale_counter_request = signed_apple_app_attest_request_with_key(
        &config,
        "iphone-real-device",
        "apple-key-real-stateful",
        "server-challenge-2",
        7,
        &pkcs8,
    );
    assert_eq!(
        verifier.verify_app_attest_assertion(&stale_counter_request, &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::SignCountNotAdvanced)
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

#[cfg(feature = "production-crypto")]
fn signed_apple_app_attest_request(
    config: &AppAttestClientConfig,
    device_ref: &str,
    key_id: &str,
    challenge_nonce: &str,
    sign_count: u32,
) -> (AppAttestAssertionVerificationRequest, Vec<u8>) {
    let (pkcs8, public_key_bytes) = test_app_attest_key_pair();
    (
        signed_apple_app_attest_request_with_key(
            config,
            device_ref,
            key_id,
            challenge_nonce,
            sign_count,
            &pkcs8,
        ),
        public_key_bytes,
    )
}

#[cfg(feature = "production-crypto")]
struct TestAppAttestKeyRegistrationFixture {
    request: AppleAppAttestKeyRegistrationVerificationRequest,
    trusted_root_certificate_der: Vec<u8>,
}

#[cfg(feature = "production-crypto")]
fn test_app_attest_key_registration_verifier(
    config: &AppAttestClientConfig,
    fixture: &TestAppAttestKeyRegistrationFixture,
) -> AppleAppAttestKeyRegistrationVerifier {
    AppleAppAttestKeyRegistrationVerifier::with_trusted_root_certificates(
        config.clone(),
        vec![fixture.trusted_root_certificate_der.clone()],
    )
}

#[cfg(feature = "production-crypto")]
fn apple_app_attest_key_registration_fixture(
    config: &AppAttestClientConfig,
    key_id: &str,
    device_ref: &str,
    challenge_nonce: &str,
    public_key_bytes: &[u8],
) -> TestAppAttestKeyRegistrationFixture {
    let authenticator_data =
        apple_app_attest_registration_authenticator_data(config, key_id, public_key_bytes);
    let client_data_hash = apple_app_attest_client_data_hash(challenge_nonce);
    let expected_nonce = test_app_attest_attestation_nonce(&authenticator_data, &client_data_hash);
    let (certificate_chain_der, trusted_root_certificate_der) =
        test_certificate_chain(public_key_bytes, &expected_nonce);
    TestAppAttestKeyRegistrationFixture {
        request: AppleAppAttestKeyRegistrationVerificationRequest {
            key_id: key_id.to_string(),
            device_ref: device_ref.to_string(),
            public_key_bytes: public_key_bytes.to_vec(),
            certificate_chain_der,
            credential_id: key_id.as_bytes().to_vec(),
            authenticator_data,
            client_data_hash,
            challenge_nonce: challenge_nonce.to_string(),
            registered_at: ts("2026-05-29T00:05:00Z"),
            attestation_format: "apple-app-attest".to_string(),
            config: config.clone(),
        },
        trusted_root_certificate_der,
    }
}

#[cfg(feature = "production-crypto")]
fn test_app_attest_attestation_nonce(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
) -> Vec<u8> {
    let mut nonce_input = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    nonce_input.extend_from_slice(authenticator_data);
    nonce_input.extend_from_slice(client_data_hash);
    ring::digest::digest(&ring::digest::SHA256, &nonce_input)
        .as_ref()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
fn apple_app_attest_registration_authenticator_data(
    config: &AppAttestClientConfig,
    key_id: &str,
    public_key_bytes: &[u8],
) -> Vec<u8> {
    let credential_id = key_id.as_bytes();
    let mut authenticator_data = apple_app_attest_app_id_hash(config);
    authenticator_data.push(0x41);
    authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
    authenticator_data.extend_from_slice(b"appattestdevelop");
    authenticator_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    authenticator_data.extend_from_slice(credential_id);
    authenticator_data.extend_from_slice(&test_cose_p256_public_key(public_key_bytes));
    authenticator_data
}

#[cfg(feature = "production-crypto")]
fn test_cose_p256_public_key(public_key_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(public_key_bytes.len(), 65);
    assert_eq!(public_key_bytes[0], 0x04);
    let mut output = Vec::new();
    test_cbor_write_len(&mut output, 5, 5);
    test_cbor_write_i64(&mut output, 1);
    test_cbor_write_i64(&mut output, 2);
    test_cbor_write_i64(&mut output, 3);
    test_cbor_write_i64(&mut output, -7);
    test_cbor_write_i64(&mut output, -1);
    test_cbor_write_i64(&mut output, 1);
    test_cbor_write_i64(&mut output, -2);
    test_cbor_write_bytes(&mut output, &public_key_bytes[1..33]);
    test_cbor_write_i64(&mut output, -3);
    test_cbor_write_bytes(&mut output, &public_key_bytes[33..65]);
    output
}

#[cfg(feature = "production-crypto")]
fn test_certificate_chain(
    public_key_bytes: &[u8],
    app_attest_nonce: &[u8],
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let (root_pkcs8, root_public_key_bytes) = test_app_attest_key_pair();
    let (intermediate_pkcs8, intermediate_public_key_bytes) = test_app_attest_key_pair();
    let root_subject = test_x509_name("Test App Attest Root");
    let intermediate_subject = test_x509_name("Test App Attest Intermediate");
    let leaf_subject = test_x509_name("Test App Attest Leaf");
    let root_certificate = test_certificate_der(
        &root_subject,
        &root_subject,
        &root_public_key_bytes,
        None,
        &root_pkcs8,
    );
    let intermediate_certificate = test_certificate_der(
        &intermediate_subject,
        &root_subject,
        &intermediate_public_key_bytes,
        None,
        &root_pkcs8,
    );
    let leaf_certificate = test_certificate_der(
        &leaf_subject,
        &intermediate_subject,
        public_key_bytes,
        Some(app_attest_nonce),
        &intermediate_pkcs8,
    );
    (
        vec![leaf_certificate, intermediate_certificate],
        root_certificate,
    )
}

#[cfg(feature = "production-crypto")]
fn test_certificate_der(
    subject_der: &[u8],
    issuer_der: &[u8],
    public_key_bytes: &[u8],
    app_attest_nonce: Option<&[u8]>,
    signer_pkcs8: &[u8],
) -> Vec<u8> {
    let signature_algorithm = test_ecdsa_sha256_algorithm_identifier();
    let validity = test_der_sequence(&[
        test_der_generalized_time("20200101000000Z"),
        test_der_generalized_time("20450101000000Z"),
    ]);
    let subject_public_key_info = test_subject_public_key_info(public_key_bytes);
    let mut tbs_elements = vec![
        test_der_tag(0xa0, &test_der_integer(&[2])),
        test_der_integer(&[1]),
        signature_algorithm.clone(),
        issuer_der.to_vec(),
        validity,
        subject_der.to_vec(),
        subject_public_key_info,
    ];
    if let Some(app_attest_nonce) = app_attest_nonce {
        tbs_elements.push(test_x509_extensions(app_attest_nonce));
    }
    let tbs_certificate = test_der_sequence(&tbs_elements);
    let rng = SystemRandom::new();
    let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signer_pkcs8, &rng)
        .expect("test signing certificate key should parse");
    let signature = signer
        .sign(&rng, &tbs_certificate)
        .expect("test certificate signing should succeed");
    test_der_sequence(&[
        tbs_certificate,
        signature_algorithm,
        test_der_bit_string(signature.as_ref()),
    ])
}

#[cfg(feature = "production-crypto")]
fn test_subject_public_key_info(public_key_bytes: &[u8]) -> Vec<u8> {
    test_der_sequence(&[
        test_der_sequence(&[
            test_der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            test_der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]),
        test_der_bit_string(public_key_bytes),
    ])
}

#[cfg(feature = "production-crypto")]
fn test_ecdsa_sha256_algorithm_identifier() -> Vec<u8> {
    test_der_sequence(&[test_der_oid(&[
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ])])
}

#[cfg(feature = "production-crypto")]
fn test_x509_extensions(app_attest_nonce: &[u8]) -> Vec<u8> {
    let nonce_extension_payload = test_der_sequence(&[test_der_octet_string(app_attest_nonce)]);
    let app_attest_extension = test_der_sequence(&[
        test_der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02]),
        test_der_octet_string(&nonce_extension_payload),
    ]);
    test_der_tag(0xa3, &test_der_sequence(&[app_attest_extension]))
}

#[cfg(feature = "production-crypto")]
fn test_x509_name(common_name: &str) -> Vec<u8> {
    test_der_sequence(&[test_der_set(&[test_der_sequence(&[
        test_der_oid(&[0x55, 0x04, 0x03]),
        test_der_utf8_string(common_name),
    ])])])
}

#[cfg(feature = "production-crypto")]
fn test_der_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut contents = Vec::new();
    for element in elements {
        contents.extend_from_slice(element);
    }
    test_der_tag(0x30, &contents)
}

#[cfg(feature = "production-crypto")]
fn test_der_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut contents = Vec::new();
    for element in elements {
        contents.extend_from_slice(element);
    }
    test_der_tag(0x31, &contents)
}

#[cfg(feature = "production-crypto")]
fn test_der_integer(bytes: &[u8]) -> Vec<u8> {
    test_der_tag(0x02, bytes)
}

#[cfg(feature = "production-crypto")]
fn test_der_oid(body: &[u8]) -> Vec<u8> {
    test_der_tag(0x06, body)
}

#[cfg(feature = "production-crypto")]
fn test_der_octet_string(bytes: &[u8]) -> Vec<u8> {
    test_der_tag(0x04, bytes)
}

#[cfg(feature = "production-crypto")]
fn test_der_utf8_string(value: &str) -> Vec<u8> {
    test_der_tag(0x0c, value.as_bytes())
}

#[cfg(feature = "production-crypto")]
fn test_der_generalized_time(value: &str) -> Vec<u8> {
    test_der_tag(0x18, value.as_bytes())
}

#[cfg(feature = "production-crypto")]
fn test_der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(bytes.len() + 1);
    contents.push(0);
    contents.extend_from_slice(bytes);
    test_der_tag(0x03, &contents)
}

#[cfg(feature = "production-crypto")]
fn test_der_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    test_der_write_len(&mut output, contents.len());
    output.extend_from_slice(contents);
    output
}

#[cfg(feature = "production-crypto")]
fn test_der_write_len(output: &mut Vec<u8>, len: usize) {
    if len < 128 {
        output.push(len as u8);
    } else if u8::try_from(len).is_ok() {
        output.push(0x81);
        output.push(len as u8);
    } else {
        output.push(0x82);
        output.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

#[cfg(feature = "production-crypto")]
fn test_cbor_write_bytes(output: &mut Vec<u8>, value: &[u8]) {
    test_cbor_write_len(output, 2, value.len());
    output.extend_from_slice(value);
}

#[cfg(feature = "production-crypto")]
fn test_cbor_write_i64(output: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        test_cbor_write_len(output, 0, value as usize);
    } else {
        test_cbor_write_len(output, 1, (-1 - value) as usize);
    }
}

#[cfg(feature = "production-crypto")]
fn test_cbor_write_len(output: &mut Vec<u8>, major: u8, len: usize) {
    let prefix = major << 5;
    if len <= 23 {
        output.push(prefix | len as u8);
    } else if u8::try_from(len).is_ok() {
        output.push(prefix | 24);
        output.push(len as u8);
    } else {
        output.push(prefix | 25);
        output.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

#[cfg(feature = "production-crypto")]
fn test_app_attest_key_pair() -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("test key generation should succeed");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("test key should parse");
    (
        pkcs8.as_ref().to_vec(),
        key_pair.public_key().as_ref().to_vec(),
    )
}

#[cfg(feature = "production-crypto")]
fn signed_apple_app_attest_request_with_key(
    config: &AppAttestClientConfig,
    device_ref: &str,
    key_id: &str,
    challenge_nonce: &str,
    sign_count: u32,
    pkcs8: &[u8],
) -> AppAttestAssertionVerificationRequest {
    signed_apple_app_attest_request_with_authenticator_config(
        config,
        config,
        device_ref,
        key_id,
        challenge_nonce,
        sign_count,
        pkcs8,
    )
}

#[cfg(feature = "production-crypto")]
fn signed_apple_app_attest_request_with_authenticator_config(
    authenticator_config: &AppAttestClientConfig,
    request_config: &AppAttestClientConfig,
    device_ref: &str,
    key_id: &str,
    challenge_nonce: &str,
    sign_count: u32,
    pkcs8: &[u8],
) -> AppAttestAssertionVerificationRequest {
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
        .expect("test key should parse");
    let mut authenticator_data = apple_app_attest_app_id_hash(authenticator_config);
    authenticator_data.push(0x00);
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
    let client_data_hash = apple_app_attest_client_data_hash(challenge_nonce);
    let mut signed_bytes = authenticator_data.clone();
    signed_bytes.extend_from_slice(&client_data_hash);
    let signature = key_pair
        .sign(&rng, &signed_bytes)
        .expect("test assertion signing should succeed");

    let evidence = AppleAppAttestAssertionEvidence {
        device_ref: device_ref.to_string(),
        key_id: key_id.to_string(),
        authenticator_data,
        client_data_hash,
        signature_der: signature.as_ref().to_vec(),
        asserted_at: ts("2026-05-29T00:05:00Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        assurance_level: AssuranceLevel::Medium,
    };
    AppAttestAssertionVerificationRequest {
        assertion: evidence.to_compact_assertion(),
        challenge_nonce: challenge_nonce.to_string(),
        config: request_config.clone(),
    }
}

#[cfg(feature = "production-crypto")]
fn test_hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

// --- P-384 intermediate chain regression (real Apple App Attest cert shape) ---

#[cfg(feature = "production-crypto")]
fn test_p384_signing_key(fill: u8) -> p384::ecdsa::SigningKey {
    // A fixed, small, non-zero scalar is a valid P-384 private key and keeps the
    // test deterministic without an RNG.
    p384::ecdsa::SigningKey::from_slice(&[fill.max(1); 48])
        .expect("test P-384 scalar should be a valid signing key")
}

#[cfg(feature = "production-crypto")]
fn test_p384_public_key_bytes(key: &p384::ecdsa::SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
fn test_p384_sign_prehash(key: &p384::ecdsa::SigningKey, prehash: &[u8]) -> Vec<u8> {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    let signature: p384::ecdsa::Signature = key
        .sign_prehash(prehash)
        .expect("test P-384 prehash signing should succeed");
    // Encode the fixed r||s signature as an ASN.1 ECDSA-Sig-Value SEQUENCE, which
    // is what the verifier's ring ECDSA_*_ASN1 algorithms expect. Done by hand so
    // the test does not depend on an optional ecdsa `der` feature.
    let fixed = signature.to_bytes();
    test_der_ecdsa_signature(fixed.as_slice())
}

#[cfg(feature = "production-crypto")]
fn test_der_ecdsa_signature(fixed: &[u8]) -> Vec<u8> {
    let half = fixed.len() / 2;
    test_der_sequence(&[
        test_der_unsigned_integer(&fixed[..half]),
        test_der_unsigned_integer(&fixed[half..]),
    ])
}

#[cfg(feature = "production-crypto")]
fn test_der_unsigned_integer(bytes: &[u8]) -> Vec<u8> {
    // DER INTEGER: strip leading zero bytes (keeping at least one), then prepend
    // 0x00 when the high bit is set so the value stays non-negative.
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];
    let mut contents = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        contents.push(0x00);
    }
    contents.extend_from_slice(trimmed);
    test_der_tag(0x02, &contents)
}

#[cfg(feature = "production-crypto")]
fn test_sha256(bytes: &[u8]) -> Vec<u8> {
    <sha2::Sha256 as sha2::Digest>::digest(bytes)
        .as_slice()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
fn test_sha384(bytes: &[u8]) -> Vec<u8> {
    <sha2::Sha384 as sha2::Digest>::digest(bytes)
        .as_slice()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
fn test_ecdsa_sha384_algorithm_identifier() -> Vec<u8> {
    test_der_sequence(&[test_der_oid(&[
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
    ])])
}

#[cfg(feature = "production-crypto")]
fn test_subject_public_key_info_p384(public_key_bytes: &[u8]) -> Vec<u8> {
    test_der_sequence(&[
        test_der_sequence(&[
            test_der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            test_der_oid(&[0x2b, 0x81, 0x04, 0x00, 0x22]),
        ]),
        test_der_bit_string(public_key_bytes),
    ])
}

#[cfg(feature = "production-crypto")]
fn test_certificate_der_with_signature(
    subject_der: &[u8],
    issuer_der: &[u8],
    subject_public_key_info: &[u8],
    signature_algorithm: &[u8],
    app_attest_nonce: Option<&[u8]>,
    signature_der: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let validity = test_der_sequence(&[
        test_der_generalized_time("20200101000000Z"),
        test_der_generalized_time("20450101000000Z"),
    ]);
    let mut tbs_elements = vec![
        test_der_tag(0xa0, &test_der_integer(&[2])),
        test_der_integer(&[1]),
        signature_algorithm.to_vec(),
        issuer_der.to_vec(),
        validity,
        subject_der.to_vec(),
        subject_public_key_info.to_vec(),
    ];
    if let Some(app_attest_nonce) = app_attest_nonce {
        tbs_elements.push(test_x509_extensions(app_attest_nonce));
    }
    let tbs_certificate = test_der_sequence(&tbs_elements);
    let signature = signature_der(&tbs_certificate);
    test_der_sequence(&[
        tbs_certificate,
        signature_algorithm.to_vec(),
        test_der_bit_string(&signature),
    ])
}

#[cfg(feature = "production-crypto")]
#[test]
fn apple_app_attest_key_registration_verifier_accepts_p384_intermediate_chain() {
    // Regression for the real Apple App Attest certificate shape: a P-256 leaf
    // signed by the P-384 "Apple App Attestation CA 1" intermediate using
    // ecdsa-with-SHA256. The signatureAlgorithm OID only names the digest, so the
    // verifying curve must be taken from the issuer key. An earlier version
    // selected the curve from the child certificate's OID, handed the P-384
    // issuer key to a P-256 verifier, and rejected every real-device attestation
    // with InvalidSignature. The all-P-256 fixtures could not catch this because
    // ring can only sign the two matched curve/digest combinations.
    let config = app_attest_config();
    let key_id = "apple-key-p384-chain";
    let device_ref = "iphone-real-device";
    let challenge_nonce = "server-registration-challenge";

    let (_leaf_pkcs8, leaf_public_key_bytes) = test_app_attest_key_pair();
    let authenticator_data =
        apple_app_attest_registration_authenticator_data(&config, key_id, &leaf_public_key_bytes);
    let client_data_hash = apple_app_attest_client_data_hash(challenge_nonce);
    let expected_nonce = test_app_attest_attestation_nonce(&authenticator_data, &client_data_hash);

    let root_key = test_p384_signing_key(2);
    let intermediate_key = test_p384_signing_key(3);
    let root_public = test_p384_public_key_bytes(&root_key);
    let intermediate_public = test_p384_public_key_bytes(&intermediate_key);
    let root_subject = test_x509_name("Test App Attest P384 Root");
    let intermediate_subject = test_x509_name("Test App Attest P384 Intermediate");
    let leaf_subject = test_x509_name("Test App Attest Leaf");
    let sha256_algorithm = test_ecdsa_sha256_algorithm_identifier();
    let sha384_algorithm = test_ecdsa_sha384_algorithm_identifier();

    // Root: P-384, self-signed with ecdsa-with-SHA384.
    let root_certificate = test_certificate_der_with_signature(
        &root_subject,
        &root_subject,
        &test_subject_public_key_info_p384(&root_public),
        &sha384_algorithm,
        None,
        |tbs| test_p384_sign_prehash(&root_key, &test_sha384(tbs)),
    );
    // Intermediate: P-384, signed by the root with ecdsa-with-SHA384.
    let intermediate_certificate = test_certificate_der_with_signature(
        &intermediate_subject,
        &root_subject,
        &test_subject_public_key_info_p384(&intermediate_public),
        &sha384_algorithm,
        None,
        |tbs| test_p384_sign_prehash(&root_key, &test_sha384(tbs)),
    );
    // Leaf: P-256, signed by the P-384 intermediate with ecdsa-with-SHA256.
    let leaf_certificate = test_certificate_der_with_signature(
        &leaf_subject,
        &intermediate_subject,
        &test_subject_public_key_info(&leaf_public_key_bytes),
        &sha256_algorithm,
        Some(&expected_nonce),
        |tbs| test_p384_sign_prehash(&intermediate_key, &test_sha256(tbs)),
    );

    let request = AppleAppAttestKeyRegistrationVerificationRequest {
        key_id: key_id.to_string(),
        device_ref: device_ref.to_string(),
        public_key_bytes: leaf_public_key_bytes.clone(),
        certificate_chain_der: vec![leaf_certificate, intermediate_certificate],
        credential_id: key_id.as_bytes().to_vec(),
        authenticator_data,
        client_data_hash,
        challenge_nonce: challenge_nonce.to_string(),
        registered_at: ts("2026-05-29T00:05:00Z"),
        attestation_format: "apple-app-attest".to_string(),
        config: config.clone(),
    };
    let verifier = AppleAppAttestKeyRegistrationVerifier::with_trusted_root_certificates(
        config.clone(),
        vec![root_certificate],
    );

    let registration = verifier
        .verify_app_attest_key_registration(&request, &ts("2026-05-29T00:05:30Z"))
        .expect("Apple-shaped P-384 intermediate chain must verify");

    assert_eq!(registration.key_id, key_id);
    assert_eq!(registration.device_ref, device_ref);
}
