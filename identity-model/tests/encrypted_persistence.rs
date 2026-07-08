use identity_model::*;

mod common;
use common::*;

const KEY_ID: &str = "fact-key-active";

#[test]
fn encrypted_fact_envelope_round_trips_after_policy_gated_materialization() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact(
        "fact-encrypted-round-trip",
        id("subject-encrypted-round-trip"),
    );

    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);
    let materialized = materialize_encrypted_fact(
        &envelope,
        &allowed_policy(materialization_policy_refs()),
        &resolver,
        &encryptor,
    )
    .expect("authorized materialization should decrypt");

    assert_eq!(envelope.fact_id, fact.id);
    assert_eq!(envelope.subject_id, fact.subject_id);
    assert_eq!(
        envelope.payload_type,
        FactPayloadType::ClinicalIdentityLinkEstablished
    );
    assert!(!envelope.ciphertext.is_empty());
    assert_eq!(materialized, fact);

    let associated_data = String::from_utf8(canonical_encrypted_fact_associated_data(&envelope))
        .expect("associated data should be utf-8 labels");
    assert!(associated_data.contains("profile=18:fen-encrypted-fact"));
    assert!(associated_data.contains("payload_type=34:clinical_identity_link_established"));
}

#[cfg(feature = "production-crypto")]
#[test]
fn aes_256_gcm_fact_encryptor_round_trips_and_authenticates_envelope_context() {
    let key = FactDataEncryptionKey::active("aes-key", vec![7_u8; 32]);
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = RingAes256GcmFactEncryptor::new();
    let fact = sensitive_fact("fact-aes-gcm", id("subject-aes-gcm"));
    let encryption = FactEncryptionMetadata::aes_256_gcm(
        "aes-key",
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        None,
    );

    let envelope = encrypt_fact_envelope(
        &fact,
        7,
        id("tx-aes-gcm"),
        ts("2026-05-29T00:00:01Z"),
        materialization_policy_refs(),
        encryption,
        &key,
        &encryptor,
    )
    .expect("AES-GCM envelope should encrypt");
    let materialized = materialize_encrypted_fact(
        &envelope,
        &allowed_policy(materialization_policy_refs()),
        &resolver,
        &encryptor,
    )
    .expect("authorized AES-GCM envelope should materialize");
    assert_eq!(materialized, fact);
    assert_eq!(
        envelope.encryption.algorithm,
        FactEncryptionAlgorithm::Aes256Gcm
    );

    let mut tampered_ciphertext = envelope.clone();
    tampered_ciphertext.ciphertext[0] ^= 0x01;
    assert_eq!(
        materialize_encrypted_fact(
            &tampered_ciphertext,
            &allowed_policy(materialization_policy_refs()),
            &resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );

    let mut tampered_aad = envelope.clone();
    tampered_aad.subject_id = id("subject-aes-gcm-swapped");
    assert_eq!(
        materialize_encrypted_fact(
            &tampered_aad,
            &allowed_policy(materialization_policy_refs()),
            &resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );

    let wrong_key_resolver = StaticFactKeyResolver::from_keys([FactDataEncryptionKey::active(
        "aes-key",
        vec![9_u8; 32],
    )]);
    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(materialization_policy_refs()),
            &wrong_key_resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );
}

#[cfg(feature = "production-crypto")]
#[test]
fn aes_256_gcm_metadata_planner_derives_unique_nonces_from_append_sequence() {
    let mut planner = Aes256GcmFactEncryptionMetadataPlanner::new("aes-key", *b"FEN1", None);
    let fact = sensitive_fact("fact-aes-gcm-nonce", id("subject-aes-gcm-nonce"));

    // `FactEncryptionMetadataPlanner` is generic over the payload family since
    // the D3 seam; a concrete planner implements it for every family, so the
    // family must be named at the call site (the identity one here).
    let first = FactEncryptionMetadataPlanner::<IdentityPayloadFamily>::metadata_for_fact(
        &mut planner,
        &fact,
        1,
    );
    let second = FactEncryptionMetadataPlanner::<IdentityPayloadFamily>::metadata_for_fact(
        &mut planner,
        &fact,
        2,
    );

    assert_eq!(first.algorithm, FactEncryptionAlgorithm::Aes256Gcm);
    assert_eq!(first.nonce.len(), 12);
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(&first.nonce[..4], b"FEN1");
    assert_eq!(&first.nonce[4..], 1_u64.to_be_bytes());
}

#[test]
fn encrypted_fact_repository_preserves_explicit_append_sequence_for_replay() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = DeterministicTestFactEncryptor::new();
    let subject_id: SubjectId = id("subject-encrypted-replay");
    let witness = fact(
        "fact-encrypted-witness",
        subject_id.clone(),
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::GovernmentIdVerification,
            target_subject_id: subject_id.clone(),
            assurance_level: AssuranceLevel::High,
            evidence_ref: Some("government-id-document".to_string()),
            expires_at: None,
            context: IdentityWitnessContext::default(),
        },
    );
    let device = fact(
        "fact-encrypted-device",
        subject_id.clone(),
        FactPayload::DeviceBindingEstablished {
            device_ref: "device-encrypted".to_string(),
            authenticator_type: AuthenticatorType::Passkey,
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let later = encrypted_envelope(&device, 2, materialization_policy_refs(), &key, &encryptor);
    let earlier = encrypted_envelope(&witness, 1, materialization_policy_refs(), &key, &encryptor);
    let mut repository = InMemoryEncryptedFactRepository::new();

    repository
        .append_encrypted_fact(later)
        .expect("later fact should append");
    repository
        .append_encrypted_fact(earlier)
        .expect("earlier fact should append and sort by append sequence");

    let envelopes = repository.encrypted_facts_for_subject(&subject_id);
    assert_eq!(
        envelopes
            .iter()
            .map(|envelope| envelope.append_sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    let materialized = materialize_encrypted_facts(
        &envelopes,
        &allowed_policy(materialization_policy_refs()),
        &resolver,
        &encryptor,
    )
    .expect("authorized replay should materialize facts in append order");
    let projection = replay_identity_state(subject_id, &materialized);

    assert_eq!(projection.assurance_level, AssuranceLevel::High);
    assert_eq!(
        projection.active_devices,
        vec!["device-encrypted".to_string()]
    );
}

#[test]
fn encryption_aware_workflow_repository_appends_and_replays_mobile_workflow() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-mobile-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-mobile-user",
            config.client_id.clone(),
            "mobile-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("mobile.patient@example.test"),
    );
    let app_attest_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let app_attest_verifier = StaticAppAttestAssertionVerifier::new(
        "valid-app-attest-assertion",
        VerifiedAppAttestAssertion {
            team_id: app_attest_config.team_id.clone(),
            bundle_id: app_attest_config.bundle_id.clone(),
            app_id: app_attest_config.app_id.clone(),
            environment: app_attest_config.environment,
            device_ref: "iphone-encrypted-workflow-device".to_string(),
            key_id: "app-attest-key-encrypted-workflow".to_string(),
            challenge_nonce: "app-attest-encrypted-workflow-nonce".to_string(),
            sign_count: 13,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let bootstrap = service
        .accept_account_token_with_app_attest(
            AccountTokenWithAppAttestBootstrapRequest {
                account: AccountTokenBootstrapRequest {
                    subject_id: id("subject-encrypted-mobile-workflow"),
                    authored_by: author,
                    observed_at: ts("2026-05-29T00:05:30Z"),
                    id_namespace: "encrypted-mobile-workflow".to_string(),
                    token: "valid-mobile-token".to_string(),
                    oidc_config: config,
                    device_ref: Some("iphone-encrypted-workflow-device".to_string()),
                    assurance_policy: OidcAssurancePolicy::default(),
                },
                app_attest: AppAttestAssertionVerificationRequest {
                    assertion: "valid-app-attest-assertion".to_string(),
                    challenge_nonce: "app-attest-encrypted-workflow-nonce".to_string(),
                    config: app_attest_config,
                },
            },
            &verifier,
            &app_attest_verifier,
            &mut ids,
        )
        .expect("verified mobile evidence should build a workflow slice");
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let policy_refs = materialization_policy_refs();
    let mut repository = EncryptionAwareWorkflowRepository::new(
        InMemoryStoredEncryptedWorkflowRepository::new(),
        DeterministicTestFactEncryptionMetadataPlanner::new(KEY_ID, "nonce-mobile-workflow"),
        DeterministicTestFactEncryptor::new(),
        key,
        policy_refs.clone(),
        EncryptedWorkflowAppendSequenceState::new(10, 20, 30),
    );

    let stored = repository
        .append_workflow_slice(
            bootstrap.workflow.slice.clone(),
            id("tx-encrypted-mobile-workflow"),
            ts("2026-05-29T00:05:31Z"),
        )
        .expect("encryption-aware repository should append the stored workflow");

    assert_eq!(stored.transaction_id, id("tx-encrypted-mobile-workflow"));
    assert_eq!(stored.episode.append_sequence, 20);
    assert_eq!(
        stored
            .encrypted_facts
            .iter()
            .map(|fact| fact.append_sequence)
            .collect::<Vec<_>>(),
        vec![10, 11, 12, 13]
    );
    assert_eq!(
        stored
            .memberships
            .iter()
            .map(|membership| membership.append_sequence)
            .collect::<Vec<_>>(),
        vec![30, 31, 32, 33]
    );
    assert!(
        stored
            .encrypted_facts
            .iter()
            .all(|fact| fact.materialization_policy_refs == policy_refs
                && !fact.ciphertext.is_empty())
    );
    assert_eq!(
        repository.sequence_state(),
        EncryptedWorkflowAppendSequenceState::new(14, 21, 34)
    );

    let replayed = repository
        .replay_identity_state(
            id("subject-encrypted-mobile-workflow"),
            &allowed_policy(policy_refs),
            &resolver,
        )
        .expect("policy-approved encrypted workflow should materialize and replay");

    assert_eq!(replayed, bootstrap.workflow.projection);
    assert_eq!(
        replayed.active_devices,
        vec!["iphone-encrypted-workflow-device".to_string()]
    );
}

#[test]
fn materialization_requires_allowed_policy_before_key_access() {
    let key = active_key();
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact("fact-policy-gated", id("subject-policy-gated"));
    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);

    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &denied_policy(),
            &PanickingKeyResolver,
            &encryptor
        ),
        Err(FactMaterializationError::PolicyDenied)
    );
    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(vec![id("other-materialization-policy@v1")]),
            &PanickingKeyResolver,
            &encryptor,
        ),
        Err(FactMaterializationError::MaterializationPolicyRefsNotSatisfied)
    );
}

#[test]
fn tampered_envelope_associated_data_is_rejected() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact("fact-aad-binding", id("subject-aad-binding"));
    let envelope = encrypted_envelope(&fact, 7, materialization_policy_refs(), &key, &encryptor);

    let mut tampered_fact_id = envelope.clone();
    tampered_fact_id.fact_id = id("fact-aad-tampered");

    let mut tampered_subject_id = envelope.clone();
    tampered_subject_id.subject_id = id("subject-aad-tampered");

    let mut tampered_append_sequence = envelope.clone();
    tampered_append_sequence.append_sequence = 8;

    let mut tampered_payload_type = envelope.clone();
    tampered_payload_type.payload_type = FactPayloadType::CredentialAssertion;

    let mut tampered_status = envelope.clone();
    tampered_status.status = FactStatus::EnteredInError {
        corrected_by: system_author(),
        corrected_at: TemporalAnchor::Point(ts("2026-05-29T00:10:00Z")),
        replaced_by: None,
    };

    let other_policy_refs = vec![id("other-materialization-policy@v1")];
    let mut tampered_policy_refs = envelope;
    tampered_policy_refs.materialization_policy_refs = other_policy_refs.clone();

    for tampered in [
        tampered_fact_id,
        tampered_subject_id,
        tampered_append_sequence,
        tampered_payload_type,
        tampered_status,
    ] {
        assert_eq!(
            materialize_encrypted_fact(
                &tampered,
                &allowed_policy(materialization_policy_refs()),
                &resolver,
                &encryptor,
            ),
            Err(FactMaterializationError::AuthenticationFailed)
        );
    }

    assert_eq!(
        materialize_encrypted_fact(
            &tampered_policy_refs,
            &allowed_policy(other_policy_refs),
            &resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );
}

#[test]
fn ciphertext_wrong_key_missing_key_and_retired_key_are_rejected() {
    let key = active_key();
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact("fact-key-failures", id("subject-key-failures"));
    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);

    let mut tampered_ciphertext = envelope.clone();
    tampered_ciphertext.ciphertext.push(0xff);
    assert_eq!(
        materialize_encrypted_fact(
            &tampered_ciphertext,
            &allowed_policy(materialization_policy_refs()),
            &StaticFactKeyResolver::from_keys([key.clone()]),
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );

    let wrong_key = FactDataEncryptionKey::active(KEY_ID, b"wrong-key-material".to_vec());
    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(materialization_policy_refs()),
            &StaticFactKeyResolver::from_keys([wrong_key]),
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );

    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(materialization_policy_refs()),
            &StaticFactKeyResolver::new(),
            &encryptor,
        ),
        Err(FactMaterializationError::MissingKey)
    );

    let retired_key = FactDataEncryptionKey::retired(KEY_ID, b"test-key-material".to_vec());
    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(materialization_policy_refs()),
            &StaticFactKeyResolver::from_keys([retired_key]),
            &encryptor,
        ),
        Err(FactMaterializationError::RetiredKey)
    );
}

#[test]
fn materialization_audit_records_policy_key_and_decryption_stages() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact("fact-audit-success", id("subject-audit-success"));
    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);
    let context = FactMaterializationAuditContext::new(
        Some("support-agent-1".to_string()),
        Some("identity-support-review".to_string()),
        Some(ts("2026-05-29T00:05:00Z")),
    );
    let mut audit_log = InMemoryFactMaterializationAuditLog::new();

    let materialized = materialize_encrypted_fact_with_audit(
        &envelope,
        &allowed_policy(materialization_policy_refs()),
        &resolver,
        &encryptor,
        &context,
        &mut audit_log,
    )
    .expect("authorized materialization should succeed");

    assert_eq!(materialized, fact);
    assert_eq!(
        audit_log
            .events()
            .iter()
            .map(|event| event.outcome)
            .collect::<Vec<_>>(),
        vec![
            FactMaterializationAuditOutcome::Attempted,
            FactMaterializationAuditOutcome::KeyAccessAttempted,
            FactMaterializationAuditOutcome::KeyAccessSucceeded,
            FactMaterializationAuditOutcome::DecryptionAttempted,
            FactMaterializationAuditOutcome::Succeeded,
        ]
    );
    let first_event = audit_log
        .events()
        .first()
        .cloned()
        .expect("audit should record attempted materialization");
    assert_eq!(first_event.subject_id, id("subject-audit-success"));
    assert_eq!(first_event.fact_ids, vec![id("fact-audit-success")]);
    assert_eq!(
        first_event.materialization_policy_refs,
        materialization_policy_refs()
    );
    assert_eq!(
        first_event.evaluated_policy_refs,
        materialization_policy_refs()
    );
    assert_eq!(first_event.caller, Some("support-agent-1".to_string()));
    assert_eq!(
        first_event.purpose,
        Some("identity-support-review".to_string())
    );

    let mut denied_audit_log = InMemoryFactMaterializationAuditLog::new();
    assert_eq!(
        materialize_encrypted_fact_with_audit(
            &envelope,
            &denied_policy(),
            &PanickingKeyResolver,
            &encryptor,
            &context,
            &mut denied_audit_log,
        ),
        Err(FactMaterializationError::PolicyDenied)
    );
    assert_eq!(
        denied_audit_log
            .events()
            .iter()
            .map(|event| (event.outcome, event.error))
            .collect::<Vec<_>>(),
        vec![
            (FactMaterializationAuditOutcome::Attempted, None),
            (
                FactMaterializationAuditOutcome::PolicyDenied,
                Some(FactMaterializationError::PolicyDenied),
            ),
        ]
    );
}

#[test]
fn deterministic_encryptor_uses_explicit_plaintext_codec_boundary() {
    let key = active_key();
    let encryptor =
        DeterministicTestFactEncryptor::with_codec(InMemoryEncryptedFactPlaintextCodec::new());
    let fresh_codec_encryptor =
        DeterministicTestFactEncryptor::with_codec(InMemoryEncryptedFactPlaintextCodec::new());
    let fact = sensitive_fact("fact-codec-boundary", id("subject-codec-boundary"));
    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);

    assert_eq!(
        materialize_encrypted_fact(
            &envelope,
            &allowed_policy(materialization_policy_refs()),
            &StaticFactKeyResolver::from_keys([key]),
            &fresh_codec_encryptor,
        ),
        Err(FactMaterializationError::PlaintextDecodeFailed)
    );
}

#[test]
fn encryption_requires_matching_active_key() {
    let fact = sensitive_fact(
        "fact-encryption-key-status",
        id("subject-encryption-key-status"),
    );
    let encryptor = DeterministicTestFactEncryptor::new();
    let retired_key = FactDataEncryptionKey::retired(KEY_ID, b"test-key-material".to_vec());
    let mismatched_key =
        FactDataEncryptionKey::active("different-key", b"test-key-material".to_vec());

    assert_eq!(
        encrypt_fact_envelope(
            &fact,
            1,
            id("tx-retired-key"),
            ts("2026-05-29T00:00:00Z"),
            materialization_policy_refs(),
            encryption_metadata(),
            &retired_key,
            &encryptor,
        ),
        Err(FactEncryptionError::KeyNotActive)
    );
    assert_eq!(
        encrypt_fact_envelope(
            &fact,
            1,
            id("tx-mismatched-key"),
            ts("2026-05-29T00:00:00Z"),
            materialization_policy_refs(),
            encryption_metadata(),
            &mismatched_key,
            &encryptor,
        ),
        Err(FactEncryptionError::KeyIdMismatch)
    );
}

#[derive(Debug, Clone, Copy)]
struct PanickingKeyResolver;

impl FactKeyResolver for PanickingKeyResolver {
    fn resolve_fact_key(
        &self,
        _key_id: &FactEncryptionKeyId,
    ) -> Result<FactDataEncryptionKey, FactKeyAccessError> {
        panic!("policy denial should happen before key lookup");
    }
}

fn sensitive_fact(id_value: &str, subject_id: SubjectId) -> Fact {
    let mut fact = fact(
        id_value,
        subject_id,
        FactPayload::ClinicalIdentityLinkEstablished {
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-sensitive".to_string(),
                uri: Some("https://example.invalid/fhir/Patient/patient-sensitive".to_string()),
            },
            match_confidence: MatchConfidence::High,
        },
    );
    fact.code = Some(CodedValue {
        system: CodingSystem::Local,
        code: "identity-link".to_string(),
        display: "Identity link".to_string(),
    });
    fact.external_refs = vec![ExternalRef {
        system: ExternalSystem::IdentityProvider,
        resource_type: Some("identity-proofing-event".to_string()),
        resource_id: "proofing-event-sensitive".to_string(),
        uri: None,
    }];
    fact
}

fn encrypted_envelope(
    fact: &Fact,
    append_sequence: AppendSequence,
    policy_refs: Vec<PolicyRef>,
    key: &FactDataEncryptionKey,
    encryptor: &DeterministicTestFactEncryptor,
) -> StoredEncryptedFact {
    encrypt_fact_envelope(
        fact,
        append_sequence,
        id("tx-encrypted-facts"),
        ts("2026-05-29T00:00:01Z"),
        policy_refs,
        encryption_metadata(),
        key,
        encryptor,
    )
    .expect("fact should encrypt")
}

fn encryption_metadata() -> FactEncryptionMetadata {
    FactEncryptionMetadata::deterministic_test(KEY_ID, b"nonce-encrypted-fact".to_vec())
}

fn active_key() -> FactDataEncryptionKey {
    FactDataEncryptionKey::active(KEY_ID, b"test-key-material".to_vec())
}

fn materialization_policy_refs() -> Vec<PolicyRef> {
    vec![id("identity-materialization-policy@v1")]
}

fn allowed_policy(policy_refs: Vec<PolicyRef>) -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Allowed,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs,
    }
}

fn denied_policy() -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Denied,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs: materialization_policy_refs(),
    }
}
