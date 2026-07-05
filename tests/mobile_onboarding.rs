use identity_model::*;

mod common;
use common::*;

#[test]
fn mobile_onboarding_command_returns_safe_summary_and_appends_workflow() {
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
            device_ref: "iphone-command-device".to_string(),
            key_id: "app-attest-key-command".to_string(),
            challenge_nonce: "app-attest-command-nonce".to_string(),
            sign_count: 11,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let outcome = execute_mobile_onboarding_command(
        &service,
        MobileOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: id("subject-mobile-command"),
                authored_by: author,
                observed_at: ts("2026-05-29T00:05:30Z"),
                id_namespace: "mobile-command".to_string(),
                token: "valid-mobile-token".to_string(),
                oidc_config: config,
                device_ref: Some("iphone-command-device".to_string()),
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: "valid-app-attest-assertion".to_string(),
                challenge_nonce: "app-attest-command-nonce".to_string(),
                config: app_attest_config,
            },
            client_context: MobileOnboardingClientContext::iphone("request-mobile-command"),
        },
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    )
    .expect("valid mobile onboarding command should append and summarize");

    assert_eq!(
        outcome.client_context,
        MobileOnboardingClientContext::iphone("request-mobile-command")
    );
    assert_eq!(outcome.summary.subject_id, id("subject-mobile-command"));
    assert_eq!(outcome.summary.assurance_level, AssuranceLevel::Medium);
    assert_eq!(
        outcome.summary.active_devices,
        vec!["iphone-command-device".to_string()]
    );
    assert_eq!(
        outcome.summary.workflow_episode_id,
        id("episode-mobile-command-0")
    );
    assert_eq!(outcome.summary.committed_fact_count, 4);
    assert_eq!(
        outcome.summary.fact_ids,
        MobileOnboardingFactIds {
            credential_fact_id: id("fact-mobile-command-0"),
            portal_login_witness_fact_id: id("fact-mobile-command-1"),
            verified_email_attribute_fact_id: Some(id("fact-mobile-command-2")),
            device_binding_fact_id: id("fact-mobile-command-3"),
        }
    );
    assert_eq!(repository.all_facts().len(), 4);
    assert_eq!(repository.all_episodes().len(), 1);
    assert_eq!(repository.all_memberships().len(), 4);
}

#[test]
fn encrypted_mobile_onboarding_command_appends_through_facade_and_replays_summary() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-encrypted-mobile-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-encrypted-mobile-user",
            config.client_id.clone(),
            "encrypted-mobile-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("encrypted.mobile.patient@example.test"),
    );
    let app_attest_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let app_attest_verifier = StaticAppAttestAssertionVerifier::new(
        "valid-encrypted-app-attest-assertion",
        VerifiedAppAttestAssertion {
            team_id: app_attest_config.team_id.clone(),
            bundle_id: app_attest_config.bundle_id.clone(),
            app_id: app_attest_config.app_id.clone(),
            environment: app_attest_config.environment,
            device_ref: "iphone-encrypted-command-device".to_string(),
            key_id: "app-attest-key-encrypted-command".to_string(),
            challenge_nonce: "app-attest-encrypted-command-nonce".to_string(),
            sign_count: 14,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let key = mobile_active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let policy_refs = mobile_materialization_policy_refs();
    let mut repository = EncryptionAwareWorkflowRepository::new(
        InMemoryStoredEncryptedWorkflowRepository::new(),
        DeterministicTestFactEncryptionMetadataPlanner::new(
            "mobile-command-key",
            "nonce-encrypted-mobile-command",
        ),
        DeterministicTestFactEncryptor::new(),
        key,
        policy_refs.clone(),
        EncryptedWorkflowAppendSequenceState::new(100, 200, 300),
    );

    let outcome = execute_encrypted_mobile_onboarding_command(
        &service,
        MobileOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: id("subject-encrypted-mobile-command"),
                authored_by: author,
                observed_at: ts("2026-05-29T00:05:30Z"),
                id_namespace: "encrypted-mobile-command".to_string(),
                token: "valid-encrypted-mobile-token".to_string(),
                oidc_config: config,
                device_ref: Some("iphone-encrypted-command-device".to_string()),
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: "valid-encrypted-app-attest-assertion".to_string(),
                challenge_nonce: "app-attest-encrypted-command-nonce".to_string(),
                config: app_attest_config,
            },
            client_context: MobileOnboardingClientContext::iphone(
                "request-encrypted-mobile-command",
            ),
        },
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
        MobileOnboardingEncryptedPersistenceContext {
            transaction_id: id("tx-encrypted-mobile-command"),
            committed_at: ts("2026-05-29T00:05:31Z"),
            materialization_policy: mobile_allowed_policy(policy_refs.clone()),
            materialization_audit_context: FactMaterializationAuditContext::default(),
        },
        &resolver,
    )
    .expect("encrypted mobile onboarding command should append and replay");

    assert_eq!(
        outcome.summary.active_devices,
        vec!["iphone-encrypted-command-device".to_string()]
    );
    assert_eq!(outcome.summary.committed_fact_count, 4);
    assert_eq!(
        outcome.summary.fact_ids,
        MobileOnboardingFactIds {
            credential_fact_id: id("fact-encrypted-mobile-command-0"),
            portal_login_witness_fact_id: id("fact-encrypted-mobile-command-1"),
            verified_email_attribute_fact_id: Some(id("fact-encrypted-mobile-command-2")),
            device_binding_fact_id: id("fact-encrypted-mobile-command-3"),
        }
    );

    let stored_slices = repository.storage().workflow_slices();
    assert_eq!(stored_slices.len(), 1);
    assert_eq!(
        stored_slices[0].transaction_id,
        id("tx-encrypted-mobile-command")
    );
    assert_eq!(
        stored_slices[0]
            .encrypted_facts
            .iter()
            .map(|fact| fact.append_sequence)
            .collect::<Vec<_>>(),
        vec![100, 101, 102, 103]
    );
    assert!(
        stored_slices[0]
            .encrypted_facts
            .iter()
            .all(|fact| fact.materialization_policy_refs == policy_refs
                && !fact.ciphertext.is_empty())
    );
    assert_eq!(
        repository.sequence_state(),
        EncryptedWorkflowAppendSequenceState::new(104, 201, 304)
    );
}

#[test]
fn mobile_onboarding_command_rejection_leaves_repository_empty() {
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
        ),
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
            device_ref: "iphone-command-device".to_string(),
            key_id: "app-attest-key-command".to_string(),
            challenge_nonce: "app-attest-command-nonce".to_string(),
            sign_count: 11,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let result = execute_mobile_onboarding_command(
        &service,
        MobileOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: id("subject-mobile-command-rejected"),
                authored_by: author,
                observed_at: ts("2026-05-29T00:05:30Z"),
                id_namespace: "mobile-command-rejected".to_string(),
                token: "valid-mobile-token".to_string(),
                oidc_config: config,
                device_ref: Some("different-device".to_string()),
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: "valid-app-attest-assertion".to_string(),
                challenge_nonce: "app-attest-command-nonce".to_string(),
                config: app_attest_config,
            },
            client_context: MobileOnboardingClientContext::iphone("request-mobile-command"),
        },
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    );

    assert_eq!(result, Err(MobileOnboardingCommandError::DeviceRefMismatch));
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_memberships().is_empty());
}

#[test]
fn app_attest_context_rejects_empty_challenge_nonce() {
    let config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let assertion = VerifiedAppAttestAssertion {
        team_id: config.team_id.clone(),
        bundle_id: config.bundle_id.clone(),
        app_id: config.app_id.clone(),
        environment: config.environment,
        device_ref: "iphone-command-device".to_string(),
        key_id: "app-attest-key-command".to_string(),
        challenge_nonce: String::new(),
        sign_count: 11,
        asserted_at: ts("2026-05-29T00:05:00Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        assurance_level: AssuranceLevel::Medium,
    };

    assert_eq!(
        validate_app_attest_assertion_context(&assertion, &config, "", &ts("2026-05-29T00:05:30Z")),
        Err(AppAttestAssertionVerificationError::MissingChallengeNonce)
    );

    let valid_challenge_assertion = VerifiedAppAttestAssertion {
        challenge_nonce: "valid-nonce".to_string(),
        ..assertion
    };
    assert_eq!(
        validate_app_attest_assertion_context(
            &valid_challenge_assertion,
            &config,
            "valid-nonce",
            &ts("2026-02-31T00:05:30Z")
        ),
        Err(AppAttestAssertionVerificationError::InvalidTimestamp)
    );
    assert_eq!(
        validate_app_attest_assertion_context(
            &VerifiedAppAttestAssertion {
                expires_at: ts("2026-02-31T00:06:00Z"),
                ..valid_challenge_assertion
            },
            &config,
            "valid-nonce",
            &ts("2026-05-29T00:05:30Z")
        ),
        Err(AppAttestAssertionVerificationError::InvalidTimestamp)
    );
}

fn mobile_active_key() -> FactDataEncryptionKey {
    FactDataEncryptionKey::active(
        "mobile-command-key",
        b"mobile-command-key-material".to_vec(),
    )
}

fn mobile_materialization_policy_refs() -> Vec<PolicyRef> {
    vec![id("mobile-materialization-policy@v1")]
}

fn mobile_allowed_policy(policy_refs: Vec<PolicyRef>) -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Allowed,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs,
    }
}

#[test]
fn mobile_identity_onboarding_records_persona_proofing_liveness_and_enrollment() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let subject_id: SubjectId = id("subject-mobile-identity");
    let evidence = mobile_evidence_fixture(
        "identity-onboarding",
        "valid-identity-token",
        "valid-identity-app-attest",
        "iphone-identity-device",
    );
    let liveness_verifier = StaticLivenessCeremonyVerifier::new(
        "valid-live-presence",
        liveness_ceremony(
            "identity-onboarding",
            &evidence,
            IdentityWitnessResult::Passed,
            PresentationAttackDetectionResult::Passed,
            AssuranceLevel::High,
        ),
    );
    let provider = MockPhase1ContinuityProvider::successful();
    let identity_proofing_provider = PersonaIdentityProofingProvider::new();
    let challenge_store = InMemoryLivePresenceChallengeStore::new();
    issue_live_presence_challenge(
        &challenge_store,
        "identity-onboarding",
        &subject_id,
        &evidence,
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let outcome = execute_mobile_identity_onboarding_command(
        &service,
        mobile_identity_onboarding_request(
            author,
            &subject_id.0,
            "mobile-identity",
            &evidence,
            "valid-identity-token",
            "valid-identity-app-attest",
            "valid-live-presence",
        ),
        &evidence.oidc_verifier,
        &evidence.app_attest_verifier,
        &identity_proofing_provider,
        &liveness_verifier,
        &challenge_store,
        &provider,
        &mut ids,
        &mut repository,
    )
    .expect("valid mobile identity onboarding should append");

    assert_eq!(
        outcome.summary.decision,
        MobileIdentityOnboardingDecision::Accepted
    );
    assert_eq!(outcome.summary.committed_fact_count, 10);
    assert_eq!(
        outcome.summary.fact_ids.enrollment_fact_id,
        Some(id("fact-mobile-identity-enroll-continuity-0"))
    );
    assert_eq!(repository.all_facts().len(), 10);
    assert_eq!(repository.all_episodes().len(), 5);
    assert_eq!(repository.all_memberships().len(), 10);
    assert_eq!(repository.all_episode_relations().len(), 4);

    let facts = repository.all_facts();
    assert!(facts
        .iter()
        .any(|fact| matches!(fact.payload, FactPayload::CredentialAssertion { .. })));
    assert!(facts
        .iter()
        .any(|fact| matches!(fact.payload, FactPayload::DeviceBindingEstablished { .. })));
    assert!(facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::BiometricEnrollmentReferenceAdded { .. }
    )));

    let identity_proofing = fact_by_id(
        &facts,
        &outcome.summary.fact_ids.identity_proofing_witness_fact_id,
    );
    assert!(matches!(
        &identity_proofing.payload,
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::GovernmentIdVerification,
            assurance_level: AssuranceLevel::High,
            evidence_ref: Some(evidence_ref),
            context,
            ..
        } if evidence_ref == "identity-proofing-mobile-identity"
            && context.witness_result == Some(IdentityWitnessResult::Passed)
            && context.retention_policy_refs == vec![id("identity-proof-retention@v1")]
    ));
    assert!(identity_proofing.external_refs.iter().any(|external_ref| {
        external_ref.resource_type.as_deref() == Some("identity_proofing_workflow")
            && external_ref.resource_id == "persona-workflow-mobile-identity"
    }));
    assert!(facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::IdentityAttributeAsserted {
            attribute: IdentityAttribute::LegalName,
            value: IdentityAttributeValue::StringValue(value),
            confidence: MatchConfidence::High,
        } if value == "Mobile Identity Patient"
    )));
    assert!(facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::IdentityAttributeAsserted {
            attribute: IdentityAttribute::DateOfBirth,
            value: IdentityAttributeValue::DateValue(date),
            confidence: MatchConfidence::High,
        } if date == &Date("1990-01-01".to_string())
    )));

    let selfie = fact_by_id(
        &facts,
        &outcome.summary.fact_ids.selfie_liveness_witness_fact_id,
    );
    assert!(matches!(
        &selfie.payload,
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::SelfieLivenessCheck,
            assurance_level: AssuranceLevel::High,
            evidence_ref: None,
            expires_at: Some(expires_at),
            context,
            ..
        } if expires_at == &ts("2026-05-29T00:06:00Z")
            && context.witness_result == Some(IdentityWitnessResult::Passed)
            && context.pad_result == Some(PresentationAttackDetectionResult::Passed)
            && context.challenge_nonce == Some(evidence.app_attest_challenge_nonce.clone())
            && context.device_ref == Some(evidence.device_ref.clone())
            && context.retention_policy_refs == vec![id("live-presence-retention@v1")]
    ));
    assert!(selfie.external_refs.iter().any(|external_ref| {
        external_ref.resource_type.as_deref() == Some("liveness_ceremony_event")
            && external_ref.resource_id == "liveness-event-identity-onboarding"
    }));
    let challenge = challenge_store
        .live_presence_challenge_by_nonce(&evidence.app_attest_challenge_nonce)
        .expect("challenge lookup should succeed")
        .expect("challenge should remain");
    assert!(matches!(
        challenge.status,
        LivePresenceChallengeStatus::Used {
            used_at,
            provider_event_id: Some(ref provider_event_id)
        } if used_at == ts("2026-05-29T00:05:30Z")
            && provider_event_id == "liveness-event-identity-onboarding"
    ));
}

#[test]
fn identity_proofing_manual_review_records_evidence_without_enrollment() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let subject_id: SubjectId = id("subject-mobile-proofing-review");
    let evidence = mobile_evidence_fixture(
        "proofing-review",
        "valid-proofing-review-token",
        "valid-proofing-review-app-attest",
        "iphone-proofing-review-device",
    );
    let liveness_verifier = StaticLivenessCeremonyVerifier::new(
        "valid-proofing-review-live-presence",
        liveness_ceremony(
            "proofing-review",
            &evidence,
            IdentityWitnessResult::Passed,
            PresentationAttackDetectionResult::Passed,
            AssuranceLevel::High,
        ),
    );
    let provider = MockPhase1ContinuityProvider::successful();
    let identity_proofing_provider = PersonaIdentityProofingProvider::new();
    let challenge_store = InMemoryLivePresenceChallengeStore::new();
    issue_live_presence_challenge(&challenge_store, "proofing-review", &subject_id, &evidence);
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();
    let mut request = mobile_identity_onboarding_request(
        author,
        &subject_id.0,
        "mobile-proofing-review",
        &evidence,
        "valid-proofing-review-token",
        "valid-proofing-review-app-attest",
        "valid-proofing-review-live-presence",
    );
    request.identity_proofing.verification_result = IdentityWitnessResult::Inconclusive;

    let outcome = execute_mobile_identity_onboarding_command(
        &service,
        request,
        &evidence.oidc_verifier,
        &evidence.app_attest_verifier,
        &identity_proofing_provider,
        &liveness_verifier,
        &challenge_store,
        &provider,
        &mut ids,
        &mut repository,
    )
    .expect("manual-review identity proofing should still append evidence");

    assert_eq!(
        outcome.summary.decision,
        MobileIdentityOnboardingDecision::ManualReviewRequired
    );
    assert_eq!(outcome.summary.fact_ids.enrollment_fact_id, None);
    assert_eq!(repository.all_facts().len(), 9);
    assert!(!repository.all_facts().iter().any(|fact| matches!(
        fact.payload,
        FactPayload::BiometricEnrollmentReferenceAdded { .. }
    )));
    let facts = repository.all_facts();
    let proofing = fact_by_id(
        &facts,
        &outcome.summary.fact_ids.identity_proofing_witness_fact_id,
    );
    assert!(matches!(
        &proofing.payload,
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::GovernmentIdVerification,
            context,
            ..
        } if context.witness_result == Some(IdentityWitnessResult::Inconclusive)
    ));
}

#[test]
fn failed_or_inconclusive_mobile_liveness_creates_manual_review_evidence() {
    for (label, result, pad_result) in [
        (
            "failed",
            IdentityWitnessResult::Failed,
            PresentationAttackDetectionResult::Failed,
        ),
        (
            "inconclusive",
            IdentityWitnessResult::Inconclusive,
            PresentationAttackDetectionResult::Inconclusive,
        ),
    ] {
        let author = system_author();
        let service = IdentityWorkflowService::new(FenTranslator {
            system_author: author.clone(),
        });
        let evidence = mobile_evidence_fixture(
            label,
            &format!("valid-{label}-token"),
            &format!("valid-{label}-app-attest"),
            &format!("iphone-{label}-device"),
        );
        let liveness_verifier = StaticLivenessCeremonyVerifier::new(
            format!("valid-{label}-live-presence"),
            liveness_ceremony(label, &evidence, result, pad_result, AssuranceLevel::Low),
        );
        let provider = MockPhase1ContinuityProvider::successful();
        let identity_proofing_provider = PersonaIdentityProofingProvider::new();
        let subject_id: SubjectId = id(&format!("subject-mobile-{label}"));
        let challenge_store = InMemoryLivePresenceChallengeStore::new();
        issue_live_presence_challenge(
            &challenge_store,
            &format!("challenge-{label}"),
            &subject_id,
            &evidence,
        );
        let mut ids = DeterministicIdGenerator::new();
        let mut repository = InMemoryIdentityRepository::new();

        let outcome = execute_mobile_identity_onboarding_command(
            &service,
            mobile_identity_onboarding_request(
                author,
                &subject_id.0,
                &format!("mobile-{label}"),
                &evidence,
                &format!("valid-{label}-token"),
                &format!("valid-{label}-app-attest"),
                &format!("valid-{label}-live-presence"),
            ),
            &evidence.oidc_verifier,
            &evidence.app_attest_verifier,
            &identity_proofing_provider,
            &liveness_verifier,
            &challenge_store,
            &provider,
            &mut ids,
            &mut repository,
        )
        .expect("failed or inconclusive liveness should still append evidence");

        assert_eq!(
            outcome.summary.decision,
            MobileIdentityOnboardingDecision::ManualReviewRequired
        );
        assert_eq!(outcome.summary.fact_ids.enrollment_fact_id, None);
        assert_eq!(repository.all_facts().len(), 9);
        assert!(!repository.all_facts().iter().any(|fact| matches!(
            fact.payload,
            FactPayload::BiometricEnrollmentReferenceAdded { .. }
        )));

        let facts = repository.all_facts();
        let selfie = fact_by_id(
            &facts,
            &outcome.summary.fact_ids.selfie_liveness_witness_fact_id,
        );
        assert!(matches!(
            &selfie.payload,
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::SelfieLivenessCheck,
                assurance_level: AssuranceLevel::Low,
                context,
                ..
            } if context.witness_result == Some(result)
                && context.pad_result == Some(pad_result)
                && context.challenge_nonce == Some(evidence.app_attest_challenge_nonce.clone())
                && context.device_ref == Some(evidence.device_ref.clone())
        ));
        let challenge = challenge_store
            .live_presence_challenge_by_nonce(&evidence.app_attest_challenge_nonce)
            .expect("challenge lookup should succeed")
            .expect("challenge should remain");
        match (result, challenge.status) {
            (
                IdentityWitnessResult::Failed,
                LivePresenceChallengeStatus::Failed {
                    reason: LivePresenceChallengeFailureReason::PresentationAttackDetected,
                    ..
                },
            ) => {}
            (
                IdentityWitnessResult::Inconclusive,
                LivePresenceChallengeStatus::ManualReview {
                    reason: LivePresenceChallengeManualReviewReason::LivenessInconclusive,
                    ..
                },
            ) => {}
            (_, status) => panic!("unexpected challenge status: {status:?}"),
        }
    }
}

#[test]
fn mobile_identity_onboarding_requires_issued_live_presence_challenge() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let evidence = mobile_evidence_fixture(
        "missing-challenge",
        "valid-missing-challenge-token",
        "valid-missing-challenge-app-attest",
        "iphone-missing-challenge-device",
    );
    let liveness_verifier = StaticLivenessCeremonyVerifier::new(
        "valid-missing-challenge-live-presence",
        liveness_ceremony(
            "missing-challenge",
            &evidence,
            IdentityWitnessResult::Passed,
            PresentationAttackDetectionResult::Passed,
            AssuranceLevel::High,
        ),
    );
    let provider = MockPhase1ContinuityProvider::successful();
    let identity_proofing_provider = PersonaIdentityProofingProvider::new();
    let challenge_store = InMemoryLivePresenceChallengeStore::new();
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let result = execute_mobile_identity_onboarding_command(
        &service,
        mobile_identity_onboarding_request(
            author,
            "subject-mobile-missing-challenge",
            "mobile-missing-challenge",
            &evidence,
            "valid-missing-challenge-token",
            "valid-missing-challenge-app-attest",
            "valid-missing-challenge-live-presence",
        ),
        &evidence.oidc_verifier,
        &evidence.app_attest_verifier,
        &identity_proofing_provider,
        &liveness_verifier,
        &challenge_store,
        &provider,
        &mut ids,
        &mut repository,
    );

    assert_eq!(
        result,
        Err(MobileIdentityOnboardingCommandError::LivePresenceChallenge(
            LivePresenceChallengeError::UnknownChallenge
        ))
    );
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_memberships().is_empty());
}

#[test]
fn mobile_liveness_must_bind_to_app_attest_challenge() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let evidence = mobile_evidence_fixture(
        "binding",
        "valid-binding-token",
        "valid-binding-app-attest",
        "iphone-binding-device",
    );
    let mut ceremony = liveness_ceremony(
        "binding",
        &evidence,
        IdentityWitnessResult::Passed,
        PresentationAttackDetectionResult::Passed,
        AssuranceLevel::High,
    );
    ceremony.challenge_nonce = "different-live-presence-nonce".to_string();
    let liveness_verifier =
        StaticLivenessCeremonyVerifier::new("valid-binding-live-presence", ceremony);
    let provider = MockPhase1ContinuityProvider::successful();
    let identity_proofing_provider = PersonaIdentityProofingProvider::new();
    let challenge_store = InMemoryLivePresenceChallengeStore::new();
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let result = execute_mobile_identity_onboarding_command(
        &service,
        mobile_identity_onboarding_request(
            author,
            "subject-mobile-binding",
            "mobile-binding",
            &evidence,
            "valid-binding-token",
            "valid-binding-app-attest",
            "valid-binding-live-presence",
        ),
        &evidence.oidc_verifier,
        &evidence.app_attest_verifier,
        &identity_proofing_provider,
        &liveness_verifier,
        &challenge_store,
        &provider,
        &mut ids,
        &mut repository,
    );

    assert_eq!(
        result,
        Err(MobileIdentityOnboardingCommandError::Liveness(
            LivenessCeremonyVerificationError::ChallengeMismatch
        ))
    );
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_memberships().is_empty());
}

#[test]
fn static_liveness_verifier_rebinds_device_ref_from_request() {
    // Regression: in apple_assertion mode the device ref is a real per-install
    // phone value carried on each request, not something known when the static
    // liveness verifier is configured from env. Without request-device-ref
    // binding the verifier kept its template device ref and later failed the
    // ceremony/App-Attest device match (DeviceMismatch); the opt-in rebind makes
    // the verified ceremony follow the request's device ref, mirroring the
    // existing challenge-nonce rebinding.
    let template = VerifiedLivenessCeremony {
        provider_metadata: ContinuityProviderMetadata {
            provider_name: "StaticLivePresenceProvider".to_string(),
            provider_event_id: Some("liveness-event-rebind".to_string()),
            provider_subject_ref: Some("liveness-subject-rebind".to_string()),
            sdk_or_api_version: Some("static/1.0".to_string()),
        },
        challenge_nonce: "live-presence-nonce".to_string(),
        device_ref: "env-template-device".to_string(),
        observed_at: ts("2026-05-29T00:05:20Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        result: IdentityWitnessResult::Passed,
        assurance_level: AssuranceLevel::High,
        pad_result: PresentationAttackDetectionResult::Passed,
        retention_policy_refs: vec![id("live-presence-retention@v1")],
    };
    let request = LivenessCeremonyVerificationRequest {
        assertion: "valid-live-presence".to_string(),
        challenge_nonce: "live-presence-nonce".to_string(),
        expected_device_ref: Some("real-phone-device".to_string()),
    };
    let observed_at = ts("2026-05-29T00:05:30Z");

    // Without rebinding, the template device ref does not match the request's.
    let strict = StaticLivenessCeremonyVerifier::new("valid-live-presence", template.clone());
    assert!(matches!(
        strict.verify_liveness_ceremony(&request, &observed_at),
        Err(LivenessCeremonyVerificationError::DeviceRefMismatch)
    ));

    // With rebinding, the verified ceremony follows the request's device ref.
    let rebinding = StaticLivenessCeremonyVerifier::new("valid-live-presence", template)
        .with_request_device_ref();
    let verified = rebinding
        .verify_liveness_ceremony(&request, &observed_at)
        .expect("request-device-ref binding should accept the dynamic device ref");
    assert_eq!(verified.device_ref, "real-phone-device");
}

fn mobile_identity_onboarding_request(
    authored_by: Author,
    subject_id: &str,
    id_namespace: &str,
    evidence: &MobileEvidenceFixture,
    token: &str,
    app_attest_assertion: &str,
    liveness_assertion: &str,
) -> MobileIdentityOnboardingCommandRequest {
    MobileIdentityOnboardingCommandRequest {
        account: AccountTokenBootstrapRequest {
            subject_id: id(subject_id),
            authored_by,
            observed_at: ts("2026-05-29T00:05:30Z"),
            id_namespace: id_namespace.to_string(),
            token: token.to_string(),
            oidc_config: evidence.oidc_config.clone(),
            device_ref: Some(evidence.device_ref.clone()),
            assurance_policy: OidcAssurancePolicy::default(),
        },
        app_attest: AppAttestAssertionVerificationRequest {
            assertion: app_attest_assertion.to_string(),
            challenge_nonce: evidence.app_attest_challenge_nonce.clone(),
            config: evidence.app_attest_config.clone(),
        },
        liveness: LivenessCeremonyVerificationRequest {
            assertion: liveness_assertion.to_string(),
            challenge_nonce: evidence.app_attest_challenge_nonce.clone(),
            expected_device_ref: Some(evidence.device_ref.clone()),
        },
        identity_proofing: persona_identity_proofing_request(id_namespace),
        client_context: MobileOnboardingClientContext::iphone(format!("request-{id_namespace}")),
        subject_kind: SubjectKind::HumanPerson,
        stable_profile: StableIdentityProfile {
            legal_name: Some("Mobile Identity Patient".to_string()),
            date_of_birth: Some(Date("1990-01-01".to_string())),
            demographic_attributes: Vec::new(),
        },
        continuity_modality: BiometricModality::Face,
    }
}

fn issue_live_presence_challenge(
    store: &impl LivePresenceChallengeStore,
    challenge_label: &str,
    subject_id: &SubjectId,
    evidence: &MobileEvidenceFixture,
) {
    let mut challenge = LivePresenceChallenge::onboarding(
        id(&format!("live-presence-{challenge_label}")),
        evidence.app_attest_challenge_nonce.clone(),
        Some(subject_id.clone()),
        Some(evidence.device_ref.clone()),
        Some(LivePresenceExpectedAppContext::from_app_attest_config(
            &evidence.app_attest_config,
        )),
        ts("2026-05-29T00:04:55Z"),
        ts("2026-05-29T00:06:00Z"),
    );
    challenge.retry_policy_refs = vec![id("live-presence-retry@v1")];
    challenge.manual_review_policy_refs = vec![id("live-presence-manual-review@v1")];
    challenge.retention_policy_refs = vec![id("live-presence-retention@v1")];
    store
        .issue_live_presence_challenge(challenge)
        .expect("live-presence challenge should issue");
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

fn fact_by_id<'a>(facts: &'a [Fact], fact_id: &FactId) -> &'a Fact {
    facts
        .iter()
        .find(|fact| &fact.id == fact_id)
        .expect("fact should exist")
}
