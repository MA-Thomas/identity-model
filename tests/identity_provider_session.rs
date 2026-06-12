use identity_model::*;

mod common;
use common::*;

#[test]
fn keycloak_session_bootstrap_records_login_witness_and_verified_email() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let session = VerifiedOidcSession::keycloak(
        config.issuer.clone(),
        "keycloak-user-123",
        config.client_id.clone(),
        "session-abc",
        ts("2026-05-29T00:00:00Z"),
        ts("2026-05-29T01:00:00Z"),
    )
    .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
    .with_verified_email("patient@example.test")
    .with_preferred_username("patient");
    let verifier = StaticOidcSessionVerifier::new("verified-access-token", session);
    let verified_session = verifier
        .verify_session(
            "verified-access-token",
            &config,
            &ts("2026-05-29T00:05:00Z"),
        )
        .expect("static verifier should accept expected Keycloak session");
    let mut ids = DeterministicIdGenerator::new();

    let outcome =
        service.accept_account_session(AccountSessionBootstrapRequest::with_generated_ids(
            id("subject-keycloak-bootstrap"),
            author,
            ts("2026-05-29T00:05:00Z"),
            verified_session,
            Some("iphone-passkey-device".to_string()),
            OidcAssurancePolicy::default(),
            "keycloak-bootstrap",
            &mut ids,
        ));

    assert_eq!(
        outcome.workflow.slice.episode.label,
        "Keycloak account session".to_string()
    );
    assert_eq!(outcome.credential_fact_id, id("fact-keycloak-bootstrap-0"));
    assert_eq!(
        outcome.portal_login_witness_fact_id,
        id("fact-keycloak-bootstrap-1")
    );
    assert_eq!(
        outcome.verified_email_attribute_fact_id,
        Some(id("fact-keycloak-bootstrap-2"))
    );
    assert_eq!(outcome.workflow.slice.facts.len(), 3);
    assert_eq!(outcome.workflow.slice.memberships.len(), 3);
    assert_eq!(
        outcome.workflow.projection.assurance_level,
        AssuranceLevel::Medium
    );

    let credential = fact_by_id(&outcome.workflow.slice.facts, &outcome.credential_fact_id);
    assert!(matches!(
        &credential.payload,
        FactPayload::CredentialAssertion {
            authenticator_type: AuthenticatorType::Passkey,
            device_ref: Some(device_ref),
            result: CredentialAssertionResult::Succeeded,
            assurance_level: AssuranceLevel::Medium,
        } if device_ref == "iphone-passkey-device"
    ));
    assert_eq!(
        credential.provenance.source_system,
        Some("Keycloak:https://id.example.test/realms/fen".to_string())
    );
    assert!(credential.external_refs.iter().any(|reference| matches!(
        reference,
        ExternalRef {
            system: ExternalSystem::IdentityProvider,
            resource_type: Some(resource_type),
            resource_id,
            ..
        } if resource_type == "oidc_subject"
            && resource_id == "https://id.example.test/realms/fen#keycloak-user-123"
    )));
    assert!(credential.external_refs.iter().any(|reference| matches!(
        reference,
        ExternalRef {
            resource_type: Some(resource_type),
            resource_id,
            ..
        } if resource_type == "oidc_session"
            && resource_id == "https://id.example.test/realms/fen#session-abc"
    )));
    assert!(credential.external_refs.iter().any(|reference| matches!(
        reference,
        ExternalRef {
            resource_type: Some(resource_type),
            resource_id,
            ..
        } if resource_type == "oidc_client" && resource_id == "fen-identity"
    )));

    let witness = fact_by_id(
        &outcome.workflow.slice.facts,
        &outcome.portal_login_witness_fact_id,
    );
    assert!(matches!(
        &witness.payload,
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::PatientPortalLoginProof,
            target_subject_id,
            assurance_level: AssuranceLevel::Medium,
            expires_at: Some(expires_at),
            ..
        } if target_subject_id == &id("subject-keycloak-bootstrap")
            && expires_at == &ts("2026-05-29T01:00:00Z")
    ));

    let email_fact = fact_by_id(
        &outcome.workflow.slice.facts,
        &outcome
            .verified_email_attribute_fact_id
            .clone()
            .expect("verified email fact should exist"),
    );
    assert!(matches!(
        &email_fact.payload,
        FactPayload::IdentityAttributeAsserted {
            attribute: IdentityAttribute::Email,
            value: IdentityAttributeValue::StringValue(email),
            confidence: MatchConfidence::Medium,
        } if email == "patient@example.test"
    ));
}

#[test]
fn oidc_session_verifier_rejects_wrong_token_context_and_expiration() {
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let session = VerifiedOidcSession::keycloak(
        config.issuer.clone(),
        "keycloak-user-123",
        config.client_id.clone(),
        "session-abc",
        ts("2026-05-29T00:00:00Z"),
        ts("2026-05-29T01:00:00Z"),
    );
    let verifier = StaticOidcSessionVerifier::new("expected-token", session.clone());

    assert_eq!(
        verifier.verify_session("wrong-token", &config, &ts("2026-05-29T00:05:00Z")),
        Err(OidcSessionVerificationError::InvalidToken)
    );
    assert_eq!(
        verifier.verify_session(
            "expected-token",
            &OidcClientConfig::keycloak(config.issuer.clone(), "different-client"),
            &ts("2026-05-29T00:05:00Z")
        ),
        Err(OidcSessionVerificationError::AudienceMismatch)
    );
    assert_eq!(
        verifier.verify_session("expected-token", &config, &ts("2026-05-29T01:00:00Z")),
        Err(OidcSessionVerificationError::Expired)
    );
    assert_eq!(
        verifier.verify_session("expected-token", &config, &ts("2026-02-31T00:05:00Z")),
        Err(OidcSessionVerificationError::InvalidObservedTimestamp)
    );

    let invalid_session_timestamp = StaticOidcSessionVerifier::new(
        "expected-token",
        VerifiedOidcSession {
            expires_at: ts("2026-02-31T01:00:00Z"),
            ..session.clone()
        },
    );
    assert_eq!(
        invalid_session_timestamp.verify_session(
            "expected-token",
            &config,
            &ts("2026-05-29T00:05:00Z")
        ),
        Err(OidcSessionVerificationError::InvalidSessionTimestamp)
    );

    let wrong_issuer = StaticOidcSessionVerifier::new(
        "expected-token",
        VerifiedOidcSession {
            issuer: "https://id.example.test/realms/other".to_string(),
            ..session
        },
    );
    assert_eq!(
        wrong_issuer.verify_session("expected-token", &config, &ts("2026-05-29T00:05:00Z")),
        Err(OidcSessionVerificationError::IssuerMismatch)
    );
}

#[test]
fn unverified_oidc_email_is_not_promoted_to_identity_attribute_fact() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let session = VerifiedOidcSession::keycloak(
        "https://id.example.test/realms/fen",
        "keycloak-user-456",
        "fen-identity",
        "session-def",
        ts("2026-05-29T00:00:00Z"),
        ts("2026-05-29T01:00:00Z"),
    )
    .with_amr(vec!["pwd".to_string()])
    .with_unverified_email("unverified@example.test");
    let mut ids = DeterministicIdGenerator::new();

    let outcome =
        service.accept_account_session(AccountSessionBootstrapRequest::with_generated_ids(
            id("subject-unverified-email"),
            author,
            ts("2026-05-29T00:05:00Z"),
            session,
            None,
            OidcAssurancePolicy::default(),
            "unverified-email",
            &mut ids,
        ));

    assert_eq!(outcome.workflow.slice.facts.len(), 2);
    assert_eq!(outcome.verified_email_attribute_fact_id, None);
    assert_eq!(
        outcome.workflow.projection.assurance_level,
        AssuranceLevel::Low
    );

    let credential = fact_by_id(&outcome.workflow.slice.facts, &outcome.credential_fact_id);
    assert!(matches!(
        &credential.payload,
        FactPayload::CredentialAssertion {
            authenticator_type: AuthenticatorType::Password,
            device_ref: None,
            result: CredentialAssertionResult::Succeeded,
            assurance_level: AssuranceLevel::Low,
        }
    ));
}

#[test]
fn service_can_accept_account_token_and_append_replayable_session_evidence() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-keycloak-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-token-user",
            config.client_id.clone(),
            "token-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("token.patient@example.test"),
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let persisted = service
        .accept_account_token_append_and_replay(
            AccountTokenBootstrapRequest {
                subject_id: id("subject-account-token"),
                authored_by: author,
                observed_at: ts("2026-05-29T00:05:00Z"),
                id_namespace: "account-token".to_string(),
                token: "valid-keycloak-token".to_string(),
                oidc_config: config,
                device_ref: Some("iphone-passkey-device".to_string()),
                assurance_policy: OidcAssurancePolicy::default(),
            },
            &verifier,
            &mut ids,
            &mut repository,
        )
        .expect("valid token should append session evidence");

    assert_eq!(
        persisted.bootstrap.credential_fact_id,
        id("fact-account-token-0")
    );
    assert_eq!(
        persisted.bootstrap.portal_login_witness_fact_id,
        id("fact-account-token-1")
    );
    assert_eq!(
        persisted.bootstrap.verified_email_attribute_fact_id,
        Some(id("fact-account-token-2"))
    );
    assert_eq!(
        persisted.replayed_projection,
        persisted.bootstrap.workflow.projection
    );
    assert_eq!(repository.all_facts().len(), 3);
    assert_eq!(repository.all_episodes().len(), 1);
    assert_eq!(repository.all_memberships().len(), 3);
}

#[test]
fn service_can_accept_account_token_with_app_attest_and_append_device_evidence() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-keycloak-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-token-user",
            config.client_id.clone(),
            "token-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("token.patient@example.test"),
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
            device_ref: "iphone-app-attest-device".to_string(),
            key_id: "app-attest-key-1".to_string(),
            challenge_nonce: "app-attest-nonce-1".to_string(),
            sign_count: 7,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let persisted = service
        .accept_account_token_with_app_attest_append_and_replay(
            AccountTokenWithAppAttestBootstrapRequest {
                account: AccountTokenBootstrapRequest {
                    subject_id: id("subject-iphone-app-attest"),
                    authored_by: author,
                    observed_at: ts("2026-05-29T00:05:30Z"),
                    id_namespace: "iphone-app-attest".to_string(),
                    token: "valid-keycloak-token".to_string(),
                    oidc_config: config,
                    device_ref: None,
                    assurance_policy: OidcAssurancePolicy::default(),
                },
                app_attest: AppAttestAssertionVerificationRequest {
                    assertion: "valid-app-attest-assertion".to_string(),
                    challenge_nonce: "app-attest-nonce-1".to_string(),
                    config: app_attest_config,
                },
            },
            &verifier,
            &app_attest_verifier,
            &mut ids,
            &mut repository,
        )
        .expect("valid token and App Attest assertion should append device evidence");

    assert_eq!(
        persisted.bootstrap.credential_fact_id,
        id("fact-iphone-app-attest-0")
    );
    assert_eq!(
        persisted.bootstrap.portal_login_witness_fact_id,
        id("fact-iphone-app-attest-1")
    );
    assert_eq!(
        persisted.bootstrap.verified_email_attribute_fact_id,
        Some(id("fact-iphone-app-attest-2"))
    );
    assert_eq!(
        persisted.bootstrap.device_binding_fact_id,
        Some(id("fact-iphone-app-attest-3"))
    );
    assert_eq!(repository.all_facts().len(), 4);
    assert_eq!(repository.all_episodes().len(), 1);
    assert_eq!(repository.all_memberships().len(), 4);
    assert_eq!(
        persisted.replayed_projection.active_devices,
        vec!["iphone-app-attest-device".to_string()]
    );

    let device_fact = fact_by_id(
        &persisted.bootstrap.workflow.slice.facts,
        &persisted
            .bootstrap
            .device_binding_fact_id
            .clone()
            .expect("device binding fact should exist"),
    );
    assert!(matches!(
        &device_fact.payload,
        FactPayload::DeviceBindingEstablished {
            device_ref,
            authenticator_type: AuthenticatorType::Other(kind),
            assurance_level: AssuranceLevel::Medium,
        } if device_ref == "iphone-app-attest-device" && kind == "apple_app_attest"
    ));
    assert_eq!(
        device_fact.provenance.source_system,
        Some("AppleAppAttest:TEAMID1234.com.fen.identity".to_string())
    );
    assert!(device_fact.external_refs.iter().any(|reference| matches!(
        reference,
        ExternalRef {
            system: ExternalSystem::Other(system),
            resource_type: Some(resource_type),
            resource_id,
            ..
        } if system == "AppleAppAttest"
            && resource_type == "app_attest_key"
            && resource_id == "app-attest-key-1"
    )));
}

#[test]
fn app_attest_rejection_prevents_account_token_append() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-keycloak-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-token-user",
            config.client_id.clone(),
            "token-session-123",
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
            device_ref: "iphone-app-attest-device".to_string(),
            key_id: "app-attest-key-1".to_string(),
            challenge_nonce: "app-attest-nonce-1".to_string(),
            sign_count: 7,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let result = service.accept_account_token_with_app_attest_append_and_replay(
        AccountTokenWithAppAttestBootstrapRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: id("subject-iphone-app-attest-rejected"),
                authored_by: author,
                observed_at: ts("2026-05-29T00:05:30Z"),
                id_namespace: "iphone-app-attest-rejected".to_string(),
                token: "valid-keycloak-token".to_string(),
                oidc_config: config,
                device_ref: None,
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: "valid-app-attest-assertion".to_string(),
                challenge_nonce: "wrong-nonce".to_string(),
                config: app_attest_config,
            },
        },
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    );

    assert_eq!(
        result,
        Err(AccountTokenWithAppAttestBootstrapError::AppAttest(
            AppAttestAssertionVerificationError::ChallengeMismatch
        ))
    );
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_memberships().is_empty());
}

#[test]
fn service_account_token_harness_surfaces_verifier_errors_without_appending() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "different-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-token-user",
            config.client_id.clone(),
            "token-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        ),
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let result = service.accept_account_token_append_and_replay(
        AccountTokenBootstrapRequest {
            subject_id: id("subject-account-token-rejected"),
            authored_by: author,
            observed_at: ts("2026-05-29T00:05:00Z"),
            id_namespace: "account-token-rejected".to_string(),
            token: "invalid-token".to_string(),
            oidc_config: config,
            device_ref: None,
            assurance_policy: OidcAssurancePolicy::default(),
        },
        &verifier,
        &mut ids,
        &mut repository,
    );

    assert_eq!(
        result,
        Err(AccountTokenBootstrapError::Verification(
            OidcSessionVerificationError::InvalidToken
        ))
    );
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_memberships().is_empty());
}

fn fact_by_id<'a>(facts: &'a [Fact], fact_id: &FactId) -> &'a Fact {
    facts
        .iter()
        .find(|fact| &fact.id == fact_id)
        .expect("fact should exist")
}

#[cfg(feature = "oidc-jwks-verifier")]
mod live_jwks {
    use super::*;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::Serialize;
    use serde_json::json;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize)]
    struct TestOidcClaims {
        iss: String,
        sub: String,
        aud: Vec<String>,
        azp: String,
        sid: String,
        nonce: String,
        auth_time: i64,
        iat: i64,
        exp: i64,
        acr: String,
        amr: Vec<String>,
        email: String,
        email_verified: bool,
        preferred_username: String,
        name: String,
    }

    #[test]
    fn jwks_verifier_validates_rs256_keycloak_token_into_verified_session() {
        let config =
            OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
        let issued_at = timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00Z")).unwrap();
        let expires_at = timestamp_to_unix_seconds(&ts("2033-05-18T03:33:20Z")).unwrap();
        let token = signed_rs256_token(
            "rsa01",
            TestOidcClaims {
                iss: config.issuer.clone(),
                sub: "keycloak-live-user".to_string(),
                aud: vec!["account".to_string(), config.client_id.clone()],
                azp: config.client_id.clone(),
                sid: "live-session-123".to_string(),
                nonce: "nonce-live-123".to_string(),
                auth_time: issued_at,
                iat: issued_at,
                exp: expires_at,
                acr: "urn:fen:aal2".to_string(),
                amr: vec!["pwd".to_string(), "webauthn".to_string()],
                email: "live.patient@example.test".to_string(),
                email_verified: true,
                preferred_username: "live-patient".to_string(),
                name: "Live Patient".to_string(),
            },
        );

        let session = OidcJwksSessionVerifier::new()
            .verify_session_with_jwks(&token, &config, &ts("2026-05-29T00:01:00Z"), &rsa_jwk_set())
            .expect("RS256 token should verify against JWKS");

        assert_eq!(session.provider_name, "Keycloak".to_string());
        assert_eq!(session.issuer, config.issuer);
        assert_eq!(session.subject, "keycloak-live-user".to_string());
        assert_eq!(
            session.audiences,
            vec!["account".to_string(), "fen-identity".to_string()]
        );
        assert_eq!(session.authorized_party, Some("fen-identity".to_string()));
        assert_eq!(session.session_id, Some("live-session-123".to_string()));
        assert_eq!(session.nonce, Some("nonce-live-123".to_string()));
        assert_eq!(session.auth_time, Some(ts("2026-05-29T00:00:00Z")));
        assert_eq!(session.issued_at, ts("2026-05-29T00:00:00Z"));
        assert_eq!(session.expires_at, ts("2033-05-18T03:33:20Z"));
        assert_eq!(session.acr, Some("urn:fen:aal2".to_string()));
        assert_eq!(session.amr, vec!["pwd".to_string(), "webauthn".to_string()]);
        assert_eq!(session.verified_email(), Some("live.patient@example.test"));
        assert_eq!(session.preferred_username, Some("live-patient".to_string()));
        assert_eq!(session.display_name, Some("Live Patient".to_string()));
    }

    #[test]
    fn jwks_verifier_rejects_symmetric_algorithm_unknown_kid_and_observed_expiration() {
        let config =
            OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
        let claims = TestOidcClaims {
            iss: config.issuer.clone(),
            sub: "keycloak-live-user".to_string(),
            aud: vec![config.client_id.clone()],
            azp: config.client_id.clone(),
            sid: "live-session-123".to_string(),
            nonce: "nonce-live-123".to_string(),
            auth_time: timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00Z")).unwrap(),
            iat: timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00Z")).unwrap(),
            exp: timestamp_to_unix_seconds(&ts("2033-05-18T03:33:20Z")).unwrap(),
            acr: "urn:fen:aal2".to_string(),
            amr: vec!["pwd".to_string()],
            email: "live.patient@example.test".to_string(),
            email_verified: true,
            preferred_username: "live-patient".to_string(),
            name: "Live Patient".to_string(),
        };
        let verifier = OidcJwksSessionVerifier::new();

        assert_eq!(
            verifier.verify_session_with_jwks(
                &signed_hs256_token("rsa01", &claims),
                &config,
                &ts("2026-05-29T00:01:00Z"),
                &rsa_jwk_set(),
            ),
            Err(OidcSessionVerificationError::UnsupportedAlgorithm)
        );
        assert_eq!(
            verifier.verify_session_with_jwks(
                &signed_rs256_token("missing", claims),
                &config,
                &ts("2026-05-29T00:01:00Z"),
                &rsa_jwk_set(),
            ),
            Err(OidcSessionVerificationError::UnknownKeyId)
        );

        let expired_for_observation = signed_rs256_token(
            "rsa01",
            TestOidcClaims {
                iss: config.issuer.clone(),
                sub: "keycloak-live-user".to_string(),
                aud: vec![config.client_id.clone()],
                azp: config.client_id.clone(),
                sid: "live-session-123".to_string(),
                nonce: "nonce-live-123".to_string(),
                auth_time: timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00Z")).unwrap(),
                iat: timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00Z")).unwrap(),
                exp: timestamp_to_unix_seconds(&ts("2026-05-29T00:02:00Z")).unwrap(),
                acr: "urn:fen:aal1".to_string(),
                amr: vec!["pwd".to_string()],
                email: "live.patient@example.test".to_string(),
                email_verified: true,
                preferred_username: "live-patient".to_string(),
                name: "Live Patient".to_string(),
            },
        );

        assert_eq!(
            verifier.verify_session_with_jwks(
                &expired_for_observation,
                &config,
                &ts("2026-05-29T00:02:00Z"),
                &rsa_jwk_set(),
            ),
            Err(OidcSessionVerificationError::Expired)
        );
    }

    #[test]
    fn unix_seconds_timestamp_conversion_round_trips_jwt_claim_times() {
        for timestamp in [
            ts("1970-01-01T00:00:00Z"),
            ts("2026-05-29T00:00:00Z"),
            ts("2033-05-18T03:33:20Z"),
        ] {
            let seconds = timestamp_to_unix_seconds(&timestamp).unwrap();

            assert_eq!(unix_seconds_to_timestamp(seconds), timestamp);
        }
    }

    #[test]
    fn live_keycloak_token_can_bootstrap_append_and_replay_when_env_is_set() {
        let Ok(issuer) = env::var("IDENTITY_MODEL_KEYCLOAK_ISSUER") else {
            return;
        };
        let Ok(client_id) = env::var("IDENTITY_MODEL_KEYCLOAK_CLIENT_ID") else {
            return;
        };
        let Ok(token) = env::var("IDENTITY_MODEL_KEYCLOAK_TOKEN") else {
            return;
        };
        let subject_id: SubjectId = env::var("IDENTITY_MODEL_KEYCLOAK_SUBJECT_ID")
            .map(|value| id(&value))
            .unwrap_or_else(|_| id("subject-live-keycloak"));
        let device_ref = env::var("IDENTITY_MODEL_KEYCLOAK_DEVICE_REF").ok();
        let observed_at = unix_seconds_to_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_secs() as i64,
        );
        let author = system_author();
        let service = IdentityWorkflowService::new(FenTranslator {
            system_author: author.clone(),
        });
        let verifier = OidcJwksSessionVerifier::new();
        let mut ids = DeterministicIdGenerator::new();
        let mut repository = InMemoryIdentityRepository::new();

        let persisted = service
            .accept_account_token_append_and_replay(
                AccountTokenBootstrapRequest {
                    subject_id: subject_id.clone(),
                    authored_by: author,
                    observed_at,
                    id_namespace: "live-keycloak".to_string(),
                    token,
                    oidc_config: OidcClientConfig::keycloak(issuer, client_id),
                    device_ref,
                    assurance_policy: OidcAssurancePolicy::default(),
                },
                &verifier,
                &mut ids,
                &mut repository,
            )
            .expect("live Keycloak token should verify and append");

        assert_eq!(persisted.replayed_projection.subject_id, subject_id);
        assert_eq!(
            persisted.replayed_projection,
            replay_identity_state_from_repository(subject_id, &repository)
        );
        assert!(!repository.all_facts().is_empty());
        assert_eq!(repository.all_episodes().len(), 1);
    }

    fn signed_rs256_token(kid: &str, claims: TestOidcClaims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn signed_hs256_token(kid: &str, claims: &TestOidcClaims) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &EncodingKey::from_secret(b"test-secret")).unwrap()
    }

    fn rsa_jwk_set() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "rsa01",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
                    "e": "AQAB"
                }
            ]
        }))
        .unwrap()
    }

    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;
}
