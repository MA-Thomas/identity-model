#![cfg(feature = "mobile-http")]

use identity_model::*;
use serde_json::json;

mod common;
use common::*;

#[test]
fn mobile_onboarding_http_endpoint_accepts_valid_request() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let fixture = mobile_evidence_fixture(
        "http",
        "valid-http-token",
        "valid-app-attest-assertion",
        "iphone-http-device",
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();
    let request_body = json!({
        "subject_id": "subject-mobile-http",
        "observed_at": "2026-05-29T00:05:30Z",
        "id_namespace": "mobile-http",
        "expected_device_ref": fixture.device_ref.clone(),
        "oidc": {
            "access_token": "valid-http-token",
            "issuer": fixture.oidc_config.issuer.clone(),
            "client_id": fixture.oidc_config.client_id.clone(),
            "provider_name": "Keycloak"
        },
        "app_attest": {
            "assertion": fixture.app_attest_assertion.clone(),
            "challenge_nonce": fixture.app_attest_challenge_nonce.clone(),
            "team_id": fixture.app_attest_config.team_id.clone(),
            "bundle_id": fixture.app_attest_config.bundle_id.clone(),
            "environment": "development"
        },
        "client_context": {
            "platform": "iphone",
            "request_id": "request-mobile-http",
            "app_version": "1.0.0",
            "user_agent": "FENIdentity/1.0"
        }
    });

    let response = handle_mobile_onboarding_http_request(
        MobileOnboardingHttpRequest::post(MOBILE_ONBOARDING_HTTP_PATH, request_body.to_string()),
        &service,
        author,
        &fixture.oidc_verifier,
        &fixture.app_attest_verifier,
        &mut ids,
        &mut repository,
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.content_type, APPLICATION_JSON);
    let body: MobileOnboardingHttpResponseBody =
        serde_json::from_str(&response.body).expect("accepted response should be JSON");
    assert_eq!(
        body,
        MobileOnboardingHttpResponseBody::Accepted {
            request_id: Some("request-mobile-http".to_string()),
            summary: MobileOnboardingHttpSummary {
                subject_id: "subject-mobile-http".to_string(),
                assurance_level: "medium".to_string(),
                active_devices: vec!["iphone-http-device".to_string()],
                workflow_episode_id: "episode-mobile-http-0".to_string(),
                fact_ids: MobileOnboardingHttpFactIds {
                    credential_fact_id: "fact-mobile-http-0".to_string(),
                    portal_login_witness_fact_id: "fact-mobile-http-1".to_string(),
                    verified_email_attribute_fact_id: Some("fact-mobile-http-2".to_string()),
                    device_binding_fact_id: "fact-mobile-http-3".to_string(),
                },
                committed_fact_count: 4,
            },
        }
    );
    assert_eq!(repository.all_facts().len(), 4);
}

#[test]
fn mobile_onboarding_http_endpoint_can_append_through_encrypted_facade() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-encrypted-http-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-encrypted-http-user",
            config.client_id.clone(),
            "encrypted-http-session-123",
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email("encrypted.http.patient@example.test"),
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
            device_ref: "iphone-encrypted-http-device".to_string(),
            key_id: "app-attest-key-encrypted-http".to_string(),
            challenge_nonce: "app-attest-encrypted-http-nonce".to_string(),
            sign_count: 15,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let key = http_active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let policy_refs = http_materialization_policy_refs();
    let mut repository = EncryptionAwareWorkflowRepository::new(
        InMemoryStoredEncryptedWorkflowRepository::new(),
        DeterministicTestFactEncryptionMetadataPlanner::new(
            "mobile-http-key",
            "nonce-encrypted-mobile-http",
        ),
        DeterministicTestFactEncryptor::new(),
        key,
        policy_refs.clone(),
        EncryptedWorkflowAppendSequenceState::new(1000, 2000, 3000),
    );
    let request_body = json!({
        "subject_id": "subject-encrypted-mobile-http",
        "observed_at": "2026-05-29T00:05:30Z",
        "id_namespace": "encrypted-mobile-http",
        "expected_device_ref": "iphone-encrypted-http-device",
        "oidc": {
            "access_token": "valid-encrypted-http-token",
            "issuer": config.issuer,
            "client_id": config.client_id,
            "provider_name": "Keycloak"
        },
        "app_attest": {
            "assertion": "valid-encrypted-app-attest-assertion",
            "challenge_nonce": "app-attest-encrypted-http-nonce",
            "team_id": app_attest_config.team_id,
            "bundle_id": app_attest_config.bundle_id,
            "environment": "development"
        },
        "client_context": {
            "platform": "iphone",
            "request_id": "request-encrypted-mobile-http"
        }
    });

    let response = handle_encrypted_mobile_onboarding_http_request(
        MobileOnboardingHttpRequest::post(MOBILE_ONBOARDING_HTTP_PATH, request_body.to_string()),
        &service,
        author,
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
        MobileOnboardingEncryptedPersistenceContext {
            transaction_id: id("tx-encrypted-mobile-http"),
            committed_at: ts("2026-05-29T00:05:31Z"),
            materialization_policy: http_allowed_policy(policy_refs.clone()),
            materialization_audit_context: FactMaterializationAuditContext::default(),
        },
        &resolver,
    );

    assert_eq!(response.status_code, 200);
    let body: MobileOnboardingHttpResponseBody =
        serde_json::from_str(&response.body).expect("accepted response should be JSON");
    assert_eq!(
        body,
        MobileOnboardingHttpResponseBody::Accepted {
            request_id: Some("request-encrypted-mobile-http".to_string()),
            summary: MobileOnboardingHttpSummary {
                subject_id: "subject-encrypted-mobile-http".to_string(),
                assurance_level: "medium".to_string(),
                active_devices: vec!["iphone-encrypted-http-device".to_string()],
                workflow_episode_id: "episode-encrypted-mobile-http-0".to_string(),
                fact_ids: MobileOnboardingHttpFactIds {
                    credential_fact_id: "fact-encrypted-mobile-http-0".to_string(),
                    portal_login_witness_fact_id: "fact-encrypted-mobile-http-1".to_string(),
                    verified_email_attribute_fact_id: Some(
                        "fact-encrypted-mobile-http-2".to_string()
                    ),
                    device_binding_fact_id: "fact-encrypted-mobile-http-3".to_string(),
                },
                committed_fact_count: 4,
            },
        }
    );
    let stored_slices = repository.storage().workflow_slices();
    assert_eq!(stored_slices.len(), 1);
    assert_eq!(
        stored_slices[0].transaction_id,
        id("tx-encrypted-mobile-http")
    );
    assert_eq!(
        stored_slices[0]
            .encrypted_facts
            .iter()
            .map(|fact| fact.append_sequence)
            .collect::<Vec<_>>(),
        vec![1000, 1001, 1002, 1003]
    );
    assert!(
        stored_slices[0]
            .encrypted_facts
            .iter()
            .all(|fact| fact.materialization_policy_refs == policy_refs
                && !fact.ciphertext.is_empty())
    );
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_mobile_onboarding_http_endpoint_uses_durable_encrypted_facade_when_env_is_set() {
    let Ok(database_url) = std::env::var("IDENTITY_MODEL_POSTGRES_URL") else {
        eprintln!(
            "skipping live PostgreSQL mobile HTTP test; set IDENTITY_MODEL_POSTGRES_URL to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let author = system_author();
        let service = IdentityWorkflowService::new(FenTranslator {
            system_author: author.clone(),
        });
        let config =
            OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
        let suffix = live_http_test_suffix();
        let id_namespace = format!("live-postgres-mobile-http-{suffix}");
        let subject_id = id(&format!("subject-{id_namespace}"));
        let transaction_id = id(&format!("tx-{id_namespace}"));
        let device_ref = format!("iphone-{id_namespace}");
        let fact_ids = [
            format!("fact-{id_namespace}-0"),
            format!("fact-{id_namespace}-1"),
            format!("fact-{id_namespace}-2"),
            format!("fact-{id_namespace}-3"),
        ];
        let episode_ids = [format!("episode-{id_namespace}-0")];
        let membership_ids = [
            format!("membership-{id_namespace}-0"),
            format!("membership-{id_namespace}-1"),
            format!("membership-{id_namespace}-2"),
            format!("membership-{id_namespace}-3"),
        ];
        let fact_id_refs = fact_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let episode_id_refs = episode_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let membership_id_refs = membership_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let transaction_id_refs = [transaction_id.0.as_str()];

        let app_attest_config = AppAttestClientConfig::ios_app(
            "TEAMID1234",
            "com.fen.identity",
            AppAttestEnvironment::Development,
        );
        let verifier = StaticOidcSessionVerifier::new(
            "valid-live-postgres-http-token",
            VerifiedOidcSession::keycloak(
                config.issuer.clone(),
                format!("keycloak-{id_namespace}"),
                config.client_id.clone(),
                format!("session-{id_namespace}"),
                ts("2026-05-29T00:00:00Z"),
                ts("2026-05-29T01:00:00Z"),
            )
            .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
            .with_verified_email(format!("{id_namespace}@example.test")),
        );
        let app_attest_verifier = StaticAppAttestAssertionVerifier::new(
            "valid-live-postgres-app-attest-assertion",
            VerifiedAppAttestAssertion {
                team_id: app_attest_config.team_id.clone(),
                bundle_id: app_attest_config.bundle_id.clone(),
                app_id: app_attest_config.app_id.clone(),
                environment: app_attest_config.environment,
                device_ref: device_ref.clone(),
                key_id: format!("app-attest-key-{id_namespace}"),
                challenge_nonce: format!("app-attest-nonce-{id_namespace}"),
                sign_count: 21,
                asserted_at: ts("2026-05-29T00:05:00Z"),
                expires_at: ts("2026-05-29T00:06:00Z"),
                assurance_level: AssuranceLevel::Medium,
            },
        );

        let storage = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        storage
            .run_migration()
            .await
            .expect("migration should run against live PostgreSQL");
        cleanup_live_mobile_http_postgres_rows(
            storage.pool(),
            &subject_id,
            &fact_id_refs,
            &episode_id_refs,
            &membership_id_refs,
            &transaction_id_refs,
        )
        .await;

        let key = http_active_key();
        let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
        let policy_refs = http_materialization_policy_refs();
        let repository = SqlxPostgresEncryptionAwareWorkflowRepository::new(
            storage,
            DeterministicTestFactEncryptionMetadataPlanner::new(
                "mobile-http-key",
                format!("nonce-{id_namespace}"),
            ),
            DeterministicTestFactEncryptor::new(),
            key,
            policy_refs.clone(),
        );
        let mut runtime = PostgresEncryptedMobileOnboardingRuntime::new(
            service,
            author,
            verifier,
            app_attest_verifier,
            DeterministicIdGenerator::new(),
            repository,
            resolver,
        );
        let request_body = json!({
            "subject_id": subject_id.0.clone(),
            "observed_at": "2026-05-29T00:05:30Z",
            "id_namespace": id_namespace.clone(),
            "expected_device_ref": device_ref.clone(),
            "oidc": {
                "access_token": "valid-live-postgres-http-token",
                "issuer": config.issuer,
                "client_id": config.client_id,
                "provider_name": "Keycloak"
            },
            "app_attest": {
                "assertion": "valid-live-postgres-app-attest-assertion",
                "challenge_nonce": format!("app-attest-nonce-{id_namespace}"),
                "team_id": app_attest_config.team_id,
                "bundle_id": app_attest_config.bundle_id,
                "environment": "development"
            },
            "client_context": {
                "platform": "iphone",
                "request_id": format!("request-{id_namespace}")
            }
        });

        let response = runtime
            .handle_http_request(
                MobileOnboardingHttpRequest::post(
                    MOBILE_ONBOARDING_HTTP_PATH,
                    request_body.to_string(),
                ),
                MobileOnboardingEncryptedPersistenceContext {
                    transaction_id: transaction_id.clone(),
                    committed_at: ts("2026-05-29T00:05:31Z"),
                    materialization_policy: http_allowed_policy(policy_refs.clone()),
                    materialization_audit_context: FactMaterializationAuditContext::new(
                        Some("mobile-http-handler".to_string()),
                        Some("mobile-onboarding-summary".to_string()),
                        Some(ts("2026-05-29T00:05:31Z")),
                    ),
                },
            )
            .await;

        assert_eq!(response.status_code, 200);
        let body: MobileOnboardingHttpResponseBody =
            serde_json::from_str(&response.body).expect("accepted response should be JSON");
        assert!(matches!(
            body,
            MobileOnboardingHttpResponseBody::Accepted { summary, .. }
                if summary.subject_id == subject_id.0
                    && summary.active_devices == vec![device_ref]
                    && summary.committed_fact_count == 4
        ));
        let stored = runtime
            .repository
            .storage()
            .encrypted_facts_for_subject(&subject_id)
            .await
            .expect("stored encrypted facts should be queryable");
        assert_eq!(stored.len(), 4);
        assert!(stored
            .iter()
            .all(|fact| fact.materialization_policy_refs == policy_refs
                && !fact.ciphertext.is_empty()));
        let audit_event_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM identity_fact_materialization_audit
            WHERE subject_id = $1
              AND caller = $2
              AND purpose = $3
            "#,
        )
        .bind(&subject_id.0)
        .bind("mobile-http-handler")
        .bind("mobile-onboarding-summary")
        .fetch_one(runtime.repository.storage().pool())
        .await
        .expect("materialization audit count should query");
        assert_eq!(audit_event_count, 20);

        cleanup_live_mobile_http_postgres_rows(
            runtime.repository.storage().pool(),
            &subject_id,
            &fact_id_refs,
            &episode_id_refs,
            &membership_id_refs,
            &transaction_id_refs,
        )
        .await;
    });
}

#[test]
fn mobile_onboarding_http_endpoint_shapes_request_and_verification_errors() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let config = OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let verifier = StaticOidcSessionVerifier::new(
        "valid-http-token",
        VerifiedOidcSession::keycloak(
            config.issuer.clone(),
            "keycloak-http-user",
            config.client_id.clone(),
            "http-session-123",
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
            device_ref: "iphone-http-device".to_string(),
            key_id: "app-attest-key-http".to_string(),
            challenge_nonce: "app-attest-http-nonce".to_string(),
            sign_count: 12,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let invalid_json = handle_mobile_onboarding_http_request(
        MobileOnboardingHttpRequest::post(MOBILE_ONBOARDING_HTTP_PATH, "{"),
        &service,
        author.clone(),
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    );
    assert_error_code(invalid_json, 400, "invalid_request_json");

    let wrong_method = handle_mobile_onboarding_http_request(
        MobileOnboardingHttpRequest {
            method: "GET".to_string(),
            path: MOBILE_ONBOARDING_HTTP_PATH.to_string(),
            body: "{}".to_string(),
        },
        &service,
        author.clone(),
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    );
    assert_error_code(wrong_method, 405, "method_not_allowed");

    let request_body = json!({
        "subject_id": "subject-mobile-http-rejected",
        "observed_at": "2026-05-29T00:05:30Z",
        "id_namespace": "mobile-http-rejected",
        "expected_device_ref": "different-device",
        "oidc": {
            "access_token": "valid-http-token",
            "issuer": config.issuer,
            "client_id": config.client_id
        },
        "app_attest": {
            "assertion": "valid-app-attest-assertion",
            "challenge_nonce": "app-attest-http-nonce",
            "team_id": app_attest_config.team_id,
            "bundle_id": app_attest_config.bundle_id,
            "environment": "development"
        }
    });
    let mismatch = handle_mobile_onboarding_http_request(
        MobileOnboardingHttpRequest::post(MOBILE_ONBOARDING_HTTP_PATH, request_body.to_string()),
        &service,
        author,
        &verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    );
    assert_error_code(mismatch, 422, "device_ref_mismatch");
    assert!(repository.all_facts().is_empty());
}

fn assert_error_code(response: MobileOnboardingHttpResponse, status_code: u16, code: &str) {
    assert_eq!(response.status_code, status_code);
    assert_eq!(response.content_type, APPLICATION_JSON);
    let body: MobileOnboardingHttpResponseBody =
        serde_json::from_str(&response.body).expect("error response should be JSON");
    assert!(matches!(
        body,
        MobileOnboardingHttpResponseBody::Error { error }
            if error.code == code
    ));
}

fn http_active_key() -> FactDataEncryptionKey {
    FactDataEncryptionKey::active("mobile-http-key", b"mobile-http-key-material".to_vec())
}

fn http_materialization_policy_refs() -> Vec<PolicyRef> {
    vec![id("mobile-http-materialization-policy@v1")]
}

fn http_allowed_policy(policy_refs: Vec<PolicyRef>) -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Allowed,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs,
    }
}

#[cfg(feature = "postgres-adapter")]
fn live_http_test_suffix() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos()
        .to_string()
}

#[cfg(feature = "postgres-adapter")]
async fn cleanup_live_mobile_http_postgres_rows(
    pool: &sqlx::PgPool,
    subject_id: &SubjectId,
    fact_ids: &[&str],
    episode_ids: &[&str],
    membership_ids: &[&str],
    transaction_ids: &[&str],
) {
    sqlx::query(
        r#"
        DELETE FROM identity_episode_relations
        WHERE source_episode_id = ANY($1)
           OR target_episode_id = ANY($1)
        "#,
    )
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live relation cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episode_memberships
        WHERE membership_id = ANY($1)
           OR fact_id = ANY($2)
           OR episode_id = ANY($3)
        "#,
    )
    .bind(membership_ids)
    .bind(fact_ids)
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live membership cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episodes
        WHERE episode_id = ANY($1)
        "#,
    )
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live episode cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_workflow_transactions
        WHERE transaction_id = ANY($1)
        "#,
    )
    .bind(transaction_ids)
    .execute(pool)
    .await
    .expect("live transaction cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_fact_materialization_audit
        WHERE subject_id = $1
        "#,
    )
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("live audit cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_facts
        WHERE fact_id = ANY($1)
        "#,
    )
    .bind(fact_ids)
    .execute(pool)
    .await
    .expect("live fact cleanup should succeed");
}
