#![allow(dead_code)]

use identity_model::*;

pub fn id<T: From<String>>(value: &str) -> T {
    T::from(value.to_string())
}

pub fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

pub fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(id("author-system")),
        display_name: Some("FEN".to_string()),
    }
}

pub fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test".to_string()),
        source_document: None,
        imported_at: ts("2026-05-29T00:00:00Z"),
        author: system_author(),
        tier: ProvenanceTier::ApiSourced,
        content_hash: None,
        authorization_basis: None,
    }
}

pub fn fact(id_value: &str, subject_id: SubjectId, payload: FactPayload) -> Fact {
    Fact {
        id: id(id_value),
        subject_id,
        occurred_at: TemporalAnchor::Point(ts("2026-05-29T00:00:00Z")),
        code: None,
        payload,
        status: FactStatus::Active,
        provenance: provenance(),
        external_refs: Vec::new(),
    }
}

pub fn continuity_result_shape(
    facts: &[Fact],
) -> Option<(String, ContinuityCheckResult, AssuranceLevel)> {
    facts.iter().find_map(|fact| match &fact.payload {
        FactPayload::BiometricContinuityCheck {
            enrollment_ref,
            result,
            assurance_level,
            ..
        } => Some((enrollment_ref.clone(), *result, *assurance_level)),
        _ => None,
    })
}

pub fn access_decision_shape(
    facts: &[Fact],
) -> Option<(SensitiveAction, AccessDecisionResult, Vec<PolicyRef>)> {
    facts.iter().find_map(|fact| match &fact.payload {
        FactPayload::AccessDecision {
            action,
            decision,
            policy_refs,
            ..
        } => Some((*action, *decision, policy_refs.clone())),
        _ => None,
    })
}

pub struct MobileEvidenceFixture {
    pub oidc_config: OidcClientConfig,
    pub oidc_verifier: StaticOidcSessionVerifier,
    pub app_attest_config: AppAttestClientConfig,
    pub app_attest_verifier: StaticAppAttestAssertionVerifier,
    pub app_attest_assertion: String,
    pub app_attest_challenge_nonce: String,
    pub device_ref: DeviceRef,
}

pub fn mobile_evidence_fixture(
    id_namespace: &str,
    token: &str,
    app_attest_assertion: &str,
    device_ref: &str,
) -> MobileEvidenceFixture {
    let oidc_config =
        OidcClientConfig::keycloak("https://id.example.test/realms/fen", "fen-identity");
    let oidc_verifier = StaticOidcSessionVerifier::new(
        token,
        VerifiedOidcSession::keycloak(
            oidc_config.issuer.clone(),
            format!("keycloak-{id_namespace}"),
            oidc_config.client_id.clone(),
            format!("session-{id_namespace}"),
            ts("2026-05-29T00:00:00Z"),
            ts("2026-05-29T01:00:00Z"),
        )
        .with_amr(vec!["pwd".to_string(), "webauthn".to_string()])
        .with_verified_email(format!("{id_namespace}@example.test")),
    );
    let app_attest_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let app_attest_challenge_nonce = format!("app-attest-nonce-{id_namespace}");
    let app_attest_verifier = StaticAppAttestAssertionVerifier::new(
        app_attest_assertion,
        VerifiedAppAttestAssertion {
            team_id: app_attest_config.team_id.clone(),
            bundle_id: app_attest_config.bundle_id.clone(),
            app_id: app_attest_config.app_id.clone(),
            environment: app_attest_config.environment,
            device_ref: device_ref.to_string(),
            key_id: format!("app-attest-key-{id_namespace}"),
            challenge_nonce: app_attest_challenge_nonce.clone(),
            sign_count: 12,
            asserted_at: ts("2026-05-29T00:05:00Z"),
            expires_at: ts("2026-05-29T00:06:00Z"),
            assurance_level: AssuranceLevel::Medium,
        },
    );

    MobileEvidenceFixture {
        oidc_config,
        oidc_verifier,
        app_attest_config,
        app_attest_verifier,
        app_attest_assertion: app_attest_assertion.to_string(),
        app_attest_challenge_nonce,
        device_ref: device_ref.to_string(),
    }
}

pub fn persona_identity_proofing_request(
    id_namespace: &str,
) -> IdentityProofingVerificationRequest {
    IdentityProofingVerificationRequest {
        provider_name: PERSONA_PROVIDER_NAME.to_string(),
        workflow_id: format!("persona-workflow-{id_namespace}"),
        provider_event_id: Some(format!("persona-inquiry-{id_namespace}")),
        asserted_attributes: vec![
            IdentityProofingAssertedAttribute {
                attribute: IdentityAttribute::LegalName,
                value: IdentityAttributeValue::StringValue("Mobile Identity Patient".to_string()),
                confidence: MatchConfidence::High,
            },
            IdentityProofingAssertedAttribute {
                attribute: IdentityAttribute::DateOfBirth,
                value: IdentityAttributeValue::DateValue(Date("1990-01-01".to_string())),
                confidence: MatchConfidence::High,
            },
        ],
        evidence_types: vec![IdentityProofingEvidenceType::GovernmentIdDocument],
        verification_result: IdentityWitnessResult::Passed,
        assurance_level: AssuranceLevel::High,
        risk_signals: Vec::new(),
        verified_at: ts("2026-05-29T00:05:10Z"),
        expires_at: None,
        audit_ref: Some(format!("persona-audit-{id_namespace}")),
        evidence_ref: Some(format!("identity-proofing-{id_namespace}")),
        retention_policy_refs: vec![id("identity-proof-retention@v1")],
    }
}
