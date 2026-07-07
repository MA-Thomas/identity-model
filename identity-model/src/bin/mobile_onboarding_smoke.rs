use identity_model::*;
use std::env;

fn main() {
    match run() {
        Ok(outcome) => print_outcome(outcome),
        Err(error) => {
            eprintln!("mobile onboarding smoke failed: {error:?}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<MobileOnboardingCommandOutcome, SmokeError> {
    let issuer = required_env("IDENTITY_MODEL_MOBILE_OIDC_ISSUER")?;
    let client_id = required_env("IDENTITY_MODEL_MOBILE_OIDC_CLIENT_ID")?;
    let token = required_env("IDENTITY_MODEL_MOBILE_OIDC_TOKEN")?;
    let oidc_subject = required_env("IDENTITY_MODEL_MOBILE_OIDC_SUBJECT")?;
    let oidc_session_id = optional_env("IDENTITY_MODEL_MOBILE_OIDC_SESSION_ID")
        .unwrap_or_else(|| "mobile-smoke-session".to_string());
    let observed_at = timestamp_env("IDENTITY_MODEL_MOBILE_OBSERVED_AT")?;
    let oidc_issued_at = optional_timestamp_env("IDENTITY_MODEL_MOBILE_OIDC_ISSUED_AT")
        .unwrap_or_else(|| Timestamp("2026-05-29T00:00:00Z".to_string()));
    let oidc_expires_at = timestamp_env("IDENTITY_MODEL_MOBILE_OIDC_EXPIRES_AT")?;

    let app_attest_config = AppAttestClientConfig::ios_app(
        required_env("IDENTITY_MODEL_MOBILE_APPLE_TEAM_ID")?,
        required_env("IDENTITY_MODEL_MOBILE_BUNDLE_ID")?,
        app_attest_environment()?,
    );
    let app_attest_assertion = required_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_ASSERTION")?;
    let app_attest_nonce = required_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_NONCE")?;
    let device_ref = required_env("IDENTITY_MODEL_MOBILE_DEVICE_REF")?;

    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let oidc_config = OidcClientConfig::keycloak(issuer, client_id.clone());
    let mut session = VerifiedOidcSession::keycloak(
        oidc_config.issuer.clone(),
        oidc_subject,
        client_id,
        oidc_session_id,
        oidc_issued_at,
        oidc_expires_at,
    )
    .with_amr(amr_values());
    if let Some(email) = optional_env("IDENTITY_MODEL_MOBILE_VERIFIED_EMAIL") {
        session = session.with_verified_email(email);
    }
    let oidc_verifier = StaticOidcSessionVerifier::new(token.clone(), session);
    let app_attest_verifier = StaticAppAttestAssertionVerifier::new(
        app_attest_assertion.clone(),
        VerifiedAppAttestAssertion {
            team_id: app_attest_config.team_id.clone(),
            bundle_id: app_attest_config.bundle_id.clone(),
            app_id: app_attest_config.app_id.clone(),
            environment: app_attest_config.environment,
            device_ref: device_ref.clone(),
            key_id: required_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_KEY_ID")?,
            challenge_nonce: app_attest_nonce.clone(),
            sign_count: optional_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_SIGN_COUNT")
                .as_deref()
                .map(parse_sign_count)
                .transpose()?
                .unwrap_or(1),
            asserted_at: optional_timestamp_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_ASSERTED_AT")
                .unwrap_or_else(|| observed_at.clone()),
            expires_at: timestamp_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_EXPIRES_AT")?,
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();
    execute_mobile_onboarding_command(
        &service,
        MobileOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: SubjectId(required_env("IDENTITY_MODEL_MOBILE_SUBJECT_ID")?),
                authored_by: author,
                observed_at,
                id_namespace: optional_env("IDENTITY_MODEL_MOBILE_ID_NAMESPACE")
                    .unwrap_or_else(|| "mobile-smoke".to_string()),
                token,
                oidc_config,
                device_ref: Some(device_ref),
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: app_attest_assertion,
                challenge_nonce: app_attest_nonce,
                config: app_attest_config,
            },
            client_context: MobileOnboardingClientContext {
                platform: MobileOnboardingPlatform::Iphone,
                request_id: optional_env("IDENTITY_MODEL_MOBILE_REQUEST_ID"),
                app_version: optional_env("IDENTITY_MODEL_MOBILE_APP_VERSION"),
                user_agent: optional_env("IDENTITY_MODEL_MOBILE_USER_AGENT"),
            },
        },
        &oidc_verifier,
        &app_attest_verifier,
        &mut ids,
        &mut repository,
    )
    .map_err(SmokeError::Onboarding)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SmokeError {
    MissingEnv(&'static str),
    InvalidEnvironment(String),
    InvalidSignCount(String),
    Onboarding(MobileOnboardingCommandError),
}

fn required_env(name: &'static str) -> Result<String, SmokeError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(SmokeError::MissingEnv(name))
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn timestamp_env(name: &'static str) -> Result<Timestamp, SmokeError> {
    required_env(name).map(Timestamp)
}

fn optional_timestamp_env(name: &str) -> Option<Timestamp> {
    optional_env(name).map(Timestamp)
}

fn app_attest_environment() -> Result<AppAttestEnvironment, SmokeError> {
    match optional_env("IDENTITY_MODEL_MOBILE_APP_ATTEST_ENVIRONMENT")
        .unwrap_or_else(|| "development".to_string())
        .as_str()
    {
        "development" => Ok(AppAttestEnvironment::Development),
        "production" => Ok(AppAttestEnvironment::Production),
        other => Err(SmokeError::InvalidEnvironment(other.to_string())),
    }
}

fn amr_values() -> Vec<String> {
    optional_env("IDENTITY_MODEL_MOBILE_OIDC_AMR")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_else(|| vec!["pwd".to_string(), "webauthn".to_string()])
}

fn parse_sign_count(value: &str) -> Result<u64, SmokeError> {
    value
        .parse()
        .map_err(|_| SmokeError::InvalidSignCount(value.to_string()))
}

fn print_outcome(outcome: MobileOnboardingCommandOutcome) {
    println!("mobile onboarding accepted");
    println!("subject_id={}", outcome.summary.subject_id.0);
    println!("assurance_level={:?}", outcome.summary.assurance_level);
    println!(
        "active_devices={}",
        outcome.summary.active_devices.join(",")
    );
    println!("episode_id={}", outcome.summary.workflow_episode_id.0);
    println!(
        "credential_fact_id={}",
        outcome.summary.fact_ids.credential_fact_id.0
    );
    println!(
        "portal_login_witness_fact_id={}",
        outcome.summary.fact_ids.portal_login_witness_fact_id.0
    );
    if let Some(fact_id) = outcome.summary.fact_ids.verified_email_attribute_fact_id {
        println!("verified_email_attribute_fact_id={}", fact_id.0);
    }
    println!(
        "device_binding_fact_id={}",
        outcome.summary.fact_ids.device_binding_fact_id.0
    );
    println!(
        "committed_fact_count={}",
        outcome.summary.committed_fact_count
    );
}

fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(AuthorId("author-mobile-smoke".to_string())),
        display_name: Some("FEN mobile smoke".to_string()),
    }
}
