use crate::device::*;
use crate::fen::*;
use crate::iam::*;
use crate::identity::*;
use crate::ids::*;
use crate::mobile::*;
use crate::persistence::*;
use crate::service::*;
use serde::{Deserialize, Serialize};

pub const MOBILE_ONBOARDING_HTTP_METHOD: &str = "POST";
pub const MOBILE_ONBOARDING_HTTP_PATH: &str = "/mobile/onboarding";
pub const APPLICATION_JSON: &str = "application/json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingHttpRequest {
    pub method: String,
    pub path: String,
    pub body: String,
}

impl MobileOnboardingHttpRequest {
    pub fn post(path: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method: MOBILE_ONBOARDING_HTTP_METHOD.to_string(),
            path: path.into(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingHttpResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub body: String,
}

pub fn handle_mobile_onboarding_http_request(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    repository: &mut impl IdentityWorkflowRepository,
) -> MobileOnboardingHttpResponse {
    let command = match command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_mobile_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
        repository,
    ) {
        Ok(outcome) => json_response(
            200,
            MobileOnboardingHttpResponseBody::Accepted {
                summary: MobileOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => command_error_response(error),
    }
}

pub fn handle_encrypted_mobile_onboarding_http_request<R, M, E>(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    encrypted_repository: &mut EncryptionAwareWorkflowRepository<R, M, E>,
    persistence_context: MobileOnboardingEncryptedPersistenceContext,
    key_resolver: &impl FactKeyResolver,
) -> MobileOnboardingHttpResponse
where
    R: StoredEncryptedWorkflowRepository,
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let command = match command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_encrypted_mobile_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
        encrypted_repository,
        persistence_context,
        key_resolver,
    ) {
        Ok(outcome) => json_response(
            200,
            MobileOnboardingHttpResponseBody::Accepted {
                summary: MobileOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => command_error_response(error),
    }
}

#[cfg(feature = "postgres-adapter")]
pub async fn handle_postgres_encrypted_mobile_onboarding_http_request<M, E>(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    encrypted_repository: &mut SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
    persistence_context: MobileOnboardingEncryptedPersistenceContext,
    key_resolver: &impl FactKeyResolver,
) -> MobileOnboardingHttpResponse
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let command = match command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_postgres_encrypted_mobile_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
        encrypted_repository,
        persistence_context,
        key_resolver,
    )
    .await
    {
        Ok(outcome) => json_response(
            200,
            MobileOnboardingHttpResponseBody::Accepted {
                summary: MobileOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => command_error_response(error),
    }
}

fn command_from_http_request(
    request: MobileOnboardingHttpRequest,
    authored_by: Author,
) -> Result<MobileOnboardingCommandRequest, MobileOnboardingHttpResponse> {
    if request.path != MOBILE_ONBOARDING_HTTP_PATH {
        return Err(error_response(
            404,
            "not_found",
            "mobile onboarding endpoint not found",
        ));
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(error_response(
            405,
            "method_not_allowed",
            "mobile onboarding accepts POST requests",
        ));
    }

    let parsed =
        serde_json::from_str::<MobileOnboardingHttpRequestBody>(&request.body).map_err(|_| {
            error_response(
                400,
                "invalid_request_json",
                "request body must be valid mobile onboarding JSON",
            )
        })?;

    Ok(parsed.into_command_request(authored_by))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileOnboardingHttpRequestBody {
    pub subject_id: String,
    pub observed_at: String,
    #[serde(default)]
    pub id_namespace: Option<String>,
    pub oidc: MobileOnboardingOidcHttpInput,
    pub app_attest: MobileOnboardingAppAttestHttpInput,
    #[serde(default)]
    pub expected_device_ref: Option<String>,
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
}

impl MobileOnboardingHttpRequestBody {
    fn into_command_request(self, authored_by: Author) -> MobileOnboardingCommandRequest {
        let client_context = self.client_context.unwrap_or_default();
        let platform = client_context.platform.into_command_platform();
        MobileOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: Id(self.subject_id),
                authored_by,
                observed_at: Timestamp(self.observed_at),
                id_namespace: self
                    .id_namespace
                    .unwrap_or_else(|| "mobile-onboarding".to_string()),
                token: self.oidc.access_token,
                oidc_config: OidcClientConfig {
                    provider_name: self
                        .oidc
                        .provider_name
                        .unwrap_or_else(|| "Keycloak".to_string()),
                    issuer: self.oidc.issuer,
                    client_id: self.oidc.client_id,
                },
                device_ref: self.expected_device_ref,
                assurance_policy: OidcAssurancePolicy::default(),
            },
            app_attest: AppAttestAssertionVerificationRequest {
                assertion: self.app_attest.assertion,
                challenge_nonce: self.app_attest.challenge_nonce,
                config: AppAttestClientConfig::ios_app(
                    self.app_attest.team_id,
                    self.app_attest.bundle_id,
                    self.app_attest.environment.into_app_attest_environment(),
                ),
            },
            client_context: MobileOnboardingClientContext {
                platform,
                request_id: client_context.request_id,
                app_version: client_context.app_version,
                user_agent: client_context.user_agent,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileOnboardingOidcHttpInput {
    pub access_token: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub provider_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileOnboardingAppAttestHttpInput {
    pub assertion: String,
    pub challenge_nonce: String,
    pub team_id: String,
    pub bundle_id: String,
    pub environment: MobileOnboardingAppAttestEnvironmentHttpInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileOnboardingAppAttestEnvironmentHttpInput {
    Development,
    Production,
}

impl MobileOnboardingAppAttestEnvironmentHttpInput {
    fn into_app_attest_environment(self) -> AppAttestEnvironment {
        match self {
            Self::Development => AppAttestEnvironment::Development,
            Self::Production => AppAttestEnvironment::Production,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileOnboardingClientHttpInput {
    pub platform: MobileOnboardingPlatformHttpInput,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

impl Default for MobileOnboardingClientHttpInput {
    fn default() -> Self {
        Self {
            platform: MobileOnboardingPlatformHttpInput::Iphone,
            request_id: None,
            app_version: None,
            user_agent: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileOnboardingPlatformHttpInput {
    Iphone,
    Ipad,
}

impl MobileOnboardingPlatformHttpInput {
    fn into_command_platform(self) -> MobileOnboardingPlatform {
        match self {
            Self::Iphone => MobileOnboardingPlatform::Iphone,
            Self::Ipad => MobileOnboardingPlatform::Ipad,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileOnboardingHttpResponseBody {
    Accepted {
        summary: MobileOnboardingHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileOnboardingHttpSummary {
    pub subject_id: String,
    pub assurance_level: String,
    pub active_devices: Vec<String>,
    pub workflow_episode_id: String,
    pub fact_ids: MobileOnboardingHttpFactIds,
    pub committed_fact_count: usize,
}

impl MobileOnboardingHttpSummary {
    fn from_command(summary: MobileOnboardingSummary) -> Self {
        Self {
            subject_id: summary.subject_id.0,
            assurance_level: assurance_level_wire(summary.assurance_level).to_string(),
            active_devices: summary.active_devices,
            workflow_episode_id: summary.workflow_episode_id.0,
            fact_ids: MobileOnboardingHttpFactIds {
                credential_fact_id: summary.fact_ids.credential_fact_id.0,
                portal_login_witness_fact_id: summary.fact_ids.portal_login_witness_fact_id.0,
                verified_email_attribute_fact_id: summary
                    .fact_ids
                    .verified_email_attribute_fact_id
                    .map(|fact_id| fact_id.0),
                device_binding_fact_id: summary.fact_ids.device_binding_fact_id.0,
            },
            committed_fact_count: summary.committed_fact_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileOnboardingHttpFactIds {
    pub credential_fact_id: String,
    pub portal_login_witness_fact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_email_attribute_fact_id: Option<String>,
    pub device_binding_fact_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileOnboardingHttpErrorBody {
    pub code: String,
    pub message: String,
}

fn command_error_response(error: MobileOnboardingCommandError) -> MobileOnboardingHttpResponse {
    match error {
        MobileOnboardingCommandError::Verification(_) => {
            error_response(401, "oidc_verification_failed", "OIDC token was rejected")
        }
        MobileOnboardingCommandError::AppAttest(
            AppAttestAssertionVerificationError::KeyStateUnavailable,
        ) => error_response(
            500,
            "app_attest_key_state_unavailable",
            "App Attest key state could not be checked",
        ),
        MobileOnboardingCommandError::AppAttest(_) => error_response(
            422,
            "app_attest_verification_failed",
            "App Attest evidence was rejected",
        ),
        MobileOnboardingCommandError::DeviceRefMismatch => error_response(
            422,
            "device_ref_mismatch",
            "expected device reference did not match verified device evidence",
        ),
        MobileOnboardingCommandError::Repository(_) => error_response(
            409,
            "repository_append_failed",
            "mobile onboarding evidence could not be appended",
        ),
        MobileOnboardingCommandError::Encryption(_) => error_response(
            500,
            "fact_encryption_failed",
            "mobile onboarding evidence could not be encrypted",
        ),
        #[cfg(feature = "postgres-adapter")]
        MobileOnboardingCommandError::Storage(_) => error_response(
            500,
            "encrypted_workflow_storage_failed",
            "mobile onboarding evidence could not be stored or replayed",
        ),
        MobileOnboardingCommandError::Materialization(_) => error_response(
            500,
            "materialization_failed",
            "mobile onboarding evidence was appended but summary replay failed",
        ),
    }
}

fn json_response(
    status_code: u16,
    body: MobileOnboardingHttpResponseBody,
) -> MobileOnboardingHttpResponse {
    MobileOnboardingHttpResponse {
        status_code,
        content_type: APPLICATION_JSON,
        body: serde_json::to_string(&body).expect("mobile onboarding response should serialize"),
    }
}

fn error_response(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileOnboardingHttpResponseBody::Error {
            error: MobileOnboardingHttpErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )
}

fn assurance_level_wire(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Low => "low",
        AssuranceLevel::Medium => "medium",
        AssuranceLevel::High => "high",
        AssuranceLevel::VeryHigh => "very_high",
    }
}
