use crate::device::*;
use crate::fen::*;
use crate::flows::*;
use crate::iam::*;
use crate::identity::*;
use crate::ids::*;
use crate::liveness::*;
use crate::mobile::*;
use crate::persistence::*;
use crate::provider::*;
use crate::service::*;
use serde::{Deserialize, Serialize};

pub const MOBILE_ONBOARDING_HTTP_METHOD: &str = "POST";
pub const MOBILE_ONBOARDING_HTTP_PATH: &str = "/mobile/onboarding";
pub const MOBILE_IDENTITY_ONBOARDING_HTTP_PATH: &str = "/mobile/identity-onboarding";
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

pub fn handle_mobile_identity_onboarding_http_request(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    liveness_verifier: &impl LivenessCeremonyVerifier,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    continuity_provider: &impl ContinuityVaultProvider,
    id_generator: &mut impl IdGenerator,
    repository: &mut impl IdentityWorkflowRepository,
) -> MobileOnboardingHttpResponse {
    let command = match identity_command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_mobile_identity_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
        repository,
    ) {
        Ok(outcome) => json_response(
            200,
            MobileIdentityOnboardingHttpResponseBody::Accepted {
                summary: MobileIdentityOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => identity_command_error_response(error),
    }
}

pub fn handle_encrypted_mobile_identity_onboarding_http_request<R, M, E>(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    liveness_verifier: &impl LivenessCeremonyVerifier,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    continuity_provider: &impl ContinuityVaultProvider,
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
    let command = match identity_command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_encrypted_mobile_identity_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
        encrypted_repository,
        persistence_context,
        key_resolver,
    ) {
        Ok(outcome) => json_response(
            200,
            MobileIdentityOnboardingHttpResponseBody::Accepted {
                summary: MobileIdentityOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => identity_command_error_response(error),
    }
}

#[cfg(feature = "postgres-adapter")]
pub async fn handle_postgres_encrypted_mobile_identity_onboarding_http_request<M, E>(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    liveness_verifier: &impl LivenessCeremonyVerifier,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    continuity_provider: &impl ContinuityVaultProvider,
    id_generator: &mut impl IdGenerator,
    encrypted_repository: &mut SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
    persistence_context: MobileOnboardingEncryptedPersistenceContext,
    key_resolver: &impl FactKeyResolver,
) -> MobileOnboardingHttpResponse
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let command = match identity_command_from_http_request(request, authored_by) {
        Ok(command) => command,
        Err(response) => return response,
    };

    match execute_postgres_encrypted_mobile_identity_onboarding_command(
        service,
        command,
        oidc_verifier,
        app_attest_verifier,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
        encrypted_repository,
        persistence_context,
        key_resolver,
    )
    .await
    {
        Ok(outcome) => json_response(
            200,
            MobileIdentityOnboardingHttpResponseBody::Accepted {
                summary: MobileIdentityOnboardingHttpSummary::from_command(outcome.summary),
                request_id: outcome.client_context.request_id,
            },
        ),
        Err(error) => identity_command_error_response(error),
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

fn identity_command_from_http_request(
    request: MobileOnboardingHttpRequest,
    authored_by: Author,
) -> Result<MobileIdentityOnboardingCommandRequest, MobileOnboardingHttpResponse> {
    if request.path != MOBILE_IDENTITY_ONBOARDING_HTTP_PATH {
        return Err(identity_error_response(
            404,
            "not_found",
            "mobile identity onboarding endpoint not found",
        ));
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(identity_error_response(
            405,
            "method_not_allowed",
            "mobile identity onboarding accepts POST requests",
        ));
    }

    let parsed = serde_json::from_str::<MobileIdentityOnboardingHttpRequestBody>(&request.body)
        .map_err(|_| {
            identity_error_response(
                400,
                "invalid_request_json",
                "request body must be valid mobile identity onboarding JSON",
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
pub struct MobileIdentityOnboardingHttpRequestBody {
    pub subject_id: String,
    pub observed_at: String,
    #[serde(default)]
    pub id_namespace: Option<String>,
    pub oidc: MobileOnboardingOidcHttpInput,
    pub app_attest: MobileOnboardingAppAttestHttpInput,
    pub liveness: MobileIdentityOnboardingLivenessHttpInput,
    pub government_id: MobileIdentityOnboardingGovernmentIdHttpInput,
    #[serde(default)]
    pub expected_device_ref: Option<String>,
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
    #[serde(default)]
    pub subject_kind: Option<MobileIdentityOnboardingSubjectKindHttpInput>,
    #[serde(default)]
    pub stable_profile: Option<MobileIdentityOnboardingStableProfileHttpInput>,
    #[serde(default)]
    pub continuity_modality: Option<MobileIdentityOnboardingBiometricModalityHttpInput>,
}

impl MobileIdentityOnboardingHttpRequestBody {
    fn into_command_request(self, authored_by: Author) -> MobileIdentityOnboardingCommandRequest {
        let client_context = self.client_context.unwrap_or_default();
        let platform = client_context.platform.into_command_platform();
        let liveness_expected_device_ref = self
            .liveness
            .expected_device_ref
            .clone()
            .or_else(|| self.expected_device_ref.clone());
        MobileIdentityOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: Id(self.subject_id),
                authored_by,
                observed_at: Timestamp(self.observed_at),
                id_namespace: self
                    .id_namespace
                    .unwrap_or_else(|| "mobile-identity-onboarding".to_string()),
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
            liveness: LivenessCeremonyVerificationRequest {
                assertion: self.liveness.assertion,
                challenge_nonce: self.liveness.challenge_nonce,
                expected_device_ref: liveness_expected_device_ref,
            },
            government_id: self.government_id.into_command_input(),
            client_context: MobileOnboardingClientContext {
                platform,
                request_id: client_context.request_id,
                app_version: client_context.app_version,
                user_agent: client_context.user_agent,
            },
            subject_kind: self
                .subject_kind
                .unwrap_or(MobileIdentityOnboardingSubjectKindHttpInput::HumanPerson)
                .into_subject_kind(),
            stable_profile: self
                .stable_profile
                .map(MobileIdentityOnboardingStableProfileHttpInput::into_stable_profile)
                .unwrap_or(StableIdentityProfile {
                    legal_name: None,
                    date_of_birth: None,
                    demographic_attributes: Vec::new(),
                }),
            continuity_modality: self
                .continuity_modality
                .unwrap_or(MobileIdentityOnboardingBiometricModalityHttpInput::Face)
                .into_biometric_modality(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileIdentityOnboardingLivenessHttpInput {
    pub assertion: String,
    pub challenge_nonce: String,
    #[serde(default)]
    pub expected_device_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileIdentityOnboardingGovernmentIdHttpInput {
    #[serde(default)]
    pub source_system: Option<String>,
    #[serde(default)]
    pub provider_event_id: Option<String>,
    #[serde(default)]
    pub evidence_ref: Option<String>,
    #[serde(default)]
    pub assurance_level: Option<MobileIdentityOnboardingAssuranceLevelHttpInput>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub retention_policy_refs: Option<Vec<String>>,
}

impl MobileIdentityOnboardingGovernmentIdHttpInput {
    fn into_command_input(self) -> GovernmentIdWitnessInput {
        GovernmentIdWitnessInput {
            source_system: self.source_system,
            provider_event_id: self.provider_event_id,
            evidence_ref: self.evidence_ref,
            assurance_level: self
                .assurance_level
                .unwrap_or(MobileIdentityOnboardingAssuranceLevelHttpInput::High)
                .into_assurance_level(),
            expires_at: self.expires_at.map(Timestamp),
            retention_policy_refs: self
                .retention_policy_refs
                .unwrap_or_default()
                .into_iter()
                .map(Id)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingSubjectKindHttpInput {
    HumanPerson,
    Organization,
    Device,
    SystemAgent,
}

impl MobileIdentityOnboardingSubjectKindHttpInput {
    fn into_subject_kind(self) -> SubjectKind {
        match self {
            Self::HumanPerson => SubjectKind::HumanPerson,
            Self::Organization => SubjectKind::Organization,
            Self::Device => SubjectKind::Device,
            Self::SystemAgent => SubjectKind::SystemAgent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileIdentityOnboardingStableProfileHttpInput {
    #[serde(default)]
    pub legal_name: Option<String>,
    #[serde(default)]
    pub date_of_birth: Option<String>,
}

impl MobileIdentityOnboardingStableProfileHttpInput {
    fn into_stable_profile(self) -> StableIdentityProfile {
        StableIdentityProfile {
            legal_name: self.legal_name,
            date_of_birth: self.date_of_birth.map(Date),
            demographic_attributes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingBiometricModalityHttpInput {
    Face,
    Fingerprint,
    Voice,
    Palm,
    Other,
}

impl MobileIdentityOnboardingBiometricModalityHttpInput {
    fn into_biometric_modality(self) -> BiometricModality {
        match self {
            Self::Face => BiometricModality::Face,
            Self::Fingerprint => BiometricModality::Fingerprint,
            Self::Voice => BiometricModality::Voice,
            Self::Palm => BiometricModality::Palm,
            Self::Other => BiometricModality::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingAssuranceLevelHttpInput {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl MobileIdentityOnboardingAssuranceLevelHttpInput {
    fn into_assurance_level(self) -> AssuranceLevel {
        match self {
            Self::Low => AssuranceLevel::Low,
            Self::Medium => AssuranceLevel::Medium,
            Self::High => AssuranceLevel::High,
            Self::VeryHigh => AssuranceLevel::VeryHigh,
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
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileIdentityOnboardingHttpResponseBody {
    Accepted {
        summary: MobileIdentityOnboardingHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileIdentityOnboardingHttpSummary {
    pub subject_id: String,
    pub decision: String,
    pub assurance_level: String,
    pub active_devices: Vec<String>,
    pub parent_episode_id: String,
    pub fact_ids: MobileIdentityOnboardingHttpFactIds,
    pub committed_fact_count: usize,
}

impl MobileIdentityOnboardingHttpSummary {
    fn from_command(summary: MobileIdentityOnboardingSummary) -> Self {
        Self {
            subject_id: summary.subject_id.0,
            decision: identity_decision_wire(summary.decision).to_string(),
            assurance_level: assurance_level_wire(summary.assurance_level).to_string(),
            active_devices: summary.active_devices,
            parent_episode_id: summary.parent_episode_id.0,
            fact_ids: MobileIdentityOnboardingHttpFactIds {
                subject_fact_id: summary.fact_ids.subject_fact_id.0,
                credential_fact_id: summary.fact_ids.credential_fact_id.0,
                portal_login_witness_fact_id: summary.fact_ids.portal_login_witness_fact_id.0,
                verified_email_attribute_fact_id: summary
                    .fact_ids
                    .verified_email_attribute_fact_id
                    .map(|fact_id| fact_id.0),
                device_binding_fact_id: summary.fact_ids.device_binding_fact_id.0,
                government_id_witness_fact_id: summary.fact_ids.government_id_witness_fact_id.0,
                selfie_liveness_witness_fact_id: summary.fact_ids.selfie_liveness_witness_fact_id.0,
                enrollment_fact_id: summary.fact_ids.enrollment_fact_id.map(|fact_id| fact_id.0),
            },
            committed_fact_count: summary.committed_fact_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileIdentityOnboardingHttpFactIds {
    pub subject_fact_id: String,
    pub credential_fact_id: String,
    pub portal_login_witness_fact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_email_attribute_fact_id: Option<String>,
    pub device_binding_fact_id: String,
    pub government_id_witness_fact_id: String,
    pub selfie_liveness_witness_fact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_fact_id: Option<String>,
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

fn identity_command_error_response(
    error: MobileIdentityOnboardingCommandError,
) -> MobileOnboardingHttpResponse {
    match error {
        MobileIdentityOnboardingCommandError::Verification(_) => {
            identity_error_response(401, "oidc_verification_failed", "OIDC token was rejected")
        }
        MobileIdentityOnboardingCommandError::AppAttest(
            AppAttestAssertionVerificationError::KeyStateUnavailable,
        ) => identity_error_response(
            500,
            "app_attest_key_state_unavailable",
            "App Attest key state could not be checked",
        ),
        MobileIdentityOnboardingCommandError::AppAttest(_) => identity_error_response(
            422,
            "app_attest_verification_failed",
            "App Attest evidence was rejected",
        ),
        MobileIdentityOnboardingCommandError::Liveness(_) => identity_error_response(
            422,
            "liveness_verification_failed",
            "liveness evidence was rejected",
        ),
        MobileIdentityOnboardingCommandError::LivePresenceChallenge(error) => {
            live_presence_challenge_error_response(error)
        }
        MobileIdentityOnboardingCommandError::DeviceRefMismatch => identity_error_response(
            422,
            "device_ref_mismatch",
            "expected device reference did not match verified device evidence",
        ),
        MobileIdentityOnboardingCommandError::Provider(_) => identity_error_response(
            502,
            "continuity_provider_failed",
            "continuity enrollment provider could not complete onboarding",
        ),
        MobileIdentityOnboardingCommandError::Repository(_) => identity_error_response(
            409,
            "repository_append_failed",
            "mobile identity onboarding evidence could not be appended",
        ),
        MobileIdentityOnboardingCommandError::Encryption(_) => identity_error_response(
            500,
            "fact_encryption_failed",
            "mobile identity onboarding evidence could not be encrypted",
        ),
        #[cfg(feature = "postgres-adapter")]
        MobileIdentityOnboardingCommandError::Storage(_) => identity_error_response(
            500,
            "encrypted_workflow_storage_failed",
            "mobile identity onboarding evidence could not be stored or replayed",
        ),
        MobileIdentityOnboardingCommandError::Materialization(_) => identity_error_response(
            500,
            "materialization_failed",
            "mobile identity onboarding evidence was appended but summary replay failed",
        ),
    }
}

fn live_presence_challenge_error_response(
    error: LivePresenceChallengeError,
) -> MobileOnboardingHttpResponse {
    match error {
        LivePresenceChallengeError::MissingChallengeNonce => identity_error_response(
            422,
            "live_presence_challenge_missing_nonce",
            "live-presence challenge nonce was missing",
        ),
        LivePresenceChallengeError::UnknownChallenge => identity_error_response(
            409,
            "live_presence_challenge_unknown",
            "live-presence challenge was not issued or is no longer available",
        ),
        LivePresenceChallengeError::ChallengeAlreadyConsumed => identity_error_response(
            409,
            "live_presence_challenge_already_consumed",
            "live-presence challenge was already consumed",
        ),
        LivePresenceChallengeError::ChallengeExpired => identity_error_response(
            409,
            "live_presence_challenge_expired",
            "live-presence challenge has expired",
        ),
        LivePresenceChallengeError::ChallengeNonceMismatch
        | LivePresenceChallengeError::SubjectMismatch
        | LivePresenceChallengeError::DeviceMismatch
        | LivePresenceChallengeError::AppContextMismatch => identity_error_response(
            422,
            "live_presence_challenge_mismatch",
            "live-presence challenge did not match verified evidence",
        ),
        LivePresenceChallengeError::StorageUnavailable => identity_error_response(
            500,
            "live_presence_challenge_storage_unavailable",
            "live-presence challenge state could not be checked",
        ),
        LivePresenceChallengeError::DuplicateChallengeId
        | LivePresenceChallengeError::DuplicateChallengeNonce => identity_error_response(
            409,
            "live_presence_challenge_duplicate",
            "live-presence challenge already exists",
        ),
        LivePresenceChallengeError::InvalidTimestamp => identity_error_response(
            422,
            "live_presence_challenge_invalid_timestamp",
            "live-presence challenge timestamp was invalid",
        ),
    }
}

fn json_response<T: Serialize>(status_code: u16, body: T) -> MobileOnboardingHttpResponse {
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

fn identity_error_response(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileIdentityOnboardingHttpResponseBody::Error {
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

fn identity_decision_wire(decision: MobileIdentityOnboardingDecision) -> &'static str {
    match decision {
        MobileIdentityOnboardingDecision::Accepted => "accepted",
        MobileIdentityOnboardingDecision::ManualReviewRequired => "manual_review_required",
    }
}
