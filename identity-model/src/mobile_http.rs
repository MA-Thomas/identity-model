use crate::continuity::*;
use crate::device::*;
use crate::fen::*;
use crate::iam::*;
use crate::identity::*;
use crate::identity_proofing::*;
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
pub const MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CHALLENGE_HTTP_PATH: &str =
    "/mobile/identity-onboarding/live-presence-challenge";
pub const MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CALLBACK_HTTP_PATH: &str =
    "/mobile/identity-onboarding/live-presence-callback";
pub const MOBILE_APP_ATTEST_KEY_REGISTRATION_CHALLENGE_HTTP_PATH: &str =
    "/mobile/app-attest/key-registration-challenge";
pub const MOBILE_APP_ATTEST_KEY_REGISTRATION_HTTP_PATH: &str =
    "/mobile/app-attest/key-registration";
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
    identity_proofing_provider: &impl IdentityProofingProvider,
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
        identity_proofing_provider,
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

// Pure (no I/O) parse + challenge construction, split out so the runtime server
// can run the store write on the runtime that owns the PostgreSQL pool.
pub fn prepare_mobile_identity_onboarding_live_presence_challenge(
    request: MobileOnboardingHttpRequest,
    issue_context: &MobileLivePresenceChallengeIssueContext,
) -> Result<(LivePresenceChallenge, Option<String>), MobileOnboardingHttpResponse> {
    let (parsed, request_id) = live_presence_challenge_issue_from_http_request(request)?;

    let mut challenge = LivePresenceChallenge::onboarding(
        issue_context.challenge_id.clone(),
        issue_context.challenge_nonce.clone(),
        parsed.subject_id.map(SubjectId),
        parsed.expected_device_ref,
        Some(parsed.expected_app.into_expected_app()),
        issue_context.issued_at.clone(),
        issue_context.expires_at.clone(),
    );
    challenge.retry_policy_refs = issue_context.retry_policy_refs.clone();
    challenge.manual_review_policy_refs = issue_context.manual_review_policy_refs.clone();
    challenge.retention_policy_refs = issue_context.retention_policy_refs.clone();

    Ok((challenge, request_id))
}

// Builds the HTTP response from the outcome of the (async or sync) store write.
pub fn live_presence_challenge_issue_response(
    stored: Result<LivePresenceChallenge, LivePresenceChallengeError>,
    issue_context: &MobileLivePresenceChallengeIssueContext,
    request_id: Option<String>,
) -> MobileOnboardingHttpResponse {
    match stored {
        Ok(challenge) => json_response(
            200,
            MobileLivePresenceChallengeIssueHttpResponseBody::Issued {
                challenge: MobileLivePresenceChallengeHttpSummary::from_challenge(
                    challenge,
                    issue_context,
                ),
                request_id,
            },
        ),
        Err(error) => live_presence_challenge_issue_error_response(error),
    }
}

pub fn handle_mobile_identity_onboarding_live_presence_challenge_http_request(
    request: MobileOnboardingHttpRequest,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    issue_context: MobileLivePresenceChallengeIssueContext,
) -> MobileOnboardingHttpResponse {
    let (challenge, request_id) =
        match prepare_mobile_identity_onboarding_live_presence_challenge(request, &issue_context) {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };

    live_presence_challenge_issue_response(
        live_presence_challenge_store.issue_live_presence_challenge(challenge),
        &issue_context,
        request_id,
    )
}

pub fn handle_mobile_identity_onboarding_live_presence_callback_http_request(
    request: MobileOnboardingHttpRequest,
    callback_verifier: &impl LivenessProviderCallbackVerifier,
    callback_context: MobileLivePresenceCallbackContext,
) -> MobileOnboardingHttpResponse {
    let (parsed, request_id) = match live_presence_callback_from_http_request(request) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let liveness_assertion = parsed.assertion.clone();

    match callback_verifier.verify_liveness_provider_callback(
        parsed.into_callback_request(),
        &callback_context.observed_at,
    ) {
        Ok(ceremony) => json_response(
            200,
            MobileLivePresenceCallbackHttpResponseBody::Verified {
                liveness: MobileLivePresenceCallbackLivenessHttpInput::from_ceremony(
                    &ceremony,
                    liveness_assertion,
                ),
                ceremony: MobileLivePresenceCallbackHttpSummary::from_ceremony(ceremony),
                request_id,
            },
        ),
        Err(error) => live_presence_callback_error_response(error),
    }
}

pub fn handle_mobile_app_attest_key_registration_challenge_http_request(
    request: MobileOnboardingHttpRequest,
    issue_context: MobileAppAttestKeyRegistrationChallengeIssueContext,
) -> MobileOnboardingHttpResponse {
    let request_id = match app_attest_key_registration_challenge_from_http_request(request) {
        Ok(request_id) => request_id,
        Err(response) => return response,
    };

    json_response(
        200,
        MobileAppAttestKeyRegistrationChallengeHttpResponseBody::Issued {
            challenge: MobileAppAttestKeyRegistrationChallengeHttpSummary::from_context(
                issue_context,
            ),
            request_id,
        },
    )
}

// Pure (no I/O) parse + App Attest attestation verification. The DB write is
// intentionally kept out of here so callers that own an async runtime (the
// runtime server) can execute the store step on the same runtime that owns the
// PostgreSQL pool, instead of a foreign runtime.
#[cfg(feature = "production-crypto")]
pub fn verify_mobile_app_attest_key_registration_http_request(
    request: MobileOnboardingHttpRequest,
    registration_verifier: &impl AppAttestKeyRegistrationVerifier,
    registration_context: &MobileAppAttestKeyRegistrationContext,
) -> Result<(AppAttestKeyRegistration, Option<String>), MobileOnboardingHttpResponse> {
    let (parsed, request_id) = app_attest_key_registration_from_http_request(request)?;

    let registration_request = parsed
        .into_registration_request(
            registration_context.expected_config.clone(),
            registration_context.observed_at.clone(),
        )
        .map_err(app_attest_key_registration_error_response)?;

    let registration = registration_verifier
        .verify_app_attest_key_registration(&registration_request, &registration_context.observed_at)
        .map_err(|error| {
            eprintln!(
                "App Attest key registration diagnostic: registration verification failed: {error:?}"
            );
            app_attest_key_registration_error_response(error)
        })?;

    Ok((registration, request_id))
}

// Builds the HTTP response from the outcome of the (async or sync) store write.
#[cfg(feature = "production-crypto")]
pub fn app_attest_key_registration_response(
    stored: Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError>,
    request_id: Option<String>,
) -> MobileOnboardingHttpResponse {
    match stored {
        Ok(registration) => json_response(
            200,
            MobileAppAttestKeyRegistrationHttpResponseBody::Registered {
                registration: MobileAppAttestKeyRegistrationHttpSummary::from_registration(
                    registration,
                ),
                request_id,
            },
        ),
        Err(error) => app_attest_key_registration_error_response(error),
    }
}

#[cfg(feature = "production-crypto")]
pub fn handle_mobile_app_attest_key_registration_http_request(
    request: MobileOnboardingHttpRequest,
    registration_verifier: &impl AppAttestKeyRegistrationVerifier,
    registration_store: &impl AppAttestKeyRegistrationStore,
    registration_context: MobileAppAttestKeyRegistrationContext,
) -> MobileOnboardingHttpResponse {
    let (registration, request_id) = match verify_mobile_app_attest_key_registration_http_request(
        request,
        registration_verifier,
        &registration_context,
    ) {
        Ok(verified) => verified,
        Err(response) => return response,
    };

    app_attest_key_registration_response(
        registration_store.record_app_attest_key_registration(&registration),
        request_id,
    )
}

pub fn handle_encrypted_mobile_identity_onboarding_http_request<R, M, E>(
    request: MobileOnboardingHttpRequest,
    service: &IdentityWorkflowService,
    authored_by: Author,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    identity_proofing_provider: &impl IdentityProofingProvider,
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
        identity_proofing_provider,
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
    identity_proofing_provider: &impl IdentityProofingProvider,
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
        identity_proofing_provider,
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

fn live_presence_challenge_issue_from_http_request(
    request: MobileOnboardingHttpRequest,
) -> Result<
    (
        MobileLivePresenceChallengeIssueHttpRequestBody,
        Option<String>,
    ),
    MobileOnboardingHttpResponse,
> {
    if request.path != MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CHALLENGE_HTTP_PATH {
        return Err(live_presence_challenge_issue_error_response_with_code(
            404,
            "not_found",
            "mobile identity live-presence challenge endpoint not found",
        ));
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(live_presence_challenge_issue_error_response_with_code(
            405,
            "method_not_allowed",
            "mobile identity live-presence challenge issuance accepts POST requests",
        ));
    }

    let parsed =
        serde_json::from_str::<MobileLivePresenceChallengeIssueHttpRequestBody>(&request.body)
            .map_err(|_| {
                live_presence_challenge_issue_error_response_with_code(
                    400,
                    "invalid_request_json",
                    "request body must be valid live-presence challenge JSON",
                )
            })?;
    let request_id = parsed
        .client_context
        .as_ref()
        .and_then(|context| context.request_id.clone());

    Ok((parsed, request_id))
}

fn live_presence_callback_from_http_request(
    request: MobileOnboardingHttpRequest,
) -> Result<(MobileLivePresenceCallbackHttpRequestBody, Option<String>), MobileOnboardingHttpResponse>
{
    if request.path != MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CALLBACK_HTTP_PATH {
        return Err(live_presence_callback_error_response_with_code(
            404,
            "not_found",
            "mobile identity live-presence callback endpoint not found",
        ));
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(live_presence_callback_error_response_with_code(
            405,
            "method_not_allowed",
            "mobile identity live-presence callback accepts POST requests",
        ));
    }

    let parsed = serde_json::from_str::<MobileLivePresenceCallbackHttpRequestBody>(&request.body)
        .map_err(|_| {
        live_presence_callback_error_response_with_code(
            400,
            "invalid_request_json",
            "request body must be valid live-presence callback JSON",
        )
    })?;
    let request_id = parsed
        .client_context
        .as_ref()
        .and_then(|context| context.request_id.clone());

    Ok((parsed, request_id))
}

fn app_attest_key_registration_challenge_from_http_request(
    request: MobileOnboardingHttpRequest,
) -> Result<Option<String>, MobileOnboardingHttpResponse> {
    if request.path != MOBILE_APP_ATTEST_KEY_REGISTRATION_CHALLENGE_HTTP_PATH {
        return Err(
            app_attest_key_registration_challenge_error_response_with_code(
                404,
                "not_found",
                "App Attest key-registration challenge endpoint not found",
            ),
        );
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(
            app_attest_key_registration_challenge_error_response_with_code(
                405,
                "method_not_allowed",
                "App Attest key-registration challenge issuance accepts POST requests",
            ),
        );
    }

    let parsed = serde_json::from_str::<MobileAppAttestKeyRegistrationChallengeHttpRequestBody>(
        &request.body,
    )
    .map_err(|_| {
        app_attest_key_registration_challenge_error_response_with_code(
            400,
            "invalid_request_json",
            "request body must be valid App Attest key-registration challenge JSON",
        )
    })?;
    Ok(parsed
        .client_context
        .as_ref()
        .and_then(|context| context.request_id.clone()))
}

#[cfg(feature = "production-crypto")]
fn app_attest_key_registration_from_http_request(
    request: MobileOnboardingHttpRequest,
) -> Result<
    (
        MobileAppAttestKeyRegistrationHttpRequestBody,
        Option<String>,
    ),
    MobileOnboardingHttpResponse,
> {
    if request.path != MOBILE_APP_ATTEST_KEY_REGISTRATION_HTTP_PATH {
        return Err(app_attest_key_registration_error_response_with_code(
            404,
            "not_found",
            "App Attest key-registration endpoint not found",
        ));
    }
    if request.method != MOBILE_ONBOARDING_HTTP_METHOD {
        return Err(app_attest_key_registration_error_response_with_code(
            405,
            "method_not_allowed",
            "App Attest key registration accepts POST requests",
        ));
    }

    let parsed =
        serde_json::from_str::<MobileAppAttestKeyRegistrationHttpRequestBody>(&request.body)
            .map_err(|_| {
                app_attest_key_registration_error_response_with_code(
                    400,
                    "invalid_request_json",
                    "request body must be valid App Attest key-registration JSON",
                )
            })?;
    let request_id = parsed
        .client_context
        .as_ref()
        .and_then(|context| context.request_id.clone());

    Ok((parsed, request_id))
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
                subject_id: SubjectId(self.subject_id),
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
    pub identity_proofing: MobileIdentityOnboardingIdentityProofingHttpInput,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileLivePresenceChallengeIssueContext {
    pub challenge_id: LivePresenceChallengeId,
    pub challenge_nonce: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub provider_name: String,
    pub handoff_uri: Option<String>,
    pub callback_path: String,
    pub retry_policy_refs: Vec<PolicyRef>,
    pub manual_review_policy_refs: Vec<PolicyRef>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileLivePresenceCallbackContext {
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileAppAttestKeyRegistrationChallengeIssueContext {
    pub challenge_nonce: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub expected_config: AppAttestClientConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileAppAttestKeyRegistrationContext {
    pub observed_at: Timestamp,
    pub expected_config: AppAttestClientConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileAppAttestKeyRegistrationChallengeHttpRequestBody {
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileLivePresenceChallengeIssueHttpRequestBody {
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub expected_device_ref: Option<String>,
    pub expected_app: MobileLivePresenceExpectedAppHttpInput,
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileLivePresenceCallbackHttpRequestBody {
    pub provider_name: String,
    pub assertion: String,
    pub challenge_nonce: String,
    pub device_ref: String,
    pub observed_at: String,
    pub expires_at: String,
    pub result: MobileLivePresenceCallbackResultHttpInput,
    pub pad_result: MobileLivePresenceCallbackPadResultHttpInput,
    pub assurance_level: MobileIdentityOnboardingAssuranceLevelHttpInput,
    #[serde(default)]
    pub provider_event_id: Option<String>,
    #[serde(default)]
    pub provider_subject_ref: Option<String>,
    #[serde(default)]
    pub sdk_or_api_version: Option<String>,
    #[serde(default)]
    pub retention_policy_refs: Option<Vec<String>>,
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileAppAttestKeyRegistrationHttpRequestBody {
    pub key_id: String,
    pub device_ref: String,
    pub challenge_nonce: String,
    #[serde(default)]
    pub attestation_object_hex: Option<String>,
    #[serde(default)]
    pub public_key_bytes_hex: Option<String>,
    #[serde(default)]
    pub certificate_chain_der_hex: Vec<String>,
    #[serde(default)]
    pub credential_id_hex: Option<String>,
    #[serde(default)]
    pub authenticator_data_hex: Option<String>,
    #[serde(default)]
    pub client_data_hash_hex: Option<String>,
    #[serde(default)]
    pub attestation_format: Option<String>,
    #[serde(default)]
    pub client_context: Option<MobileOnboardingClientHttpInput>,
}

#[cfg(feature = "production-crypto")]
impl MobileAppAttestKeyRegistrationHttpRequestBody {
    fn into_registration_request(
        self,
        expected_config: AppAttestClientConfig,
        observed_at: Timestamp,
    ) -> Result<AppleAppAttestKeyRegistrationVerificationRequest, AppAttestAssertionVerificationError>
    {
        if let Some(attestation_object_hex) = self.attestation_object_hex {
            let attestation_object_bytes =
                mobile_hex_decode(&attestation_object_hex).map_err(|error| {
                    eprintln!(
                        "App Attest key registration diagnostic: attestation_object_hex decode failed: {error:?}"
                    );
                    error
                })?;
            let attestation_object =
                parse_apple_app_attest_attestation_object(&attestation_object_bytes).map_err(
                    |error| {
                        eprintln!(
                            "App Attest key registration diagnostic: attestation object CBOR parse failed: {error:?}"
                        );
                        error
                    },
                )?;
            return AppleAppAttestKeyRegistrationVerificationRequest::from_attestation_object(
                self.key_id,
                self.device_ref,
                self.challenge_nonce,
                observed_at,
                expected_config,
                attestation_object,
            )
            .map_err(|error| {
                eprintln!(
                    "App Attest key registration diagnostic: attestation object normalization failed: {error:?}"
                );
                error
            });
        }

        Ok(AppleAppAttestKeyRegistrationVerificationRequest {
            key_id: self.key_id,
            device_ref: self.device_ref,
            public_key_bytes: mobile_hex_decode(required_registration_field(
                self.public_key_bytes_hex.as_deref(),
            )?)?,
            certificate_chain_der: self
                .certificate_chain_der_hex
                .iter()
                .map(|certificate| mobile_hex_decode(certificate))
                .collect::<Result<Vec<_>, _>>()?,
            credential_id: mobile_hex_decode(required_registration_field(
                self.credential_id_hex.as_deref(),
            )?)?,
            authenticator_data: mobile_hex_decode(required_registration_field(
                self.authenticator_data_hex.as_deref(),
            )?)?,
            client_data_hash: mobile_hex_decode(required_registration_field(
                self.client_data_hash_hex.as_deref(),
            )?)?,
            challenge_nonce: self.challenge_nonce,
            registered_at: observed_at,
            attestation_format: self
                .attestation_format
                .unwrap_or_else(|| "apple-app-attest".to_string()),
            config: expected_config,
        })
    }
}

impl MobileLivePresenceCallbackHttpRequestBody {
    fn into_callback_request(self) -> LivenessProviderCallbackVerificationRequest {
        LivenessProviderCallbackVerificationRequest {
            provider_metadata: ContinuityProviderMetadata {
                provider_name: self.provider_name,
                provider_event_id: self.provider_event_id,
                provider_subject_ref: self.provider_subject_ref,
                sdk_or_api_version: self.sdk_or_api_version,
            },
            assertion: self.assertion,
            challenge_nonce: self.challenge_nonce,
            device_ref: self.device_ref,
            observed_at: Timestamp(self.observed_at),
            expires_at: Timestamp(self.expires_at),
            result: self.result.into_identity_witness_result(),
            assurance_level: self.assurance_level.into_assurance_level(),
            pad_result: self.pad_result.into_pad_result(),
            retention_policy_refs: self
                .retention_policy_refs
                .unwrap_or_default()
                .into_iter()
                .map(PolicyRef)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileLivePresenceExpectedAppHttpInput {
    pub team_id: String,
    pub bundle_id: String,
    pub environment: MobileOnboardingAppAttestEnvironmentHttpInput,
}

impl MobileLivePresenceExpectedAppHttpInput {
    fn into_expected_app(self) -> LivePresenceExpectedAppContext {
        LivePresenceExpectedAppContext::from_app_attest_config(&AppAttestClientConfig::ios_app(
            self.team_id,
            self.bundle_id,
            self.environment.into_app_attest_environment(),
        ))
    }
}

impl MobileIdentityOnboardingHttpRequestBody {
    fn into_command_request(self, authored_by: Author) -> MobileIdentityOnboardingCommandRequest {
        let client_context = self.client_context.unwrap_or_default();
        let platform = client_context.platform.into_command_platform();
        let observed_at = self.observed_at;
        let liveness_expected_device_ref = self
            .liveness
            .expected_device_ref
            .clone()
            .or_else(|| self.expected_device_ref.clone());
        MobileIdentityOnboardingCommandRequest {
            account: AccountTokenBootstrapRequest {
                subject_id: SubjectId(self.subject_id),
                authored_by,
                observed_at: Timestamp(observed_at.clone()),
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
            identity_proofing: self.identity_proofing.into_command_input(),
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
pub struct MobileIdentityOnboardingIdentityProofingHttpInput {
    #[serde(default)]
    pub provider_name: Option<String>,
    pub workflow_id: String,
    #[serde(default)]
    pub provider_event_id: Option<String>,
    #[serde(default)]
    pub evidence_ref: Option<String>,
    #[serde(default)]
    pub evidence_types: Vec<MobileIdentityOnboardingIdentityProofingEvidenceTypeHttpInput>,
    pub verification_result: MobileIdentityOnboardingIdentityProofingResultHttpInput,
    pub assurance_level: MobileIdentityOnboardingAssuranceLevelHttpInput,
    #[serde(default)]
    pub asserted_attributes: Vec<MobileIdentityOnboardingAssertedAttributeHttpInput>,
    #[serde(default)]
    pub risk_signals: Vec<MobileIdentityOnboardingRiskSignalHttpInput>,
    pub verified_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub audit_ref: Option<String>,
    #[serde(default)]
    pub retention_policy_refs: Option<Vec<String>>,
}

impl MobileIdentityOnboardingIdentityProofingHttpInput {
    fn into_command_input(self) -> IdentityProofingVerificationRequest {
        IdentityProofingVerificationRequest {
            provider_name: self
                .provider_name
                .unwrap_or_else(|| PERSONA_PROVIDER_NAME.to_string()),
            workflow_id: self.workflow_id,
            provider_event_id: self.provider_event_id,
            asserted_attributes: self
                .asserted_attributes
                .into_iter()
                .map(MobileIdentityOnboardingAssertedAttributeHttpInput::into_asserted_attribute)
                .collect(),
            evidence_types: self
                .evidence_types
                .into_iter()
                .map(MobileIdentityOnboardingIdentityProofingEvidenceTypeHttpInput::into_evidence_type)
                .collect(),
            verification_result: self.verification_result.into_identity_witness_result(),
            assurance_level: self.assurance_level.into_assurance_level(),
            risk_signals: self
                .risk_signals
                .into_iter()
                .map(MobileIdentityOnboardingRiskSignalHttpInput::into_risk_signal)
                .collect(),
            verified_at: Timestamp(self.verified_at),
            expires_at: self.expires_at.map(Timestamp),
            audit_ref: self.audit_ref,
            evidence_ref: self.evidence_ref,
            retention_policy_refs: self
                .retention_policy_refs
                .unwrap_or_default()
                .into_iter()
                .map(PolicyRef)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileIdentityOnboardingAssertedAttributeHttpInput {
    pub attribute: MobileIdentityOnboardingAttributeHttpInput,
    pub value: String,
    #[serde(default)]
    pub confidence: Option<MobileIdentityOnboardingMatchConfidenceHttpInput>,
}

impl MobileIdentityOnboardingAssertedAttributeHttpInput {
    fn into_asserted_attribute(self) -> IdentityProofingAssertedAttribute {
        let attribute = self.attribute.into_identity_attribute();
        let value = match attribute {
            IdentityAttribute::DateOfBirth => IdentityAttributeValue::DateValue(Date(self.value)),
            _ => IdentityAttributeValue::StringValue(self.value),
        };

        IdentityProofingAssertedAttribute {
            attribute,
            value,
            confidence: self
                .confidence
                .unwrap_or(MobileIdentityOnboardingMatchConfidenceHttpInput::High)
                .into_match_confidence(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MobileIdentityOnboardingRiskSignalHttpInput {
    pub signal_type: String,
    pub result: MobileIdentityOnboardingRiskResultHttpInput,
    #[serde(default)]
    pub required_assurance: Option<MobileIdentityOnboardingAssuranceLevelHttpInput>,
    #[serde(default)]
    pub affects_policy: Option<bool>,
}

impl MobileIdentityOnboardingRiskSignalHttpInput {
    fn into_risk_signal(self) -> IdentityProofingRiskSignal {
        IdentityProofingRiskSignal {
            signal_type: self.signal_type,
            action: SensitiveAction::AuthorizeDataTransaction,
            result: self.result.into_risk_evaluation_result(),
            required_assurance: self
                .required_assurance
                .unwrap_or(MobileIdentityOnboardingAssuranceLevelHttpInput::High)
                .into_assurance_level(),
            affects_policy: self.affects_policy.unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingIdentityProofingEvidenceTypeHttpInput {
    GovernmentIdDocument,
    Passport,
    DriversLicense,
    NationalId,
    AddressDocument,
    SelfieCapture,
}

impl MobileIdentityOnboardingIdentityProofingEvidenceTypeHttpInput {
    fn into_evidence_type(self) -> IdentityProofingEvidenceType {
        match self {
            Self::GovernmentIdDocument => IdentityProofingEvidenceType::GovernmentIdDocument,
            Self::Passport => IdentityProofingEvidenceType::Passport,
            Self::DriversLicense => IdentityProofingEvidenceType::DriversLicense,
            Self::NationalId => IdentityProofingEvidenceType::NationalId,
            Self::AddressDocument => IdentityProofingEvidenceType::AddressDocument,
            Self::SelfieCapture => IdentityProofingEvidenceType::SelfieCapture,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingIdentityProofingResultHttpInput {
    Passed,
    Failed,
    Inconclusive,
}

impl MobileIdentityOnboardingIdentityProofingResultHttpInput {
    fn into_identity_witness_result(self) -> IdentityWitnessResult {
        match self {
            Self::Passed => IdentityWitnessResult::Passed,
            Self::Failed => IdentityWitnessResult::Failed,
            Self::Inconclusive => IdentityWitnessResult::Inconclusive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileLivePresenceCallbackResultHttpInput {
    Passed,
    Failed,
    Inconclusive,
}

impl MobileLivePresenceCallbackResultHttpInput {
    fn into_identity_witness_result(self) -> IdentityWitnessResult {
        match self {
            Self::Passed => IdentityWitnessResult::Passed,
            Self::Failed => IdentityWitnessResult::Failed,
            Self::Inconclusive => IdentityWitnessResult::Inconclusive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileLivePresenceCallbackPadResultHttpInput {
    Passed,
    Failed,
    Inconclusive,
    NotPerformed,
}

impl MobileLivePresenceCallbackPadResultHttpInput {
    fn into_pad_result(self) -> PresentationAttackDetectionResult {
        match self {
            Self::Passed => PresentationAttackDetectionResult::Passed,
            Self::Failed => PresentationAttackDetectionResult::Failed,
            Self::Inconclusive => PresentationAttackDetectionResult::Inconclusive,
            Self::NotPerformed => PresentationAttackDetectionResult::NotPerformed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingAttributeHttpInput {
    LegalName,
    DateOfBirth,
    Address,
    PhoneNumber,
    Email,
    SexAdministrative,
}

impl MobileIdentityOnboardingAttributeHttpInput {
    fn into_identity_attribute(self) -> IdentityAttribute {
        match self {
            Self::LegalName => IdentityAttribute::LegalName,
            Self::DateOfBirth => IdentityAttribute::DateOfBirth,
            Self::Address => IdentityAttribute::Address,
            Self::PhoneNumber => IdentityAttribute::PhoneNumber,
            Self::Email => IdentityAttribute::Email,
            Self::SexAdministrative => IdentityAttribute::SexAdministrative,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingMatchConfidenceHttpInput {
    Low,
    Medium,
    High,
    Exact,
    Ambiguous,
    Conflicting,
}

impl MobileIdentityOnboardingMatchConfidenceHttpInput {
    fn into_match_confidence(self) -> MatchConfidence {
        match self {
            Self::Low => MatchConfidence::Low,
            Self::Medium => MatchConfidence::Medium,
            Self::High => MatchConfidence::High,
            Self::Exact => MatchConfidence::Exact,
            Self::Ambiguous => MatchConfidence::Ambiguous,
            Self::Conflicting => MatchConfidence::Conflicting,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileIdentityOnboardingRiskResultHttpInput {
    Passed,
    Failed,
    RequiresStepUp,
    RequiresManualReview,
}

impl MobileIdentityOnboardingRiskResultHttpInput {
    fn into_risk_evaluation_result(self) -> RiskEvaluationResult {
        match self {
            Self::Passed => RiskEvaluationResult::Passed,
            Self::Failed => RiskEvaluationResult::Failed,
            Self::RequiresStepUp => RiskEvaluationResult::RequiresStepUp,
            Self::RequiresManualReview => RiskEvaluationResult::RequiresManualReview,
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
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileLivePresenceChallengeIssueHttpResponseBody {
    Issued {
        challenge: MobileLivePresenceChallengeHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileLivePresenceCallbackHttpResponseBody {
    Verified {
        liveness: MobileLivePresenceCallbackLivenessHttpInput,
        ceremony: MobileLivePresenceCallbackHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileAppAttestKeyRegistrationChallengeHttpResponseBody {
    Issued {
        challenge: MobileAppAttestKeyRegistrationChallengeHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MobileAppAttestKeyRegistrationHttpResponseBody {
    Registered {
        registration: MobileAppAttestKeyRegistrationHttpSummary,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    Error {
        error: MobileOnboardingHttpErrorBody,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileAppAttestKeyRegistrationChallengeHttpSummary {
    pub challenge_nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub expected_app: MobileLivePresenceExpectedAppHttpSummary,
}

impl MobileAppAttestKeyRegistrationChallengeHttpSummary {
    fn from_context(context: MobileAppAttestKeyRegistrationChallengeIssueContext) -> Self {
        Self {
            challenge_nonce: context.challenge_nonce,
            issued_at: context.issued_at.0,
            expires_at: context.expires_at.0,
            expected_app: MobileLivePresenceExpectedAppHttpSummary::from_expected_app(
                LivePresenceExpectedAppContext::from_app_attest_config(&context.expected_config),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileAppAttestKeyRegistrationHttpSummary {
    pub key_id: String,
    pub device_ref: String,
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: String,
    pub registered_at: String,
    pub attestation_challenge_nonce: String,
    pub attestation_format: String,
}

#[cfg(feature = "production-crypto")]
impl MobileAppAttestKeyRegistrationHttpSummary {
    fn from_registration(registration: AppAttestKeyRegistration) -> Self {
        Self {
            key_id: registration.key_id,
            device_ref: registration.device_ref,
            team_id: registration.team_id,
            bundle_id: registration.bundle_id,
            app_id: registration.app_id,
            environment: match registration.environment {
                AppAttestEnvironment::Development => "development".to_string(),
                AppAttestEnvironment::Production => "production".to_string(),
            },
            registered_at: registration.registered_at.0,
            attestation_challenge_nonce: registration.attestation_challenge_nonce,
            attestation_format: registration.attestation_format,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileLivePresenceChallengeHttpSummary {
    pub challenge_id: String,
    pub challenge_nonce: String,
    pub intended_workflow: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_device_ref: Option<String>,
    pub expected_app: MobileLivePresenceExpectedAppHttpSummary,
    pub issued_at: String,
    pub expires_at: String,
    pub retry_policy_refs: Vec<String>,
    pub manual_review_policy_refs: Vec<String>,
    pub retention_policy_refs: Vec<String>,
    pub provider_handoff: MobileLivePresenceProviderHandoffHttpSummary,
}

impl MobileLivePresenceChallengeHttpSummary {
    fn from_challenge(
        challenge: LivePresenceChallenge,
        issue_context: &MobileLivePresenceChallengeIssueContext,
    ) -> Self {
        let handoff_challenge_nonce = challenge.challenge_nonce.clone();
        let handoff_expires_at = challenge.expires_at.0.clone();
        Self {
            challenge_id: challenge.challenge_id.0,
            challenge_nonce: challenge.challenge_nonce,
            intended_workflow: match challenge.intended_workflow {
                LivePresenceChallengeWorkflow::MobileIdentityOnboarding => {
                    "mobile_identity_onboarding".to_string()
                }
                LivePresenceChallengeWorkflow::AccountRecovery => "account_recovery".to_string(),
                LivePresenceChallengeWorkflow::SensitiveActionStepUp => {
                    "sensitive_action_step_up".to_string()
                }
            },
            expected_subject_id: challenge.expected_subject_id.map(|subject_id| subject_id.0),
            expected_device_ref: challenge.expected_device_ref,
            expected_app: MobileLivePresenceExpectedAppHttpSummary::from_expected_app(
                challenge
                    .expected_app
                    .expect("issued onboarding challenge should include expected app context"),
            ),
            issued_at: challenge.issued_at.0,
            expires_at: challenge.expires_at.0,
            retry_policy_refs: challenge
                .retry_policy_refs
                .into_iter()
                .map(|policy_ref| policy_ref.0)
                .collect(),
            manual_review_policy_refs: challenge
                .manual_review_policy_refs
                .into_iter()
                .map(|policy_ref| policy_ref.0)
                .collect(),
            retention_policy_refs: challenge
                .retention_policy_refs
                .into_iter()
                .map(|policy_ref| policy_ref.0)
                .collect(),
            provider_handoff: MobileLivePresenceProviderHandoffHttpSummary {
                provider_name: issue_context.provider_name.clone(),
                challenge_nonce: handoff_challenge_nonce,
                handoff_uri: issue_context.handoff_uri.clone(),
                callback_path: issue_context.callback_path.clone(),
                expires_at: handoff_expires_at,
                retention_policy_refs: issue_context
                    .retention_policy_refs
                    .iter()
                    .map(|policy_ref| policy_ref.0.clone())
                    .collect(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileLivePresenceProviderHandoffHttpSummary {
    pub provider_name: String,
    pub challenge_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handoff_uri: Option<String>,
    pub callback_path: String,
    pub expires_at: String,
    pub retention_policy_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileLivePresenceExpectedAppHttpSummary {
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileLivePresenceCallbackLivenessHttpInput {
    pub assertion: String,
    pub challenge_nonce: String,
    pub expected_device_ref: String,
}

impl MobileLivePresenceCallbackLivenessHttpInput {
    fn from_ceremony(ceremony: &VerifiedLivenessCeremony, assertion: String) -> Self {
        Self {
            assertion,
            challenge_nonce: ceremony.challenge_nonce.clone(),
            expected_device_ref: ceremony.device_ref.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileLivePresenceCallbackHttpSummary {
    pub provider_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_subject_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_or_api_version: Option<String>,
    pub challenge_nonce: String,
    pub device_ref: String,
    pub observed_at: String,
    pub expires_at: String,
    pub result: String,
    pub pad_result: String,
    pub assurance_level: String,
    pub retention_policy_refs: Vec<String>,
}

impl MobileLivePresenceCallbackHttpSummary {
    fn from_ceremony(ceremony: VerifiedLivenessCeremony) -> Self {
        Self {
            provider_name: ceremony.provider_metadata.provider_name,
            provider_event_id: ceremony.provider_metadata.provider_event_id,
            provider_subject_ref: ceremony.provider_metadata.provider_subject_ref,
            sdk_or_api_version: ceremony.provider_metadata.sdk_or_api_version,
            challenge_nonce: ceremony.challenge_nonce,
            device_ref: ceremony.device_ref,
            observed_at: ceremony.observed_at.0,
            expires_at: ceremony.expires_at.0,
            result: identity_witness_result_wire(ceremony.result).to_string(),
            pad_result: pad_result_wire(ceremony.pad_result).to_string(),
            assurance_level: assurance_level_wire(ceremony.assurance_level).to_string(),
            retention_policy_refs: ceremony
                .retention_policy_refs
                .into_iter()
                .map(|policy_ref| policy_ref.0)
                .collect(),
        }
    }
}

impl MobileLivePresenceExpectedAppHttpSummary {
    fn from_expected_app(expected_app: LivePresenceExpectedAppContext) -> Self {
        Self {
            team_id: expected_app.team_id,
            bundle_id: expected_app.bundle_id,
            app_id: expected_app.app_id,
            environment: match expected_app.environment {
                AppAttestEnvironment::Development => "development".to_string(),
                AppAttestEnvironment::Production => "production".to_string(),
            },
        }
    }
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
                identity_proofing_witness_fact_id: summary
                    .fact_ids
                    .identity_proofing_witness_fact_id
                    .0,
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
    pub identity_proofing_witness_fact_id: String,
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
        MobileIdentityOnboardingCommandError::IdentityProofing(_) => identity_error_response(
            422,
            "identity_proofing_verification_failed",
            "identity proofing evidence was rejected",
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

fn live_presence_challenge_issue_error_response(
    error: LivePresenceChallengeError,
) -> MobileOnboardingHttpResponse {
    match error {
        LivePresenceChallengeError::MissingChallengeNonce => {
            live_presence_challenge_issue_error_response_with_code(
                422,
                "live_presence_challenge_missing_nonce",
                "live-presence challenge nonce was missing",
            )
        }
        LivePresenceChallengeError::DuplicateChallengeId
        | LivePresenceChallengeError::DuplicateChallengeNonce => {
            live_presence_challenge_issue_error_response_with_code(
                409,
                "live_presence_challenge_duplicate",
                "live-presence challenge already exists",
            )
        }
        LivePresenceChallengeError::StorageUnavailable => {
            live_presence_challenge_issue_error_response_with_code(
                500,
                "live_presence_challenge_storage_unavailable",
                "live-presence challenge state could not be stored",
            )
        }
        LivePresenceChallengeError::InvalidTimestamp => {
            live_presence_challenge_issue_error_response_with_code(
                422,
                "live_presence_challenge_invalid_timestamp",
                "live-presence challenge timestamp was invalid",
            )
        }
        _ => live_presence_challenge_issue_error_response_with_code(
            409,
            "live_presence_challenge_unavailable",
            "live-presence challenge could not be issued",
        ),
    }
}

fn live_presence_challenge_issue_error_response_with_code(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileLivePresenceChallengeIssueHttpResponseBody::Error {
            error: MobileOnboardingHttpErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )
}

fn live_presence_callback_error_response(
    error: LivenessProviderCallbackVerificationError,
) -> MobileOnboardingHttpResponse {
    match error {
        LivenessProviderCallbackVerificationError::InvalidAssertion => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_verification_failed",
                "live-presence callback assertion was rejected",
            )
        }
        LivenessProviderCallbackVerificationError::ProviderMismatch => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_provider_mismatch",
                "live-presence callback provider did not match the configured provider",
            )
        }
        LivenessProviderCallbackVerificationError::MissingProviderName => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_missing_provider",
                "live-presence callback provider was missing",
            )
        }
        LivenessProviderCallbackVerificationError::MissingChallengeNonce => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_missing_nonce",
                "live-presence callback challenge nonce was missing",
            )
        }
        LivenessProviderCallbackVerificationError::MissingDeviceRef => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_missing_device",
                "live-presence callback device reference was missing",
            )
        }
        LivenessProviderCallbackVerificationError::FutureObservedAt => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_future_observed_at",
                "live-presence callback observed time was in the future",
            )
        }
        LivenessProviderCallbackVerificationError::Expired => {
            live_presence_callback_error_response_with_code(
                409,
                "live_presence_callback_expired",
                "live-presence callback evidence has expired",
            )
        }
        LivenessProviderCallbackVerificationError::InvalidTimestamp => {
            live_presence_callback_error_response_with_code(
                422,
                "live_presence_callback_invalid_timestamp",
                "live-presence callback timestamp was invalid",
            )
        }
    }
}

fn live_presence_callback_error_response_with_code(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileLivePresenceCallbackHttpResponseBody::Error {
            error: MobileOnboardingHttpErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )
}

#[cfg(feature = "production-crypto")]
fn app_attest_key_registration_error_response(
    error: AppAttestAssertionVerificationError,
) -> MobileOnboardingHttpResponse {
    match error {
        AppAttestAssertionVerificationError::KeyStateUnavailable => {
            app_attest_key_registration_error_response_with_code(
                500,
                "app_attest_registration_storage_unavailable",
                "App Attest key registration could not be stored",
            )
        }
        AppAttestAssertionVerificationError::KeyContextMismatch => {
            app_attest_key_registration_error_response_with_code(
                409,
                "app_attest_registration_key_conflict",
                "App Attest key registration conflicts with existing key state",
            )
        }
        _ => app_attest_key_registration_error_response_with_code(
            422,
            "app_attest_registration_verification_failed",
            format!("App Attest key registration evidence was rejected: {error:?}"),
        ),
    }
}

fn app_attest_key_registration_challenge_error_response_with_code(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileAppAttestKeyRegistrationChallengeHttpResponseBody::Error {
            error: MobileOnboardingHttpErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )
}

#[cfg(feature = "production-crypto")]
fn app_attest_key_registration_error_response_with_code(
    status_code: u16,
    code: impl Into<String>,
    message: impl Into<String>,
) -> MobileOnboardingHttpResponse {
    json_response(
        status_code,
        MobileAppAttestKeyRegistrationHttpResponseBody::Error {
            error: MobileOnboardingHttpErrorBody {
                code: code.into(),
                message: message.into(),
            },
        },
    )
}

#[cfg(feature = "production-crypto")]
fn required_registration_field(
    value: Option<&str>,
) -> Result<&str, AppAttestAssertionVerificationError> {
    value.ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)
}

#[cfg(feature = "production-crypto")]
fn mobile_hex_decode(value: &str) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = mobile_hex_nibble(pair[0])?;
        let low = mobile_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg(feature = "production-crypto")]
fn mobile_hex_nibble(byte: u8) -> Result<u8, AppAttestAssertionVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
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

fn identity_witness_result_wire(result: IdentityWitnessResult) -> &'static str {
    match result {
        IdentityWitnessResult::Passed => "passed",
        IdentityWitnessResult::Failed => "failed",
        IdentityWitnessResult::Inconclusive => "inconclusive",
    }
}

fn pad_result_wire(result: PresentationAttackDetectionResult) -> &'static str {
    match result {
        PresentationAttackDetectionResult::Passed => "passed",
        PresentationAttackDetectionResult::Failed => "failed",
        PresentationAttackDetectionResult::Inconclusive => "inconclusive",
        PresentationAttackDetectionResult::NotPerformed => "not_performed",
    }
}

fn identity_decision_wire(decision: MobileIdentityOnboardingDecision) -> &'static str {
    match decision {
        MobileIdentityOnboardingDecision::Accepted => "accepted",
        MobileIdentityOnboardingDecision::ManualReviewRequired => "manual_review_required",
    }
}
