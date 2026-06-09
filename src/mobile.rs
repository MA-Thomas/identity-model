use crate::device::*;
use crate::fen::*;
use crate::flows::*;
use crate::iam::*;
use crate::identity::*;
use crate::identity_proofing::*;
use crate::ids::*;
use crate::liveness::*;
use crate::materialized::*;
use crate::persistence::*;
use crate::policy::*;
use crate::provider::*;
use crate::service::*;
use crate::workflows::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingCommandRequest {
    pub account: AccountTokenBootstrapRequest,
    pub app_attest: AppAttestAssertionVerificationRequest,
    pub client_context: MobileOnboardingClientContext,
}

impl MobileOnboardingCommandRequest {
    pub fn into_bootstrap_request(self) -> AccountTokenWithAppAttestBootstrapRequest {
        AccountTokenWithAppAttestBootstrapRequest {
            account: self.account,
            app_attest: self.app_attest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingClientContext {
    pub platform: MobileOnboardingPlatform,
    pub request_id: Option<String>,
    pub app_version: Option<String>,
    pub user_agent: Option<String>,
}

impl MobileOnboardingClientContext {
    pub fn iphone(request_id: impl Into<String>) -> Self {
        Self {
            platform: MobileOnboardingPlatform::Iphone,
            request_id: Some(request_id.into()),
            app_version: None,
            user_agent: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileOnboardingPlatform {
    Iphone,
    Ipad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingCommandOutcome {
    pub client_context: MobileOnboardingClientContext,
    pub summary: MobileOnboardingSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingSummary {
    pub subject_id: SubjectId,
    pub assurance_level: AssuranceLevel,
    pub active_devices: Vec<DeviceRef>,
    pub workflow_episode_id: ProblemEpisodeId,
    pub fact_ids: MobileOnboardingFactIds,
    pub committed_fact_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingFactIds {
    pub credential_fact_id: FactId,
    pub portal_login_witness_fact_id: FactId,
    pub verified_email_attribute_fact_id: Option<FactId>,
    pub device_binding_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdentityOnboardingCommandRequest {
    pub account: AccountTokenBootstrapRequest,
    pub app_attest: AppAttestAssertionVerificationRequest,
    pub liveness: LivenessCeremonyVerificationRequest,
    pub identity_proofing: IdentityProofingVerificationRequest,
    pub client_context: MobileOnboardingClientContext,
    pub subject_kind: SubjectKind,
    pub stable_profile: StableIdentityProfile,
    pub continuity_modality: BiometricModality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdentityOnboardingCommandOutcome {
    pub client_context: MobileOnboardingClientContext,
    pub summary: MobileIdentityOnboardingSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdentityOnboardingSummary {
    pub subject_id: SubjectId,
    pub decision: MobileIdentityOnboardingDecision,
    pub assurance_level: AssuranceLevel,
    pub active_devices: Vec<DeviceRef>,
    pub parent_episode_id: ProblemEpisodeId,
    pub fact_ids: MobileIdentityOnboardingFactIds,
    pub committed_fact_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileIdentityOnboardingDecision {
    Accepted,
    ManualReviewRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdentityOnboardingFactIds {
    pub subject_fact_id: FactId,
    pub credential_fact_id: FactId,
    pub portal_login_witness_fact_id: FactId,
    pub verified_email_attribute_fact_id: Option<FactId>,
    pub device_binding_fact_id: FactId,
    pub identity_proofing_witness_fact_id: FactId,
    pub selfie_liveness_witness_fact_id: FactId,
    pub enrollment_fact_id: Option<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileOnboardingCommandError {
    Verification(OidcSessionVerificationError),
    AppAttest(AppAttestAssertionVerificationError),
    DeviceRefMismatch,
    Repository(RepositoryError),
    Encryption(FactEncryptionError),
    #[cfg(feature = "postgres-adapter")]
    Storage(PostgresAdapterError),
    Materialization(FactMaterializationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIdentityOnboardingCommandError {
    Verification(OidcSessionVerificationError),
    AppAttest(AppAttestAssertionVerificationError),
    IdentityProofing(IdentityProofingVerificationError),
    Liveness(LivenessCeremonyVerificationError),
    LivePresenceChallenge(LivePresenceChallengeError),
    DeviceRefMismatch,
    Provider(ContinuityProviderError),
    Repository(RepositoryError),
    Encryption(FactEncryptionError),
    #[cfg(feature = "postgres-adapter")]
    Storage(PostgresAdapterError),
    Materialization(FactMaterializationError),
}

impl From<AccountTokenWithAppAttestBootstrapError> for MobileOnboardingCommandError {
    fn from(error: AccountTokenWithAppAttestBootstrapError) -> Self {
        match error {
            AccountTokenWithAppAttestBootstrapError::Verification(error) => {
                Self::Verification(error)
            }
            AccountTokenWithAppAttestBootstrapError::AppAttest(error) => Self::AppAttest(error),
            AccountTokenWithAppAttestBootstrapError::DeviceRefMismatch => Self::DeviceRefMismatch,
            AccountTokenWithAppAttestBootstrapError::Repository(error) => Self::Repository(error),
        }
    }
}

impl From<OidcSessionVerificationError> for MobileIdentityOnboardingCommandError {
    fn from(error: OidcSessionVerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<AppAttestAssertionVerificationError> for MobileIdentityOnboardingCommandError {
    fn from(error: AppAttestAssertionVerificationError) -> Self {
        Self::AppAttest(error)
    }
}

impl From<IdentityProofingVerificationError> for MobileIdentityOnboardingCommandError {
    fn from(error: IdentityProofingVerificationError) -> Self {
        Self::IdentityProofing(error)
    }
}

impl From<LivenessCeremonyVerificationError> for MobileIdentityOnboardingCommandError {
    fn from(error: LivenessCeremonyVerificationError) -> Self {
        Self::Liveness(error)
    }
}

impl From<LivePresenceChallengeError> for MobileIdentityOnboardingCommandError {
    fn from(error: LivePresenceChallengeError) -> Self {
        Self::LivePresenceChallenge(error)
    }
}

impl From<ContinuityProviderError> for MobileIdentityOnboardingCommandError {
    fn from(error: ContinuityProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<VerticalSliceError> for MobileIdentityOnboardingCommandError {
    fn from(error: VerticalSliceError) -> Self {
        match error {
            VerticalSliceError::Provider(error) => Self::Provider(error),
            VerticalSliceError::Verification(_) => {
                Self::Provider(ContinuityProviderError::AssertionUnavailable(
                    "continuity verification is not part of enrollment".to_string(),
                ))
            }
        }
    }
}

impl From<RepositoryError> for MobileIdentityOnboardingCommandError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl From<EncryptionAwareWorkflowRepositoryError> for MobileIdentityOnboardingCommandError {
    fn from(error: EncryptionAwareWorkflowRepositoryError) -> Self {
        match error {
            EncryptionAwareWorkflowRepositoryError::Encryption(error) => Self::Encryption(error),
            EncryptionAwareWorkflowRepositoryError::Repository(error) => Self::Repository(error),
        }
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresEncryptedWorkflowAppendError> for MobileIdentityOnboardingCommandError {
    fn from(error: PostgresEncryptedWorkflowAppendError) -> Self {
        match error {
            PostgresEncryptedWorkflowAppendError::Encryption(error) => Self::Encryption(error),
            PostgresEncryptedWorkflowAppendError::Storage(PostgresAdapterError::Repository(
                error,
            )) => Self::Repository(error),
            PostgresEncryptedWorkflowAppendError::Storage(error) => Self::Storage(error),
        }
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresEncryptedWorkflowReplayError> for MobileIdentityOnboardingCommandError {
    fn from(error: PostgresEncryptedWorkflowReplayError) -> Self {
        match error {
            PostgresEncryptedWorkflowReplayError::Storage(error) => Self::Storage(error),
            PostgresEncryptedWorkflowReplayError::Materialization(error) => {
                Self::Materialization(error)
            }
        }
    }
}

impl From<FactMaterializationError> for MobileIdentityOnboardingCommandError {
    fn from(error: FactMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

impl From<EncryptionAwareWorkflowRepositoryError> for MobileOnboardingCommandError {
    fn from(error: EncryptionAwareWorkflowRepositoryError) -> Self {
        match error {
            EncryptionAwareWorkflowRepositoryError::Encryption(error) => Self::Encryption(error),
            EncryptionAwareWorkflowRepositoryError::Repository(error) => Self::Repository(error),
        }
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresEncryptedWorkflowAppendError> for MobileOnboardingCommandError {
    fn from(error: PostgresEncryptedWorkflowAppendError) -> Self {
        match error {
            PostgresEncryptedWorkflowAppendError::Encryption(error) => Self::Encryption(error),
            PostgresEncryptedWorkflowAppendError::Storage(PostgresAdapterError::Repository(
                error,
            )) => Self::Repository(error),
            PostgresEncryptedWorkflowAppendError::Storage(error) => Self::Storage(error),
        }
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresEncryptedWorkflowReplayError> for MobileOnboardingCommandError {
    fn from(error: PostgresEncryptedWorkflowReplayError) -> Self {
        match error {
            PostgresEncryptedWorkflowReplayError::Storage(error) => Self::Storage(error),
            PostgresEncryptedWorkflowReplayError::Materialization(error) => {
                Self::Materialization(error)
            }
        }
    }
}

impl From<FactMaterializationError> for MobileOnboardingCommandError {
    fn from(error: FactMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileOnboardingEncryptedPersistenceContext {
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub materialization_policy: PolicyEvaluation,
    pub materialization_audit_context: FactMaterializationAuditContext,
}

pub fn execute_mobile_onboarding_command(
    service: &IdentityWorkflowService,
    request: MobileOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    repository: &mut impl IdentityWorkflowRepository,
) -> Result<MobileOnboardingCommandOutcome, MobileOnboardingCommandError> {
    let (client_context, bootstrap, subject_id) = build_verified_mobile_onboarding_bootstrap(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
    )?;
    repository
        .append_workflow_slice(bootstrap.workflow.slice.clone())
        .map_err(MobileOnboardingCommandError::Repository)?;
    let replayed_projection = replay_identity_state_from_repository(subject_id, repository);

    Ok(mobile_onboarding_outcome_from_bootstrap(
        client_context,
        bootstrap,
        replayed_projection,
    ))
}

pub fn execute_mobile_identity_onboarding_command(
    service: &IdentityWorkflowService,
    request: MobileIdentityOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    identity_proofing_provider: &impl IdentityProofingProvider,
    liveness_verifier: &impl LivenessCeremonyVerifier,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    continuity_provider: &impl ContinuityVaultProvider,
    id_generator: &mut impl IdGenerator,
    repository: &mut impl IdentityWorkflowRepository,
) -> Result<MobileIdentityOnboardingCommandOutcome, MobileIdentityOnboardingCommandError> {
    let composition = build_verified_mobile_identity_onboarding_composition(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        identity_proofing_provider,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
    )?;

    repository.append_episode_composition(
        composition.parent_episode.clone(),
        composition.child_slices.clone(),
        composition.episode_relations.clone(),
    )?;
    let replayed_projection =
        replay_identity_state_from_repository(composition.subject_id.clone(), repository);

    Ok(mobile_identity_onboarding_outcome_from_composition(
        composition,
        replayed_projection,
    ))
}

pub fn execute_encrypted_mobile_identity_onboarding_command<R, M, E>(
    service: &IdentityWorkflowService,
    request: MobileIdentityOnboardingCommandRequest,
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
) -> Result<MobileIdentityOnboardingCommandOutcome, MobileIdentityOnboardingCommandError>
where
    R: StoredEncryptedWorkflowRepository,
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let composition = build_verified_mobile_identity_onboarding_composition(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        identity_proofing_provider,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
    )?;

    encrypted_repository.append_episode_composition(
        composition.parent_episode.clone(),
        composition.child_slices.clone(),
        composition.episode_relations.clone(),
        persistence_context.transaction_id,
        persistence_context.committed_at,
    )?;
    let replayed_projection = encrypted_repository.replay_identity_state(
        composition.subject_id.clone(),
        &persistence_context.materialization_policy,
        key_resolver,
    )?;

    Ok(mobile_identity_onboarding_outcome_from_composition(
        composition,
        replayed_projection,
    ))
}

#[cfg(feature = "postgres-adapter")]
pub async fn execute_postgres_encrypted_mobile_identity_onboarding_command<M, E>(
    service: &IdentityWorkflowService,
    request: MobileIdentityOnboardingCommandRequest,
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
) -> Result<MobileIdentityOnboardingCommandOutcome, MobileIdentityOnboardingCommandError>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let composition = build_verified_mobile_identity_onboarding_composition(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        identity_proofing_provider,
        liveness_verifier,
        live_presence_challenge_store,
        continuity_provider,
        id_generator,
    )?;

    encrypted_repository
        .append_episode_composition(
            composition.parent_episode.clone(),
            composition.child_slices.clone(),
            composition.episode_relations.clone(),
            persistence_context.transaction_id,
            persistence_context.committed_at,
        )
        .await
        .map_err(MobileIdentityOnboardingCommandError::from)?;
    let replayed_projection = encrypted_repository
        .replay_identity_state(
            composition.subject_id.clone(),
            &persistence_context.materialization_policy,
            &persistence_context.materialization_audit_context,
            key_resolver,
        )
        .await
        .map_err(MobileIdentityOnboardingCommandError::from)?;

    Ok(mobile_identity_onboarding_outcome_from_composition(
        composition,
        replayed_projection,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MobileIdentityOnboardingComposition {
    client_context: MobileOnboardingClientContext,
    subject_id: SubjectId,
    decision: MobileIdentityOnboardingDecision,
    parent_episode: ProblemEpisode,
    child_slices: Vec<IdentityWorkflowSlice>,
    episode_relations: Vec<EpisodeRelation>,
    fact_ids: MobileIdentityOnboardingFactIds,
    committed_fact_count: usize,
}

fn build_verified_mobile_identity_onboarding_composition(
    service: &IdentityWorkflowService,
    request: MobileIdentityOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    identity_proofing_provider: &impl IdentityProofingProvider,
    liveness_verifier: &impl LivenessCeremonyVerifier,
    live_presence_challenge_store: &impl LivePresenceChallengeStore,
    continuity_provider: &impl ContinuityVaultProvider,
    id_generator: &mut impl IdGenerator,
) -> Result<MobileIdentityOnboardingComposition, MobileIdentityOnboardingCommandError> {
    let observed_at = request.account.observed_at.clone();
    let subject_id = request.account.subject_id.clone();
    let authored_by = request.account.authored_by.clone();
    let id_namespace = request.account.id_namespace.clone();

    let session = oidc_verifier.verify_session(
        &request.account.token,
        &request.account.oidc_config,
        &observed_at,
    )?;
    let app_attest_assertion =
        app_attest_verifier.verify_app_attest_assertion(&request.app_attest, &observed_at)?;
    if request
        .account
        .device_ref
        .as_ref()
        .is_some_and(|device_ref| device_ref != &app_attest_assertion.device_ref)
    {
        return Err(MobileIdentityOnboardingCommandError::DeviceRefMismatch);
    }

    let identity_proofing = identity_proofing_provider
        .verify_identity_proofing(&request.identity_proofing, &observed_at)?;
    let identity_proofing_requires_review =
        identity_proofing.requires_manual_review_at(&observed_at)?;

    let liveness = liveness_verifier.verify_liveness_ceremony(&request.liveness, &observed_at)?;
    validate_liveness_bound_to_app_attest(&liveness, &app_attest_assertion)?;
    live_presence_challenge_store.consume_verified_live_presence_challenge(
        &liveness,
        &app_attest_assertion,
        &subject_id,
        &observed_at,
    )?;

    let parent_episode = parent_onboarding_episode(
        id_generator.next_episode_id(&format!("episode-{id_namespace}-parent")),
        subject_id.clone(),
        authored_by.clone(),
        observed_at.clone(),
    );

    let registration = service.register_subject(RegisterSubjectRequest::with_generated_ids(
        subject_id.clone(),
        authored_by.clone(),
        observed_at.clone(),
        request.subject_kind,
        request.stable_profile,
        &format!("{id_namespace}-register-subject"),
        id_generator,
    ));

    let account_bootstrap = service.accept_account_session(
        AccountSessionBootstrapRequest::with_generated_ids_and_app_attest(
            subject_id.clone(),
            authored_by.clone(),
            observed_at.clone(),
            session,
            app_attest_assertion,
            request.account.assurance_policy,
            &format!("{id_namespace}-account-session"),
            id_generator,
        ),
    );

    let witness_slice = onboarding_identity_witnesses_slice_from_request(
        OnboardingIdentityWitnessesRequest {
            subject_id: subject_id.clone(),
            authored_by: authored_by.clone(),
            started_at: observed_at.clone(),
            id_plan: WorkflowIdPlan::generated(
                id_generator,
                &format!("{id_namespace}-identity-witnesses"),
                identity_proofing.mapped_fact_count() + 1,
            ),
            identity_proofing,
            liveness: liveness.clone(),
        },
        &service.translator,
    );
    let identity_proofing_witness_fact_id = required_fact_id_in_slice(&witness_slice, |payload| {
        matches!(
            payload,
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::GovernmentIdVerification
                    | IdentityWitnessType::LegalDocument,
                ..
            }
        )
    });
    let selfie_liveness_witness_fact_id = required_fact_id_in_slice(&witness_slice, |payload| {
        matches!(
            payload,
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::SelfieLivenessCheck,
                ..
            }
        )
    });

    let continuity_enrollment = if liveness.passed() && !identity_proofing_requires_review {
        Some(service.enroll_continuity_reference(
            EnrollContinuityRequest::with_generated_ids(
                subject_id.clone(),
                authored_by.clone(),
                observed_at.clone(),
                request.continuity_modality,
                &format!("{id_namespace}-enroll-continuity"),
                id_generator,
            ),
            continuity_provider,
        )?)
    } else {
        None
    };

    let mut child_slices = vec![
        registration.workflow.slice.clone(),
        account_bootstrap.workflow.slice.clone(),
        witness_slice.clone(),
    ];
    if let Some(enrollment) = &continuity_enrollment {
        child_slices.push(enrollment.workflow.slice.clone());
    }

    let relation_namespace = format!("relation-{id_namespace}");
    let episode_relations = child_slices
        .iter()
        .map(|slice| {
            episode_relation(
                id_generator.next_relation_id(&relation_namespace),
                slice.episode.id.clone(),
                parent_episode.id.clone(),
                EpisodeRelationType::PartOf,
                authored_by.clone(),
                slice.episode.authored_at.clone(),
            )
        })
        .collect::<Vec<_>>();

    let committed_fact_count = child_slices.iter().map(|slice| slice.facts.len()).sum();
    Ok(MobileIdentityOnboardingComposition {
        client_context: request.client_context,
        subject_id,
        decision: if liveness.passed() {
            if identity_proofing_requires_review {
                MobileIdentityOnboardingDecision::ManualReviewRequired
            } else {
                MobileIdentityOnboardingDecision::Accepted
            }
        } else {
            MobileIdentityOnboardingDecision::ManualReviewRequired
        },
        parent_episode,
        child_slices,
        episode_relations,
        fact_ids: MobileIdentityOnboardingFactIds {
            subject_fact_id: registration.subject_fact_id,
            credential_fact_id: account_bootstrap.credential_fact_id,
            portal_login_witness_fact_id: account_bootstrap.portal_login_witness_fact_id,
            verified_email_attribute_fact_id: account_bootstrap.verified_email_attribute_fact_id,
            device_binding_fact_id: account_bootstrap
                .device_binding_fact_id
                .expect("App Attest onboarding requires device binding"),
            identity_proofing_witness_fact_id,
            selfie_liveness_witness_fact_id,
            enrollment_fact_id: continuity_enrollment
                .map(|enrollment| enrollment.enrollment_fact_id),
        },
        committed_fact_count,
    })
}

pub fn execute_encrypted_mobile_onboarding_command<R, M, E>(
    service: &IdentityWorkflowService,
    request: MobileOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    encrypted_repository: &mut EncryptionAwareWorkflowRepository<R, M, E>,
    persistence_context: MobileOnboardingEncryptedPersistenceContext,
    key_resolver: &impl FactKeyResolver,
) -> Result<MobileOnboardingCommandOutcome, MobileOnboardingCommandError>
where
    R: StoredEncryptedWorkflowRepository,
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let (client_context, bootstrap, subject_id) = build_verified_mobile_onboarding_bootstrap(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
    )?;

    encrypted_repository.append_workflow_slice(
        bootstrap.workflow.slice.clone(),
        persistence_context.transaction_id,
        persistence_context.committed_at,
    )?;
    let replayed_projection = encrypted_repository.replay_identity_state(
        subject_id,
        &persistence_context.materialization_policy,
        key_resolver,
    )?;

    Ok(mobile_onboarding_outcome_from_bootstrap(
        client_context,
        bootstrap,
        replayed_projection,
    ))
}

#[cfg(feature = "postgres-adapter")]
pub async fn execute_postgres_encrypted_mobile_onboarding_command<M, E>(
    service: &IdentityWorkflowService,
    request: MobileOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
    encrypted_repository: &mut SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
    persistence_context: MobileOnboardingEncryptedPersistenceContext,
    key_resolver: &impl FactKeyResolver,
) -> Result<MobileOnboardingCommandOutcome, MobileOnboardingCommandError>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    let (client_context, bootstrap, subject_id) = build_verified_mobile_onboarding_bootstrap(
        service,
        request,
        oidc_verifier,
        app_attest_verifier,
        id_generator,
    )?;

    encrypted_repository
        .append_workflow_slice(
            bootstrap.workflow.slice.clone(),
            persistence_context.transaction_id,
            persistence_context.committed_at,
        )
        .await
        .map_err(MobileOnboardingCommandError::from)?;
    let replayed_projection = encrypted_repository
        .replay_identity_state(
            subject_id,
            &persistence_context.materialization_policy,
            &persistence_context.materialization_audit_context,
            key_resolver,
        )
        .await
        .map_err(MobileOnboardingCommandError::from)?;

    Ok(mobile_onboarding_outcome_from_bootstrap(
        client_context,
        bootstrap,
        replayed_projection,
    ))
}

fn build_verified_mobile_onboarding_bootstrap(
    service: &IdentityWorkflowService,
    request: MobileOnboardingCommandRequest,
    oidc_verifier: &impl OidcSessionVerifier,
    app_attest_verifier: &impl AppAttestAssertionVerifier,
    id_generator: &mut impl IdGenerator,
) -> Result<
    (
        MobileOnboardingClientContext,
        AccountSessionBootstrapOutcome,
        SubjectId,
    ),
    MobileOnboardingCommandError,
> {
    let client_context = request.client_context.clone();
    let bootstrap = service
        .accept_account_token_with_app_attest(
            request.into_bootstrap_request(),
            oidc_verifier,
            app_attest_verifier,
            id_generator,
        )
        .map_err(MobileOnboardingCommandError::from)?;
    let subject_id = bootstrap.workflow.slice.episode.subject_id.clone();

    Ok((client_context, bootstrap, subject_id))
}

fn mobile_onboarding_outcome_from_bootstrap(
    client_context: MobileOnboardingClientContext,
    bootstrap: AccountSessionBootstrapOutcome,
    replayed_projection: MaterializedIdentityState,
) -> MobileOnboardingCommandOutcome {
    let device_binding_fact_id = bootstrap
        .device_binding_fact_id
        .clone()
        .expect("mobile onboarding requires App Attest device-binding evidence");

    MobileOnboardingCommandOutcome {
        client_context,
        summary: MobileOnboardingSummary {
            subject_id: replayed_projection.subject_id,
            assurance_level: replayed_projection.assurance_level,
            active_devices: replayed_projection.active_devices,
            workflow_episode_id: bootstrap.workflow.slice.episode.id,
            fact_ids: MobileOnboardingFactIds {
                credential_fact_id: bootstrap.credential_fact_id,
                portal_login_witness_fact_id: bootstrap.portal_login_witness_fact_id,
                verified_email_attribute_fact_id: bootstrap.verified_email_attribute_fact_id,
                device_binding_fact_id,
            },
            committed_fact_count: bootstrap.workflow.slice.facts.len(),
        },
    }
}

fn mobile_identity_onboarding_outcome_from_composition(
    composition: MobileIdentityOnboardingComposition,
    replayed_projection: MaterializedIdentityState,
) -> MobileIdentityOnboardingCommandOutcome {
    MobileIdentityOnboardingCommandOutcome {
        client_context: composition.client_context,
        summary: MobileIdentityOnboardingSummary {
            subject_id: replayed_projection.subject_id,
            decision: composition.decision,
            assurance_level: replayed_projection.assurance_level,
            active_devices: replayed_projection.active_devices,
            parent_episode_id: composition.parent_episode.id,
            fact_ids: composition.fact_ids,
            committed_fact_count: composition.committed_fact_count,
        },
    }
}

fn required_fact_id_in_slice(
    slice: &IdentityWorkflowSlice,
    predicate: impl Fn(&FactPayload) -> bool,
) -> FactId {
    slice
        .facts
        .iter()
        .find_map(|fact| predicate(&fact.payload).then(|| fact.id.clone()))
        .expect("workflow slice should include required fact")
}
