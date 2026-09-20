use crate::mobile::*;
use crate::mobile_http::*;
use identity_application::workflows::EncryptedWorkflowService;
use identity_model::device::*;
use identity_model::fen::*;
use identity_model::iam::*;
use identity_model::identity_proofing::*;
use identity_model::ids::*;
use identity_model::liveness::*;
use identity_model::persistence::*;
use identity_model::provider::*;
use identity_model::service::*;
use identity_storage_postgres::*;

pub struct PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I> {
    pub service: IdentityWorkflowService,
    pub authored_by: Author,
    pub oidc_verifier: O,
    pub app_attest_verifier: A,
    pub id_generator: I,
    pub repository: EncryptedWorkflowService<SqlxPostgresEncryptedFactRepository, M, E>,
}

pub struct PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I> {
    pub service: IdentityWorkflowService,
    pub authored_by: Author,
    pub oidc_verifier: O,
    pub app_attest_verifier: A,
    pub identity_proofing_provider: G,
    pub liveness_verifier: L,
    pub live_presence_challenge_store: C,
    pub continuity_provider: P,
    pub id_generator: I,
    pub repository: EncryptedWorkflowService<SqlxPostgresEncryptedFactRepository, M, E>,
}

impl<M, E, O, A, I> PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I> {
    pub fn new(
        service: IdentityWorkflowService,
        authored_by: Author,
        oidc_verifier: O,
        app_attest_verifier: A,
        id_generator: I,
        repository: EncryptedWorkflowService<SqlxPostgresEncryptedFactRepository, M, E>,
    ) -> Self {
        Self {
            service,
            authored_by,
            oidc_verifier,
            app_attest_verifier,
            id_generator,
            repository,
        }
    }
}

impl<M, E, O, A, G, L, C, P, I>
    PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I>
{
    pub fn new(
        service: IdentityWorkflowService,
        authored_by: Author,
        oidc_verifier: O,
        app_attest_verifier: A,
        identity_proofing_provider: G,
        liveness_verifier: L,
        live_presence_challenge_store: C,
        continuity_provider: P,
        id_generator: I,
        repository: EncryptedWorkflowService<SqlxPostgresEncryptedFactRepository, M, E>,
    ) -> Self {
        Self {
            service,
            authored_by,
            oidc_verifier,
            app_attest_verifier,
            identity_proofing_provider,
            liveness_verifier,
            live_presence_challenge_store,
            continuity_provider,
            id_generator,
            repository,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresEncryptedMobileOnboardingReadiness {
    pub database_reachable: bool,
}

impl<M, E, O, A, I> PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
    O: OidcSessionVerifier,
    A: AppAttestAssertionVerifier,
    I: IdGenerator,
{
    pub async fn handle_http_request(
        &mut self,
        request: MobileOnboardingHttpRequest,
        persistence_context: MobileOnboardingEncryptedPersistenceContext,
    ) -> MobileOnboardingHttpResponse {
        handle_postgres_encrypted_mobile_onboarding_http_request(
            request,
            &self.service,
            self.authored_by.clone(),
            &self.oidc_verifier,
            &self.app_attest_verifier,
            &mut self.id_generator,
            &mut self.repository,
            persistence_context,
        )
        .await
    }

    pub async fn run_migrations(&self) -> Result<(), PostgresAdapterError> {
        self.repository.storage().run_migration().await
    }

    pub async fn readiness_check(
        &self,
    ) -> Result<PostgresEncryptedMobileOnboardingReadiness, PostgresAdapterError> {
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(self.repository.storage().pool())
            .await
            .map_err(|error| PostgresAdapterError::Sqlx(error.to_string()))?;
        Ok(PostgresEncryptedMobileOnboardingReadiness {
            database_reachable: one == 1,
        })
    }
}

impl<M, E, O, A, G, L, C, P, I>
    PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
    O: OidcSessionVerifier,
    A: AppAttestAssertionVerifier,
    G: IdentityProofingProvider,
    L: LivenessCeremonyVerifier,
    C: LivePresenceChallengeStore,
    P: ContinuityVaultProvider,
    I: IdGenerator,
{
    pub async fn handle_http_request(
        &mut self,
        request: MobileOnboardingHttpRequest,
        persistence_context: MobileOnboardingEncryptedPersistenceContext,
    ) -> MobileOnboardingHttpResponse {
        handle_postgres_encrypted_mobile_identity_onboarding_http_request(
            request,
            &self.service,
            self.authored_by.clone(),
            &self.oidc_verifier,
            &self.app_attest_verifier,
            &self.identity_proofing_provider,
            &self.liveness_verifier,
            &self.live_presence_challenge_store,
            &self.continuity_provider,
            &mut self.id_generator,
            &mut self.repository,
            persistence_context,
        )
        .await
    }

    pub async fn run_migrations(&self) -> Result<(), PostgresAdapterError> {
        self.repository.storage().run_migration().await
    }

    pub async fn readiness_check(
        &self,
    ) -> Result<PostgresEncryptedMobileOnboardingReadiness, PostgresAdapterError> {
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(self.repository.storage().pool())
            .await
            .map_err(|error| PostgresAdapterError::Sqlx(error.to_string()))?;
        Ok(PostgresEncryptedMobileOnboardingReadiness {
            database_reachable: one == 1,
        })
    }
}
