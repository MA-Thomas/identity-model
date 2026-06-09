use crate::device::*;
use crate::fen::*;
use crate::iam::*;
use crate::identity_proofing::*;
use crate::ids::*;
use crate::liveness::*;
use crate::mobile::*;
use crate::mobile_http::*;
use crate::persistence::*;
use crate::provider::*;
use crate::service::*;

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
pub struct PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I, K> {
    pub service: IdentityWorkflowService,
    pub authored_by: Author,
    pub oidc_verifier: O,
    pub app_attest_verifier: A,
    pub id_generator: I,
    pub repository: SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
    pub key_resolver: K,
}

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
pub struct PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I, K> {
    pub service: IdentityWorkflowService,
    pub authored_by: Author,
    pub oidc_verifier: O,
    pub app_attest_verifier: A,
    pub identity_proofing_provider: G,
    pub liveness_verifier: L,
    pub live_presence_challenge_store: C,
    pub continuity_provider: P,
    pub id_generator: I,
    pub repository: SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
    pub key_resolver: K,
}

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
impl<M, E, O, A, I, K> PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I, K> {
    pub fn new(
        service: IdentityWorkflowService,
        authored_by: Author,
        oidc_verifier: O,
        app_attest_verifier: A,
        id_generator: I,
        repository: SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
        key_resolver: K,
    ) -> Self {
        Self {
            service,
            authored_by,
            oidc_verifier,
            app_attest_verifier,
            id_generator,
            repository,
            key_resolver,
        }
    }
}

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
impl<M, E, O, A, G, L, C, P, I, K>
    PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I, K>
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
        repository: SqlxPostgresEncryptionAwareWorkflowRepository<M, E>,
        key_resolver: K,
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
            key_resolver,
        }
    }
}

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresEncryptedMobileOnboardingReadiness {
    pub database_reachable: bool,
}

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
impl<M, E, O, A, I, K> PostgresEncryptedMobileOnboardingRuntime<M, E, O, A, I, K>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
    O: OidcSessionVerifier,
    A: AppAttestAssertionVerifier,
    I: IdGenerator,
    K: FactKeyResolver,
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
            &self.key_resolver,
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

#[cfg(all(feature = "mobile-http", feature = "postgres-adapter"))]
impl<M, E, O, A, G, L, C, P, I, K>
    PostgresEncryptedMobileIdentityOnboardingRuntime<M, E, O, A, G, L, C, P, I, K>
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
    K: FactKeyResolver,
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
            &self.key_resolver,
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
