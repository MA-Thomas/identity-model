use super::*;
use crate::device::*;
#[cfg(feature = "postgres-adapter")]
use crate::flows::IdentityWorkflowSlice;
#[cfg(feature = "postgres-adapter")]
use crate::identity::AccessDecisionResult;
use crate::liveness::*;
#[cfg(feature = "postgres-adapter")]
use crate::materialized::{materialize_identity_state, MaterializedIdentityState};
#[cfg(feature = "postgres-adapter")]
use crate::policy::PolicyEvaluation;
#[cfg(feature = "postgres-adapter")]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};
#[cfg(feature = "postgres-adapter")]
use std::future::Future;

pub const IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL: &str =
    include_str!("../../migrations/0001_identity_encrypted_facts.sql");
pub const IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL: &str =
    include_str!("../../migrations/0002_identity_workflow_transactions.sql");
pub const IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL: &str =
    include_str!("../../migrations/0003_identity_app_attest_key_state.sql");
pub const IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL: &str =
    include_str!("../../migrations/0004_identity_live_presence_challenges.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresMigration {
    pub name: &'static str,
    pub sql: &'static str,
}

pub const IDENTITY_POSTGRES_MIGRATIONS: [PostgresMigration; 4] = [
    PostgresMigration {
        name: "0001_identity_encrypted_facts",
        sql: IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0002_identity_workflow_transactions",
        sql: IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0003_identity_app_attest_key_state",
        sql: IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0004_identity_live_presence_challenges",
        sql: IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL,
    },
];

pub const IDENTITY_POSTGRES_MIGRATIONS_SQL: [&str; 4] = [
    IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL,
    IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL,
    IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL,
    IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL,
];

#[cfg(feature = "postgres-adapter")]
const IDENTITY_WORKFLOW_SEQUENCE_LOCK_KEY: i64 = 3_601_170_001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProblemEpisode {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub episode: ProblemEpisode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeMembership {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub membership: EpisodeMembership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeRelation {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub relation: EpisodeRelation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentityWorkflowSlice {
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub episode: StoredProblemEpisode,
    pub encrypted_facts: Vec<StoredEncryptedFact>,
    pub memberships: Vec<StoredEpisodeMembership>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeComposition {
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub parent_episode: StoredProblemEpisode,
    pub child_slices: Vec<StoredIdentityWorkflowSlice>,
    pub episode_relations: Vec<StoredEpisodeRelation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresWorkflowTransactionKind {
    WorkflowSlice,
    EpisodeComposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresWorkflowTransactionRow {
    pub transaction_id: String,
    pub transaction_kind: String,
    pub committed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresEncryptedFactRow {
    pub append_sequence: i64,
    pub transaction_id: String,
    pub committed_at: String,
    pub fact_id: String,
    pub subject_id: String,
    pub occurred_kind: String,
    pub occurred_start: String,
    pub occurred_end: Option<String>,
    pub payload_type: String,
    pub status_kind: String,
    pub status_payload: PostgresFactStatusPayload,
    pub materialization_policy_refs: Vec<String>,
    pub encryption_algorithm: String,
    pub encryption_key_id: String,
    pub wrapped_dek_ref: Option<String>,
    pub nonce: Vec<u8>,
    pub aad_version: String,
    pub ciphertext: Vec<u8>,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    feature = "postgres-adapter",
    serde(tag = "kind", rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresFactStatusPayload {
    Active,
    Superseded {
        superseded_by: PostgresAuthorRecord,
        superseded_at: PostgresTemporalAnchorRecord,
        replaced_by: Option<String>,
        reason: String,
    },
    EnteredInError {
        corrected_by: PostgresAuthorRecord,
        corrected_at: PostgresTemporalAnchorRecord,
        replaced_by: Option<String>,
    },
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresAuthorRecord {
    pub author_type: String,
    pub author_id: Option<String>,
    pub display_name: Option<String>,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTemporalAnchorRecord {
    pub kind: String,
    pub start: String,
    pub end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresMaterializationAuditRow {
    pub subject_id: String,
    pub fact_ids: Vec<String>,
    pub materialization_policy_refs: Vec<String>,
    pub evaluated_policy_refs: Vec<String>,
    pub caller: Option<String>,
    pub purpose: Option<String>,
    pub requested_at: Option<String>,
    pub outcome: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresAppAttestKeyStateRow {
    pub key_id: String,
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: String,
    pub device_ref: String,
    pub status: String,
    pub registered_at: String,
    pub last_asserted_at: String,
    pub last_sign_count: i64,
    pub last_challenge_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresLivePresenceChallengeRow {
    pub challenge_id: String,
    pub challenge_nonce: String,
    pub intended_workflow: String,
    pub expected_subject_id: Option<String>,
    pub expected_device_ref: Option<String>,
    pub expected_team_id: Option<String>,
    pub expected_bundle_id: Option<String>,
    pub expected_app_id: Option<String>,
    pub expected_environment: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub status_kind: String,
    pub status_payload: PostgresLivePresenceChallengeStatusPayload,
    pub retry_policy_refs: Vec<String>,
    pub manual_review_policy_refs: Vec<String>,
    pub retention_policy_refs: Vec<String>,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    feature = "postgres-adapter",
    serde(tag = "kind", rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresLivePresenceChallengeStatusPayload {
    Issued,
    Used {
        used_at: String,
        provider_event_id: Option<String>,
    },
    Expired {
        expired_at: String,
    },
    Failed {
        failed_at: String,
        reason: String,
        provider_event_id: Option<String>,
    },
    ManualReview {
        referred_at: String,
        reason: String,
        provider_event_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresProblemEpisodeRow {
    pub append_sequence: i64,
    pub transaction_id: String,
    pub committed_at: String,
    pub episode_id: String,
    pub subject_id: String,
    pub episode_kind: String,
    pub label: String,
    pub problem_code: Option<PostgresCodedValueRecord>,
    pub status_kind: String,
    pub status_payload: PostgresEpisodeStatusPayload,
    pub onset: Option<PostgresApproximateDateRecord>,
    pub authored_by: PostgresAuthorRecord,
    pub authored_at: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresEpisodeMembershipRow {
    pub append_sequence: i64,
    pub transaction_id: String,
    pub committed_at: String,
    pub membership_id: String,
    pub fact_id: String,
    pub episode_id: String,
    pub role: String,
    pub asserted_by: PostgresAuthorRecord,
    pub asserted_kind: String,
    pub asserted_start: String,
    pub asserted_end: Option<String>,
    pub status_kind: String,
    pub status_payload: PostgresMembershipStatusPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresEpisodeRelationRow {
    pub append_sequence: i64,
    pub transaction_id: String,
    pub committed_at: String,
    pub relation_id: String,
    pub source_episode_id: String,
    pub target_episode_id: String,
    pub relation_type: String,
    pub asserted_by: PostgresAuthorRecord,
    pub asserted_kind: String,
    pub asserted_start: String,
    pub asserted_end: Option<String>,
    pub status_kind: String,
    pub status_payload: PostgresEpisodeRelationStatusPayload,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresCodedValueRecord {
    pub system: String,
    pub code: String,
    pub display: String,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresApproximateDateRecord {
    pub date: String,
    pub precision: String,
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    feature = "postgres-adapter",
    serde(tag = "kind", rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresEpisodeStatusPayload {
    Active,
    Dormant,
    Resolved {
        at: Option<PostgresApproximateDateRecord>,
    },
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    feature = "postgres-adapter",
    serde(tag = "kind", rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresMembershipStatusPayload {
    Active,
    Retracted {
        retracted_by: PostgresAuthorRecord,
        retracted_at: PostgresTemporalAnchorRecord,
    },
}

#[cfg_attr(
    feature = "postgres-adapter",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    feature = "postgres-adapter",
    serde(tag = "kind", rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresEpisodeRelationStatusPayload {
    Active,
    Retracted {
        retracted_by: PostgresAuthorRecord,
        retracted_at: PostgresTemporalAnchorRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresAdapterError {
    AppendSequenceOutOfRange,
    NegativeAppendSequence,
    InvalidTemporalAnchor,
    UnknownTemporalKind(String),
    UnknownFactStatusKind(String),
    InvalidFactStatusPayload,
    UnknownAuthorType(String),
    UnknownSupersessionReason(String),
    UnknownPayloadType(String),
    UnknownEncryptionAlgorithm(String),
    UnknownAssociatedDataVersion(String),
    UnknownMaterializationAuditOutcome(String),
    UnknownMaterializationError(String),
    UnknownWorkflowTransactionKind(String),
    UnknownEpisodeKind(String),
    UnknownEpisodeStatusKind(String),
    InvalidEpisodeStatusPayload,
    UnknownDatePrecision(String),
    UnknownCodingSystem(String),
    UnknownMembershipStatusKind(String),
    InvalidMembershipStatusPayload,
    UnknownFactRole(String),
    UnknownEpisodeRelationType(String),
    UnknownEpisodeRelationStatusKind(String),
    UnknownAppAttestEnvironment(String),
    UnknownAppAttestKeyStatus(String),
    UnknownLivePresenceChallengeWorkflow(String),
    UnknownLivePresenceChallengeStatusKind(String),
    UnknownLivePresenceChallengeFailureReason(String),
    UnknownLivePresenceChallengeManualReviewReason(String),
    AppAttestSignCountOutOfRange,
    InvalidEpisodeRelationStatusPayload,
    InvalidLivePresenceChallengeStatusPayload,
    StatusPayloadJson(String),
    Repository(RepositoryError),
    Sqlx(String),
}

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresEncryptedWorkflowAppendError {
    Encryption(FactEncryptionError),
    Storage(PostgresAdapterError),
}

#[cfg(feature = "postgres-adapter")]
impl From<FactEncryptionError> for PostgresEncryptedWorkflowAppendError {
    fn from(error: FactEncryptionError) -> Self {
        Self::Encryption(error)
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresAdapterError> for PostgresEncryptedWorkflowAppendError {
    fn from(error: PostgresAdapterError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresEncryptedWorkflowReplayError {
    Storage(PostgresAdapterError),
    Materialization(FactMaterializationError),
}

#[cfg(feature = "postgres-adapter")]
impl From<PostgresAdapterError> for PostgresEncryptedWorkflowReplayError {
    fn from(error: PostgresAdapterError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(feature = "postgres-adapter")]
impl From<FactMaterializationError> for PostgresEncryptedWorkflowReplayError {
    fn from(error: FactMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct SqlxPostgresEncryptedFactRepository {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct PostgresAppAttestKeyStateStore {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct PostgresLivePresenceChallengeStore {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
pub struct SqlxPostgresEncryptionAwareWorkflowRepository<M, E> {
    storage: SqlxPostgresEncryptedFactRepository,
    metadata_planner: M,
    encryptor: E,
    key: FactDataEncryptionKey,
    materialization_policy_refs: Vec<PolicyRef>,
}

#[cfg(feature = "postgres-adapter")]
impl<M, E> SqlxPostgresEncryptionAwareWorkflowRepository<M, E> {
    pub fn new(
        storage: SqlxPostgresEncryptedFactRepository,
        metadata_planner: M,
        encryptor: E,
        key: FactDataEncryptionKey,
        materialization_policy_refs: Vec<PolicyRef>,
    ) -> Self {
        Self {
            storage,
            metadata_planner,
            encryptor,
            key,
            materialization_policy_refs,
        }
    }

    pub fn from_pool(
        pool: PgPool,
        metadata_planner: M,
        encryptor: E,
        key: FactDataEncryptionKey,
        materialization_policy_refs: Vec<PolicyRef>,
    ) -> Self {
        Self::new(
            SqlxPostgresEncryptedFactRepository::from_pool(pool),
            metadata_planner,
            encryptor,
            key,
            materialization_policy_refs,
        )
    }

    pub async fn connect(
        database_url: &str,
        metadata_planner: M,
        encryptor: E,
        key: FactDataEncryptionKey,
        materialization_policy_refs: Vec<PolicyRef>,
    ) -> Result<Self, PostgresAdapterError> {
        Ok(Self::new(
            SqlxPostgresEncryptedFactRepository::connect(database_url).await?,
            metadata_planner,
            encryptor,
            key,
            materialization_policy_refs,
        ))
    }

    pub fn storage(&self) -> &SqlxPostgresEncryptedFactRepository {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut SqlxPostgresEncryptedFactRepository {
        &mut self.storage
    }
}

#[cfg(feature = "postgres-adapter")]
impl<M, E> SqlxPostgresEncryptionAwareWorkflowRepository<M, E>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    pub async fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredIdentityWorkflowSlice, PostgresEncryptedWorkflowAppendError> {
        let mut transaction = self.storage.pool.begin().await.map_err(sqlx_error)?;
        acquire_workflow_sequence_lock(&mut transaction).await?;
        let sequence_state = next_workflow_sequence_state(&mut transaction).await?;
        let sequence_plan = sequence_state.plan_for_slice(&slice);
        let stored = build_stored_encrypted_workflow_slice(
            slice,
            transaction_id,
            committed_at,
            &sequence_plan,
            self.materialization_policy_refs.clone(),
            &self.key,
            &mut self.metadata_planner,
            &self.encryptor,
        )?;

        insert_stored_workflow_slice_rows(&mut transaction, &stored).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(stored)
    }

    pub async fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredEpisodeComposition, PostgresEncryptedWorkflowAppendError> {
        let mut transaction = self.storage.pool.begin().await.map_err(sqlx_error)?;
        acquire_workflow_sequence_lock(&mut transaction).await?;
        let sequence_state = next_workflow_sequence_state(&mut transaction).await?;
        let sequence_plan =
            sequence_state.plan_for_episode_composition(&child_slices, &episode_relations);
        let stored = build_stored_encrypted_episode_composition(
            parent_episode,
            child_slices,
            episode_relations,
            transaction_id,
            committed_at,
            &sequence_plan,
            self.materialization_policy_refs.clone(),
            &self.key,
            &mut self.metadata_planner,
            &self.encryptor,
        )?;

        insert_stored_episode_composition_rows(&mut transaction, &stored).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(stored)
    }

    pub async fn materialize_subject_facts(
        &self,
        subject_id: &SubjectId,
        policy_evaluation: &PolicyEvaluation,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<Vec<Fact>, PostgresEncryptedWorkflowReplayError> {
        self.materialize_subject_facts_with_audit(
            subject_id,
            policy_evaluation,
            &FactMaterializationAuditContext::default(),
            key_resolver,
        )
        .await
    }

    pub async fn materialize_subject_facts_with_audit(
        &self,
        subject_id: &SubjectId,
        policy_evaluation: &PolicyEvaluation,
        audit_context: &FactMaterializationAuditContext,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<Vec<Fact>, PostgresEncryptedWorkflowReplayError> {
        let envelopes = self.storage.encrypted_facts_for_subject(subject_id).await?;
        let mut facts = Vec::with_capacity(envelopes.len());
        for envelope in &envelopes {
            facts.push(
                materialize_postgres_encrypted_fact_with_durable_audit(
                    &self.storage,
                    envelope,
                    policy_evaluation,
                    audit_context,
                    key_resolver,
                    &self.encryptor,
                )
                .await?,
            );
        }
        Ok(facts)
    }

    pub async fn replay_identity_state(
        &self,
        subject_id: SubjectId,
        policy_evaluation: &PolicyEvaluation,
        audit_context: &FactMaterializationAuditContext,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<MaterializedIdentityState, PostgresEncryptedWorkflowReplayError> {
        let facts = self
            .materialize_subject_facts_with_audit(
                &subject_id,
                policy_evaluation,
                audit_context,
                key_resolver,
            )
            .await?;
        Ok(materialize_identity_state(subject_id, &facts))
    }
}

#[cfg(feature = "postgres-adapter")]
async fn materialize_postgres_encrypted_fact_with_durable_audit(
    storage: &SqlxPostgresEncryptedFactRepository,
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<Fact, PostgresEncryptedWorkflowReplayError> {
    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::Attempted,
        None,
    )
    .await?;

    if policy_evaluation.decision != AccessDecisionResult::Allowed {
        return fail_postgres_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::PolicyDenied,
        )
        .await;
    }
    if !envelope
        .materialization_policy_refs
        .iter()
        .all(|required| policy_evaluation.policy_refs.contains(required))
    {
        return fail_postgres_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::MaterializationPolicyRefsNotSatisfied,
        )
        .await;
    }

    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::KeyAccessAttempted,
        None,
    )
    .await?;
    let key = match key_resolver.resolve_fact_key(&envelope.encryption.key_id) {
        Ok(key) => key,
        Err(_) => {
            return fail_postgres_materialization(
                storage,
                envelope,
                policy_evaluation,
                audit_context,
                FactMaterializationAuditOutcome::KeyAccessFailed,
                FactMaterializationError::MissingKey,
            )
            .await;
        }
    };
    if key.status != FactKeyStatus::Active {
        return fail_postgres_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::KeyAccessFailed,
            FactMaterializationError::RetiredKey,
        )
        .await;
    }
    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::KeyAccessSucceeded,
        None,
    )
    .await?;

    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::DecryptionAttempted,
        None,
    )
    .await?;
    let associated_data = canonical_encrypted_fact_associated_data(envelope);
    let plaintext = match encryptor.decrypt_fact_plaintext(
        &key,
        &envelope.encryption,
        &associated_data,
        &envelope.ciphertext,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            return fail_postgres_materialization(
                storage,
                envelope,
                policy_evaluation,
                audit_context,
                FactMaterializationAuditOutcome::DecryptionFailed,
                error,
            )
            .await;
        }
    };
    if FactPayloadType::from_payload(&plaintext.payload) != envelope.payload_type {
        return fail_postgres_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::DecryptionFailed,
            FactMaterializationError::AuthenticationFailed,
        )
        .await;
    }

    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::Succeeded,
        None,
    )
    .await?;
    Ok(plaintext.into_fact(envelope))
}

#[cfg(feature = "postgres-adapter")]
async fn fail_postgres_materialization<T>(
    storage: &SqlxPostgresEncryptedFactRepository,
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    outcome: FactMaterializationAuditOutcome,
    error: FactMaterializationError,
) -> Result<T, PostgresEncryptedWorkflowReplayError> {
    record_postgres_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        outcome,
        Some(error),
    )
    .await?;
    Err(PostgresEncryptedWorkflowReplayError::Materialization(error))
}

#[cfg(feature = "postgres-adapter")]
async fn record_postgres_materialization_event(
    storage: &SqlxPostgresEncryptedFactRepository,
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    outcome: FactMaterializationAuditOutcome,
    error: Option<FactMaterializationError>,
) -> Result<(), PostgresAdapterError> {
    storage
        .record_materialization_audit_event(&FactMaterializationAuditEvent {
            subject_id: envelope.subject_id.clone(),
            fact_ids: vec![envelope.fact_id.clone()],
            materialization_policy_refs: envelope.materialization_policy_refs.clone(),
            evaluated_policy_refs: policy_evaluation.policy_refs.clone(),
            caller: audit_context.caller.clone(),
            purpose: audit_context.purpose.clone(),
            requested_at: audit_context.requested_at.clone(),
            outcome,
            error,
        })
        .await
}

#[cfg(feature = "postgres-adapter")]
impl SqlxPostgresEncryptedFactRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, PostgresAdapterError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migration(&self) -> Result<(), PostgresAdapterError> {
        for migration in IDENTITY_POSTGRES_MIGRATIONS {
            sqlx::raw_sql(migration.sql)
                .execute(&self.pool)
                .await
                .map_err(sqlx_error)?;
        }
        Ok(())
    }

    pub async fn append_encrypted_fact(
        &self,
        envelope: &StoredEncryptedFact,
    ) -> Result<(), PostgresAdapterError> {
        let row = PostgresEncryptedFactRow::try_from_envelope(envelope)?;
        let status_payload = row.status_payload_json()?;

        sqlx::query(
            r#"
            INSERT INTO identity_facts (
              append_sequence,
              transaction_id,
              committed_at,
              fact_id,
              subject_id,
              occurred_kind,
              occurred_start,
              occurred_end,
              payload_type,
              status_kind,
              status_payload,
              materialization_policy_refs,
              encryption_algorithm,
              encryption_key_id,
              wrapped_dek_ref,
              nonce,
              aad_version,
              ciphertext
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              CAST($11 AS jsonb), $12, $13, $14, $15, $16, $17, $18
            )
            "#,
        )
        .bind(row.append_sequence)
        .bind(row.transaction_id)
        .bind(row.committed_at)
        .bind(row.fact_id)
        .bind(row.subject_id)
        .bind(row.occurred_kind)
        .bind(row.occurred_start)
        .bind(row.occurred_end)
        .bind(row.payload_type)
        .bind(row.status_kind)
        .bind(status_payload)
        .bind(row.materialization_policy_refs)
        .bind(row.encryption_algorithm)
        .bind(row.encryption_key_id)
        .bind(row.wrapped_dek_ref)
        .bind(row.nonce)
        .bind(row.aad_version)
        .bind(row.ciphertext)
        .execute(&self.pool)
        .await
        .map_err(repository_sqlx_error)?;

        Ok(())
    }

    pub async fn all_encrypted_facts(
        &self,
    ) -> Result<Vec<StoredEncryptedFact>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_ENCRYPTED_FACT_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(envelope_from_pg_row).collect()
    }

    pub async fn encrypted_facts_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredEncryptedFact>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_ENCRYPTED_FACT_COLUMNS_SQL} WHERE subject_id = $1 ORDER BY append_sequence"
        ))
        .bind(&subject_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(envelope_from_pg_row).collect()
    }

    pub async fn record_materialization_audit_event(
        &self,
        event: &FactMaterializationAuditEvent,
    ) -> Result<(), PostgresAdapterError> {
        let row = PostgresMaterializationAuditRow::from_event(event);

        sqlx::query(
            r#"
            INSERT INTO identity_fact_materialization_audit (
              subject_id,
              fact_ids,
              materialization_policy_refs,
              evaluated_policy_refs,
              caller,
              purpose,
              requested_at,
              outcome,
              error
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(row.subject_id)
        .bind(row.fact_ids)
        .bind(row.materialization_policy_refs)
        .bind(row.evaluated_policy_refs)
        .bind(row.caller)
        .bind(row.purpose)
        .bind(row.requested_at)
        .bind(row.outcome)
        .bind(row.error)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;

        Ok(())
    }

    pub async fn append_stored_workflow_slice(
        &self,
        workflow_slice: &StoredIdentityWorkflowSlice,
    ) -> Result<(), PostgresAdapterError> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        insert_stored_workflow_slice_rows(&mut transaction, workflow_slice).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    pub async fn append_stored_episode_composition(
        &self,
        composition: &StoredEpisodeComposition,
    ) -> Result<(), PostgresAdapterError> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        insert_stored_episode_composition_rows(&mut transaction, composition).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    pub async fn all_stored_episodes(
        &self,
    ) -> Result<Vec<StoredProblemEpisode>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_PROBLEM_EPISODE_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(problem_episode_from_pg_row).collect()
    }

    pub async fn stored_episodes_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredProblemEpisode>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_PROBLEM_EPISODE_COLUMNS_SQL} WHERE subject_id = $1 ORDER BY append_sequence"
        ))
        .bind(&subject_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(problem_episode_from_pg_row).collect()
    }

    pub async fn all_stored_memberships(
        &self,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn stored_memberships_for_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} WHERE episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn stored_memberships_for_fact(
        &self,
        fact_id: &FactId,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} WHERE fact_id = $1 ORDER BY append_sequence"
        ))
        .bind(&fact_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn all_stored_episode_relations(
        &self,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }

    pub async fn stored_relations_for_parent_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} WHERE target_episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }

    pub async fn stored_relations_for_child_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} WHERE source_episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresAppAttestKeyStateStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, PostgresAdapterError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn record_verified_app_attest_assertion_async(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
        record_verified_app_attest_assertion_in_postgres(&self.pool, assertion).await
    }

    pub async fn app_attest_key_state_async(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError> {
        let row = sqlx::query(SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL)
            .bind(key_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(app_attest_sqlx_error)?;
        row.map(app_attest_key_state_from_pg_row).transpose()
    }

    pub async fn app_attest_challenge_nonce_seen_async(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError> {
        let seen: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
              SELECT 1
              FROM identity_app_attest_challenge_nonces
              WHERE key_id = $1
                AND challenge_nonce = $2
            )
            "#,
        )
        .bind(key_id)
        .bind(challenge_nonce)
        .fetch_one(&self.pool)
        .await
        .map_err(app_attest_sqlx_error)?;
        Ok(seen)
    }

    pub async fn revoke_app_attest_key_async(
        &self,
        key_id: &str,
    ) -> Result<(), AppAttestAssertionVerificationError> {
        let updated = sqlx::query(
            r#"
            UPDATE identity_app_attest_keys
            SET status = 'revoked'
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .execute(&self.pool)
        .await
        .map_err(app_attest_sqlx_error)?
        .rows_affected();
        if updated == 0 {
            return Err(AppAttestAssertionVerificationError::MissingKeyId);
        }
        Ok(())
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresLivePresenceChallengeStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, PostgresAdapterError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn issue_live_presence_challenge_async(
        &self,
        challenge: &LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        if challenge.challenge_nonce.is_empty() {
            return Err(LivePresenceChallengeError::MissingChallengeNonce);
        }
        let row = PostgresLivePresenceChallengeRow::try_from_challenge(challenge)
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        let status_payload = row
            .status_payload
            .status_payload_json()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        sqlx::query(
            r#"
            INSERT INTO identity_live_presence_challenges (
              challenge_id,
              challenge_nonce,
              intended_workflow,
              expected_subject_id,
              expected_device_ref,
              expected_team_id,
              expected_bundle_id,
              expected_app_id,
              expected_environment,
              issued_at,
              expires_at,
              status_kind,
              status_payload,
              retry_policy_refs,
              manual_review_policy_refs,
              retention_policy_refs
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              $11, $12, CAST($13 AS jsonb), $14, $15, $16
            )
            "#,
        )
        .bind(&row.challenge_id)
        .bind(&row.challenge_nonce)
        .bind(&row.intended_workflow)
        .bind(&row.expected_subject_id)
        .bind(&row.expected_device_ref)
        .bind(&row.expected_team_id)
        .bind(&row.expected_bundle_id)
        .bind(&row.expected_app_id)
        .bind(&row.expected_environment)
        .bind(&row.issued_at)
        .bind(&row.expires_at)
        .bind(&row.status_kind)
        .bind(status_payload)
        .bind(&row.retry_policy_refs)
        .bind(&row.manual_review_policy_refs)
        .bind(&row.retention_policy_refs)
        .execute(&self.pool)
        .await
        .map_err(live_presence_challenge_sqlx_error)?;
        Ok(challenge.clone())
    }

    pub async fn live_presence_challenge_by_nonce_async(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError> {
        let sql =
            format!("{SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL} WHERE challenge_nonce = $1");
        let row = sqlx::query(&sql)
            .bind(challenge_nonce)
            .fetch_optional(&self.pool)
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        row.map(live_presence_challenge_from_pg_row).transpose()
    }

    pub async fn record_live_presence_challenge_status_async(
        &self,
        challenge_nonce: &str,
        status: &LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let challenge =
            locked_live_presence_challenge_by_nonce(&mut transaction, challenge_nonce).await?;
        if !matches!(challenge.status, LivePresenceChallengeStatus::Issued) {
            return Err(LivePresenceChallengeError::ChallengeAlreadyConsumed);
        }
        update_live_presence_challenge_status(&mut transaction, challenge_nonce, status).await?;
        transaction
            .commit()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let mut updated = challenge;
        updated.status = status.clone();
        Ok(updated)
    }

    pub async fn consume_verified_live_presence_challenge_async(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let mut challenge =
            locked_live_presence_challenge_by_nonce(&mut transaction, &ceremony.challenge_nonce)
                .await?;

        if let Err(error) = validate_live_presence_challenge_context(
            &challenge,
            ceremony,
            app_attest,
            subject_id,
            observed_at,
        ) {
            if let Some(status) = postgres_terminal_live_presence_challenge_status_for_error(
                error,
                observed_at.clone(),
            ) {
                update_live_presence_challenge_status(
                    &mut transaction,
                    &ceremony.challenge_nonce,
                    &status,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(live_presence_challenge_sqlx_error)?;
            }
            return Err(error);
        }

        let status =
            terminal_live_presence_challenge_status_for_ceremony(ceremony, observed_at.clone());
        update_live_presence_challenge_status(&mut transaction, &ceremony.challenge_nonce, &status)
            .await?;
        transaction
            .commit()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        challenge.status = status;
        Ok(challenge)
    }
}

#[cfg(feature = "postgres-adapter")]
impl LivePresenceChallengeStore for PostgresLivePresenceChallengeStore {
    fn issue_live_presence_challenge(
        &self,
        challenge: LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        run_live_presence_challenge_store_blocking(move || async move {
            store.issue_live_presence_challenge_async(&challenge).await
        })
    }

    fn live_presence_challenge_by_nonce(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError> {
        let store = self.clone();
        let challenge_nonce = challenge_nonce.to_string();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .live_presence_challenge_by_nonce_async(&challenge_nonce)
                .await
        })
    }

    fn record_live_presence_challenge_status(
        &self,
        challenge_nonce: &str,
        status: LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        let challenge_nonce = challenge_nonce.to_string();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .record_live_presence_challenge_status_async(&challenge_nonce, &status)
                .await
        })
    }

    fn consume_verified_live_presence_challenge(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        let ceremony = ceremony.clone();
        let app_attest = app_attest.clone();
        let subject_id = subject_id.clone();
        let observed_at = observed_at.clone();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .consume_verified_live_presence_challenge_async(
                    &ceremony,
                    &app_attest,
                    &subject_id,
                    &observed_at,
                )
                .await
        })
    }
}

#[cfg(feature = "postgres-adapter")]
impl AppAttestKeyStateStore for PostgresAppAttestKeyStateStore {
    fn record_verified_app_attest_assertion(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let assertion = assertion.clone();
        run_app_attest_store_blocking(move || async move {
            store
                .record_verified_app_attest_assertion_async(&assertion)
                .await
        })
    }

    fn app_attest_key_state(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let key_id = key_id.to_string();
        run_app_attest_store_blocking(move || async move {
            store.app_attest_key_state_async(&key_id).await
        })
    }

    fn app_attest_challenge_nonce_seen(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let key_id = key_id.to_string();
        let challenge_nonce = challenge_nonce.to_string();
        run_app_attest_store_blocking(move || async move {
            store
                .app_attest_challenge_nonce_seen_async(&key_id, &challenge_nonce)
                .await
        })
    }
}

impl PostgresEncryptedFactRow {
    pub fn try_from_envelope(envelope: &StoredEncryptedFact) -> Result<Self, PostgresAdapterError> {
        let append_sequence = i64::try_from(envelope.append_sequence)
            .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)?;
        let occurred_at = PostgresTemporalAnchorRecord::from_temporal_anchor(&envelope.occurred_at);
        let (status_kind, status_payload) = postgres_fact_status_parts(&envelope.status);

        Ok(Self {
            append_sequence,
            transaction_id: envelope.transaction_id.0.clone(),
            committed_at: envelope.committed_at.0.clone(),
            fact_id: envelope.fact_id.0.clone(),
            subject_id: envelope.subject_id.0.clone(),
            occurred_kind: occurred_at.kind,
            occurred_start: occurred_at.start,
            occurred_end: occurred_at.end,
            payload_type: envelope.payload_type.as_str().to_string(),
            status_kind: status_kind.to_string(),
            status_payload,
            materialization_policy_refs: envelope
                .materialization_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
            encryption_algorithm: envelope.encryption.algorithm.as_str().to_string(),
            encryption_key_id: envelope.encryption.key_id.clone(),
            wrapped_dek_ref: envelope.encryption.wrapped_dek_ref.clone(),
            nonce: envelope.encryption.nonce.clone(),
            aad_version: envelope.encryption.aad_version.as_str().to_string(),
            ciphertext: envelope.ciphertext.clone(),
        })
    }

    pub fn try_into_envelope(self) -> Result<StoredEncryptedFact, PostgresAdapterError> {
        if self.append_sequence < 0 {
            return Err(PostgresAdapterError::NegativeAppendSequence);
        }

        Ok(StoredEncryptedFact {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: Id(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            fact_id: Id(self.fact_id),
            subject_id: Id(self.subject_id),
            occurred_at: PostgresTemporalAnchorRecord {
                kind: self.occurred_kind,
                start: self.occurred_start,
                end: self.occurred_end,
            }
            .try_into_temporal_anchor()?,
            payload_type: FactPayloadType::from_str_label(&self.payload_type).ok_or_else(|| {
                PostgresAdapterError::UnknownPayloadType(self.payload_type.clone())
            })?,
            status: fact_status_from_postgres(&self.status_kind, self.status_payload)?,
            materialization_policy_refs: self
                .materialization_policy_refs
                .into_iter()
                .map(Id)
                .collect(),
            encryption: FactEncryptionMetadata {
                algorithm: FactEncryptionAlgorithm::from_str_label(&self.encryption_algorithm)
                    .ok_or_else(|| {
                        PostgresAdapterError::UnknownEncryptionAlgorithm(
                            self.encryption_algorithm.clone(),
                        )
                    })?,
                key_id: self.encryption_key_id,
                wrapped_dek_ref: self.wrapped_dek_ref,
                nonce: self.nonce,
                aad_version: EncryptedFactAssociatedDataVersion::from_str_label(&self.aad_version)
                    .ok_or_else(|| {
                        PostgresAdapterError::UnknownAssociatedDataVersion(self.aad_version.clone())
                    })?,
            },
            ciphertext: self.ciphertext,
        })
    }

    pub fn sort_for_replay(rows: &mut [Self]) {
        rows.sort_by_key(|row| row.append_sequence);
    }
}

#[cfg(feature = "postgres-adapter")]
const SELECT_ENCRYPTED_FACT_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  fact_id,
  subject_id,
  occurred_kind,
  occurred_start,
  occurred_end,
  payload_type,
  status_kind,
  status_payload::text AS status_payload,
  materialization_policy_refs,
  encryption_algorithm,
  encryption_key_id,
  wrapped_dek_ref,
  nonce,
  aad_version,
  ciphertext
FROM identity_facts
"#;

#[cfg(feature = "postgres-adapter")]
fn envelope_from_pg_row(row: PgRow) -> Result<StoredEncryptedFact, PostgresAdapterError> {
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    PostgresEncryptedFactRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        fact_id: row.try_get("fact_id").map_err(sqlx_error)?,
        subject_id: row.try_get("subject_id").map_err(sqlx_error)?,
        occurred_kind: row.try_get("occurred_kind").map_err(sqlx_error)?,
        occurred_start: row.try_get("occurred_start").map_err(sqlx_error)?,
        occurred_end: row.try_get("occurred_end").map_err(sqlx_error)?,
        payload_type: row.try_get("payload_type").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresFactStatusPayload::from_json(&status_payload_json)?,
        materialization_policy_refs: row
            .try_get("materialization_policy_refs")
            .map_err(sqlx_error)?,
        encryption_algorithm: row.try_get("encryption_algorithm").map_err(sqlx_error)?,
        encryption_key_id: row.try_get("encryption_key_id").map_err(sqlx_error)?,
        wrapped_dek_ref: row.try_get("wrapped_dek_ref").map_err(sqlx_error)?,
        nonce: row.try_get("nonce").map_err(sqlx_error)?,
        aad_version: row.try_get("aad_version").map_err(sqlx_error)?,
        ciphertext: row.try_get("ciphertext").map_err(sqlx_error)?,
    }
    .try_into_envelope()
}

#[cfg(feature = "postgres-adapter")]
fn live_presence_challenge_from_pg_row(
    row: PgRow,
) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
    let status_payload_json: String = row
        .try_get("status_payload")
        .map_err(live_presence_challenge_sqlx_error)?;
    PostgresLivePresenceChallengeRow {
        challenge_id: row
            .try_get("challenge_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        challenge_nonce: row
            .try_get("challenge_nonce")
            .map_err(live_presence_challenge_sqlx_error)?,
        intended_workflow: row
            .try_get("intended_workflow")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_subject_id: row
            .try_get("expected_subject_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_device_ref: row
            .try_get("expected_device_ref")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_team_id: row
            .try_get("expected_team_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_bundle_id: row
            .try_get("expected_bundle_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_app_id: row
            .try_get("expected_app_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_environment: row
            .try_get("expected_environment")
            .map_err(live_presence_challenge_sqlx_error)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(live_presence_challenge_sqlx_error)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(live_presence_challenge_sqlx_error)?,
        status_kind: row
            .try_get("status_kind")
            .map_err(live_presence_challenge_sqlx_error)?,
        status_payload: PostgresLivePresenceChallengeStatusPayload::from_json(&status_payload_json)
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?,
        retry_policy_refs: row
            .try_get("retry_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
        manual_review_policy_refs: row
            .try_get("manual_review_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
        retention_policy_refs: row
            .try_get("retention_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
    }
    .try_into_challenge()
    .map_err(|_| LivePresenceChallengeError::StorageUnavailable)
}

#[cfg(feature = "postgres-adapter")]
const SELECT_PROBLEM_EPISODE_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  episode_id,
  subject_id,
  episode_kind,
  label,
  problem_code::text AS problem_code,
  status_kind,
  status_payload::text AS status_payload,
  onset::text AS onset,
  authored_by::text AS authored_by,
  authored_at,
  notes
FROM identity_episodes
"#;

#[cfg(feature = "postgres-adapter")]
const SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  membership_id,
  fact_id,
  episode_id,
  role,
  asserted_by::text AS asserted_by,
  asserted_kind,
  asserted_start,
  asserted_end,
  status_kind,
  status_payload::text AS status_payload
FROM identity_episode_memberships
"#;

#[cfg(feature = "postgres-adapter")]
const SELECT_EPISODE_RELATION_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  relation_id,
  source_episode_id,
  target_episode_id,
  relation_type,
  asserted_by::text AS asserted_by,
  asserted_kind,
  asserted_start,
  asserted_end,
  status_kind,
  status_payload::text AS status_payload
FROM identity_episode_relations
"#;

#[cfg(feature = "postgres-adapter")]
const SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL: &str = r#"
SELECT
  key_id,
  team_id,
  bundle_id,
  app_id,
  environment,
  device_ref,
  status,
  registered_at,
  last_asserted_at,
  last_sign_count,
  last_challenge_nonce
FROM identity_app_attest_keys
WHERE key_id = $1
"#;

#[cfg(feature = "postgres-adapter")]
const SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL: &str = r#"
SELECT
  challenge_id,
  challenge_nonce,
  intended_workflow,
  expected_subject_id,
  expected_device_ref,
  expected_team_id,
  expected_bundle_id,
  expected_app_id,
  expected_environment,
  issued_at,
  expires_at,
  status_kind,
  status_payload::text AS status_payload,
  retry_policy_refs,
  manual_review_policy_refs,
  retention_policy_refs
FROM identity_live_presence_challenges
"#;

#[cfg(feature = "postgres-adapter")]
async fn insert_stored_workflow_slice_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workflow_slice: &StoredIdentityWorkflowSlice,
) -> Result<(), PostgresAdapterError> {
    insert_workflow_transaction_row(
        transaction,
        &PostgresWorkflowTransactionRow::workflow_slice(
            &workflow_slice.transaction_id,
            &workflow_slice.committed_at,
        ),
    )
    .await?;
    insert_problem_episode_row(
        transaction,
        &PostgresProblemEpisodeRow::try_from_stored(&workflow_slice.episode)?,
    )
    .await?;
    for envelope in &workflow_slice.encrypted_facts {
        insert_encrypted_fact_row(
            transaction,
            &PostgresEncryptedFactRow::try_from_envelope(envelope)?,
        )
        .await?;
    }
    for membership in &workflow_slice.memberships {
        insert_episode_membership_row(
            transaction,
            &PostgresEpisodeMembershipRow::try_from_stored(membership)?,
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_stored_episode_composition_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    composition: &StoredEpisodeComposition,
) -> Result<(), PostgresAdapterError> {
    insert_workflow_transaction_row(
        transaction,
        &PostgresWorkflowTransactionRow::episode_composition(
            &composition.transaction_id,
            &composition.committed_at,
        ),
    )
    .await?;
    insert_problem_episode_row(
        transaction,
        &PostgresProblemEpisodeRow::try_from_stored(&composition.parent_episode)?,
    )
    .await?;
    for child_slice in &composition.child_slices {
        insert_problem_episode_row(
            transaction,
            &PostgresProblemEpisodeRow::try_from_stored(&child_slice.episode)?,
        )
        .await?;
        for envelope in &child_slice.encrypted_facts {
            insert_encrypted_fact_row(
                transaction,
                &PostgresEncryptedFactRow::try_from_envelope(envelope)?,
            )
            .await?;
        }
        for membership in &child_slice.memberships {
            insert_episode_membership_row(
                transaction,
                &PostgresEpisodeMembershipRow::try_from_stored(membership)?,
            )
            .await?;
        }
    }
    for relation in &composition.episode_relations {
        insert_episode_relation_row(
            transaction,
            &PostgresEpisodeRelationRow::try_from_stored(relation)?,
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn acquire_workflow_sequence_lock(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PostgresAdapterError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(IDENTITY_WORKFLOW_SEQUENCE_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn next_workflow_sequence_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<EncryptedWorkflowAppendSequenceState, PostgresAdapterError> {
    Ok(
        EncryptedWorkflowAppendSequenceState::with_relation_append_sequence(
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_facts",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episodes",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_memberships",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_relations",
            )
            .await?,
        ),
    )
}

#[cfg(feature = "postgres-adapter")]
async fn next_append_sequence_from_sql(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sql: &str,
) -> Result<AppendSequence, PostgresAdapterError> {
    let next_sequence: i64 = sqlx::query_scalar(sql)
        .fetch_one(&mut **transaction)
        .await
        .map_err(sqlx_error)?;
    if next_sequence < 0 {
        return Err(PostgresAdapterError::NegativeAppendSequence);
    }
    AppendSequence::try_from(next_sequence)
        .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)
}

#[cfg(feature = "postgres-adapter")]
async fn insert_workflow_transaction_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresWorkflowTransactionRow,
) -> Result<(), PostgresAdapterError> {
    sqlx::query(
        r#"
        INSERT INTO identity_workflow_transactions (
          transaction_id,
          transaction_kind,
          committed_at
        )
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&row.transaction_id)
    .bind(&row.transaction_kind)
    .bind(&row.committed_at)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_encrypted_fact_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEncryptedFactRow,
) -> Result<(), PostgresAdapterError> {
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_facts (
          append_sequence,
          transaction_id,
          committed_at,
          fact_id,
          subject_id,
          occurred_kind,
          occurred_start,
          occurred_end,
          payload_type,
          status_kind,
          status_payload,
          materialization_policy_refs,
          encryption_algorithm,
          encryption_key_id,
          wrapped_dek_ref,
          nonce,
          aad_version,
          ciphertext
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
          CAST($11 AS jsonb), $12, $13, $14, $15, $16, $17, $18
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.fact_id)
    .bind(&row.subject_id)
    .bind(&row.occurred_kind)
    .bind(&row.occurred_start)
    .bind(&row.occurred_end)
    .bind(&row.payload_type)
    .bind(&row.status_kind)
    .bind(status_payload)
    .bind(&row.materialization_policy_refs)
    .bind(&row.encryption_algorithm)
    .bind(&row.encryption_key_id)
    .bind(&row.wrapped_dek_ref)
    .bind(&row.nonce)
    .bind(&row.aad_version)
    .bind(&row.ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_problem_episode_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresProblemEpisodeRow,
) -> Result<(), PostgresAdapterError> {
    let problem_code = row.problem_code_json()?;
    let status_payload = row.status_payload_json()?;
    let onset = row.onset_json()?;
    let authored_by = row.authored_by_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episodes (
          append_sequence,
          transaction_id,
          committed_at,
          episode_id,
          subject_id,
          episode_kind,
          label,
          problem_code,
          status_kind,
          status_payload,
          onset,
          authored_by,
          authored_at,
          notes
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          CAST($10 AS jsonb), CAST($11 AS jsonb), CAST($12 AS jsonb), $13, $14
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.episode_id)
    .bind(&row.subject_id)
    .bind(&row.episode_kind)
    .bind(&row.label)
    .bind(problem_code)
    .bind(&row.status_kind)
    .bind(status_payload)
    .bind(onset)
    .bind(authored_by)
    .bind(&row.authored_at)
    .bind(&row.notes)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_episode_membership_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEpisodeMembershipRow,
) -> Result<(), PostgresAdapterError> {
    let asserted_by = row.asserted_by_json()?;
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episode_memberships (
          append_sequence,
          transaction_id,
          committed_at,
          membership_id,
          fact_id,
          episode_id,
          role,
          asserted_by,
          asserted_kind,
          asserted_start,
          asserted_end,
          status_kind,
          status_payload
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          $10, $11, $12, CAST($13 AS jsonb)
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.membership_id)
    .bind(&row.fact_id)
    .bind(&row.episode_id)
    .bind(&row.role)
    .bind(asserted_by)
    .bind(&row.asserted_kind)
    .bind(&row.asserted_start)
    .bind(&row.asserted_end)
    .bind(&row.status_kind)
    .bind(status_payload)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_episode_relation_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEpisodeRelationRow,
) -> Result<(), PostgresAdapterError> {
    let asserted_by = row.asserted_by_json()?;
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episode_relations (
          append_sequence,
          transaction_id,
          committed_at,
          relation_id,
          source_episode_id,
          target_episode_id,
          relation_type,
          asserted_by,
          asserted_kind,
          asserted_start,
          asserted_end,
          status_kind,
          status_payload
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          $10, $11, $12, CAST($13 AS jsonb)
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.relation_id)
    .bind(&row.source_episode_id)
    .bind(&row.target_episode_id)
    .bind(&row.relation_type)
    .bind(asserted_by)
    .bind(&row.asserted_kind)
    .bind(&row.asserted_start)
    .bind(&row.asserted_end)
    .bind(&row.status_kind)
    .bind(status_payload)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn locked_live_presence_challenge_by_nonce(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_nonce: &str,
) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
    let sql = format!(
        "{SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL} WHERE challenge_nonce = $1 FOR UPDATE"
    );
    let row = sqlx::query(&sql)
        .bind(challenge_nonce)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(live_presence_challenge_sqlx_error)?;
    row.map(live_presence_challenge_from_pg_row)
        .transpose()?
        .ok_or(LivePresenceChallengeError::UnknownChallenge)
}

#[cfg(feature = "postgres-adapter")]
async fn update_live_presence_challenge_status(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_nonce: &str,
    status: &LivePresenceChallengeStatus,
) -> Result<(), LivePresenceChallengeError> {
    let (status_kind, status_payload) = postgres_live_presence_challenge_status_parts(status);
    let status_payload = status_payload
        .status_payload_json()
        .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
    let updated = sqlx::query(
        r#"
        UPDATE identity_live_presence_challenges
        SET status_kind = $1,
            status_payload = CAST($2 AS jsonb)
        WHERE challenge_nonce = $3
        "#,
    )
    .bind(status_kind)
    .bind(status_payload)
    .bind(challenge_nonce)
    .execute(&mut **transaction)
    .await
    .map_err(live_presence_challenge_sqlx_error)?
    .rows_affected();
    if updated == 0 {
        return Err(LivePresenceChallengeError::UnknownChallenge);
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
fn problem_episode_from_pg_row(row: PgRow) -> Result<StoredProblemEpisode, PostgresAdapterError> {
    let problem_code_json: Option<String> = row.try_get("problem_code").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    let onset_json: Option<String> = row.try_get("onset").map_err(sqlx_error)?;
    let authored_by_json: String = row.try_get("authored_by").map_err(sqlx_error)?;
    PostgresProblemEpisodeRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        episode_id: row.try_get("episode_id").map_err(sqlx_error)?,
        subject_id: row.try_get("subject_id").map_err(sqlx_error)?,
        episode_kind: row.try_get("episode_kind").map_err(sqlx_error)?,
        label: row.try_get("label").map_err(sqlx_error)?,
        problem_code: problem_code_json
            .as_deref()
            .map(PostgresCodedValueRecord::from_json)
            .transpose()?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresEpisodeStatusPayload::from_json(&status_payload_json)?,
        onset: onset_json
            .as_deref()
            .map(PostgresApproximateDateRecord::from_json)
            .transpose()?,
        authored_by: PostgresAuthorRecord::from_json(&authored_by_json)?,
        authored_at: row.try_get("authored_at").map_err(sqlx_error)?,
        notes: row.try_get("notes").map_err(sqlx_error)?,
    }
    .try_into_stored()
}

#[cfg(feature = "postgres-adapter")]
fn episode_membership_from_pg_row(
    row: PgRow,
) -> Result<StoredEpisodeMembership, PostgresAdapterError> {
    let asserted_by_json: String = row.try_get("asserted_by").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    PostgresEpisodeMembershipRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        membership_id: row.try_get("membership_id").map_err(sqlx_error)?,
        fact_id: row.try_get("fact_id").map_err(sqlx_error)?,
        episode_id: row.try_get("episode_id").map_err(sqlx_error)?,
        role: row.try_get("role").map_err(sqlx_error)?,
        asserted_by: PostgresAuthorRecord::from_json(&asserted_by_json)?,
        asserted_kind: row.try_get("asserted_kind").map_err(sqlx_error)?,
        asserted_start: row.try_get("asserted_start").map_err(sqlx_error)?,
        asserted_end: row.try_get("asserted_end").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresMembershipStatusPayload::from_json(&status_payload_json)?,
    }
    .try_into_stored()
}

#[cfg(feature = "postgres-adapter")]
fn episode_relation_from_pg_row(row: PgRow) -> Result<StoredEpisodeRelation, PostgresAdapterError> {
    let asserted_by_json: String = row.try_get("asserted_by").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    PostgresEpisodeRelationRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        relation_id: row.try_get("relation_id").map_err(sqlx_error)?,
        source_episode_id: row.try_get("source_episode_id").map_err(sqlx_error)?,
        target_episode_id: row.try_get("target_episode_id").map_err(sqlx_error)?,
        relation_type: row.try_get("relation_type").map_err(sqlx_error)?,
        asserted_by: PostgresAuthorRecord::from_json(&asserted_by_json)?,
        asserted_kind: row.try_get("asserted_kind").map_err(sqlx_error)?,
        asserted_start: row.try_get("asserted_start").map_err(sqlx_error)?,
        asserted_end: row.try_get("asserted_end").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresEpisodeRelationStatusPayload::from_json(&status_payload_json)?,
    }
    .try_into_stored()
}

#[cfg(feature = "postgres-adapter")]
fn app_attest_key_state_from_pg_row(
    row: PgRow,
) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
    PostgresAppAttestKeyStateRow {
        key_id: row
            .try_get("key_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        team_id: row
            .try_get("team_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        bundle_id: row
            .try_get("bundle_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        app_id: row
            .try_get("app_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        environment: row
            .try_get("environment")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        device_ref: row
            .try_get("device_ref")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        status: row
            .try_get("status")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        registered_at: row
            .try_get("registered_at")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_asserted_at: row
            .try_get("last_asserted_at")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_sign_count: row
            .try_get("last_sign_count")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_challenge_nonce: row
            .try_get("last_challenge_nonce")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
    }
    .try_into_key_state()
    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)
}

#[cfg(feature = "postgres-adapter")]
async fn record_verified_app_attest_assertion_in_postgres(
    pool: &PgPool,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
    let mut transaction = pool.begin().await.map_err(app_attest_sqlx_error)?;
    let existing = sqlx::query(&format!(
        "{SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL} FOR UPDATE"
    ))
    .bind(&assertion.key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(app_attest_sqlx_error)?
    .map(app_attest_key_state_from_pg_row)
    .transpose()?;
    let nonce_seen: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
          SELECT 1
          FROM identity_app_attest_challenge_nonces
          WHERE key_id = $1
            AND challenge_nonce = $2
        )
        "#,
    )
    .bind(&assertion.key_id)
    .bind(&assertion.challenge_nonce)
    .fetch_one(&mut *transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    if nonce_seen {
        return Err(AppAttestAssertionVerificationError::ChallengeReplay);
    }

    let updated = match existing {
        Some(mut state) => {
            validate_app_attest_key_state_transition(&state, assertion)?;
            insert_app_attest_challenge_nonce(&mut transaction, assertion).await?;
            state.last_sign_count = assertion.sign_count;
            state.last_asserted_at = assertion.asserted_at.clone();
            state.last_challenge_nonce = Some(assertion.challenge_nonce.clone());
            update_app_attest_key_state_row(
                &mut transaction,
                &PostgresAppAttestKeyStateRow::try_from_key_state(&state)
                    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
            )
            .await?;
            state
        }
        None => {
            let state = AppAttestKeyState::active_from_assertion(assertion);
            insert_app_attest_key_state_row(
                &mut transaction,
                &PostgresAppAttestKeyStateRow::try_from_key_state(&state)
                    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
            )
            .await?;
            insert_app_attest_challenge_nonce(&mut transaction, assertion).await?;
            state
        }
    };

    transaction.commit().await.map_err(app_attest_sqlx_error)?;
    Ok(updated)
}

#[cfg(feature = "postgres-adapter")]
fn validate_app_attest_key_state_transition(
    state: &AppAttestKeyState,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<(), AppAttestAssertionVerificationError> {
    if state.status == AppAttestKeyStateStatus::Revoked {
        return Err(AppAttestAssertionVerificationError::KeyRevoked);
    }
    if !state.matches_assertion_context(assertion) {
        return Err(AppAttestAssertionVerificationError::KeyContextMismatch);
    }
    if assertion.sign_count <= state.last_sign_count {
        return Err(AppAttestAssertionVerificationError::SignCountNotAdvanced);
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_app_attest_key_state_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresAppAttestKeyStateRow,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        INSERT INTO identity_app_attest_keys (
          key_id,
          team_id,
          bundle_id,
          app_id,
          environment,
          device_ref,
          status,
          registered_at,
          last_asserted_at,
          last_sign_count,
          last_challenge_nonce
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(&row.key_id)
    .bind(&row.team_id)
    .bind(&row.bundle_id)
    .bind(&row.app_id)
    .bind(&row.environment)
    .bind(&row.device_ref)
    .bind(&row.status)
    .bind(&row.registered_at)
    .bind(&row.last_asserted_at)
    .bind(row.last_sign_count)
    .bind(&row.last_challenge_nonce)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn update_app_attest_key_state_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresAppAttestKeyStateRow,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        UPDATE identity_app_attest_keys
        SET last_asserted_at = $2,
            last_sign_count = $3,
            last_challenge_nonce = $4,
            status = $5
        WHERE key_id = $1
        "#,
    )
    .bind(&row.key_id)
    .bind(&row.last_asserted_at)
    .bind(row.last_sign_count)
    .bind(&row.last_challenge_nonce)
    .bind(&row.status)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
async fn insert_app_attest_challenge_nonce(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        INSERT INTO identity_app_attest_challenge_nonces (
          key_id,
          challenge_nonce,
          first_seen_at
        )
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&assertion.key_id)
    .bind(&assertion.challenge_nonce)
    .bind(&assertion.asserted_at.0)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
impl PostgresFactStatusPayload {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEncryptedFactRow {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresCodedValueRecord {
    fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresApproximateDateRecord {
    fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresAuthorRecord {
    fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeStatusPayload {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresMembershipStatusPayload {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeRelationStatusPayload {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresLivePresenceChallengeStatusPayload {
    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresProblemEpisodeRow {
    fn problem_code_json(&self) -> Result<Option<String>, PostgresAdapterError> {
        self.problem_code
            .as_ref()
            .map(PostgresCodedValueRecord::to_json)
            .transpose()
    }

    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }

    fn onset_json(&self) -> Result<Option<String>, PostgresAdapterError> {
        self.onset
            .as_ref()
            .map(PostgresApproximateDateRecord::to_json)
            .transpose()
    }

    fn authored_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.authored_by.to_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeMembershipRow {
    fn asserted_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.asserted_by.to_json()
    }

    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeRelationRow {
    fn asserted_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.asserted_by.to_json()
    }

    fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }
}

#[cfg(feature = "postgres-adapter")]
fn sqlx_error(error: sqlx::Error) -> PostgresAdapterError {
    PostgresAdapterError::Sqlx(error.to_string())
}

#[cfg(feature = "postgres-adapter")]
fn repository_sqlx_error(error: sqlx::Error) -> PostgresAdapterError {
    if let sqlx::Error::Database(database_error) = &error {
        match database_error.constraint() {
            Some("identity_facts_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateFactId)
            }
            Some("identity_facts_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episodes_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateEpisodeId)
            }
            Some("identity_episodes_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episode_memberships_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateMembershipId)
            }
            Some("identity_episode_memberships_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            Some("identity_episode_relations_pkey") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateRelationId)
            }
            Some("identity_episode_relations_append_sequence_key") => {
                return PostgresAdapterError::Repository(RepositoryError::DuplicateAppendSequence);
            }
            _ => {}
        }
    }
    sqlx_error(error)
}

#[cfg(feature = "postgres-adapter")]
fn app_attest_sqlx_error(error: sqlx::Error) -> AppAttestAssertionVerificationError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.constraint() == Some("identity_app_attest_challenge_nonces_pkey") {
            return AppAttestAssertionVerificationError::ChallengeReplay;
        }
    }
    AppAttestAssertionVerificationError::KeyStateUnavailable
}

#[cfg(feature = "postgres-adapter")]
fn live_presence_challenge_sqlx_error(error: sqlx::Error) -> LivePresenceChallengeError {
    if let sqlx::Error::Database(database_error) = &error {
        match database_error.constraint() {
            Some("identity_live_presence_challenges_pkey") => {
                return LivePresenceChallengeError::DuplicateChallengeId
            }
            Some("identity_live_presence_challenges_challenge_nonce_key") => {
                return LivePresenceChallengeError::DuplicateChallengeNonce
            }
            _ => {}
        }
    }
    LivePresenceChallengeError::StorageUnavailable
}

#[cfg(feature = "postgres-adapter")]
fn run_app_attest_store_blocking<T, F, Fut>(
    operation: F,
) -> Result<T, AppAttestAssertionVerificationError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, AppAttestAssertionVerificationError>> + Send + 'static,
{
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        runtime.block_on(operation())
    });
    handle.join().unwrap_or(Err(
        AppAttestAssertionVerificationError::KeyStateUnavailable,
    ))
}

#[cfg(feature = "postgres-adapter")]
fn run_live_presence_challenge_store_blocking<T, F, Fut>(
    operation: F,
) -> Result<T, LivePresenceChallengeError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, LivePresenceChallengeError>> + Send + 'static,
{
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        runtime.block_on(operation())
    });
    handle
        .join()
        .unwrap_or(Err(LivePresenceChallengeError::StorageUnavailable))
}

#[cfg(feature = "postgres-adapter")]
fn postgres_terminal_live_presence_challenge_status_for_error(
    error: LivePresenceChallengeError,
    observed_at: Timestamp,
) -> Option<LivePresenceChallengeStatus> {
    match error {
        LivePresenceChallengeError::ChallengeExpired => {
            Some(LivePresenceChallengeStatus::Expired {
                expired_at: observed_at,
            })
        }
        LivePresenceChallengeError::ChallengeNonceMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::ChallengeMismatch,
                provider_event_id: None,
            })
        }
        LivePresenceChallengeError::SubjectMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::SubjectMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::DeviceMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::DeviceMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::AppContextMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::AppContextMismatch,
                provider_event_id: None,
            })
        }
        _ => None,
    }
}

impl PostgresMaterializationAuditRow {
    pub fn from_event(event: &FactMaterializationAuditEvent) -> Self {
        Self {
            subject_id: event.subject_id.0.clone(),
            fact_ids: event
                .fact_ids
                .iter()
                .map(|fact_id| fact_id.0.clone())
                .collect(),
            materialization_policy_refs: event
                .materialization_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
            evaluated_policy_refs: event
                .evaluated_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
            caller: event.caller.clone(),
            purpose: event.purpose.clone(),
            requested_at: event
                .requested_at
                .as_ref()
                .map(|timestamp| timestamp.0.clone()),
            outcome: postgres_audit_outcome(event.outcome).to_string(),
            error: event
                .error
                .map(|error| postgres_materialization_error(error).to_string()),
        }
    }

    pub fn try_into_event(self) -> Result<FactMaterializationAuditEvent, PostgresAdapterError> {
        Ok(FactMaterializationAuditEvent {
            subject_id: Id(self.subject_id),
            fact_ids: self.fact_ids.into_iter().map(Id).collect(),
            materialization_policy_refs: self
                .materialization_policy_refs
                .into_iter()
                .map(Id)
                .collect(),
            evaluated_policy_refs: self.evaluated_policy_refs.into_iter().map(Id).collect(),
            caller: self.caller,
            purpose: self.purpose,
            requested_at: self.requested_at.map(Timestamp),
            outcome: audit_outcome_from_postgres(&self.outcome)?,
            error: self
                .error
                .as_deref()
                .map(materialization_error_from_postgres)
                .transpose()?,
        })
    }
}

impl PostgresAppAttestKeyStateRow {
    pub fn try_from_key_state(state: &AppAttestKeyState) -> Result<Self, PostgresAdapterError> {
        let last_sign_count = i64::try_from(state.last_sign_count)
            .map_err(|_| PostgresAdapterError::AppAttestSignCountOutOfRange)?;
        Ok(Self {
            key_id: state.key_id.clone(),
            team_id: state.team_id.clone(),
            bundle_id: state.bundle_id.clone(),
            app_id: state.app_id.clone(),
            environment: postgres_app_attest_environment(state.environment).to_string(),
            device_ref: state.device_ref.clone(),
            status: postgres_app_attest_key_status(state.status).to_string(),
            registered_at: state.registered_at.0.clone(),
            last_asserted_at: state.last_asserted_at.0.clone(),
            last_sign_count,
            last_challenge_nonce: state.last_challenge_nonce.clone(),
        })
    }

    pub fn try_into_key_state(self) -> Result<AppAttestKeyState, PostgresAdapterError> {
        if self.last_sign_count < 0 {
            return Err(PostgresAdapterError::AppAttestSignCountOutOfRange);
        }
        Ok(AppAttestKeyState {
            key_id: self.key_id,
            team_id: self.team_id,
            bundle_id: self.bundle_id,
            app_id: self.app_id,
            environment: app_attest_environment_from_postgres(&self.environment)?,
            device_ref: self.device_ref,
            status: app_attest_key_status_from_postgres(&self.status)?,
            registered_at: Timestamp(self.registered_at),
            last_asserted_at: Timestamp(self.last_asserted_at),
            last_sign_count: self.last_sign_count as u64,
            last_challenge_nonce: self.last_challenge_nonce,
        })
    }
}

impl PostgresLivePresenceChallengeRow {
    pub fn try_from_challenge(
        challenge: &LivePresenceChallenge,
    ) -> Result<Self, PostgresAdapterError> {
        let expected_app = challenge.expected_app.as_ref();
        let (status_kind, status_payload) =
            postgres_live_presence_challenge_status_parts(&challenge.status);
        Ok(Self {
            challenge_id: challenge.challenge_id.0.clone(),
            challenge_nonce: challenge.challenge_nonce.clone(),
            intended_workflow: postgres_live_presence_challenge_workflow(
                challenge.intended_workflow,
            )
            .to_string(),
            expected_subject_id: challenge
                .expected_subject_id
                .as_ref()
                .map(|subject_id| subject_id.0.clone()),
            expected_device_ref: challenge.expected_device_ref.clone(),
            expected_team_id: expected_app.map(|app| app.team_id.clone()),
            expected_bundle_id: expected_app.map(|app| app.bundle_id.clone()),
            expected_app_id: expected_app.map(|app| app.app_id.clone()),
            expected_environment: expected_app
                .map(|app| postgres_app_attest_environment(app.environment).to_string()),
            issued_at: challenge.issued_at.0.clone(),
            expires_at: challenge.expires_at.0.clone(),
            status_kind: status_kind.to_string(),
            status_payload,
            retry_policy_refs: challenge
                .retry_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
            manual_review_policy_refs: challenge
                .manual_review_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
            retention_policy_refs: challenge
                .retention_policy_refs
                .iter()
                .map(|policy_ref| policy_ref.0.clone())
                .collect(),
        })
    }

    pub fn try_into_challenge(self) -> Result<LivePresenceChallenge, PostgresAdapterError> {
        let expected_app = match (
            self.expected_team_id,
            self.expected_bundle_id,
            self.expected_app_id,
            self.expected_environment,
        ) {
            (None, None, None, None) => None,
            (Some(team_id), Some(bundle_id), Some(app_id), Some(environment)) => {
                Some(LivePresenceExpectedAppContext {
                    team_id,
                    bundle_id,
                    app_id,
                    environment: app_attest_environment_from_postgres(&environment)?,
                })
            }
            _ => return Err(PostgresAdapterError::InvalidLivePresenceChallengeStatusPayload),
        };

        Ok(LivePresenceChallenge {
            challenge_id: Id(self.challenge_id),
            challenge_nonce: self.challenge_nonce,
            intended_workflow: live_presence_challenge_workflow_from_postgres(
                &self.intended_workflow,
            )?,
            expected_subject_id: self.expected_subject_id.map(Id),
            expected_device_ref: self.expected_device_ref,
            expected_app,
            issued_at: Timestamp(self.issued_at),
            expires_at: Timestamp(self.expires_at),
            status: live_presence_challenge_status_from_postgres(
                &self.status_kind,
                self.status_payload,
            )?,
            retry_policy_refs: self.retry_policy_refs.into_iter().map(Id).collect(),
            manual_review_policy_refs: self.manual_review_policy_refs.into_iter().map(Id).collect(),
            retention_policy_refs: self.retention_policy_refs.into_iter().map(Id).collect(),
        })
    }
}

impl PostgresWorkflowTransactionRow {
    pub fn new(
        transaction_id: &PersistenceTransactionId,
        transaction_kind: PostgresWorkflowTransactionKind,
        committed_at: &Timestamp,
    ) -> Self {
        Self {
            transaction_id: transaction_id.0.clone(),
            transaction_kind: postgres_workflow_transaction_kind(transaction_kind).to_string(),
            committed_at: committed_at.0.clone(),
        }
    }

    pub fn workflow_slice(
        transaction_id: &PersistenceTransactionId,
        committed_at: &Timestamp,
    ) -> Self {
        Self::new(
            transaction_id,
            PostgresWorkflowTransactionKind::WorkflowSlice,
            committed_at,
        )
    }

    pub fn episode_composition(
        transaction_id: &PersistenceTransactionId,
        committed_at: &Timestamp,
    ) -> Self {
        Self::new(
            transaction_id,
            PostgresWorkflowTransactionKind::EpisodeComposition,
            committed_at,
        )
    }

    pub fn transaction_kind(
        &self,
    ) -> Result<PostgresWorkflowTransactionKind, PostgresAdapterError> {
        workflow_transaction_kind_from_postgres(&self.transaction_kind)
    }
}

impl PostgresProblemEpisodeRow {
    pub fn try_from_stored(stored: &StoredProblemEpisode) -> Result<Self, PostgresAdapterError> {
        let append_sequence = i64::try_from(stored.append_sequence)
            .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)?;
        let (status_kind, status_payload) = postgres_episode_status_parts(&stored.episode.status);

        Ok(Self {
            append_sequence,
            transaction_id: stored.transaction_id.0.clone(),
            committed_at: stored.committed_at.0.clone(),
            episode_id: stored.episode.id.0.clone(),
            subject_id: stored.episode.subject_id.0.clone(),
            episode_kind: postgres_episode_kind(stored.episode.episode_kind).to_string(),
            label: stored.episode.label.clone(),
            problem_code: stored
                .episode
                .problem_code
                .as_ref()
                .map(PostgresCodedValueRecord::from_coded_value),
            status_kind: status_kind.to_string(),
            status_payload,
            onset: stored
                .episode
                .onset
                .as_ref()
                .map(PostgresApproximateDateRecord::from_approximate_date),
            authored_by: PostgresAuthorRecord::from_author(&stored.episode.authored_by),
            authored_at: stored.episode.authored_at.0.clone(),
            notes: stored.episode.notes.clone(),
        })
    }

    pub fn try_into_stored(self) -> Result<StoredProblemEpisode, PostgresAdapterError> {
        if self.append_sequence < 0 {
            return Err(PostgresAdapterError::NegativeAppendSequence);
        }

        Ok(StoredProblemEpisode {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: Id(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            episode: ProblemEpisode {
                id: Id(self.episode_id),
                subject_id: Id(self.subject_id),
                episode_kind: episode_kind_from_postgres(&self.episode_kind)?,
                label: self.label,
                problem_code: self
                    .problem_code
                    .map(PostgresCodedValueRecord::try_into_coded_value)
                    .transpose()?,
                status: episode_status_from_postgres(&self.status_kind, self.status_payload)?,
                onset: self
                    .onset
                    .map(PostgresApproximateDateRecord::try_into_approximate_date)
                    .transpose()?,
                authored_by: self.authored_by.try_into_author()?,
                authored_at: Timestamp(self.authored_at),
                notes: self.notes,
            },
        })
    }

    pub fn sort_for_replay(rows: &mut [Self]) {
        rows.sort_by_key(|row| row.append_sequence);
    }
}

impl PostgresEpisodeMembershipRow {
    pub fn try_from_stored(stored: &StoredEpisodeMembership) -> Result<Self, PostgresAdapterError> {
        let append_sequence = i64::try_from(stored.append_sequence)
            .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)?;
        let asserted_at =
            PostgresTemporalAnchorRecord::from_temporal_anchor(&stored.membership.asserted_at);
        let (status_kind, status_payload) =
            postgres_membership_status_parts(&stored.membership.status);

        Ok(Self {
            append_sequence,
            transaction_id: stored.transaction_id.0.clone(),
            committed_at: stored.committed_at.0.clone(),
            membership_id: stored.membership.id.0.clone(),
            fact_id: stored.membership.fact_id.0.clone(),
            episode_id: stored.membership.episode_id.0.clone(),
            role: postgres_fact_role(&stored.membership.role).to_string(),
            asserted_by: PostgresAuthorRecord::from_author(&stored.membership.asserted_by),
            asserted_kind: asserted_at.kind,
            asserted_start: asserted_at.start,
            asserted_end: asserted_at.end,
            status_kind: status_kind.to_string(),
            status_payload,
        })
    }

    pub fn try_into_stored(self) -> Result<StoredEpisodeMembership, PostgresAdapterError> {
        if self.append_sequence < 0 {
            return Err(PostgresAdapterError::NegativeAppendSequence);
        }

        Ok(StoredEpisodeMembership {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: Id(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            membership: EpisodeMembership {
                id: Id(self.membership_id),
                fact_id: Id(self.fact_id),
                episode_id: Id(self.episode_id),
                role: fact_role_from_postgres(&self.role)?,
                asserted_by: self.asserted_by.try_into_author()?,
                asserted_at: PostgresTemporalAnchorRecord {
                    kind: self.asserted_kind,
                    start: self.asserted_start,
                    end: self.asserted_end,
                }
                .try_into_temporal_anchor()?,
                status: membership_status_from_postgres(&self.status_kind, self.status_payload)?,
            },
        })
    }

    pub fn sort_for_replay(rows: &mut [Self]) {
        rows.sort_by_key(|row| row.append_sequence);
    }
}

impl PostgresEpisodeRelationRow {
    pub fn try_from_stored(stored: &StoredEpisodeRelation) -> Result<Self, PostgresAdapterError> {
        let append_sequence = i64::try_from(stored.append_sequence)
            .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)?;
        let asserted_at =
            PostgresTemporalAnchorRecord::from_temporal_anchor(&stored.relation.asserted_at);
        let (status_kind, status_payload) =
            postgres_episode_relation_status_parts(&stored.relation.status);

        Ok(Self {
            append_sequence,
            transaction_id: stored.transaction_id.0.clone(),
            committed_at: stored.committed_at.0.clone(),
            relation_id: stored.relation.id.0.clone(),
            source_episode_id: stored.relation.source_episode_id.0.clone(),
            target_episode_id: stored.relation.target_episode_id.0.clone(),
            relation_type: postgres_episode_relation_type(stored.relation.relation_type)
                .to_string(),
            asserted_by: PostgresAuthorRecord::from_author(&stored.relation.asserted_by),
            asserted_kind: asserted_at.kind,
            asserted_start: asserted_at.start,
            asserted_end: asserted_at.end,
            status_kind: status_kind.to_string(),
            status_payload,
        })
    }

    pub fn try_into_stored(self) -> Result<StoredEpisodeRelation, PostgresAdapterError> {
        if self.append_sequence < 0 {
            return Err(PostgresAdapterError::NegativeAppendSequence);
        }

        Ok(StoredEpisodeRelation {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: Id(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            relation: EpisodeRelation {
                id: Id(self.relation_id),
                source_episode_id: Id(self.source_episode_id),
                target_episode_id: Id(self.target_episode_id),
                relation_type: episode_relation_type_from_postgres(&self.relation_type)?,
                asserted_by: self.asserted_by.try_into_author()?,
                asserted_at: PostgresTemporalAnchorRecord {
                    kind: self.asserted_kind,
                    start: self.asserted_start,
                    end: self.asserted_end,
                }
                .try_into_temporal_anchor()?,
                status: episode_relation_status_from_postgres(
                    &self.status_kind,
                    self.status_payload,
                )?,
            },
        })
    }

    pub fn sort_for_replay(rows: &mut [Self]) {
        rows.sort_by_key(|row| row.append_sequence);
    }
}

impl PostgresTemporalAnchorRecord {
    fn from_temporal_anchor(anchor: &TemporalAnchor) -> Self {
        match anchor {
            TemporalAnchor::Point(timestamp) => Self {
                kind: "point".to_string(),
                start: timestamp.0.clone(),
                end: None,
            },
            TemporalAnchor::Period(period) => Self {
                kind: "period".to_string(),
                start: period.start.0.clone(),
                end: Some(period.end.0.clone()),
            },
        }
    }

    fn try_into_temporal_anchor(self) -> Result<TemporalAnchor, PostgresAdapterError> {
        match (self.kind.as_str(), self.end) {
            ("point", None) => Ok(TemporalAnchor::Point(Timestamp(self.start))),
            ("period", Some(end)) => Ok(TemporalAnchor::Period(TimeInterval {
                start: Timestamp(self.start),
                end: Timestamp(end),
            })),
            ("point" | "period", _) => Err(PostgresAdapterError::InvalidTemporalAnchor),
            _ => Err(PostgresAdapterError::UnknownTemporalKind(self.kind)),
        }
    }
}

impl PostgresCodedValueRecord {
    fn from_coded_value(value: &CodedValue) -> Self {
        Self {
            system: postgres_coding_system(&value.system).to_string(),
            code: value.code.clone(),
            display: value.display.clone(),
        }
    }

    fn try_into_coded_value(self) -> Result<CodedValue, PostgresAdapterError> {
        Ok(CodedValue {
            system: coding_system_from_postgres(&self.system)?,
            code: self.code,
            display: self.display,
        })
    }
}

impl PostgresApproximateDateRecord {
    fn from_approximate_date(value: &ApproximateDate) -> Self {
        Self {
            date: value.date.0.clone(),
            precision: postgres_date_precision(value.precision).to_string(),
        }
    }

    fn try_into_approximate_date(self) -> Result<ApproximateDate, PostgresAdapterError> {
        Ok(ApproximateDate {
            date: Date(self.date),
            precision: date_precision_from_postgres(&self.precision)?,
        })
    }
}

fn postgres_fact_status_parts(status: &FactStatus) -> (&'static str, PostgresFactStatusPayload) {
    match status {
        FactStatus::Active => ("active", PostgresFactStatusPayload::Active),
        FactStatus::Superseded {
            superseded_by,
            superseded_at,
            replaced_by,
            reason,
        } => (
            "superseded",
            PostgresFactStatusPayload::Superseded {
                superseded_by: PostgresAuthorRecord::from_author(superseded_by),
                superseded_at: PostgresTemporalAnchorRecord::from_temporal_anchor(superseded_at),
                replaced_by: replaced_by.as_ref().map(|fact_id| fact_id.0.clone()),
                reason: postgres_supersession_reason(reason).to_string(),
            },
        ),
        FactStatus::EnteredInError {
            corrected_by,
            corrected_at,
            replaced_by,
        } => (
            "entered_in_error",
            PostgresFactStatusPayload::EnteredInError {
                corrected_by: PostgresAuthorRecord::from_author(corrected_by),
                corrected_at: PostgresTemporalAnchorRecord::from_temporal_anchor(corrected_at),
                replaced_by: replaced_by.as_ref().map(|fact_id| fact_id.0.clone()),
            },
        ),
    }
}

fn postgres_episode_status_parts(
    status: &EpisodeStatus,
) -> (&'static str, PostgresEpisodeStatusPayload) {
    match status {
        EpisodeStatus::Active => ("active", PostgresEpisodeStatusPayload::Active),
        EpisodeStatus::Dormant => ("dormant", PostgresEpisodeStatusPayload::Dormant),
        EpisodeStatus::Resolved(resolution) => (
            "resolved",
            PostgresEpisodeStatusPayload::Resolved {
                at: resolution
                    .at
                    .as_ref()
                    .map(PostgresApproximateDateRecord::from_approximate_date),
            },
        ),
    }
}

fn episode_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresEpisodeStatusPayload,
) -> Result<EpisodeStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresEpisodeStatusPayload::Active) => Ok(EpisodeStatus::Active),
        ("dormant", PostgresEpisodeStatusPayload::Dormant) => Ok(EpisodeStatus::Dormant),
        ("resolved", PostgresEpisodeStatusPayload::Resolved { at }) => {
            Ok(EpisodeStatus::Resolved(ResolutionInfo {
                at: at
                    .map(PostgresApproximateDateRecord::try_into_approximate_date)
                    .transpose()?,
            }))
        }
        ("active" | "dormant" | "resolved", _) => {
            Err(PostgresAdapterError::InvalidEpisodeStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownEpisodeStatusKind(
            status_kind.to_string(),
        )),
    }
}

fn postgres_membership_status_parts(
    status: &MembershipStatus,
) -> (&'static str, PostgresMembershipStatusPayload) {
    match status {
        MembershipStatus::Active => ("active", PostgresMembershipStatusPayload::Active),
        MembershipStatus::Retracted {
            retracted_by,
            retracted_at,
        } => (
            "retracted",
            PostgresMembershipStatusPayload::Retracted {
                retracted_by: PostgresAuthorRecord::from_author(retracted_by),
                retracted_at: PostgresTemporalAnchorRecord::from_temporal_anchor(retracted_at),
            },
        ),
    }
}

fn membership_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresMembershipStatusPayload,
) -> Result<MembershipStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresMembershipStatusPayload::Active) => Ok(MembershipStatus::Active),
        (
            "retracted",
            PostgresMembershipStatusPayload::Retracted {
                retracted_by,
                retracted_at,
            },
        ) => Ok(MembershipStatus::Retracted {
            retracted_by: retracted_by.try_into_author()?,
            retracted_at: retracted_at.try_into_temporal_anchor()?,
        }),
        ("active" | "retracted", _) => Err(PostgresAdapterError::InvalidMembershipStatusPayload),
        _ => Err(PostgresAdapterError::UnknownMembershipStatusKind(
            status_kind.to_string(),
        )),
    }
}

fn postgres_episode_relation_status_parts(
    status: &EpisodeRelationStatus,
) -> (&'static str, PostgresEpisodeRelationStatusPayload) {
    match status {
        EpisodeRelationStatus::Active => ("active", PostgresEpisodeRelationStatusPayload::Active),
        EpisodeRelationStatus::Retracted {
            retracted_by,
            retracted_at,
        } => (
            "retracted",
            PostgresEpisodeRelationStatusPayload::Retracted {
                retracted_by: PostgresAuthorRecord::from_author(retracted_by),
                retracted_at: PostgresTemporalAnchorRecord::from_temporal_anchor(retracted_at),
            },
        ),
    }
}

fn episode_relation_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresEpisodeRelationStatusPayload,
) -> Result<EpisodeRelationStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresEpisodeRelationStatusPayload::Active) => {
            Ok(EpisodeRelationStatus::Active)
        }
        (
            "retracted",
            PostgresEpisodeRelationStatusPayload::Retracted {
                retracted_by,
                retracted_at,
            },
        ) => Ok(EpisodeRelationStatus::Retracted {
            retracted_by: retracted_by.try_into_author()?,
            retracted_at: retracted_at.try_into_temporal_anchor()?,
        }),
        ("active" | "retracted", _) => {
            Err(PostgresAdapterError::InvalidEpisodeRelationStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownEpisodeRelationStatusKind(
            status_kind.to_string(),
        )),
    }
}

fn fact_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresFactStatusPayload,
) -> Result<FactStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("active", PostgresFactStatusPayload::Active) => Ok(FactStatus::Active),
        (
            "superseded",
            PostgresFactStatusPayload::Superseded {
                superseded_by,
                superseded_at,
                replaced_by,
                reason,
            },
        ) => Ok(FactStatus::Superseded {
            superseded_by: superseded_by.try_into_author()?,
            superseded_at: superseded_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(Id),
            reason: supersession_reason_from_postgres(&reason)?,
        }),
        (
            "entered_in_error",
            PostgresFactStatusPayload::EnteredInError {
                corrected_by,
                corrected_at,
                replaced_by,
            },
        ) => Ok(FactStatus::EnteredInError {
            corrected_by: corrected_by.try_into_author()?,
            corrected_at: corrected_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(Id),
        }),
        ("active" | "superseded" | "entered_in_error", _) => {
            Err(PostgresAdapterError::InvalidFactStatusPayload)
        }
        _ => Err(PostgresAdapterError::UnknownFactStatusKind(
            status_kind.to_string(),
        )),
    }
}

impl PostgresAuthorRecord {
    fn from_author(author: &Author) -> Self {
        Self {
            author_type: postgres_author_type(&author.author_type).to_string(),
            author_id: author
                .author_id
                .as_ref()
                .map(|author_id| author_id.0.clone()),
            display_name: author.display_name.clone(),
        }
    }

    fn try_into_author(self) -> Result<Author, PostgresAdapterError> {
        Ok(Author {
            author_type: author_type_from_postgres(&self.author_type)?,
            author_id: self.author_id.map(Id),
            display_name: self.display_name,
        })
    }
}

fn postgres_workflow_transaction_kind(kind: PostgresWorkflowTransactionKind) -> &'static str {
    match kind {
        PostgresWorkflowTransactionKind::WorkflowSlice => "workflow_slice",
        PostgresWorkflowTransactionKind::EpisodeComposition => "episode_composition",
    }
}

fn workflow_transaction_kind_from_postgres(
    value: &str,
) -> Result<PostgresWorkflowTransactionKind, PostgresAdapterError> {
    match value {
        "workflow_slice" => Ok(PostgresWorkflowTransactionKind::WorkflowSlice),
        "episode_composition" => Ok(PostgresWorkflowTransactionKind::EpisodeComposition),
        _ => Err(PostgresAdapterError::UnknownWorkflowTransactionKind(
            value.to_string(),
        )),
    }
}

fn postgres_app_attest_environment(environment: AppAttestEnvironment) -> &'static str {
    match environment {
        AppAttestEnvironment::Development => "development",
        AppAttestEnvironment::Production => "production",
    }
}

fn app_attest_environment_from_postgres(
    value: &str,
) -> Result<AppAttestEnvironment, PostgresAdapterError> {
    match value {
        "development" => Ok(AppAttestEnvironment::Development),
        "production" => Ok(AppAttestEnvironment::Production),
        _ => Err(PostgresAdapterError::UnknownAppAttestEnvironment(
            value.to_string(),
        )),
    }
}

fn postgres_app_attest_key_status(status: AppAttestKeyStateStatus) -> &'static str {
    match status {
        AppAttestKeyStateStatus::Active => "active",
        AppAttestKeyStateStatus::Revoked => "revoked",
    }
}

fn app_attest_key_status_from_postgres(
    value: &str,
) -> Result<AppAttestKeyStateStatus, PostgresAdapterError> {
    match value {
        "active" => Ok(AppAttestKeyStateStatus::Active),
        "revoked" => Ok(AppAttestKeyStateStatus::Revoked),
        _ => Err(PostgresAdapterError::UnknownAppAttestKeyStatus(
            value.to_string(),
        )),
    }
}

fn postgres_live_presence_challenge_workflow(
    workflow: LivePresenceChallengeWorkflow,
) -> &'static str {
    match workflow {
        LivePresenceChallengeWorkflow::MobileIdentityOnboarding => "mobile_identity_onboarding",
        LivePresenceChallengeWorkflow::AccountRecovery => "account_recovery",
        LivePresenceChallengeWorkflow::SensitiveActionStepUp => "sensitive_action_step_up",
    }
}

fn live_presence_challenge_workflow_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeWorkflow, PostgresAdapterError> {
    match value {
        "mobile_identity_onboarding" => Ok(LivePresenceChallengeWorkflow::MobileIdentityOnboarding),
        "account_recovery" => Ok(LivePresenceChallengeWorkflow::AccountRecovery),
        "sensitive_action_step_up" => Ok(LivePresenceChallengeWorkflow::SensitiveActionStepUp),
        _ => Err(PostgresAdapterError::UnknownLivePresenceChallengeWorkflow(
            value.to_string(),
        )),
    }
}

fn postgres_live_presence_challenge_status_parts(
    status: &LivePresenceChallengeStatus,
) -> (&'static str, PostgresLivePresenceChallengeStatusPayload) {
    match status {
        LivePresenceChallengeStatus::Issued => {
            ("issued", PostgresLivePresenceChallengeStatusPayload::Issued)
        }
        LivePresenceChallengeStatus::Used {
            used_at,
            provider_event_id,
        } => (
            "used",
            PostgresLivePresenceChallengeStatusPayload::Used {
                used_at: used_at.0.clone(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
        LivePresenceChallengeStatus::Expired { expired_at } => (
            "expired",
            PostgresLivePresenceChallengeStatusPayload::Expired {
                expired_at: expired_at.0.clone(),
            },
        ),
        LivePresenceChallengeStatus::Failed {
            failed_at,
            reason,
            provider_event_id,
        } => (
            "failed",
            PostgresLivePresenceChallengeStatusPayload::Failed {
                failed_at: failed_at.0.clone(),
                reason: postgres_live_presence_failure_reason(*reason).to_string(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
        LivePresenceChallengeStatus::ManualReview {
            referred_at,
            reason,
            provider_event_id,
        } => (
            "manual_review",
            PostgresLivePresenceChallengeStatusPayload::ManualReview {
                referred_at: referred_at.0.clone(),
                reason: postgres_live_presence_manual_review_reason(*reason).to_string(),
                provider_event_id: provider_event_id.clone(),
            },
        ),
    }
}

fn live_presence_challenge_status_from_postgres(
    status_kind: &str,
    status_payload: PostgresLivePresenceChallengeStatusPayload,
) -> Result<LivePresenceChallengeStatus, PostgresAdapterError> {
    match (status_kind, status_payload) {
        ("issued", PostgresLivePresenceChallengeStatusPayload::Issued) => {
            Ok(LivePresenceChallengeStatus::Issued)
        }
        (
            "used",
            PostgresLivePresenceChallengeStatusPayload::Used {
                used_at,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::Used {
            used_at: Timestamp(used_at),
            provider_event_id,
        }),
        ("expired", PostgresLivePresenceChallengeStatusPayload::Expired { expired_at }) => {
            Ok(LivePresenceChallengeStatus::Expired {
                expired_at: Timestamp(expired_at),
            })
        }
        (
            "failed",
            PostgresLivePresenceChallengeStatusPayload::Failed {
                failed_at,
                reason,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::Failed {
            failed_at: Timestamp(failed_at),
            reason: live_presence_failure_reason_from_postgres(&reason)?,
            provider_event_id,
        }),
        (
            "manual_review",
            PostgresLivePresenceChallengeStatusPayload::ManualReview {
                referred_at,
                reason,
                provider_event_id,
            },
        ) => Ok(LivePresenceChallengeStatus::ManualReview {
            referred_at: Timestamp(referred_at),
            reason: live_presence_manual_review_reason_from_postgres(&reason)?,
            provider_event_id,
        }),
        ("issued" | "used" | "expired" | "failed" | "manual_review", _) => {
            Err(PostgresAdapterError::InvalidLivePresenceChallengeStatusPayload)
        }
        _ => Err(
            PostgresAdapterError::UnknownLivePresenceChallengeStatusKind(status_kind.to_string()),
        ),
    }
}

fn postgres_live_presence_failure_reason(
    reason: LivePresenceChallengeFailureReason,
) -> &'static str {
    match reason {
        LivePresenceChallengeFailureReason::LivenessFailed => "liveness_failed",
        LivePresenceChallengeFailureReason::PresentationAttackDetected => {
            "presentation_attack_detected"
        }
        LivePresenceChallengeFailureReason::ChallengeMismatch => "challenge_mismatch",
        LivePresenceChallengeFailureReason::SubjectMismatch => "subject_mismatch",
        LivePresenceChallengeFailureReason::DeviceMismatch => "device_mismatch",
        LivePresenceChallengeFailureReason::AppContextMismatch => "app_context_mismatch",
        LivePresenceChallengeFailureReason::ProviderRejected => "provider_rejected",
    }
}

fn live_presence_failure_reason_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeFailureReason, PostgresAdapterError> {
    match value {
        "liveness_failed" => Ok(LivePresenceChallengeFailureReason::LivenessFailed),
        "presentation_attack_detected" => {
            Ok(LivePresenceChallengeFailureReason::PresentationAttackDetected)
        }
        "challenge_mismatch" => Ok(LivePresenceChallengeFailureReason::ChallengeMismatch),
        "subject_mismatch" => Ok(LivePresenceChallengeFailureReason::SubjectMismatch),
        "device_mismatch" => Ok(LivePresenceChallengeFailureReason::DeviceMismatch),
        "app_context_mismatch" => Ok(LivePresenceChallengeFailureReason::AppContextMismatch),
        "provider_rejected" => Ok(LivePresenceChallengeFailureReason::ProviderRejected),
        _ => {
            Err(PostgresAdapterError::UnknownLivePresenceChallengeFailureReason(value.to_string()))
        }
    }
}

fn postgres_live_presence_manual_review_reason(
    reason: LivePresenceChallengeManualReviewReason,
) -> &'static str {
    match reason {
        LivePresenceChallengeManualReviewReason::LivenessInconclusive => "liveness_inconclusive",
        LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive => {
            "presentation_attack_inconclusive"
        }
        LivePresenceChallengeManualReviewReason::RetryOrReviewPolicy => "retry_or_review_policy",
    }
}

fn live_presence_manual_review_reason_from_postgres(
    value: &str,
) -> Result<LivePresenceChallengeManualReviewReason, PostgresAdapterError> {
    match value {
        "liveness_inconclusive" => {
            Ok(LivePresenceChallengeManualReviewReason::LivenessInconclusive)
        }
        "presentation_attack_inconclusive" => {
            Ok(LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive)
        }
        "retry_or_review_policy" => {
            Ok(LivePresenceChallengeManualReviewReason::RetryOrReviewPolicy)
        }
        _ => Err(
            PostgresAdapterError::UnknownLivePresenceChallengeManualReviewReason(value.to_string()),
        ),
    }
}

fn postgres_episode_kind(kind: EpisodeKind) -> &'static str {
    match kind {
        EpisodeKind::ClinicalProblem => "clinical_problem",
        EpisodeKind::AdministrativeWorkflow => "administrative_workflow",
        EpisodeKind::IdentityVerificationWorkflow => "identity_verification_workflow",
        EpisodeKind::AccountRecoveryWorkflow => "account_recovery_workflow",
        EpisodeKind::DelegationWorkflow => "delegation_workflow",
        EpisodeKind::AccessAuthorizationWorkflow => "access_authorization_workflow",
        EpisodeKind::DataSharingWorkflow => "data_sharing_workflow",
        EpisodeKind::DisputeResolutionWorkflow => "dispute_resolution_workflow",
    }
}

fn episode_kind_from_postgres(value: &str) -> Result<EpisodeKind, PostgresAdapterError> {
    match value {
        "clinical_problem" => Ok(EpisodeKind::ClinicalProblem),
        "administrative_workflow" => Ok(EpisodeKind::AdministrativeWorkflow),
        "identity_verification_workflow" => Ok(EpisodeKind::IdentityVerificationWorkflow),
        "account_recovery_workflow" => Ok(EpisodeKind::AccountRecoveryWorkflow),
        "delegation_workflow" => Ok(EpisodeKind::DelegationWorkflow),
        "access_authorization_workflow" => Ok(EpisodeKind::AccessAuthorizationWorkflow),
        "data_sharing_workflow" => Ok(EpisodeKind::DataSharingWorkflow),
        "dispute_resolution_workflow" => Ok(EpisodeKind::DisputeResolutionWorkflow),
        _ => Err(PostgresAdapterError::UnknownEpisodeKind(value.to_string())),
    }
}

fn postgres_date_precision(precision: DatePrecision) -> &'static str {
    match precision {
        DatePrecision::Day => "day",
        DatePrecision::Month => "month",
        DatePrecision::Year => "year",
        DatePrecision::Approximate => "approximate",
    }
}

fn date_precision_from_postgres(value: &str) -> Result<DatePrecision, PostgresAdapterError> {
    match value {
        "day" => Ok(DatePrecision::Day),
        "month" => Ok(DatePrecision::Month),
        "year" => Ok(DatePrecision::Year),
        "approximate" => Ok(DatePrecision::Approximate),
        _ => Err(PostgresAdapterError::UnknownDatePrecision(
            value.to_string(),
        )),
    }
}

fn postgres_coding_system(system: &CodingSystem) -> &'static str {
    match system {
        CodingSystem::Snomed => "snomed",
        CodingSystem::Icd10 => "icd10",
        CodingSystem::Loinc => "loinc",
        CodingSystem::RxNorm => "rxnorm",
        CodingSystem::Cpt => "cpt",
        CodingSystem::Local => "local",
    }
}

fn coding_system_from_postgres(value: &str) -> Result<CodingSystem, PostgresAdapterError> {
    match value {
        "snomed" => Ok(CodingSystem::Snomed),
        "icd10" => Ok(CodingSystem::Icd10),
        "loinc" => Ok(CodingSystem::Loinc),
        "rxnorm" => Ok(CodingSystem::RxNorm),
        "cpt" => Ok(CodingSystem::Cpt),
        "local" => Ok(CodingSystem::Local),
        _ => Err(PostgresAdapterError::UnknownCodingSystem(value.to_string())),
    }
}

fn postgres_fact_role(role: &FactRole) -> &'static str {
    match role {
        FactRole::TriggeringSymptom => "triggering_symptom",
        FactRole::DiagnosticTest => "diagnostic_test",
        FactRole::Treatment => "treatment",
        FactRole::OutcomeMeasure => "outcome_measure",
        FactRole::Monitoring => "monitoring",
        FactRole::Complication => "complication",
        FactRole::Referral => "referral",
        FactRole::Administrative => "administrative",
        FactRole::InsuranceAction => "insurance_action",
        FactRole::IdentityAnchor => "identity_anchor",
        FactRole::IdentityWitness => "identity_witness",
        FactRole::ContinuityWitness => "continuity_witness",
        FactRole::DeviceBinding => "device_binding",
        FactRole::InstitutionalLink => "institutional_link",
        FactRole::AuthorityEvidence => "authority_evidence",
        FactRole::RecoveryEvidence => "recovery_evidence",
        FactRole::RiskSignal => "risk_signal",
        FactRole::AccessDecisionEvidence => "access_decision_evidence",
        FactRole::DisputeEvidence => "dispute_evidence",
        FactRole::Other => "other",
    }
}

fn fact_role_from_postgres(value: &str) -> Result<FactRole, PostgresAdapterError> {
    match value {
        "triggering_symptom" => Ok(FactRole::TriggeringSymptom),
        "diagnostic_test" => Ok(FactRole::DiagnosticTest),
        "treatment" => Ok(FactRole::Treatment),
        "outcome_measure" => Ok(FactRole::OutcomeMeasure),
        "monitoring" => Ok(FactRole::Monitoring),
        "complication" => Ok(FactRole::Complication),
        "referral" => Ok(FactRole::Referral),
        "administrative" => Ok(FactRole::Administrative),
        "insurance_action" => Ok(FactRole::InsuranceAction),
        "identity_anchor" => Ok(FactRole::IdentityAnchor),
        "identity_witness" => Ok(FactRole::IdentityWitness),
        "continuity_witness" => Ok(FactRole::ContinuityWitness),
        "device_binding" => Ok(FactRole::DeviceBinding),
        "institutional_link" => Ok(FactRole::InstitutionalLink),
        "authority_evidence" => Ok(FactRole::AuthorityEvidence),
        "recovery_evidence" => Ok(FactRole::RecoveryEvidence),
        "risk_signal" => Ok(FactRole::RiskSignal),
        "access_decision_evidence" => Ok(FactRole::AccessDecisionEvidence),
        "dispute_evidence" => Ok(FactRole::DisputeEvidence),
        "other" => Ok(FactRole::Other),
        _ => Err(PostgresAdapterError::UnknownFactRole(value.to_string())),
    }
}

fn postgres_episode_relation_type(relation_type: EpisodeRelationType) -> &'static str {
    match relation_type {
        EpisodeRelationType::PartOf => "part_of",
    }
}

fn episode_relation_type_from_postgres(
    value: &str,
) -> Result<EpisodeRelationType, PostgresAdapterError> {
    match value {
        "part_of" => Ok(EpisodeRelationType::PartOf),
        _ => Err(PostgresAdapterError::UnknownEpisodeRelationType(
            value.to_string(),
        )),
    }
}

fn postgres_author_type(author_type: &AuthorType) -> &'static str {
    match author_type {
        AuthorType::Patient => "patient",
        AuthorType::Clinician => "clinician",
        AuthorType::System => "system",
        AuthorType::AiAssisted => "ai_assisted",
    }
}

fn author_type_from_postgres(value: &str) -> Result<AuthorType, PostgresAdapterError> {
    match value {
        "patient" => Ok(AuthorType::Patient),
        "clinician" => Ok(AuthorType::Clinician),
        "system" => Ok(AuthorType::System),
        "ai_assisted" => Ok(AuthorType::AiAssisted),
        _ => Err(PostgresAdapterError::UnknownAuthorType(value.to_string())),
    }
}

fn postgres_supersession_reason(reason: &SupersessionReason) -> &'static str {
    match reason {
        SupersessionReason::AiEnrichment => "ai_enrichment",
        SupersessionReason::ClinicalRefinement => "clinical_refinement",
        SupersessionReason::StrongerIdentityEvidence => "stronger_identity_evidence",
        SupersessionReason::AdministrativeCorrection => "administrative_correction",
    }
}

fn supersession_reason_from_postgres(
    value: &str,
) -> Result<SupersessionReason, PostgresAdapterError> {
    match value {
        "ai_enrichment" => Ok(SupersessionReason::AiEnrichment),
        "clinical_refinement" => Ok(SupersessionReason::ClinicalRefinement),
        "stronger_identity_evidence" => Ok(SupersessionReason::StrongerIdentityEvidence),
        "administrative_correction" => Ok(SupersessionReason::AdministrativeCorrection),
        _ => Err(PostgresAdapterError::UnknownSupersessionReason(
            value.to_string(),
        )),
    }
}

fn postgres_audit_outcome(outcome: FactMaterializationAuditOutcome) -> &'static str {
    match outcome {
        FactMaterializationAuditOutcome::Attempted => "attempted",
        FactMaterializationAuditOutcome::PolicyDenied => "policy_denied",
        FactMaterializationAuditOutcome::KeyAccessAttempted => "key_access_attempted",
        FactMaterializationAuditOutcome::KeyAccessSucceeded => "key_access_succeeded",
        FactMaterializationAuditOutcome::KeyAccessFailed => "key_access_failed",
        FactMaterializationAuditOutcome::DecryptionAttempted => "decryption_attempted",
        FactMaterializationAuditOutcome::DecryptionFailed => "decryption_failed",
        FactMaterializationAuditOutcome::Succeeded => "succeeded",
    }
}

fn audit_outcome_from_postgres(
    value: &str,
) -> Result<FactMaterializationAuditOutcome, PostgresAdapterError> {
    match value {
        "attempted" => Ok(FactMaterializationAuditOutcome::Attempted),
        "policy_denied" => Ok(FactMaterializationAuditOutcome::PolicyDenied),
        "key_access_attempted" => Ok(FactMaterializationAuditOutcome::KeyAccessAttempted),
        "key_access_succeeded" => Ok(FactMaterializationAuditOutcome::KeyAccessSucceeded),
        "key_access_failed" => Ok(FactMaterializationAuditOutcome::KeyAccessFailed),
        "decryption_attempted" => Ok(FactMaterializationAuditOutcome::DecryptionAttempted),
        "decryption_failed" => Ok(FactMaterializationAuditOutcome::DecryptionFailed),
        "succeeded" => Ok(FactMaterializationAuditOutcome::Succeeded),
        _ => Err(PostgresAdapterError::UnknownMaterializationAuditOutcome(
            value.to_string(),
        )),
    }
}

fn postgres_materialization_error(error: FactMaterializationError) -> &'static str {
    match error {
        FactMaterializationError::PolicyDenied => "policy_denied",
        FactMaterializationError::MaterializationPolicyRefsNotSatisfied => {
            "materialization_policy_refs_not_satisfied"
        }
        FactMaterializationError::MissingKey => "missing_key",
        FactMaterializationError::RetiredKey => "retired_key",
        FactMaterializationError::AuthenticationFailed => "authentication_failed",
        FactMaterializationError::PlaintextDecodeFailed => "plaintext_decode_failed",
        FactMaterializationError::UnsupportedAlgorithm => "unsupported_algorithm",
        FactMaterializationError::InvalidKeyMaterial => "invalid_key_material",
        FactMaterializationError::InvalidNonce => "invalid_nonce",
    }
}

fn materialization_error_from_postgres(
    value: &str,
) -> Result<FactMaterializationError, PostgresAdapterError> {
    match value {
        "policy_denied" => Ok(FactMaterializationError::PolicyDenied),
        "materialization_policy_refs_not_satisfied" => {
            Ok(FactMaterializationError::MaterializationPolicyRefsNotSatisfied)
        }
        "missing_key" => Ok(FactMaterializationError::MissingKey),
        "retired_key" => Ok(FactMaterializationError::RetiredKey),
        "authentication_failed" => Ok(FactMaterializationError::AuthenticationFailed),
        "plaintext_decode_failed" => Ok(FactMaterializationError::PlaintextDecodeFailed),
        "unsupported_algorithm" => Ok(FactMaterializationError::UnsupportedAlgorithm),
        "invalid_key_material" => Ok(FactMaterializationError::InvalidKeyMaterial),
        "invalid_nonce" => Ok(FactMaterializationError::InvalidNonce),
        _ => Err(PostgresAdapterError::UnknownMaterializationError(
            value.to_string(),
        )),
    }
}
