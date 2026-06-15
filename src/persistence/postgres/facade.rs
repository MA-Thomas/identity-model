#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use crate::flows::IdentityWorkflowSlice;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use crate::identity::AccessDecisionResult;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use crate::materialized::{materialize_identity_state, MaterializedIdentityState};
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use crate::policy::PolicyEvaluation;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

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
        let mut transaction = self.storage.pool().begin().await.map_err(sqlx_error)?;
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
        let mut transaction = self.storage.pool().begin().await.map_err(sqlx_error)?;
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
pub(super) async fn materialize_postgres_encrypted_fact_with_durable_audit(
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
pub(super) async fn fail_postgres_materialization<T>(
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
pub(super) async fn record_postgres_materialization_event(
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
