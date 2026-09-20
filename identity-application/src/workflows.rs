use identity_model::flows::IdentityWorkflowSlice;
use identity_model::identity::AccessDecisionResult;
use identity_model::policy::PolicyEvaluation;
use identity_model::{fen::*, persistence::*, workflows::*};
use std::future::Future;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowAppendError<E> {
    Encryption(FactEncryptionError),
    Storage(E),
}
impl<E> From<FactEncryptionError> for WorkflowAppendError<E> {
    fn from(e: FactEncryptionError) -> Self {
        Self::Encryption(e)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowReadError<E> {
    Storage(E),
    Materialization(FactMaterializationError),
}
impl<E> From<FactMaterializationError> for WorkflowReadError<E> {
    fn from(e: FactMaterializationError) -> Self {
        Self::Materialization(e)
    }
}
/// Sequence allocation and the resulting encrypted workflow are one atomic append.
/// Audit acknowledgements must mean durable persistence, before any key is accessed.
pub trait EncryptedWorkflowStore {
    type Error;
    fn append_slice(
        &self,
        prepare: impl FnOnce(
            EncryptedWorkflowAppendSequenceState,
        ) -> Result<StoredIdentityWorkflowSlice, FactEncryptionError>,
    ) -> impl Future<Output = Result<StoredIdentityWorkflowSlice, WorkflowAppendError<Self::Error>>>;
    fn append_composition(
        &self,
        prepare: impl FnOnce(
            EncryptedWorkflowAppendSequenceState,
        ) -> Result<StoredEpisodeComposition, FactEncryptionError>,
    ) -> impl Future<Output = Result<StoredEpisodeComposition, WorkflowAppendError<Self::Error>>>;
    fn encrypted_facts(
        &self,
        subject: &SubjectId,
    ) -> impl Future<Output = Result<Vec<StoredEncryptedFact>, Self::Error>>;
    fn audit(
        &self,
        event: &FactMaterializationAuditEvent,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}
pub struct EncryptedWorkflowService<S, M, E> {
    storage: S,
    metadata_planner: M,
    encryptor: E,
    key: FactDataEncryptionKey,
    materialization_policy_refs: Vec<PolicyRef>,
}

impl<S: EncryptedWorkflowStore, M, E> EncryptedWorkflowService<S, M, E> {
    pub fn new(
        storage: S,
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

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }
}

impl<S: EncryptedWorkflowStore, M, E> EncryptedWorkflowService<S, M, E>
where
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    pub async fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredIdentityWorkflowSlice, WorkflowAppendError<S::Error>> {
        self.storage
            .append_slice(|sequence_state| {
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

                Ok(stored)
            })
            .await
    }

    pub async fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredEpisodeComposition, WorkflowAppendError<S::Error>> {
        self.storage
            .append_composition(|sequence_state| {
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

                Ok(stored)
            })
            .await
    }

    /// Discloses only the authorized facts; audit persistence must succeed before key access.
    pub async fn disclose_identifiers(
        &self,
        permit: &identity_model::disclosure::AuthorizedDisclosure,
        clock: &impl identity_model::clock::Clock,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<Vec<Fact>, WorkflowReadError<S::Error>> {
        let envelopes = self
            .storage
            .encrypted_facts(&permit.request().subject)
            .await
            .map_err(WorkflowReadError::Storage)?;
        let mut facts = Vec::new();
        for id in &permit.request().facts {
            let envelope = envelopes
                .iter()
                .find(|e| &e.fact_id == id)
                .ok_or(FactMaterializationError::PolicyDenied)?;
            let at = clock.now();
            if !permit.permits(&envelope.subject_id, id, &at) {
                return Err(FactMaterializationError::PolicyDenied.into());
            }
            facts.push(
                materialize_with_durable_audit(
                    &self.storage,
                    envelope,
                    key_resolver,
                    &self.encryptor,
                    permit,
                    clock,
                )
                .await?,
            );
        }
        Ok(facts)
    }
}

async fn materialize_with_durable_audit<S: EncryptedWorkflowStore>(
    storage: &S,
    envelope: &StoredEncryptedFact,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor,
    permit: &identity_model::disclosure::AuthorizedDisclosure,
    clock: &impl identity_model::clock::Clock,
) -> Result<Fact, WorkflowReadError<S::Error>> {
    let policy_evaluation = permit.evaluation();
    let audit_context = &permit.audit_context();
    record_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::Attempted,
        None,
    )
    .await?;

    if policy_evaluation.decision != AccessDecisionResult::Allowed {
        return fail_materialization(
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
        return fail_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::MaterializationPolicyRefsNotSatisfied,
        )
        .await;
    }

    record_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::KeyAccessAttempted,
        None,
    )
    .await?;
    if !permit.permits(&envelope.subject_id, &envelope.fact_id, &clock.now()) {
        return fail_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::PolicyDenied,
        )
        .await;
    }
    let key = match key_resolver.resolve_fact_key(&envelope.encryption.key_id) {
        Ok(key) => key,
        Err(_) => {
            return fail_materialization(
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
        return fail_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::KeyAccessFailed,
            FactMaterializationError::RetiredKey,
        )
        .await;
    }
    record_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::KeyAccessSucceeded,
        None,
    )
    .await?;

    record_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        FactMaterializationAuditOutcome::DecryptionAttempted,
        None,
    )
    .await?;
    if !permit.permits(&envelope.subject_id, &envelope.fact_id, &clock.now()) {
        return fail_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::PolicyDenied,
        )
        .await;
    }
    let associated_data = canonical_encrypted_fact_associated_data(envelope);
    let plaintext = match encryptor.decrypt_fact_plaintext(
        &key,
        &envelope.encryption,
        &associated_data,
        &envelope.ciphertext,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            return fail_materialization(
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
        return fail_materialization(
            storage,
            envelope,
            policy_evaluation,
            audit_context,
            FactMaterializationAuditOutcome::DecryptionFailed,
            FactMaterializationError::AuthenticationFailed,
        )
        .await;
    }

    record_materialization_event(
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

async fn fail_materialization<T, S: EncryptedWorkflowStore>(
    storage: &S,
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    outcome: FactMaterializationAuditOutcome,
    error: FactMaterializationError,
) -> Result<T, WorkflowReadError<S::Error>> {
    record_materialization_event(
        storage,
        envelope,
        policy_evaluation,
        audit_context,
        outcome,
        Some(error),
    )
    .await?;
    Err(WorkflowReadError::Materialization(error))
}

async fn record_materialization_event<S: EncryptedWorkflowStore>(
    storage: &S,
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    outcome: FactMaterializationAuditOutcome,
    error: Option<FactMaterializationError>,
) -> Result<(), WorkflowReadError<S::Error>> {
    storage
        .audit(&FactMaterializationAuditEvent {
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
        .map_err(WorkflowReadError::Storage)
}
