use super::{
    RepositoryError, StoredEpisodeComposition, StoredEpisodeMembership, StoredEpisodeRelation,
    StoredIdentityWorkflowSlice, StoredProblemEpisode,
};
use crate::fen::*;
use crate::flows::IdentityWorkflowSlice;
use crate::identity::AccessDecisionResult;
use crate::materialized::{materialize_identity_state, MaterializedIdentityState};
use crate::policy::PolicyEvaluation;
use crate::workflows::{EpisodeRelation, ProblemEpisode};
pub use fen_store::*;

/// The identity crate's own payload family: the existing `Fact`,
/// `FactPayload`, and `FactPayloadType` label enum, with labels unchanged so
/// stored rows, associated-data bytes, and golden fixtures stay identical.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdentityPayloadFamily;

impl PayloadFamily for IdentityPayloadFamily {
    type Fact = Fact;
    type Payload = FactPayload;
    type PayloadType = FactPayloadType;

    fn payload_type_label(payload_type: Self::PayloadType) -> &'static str {
        payload_type.as_str()
    }

    fn payload_type_from_label(label: &str) -> Option<Self::PayloadType> {
        FactPayloadType::from_str_label(label)
    }

    fn payload_type_of_payload(payload: &Self::Payload) -> Self::PayloadType {
        FactPayloadType::from_payload(payload)
    }

    fn payload_type_variants() -> &'static [Self::PayloadType] {
        FactPayloadType::ALL
    }

    fn fact_id(fact: &Self::Fact) -> &FactId {
        &fact.id
    }

    fn subject_id(fact: &Self::Fact) -> &SubjectId {
        &fact.subject_id
    }

    fn occurred_at(fact: &Self::Fact) -> &TemporalAnchor {
        &fact.occurred_at
    }

    fn status(fact: &Self::Fact) -> &FactStatus {
        &fact.status
    }

    fn plaintext_from_fact(fact: &Self::Fact) -> EncryptedFactPlaintextOf<Self::Payload> {
        EncryptedFactPlaintext::from_fact(fact)
    }

    fn fact_from_plaintext(
        plaintext: EncryptedFactPlaintextOf<Self::Payload>,
        envelope: &StoredEncryptedFactEnvelope<Self::PayloadType>,
    ) -> Self::Fact {
        plaintext.into_fact(envelope)
    }
}

pub type StoredEncryptedFact = StoredEncryptedFactEnvelope<FactPayloadType>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactPayloadType {
    Measurement,
    Prescription,
    Procedure,
    Diagnosis,
    Document,
    Coverage,
    Claim,
    SubjectCreated,
    IdentityAttributeAsserted,
    IdentityWitnessRecorded,
    BiometricEnrollmentReferenceAdded,
    BiometricContinuityCheck,
    ContinuityVerificationRejected,
    DeviceBindingEstablished,
    DeviceBindingRevoked,
    CredentialAssertion,
    ClinicalIdentityLinkEstablished,
    ClinicalIdentityLinkContested,
    ClinicalIdentityLinkDisputeResolved,
    PayerIdentityLinkEstablished,
    PayerIdentityLinkContested,
    PayerIdentityLinkDisputeResolved,
    DuplicateSubjectMergeRecorded,
    IncorrectMergeSplitRecorded,
    IdentityWitnessSuperseded,
    AuthorityRelationshipEstablished,
    AuthorityRelationshipRevoked,
    AccountRecoveryEvent,
    RiskEvaluationEvent,
    AccessDecision,
}

impl FactPayloadType {
    pub fn from_payload(payload: &FactPayload) -> Self {
        match payload {
            FactPayload::Measurement => Self::Measurement,
            FactPayload::Prescription => Self::Prescription,
            FactPayload::Procedure => Self::Procedure,
            FactPayload::Diagnosis => Self::Diagnosis,
            FactPayload::Document => Self::Document,
            FactPayload::Coverage => Self::Coverage,
            FactPayload::Claim => Self::Claim,
            FactPayload::SubjectCreated { .. } => Self::SubjectCreated,
            FactPayload::IdentityAttributeAsserted { .. } => Self::IdentityAttributeAsserted,
            FactPayload::IdentityWitnessRecorded { .. } => Self::IdentityWitnessRecorded,
            FactPayload::BiometricEnrollmentReferenceAdded { .. } => {
                Self::BiometricEnrollmentReferenceAdded
            }
            FactPayload::BiometricContinuityCheck { .. } => Self::BiometricContinuityCheck,
            FactPayload::ContinuityVerificationRejected { .. } => {
                Self::ContinuityVerificationRejected
            }
            FactPayload::DeviceBindingEstablished { .. } => Self::DeviceBindingEstablished,
            FactPayload::DeviceBindingRevoked { .. } => Self::DeviceBindingRevoked,
            FactPayload::CredentialAssertion { .. } => Self::CredentialAssertion,
            FactPayload::ClinicalIdentityLinkEstablished { .. } => {
                Self::ClinicalIdentityLinkEstablished
            }
            FactPayload::ClinicalIdentityLinkContested { .. } => {
                Self::ClinicalIdentityLinkContested
            }
            FactPayload::ClinicalIdentityLinkDisputeResolved { .. } => {
                Self::ClinicalIdentityLinkDisputeResolved
            }
            FactPayload::PayerIdentityLinkEstablished { .. } => Self::PayerIdentityLinkEstablished,
            FactPayload::PayerIdentityLinkContested { .. } => Self::PayerIdentityLinkContested,
            FactPayload::PayerIdentityLinkDisputeResolved { .. } => {
                Self::PayerIdentityLinkDisputeResolved
            }
            FactPayload::DuplicateSubjectMergeRecorded { .. } => {
                Self::DuplicateSubjectMergeRecorded
            }
            FactPayload::IncorrectMergeSplitRecorded { .. } => Self::IncorrectMergeSplitRecorded,
            FactPayload::IdentityWitnessSuperseded { .. } => Self::IdentityWitnessSuperseded,
            FactPayload::AuthorityRelationshipEstablished { .. } => {
                Self::AuthorityRelationshipEstablished
            }
            FactPayload::AuthorityRelationshipRevoked { .. } => Self::AuthorityRelationshipRevoked,
            FactPayload::AccountRecoveryEvent { .. } => Self::AccountRecoveryEvent,
            FactPayload::RiskEvaluationEvent { .. } => Self::RiskEvaluationEvent,
            FactPayload::AccessDecision { .. } => Self::AccessDecision,
        }
    }

    /// Every variant of this closed label enum, in declaration order.
    ///
    /// Keep in sync with the enum; `payload_type_labels_are_closed_and_stable`
    /// in `tests/postgres_adapter.rs` pins the length and label round-trip so
    /// an added variant cannot silently miss this list.
    pub const ALL: &'static [Self] = &[
        Self::Measurement,
        Self::Prescription,
        Self::Procedure,
        Self::Diagnosis,
        Self::Document,
        Self::Coverage,
        Self::Claim,
        Self::SubjectCreated,
        Self::IdentityAttributeAsserted,
        Self::IdentityWitnessRecorded,
        Self::BiometricEnrollmentReferenceAdded,
        Self::BiometricContinuityCheck,
        Self::ContinuityVerificationRejected,
        Self::DeviceBindingEstablished,
        Self::DeviceBindingRevoked,
        Self::CredentialAssertion,
        Self::ClinicalIdentityLinkEstablished,
        Self::ClinicalIdentityLinkContested,
        Self::ClinicalIdentityLinkDisputeResolved,
        Self::PayerIdentityLinkEstablished,
        Self::PayerIdentityLinkContested,
        Self::PayerIdentityLinkDisputeResolved,
        Self::DuplicateSubjectMergeRecorded,
        Self::IncorrectMergeSplitRecorded,
        Self::IdentityWitnessSuperseded,
        Self::AuthorityRelationshipEstablished,
        Self::AuthorityRelationshipRevoked,
        Self::AccountRecoveryEvent,
        Self::RiskEvaluationEvent,
        Self::AccessDecision,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measurement => "measurement",
            Self::Prescription => "prescription",
            Self::Procedure => "procedure",
            Self::Diagnosis => "diagnosis",
            Self::Document => "document",
            Self::Coverage => "coverage",
            Self::Claim => "claim",
            Self::SubjectCreated => "subject_created",
            Self::IdentityAttributeAsserted => "identity_attribute_asserted",
            Self::IdentityWitnessRecorded => "identity_witness_recorded",
            Self::BiometricEnrollmentReferenceAdded => "biometric_enrollment_reference_added",
            Self::BiometricContinuityCheck => "biometric_continuity_check",
            Self::ContinuityVerificationRejected => "continuity_verification_rejected",
            Self::DeviceBindingEstablished => "device_binding_established",
            Self::DeviceBindingRevoked => "device_binding_revoked",
            Self::CredentialAssertion => "credential_assertion",
            Self::ClinicalIdentityLinkEstablished => "clinical_identity_link_established",
            Self::ClinicalIdentityLinkContested => "clinical_identity_link_contested",
            Self::ClinicalIdentityLinkDisputeResolved => "clinical_identity_link_dispute_resolved",
            Self::PayerIdentityLinkEstablished => "payer_identity_link_established",
            Self::PayerIdentityLinkContested => "payer_identity_link_contested",
            Self::PayerIdentityLinkDisputeResolved => "payer_identity_link_dispute_resolved",
            Self::DuplicateSubjectMergeRecorded => "duplicate_subject_merge_recorded",
            Self::IncorrectMergeSplitRecorded => "incorrect_merge_split_recorded",
            Self::IdentityWitnessSuperseded => "identity_witness_superseded",
            Self::AuthorityRelationshipEstablished => "authority_relationship_established",
            Self::AuthorityRelationshipRevoked => "authority_relationship_revoked",
            Self::AccountRecoveryEvent => "account_recovery_event",
            Self::RiskEvaluationEvent => "risk_evaluation_event",
            Self::AccessDecision => "access_decision",
        }
    }

    pub fn from_str_label(value: &str) -> Option<Self> {
        let payload_type = match value {
            "measurement" => Self::Measurement,
            "prescription" => Self::Prescription,
            "procedure" => Self::Procedure,
            "diagnosis" => Self::Diagnosis,
            "document" => Self::Document,
            "coverage" => Self::Coverage,
            "claim" => Self::Claim,
            "subject_created" => Self::SubjectCreated,
            "identity_attribute_asserted" => Self::IdentityAttributeAsserted,
            "identity_witness_recorded" => Self::IdentityWitnessRecorded,
            "biometric_enrollment_reference_added" => Self::BiometricEnrollmentReferenceAdded,
            "biometric_continuity_check" => Self::BiometricContinuityCheck,
            "continuity_verification_rejected" => Self::ContinuityVerificationRejected,
            "device_binding_established" => Self::DeviceBindingEstablished,
            "device_binding_revoked" => Self::DeviceBindingRevoked,
            "credential_assertion" => Self::CredentialAssertion,
            "clinical_identity_link_established" => Self::ClinicalIdentityLinkEstablished,
            "clinical_identity_link_contested" => Self::ClinicalIdentityLinkContested,
            "clinical_identity_link_dispute_resolved" => Self::ClinicalIdentityLinkDisputeResolved,
            "payer_identity_link_established" => Self::PayerIdentityLinkEstablished,
            "payer_identity_link_contested" => Self::PayerIdentityLinkContested,
            "payer_identity_link_dispute_resolved" => Self::PayerIdentityLinkDisputeResolved,
            "duplicate_subject_merge_recorded" => Self::DuplicateSubjectMergeRecorded,
            "incorrect_merge_split_recorded" => Self::IncorrectMergeSplitRecorded,
            "identity_witness_superseded" => Self::IdentityWitnessSuperseded,
            "authority_relationship_established" => Self::AuthorityRelationshipEstablished,
            "authority_relationship_revoked" => Self::AuthorityRelationshipRevoked,
            "account_recovery_event" => Self::AccountRecoveryEvent,
            "risk_evaluation_event" => Self::RiskEvaluationEvent,
            "access_decision" => Self::AccessDecision,
            _ => return None,
        };
        Some(payload_type)
    }
}

/// Fact plaintext carried inside the ciphertext, generic over the payload
/// type of a [`PayloadFamily`]. The identity-specialized alias keeps the
/// existing public API (`EncryptedFactPlaintext`) unchanged.
pub type EncryptedFactPlaintext = EncryptedFactPlaintextOf<FactPayload>;

/// Compatibility extension for the identity payload specialization.
pub trait IdentityEncryptedFactPlaintextExt {
    fn from_fact(fact: &Fact) -> Self;
    fn into_fact(self, envelope: &StoredEncryptedFact) -> Fact;
}

impl IdentityEncryptedFactPlaintextExt for EncryptedFactPlaintextOf<FactPayload> {
    fn from_fact(fact: &Fact) -> Self {
        Self {
            code: fact.code.clone(),
            payload: fact.payload.clone(),
            provenance: fact.provenance.clone(),
            external_refs: fact.external_refs.clone(),
        }
    }

    fn into_fact(self, envelope: &StoredEncryptedFact) -> Fact {
        Fact {
            id: envelope.fact_id.clone(),
            subject_id: envelope.subject_id.clone(),
            occurred_at: envelope.occurred_at.clone(),
            code: self.code,
            payload: self.payload,
            status: envelope.status.clone(),
            provenance: self.provenance,
            external_refs: self.external_refs,
        }
    }
}

/// Identity-specialized compatibility surface over the store codec contract.
pub trait EncryptedFactPlaintextCodec<P = FactPayload>:
    fen_store::EncryptedFactPlaintextCodec<P>
{
}

impl<P, T> EncryptedFactPlaintextCodec<P> for T where T: fen_store::EncryptedFactPlaintextCodec<P> {}

/// Identity-specialized compatibility surface over the store encryptor.
pub trait FactPayloadEncryptor<P = FactPayload>: fen_store::FactPayloadEncryptor<P> {}

impl<P, T> FactPayloadEncryptor<P> for T where T: fen_store::FactPayloadEncryptor<P> {}

pub type InMemoryEncryptedFactPlaintextCodec<P = FactPayload> =
    fen_store::InMemoryEncryptedFactPlaintextCodec<P>;
pub type DeterministicTestFactEncryptor<C = InMemoryEncryptedFactPlaintextCodec<FactPayload>> =
    fen_store::DeterministicTestFactEncryptor<C>;

#[cfg(feature = "production-crypto")]
pub type RingAes256GcmFactEncryptor<C = InMemoryEncryptedFactPlaintextCodec<FactPayload>> =
    fen_store::RingAes256GcmFactEncryptor<C>;

pub trait EncryptedFactRepository {
    fn append_encrypted_fact(
        &mut self,
        envelope: StoredEncryptedFact,
    ) -> Result<(), RepositoryError>;
    fn all_encrypted_facts(&self) -> Vec<StoredEncryptedFact>;
    fn encrypted_facts_for_subject(&self, subject_id: &SubjectId) -> Vec<StoredEncryptedFact>;
}

/// In-memory envelope store, generalized over payload families exactly like
/// the envelope itself ([`StoredEncryptedFactEnvelope`]): sibling families
/// share the duplicate-fact-id and duplicate-append-sequence discipline
/// instead of reimplementing it. The identity-family alias
/// ([`InMemoryEncryptedFactRepository`]) keeps the existing public API
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryEncryptedFactEnvelopeRepository<T> {
    store: fen_store::InMemoryEncryptedEnvelopeStore<T>,
}

pub type InMemoryEncryptedFactRepository = InMemoryEncryptedFactEnvelopeRepository<FactPayloadType>;

impl<T> Default for InMemoryEncryptedFactEnvelopeRepository<T> {
    fn default() -> Self {
        Self {
            store: fen_store::InMemoryEncryptedEnvelopeStore::new(),
        }
    }
}

impl<T> InMemoryEncryptedFactEnvelopeRepository<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_encrypted_fact_envelope(
        &mut self,
        envelope: StoredEncryptedFactEnvelope<T>,
    ) -> Result<(), RepositoryError> {
        self.store.append(envelope).map_err(|error| match error {
            EncryptedFactStoreError::DuplicateFactId => RepositoryError::DuplicateFactId,
            EncryptedFactStoreError::DuplicateAppendSequence => {
                RepositoryError::DuplicateAppendSequence
            }
        })
    }
}

impl<T: Clone> InMemoryEncryptedFactEnvelopeRepository<T> {
    pub fn all_encrypted_fact_envelopes(&self) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.store.all()
    }

    pub fn encrypted_fact_envelopes_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.store.for_subject(subject_id)
    }
}

impl EncryptedFactRepository for InMemoryEncryptedFactRepository {
    fn append_encrypted_fact(
        &mut self,
        envelope: StoredEncryptedFact,
    ) -> Result<(), RepositoryError> {
        self.append_encrypted_fact_envelope(envelope)
    }

    fn all_encrypted_facts(&self) -> Vec<StoredEncryptedFact> {
        self.all_encrypted_fact_envelopes()
    }

    fn encrypted_facts_for_subject(&self, subject_id: &SubjectId) -> Vec<StoredEncryptedFact> {
        self.encrypted_fact_envelopes_for_subject(subject_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionAwareWorkflowRepository<R, M, E> {
    storage: R,
    metadata_planner: M,
    encryptor: E,
    key: FactDataEncryptionKey,
    materialization_policy_refs: Vec<PolicyRef>,
    sequence_state: EncryptedWorkflowAppendSequenceState,
}

impl<R, M, E> EncryptionAwareWorkflowRepository<R, M, E> {
    pub fn new(
        storage: R,
        metadata_planner: M,
        encryptor: E,
        key: FactDataEncryptionKey,
        materialization_policy_refs: Vec<PolicyRef>,
        sequence_state: EncryptedWorkflowAppendSequenceState,
    ) -> Self {
        Self {
            storage,
            metadata_planner,
            encryptor,
            key,
            materialization_policy_refs,
            sequence_state,
        }
    }

    pub fn storage(&self) -> &R {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut R {
        &mut self.storage
    }

    pub fn sequence_state(&self) -> EncryptedWorkflowAppendSequenceState {
        self.sequence_state
    }
}

impl<R, M, E> EncryptionAwareWorkflowRepository<R, M, E>
where
    R: StoredEncryptedWorkflowRepository,
    M: FactEncryptionMetadataPlanner,
    E: FactPayloadEncryptor,
{
    pub fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredIdentityWorkflowSlice, EncryptionAwareWorkflowRepositoryError> {
        let sequence_plan = self.sequence_state.plan_for_slice(&slice);
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

        self.storage
            .append_stored_workflow_slice(stored.clone())
            .map_err(EncryptionAwareWorkflowRepositoryError::Repository)?;
        self.sequence_state.advance_by_plan(&sequence_plan);

        Ok(stored)
    }

    pub fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
        transaction_id: PersistenceTransactionId,
        committed_at: Timestamp,
    ) -> Result<StoredEpisodeComposition, EncryptionAwareWorkflowRepositoryError> {
        let sequence_plan = self
            .sequence_state
            .plan_for_episode_composition(&child_slices, &episode_relations);
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

        self.storage
            .append_stored_episode_composition(stored.clone())
            .map_err(EncryptionAwareWorkflowRepositoryError::Repository)?;
        self.sequence_state
            .advance_by_composition_plan(&sequence_plan);

        Ok(stored)
    }

    pub fn materialize_subject_facts(
        &self,
        subject_id: &SubjectId,
        policy_evaluation: &PolicyEvaluation,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<Vec<Fact>, FactMaterializationError> {
        materialize_encrypted_facts(
            &self.storage.encrypted_facts_for_subject(subject_id),
            policy_evaluation,
            key_resolver,
            &self.encryptor,
        )
    }

    pub fn replay_identity_state(
        &self,
        subject_id: SubjectId,
        policy_evaluation: &PolicyEvaluation,
        key_resolver: &impl FactKeyResolver,
    ) -> Result<MaterializedIdentityState, FactMaterializationError> {
        let facts = self.materialize_subject_facts(&subject_id, policy_evaluation, key_resolver)?;
        Ok(materialize_identity_state(subject_id, &facts))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedWorkflowAppendSequenceState {
    pub next_fact_append_sequence: AppendSequence,
    pub next_episode_append_sequence: AppendSequence,
    pub next_membership_append_sequence: AppendSequence,
    pub next_relation_append_sequence: AppendSequence,
}

impl EncryptedWorkflowAppendSequenceState {
    pub fn new(
        next_fact_append_sequence: AppendSequence,
        next_episode_append_sequence: AppendSequence,
        next_membership_append_sequence: AppendSequence,
    ) -> Self {
        Self {
            next_fact_append_sequence,
            next_episode_append_sequence,
            next_membership_append_sequence,
            next_relation_append_sequence: 0,
        }
    }

    pub fn with_relation_append_sequence(
        next_fact_append_sequence: AppendSequence,
        next_episode_append_sequence: AppendSequence,
        next_membership_append_sequence: AppendSequence,
        next_relation_append_sequence: AppendSequence,
    ) -> Self {
        Self {
            next_fact_append_sequence,
            next_episode_append_sequence,
            next_membership_append_sequence,
            next_relation_append_sequence,
        }
    }

    pub fn plan_for_slice(
        &self,
        slice: &IdentityWorkflowSlice,
    ) -> EncryptedWorkflowAppendSequencePlan {
        EncryptedWorkflowAppendSequencePlan {
            fact_append_sequence_start: self.next_fact_append_sequence,
            episode_append_sequence: self.next_episode_append_sequence,
            membership_append_sequence_start: self.next_membership_append_sequence,
            fact_count: slice.facts.len(),
            membership_count: slice.memberships.len(),
        }
    }

    pub fn plan_for_episode_composition(
        &self,
        child_slices: &[IdentityWorkflowSlice],
        episode_relations: &[EpisodeRelation],
    ) -> EncryptedEpisodeCompositionAppendSequencePlan {
        let mut fact_sequence_start = self.next_fact_append_sequence;
        let mut episode_sequence = self.next_episode_append_sequence + 1;
        let mut membership_sequence_start = self.next_membership_append_sequence;
        let child_slice_plans = child_slices
            .iter()
            .map(|slice| {
                let plan = EncryptedWorkflowAppendSequencePlan {
                    fact_append_sequence_start: fact_sequence_start,
                    episode_append_sequence: episode_sequence,
                    membership_append_sequence_start: membership_sequence_start,
                    fact_count: slice.facts.len(),
                    membership_count: slice.memberships.len(),
                };
                fact_sequence_start += plan.fact_count as AppendSequence;
                episode_sequence += 1;
                membership_sequence_start += plan.membership_count as AppendSequence;
                plan
            })
            .collect();

        EncryptedEpisodeCompositionAppendSequencePlan {
            parent_episode_append_sequence: self.next_episode_append_sequence,
            child_slice_plans,
            relation_append_sequence_start: self.next_relation_append_sequence,
            relation_count: episode_relations.len(),
        }
    }

    pub fn advance_by_plan(&mut self, plan: &EncryptedWorkflowAppendSequencePlan) {
        self.next_fact_append_sequence += plan.fact_count as AppendSequence;
        self.next_episode_append_sequence += 1;
        self.next_membership_append_sequence += plan.membership_count as AppendSequence;
    }

    pub fn advance_by_composition_plan(
        &mut self,
        plan: &EncryptedEpisodeCompositionAppendSequencePlan,
    ) {
        self.next_fact_append_sequence += plan.fact_count() as AppendSequence;
        self.next_episode_append_sequence += 1 + plan.child_slice_plans.len() as AppendSequence;
        self.next_membership_append_sequence += plan.membership_count() as AppendSequence;
        self.next_relation_append_sequence += plan.relation_count as AppendSequence;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedWorkflowAppendSequencePlan {
    pub fact_append_sequence_start: AppendSequence,
    pub episode_append_sequence: AppendSequence,
    pub membership_append_sequence_start: AppendSequence,
    pub fact_count: usize,
    pub membership_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEpisodeCompositionAppendSequencePlan {
    pub parent_episode_append_sequence: AppendSequence,
    pub child_slice_plans: Vec<EncryptedWorkflowAppendSequencePlan>,
    pub relation_append_sequence_start: AppendSequence,
    pub relation_count: usize,
}

impl EncryptedEpisodeCompositionAppendSequencePlan {
    pub fn fact_count(&self) -> usize {
        self.child_slice_plans
            .iter()
            .map(|plan| plan.fact_count)
            .sum()
    }

    pub fn membership_count(&self) -> usize {
        self.child_slice_plans
            .iter()
            .map(|plan| plan.membership_count)
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAwareWorkflowRepositoryError {
    Encryption(FactEncryptionError),
    Repository(RepositoryError),
}

impl From<FactEncryptionError> for EncryptionAwareWorkflowRepositoryError {
    fn from(error: FactEncryptionError) -> Self {
        Self::Encryption(error)
    }
}

pub trait FactEncryptionMetadataPlanner<F: PayloadFamily = IdentityPayloadFamily> {
    fn metadata_for_fact(
        &mut self,
        fact: &F::Fact,
        append_sequence: AppendSequence,
    ) -> FactEncryptionMetadata;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicTestFactEncryptionMetadataPlanner {
    key_id: FactEncryptionKeyId,
    nonce_prefix: String,
}

impl DeterministicTestFactEncryptionMetadataPlanner {
    pub fn new(key_id: impl Into<FactEncryptionKeyId>, nonce_prefix: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            nonce_prefix: nonce_prefix.into(),
        }
    }
}

impl<F: PayloadFamily> FactEncryptionMetadataPlanner<F>
    for DeterministicTestFactEncryptionMetadataPlanner
{
    fn metadata_for_fact(
        &mut self,
        fact: &F::Fact,
        append_sequence: AppendSequence,
    ) -> FactEncryptionMetadata {
        FactEncryptionMetadata::deterministic_test(
            self.key_id.clone(),
            format!(
                "{}:{}:{}",
                self.nonce_prefix,
                append_sequence,
                F::fact_id(fact).0
            )
            .into_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aes256GcmFactEncryptionMetadataPlanner {
    key_id: FactEncryptionKeyId,
    nonce_domain: [u8; 4],
    wrapped_dek_ref: Option<String>,
}

impl Aes256GcmFactEncryptionMetadataPlanner {
    pub fn new(
        key_id: impl Into<FactEncryptionKeyId>,
        nonce_domain: [u8; 4],
        wrapped_dek_ref: Option<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            nonce_domain,
            wrapped_dek_ref,
        }
    }
}

impl<F: PayloadFamily> FactEncryptionMetadataPlanner<F> for Aes256GcmFactEncryptionMetadataPlanner {
    fn metadata_for_fact(
        &mut self,
        _fact: &F::Fact,
        append_sequence: AppendSequence,
    ) -> FactEncryptionMetadata {
        let mut nonce = Vec::with_capacity(12);
        nonce.extend_from_slice(&self.nonce_domain);
        nonce.extend_from_slice(&append_sequence.to_be_bytes());
        FactEncryptionMetadata::aes_256_gcm(
            self.key_id.clone(),
            nonce,
            self.wrapped_dek_ref.clone(),
        )
    }
}

pub trait StoredEncryptedWorkflowRepository {
    fn append_stored_workflow_slice(
        &mut self,
        workflow_slice: StoredIdentityWorkflowSlice,
    ) -> Result<(), RepositoryError>;
    fn append_stored_episode_composition(
        &mut self,
        composition: StoredEpisodeComposition,
    ) -> Result<(), RepositoryError>;
    fn encrypted_facts_for_subject(&self, subject_id: &SubjectId) -> Vec<StoredEncryptedFact>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryStoredEncryptedWorkflowRepository {
    workflow_slices: Vec<StoredIdentityWorkflowSlice>,
    episode_compositions: Vec<StoredEpisodeComposition>,
}

impl InMemoryStoredEncryptedWorkflowRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn workflow_slices(&self) -> Vec<StoredIdentityWorkflowSlice> {
        self.workflow_slices.clone()
    }

    pub fn episode_compositions(&self) -> Vec<StoredEpisodeComposition> {
        self.episode_compositions.clone()
    }

    pub fn all_encrypted_facts(&self) -> Vec<StoredEncryptedFact> {
        let mut facts: Vec<StoredEncryptedFact> = self
            .workflow_slices
            .iter()
            .flat_map(|slice| slice.encrypted_facts.clone())
            .chain(self.episode_compositions.iter().flat_map(|composition| {
                composition
                    .child_slices
                    .iter()
                    .flat_map(|slice| slice.encrypted_facts.clone())
            }))
            .collect();
        facts.sort_by_key(|fact| fact.append_sequence);
        facts
    }
}

impl StoredEncryptedWorkflowRepository for InMemoryStoredEncryptedWorkflowRepository {
    fn append_stored_workflow_slice(
        &mut self,
        workflow_slice: StoredIdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        self.validate_workflow_slice_append(&workflow_slice)?;
        self.workflow_slices.push(workflow_slice);
        Ok(())
    }

    fn append_stored_episode_composition(
        &mut self,
        composition: StoredEpisodeComposition,
    ) -> Result<(), RepositoryError> {
        self.validate_episode_composition_append(&composition)?;
        self.episode_compositions.push(composition);
        Ok(())
    }

    fn encrypted_facts_for_subject(&self, subject_id: &SubjectId) -> Vec<StoredEncryptedFact> {
        self.all_encrypted_facts()
            .into_iter()
            .filter(|fact| &fact.subject_id == subject_id)
            .collect()
    }
}

impl InMemoryStoredEncryptedWorkflowRepository {
    fn stored_slices(&self) -> impl Iterator<Item = &StoredIdentityWorkflowSlice> {
        self.workflow_slices.iter().chain(
            self.episode_compositions
                .iter()
                .flat_map(|composition| composition.child_slices.iter()),
        )
    }

    fn stored_parent_episodes(&self) -> impl Iterator<Item = &StoredProblemEpisode> {
        self.episode_compositions
            .iter()
            .map(|composition| &composition.parent_episode)
    }

    fn stored_relations(&self) -> impl Iterator<Item = &StoredEpisodeRelation> {
        self.episode_compositions
            .iter()
            .flat_map(|composition| composition.episode_relations.iter())
    }

    fn validate_workflow_slice_append(
        &self,
        workflow_slice: &StoredIdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        if self
            .stored_slices()
            .map(|slice| &slice.episode)
            .chain(self.stored_parent_episodes())
            .any(|existing| existing.episode.id == workflow_slice.episode.episode.id)
        {
            return Err(RepositoryError::DuplicateEpisodeId);
        }

        for (index, fact) in workflow_slice.encrypted_facts.iter().enumerate() {
            if self
                .stored_slices()
                .flat_map(|slice| &slice.encrypted_facts)
                .any(|existing| existing.fact_id == fact.fact_id)
                || workflow_slice.encrypted_facts[..index]
                    .iter()
                    .any(|existing| existing.fact_id == fact.fact_id)
            {
                return Err(RepositoryError::DuplicateFactId);
            }
            if self
                .stored_slices()
                .flat_map(|slice| &slice.encrypted_facts)
                .any(|existing| existing.append_sequence == fact.append_sequence)
                || workflow_slice.encrypted_facts[..index]
                    .iter()
                    .any(|existing| existing.append_sequence == fact.append_sequence)
            {
                return Err(RepositoryError::DuplicateAppendSequence);
            }
        }

        for (index, membership) in workflow_slice.memberships.iter().enumerate() {
            if self
                .stored_slices()
                .flat_map(|slice| &slice.memberships)
                .any(|existing| existing.membership.id == membership.membership.id)
                || workflow_slice.memberships[..index]
                    .iter()
                    .any(|existing| existing.membership.id == membership.membership.id)
            {
                return Err(RepositoryError::DuplicateMembershipId);
            }
            if self
                .stored_slices()
                .flat_map(|slice| &slice.memberships)
                .any(|existing| existing.append_sequence == membership.append_sequence)
                || workflow_slice.memberships[..index]
                    .iter()
                    .any(|existing| existing.append_sequence == membership.append_sequence)
            {
                return Err(RepositoryError::DuplicateAppendSequence);
            }
        }

        Ok(())
    }

    fn validate_episode_composition_append(
        &self,
        composition: &StoredEpisodeComposition,
    ) -> Result<(), RepositoryError> {
        if self
            .stored_slices()
            .map(|slice| &slice.episode)
            .chain(self.stored_parent_episodes())
            .any(|existing| existing.episode.id == composition.parent_episode.episode.id)
        {
            return Err(RepositoryError::DuplicateEpisodeId);
        }

        for (slice_index, slice) in composition.child_slices.iter().enumerate() {
            if slice.episode.episode.id == composition.parent_episode.episode.id
                || self
                    .stored_slices()
                    .map(|existing_slice| &existing_slice.episode)
                    .chain(self.stored_parent_episodes())
                    .any(|existing| existing.episode.id == slice.episode.episode.id)
                || composition.child_slices[..slice_index]
                    .iter()
                    .any(|existing| existing.episode.episode.id == slice.episode.episode.id)
            {
                return Err(RepositoryError::DuplicateEpisodeId);
            }

            for (fact_index, fact) in slice.encrypted_facts.iter().enumerate() {
                if self
                    .stored_slices()
                    .flat_map(|existing_slice| &existing_slice.encrypted_facts)
                    .any(|existing| existing.fact_id == fact.fact_id)
                    || slice.encrypted_facts[..fact_index]
                        .iter()
                        .any(|existing| existing.fact_id == fact.fact_id)
                    || composition.child_slices[..slice_index]
                        .iter()
                        .flat_map(|previous_slice| &previous_slice.encrypted_facts)
                        .any(|existing| existing.fact_id == fact.fact_id)
                {
                    return Err(RepositoryError::DuplicateFactId);
                }
                if self
                    .stored_slices()
                    .flat_map(|existing_slice| &existing_slice.encrypted_facts)
                    .any(|existing| existing.append_sequence == fact.append_sequence)
                    || slice.encrypted_facts[..fact_index]
                        .iter()
                        .any(|existing| existing.append_sequence == fact.append_sequence)
                    || composition.child_slices[..slice_index]
                        .iter()
                        .flat_map(|previous_slice| &previous_slice.encrypted_facts)
                        .any(|existing| existing.append_sequence == fact.append_sequence)
                {
                    return Err(RepositoryError::DuplicateAppendSequence);
                }
            }

            for (membership_index, membership) in slice.memberships.iter().enumerate() {
                if self
                    .stored_slices()
                    .flat_map(|existing_slice| &existing_slice.memberships)
                    .any(|existing| existing.membership.id == membership.membership.id)
                    || slice.memberships[..membership_index]
                        .iter()
                        .any(|existing| existing.membership.id == membership.membership.id)
                    || composition.child_slices[..slice_index]
                        .iter()
                        .flat_map(|previous_slice| &previous_slice.memberships)
                        .any(|existing| existing.membership.id == membership.membership.id)
                {
                    return Err(RepositoryError::DuplicateMembershipId);
                }
                if self
                    .stored_slices()
                    .flat_map(|existing_slice| &existing_slice.memberships)
                    .any(|existing| existing.append_sequence == membership.append_sequence)
                    || slice.memberships[..membership_index]
                        .iter()
                        .any(|existing| existing.append_sequence == membership.append_sequence)
                    || composition.child_slices[..slice_index]
                        .iter()
                        .flat_map(|previous_slice| &previous_slice.memberships)
                        .any(|existing| existing.append_sequence == membership.append_sequence)
                {
                    return Err(RepositoryError::DuplicateAppendSequence);
                }
            }
        }

        for (relation_index, relation) in composition.episode_relations.iter().enumerate() {
            if self
                .stored_relations()
                .any(|existing| existing.relation.id == relation.relation.id)
                || composition.episode_relations[..relation_index]
                    .iter()
                    .any(|existing| existing.relation.id == relation.relation.id)
            {
                return Err(RepositoryError::DuplicateRelationId);
            }
            if self
                .stored_relations()
                .any(|existing| existing.append_sequence == relation.append_sequence)
                || composition.episode_relations[..relation_index]
                    .iter()
                    .any(|existing| existing.append_sequence == relation.append_sequence)
            {
                return Err(RepositoryError::DuplicateAppendSequence);
            }
        }

        Ok(())
    }
}

pub fn encrypt_fact_envelope(
    fact: &Fact,
    append_sequence: AppendSequence,
    transaction_id: PersistenceTransactionId,
    committed_at: Timestamp,
    materialization_policy_refs: Vec<PolicyRef>,
    encryption: FactEncryptionMetadata,
    key: &FactDataEncryptionKey,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<StoredEncryptedFact, FactEncryptionError> {
    encrypt_fact_envelope_in_family::<IdentityPayloadFamily>(
        fact,
        append_sequence,
        transaction_id,
        committed_at,
        materialization_policy_refs,
        encryption,
        key,
        encryptor,
    )
}

pub fn encrypt_fact_envelope_in_family<F: PayloadFamily>(
    fact: &F::Fact,
    append_sequence: AppendSequence,
    transaction_id: PersistenceTransactionId,
    committed_at: Timestamp,
    materialization_policy_refs: Vec<PolicyRef>,
    encryption: FactEncryptionMetadata,
    key: &FactDataEncryptionKey,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
) -> Result<StoredEncryptedFactEnvelope<F::PayloadType>, FactEncryptionError> {
    fen_store::encrypt_fact_envelope_in_family::<F>(
        fact,
        append_sequence,
        transaction_id,
        committed_at,
        materialization_policy_refs,
        encryption,
        key,
        encryptor,
    )
}

pub fn build_stored_encrypted_workflow_slice(
    slice: IdentityWorkflowSlice,
    transaction_id: PersistenceTransactionId,
    committed_at: Timestamp,
    sequence_plan: &EncryptedWorkflowAppendSequencePlan,
    materialization_policy_refs: Vec<PolicyRef>,
    key: &FactDataEncryptionKey,
    metadata_planner: &mut impl FactEncryptionMetadataPlanner,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<StoredIdentityWorkflowSlice, FactEncryptionError> {
    let encrypted_facts = slice
        .facts
        .iter()
        .enumerate()
        .map(|(index, fact)| {
            let append_sequence =
                sequence_plan.fact_append_sequence_start + index as AppendSequence;
            let encryption = metadata_planner.metadata_for_fact(fact, append_sequence);
            encrypt_fact_envelope(
                fact,
                append_sequence,
                transaction_id.clone(),
                committed_at.clone(),
                materialization_policy_refs.clone(),
                encryption,
                key,
                encryptor,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let memberships = slice
        .memberships
        .into_iter()
        .enumerate()
        .map(|(index, membership)| StoredEpisodeMembership {
            append_sequence: sequence_plan.membership_append_sequence_start
                + index as AppendSequence,
            transaction_id: transaction_id.clone(),
            committed_at: committed_at.clone(),
            membership,
        })
        .collect();

    Ok(StoredIdentityWorkflowSlice {
        transaction_id: transaction_id.clone(),
        committed_at: committed_at.clone(),
        episode: StoredProblemEpisode {
            append_sequence: sequence_plan.episode_append_sequence,
            transaction_id,
            committed_at,
            episode: slice.episode,
        },
        encrypted_facts,
        memberships,
    })
}

pub fn build_stored_encrypted_episode_composition(
    parent_episode: ProblemEpisode,
    child_slices: Vec<IdentityWorkflowSlice>,
    episode_relations: Vec<EpisodeRelation>,
    transaction_id: PersistenceTransactionId,
    committed_at: Timestamp,
    sequence_plan: &EncryptedEpisodeCompositionAppendSequencePlan,
    materialization_policy_refs: Vec<PolicyRef>,
    key: &FactDataEncryptionKey,
    metadata_planner: &mut impl FactEncryptionMetadataPlanner,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<StoredEpisodeComposition, FactEncryptionError> {
    let child_slices = child_slices
        .into_iter()
        .zip(sequence_plan.child_slice_plans.iter())
        .map(|(slice, child_plan)| {
            build_stored_encrypted_workflow_slice(
                slice,
                transaction_id.clone(),
                committed_at.clone(),
                child_plan,
                materialization_policy_refs.clone(),
                key,
                metadata_planner,
                encryptor,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let episode_relations = episode_relations
        .into_iter()
        .enumerate()
        .map(|(index, relation)| StoredEpisodeRelation {
            append_sequence: sequence_plan.relation_append_sequence_start + index as AppendSequence,
            transaction_id: transaction_id.clone(),
            committed_at: committed_at.clone(),
            relation,
        })
        .collect();

    Ok(StoredEpisodeComposition {
        transaction_id: transaction_id.clone(),
        committed_at: committed_at.clone(),
        parent_episode: StoredProblemEpisode {
            append_sequence: sequence_plan.parent_episode_append_sequence,
            transaction_id,
            committed_at,
            episode: parent_episode,
        },
        child_slices,
        episode_relations,
    })
}

pub fn materialize_encrypted_fact(
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<Fact, FactMaterializationError> {
    materialize_encrypted_fact_in_family::<IdentityPayloadFamily>(
        envelope,
        policy_evaluation,
        key_resolver,
        encryptor,
    )
}

/// Policy-gated, audited decryption of an encrypted fact envelope of an
/// arbitrary [`PayloadFamily`]. Mirrors [`encrypt_fact_envelope_in_family`]:
/// the policy, key-access, and audit machinery is family-agnostic, while the
/// AAD, the payload-type cross-check, and the fact reconstruction go through
/// `F`. The identity-specialized [`materialize_encrypted_fact`] delegates
/// here with [`IdentityPayloadFamily`].
pub fn materialize_encrypted_fact_in_family<F: PayloadFamily>(
    envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
) -> Result<F::Fact, FactMaterializationError> {
    fen_store::materialize_encrypted_fact_in_family::<F>(
        envelope,
        &store_materialization_authorization(policy_evaluation),
        key_resolver,
        encryptor,
    )
}

pub fn materialize_encrypted_fact_with_audit(
    envelope: &StoredEncryptedFact,
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
) -> Result<Fact, FactMaterializationError> {
    materialize_encrypted_fact_with_audit_in_family::<IdentityPayloadFamily>(
        envelope,
        policy_evaluation,
        key_resolver,
        encryptor,
        audit_context,
        audit_sink,
    )
}

pub fn materialize_encrypted_fact_with_audit_in_family<F: PayloadFamily>(
    envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
) -> Result<F::Fact, FactMaterializationError> {
    fen_store::materialize_encrypted_fact_with_audit_in_family::<F>(
        envelope,
        &store_materialization_authorization(policy_evaluation),
        key_resolver,
        encryptor,
        audit_context,
        audit_sink,
    )
}

pub fn materialize_encrypted_facts(
    envelopes: &[StoredEncryptedFact],
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor,
) -> Result<Vec<Fact>, FactMaterializationError> {
    materialize_encrypted_facts_in_family::<IdentityPayloadFamily>(
        envelopes,
        policy_evaluation,
        key_resolver,
        encryptor,
    )
}

pub fn materialize_encrypted_facts_in_family<F: PayloadFamily>(
    envelopes: &[StoredEncryptedFactEnvelope<F::PayloadType>],
    policy_evaluation: &PolicyEvaluation,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
) -> Result<Vec<F::Fact>, FactMaterializationError> {
    fen_store::materialize_encrypted_facts_in_family::<F>(
        envelopes,
        &store_materialization_authorization(policy_evaluation),
        key_resolver,
        encryptor,
    )
}

pub fn canonical_encrypted_fact_associated_data(envelope: &StoredEncryptedFact) -> Vec<u8> {
    canonical_encrypted_fact_associated_data_in_family::<IdentityPayloadFamily>(envelope)
}

/// Canonical associated-data bytes for an encrypted fact envelope of an
/// arbitrary [`PayloadFamily`]. The only family-specific field is the payload
/// type label, resolved through `F::payload_type_label`. For
/// [`IdentityPayloadFamily`] that label is exactly `FactPayloadType::as_str`,
/// so identity AAD bytes — and every stored row, tag, and golden fixture that
/// depends on them — stay byte-for-byte identical.
pub fn canonical_encrypted_fact_associated_data_in_family<F: PayloadFamily>(
    envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
) -> Vec<u8> {
    fen_store::canonical_encrypted_fact_associated_data_in_family::<F>(envelope)
}

fn store_materialization_authorization(
    policy_evaluation: &PolicyEvaluation,
) -> MaterializationAuthorization {
    let policy_refs = policy_evaluation.policy_refs.clone();
    if policy_evaluation.decision == AccessDecisionResult::Allowed {
        MaterializationAuthorization::authorized(policy_refs)
    } else {
        MaterializationAuthorization::denied(policy_refs)
    }
}
