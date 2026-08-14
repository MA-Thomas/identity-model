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
use std::cell::RefCell;
use std::collections::BTreeMap;

pub type AppendSequence = u64;
typed_id!(PersistenceTransactionId);
pub type FactEncryptionKeyId = String;

pub const ENCRYPTED_FACT_AAD_PROFILE_NAME: &str = "fen-encrypted-fact";
pub const ENCRYPTED_FACT_AAD_PROFILE_VERSION_V1: &str = "v1";
const ENCRYPTED_FACT_SCHEMA_VERSION_V1: &str = "fact-v1";

/// A payload family that can live in the encrypted envelope store.
///
/// The envelope tables are payload-agnostic (`payload_type` label, policy
/// refs, append sequence, ciphertext). What is family-specific is the label
/// namespace and the codec-facing fact/payload types. The identity crate
/// implements this with its existing `Fact`/`FactPayload`/`FactPayloadType`;
/// sibling families (e.g. `fen-health-econ` with `health_econ.*` labels)
/// implement it with their own fact shape, reusing the same envelope
/// machinery, episodes, memberships, and policy-gated materialization
/// (FEN_HEALTH_ECON_EXTENSIONS.md).
pub trait PayloadFamily {
    /// Semantic fact type of this family.
    type Fact: Clone;
    /// Payload carried inside the ciphertext.
    type Payload: Clone + PartialEq + std::fmt::Debug;
    /// Closed payload-type label enum with stable string labels. `'static`
    /// because durable adapters hold the family's variant list as a
    /// `&'static` slice ([`Self::payload_type_variants`]).
    type PayloadType: Copy + Eq + std::fmt::Debug + 'static;

    fn payload_type_label(payload_type: Self::PayloadType) -> &'static str;
    fn payload_type_from_label(label: &str) -> Option<Self::PayloadType>;
    fn payload_type_of_payload(payload: &Self::Payload) -> Self::PayloadType;
    /// Every payload-type variant of this family's closed label enum.
    ///
    /// Sibling families share the payload-agnostic envelope tables, so
    /// durable adapters scope family-typed queries to exactly this label set
    /// instead of guessing at label prefixes. A row whose label is outside
    /// every family's set remains a hard error, not a silently skipped row.
    fn payload_type_variants() -> &'static [Self::PayloadType];

    fn fact_id(fact: &Self::Fact) -> &FactId;
    fn subject_id(fact: &Self::Fact) -> &SubjectId;
    fn occurred_at(fact: &Self::Fact) -> &TemporalAnchor;
    fn status(fact: &Self::Fact) -> &FactStatus;

    fn plaintext_from_fact(fact: &Self::Fact) -> EncryptedFactPlaintextOf<Self::Payload>;
    fn fact_from_plaintext(
        plaintext: EncryptedFactPlaintextOf<Self::Payload>,
        envelope: &StoredEncryptedFactEnvelope<Self::PayloadType>,
    ) -> Self::Fact;
}

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

/// Stored encrypted fact envelope, generic over the payload-type label enum
/// of a [`PayloadFamily`]. The identity-specialized alias keeps the crate's
/// existing public API (`StoredEncryptedFact`) unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEncryptedFactEnvelope<T> {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub fact_id: FactId,
    pub subject_id: SubjectId,
    pub occurred_at: TemporalAnchor,
    pub payload_type: T,
    pub status: FactStatus,
    pub materialization_policy_refs: Vec<PolicyRef>,
    pub encryption: FactEncryptionMetadata,
    pub ciphertext: Vec<u8>,
}

pub type StoredEncryptedFact = StoredEncryptedFactEnvelope<FactPayloadType>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactEncryptionMetadata {
    pub algorithm: FactEncryptionAlgorithm,
    pub key_id: FactEncryptionKeyId,
    pub wrapped_dek_ref: Option<String>,
    pub nonce: Vec<u8>,
    pub aad_version: EncryptedFactAssociatedDataVersion,
}

impl FactEncryptionMetadata {
    pub fn deterministic_test(
        key_id: impl Into<FactEncryptionKeyId>,
        nonce: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm: FactEncryptionAlgorithm::DeterministicTest,
            key_id: key_id.into(),
            wrapped_dek_ref: None,
            nonce: nonce.into(),
            aad_version: EncryptedFactAssociatedDataVersion::V1,
        }
    }

    pub fn aes_256_gcm(
        key_id: impl Into<FactEncryptionKeyId>,
        nonce: impl Into<Vec<u8>>,
        wrapped_dek_ref: Option<String>,
    ) -> Self {
        Self {
            algorithm: FactEncryptionAlgorithm::Aes256Gcm,
            key_id: key_id.into(),
            wrapped_dek_ref,
            nonce: nonce.into(),
            aad_version: EncryptedFactAssociatedDataVersion::V1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactEncryptionAlgorithm {
    DeterministicTest,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFactAssociatedDataVersion {
    V1,
}

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

impl FactEncryptionAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicTest => "deterministic_test",
            Self::Aes256Gcm => "aes_256_gcm",
        }
    }

    pub fn from_str_label(value: &str) -> Option<Self> {
        match value {
            "deterministic_test" => Some(Self::DeterministicTest),
            "aes_256_gcm" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

impl EncryptedFactAssociatedDataVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }

    pub fn from_str_label(value: &str) -> Option<Self> {
        match value {
            "v1" => Some(Self::V1),
            _ => None,
        }
    }
}

/// Fact plaintext carried inside the ciphertext, generic over the payload
/// type of a [`PayloadFamily`]. The identity-specialized alias keeps the
/// existing public API (`EncryptedFactPlaintext`) unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFactPlaintextOf<P> {
    pub code: Option<CodedValue>,
    pub payload: P,
    pub provenance: Provenance,
    pub external_refs: Vec<ExternalRef>,
}

pub type EncryptedFactPlaintext = EncryptedFactPlaintextOf<FactPayload>;

impl EncryptedFactPlaintextOf<FactPayload> {
    pub fn from_fact(fact: &Fact) -> Self {
        Self {
            code: fact.code.clone(),
            payload: fact.payload.clone(),
            provenance: fact.provenance.clone(),
            external_refs: fact.external_refs.clone(),
        }
    }

    pub fn into_fact(self, envelope: &StoredEncryptedFact) -> Fact {
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

pub trait EncryptedFactPlaintextCodec<P = FactPayload> {
    fn encode_fact_plaintext(&self, plaintext: &EncryptedFactPlaintextOf<P>) -> Vec<u8>;

    fn decode_fact_plaintext(
        &self,
        encoded: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError>;
}

#[derive(Debug)]
pub struct InMemoryEncryptedFactPlaintextCodec<P = FactPayload> {
    plaintexts_by_encoded_bytes: RefCell<BTreeMap<Vec<u8>, EncryptedFactPlaintextOf<P>>>,
}

impl<P> Default for InMemoryEncryptedFactPlaintextCodec<P> {
    fn default() -> Self {
        Self {
            plaintexts_by_encoded_bytes: RefCell::new(BTreeMap::new()),
        }
    }
}

impl<P> InMemoryEncryptedFactPlaintextCodec<P> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<P: Clone + std::fmt::Debug> EncryptedFactPlaintextCodec<P>
    for InMemoryEncryptedFactPlaintextCodec<P>
{
    fn encode_fact_plaintext(&self, plaintext: &EncryptedFactPlaintextOf<P>) -> Vec<u8> {
        let encoded = format!("{plaintext:?}").into_bytes();
        self.plaintexts_by_encoded_bytes
            .borrow_mut()
            .insert(encoded.clone(), plaintext.clone());
        encoded
    }

    fn decode_fact_plaintext(
        &self,
        encoded: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError> {
        self.plaintexts_by_encoded_bytes
            .borrow()
            .get(encoded)
            .cloned()
            .ok_or(FactMaterializationError::PlaintextDecodeFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactDataEncryptionKey {
    pub key_id: FactEncryptionKeyId,
    pub key_material: Vec<u8>,
    pub status: FactKeyStatus,
}

impl FactDataEncryptionKey {
    pub fn active(
        key_id: impl Into<FactEncryptionKeyId>,
        key_material: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            key_material: key_material.into(),
            status: FactKeyStatus::Active,
        }
    }

    pub fn retired(
        key_id: impl Into<FactEncryptionKeyId>,
        key_material: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            key_material: key_material.into(),
            status: FactKeyStatus::Retired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKeyStatus {
    Active,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKeyAccessError {
    MissingKey,
}

pub trait FactKeyResolver {
    fn resolve_fact_key(
        &self,
        key_id: &FactEncryptionKeyId,
    ) -> Result<FactDataEncryptionKey, FactKeyAccessError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticFactKeyResolver {
    keys_by_id: BTreeMap<FactEncryptionKeyId, FactDataEncryptionKey>,
}

impl StaticFactKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_keys(keys: impl IntoIterator<Item = FactDataEncryptionKey>) -> Self {
        let mut resolver = Self::new();
        for key in keys {
            resolver.register(key);
        }
        resolver
    }

    pub fn register(&mut self, key: FactDataEncryptionKey) {
        self.keys_by_id.insert(key.key_id.clone(), key);
    }
}

impl FactKeyResolver for StaticFactKeyResolver {
    fn resolve_fact_key(
        &self,
        key_id: &FactEncryptionKeyId,
    ) -> Result<FactDataEncryptionKey, FactKeyAccessError> {
        self.keys_by_id
            .get(key_id)
            .cloned()
            .ok_or(FactKeyAccessError::MissingKey)
    }
}

pub trait FactPayloadEncryptor<P = FactPayload> {
    fn encrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        plaintext: &EncryptedFactPlaintextOf<P>,
    ) -> Result<Vec<u8>, FactEncryptionError>;

    fn decrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError>;
}

#[derive(Debug)]
pub struct DeterministicTestFactEncryptor<C = InMemoryEncryptedFactPlaintextCodec> {
    codec: C,
}

impl DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec> {
    pub fn new() -> Self {
        Self::with_codec(InMemoryEncryptedFactPlaintextCodec::new())
    }
}

impl Default for DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> DeterministicTestFactEncryptor<C> {
    pub fn with_codec(codec: C) -> Self {
        Self { codec }
    }

    fn authentication_tag(
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        encoded_plaintext: &[u8],
    ) -> u64 {
        fnv64([
            key.key_id.as_bytes(),
            key.key_material.as_slice(),
            encryption.nonce.as_slice(),
            associated_data,
            encoded_plaintext,
        ])
    }
}

impl<P, C: EncryptedFactPlaintextCodec<P>> FactPayloadEncryptor<P>
    for DeterministicTestFactEncryptor<C>
{
    fn encrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        plaintext: &EncryptedFactPlaintextOf<P>,
    ) -> Result<Vec<u8>, FactEncryptionError> {
        if encryption.algorithm != FactEncryptionAlgorithm::DeterministicTest {
            return Err(FactEncryptionError::UnsupportedAlgorithm);
        }

        let encoded_plaintext = self.codec.encode_fact_plaintext(plaintext);
        let tag = Self::authentication_tag(key, encryption, associated_data, &encoded_plaintext);
        let mut ciphertext = Vec::new();
        push_bytes(&mut ciphertext, b"fen-deterministic-test-encrypted-fact");
        push_bytes(&mut ciphertext, encryption.nonce.as_slice());
        push_u64(&mut ciphertext, tag);
        push_bytes(&mut ciphertext, &encoded_plaintext);
        Ok(ciphertext)
    }

    fn decrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError> {
        if encryption.algorithm != FactEncryptionAlgorithm::DeterministicTest {
            return Err(FactMaterializationError::UnsupportedAlgorithm);
        }

        let mut reader = CiphertextReader::new(ciphertext);
        let header = reader.read_bytes()?;
        if header != b"fen-deterministic-test-encrypted-fact" {
            return Err(FactMaterializationError::AuthenticationFailed);
        }
        let nonce = reader.read_bytes()?;
        if nonce != encryption.nonce {
            return Err(FactMaterializationError::AuthenticationFailed);
        }
        let observed_tag = reader.read_u64()?;
        let encoded_plaintext = reader.read_bytes()?;
        if !reader.is_finished() {
            return Err(FactMaterializationError::AuthenticationFailed);
        }

        let expected_tag =
            Self::authentication_tag(key, encryption, associated_data, &encoded_plaintext);
        if observed_tag != expected_tag {
            return Err(FactMaterializationError::AuthenticationFailed);
        }

        self.codec.decode_fact_plaintext(&encoded_plaintext)
    }
}

#[cfg(feature = "production-crypto")]
#[derive(Debug)]
pub struct RingAes256GcmFactEncryptor<C = InMemoryEncryptedFactPlaintextCodec> {
    codec: C,
}

#[cfg(feature = "production-crypto")]
impl RingAes256GcmFactEncryptor<InMemoryEncryptedFactPlaintextCodec> {
    pub fn new() -> Self {
        Self::with_codec(InMemoryEncryptedFactPlaintextCodec::new())
    }
}

#[cfg(feature = "production-crypto")]
impl Default for RingAes256GcmFactEncryptor<InMemoryEncryptedFactPlaintextCodec> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "production-crypto")]
impl<C> RingAes256GcmFactEncryptor<C> {
    pub fn with_codec(codec: C) -> Self {
        Self { codec }
    }
}

#[cfg(feature = "production-crypto")]
impl<P, C: EncryptedFactPlaintextCodec<P>> FactPayloadEncryptor<P>
    for RingAes256GcmFactEncryptor<C>
{
    fn encrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        plaintext: &EncryptedFactPlaintextOf<P>,
    ) -> Result<Vec<u8>, FactEncryptionError> {
        if encryption.algorithm != FactEncryptionAlgorithm::Aes256Gcm {
            return Err(FactEncryptionError::UnsupportedAlgorithm);
        }
        if key.key_material.len() != 32 {
            return Err(FactEncryptionError::InvalidKeyMaterial);
        }
        if encryption.nonce.len() != 12 {
            return Err(FactEncryptionError::InvalidNonce);
        }

        let unbound_key =
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key.key_material.as_slice())
                .map_err(|_| FactEncryptionError::InvalidKeyMaterial)?;
        let sealing_key = ring::aead::LessSafeKey::new(unbound_key);
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(encryption.nonce.as_slice())
            .map_err(|_| FactEncryptionError::InvalidNonce)?;
        let mut in_out = self.codec.encode_fact_plaintext(plaintext);
        sealing_key
            .seal_in_place_append_tag(nonce, ring::aead::Aad::from(associated_data), &mut in_out)
            .map_err(|_| FactEncryptionError::EncryptionFailed)?;
        Ok(in_out)
    }

    fn decrypt_fact_plaintext(
        &self,
        key: &FactDataEncryptionKey,
        encryption: &FactEncryptionMetadata,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError> {
        if encryption.algorithm != FactEncryptionAlgorithm::Aes256Gcm {
            return Err(FactMaterializationError::UnsupportedAlgorithm);
        }
        if key.key_material.len() != 32 {
            return Err(FactMaterializationError::InvalidKeyMaterial);
        }
        if encryption.nonce.len() != 12 {
            return Err(FactMaterializationError::InvalidNonce);
        }

        let unbound_key =
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key.key_material.as_slice())
                .map_err(|_| FactMaterializationError::InvalidKeyMaterial)?;
        let opening_key = ring::aead::LessSafeKey::new(unbound_key);
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(encryption.nonce.as_slice())
            .map_err(|_| FactMaterializationError::InvalidNonce)?;
        let mut in_out = ciphertext.to_vec();
        let encoded_plaintext = opening_key
            .open_in_place(nonce, ring::aead::Aad::from(associated_data), &mut in_out)
            .map_err(|_| FactMaterializationError::AuthenticationFailed)?;
        self.codec.decode_fact_plaintext(encoded_plaintext)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactEncryptionError {
    KeyIdMismatch,
    KeyNotActive,
    UnsupportedAlgorithm,
    InvalidKeyMaterial,
    InvalidNonce,
    EncryptionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactMaterializationError {
    PolicyDenied,
    MaterializationPolicyRefsNotSatisfied,
    MissingKey,
    RetiredKey,
    AuthenticationFailed,
    PlaintextDecodeFailed,
    UnsupportedAlgorithm,
    InvalidKeyMaterial,
    InvalidNonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactMaterializationAuditOutcome {
    Attempted,
    PolicyDenied,
    KeyAccessAttempted,
    KeyAccessSucceeded,
    KeyAccessFailed,
    DecryptionAttempted,
    DecryptionFailed,
    Succeeded,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactMaterializationAuditContext {
    pub caller: Option<String>,
    pub purpose: Option<String>,
    pub requested_at: Option<Timestamp>,
}

impl FactMaterializationAuditContext {
    pub fn new(
        caller: Option<String>,
        purpose: Option<String>,
        requested_at: Option<Timestamp>,
    ) -> Self {
        Self {
            caller,
            purpose,
            requested_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactMaterializationAuditEvent {
    pub subject_id: SubjectId,
    pub fact_ids: Vec<FactId>,
    pub materialization_policy_refs: Vec<PolicyRef>,
    pub evaluated_policy_refs: Vec<PolicyRef>,
    pub caller: Option<String>,
    pub purpose: Option<String>,
    pub requested_at: Option<Timestamp>,
    pub outcome: FactMaterializationAuditOutcome,
    pub error: Option<FactMaterializationError>,
}

pub trait FactMaterializationAuditSink {
    fn record_materialization_event(&mut self, event: FactMaterializationAuditEvent);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryFactMaterializationAuditLog {
    events: Vec<FactMaterializationAuditEvent>,
}

impl InMemoryFactMaterializationAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<FactMaterializationAuditEvent> {
        self.events.clone()
    }
}

impl FactMaterializationAuditSink for InMemoryFactMaterializationAuditLog {
    fn record_materialization_event(&mut self, event: FactMaterializationAuditEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopFactMaterializationAuditSink;

impl FactMaterializationAuditSink for NoopFactMaterializationAuditSink {
    fn record_materialization_event(&mut self, _event: FactMaterializationAuditEvent) {}
}

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
    encrypted_facts: Vec<StoredEncryptedFactEnvelope<T>>,
}

pub type InMemoryEncryptedFactRepository =
    InMemoryEncryptedFactEnvelopeRepository<FactPayloadType>;

impl<T> Default for InMemoryEncryptedFactEnvelopeRepository<T> {
    fn default() -> Self {
        Self {
            encrypted_facts: Vec::new(),
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
        if self
            .encrypted_facts
            .iter()
            .any(|existing| existing.fact_id == envelope.fact_id)
        {
            return Err(RepositoryError::DuplicateFactId);
        }
        if self
            .encrypted_facts
            .iter()
            .any(|existing| existing.append_sequence == envelope.append_sequence)
        {
            return Err(RepositoryError::DuplicateAppendSequence);
        }

        self.encrypted_facts.push(envelope);
        self.encrypted_facts
            .sort_by_key(|envelope| envelope.append_sequence);
        Ok(())
    }
}

impl<T: Clone> InMemoryEncryptedFactEnvelopeRepository<T> {
    pub fn all_encrypted_fact_envelopes(&self) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.encrypted_facts.clone()
    }

    pub fn encrypted_fact_envelopes_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.encrypted_facts
            .iter()
            .filter(|envelope| &envelope.subject_id == subject_id)
            .cloned()
            .collect()
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
    if encryption.key_id != key.key_id {
        return Err(FactEncryptionError::KeyIdMismatch);
    }
    if key.status != FactKeyStatus::Active {
        return Err(FactEncryptionError::KeyNotActive);
    }

    let plaintext = F::plaintext_from_fact(fact);
    let mut envelope = StoredEncryptedFactEnvelope {
        append_sequence,
        transaction_id,
        committed_at,
        fact_id: F::fact_id(fact).clone(),
        subject_id: F::subject_id(fact).clone(),
        occurred_at: F::occurred_at(fact).clone(),
        payload_type: F::payload_type_of_payload(&plaintext.payload),
        status: F::status(fact).clone(),
        materialization_policy_refs,
        encryption,
        ciphertext: Vec::new(),
    };
    let associated_data = canonical_encrypted_fact_associated_data_in_family::<F>(&envelope);
    envelope.ciphertext = encryptor.encrypt_fact_plaintext(
        key,
        &envelope.encryption,
        &associated_data,
        &plaintext,
    )?;
    Ok(envelope)
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
    let mut audit_sink = NoopFactMaterializationAuditSink;
    materialize_encrypted_fact_with_audit_in_family::<F>(
        envelope,
        policy_evaluation,
        key_resolver,
        encryptor,
        &FactMaterializationAuditContext::default(),
        &mut audit_sink,
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
    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::Attempted,
        None,
    );

    if policy_evaluation.decision != AccessDecisionResult::Allowed {
        return fail_materialization(
            envelope,
            policy_evaluation,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::PolicyDenied,
        );
    }
    if !envelope
        .materialization_policy_refs
        .iter()
        .all(|required| policy_evaluation.policy_refs.contains(required))
    {
        return fail_materialization(
            envelope,
            policy_evaluation,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::MaterializationPolicyRefsNotSatisfied,
        );
    }

    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::KeyAccessAttempted,
        None,
    );
    let key = match key_resolver.resolve_fact_key(&envelope.encryption.key_id) {
        Ok(key) => key,
        Err(_) => {
            return fail_materialization(
                envelope,
                policy_evaluation,
                audit_context,
                audit_sink,
                FactMaterializationAuditOutcome::KeyAccessFailed,
                FactMaterializationError::MissingKey,
            );
        }
    };
    if key.status != FactKeyStatus::Active {
        return fail_materialization(
            envelope,
            policy_evaluation,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::KeyAccessFailed,
            FactMaterializationError::RetiredKey,
        );
    }
    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::KeyAccessSucceeded,
        None,
    );

    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::DecryptionAttempted,
        None,
    );
    let associated_data = canonical_encrypted_fact_associated_data_in_family::<F>(envelope);
    let plaintext = match encryptor.decrypt_fact_plaintext(
        &key,
        &envelope.encryption,
        &associated_data,
        &envelope.ciphertext,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            return fail_materialization(
                envelope,
                policy_evaluation,
                audit_context,
                audit_sink,
                FactMaterializationAuditOutcome::DecryptionFailed,
                error,
            );
        }
    };
    if F::payload_type_of_payload(&plaintext.payload) != envelope.payload_type {
        return fail_materialization(
            envelope,
            policy_evaluation,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::DecryptionFailed,
            FactMaterializationError::AuthenticationFailed,
        );
    }

    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::Succeeded,
        None,
    );
    Ok(F::fact_from_plaintext(plaintext, envelope))
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
    envelopes
        .iter()
        .map(|envelope| {
            materialize_encrypted_fact_in_family::<F>(
                envelope,
                policy_evaluation,
                key_resolver,
                encryptor,
            )
        })
        .collect()
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
    let mut canonical = String::new();
    push_field(&mut canonical, "profile", ENCRYPTED_FACT_AAD_PROFILE_NAME);
    push_field(
        &mut canonical,
        "profile_version",
        ENCRYPTED_FACT_AAD_PROFILE_VERSION_V1,
    );
    push_field(
        &mut canonical,
        "aad_version",
        envelope.encryption.aad_version.as_str(),
    );
    push_field(
        &mut canonical,
        "schema_version",
        ENCRYPTED_FACT_SCHEMA_VERSION_V1,
    );
    push_field(
        &mut canonical,
        "append_sequence",
        &envelope.append_sequence.to_string(),
    );
    push_field(&mut canonical, "transaction_id", &envelope.transaction_id.0);
    push_field(&mut canonical, "committed_at", &envelope.committed_at.0);
    push_field(&mut canonical, "fact_id", &envelope.fact_id.0);
    push_field(&mut canonical, "subject_id", &envelope.subject_id.0);
    push_field(
        &mut canonical,
        "occurred_at",
        &canonical_temporal_anchor(&envelope.occurred_at),
    );
    push_field(
        &mut canonical,
        "payload_type",
        F::payload_type_label(envelope.payload_type),
    );
    push_field(
        &mut canonical,
        "status",
        &canonical_fact_status(&envelope.status),
    );
    push_field(
        &mut canonical,
        "materialization_policy_refs",
        &canonical_policy_refs(&envelope.materialization_policy_refs),
    );
    push_field(
        &mut canonical,
        "encryption_algorithm",
        envelope.encryption.algorithm.as_str(),
    );
    push_field(&mut canonical, "key_id", &envelope.encryption.key_id);
    push_field(
        &mut canonical,
        "wrapped_dek_ref",
        envelope.encryption.wrapped_dek_ref.as_deref().unwrap_or(""),
    );
    push_field(
        &mut canonical,
        "nonce",
        &canonical_bytes(&envelope.encryption.nonce),
    );

    canonical.into_bytes()
}

fn record_audit_event<PT>(
    envelope: &StoredEncryptedFactEnvelope<PT>,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
    outcome: FactMaterializationAuditOutcome,
    error: Option<FactMaterializationError>,
) {
    audit_sink.record_materialization_event(FactMaterializationAuditEvent {
        subject_id: envelope.subject_id.clone(),
        fact_ids: vec![envelope.fact_id.clone()],
        materialization_policy_refs: envelope.materialization_policy_refs.clone(),
        evaluated_policy_refs: policy_evaluation.policy_refs.clone(),
        caller: audit_context.caller.clone(),
        purpose: audit_context.purpose.clone(),
        requested_at: audit_context.requested_at.clone(),
        outcome,
        error,
    });
}

fn fail_materialization<PT, T>(
    envelope: &StoredEncryptedFactEnvelope<PT>,
    policy_evaluation: &PolicyEvaluation,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
    outcome: FactMaterializationAuditOutcome,
    error: FactMaterializationError,
) -> Result<T, FactMaterializationError> {
    record_audit_event(
        envelope,
        policy_evaluation,
        audit_context,
        audit_sink,
        outcome,
        Some(error),
    );
    Err(error)
}

fn push_field(target: &mut String, name: &str, value: &str) {
    target.push_str(name);
    target.push('=');
    target.push_str(&value.len().to_string());
    target.push(':');
    target.push_str(value);
    target.push('\n');
}

fn canonical_temporal_anchor(anchor: &TemporalAnchor) -> String {
    let mut canonical = String::new();
    match anchor {
        TemporalAnchor::Point(timestamp) => {
            push_field(&mut canonical, "kind", "point");
            push_field(&mut canonical, "timestamp", &timestamp.0);
        }
        TemporalAnchor::Period(period) => {
            push_field(&mut canonical, "kind", "period");
            push_field(&mut canonical, "start", &period.start.0);
            push_field(&mut canonical, "end", &period.end.0);
        }
    }
    canonical
}

fn canonical_fact_status(status: &FactStatus) -> String {
    let mut canonical = String::new();
    match status {
        FactStatus::Active => {
            push_field(&mut canonical, "kind", "active");
        }
        FactStatus::Superseded {
            superseded_by,
            superseded_at,
            replaced_by,
            reason,
        } => {
            push_field(&mut canonical, "kind", "superseded");
            push_field(
                &mut canonical,
                "superseded_by",
                &canonical_author(superseded_by),
            );
            push_field(
                &mut canonical,
                "superseded_at",
                &canonical_temporal_anchor(superseded_at),
            );
            push_field(
                &mut canonical,
                "replaced_by",
                replaced_by.as_ref().map(|id| id.0.as_str()).unwrap_or(""),
            );
            push_field(&mut canonical, "reason", supersession_reason_label(reason));
        }
        FactStatus::EnteredInError {
            corrected_by,
            corrected_at,
            replaced_by,
        } => {
            push_field(&mut canonical, "kind", "entered_in_error");
            push_field(
                &mut canonical,
                "corrected_by",
                &canonical_author(corrected_by),
            );
            push_field(
                &mut canonical,
                "corrected_at",
                &canonical_temporal_anchor(corrected_at),
            );
            push_field(
                &mut canonical,
                "replaced_by",
                replaced_by.as_ref().map(|id| id.0.as_str()).unwrap_or(""),
            );
        }
    }
    canonical
}

fn canonical_author(author: &Author) -> String {
    let mut canonical = String::new();
    push_field(
        &mut canonical,
        "author_type",
        author_type_label(&author.author_type),
    );
    push_field(
        &mut canonical,
        "author_id",
        author
            .author_id
            .as_ref()
            .map(|id| id.0.as_str())
            .unwrap_or(""),
    );
    push_field(
        &mut canonical,
        "display_name",
        author.display_name.as_deref().unwrap_or(""),
    );
    canonical
}

fn canonical_policy_refs(policy_refs: &[PolicyRef]) -> String {
    let mut canonical = String::new();
    push_field(&mut canonical, "count", &policy_refs.len().to_string());
    for (index, policy_ref) in policy_refs.iter().enumerate() {
        push_field(
            &mut canonical,
            &format!("policy_ref_{index}"),
            &policy_ref.0,
        );
    }
    canonical
}

fn canonical_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn author_type_label(author_type: &AuthorType) -> &'static str {
    match author_type {
        AuthorType::Patient => "patient",
        AuthorType::Clinician => "clinician",
        AuthorType::System => "system",
        AuthorType::AiAssisted => "ai_assisted",
    }
}

fn supersession_reason_label(reason: &SupersessionReason) -> &'static str {
    match reason {
        SupersessionReason::AiEnrichment => "ai_enrichment",
        SupersessionReason::ClinicalRefinement => "clinical_refinement",
        SupersessionReason::StrongerIdentityEvidence => "stronger_identity_evidence",
        SupersessionReason::AdministrativeCorrection => "administrative_correction",
        SupersessionReason::RuleReEvaluation => "rule_re_evaluation",
    }
}

fn push_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

fn push_u64(target: &mut Vec<u8>, value: u64) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn fnv64<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for part in parts {
        for byte in (part.len() as u64).to_be_bytes().iter().chain(part.iter()) {
            state ^= u64::from(*byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    state
}

struct CiphertextReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CiphertextReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, FactMaterializationError> {
        let length = self.read_u64()? as usize;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FactMaterializationError::AuthenticationFailed)?;
        if end > self.bytes.len() {
            return Err(FactMaterializationError::AuthenticationFailed);
        }
        let value = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, FactMaterializationError> {
        let end = self
            .offset
            .checked_add(8)
            .ok_or(FactMaterializationError::AuthenticationFailed)?;
        let bytes: [u8; 8] = self
            .bytes
            .get(self.offset..end)
            .ok_or(FactMaterializationError::AuthenticationFailed)?
            .try_into()
            .map_err(|_| FactMaterializationError::AuthenticationFailed)?;
        self.offset = end;
        Ok(u64::from_be_bytes(bytes))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
