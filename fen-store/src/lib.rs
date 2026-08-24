//! Identity-neutral encrypted storage contracts for FEN payload families.
//!
//! This crate defines the durable envelope, payload-family boundary, key
//! interfaces, codecs, cryptographic behavior, append-only in-memory storage,
//! and materialization audit vocabulary. Domain policy engines, durable
//! database adapters, and application workflows live above it.

mod behavior;

pub use behavior::*;

use fen_core::{
    CodedValue, ExternalRef, FactId, FactStatus, PolicyRef, Provenance, SubjectId, TemporalAnchor,
    Timestamp,
};
use std::collections::BTreeMap;

pub type AppendSequence = u64;
pub type FactEncryptionKeyId = String;

pub const ENCRYPTED_FACT_AAD_PROFILE_NAME: &str = "fen-encrypted-fact";
pub const ENCRYPTED_FACT_AAD_PROFILE_VERSION_V1: &str = "v1";

/// Stable identifier for one durable persistence transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PersistenceTransactionId(pub String);

impl PersistenceTransactionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for PersistenceTransactionId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for PersistenceTransactionId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for PersistenceTransactionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PersistenceTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A semantic payload family that can live in the shared encrypted store.
pub trait PayloadFamily {
    type Fact: Clone;
    type Payload: Clone + PartialEq + std::fmt::Debug;
    type PayloadType: Copy + Eq + std::fmt::Debug + 'static;

    fn payload_type_label(payload_type: Self::PayloadType) -> &'static str;
    fn payload_type_from_label(label: &str) -> Option<Self::PayloadType>;
    fn payload_type_of_payload(payload: &Self::Payload) -> Self::PayloadType;
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

/// Payload-agnostic durable encrypted fact envelope.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFactAssociatedDataVersion {
    V1,
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

/// Fact plaintext carried inside ciphertext, generic over a family's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFactPlaintextOf<P> {
    pub code: Option<CodedValue>,
    pub payload: P,
    pub provenance: Provenance,
    pub external_refs: Vec<ExternalRef>,
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

/// The deliberately small authorization artifact accepted by encrypted
/// materialization. Domain policy engines translate their richer evaluations
/// into this type; the storage layer never needs to understand identity,
/// authority witnesses, sensitive actions, or policy-engine reason codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationAuthorization {
    pub decision: MaterializationAuthorizationDecision,
    pub policy_refs: Vec<PolicyRef>,
}

impl MaterializationAuthorization {
    pub fn authorized(policy_refs: Vec<PolicyRef>) -> Self {
        Self {
            decision: MaterializationAuthorizationDecision::Authorized,
            policy_refs,
        }
    }

    pub fn denied(policy_refs: Vec<PolicyRef>) -> Self {
        Self {
            decision: MaterializationAuthorizationDecision::Denied,
            policy_refs,
        }
    }

    pub fn is_authorized(&self) -> bool {
        self.decision == MaterializationAuthorizationDecision::Authorized
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationAuthorizationDecision {
    Authorized,
    Denied,
}

/// Failures produced by the identity-neutral append-only envelope store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFactStoreError {
    DuplicateFactId,
    DuplicateAppendSequence,
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
