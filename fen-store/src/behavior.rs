use crate::{
    AppendSequence, EncryptedFactPlaintextOf, EncryptedFactStoreError, FactDataEncryptionKey,
    FactEncryptionAlgorithm, FactEncryptionError, FactEncryptionMetadata, FactKeyResolver,
    FactKeyStatus, FactMaterializationAuditContext, FactMaterializationAuditEvent,
    FactMaterializationAuditOutcome, FactMaterializationAuditSink, FactMaterializationError,
    MaterializationAuthorization, PayloadFamily, PersistenceTransactionId,
    StoredEncryptedFactEnvelope, ENCRYPTED_FACT_AAD_PROFILE_NAME,
    ENCRYPTED_FACT_AAD_PROFILE_VERSION_V1,
};
use fen_core::{
    Author, AuthorType, FactStatus, PolicyRef, SubjectId, SupersessionReason, TemporalAnchor,
    Timestamp,
};
use std::cell::RefCell;
use std::collections::BTreeMap;

const ENCRYPTED_FACT_SCHEMA_VERSION_V1: &str = "fact-v1";

pub trait EncryptedFactPlaintextCodec<P> {
    fn encode_fact_plaintext(&self, plaintext: &EncryptedFactPlaintextOf<P>) -> Vec<u8>;

    fn decode_fact_plaintext(
        &self,
        encoded: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<P>, FactMaterializationError>;
}

#[derive(Debug)]
pub struct InMemoryEncryptedFactPlaintextCodec<P> {
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

pub trait FactPayloadEncryptor<P> {
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
pub struct DeterministicTestFactEncryptor<C> {
    codec: C,
}

impl<P> DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec<P>> {
    pub fn new() -> Self {
        Self::with_codec(InMemoryEncryptedFactPlaintextCodec::new())
    }
}

impl<P> Default for DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec<P>> {
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
pub struct RingAes256GcmFactEncryptor<C> {
    codec: C,
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

/// Generic in-memory append-only store for encrypted envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryEncryptedEnvelopeStore<T> {
    encrypted_facts: Vec<StoredEncryptedFactEnvelope<T>>,
}

impl<T> Default for InMemoryEncryptedEnvelopeStore<T> {
    fn default() -> Self {
        Self {
            encrypted_facts: Vec::new(),
        }
    }
}

impl<T> InMemoryEncryptedEnvelopeStore<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(
        &mut self,
        envelope: StoredEncryptedFactEnvelope<T>,
    ) -> Result<(), EncryptedFactStoreError> {
        if self
            .encrypted_facts
            .iter()
            .any(|existing| existing.fact_id == envelope.fact_id)
        {
            return Err(EncryptedFactStoreError::DuplicateFactId);
        }
        if self
            .encrypted_facts
            .iter()
            .any(|existing| existing.append_sequence == envelope.append_sequence)
        {
            return Err(EncryptedFactStoreError::DuplicateAppendSequence);
        }

        self.encrypted_facts.push(envelope);
        self.encrypted_facts
            .sort_by_key(|envelope| envelope.append_sequence);
        Ok(())
    }
}

impl<T: Clone> InMemoryEncryptedEnvelopeStore<T> {
    pub fn all(&self) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.encrypted_facts.clone()
    }

    pub fn for_subject(&self, subject_id: &SubjectId) -> Vec<StoredEncryptedFactEnvelope<T>> {
        self.encrypted_facts
            .iter()
            .filter(|envelope| &envelope.subject_id == subject_id)
            .cloned()
            .collect()
    }
}

// The explicit fields make envelope construction auditable at the call site
// and preserve the existing public contract used by sibling payload families.
#[allow(clippy::too_many_arguments)]
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

pub fn materialize_encrypted_fact_in_family<F: PayloadFamily>(
    envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    authorization: &MaterializationAuthorization,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
) -> Result<F::Fact, FactMaterializationError> {
    let mut audit_sink = crate::NoopFactMaterializationAuditSink;
    materialize_encrypted_fact_with_audit_in_family::<F>(
        envelope,
        authorization,
        key_resolver,
        encryptor,
        &FactMaterializationAuditContext::default(),
        &mut audit_sink,
    )
}

pub fn materialize_encrypted_fact_with_audit_in_family<F: PayloadFamily>(
    envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    authorization: &MaterializationAuthorization,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
) -> Result<F::Fact, FactMaterializationError> {
    record_audit_event(
        envelope,
        authorization,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::Attempted,
        None,
    );

    if !authorization.is_authorized() {
        return fail_materialization(
            envelope,
            authorization,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::PolicyDenied,
        );
    }
    if !envelope
        .materialization_policy_refs
        .iter()
        .all(|required| authorization.policy_refs.contains(required))
    {
        return fail_materialization(
            envelope,
            authorization,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::PolicyDenied,
            FactMaterializationError::MaterializationPolicyRefsNotSatisfied,
        );
    }

    record_audit_event(
        envelope,
        authorization,
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
                authorization,
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
            authorization,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::KeyAccessFailed,
            FactMaterializationError::RetiredKey,
        );
    }
    record_audit_event(
        envelope,
        authorization,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::KeyAccessSucceeded,
        None,
    );

    record_audit_event(
        envelope,
        authorization,
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
                authorization,
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
            authorization,
            audit_context,
            audit_sink,
            FactMaterializationAuditOutcome::DecryptionFailed,
            FactMaterializationError::AuthenticationFailed,
        );
    }

    record_audit_event(
        envelope,
        authorization,
        audit_context,
        audit_sink,
        FactMaterializationAuditOutcome::Succeeded,
        None,
    );
    Ok(F::fact_from_plaintext(plaintext, envelope))
}

pub fn materialize_encrypted_facts_in_family<F: PayloadFamily>(
    envelopes: &[StoredEncryptedFactEnvelope<F::PayloadType>],
    authorization: &MaterializationAuthorization,
    key_resolver: &impl FactKeyResolver,
    encryptor: &impl FactPayloadEncryptor<F::Payload>,
) -> Result<Vec<F::Fact>, FactMaterializationError> {
    envelopes
        .iter()
        .map(|envelope| {
            materialize_encrypted_fact_in_family::<F>(
                envelope,
                authorization,
                key_resolver,
                encryptor,
            )
        })
        .collect()
}

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
    authorization: &MaterializationAuthorization,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
    outcome: FactMaterializationAuditOutcome,
    error: Option<FactMaterializationError>,
) {
    audit_sink.record_materialization_event(FactMaterializationAuditEvent {
        subject_id: envelope.subject_id.clone(),
        fact_ids: vec![envelope.fact_id.clone()],
        materialization_policy_refs: envelope.materialization_policy_refs.clone(),
        evaluated_policy_refs: authorization.policy_refs.clone(),
        caller: audit_context.caller.clone(),
        purpose: audit_context.purpose.clone(),
        requested_at: audit_context.requested_at.clone(),
        outcome,
        error,
    });
}

fn fail_materialization<PT, T>(
    envelope: &StoredEncryptedFactEnvelope<PT>,
    authorization: &MaterializationAuthorization,
    audit_context: &FactMaterializationAuditContext,
    audit_sink: &mut impl FactMaterializationAuditSink,
    outcome: FactMaterializationAuditOutcome,
    error: FactMaterializationError,
) -> Result<T, FactMaterializationError> {
    record_audit_event(
        envelope,
        authorization,
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
        FactStatus::Active => push_field(&mut canonical, "kind", "active"),
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
