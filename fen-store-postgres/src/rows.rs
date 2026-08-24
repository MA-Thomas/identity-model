use fen_core::{
    Author, AuthorId, AuthorType, FactId, FactStatus, PolicyRef, SubjectId, SupersessionReason,
    TemporalAnchor, TimeInterval, Timestamp,
};
use fen_store::{
    AppendSequence, EncryptedFactAssociatedDataVersion, EncryptedFactStoreError,
    FactEncryptionAlgorithm, FactEncryptionMetadata, FactMaterializationAuditEvent,
    FactMaterializationAuditOutcome, FactMaterializationError, PayloadFamily,
    PersistenceTransactionId, StoredEncryptedFactEnvelope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenStorePostgresError {
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
    StatusPayloadJson(String),
    Store(EncryptedFactStoreError),
    Sqlx(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFactPostgresRow {
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
    pub status_payload: FactStatusPostgresPayload,
    pub materialization_policy_refs: Vec<String>,
    pub encryption_algorithm: String,
    pub encryption_key_id: String,
    pub wrapped_dek_ref: Option<String>,
    pub nonce: Vec<u8>,
    pub aad_version: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactStatusPostgresPayload {
    Active,
    Superseded {
        superseded_by: AuthorPostgresRecord,
        superseded_at: TemporalAnchorPostgresRecord,
        replaced_by: Option<String>,
        reason: String,
    },
    EnteredInError {
        corrected_by: AuthorPostgresRecord,
        corrected_at: TemporalAnchorPostgresRecord,
        replaced_by: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AuthorPostgresRecord {
    pub author_type: String,
    pub author_id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TemporalAnchorPostgresRecord {
    pub kind: String,
    pub start: String,
    pub end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationAuditPostgresRow {
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

impl EncryptedFactPostgresRow {
    pub fn try_from_envelope_in_family<F: PayloadFamily>(
        envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    ) -> Result<Self, FenStorePostgresError> {
        let append_sequence = i64::try_from(envelope.append_sequence)
            .map_err(|_| FenStorePostgresError::AppendSequenceOutOfRange)?;
        let occurred_at = TemporalAnchorPostgresRecord::from_temporal_anchor(&envelope.occurred_at);
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
            payload_type: F::payload_type_label(envelope.payload_type).to_string(),
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

    pub fn try_into_envelope_in_family<F: PayloadFamily>(
        self,
    ) -> Result<StoredEncryptedFactEnvelope<F::PayloadType>, FenStorePostgresError> {
        if self.append_sequence < 0 {
            return Err(FenStorePostgresError::NegativeAppendSequence);
        }

        Ok(StoredEncryptedFactEnvelope {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: PersistenceTransactionId(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            fact_id: FactId(self.fact_id),
            subject_id: SubjectId(self.subject_id),
            occurred_at: TemporalAnchorPostgresRecord {
                kind: self.occurred_kind,
                start: self.occurred_start,
                end: self.occurred_end,
            }
            .try_into_temporal_anchor()?,
            payload_type: F::payload_type_from_label(&self.payload_type).ok_or_else(|| {
                FenStorePostgresError::UnknownPayloadType(self.payload_type.clone())
            })?,
            status: fact_status_from_postgres(&self.status_kind, self.status_payload)?,
            materialization_policy_refs: self
                .materialization_policy_refs
                .into_iter()
                .map(PolicyRef)
                .collect(),
            encryption: FactEncryptionMetadata {
                algorithm: FactEncryptionAlgorithm::from_str_label(&self.encryption_algorithm)
                    .ok_or_else(|| {
                        FenStorePostgresError::UnknownEncryptionAlgorithm(
                            self.encryption_algorithm.clone(),
                        )
                    })?,
                key_id: self.encryption_key_id,
                wrapped_dek_ref: self.wrapped_dek_ref,
                nonce: self.nonce,
                aad_version: EncryptedFactAssociatedDataVersion::from_str_label(&self.aad_version)
                    .ok_or_else(|| {
                        FenStorePostgresError::UnknownAssociatedDataVersion(
                            self.aad_version.clone(),
                        )
                    })?,
            },
            ciphertext: self.ciphertext,
        })
    }

    pub fn sort_for_replay(rows: &mut [Self]) {
        rows.sort_by_key(|row| row.append_sequence);
    }

    pub(crate) fn status_payload_json(&self) -> Result<String, FenStorePostgresError> {
        serde_json::to_string(&self.status_payload)
            .map_err(|error| FenStorePostgresError::StatusPayloadJson(error.to_string()))
    }

    pub(crate) fn with_status_payload_json(
        status_payload_json: &str,
        row: EncryptedFactPostgresRowWithoutStatusPayload,
    ) -> Result<Self, FenStorePostgresError> {
        let status_payload = serde_json::from_str(status_payload_json)
            .map_err(|error| FenStorePostgresError::StatusPayloadJson(error.to_string()))?;
        Ok(row.with_status_payload(status_payload))
    }
}

pub(crate) struct EncryptedFactPostgresRowWithoutStatusPayload {
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
    pub materialization_policy_refs: Vec<String>,
    pub encryption_algorithm: String,
    pub encryption_key_id: String,
    pub wrapped_dek_ref: Option<String>,
    pub nonce: Vec<u8>,
    pub aad_version: String,
    pub ciphertext: Vec<u8>,
}

impl EncryptedFactPostgresRowWithoutStatusPayload {
    fn with_status_payload(
        self,
        status_payload: FactStatusPostgresPayload,
    ) -> EncryptedFactPostgresRow {
        EncryptedFactPostgresRow {
            append_sequence: self.append_sequence,
            transaction_id: self.transaction_id,
            committed_at: self.committed_at,
            fact_id: self.fact_id,
            subject_id: self.subject_id,
            occurred_kind: self.occurred_kind,
            occurred_start: self.occurred_start,
            occurred_end: self.occurred_end,
            payload_type: self.payload_type,
            status_kind: self.status_kind,
            status_payload,
            materialization_policy_refs: self.materialization_policy_refs,
            encryption_algorithm: self.encryption_algorithm,
            encryption_key_id: self.encryption_key_id,
            wrapped_dek_ref: self.wrapped_dek_ref,
            nonce: self.nonce,
            aad_version: self.aad_version,
            ciphertext: self.ciphertext,
        }
    }
}

impl MaterializationAuditPostgresRow {
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

    pub fn try_into_event(self) -> Result<FactMaterializationAuditEvent, FenStorePostgresError> {
        Ok(FactMaterializationAuditEvent {
            subject_id: SubjectId(self.subject_id),
            fact_ids: self.fact_ids.into_iter().map(FactId).collect(),
            materialization_policy_refs: self
                .materialization_policy_refs
                .into_iter()
                .map(PolicyRef)
                .collect(),
            evaluated_policy_refs: self
                .evaluated_policy_refs
                .into_iter()
                .map(PolicyRef)
                .collect(),
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

impl AuthorPostgresRecord {
    fn from_author(author: &Author) -> Self {
        Self {
            author_type: postgres_author_type(&author.author_type).to_string(),
            author_id: author.author_id.as_ref().map(|id| id.0.clone()),
            display_name: author.display_name.clone(),
        }
    }

    fn try_into_author(self) -> Result<Author, FenStorePostgresError> {
        Ok(Author {
            author_type: author_type_from_postgres(&self.author_type)?,
            author_id: self.author_id.map(AuthorId),
            display_name: self.display_name,
        })
    }
}

impl TemporalAnchorPostgresRecord {
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

    fn try_into_temporal_anchor(self) -> Result<TemporalAnchor, FenStorePostgresError> {
        match (self.kind.as_str(), self.end) {
            ("point", None) => Ok(TemporalAnchor::Point(Timestamp(self.start))),
            ("period", Some(end)) => Ok(TemporalAnchor::Period(TimeInterval {
                start: Timestamp(self.start),
                end: Timestamp(end),
            })),
            ("point" | "period", _) => Err(FenStorePostgresError::InvalidTemporalAnchor),
            _ => Err(FenStorePostgresError::UnknownTemporalKind(self.kind)),
        }
    }
}

fn postgres_fact_status_parts(status: &FactStatus) -> (&'static str, FactStatusPostgresPayload) {
    match status {
        FactStatus::Active => ("active", FactStatusPostgresPayload::Active),
        FactStatus::Superseded {
            superseded_by,
            superseded_at,
            replaced_by,
            reason,
        } => (
            "superseded",
            FactStatusPostgresPayload::Superseded {
                superseded_by: AuthorPostgresRecord::from_author(superseded_by),
                superseded_at: TemporalAnchorPostgresRecord::from_temporal_anchor(superseded_at),
                replaced_by: replaced_by.as_ref().map(|id| id.0.clone()),
                reason: postgres_supersession_reason(reason).to_string(),
            },
        ),
        FactStatus::EnteredInError {
            corrected_by,
            corrected_at,
            replaced_by,
        } => (
            "entered_in_error",
            FactStatusPostgresPayload::EnteredInError {
                corrected_by: AuthorPostgresRecord::from_author(corrected_by),
                corrected_at: TemporalAnchorPostgresRecord::from_temporal_anchor(corrected_at),
                replaced_by: replaced_by.as_ref().map(|id| id.0.clone()),
            },
        ),
    }
}

fn fact_status_from_postgres(
    status_kind: &str,
    status_payload: FactStatusPostgresPayload,
) -> Result<FactStatus, FenStorePostgresError> {
    match (status_kind, status_payload) {
        ("active", FactStatusPostgresPayload::Active) => Ok(FactStatus::Active),
        (
            "superseded",
            FactStatusPostgresPayload::Superseded {
                superseded_by,
                superseded_at,
                replaced_by,
                reason,
            },
        ) => Ok(FactStatus::Superseded {
            superseded_by: superseded_by.try_into_author()?,
            superseded_at: superseded_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(FactId),
            reason: supersession_reason_from_postgres(&reason)?,
        }),
        (
            "entered_in_error",
            FactStatusPostgresPayload::EnteredInError {
                corrected_by,
                corrected_at,
                replaced_by,
            },
        ) => Ok(FactStatus::EnteredInError {
            corrected_by: corrected_by.try_into_author()?,
            corrected_at: corrected_at.try_into_temporal_anchor()?,
            replaced_by: replaced_by.map(FactId),
        }),
        ("active" | "superseded" | "entered_in_error", _) => {
            Err(FenStorePostgresError::InvalidFactStatusPayload)
        }
        _ => Err(FenStorePostgresError::UnknownFactStatusKind(
            status_kind.to_string(),
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

fn author_type_from_postgres(value: &str) -> Result<AuthorType, FenStorePostgresError> {
    match value {
        "patient" => Ok(AuthorType::Patient),
        "clinician" => Ok(AuthorType::Clinician),
        "system" => Ok(AuthorType::System),
        "ai_assisted" => Ok(AuthorType::AiAssisted),
        _ => Err(FenStorePostgresError::UnknownAuthorType(value.to_string())),
    }
}

fn postgres_supersession_reason(reason: &SupersessionReason) -> &'static str {
    match reason {
        SupersessionReason::AiEnrichment => "ai_enrichment",
        SupersessionReason::ClinicalRefinement => "clinical_refinement",
        SupersessionReason::StrongerIdentityEvidence => "stronger_identity_evidence",
        SupersessionReason::AdministrativeCorrection => "administrative_correction",
        SupersessionReason::RuleReEvaluation => "rule_re_evaluation",
    }
}

fn supersession_reason_from_postgres(
    value: &str,
) -> Result<SupersessionReason, FenStorePostgresError> {
    match value {
        "ai_enrichment" => Ok(SupersessionReason::AiEnrichment),
        "clinical_refinement" => Ok(SupersessionReason::ClinicalRefinement),
        "stronger_identity_evidence" => Ok(SupersessionReason::StrongerIdentityEvidence),
        "administrative_correction" => Ok(SupersessionReason::AdministrativeCorrection),
        "rule_re_evaluation" => Ok(SupersessionReason::RuleReEvaluation),
        _ => Err(FenStorePostgresError::UnknownSupersessionReason(
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
) -> Result<FactMaterializationAuditOutcome, FenStorePostgresError> {
    match value {
        "attempted" => Ok(FactMaterializationAuditOutcome::Attempted),
        "policy_denied" => Ok(FactMaterializationAuditOutcome::PolicyDenied),
        "key_access_attempted" => Ok(FactMaterializationAuditOutcome::KeyAccessAttempted),
        "key_access_succeeded" => Ok(FactMaterializationAuditOutcome::KeyAccessSucceeded),
        "key_access_failed" => Ok(FactMaterializationAuditOutcome::KeyAccessFailed),
        "decryption_attempted" => Ok(FactMaterializationAuditOutcome::DecryptionAttempted),
        "decryption_failed" => Ok(FactMaterializationAuditOutcome::DecryptionFailed),
        "succeeded" => Ok(FactMaterializationAuditOutcome::Succeeded),
        _ => Err(FenStorePostgresError::UnknownMaterializationAuditOutcome(
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
) -> Result<FactMaterializationError, FenStorePostgresError> {
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
        _ => Err(FenStorePostgresError::UnknownMaterializationError(
            value.to_string(),
        )),
    }
}
