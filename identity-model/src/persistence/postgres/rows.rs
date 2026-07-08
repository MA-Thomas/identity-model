use super::*;

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
pub struct PostgresAppAttestKeyRegistrationRow {
    pub key_id: String,
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: String,
    pub device_ref: String,
    pub public_key_bytes: Vec<u8>,
    pub registered_at: String,
    pub attestation_challenge_nonce: String,
    pub attestation_format: String,
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
    InvalidAppAttestKeyRegistration,
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

impl PostgresEncryptedFactRow {
    pub fn try_from_envelope(envelope: &StoredEncryptedFact) -> Result<Self, PostgresAdapterError> {
        Self::try_from_envelope_in_family::<IdentityPayloadFamily>(envelope)
    }

    /// Family-generic row mapping onto the payload-agnostic envelope table:
    /// identical columns, with the payload-type label owned by the
    /// [`PayloadFamily`] (e.g. `health_econ.*` for `fen-health-econ`).
    pub fn try_from_envelope_in_family<F: PayloadFamily>(
        envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    ) -> Result<Self, PostgresAdapterError> {
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

    pub fn try_into_envelope(self) -> Result<StoredEncryptedFact, PostgresAdapterError> {
        self.try_into_envelope_in_family::<IdentityPayloadFamily>()
    }

    /// Family-generic inverse of [`Self::try_from_envelope_in_family`]. A
    /// label outside the family's closed set is a hard
    /// [`PostgresAdapterError::UnknownPayloadType`] error: family scoping
    /// belongs in the query (`payload_type = ANY(family labels)`), not in
    /// silently skipping rows here.
    pub fn try_into_envelope_in_family<F: PayloadFamily>(
        self,
    ) -> Result<StoredEncryptedFactEnvelope<F::PayloadType>, PostgresAdapterError> {
        if self.append_sequence < 0 {
            return Err(PostgresAdapterError::NegativeAppendSequence);
        }

        Ok(StoredEncryptedFactEnvelope {
            append_sequence: self.append_sequence as AppendSequence,
            transaction_id: PersistenceTransactionId(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            fact_id: FactId(self.fact_id),
            subject_id: SubjectId(self.subject_id),
            occurred_at: PostgresTemporalAnchorRecord {
                kind: self.occurred_kind,
                start: self.occurred_start,
                end: self.occurred_end,
            }
            .try_into_temporal_anchor()?,
            payload_type: F::payload_type_from_label(&self.payload_type).ok_or_else(|| {
                PostgresAdapterError::UnknownPayloadType(self.payload_type.clone())
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
impl PostgresFactStatusPayload {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEncryptedFactRow {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresCodedValueRecord {
    pub(super) fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresApproximateDateRecord {
    pub(super) fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresAuthorRecord {
    pub(super) fn to_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeStatusPayload {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresMembershipStatusPayload {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeRelationStatusPayload {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresLivePresenceChallengeStatusPayload {
    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        serde_json::to_string(self)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }

    pub(super) fn from_json(json: &str) -> Result<Self, PostgresAdapterError> {
        serde_json::from_str(json)
            .map_err(|error| PostgresAdapterError::StatusPayloadJson(error.to_string()))
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresProblemEpisodeRow {
    pub(super) fn problem_code_json(&self) -> Result<Option<String>, PostgresAdapterError> {
        self.problem_code
            .as_ref()
            .map(PostgresCodedValueRecord::to_json)
            .transpose()
    }

    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }

    pub(super) fn onset_json(&self) -> Result<Option<String>, PostgresAdapterError> {
        self.onset
            .as_ref()
            .map(PostgresApproximateDateRecord::to_json)
            .transpose()
    }

    pub(super) fn authored_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.authored_by.to_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeMembershipRow {
    pub(super) fn asserted_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.asserted_by.to_json()
    }

    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
    }
}

#[cfg(feature = "postgres-adapter")]
impl PostgresEpisodeRelationRow {
    pub(super) fn asserted_by_json(&self) -> Result<String, PostgresAdapterError> {
        self.asserted_by.to_json()
    }

    pub(super) fn status_payload_json(&self) -> Result<String, PostgresAdapterError> {
        self.status_payload.status_payload_json()
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

impl PostgresAppAttestKeyRegistrationRow {
    pub fn try_from_registration(
        registration: &AppAttestKeyRegistration,
    ) -> Result<Self, PostgresAdapterError> {
        Ok(Self {
            key_id: registration.key_id.clone(),
            team_id: registration.team_id.clone(),
            bundle_id: registration.bundle_id.clone(),
            app_id: registration.app_id.clone(),
            environment: postgres_app_attest_environment(registration.environment).to_string(),
            device_ref: registration.device_ref.clone(),
            public_key_bytes: registration.public_key_bytes.clone(),
            registered_at: registration.registered_at.0.clone(),
            attestation_challenge_nonce: registration.attestation_challenge_nonce.clone(),
            attestation_format: registration.attestation_format.clone(),
        })
    }

    pub fn try_into_registration(self) -> Result<AppAttestKeyRegistration, PostgresAdapterError> {
        let registration = AppAttestKeyRegistration {
            key_id: self.key_id,
            team_id: self.team_id,
            bundle_id: self.bundle_id,
            app_id: self.app_id,
            environment: app_attest_environment_from_postgres(&self.environment)?,
            device_ref: self.device_ref,
            public_key_bytes: self.public_key_bytes,
            registered_at: Timestamp(self.registered_at),
            attestation_challenge_nonce: self.attestation_challenge_nonce,
            attestation_format: self.attestation_format,
        };
        validate_app_attest_key_registration(&registration)
            .map_err(|_| PostgresAdapterError::InvalidAppAttestKeyRegistration)?;
        Ok(registration)
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
            challenge_id: LivePresenceChallengeId(self.challenge_id),
            challenge_nonce: self.challenge_nonce,
            intended_workflow: live_presence_challenge_workflow_from_postgres(
                &self.intended_workflow,
            )?,
            expected_subject_id: self.expected_subject_id.map(SubjectId),
            expected_device_ref: self.expected_device_ref,
            expected_app,
            issued_at: Timestamp(self.issued_at),
            expires_at: Timestamp(self.expires_at),
            status: live_presence_challenge_status_from_postgres(
                &self.status_kind,
                self.status_payload,
            )?,
            retry_policy_refs: self.retry_policy_refs.into_iter().map(PolicyRef).collect(),
            manual_review_policy_refs: self
                .manual_review_policy_refs
                .into_iter()
                .map(PolicyRef)
                .collect(),
            retention_policy_refs: self
                .retention_policy_refs
                .into_iter()
                .map(PolicyRef)
                .collect(),
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
            transaction_id: PersistenceTransactionId(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            episode: ProblemEpisode {
                id: ProblemEpisodeId(self.episode_id),
                subject_id: SubjectId(self.subject_id),
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
            transaction_id: PersistenceTransactionId(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            membership: EpisodeMembership {
                id: MembershipId(self.membership_id),
                fact_id: FactId(self.fact_id),
                episode_id: ProblemEpisodeId(self.episode_id),
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
            transaction_id: PersistenceTransactionId(self.transaction_id),
            committed_at: Timestamp(self.committed_at),
            relation: EpisodeRelation {
                id: RelationId(self.relation_id),
                source_episode_id: ProblemEpisodeId(self.source_episode_id),
                target_episode_id: ProblemEpisodeId(self.target_episode_id),
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
    pub(super) fn from_temporal_anchor(anchor: &TemporalAnchor) -> Self {
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

    pub(super) fn try_into_temporal_anchor(self) -> Result<TemporalAnchor, PostgresAdapterError> {
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
    pub(super) fn from_coded_value(value: &CodedValue) -> Self {
        Self {
            system: postgres_coding_system(&value.system).to_string(),
            code: value.code.clone(),
            display: value.display.clone(),
        }
    }

    pub(super) fn try_into_coded_value(self) -> Result<CodedValue, PostgresAdapterError> {
        Ok(CodedValue {
            system: coding_system_from_postgres(&self.system)?,
            code: self.code,
            display: self.display,
        })
    }
}

impl PostgresApproximateDateRecord {
    pub(super) fn from_approximate_date(value: &ApproximateDate) -> Self {
        Self {
            date: value.date.0.clone(),
            precision: postgres_date_precision(value.precision).to_string(),
        }
    }

    pub(super) fn try_into_approximate_date(self) -> Result<ApproximateDate, PostgresAdapterError> {
        Ok(ApproximateDate {
            date: Date(self.date),
            precision: date_precision_from_postgres(&self.precision)?,
        })
    }
}
