use crate::fen::*;
use crate::identity::*;
use crate::time;

pub const PERSONA_PROVIDER_NAME: &str = "Persona";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProofingVerificationRequest {
    pub provider_name: String,
    pub workflow_id: String,
    pub provider_event_id: Option<String>,
    pub asserted_attributes: Vec<IdentityProofingAssertedAttribute>,
    pub evidence_types: Vec<IdentityProofingEvidenceType>,
    pub verification_result: IdentityWitnessResult,
    pub assurance_level: AssuranceLevel,
    pub risk_signals: Vec<IdentityProofingRiskSignal>,
    pub verified_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub audit_ref: Option<String>,
    pub evidence_ref: Option<DocumentRef>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl IdentityProofingVerificationRequest {
    pub fn persona_government_id(
        workflow_id: impl Into<String>,
        provider_event_id: impl Into<String>,
        verified_at: Timestamp,
    ) -> Self {
        Self {
            provider_name: PERSONA_PROVIDER_NAME.to_string(),
            workflow_id: workflow_id.into(),
            provider_event_id: Some(provider_event_id.into()),
            asserted_attributes: Vec::new(),
            evidence_types: vec![IdentityProofingEvidenceType::GovernmentIdDocument],
            verification_result: IdentityWitnessResult::Passed,
            assurance_level: AssuranceLevel::High,
            risk_signals: Vec::new(),
            verified_at,
            expires_at: None,
            audit_ref: None,
            evidence_ref: None,
            retention_policy_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProofingAssertedAttribute {
    pub attribute: IdentityAttribute,
    pub value: IdentityAttributeValue,
    pub confidence: MatchConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProofingEvidenceType {
    GovernmentIdDocument,
    Passport,
    DriversLicense,
    NationalId,
    AddressDocument,
    SelfieCapture,
    Other(String),
}

impl IdentityProofingEvidenceType {
    pub fn is_government_id(&self) -> bool {
        matches!(
            self,
            Self::GovernmentIdDocument | Self::Passport | Self::DriversLicense | Self::NationalId
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProofingRiskSignal {
    pub signal_type: String,
    pub action: SensitiveAction,
    pub result: RiskEvaluationResult,
    pub required_assurance: AssuranceLevel,
    pub affects_policy: bool,
}

impl IdentityProofingRiskSignal {
    pub fn requires_manual_review(&self) -> bool {
        self.affects_policy && self.result != RiskEvaluationResult::Passed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentityProofingEvidence {
    pub provider_name: String,
    pub workflow_id: String,
    pub provider_event_id: Option<String>,
    pub asserted_attributes: Vec<IdentityProofingAssertedAttribute>,
    pub evidence_types: Vec<IdentityProofingEvidenceType>,
    pub verification_result: IdentityWitnessResult,
    pub assurance_level: AssuranceLevel,
    pub risk_signals: Vec<IdentityProofingRiskSignal>,
    pub verified_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub audit_ref: Option<String>,
    pub evidence_ref: Option<DocumentRef>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl VerifiedIdentityProofingEvidence {
    pub fn source_system(&self) -> String {
        self.provider_name.clone()
    }

    pub fn identity_witness_type(&self) -> IdentityWitnessType {
        if self
            .evidence_types
            .iter()
            .any(IdentityProofingEvidenceType::is_government_id)
        {
            IdentityWitnessType::GovernmentIdVerification
        } else {
            IdentityWitnessType::LegalDocument
        }
    }

    pub fn identity_witness_context(&self) -> IdentityWitnessContext {
        IdentityWitnessContext {
            witness_result: Some(self.verification_result),
            challenge_nonce: None,
            device_ref: None,
            pad_result: None,
            retention_policy_refs: self.retention_policy_refs.clone(),
        }
    }

    pub fn external_refs(&self) -> Vec<ExternalRef> {
        let system = ExternalSystem::Other(self.provider_name.clone());
        let mut refs = vec![ExternalRef {
            system: system.clone(),
            resource_type: Some("identity_proofing_workflow".to_string()),
            resource_id: self.workflow_id.clone(),
            uri: None,
        }];

        if let Some(provider_event_id) = &self.provider_event_id {
            refs.push(ExternalRef {
                system: system.clone(),
                resource_type: Some("identity_proofing_event".to_string()),
                resource_id: provider_event_id.clone(),
                uri: None,
            });
        }

        if let Some(audit_ref) = &self.audit_ref {
            refs.push(ExternalRef {
                system,
                resource_type: Some("identity_proofing_audit".to_string()),
                resource_id: audit_ref.clone(),
                uri: None,
            });
        }

        refs
    }

    pub fn risk_requires_manual_review(&self) -> bool {
        self.risk_signals
            .iter()
            .any(IdentityProofingRiskSignal::requires_manual_review)
    }

    pub fn is_expired_at(
        &self,
        observed_at: &Timestamp,
    ) -> Result<bool, IdentityProofingVerificationError> {
        self.expires_at
            .as_ref()
            .map(|expires_at| {
                time::timestamp_at_or_after(observed_at, expires_at)
                    .map_err(|_| IdentityProofingVerificationError::InvalidTimestamp)
            })
            .unwrap_or(Ok(false))
    }

    pub fn requires_manual_review_at(
        &self,
        observed_at: &Timestamp,
    ) -> Result<bool, IdentityProofingVerificationError> {
        Ok(self.verification_result != IdentityWitnessResult::Passed
            || self.risk_requires_manual_review()
            || self.is_expired_at(observed_at)?)
    }

    pub fn passed_at(
        &self,
        observed_at: &Timestamp,
    ) -> Result<bool, IdentityProofingVerificationError> {
        Ok(!self.requires_manual_review_at(observed_at)?)
    }

    pub fn mapped_fact_count(&self) -> usize {
        1 + self.asserted_attributes.len()
            + self
                .risk_signals
                .iter()
                .filter(|signal| signal.affects_policy)
                .count()
    }
}

pub trait IdentityProofingProvider {
    fn verify_identity_proofing(
        &self,
        request: &IdentityProofingVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedIdentityProofingEvidence, IdentityProofingVerificationError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonaIdentityProofingProvider;

impl PersonaIdentityProofingProvider {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProofingProvider for PersonaIdentityProofingProvider {
    fn verify_identity_proofing(
        &self,
        request: &IdentityProofingVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedIdentityProofingEvidence, IdentityProofingVerificationError> {
        if request.provider_name != PERSONA_PROVIDER_NAME {
            return Err(IdentityProofingVerificationError::ProviderMismatch);
        }

        verified_identity_proofing_from_request(request, observed_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticIdentityProofingProvider {
    pub expected_provider_name: String,
    pub expected_workflow_id: String,
    pub verified_evidence: VerifiedIdentityProofingEvidence,
}

impl StaticIdentityProofingProvider {
    pub fn new(
        expected_provider_name: impl Into<String>,
        expected_workflow_id: impl Into<String>,
        verified_evidence: VerifiedIdentityProofingEvidence,
    ) -> Self {
        Self {
            expected_provider_name: expected_provider_name.into(),
            expected_workflow_id: expected_workflow_id.into(),
            verified_evidence,
        }
    }
}

impl IdentityProofingProvider for StaticIdentityProofingProvider {
    fn verify_identity_proofing(
        &self,
        request: &IdentityProofingVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedIdentityProofingEvidence, IdentityProofingVerificationError> {
        if request.provider_name != self.expected_provider_name
            || request.workflow_id != self.expected_workflow_id
        {
            return Err(IdentityProofingVerificationError::ProviderMismatch);
        }
        validate_verified_identity_proofing(&self.verified_evidence, observed_at)?;
        Ok(self.verified_evidence.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProofingVerificationError {
    ProviderMismatch,
    MissingProviderName,
    MissingWorkflowId,
    MissingEvidenceType,
    MissingRiskSignalType,
    FutureVerificationTimestamp,
    InvalidTimestamp,
}

fn verified_identity_proofing_from_request(
    request: &IdentityProofingVerificationRequest,
    observed_at: &Timestamp,
) -> Result<VerifiedIdentityProofingEvidence, IdentityProofingVerificationError> {
    let evidence = VerifiedIdentityProofingEvidence {
        provider_name: request.provider_name.clone(),
        workflow_id: request.workflow_id.clone(),
        provider_event_id: request.provider_event_id.clone(),
        asserted_attributes: request.asserted_attributes.clone(),
        evidence_types: request.evidence_types.clone(),
        verification_result: request.verification_result,
        assurance_level: request.assurance_level,
        risk_signals: request.risk_signals.clone(),
        verified_at: request.verified_at.clone(),
        expires_at: request.expires_at.clone(),
        audit_ref: request.audit_ref.clone(),
        evidence_ref: request.evidence_ref.clone(),
        retention_policy_refs: request.retention_policy_refs.clone(),
    };
    validate_verified_identity_proofing(&evidence, observed_at)?;
    Ok(evidence)
}

fn validate_verified_identity_proofing(
    evidence: &VerifiedIdentityProofingEvidence,
    observed_at: &Timestamp,
) -> Result<(), IdentityProofingVerificationError> {
    if evidence.provider_name.trim().is_empty() {
        return Err(IdentityProofingVerificationError::MissingProviderName);
    }
    if evidence.workflow_id.trim().is_empty() {
        return Err(IdentityProofingVerificationError::MissingWorkflowId);
    }
    if evidence.evidence_types.is_empty() {
        return Err(IdentityProofingVerificationError::MissingEvidenceType);
    }
    if evidence
        .risk_signals
        .iter()
        .any(|signal| signal.signal_type.trim().is_empty())
    {
        return Err(IdentityProofingVerificationError::MissingRiskSignalType);
    }

    time::timestamp_to_unix_seconds(observed_at)
        .map_err(|_| IdentityProofingVerificationError::InvalidTimestamp)?;
    let verified_after_observed = time::timestamp_after(&evidence.verified_at, observed_at)
        .map_err(|_| IdentityProofingVerificationError::InvalidTimestamp)?;
    if verified_after_observed {
        return Err(IdentityProofingVerificationError::FutureVerificationTimestamp);
    }
    if let Some(expires_at) = &evidence.expires_at {
        time::timestamp_to_unix_seconds(expires_at)
            .map_err(|_| IdentityProofingVerificationError::InvalidTimestamp)?;
    }

    Ok(())
}
