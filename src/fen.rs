use crate::identity::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(pub String);

pub type FactId = Id;
pub type SubjectId = Id;
pub type ProblemEpisodeId = Id;
pub type MembershipId = Id;
pub type RelationId = Id;
pub type NarrativeId = Id;
pub type SectionId = Id;
pub type DecisionPointId = Id;
pub type AuthorId = Id;
pub type DocumentId = Id;
pub type PolicyRef = Id;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date(pub String);

pub type DeviceRef = String;
pub type DocumentRef = String;
pub type OrganizationRef = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub id: FactId,
    pub subject_id: SubjectId,
    pub occurred_at: TemporalAnchor,
    pub code: Option<CodedValue>,
    pub payload: FactPayload,
    pub status: FactStatus,
    pub provenance: Provenance,
    pub external_refs: Vec<ExternalRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactPayload {
    Measurement,
    Prescription,
    Procedure,
    Diagnosis,
    Document,
    Coverage,
    Claim,
    SubjectCreated {
        subject_kind: SubjectKind,
        stable_profile: StableIdentityProfile,
    },
    IdentityAttributeAsserted {
        attribute: IdentityAttribute,
        value: IdentityAttributeValue,
        confidence: MatchConfidence,
    },
    IdentityWitnessRecorded {
        witness_type: IdentityWitnessType,
        target_subject_id: SubjectId,
        assurance_level: AssuranceLevel,
        evidence_ref: Option<DocumentRef>,
        expires_at: Option<Timestamp>,
        context: IdentityWitnessContext,
    },
    BiometricEnrollmentReferenceAdded {
        biometric_system: String,
        enrollment_ref: String,
        modality: BiometricModality,
    },
    BiometricContinuityCheck {
        biometric_system: String,
        enrollment_ref: String,
        result: ContinuityCheckResult,
        assurance_level: AssuranceLevel,
    },
    ContinuityVerificationRejected {
        biometric_system: Option<String>,
        enrollment_ref: String,
        challenge_nonce: String,
        reason: ContinuityVerificationRejectionReason,
    },
    DeviceBindingEstablished {
        device_ref: DeviceRef,
        authenticator_type: AuthenticatorType,
        assurance_level: AssuranceLevel,
    },
    DeviceBindingRevoked {
        device_ref: DeviceRef,
        reason: Option<String>,
    },
    CredentialAssertion {
        authenticator_type: AuthenticatorType,
        device_ref: Option<DeviceRef>,
        result: CredentialAssertionResult,
        assurance_level: AssuranceLevel,
    },
    ClinicalIdentityLinkEstablished {
        provider_org: OrganizationRef,
        external_patient_ref: ExternalRef,
        match_confidence: MatchConfidence,
    },
    ClinicalIdentityLinkContested {
        link_fact_id: FactId,
        reason: Option<String>,
    },
    ClinicalIdentityLinkDisputeResolved {
        link_fact_id: FactId,
        outcome: DisputeResolutionOutcome,
        rationale: Option<String>,
    },
    PayerIdentityLinkEstablished {
        payer: String,
        member_ref: String,
        effective_period: Option<TimeInterval>,
    },
    PayerIdentityLinkContested {
        link_fact_id: FactId,
        reason: Option<String>,
    },
    PayerIdentityLinkDisputeResolved {
        link_fact_id: FactId,
        outcome: DisputeResolutionOutcome,
        rationale: Option<String>,
    },
    DuplicateSubjectMergeRecorded {
        surviving_subject_id: SubjectId,
        merged_subject_ids: Vec<SubjectId>,
        reason: SubjectGraphCorrectionReason,
        evidence_refs: Vec<DocumentRef>,
    },
    IncorrectMergeSplitRecorded {
        prior_subject_id: SubjectId,
        restored_subject_ids: Vec<SubjectId>,
        reason: SubjectGraphCorrectionReason,
        evidence_refs: Vec<DocumentRef>,
    },
    IdentityWitnessSuperseded {
        superseded_witness_fact_id: FactId,
        replacement_witness_fact_id: FactId,
        reason: SupersessionReason,
    },
    AuthorityRelationshipEstablished {
        actor_subject_id: SubjectId,
        target_subject_id: SubjectId,
        authority_type: AuthorityType,
        scope: AuthorityScope,
        valid_period: Option<TimeInterval>,
        evidence_ref: Option<DocumentRef>,
    },
    AuthorityRelationshipRevoked {
        relationship_fact_id: FactId,
        reason: Option<String>,
    },
    AccountRecoveryEvent {
        method: RecoveryMethod,
        result: RecoveryResult,
        assurance_level: AssuranceLevel,
    },
    RiskEvaluationEvent {
        action: SensitiveAction,
        result: RiskEvaluationResult,
        required_assurance: AssuranceLevel,
    },
    AccessDecision {
        action: SensitiveAction,
        decision: AccessDecisionResult,
        relied_on_facts: Vec<FactId>,
        policy_refs: Vec<PolicyRef>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactStatus {
    Active,
    Superseded {
        superseded_by: Author,
        superseded_at: TemporalAnchor,
        replaced_by: Option<FactId>,
        reason: SupersessionReason,
    },
    EnteredInError {
        corrected_by: Author,
        corrected_at: TemporalAnchor,
        replaced_by: Option<FactId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupersessionReason {
    AiEnrichment,
    ClinicalRefinement,
    StrongerIdentityEvidence,
    AdministrativeCorrection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemporalAnchor {
    Point(Timestamp),
    Period(TimeInterval),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeInterval {
    pub start: Timestamp,
    pub end: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub source_system: Option<String>,
    pub source_document: Option<DocumentId>,
    pub imported_at: Timestamp,
    pub author: Author,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub author_type: AuthorType,
    pub author_id: Option<AuthorId>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorType {
    Patient,
    Clinician,
    System,
    AiAssisted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedValue {
    pub system: CodingSystem,
    pub code: String,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodingSystem {
    Snomed,
    Icd10,
    Loinc,
    RxNorm,
    Cpt,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRef {
    pub system: ExternalSystem,
    pub resource_type: Option<String>,
    pub resource_id: String,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSystem {
    Fhir,
    Omop,
    Ccda,
    IdentityProvider,
    ContinuityProvider,
    Other(String),
}
