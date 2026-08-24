use crate::identity::*;
pub use fen_core::*;

/// Generates a distinct newtype per identifier kind.
///
/// These were previously transparent aliases of a single `Id(pub String)`,
/// which let one ID kind be passed where another was expected. Distinct
/// newtypes make ID-kind confusion a compile error. The inner `String`
/// stays public so existing `.0` access and pattern matching keep working.
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

pub(crate) use typed_id;

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
