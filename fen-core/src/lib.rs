//! Identity-neutral primitives for the FEN semantic graph.
//!
//! This crate owns durable identifiers and value types shared by every FEN
//! payload family. It deliberately contains no identity workflow, storage,
//! transport, database, or application runtime concerns.

pub mod time;

pub use time::*;

/// Generates a distinct newtype per identifier kind.
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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

typed_id!(FactId);
typed_id!(SubjectId);
typed_id!(ProblemEpisodeId);
typed_id!(MembershipId);
typed_id!(RelationId);
typed_id!(NarrativeId);
typed_id!(SectionId);
typed_id!(DecisionPointId);
typed_id!(AuthorId);
typed_id!(DocumentId);
typed_id!(PolicyRef);
typed_id!(ContentHash);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Timestamp(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Date(pub String);

pub type DeviceRef = String;
pub type DocumentRef = String;
pub type OrganizationRef = String;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Stable reasons shared by FEN payload families when one fact supersedes
/// another. Persisted adapters own the frozen string labels for these values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SupersessionReason {
    AiEnrichment,
    ClinicalRefinement,
    StrongerIdentityEvidence,
    AdministrativeCorrection,
    RuleReEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TemporalAnchor {
    Point(Timestamp),
    Period(TimeInterval),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimeInterval {
    pub start: Timestamp,
    pub end: Timestamp,
}

/// Where a fact came from and under what authority it was ingested.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub source_system: Option<String>,
    pub source_document: Option<DocumentId>,
    pub imported_at: Timestamp,
    pub author: Author,
    pub tier: ProvenanceTier,
    pub content_hash: Option<ContentHash>,
    pub authorization_basis: Option<AuthorizationBasis>,
}

/// How the underlying material entered the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProvenanceTier {
    ApiSourced,
    RecordsRequest,
    PortalExport,
    EmployeeUpload,
    Inference,
}

/// The authority under which source material was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthorizationBasis {
    HipaaRightOfAccess,
    PatientDirection,
    EmployerPlanContext,
    SelfHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Author {
    pub author_type: AuthorType,
    pub author_id: Option<AuthorId>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthorType {
    Patient,
    Clinician,
    System,
    AiAssisted,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodedValue {
    pub system: CodingSystem,
    pub code: String,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CodingSystem {
    Snomed,
    Icd10,
    Loinc,
    RxNorm,
    Cpt,
    Hcpcs,
    Ndc,
    Carc,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalRef {
    pub system: ExternalSystem,
    pub resource_type: Option<String>,
    pub resource_id: String,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExternalSystem {
    Fhir,
    Omop,
    Ccda,
    IdentityProvider,
    ContinuityProvider,
    PayerPortal,
    Edi,
    Other(String),
}
