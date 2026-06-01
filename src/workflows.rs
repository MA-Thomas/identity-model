use crate::fen::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemEpisode {
    pub id: ProblemEpisodeId,
    pub subject_id: SubjectId,
    pub episode_kind: EpisodeKind,
    pub label: String,
    pub problem_code: Option<CodedValue>,
    pub status: EpisodeStatus,
    pub onset: Option<ApproximateDate>,
    pub authored_by: Author,
    pub authored_at: Timestamp,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpisodeKind {
    ClinicalProblem,
    AdministrativeWorkflow,
    IdentityVerificationWorkflow,
    AccountRecoveryWorkflow,
    DelegationWorkflow,
    AccessAuthorizationWorkflow,
    DataSharingWorkflow,
    DisputeResolutionWorkflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodeStatus {
    Active,
    Dormant,
    Resolved(ResolutionInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionInfo {
    pub at: Option<ApproximateDate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproximateDate {
    pub date: Date,
    pub precision: DatePrecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatePrecision {
    Day,
    Month,
    Year,
    Approximate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpisodeMembership {
    pub id: MembershipId,
    pub fact_id: FactId,
    pub episode_id: ProblemEpisodeId,
    pub role: FactRole,
    pub asserted_by: Author,
    pub asserted_at: TemporalAnchor,
    pub status: MembershipStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipStatus {
    Active,
    Retracted {
        retracted_by: Author,
        retracted_at: TemporalAnchor,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactRole {
    TriggeringSymptom,
    DiagnosticTest,
    Treatment,
    OutcomeMeasure,
    Monitoring,
    Complication,
    Referral,
    Administrative,
    InsuranceAction,
    IdentityAnchor,
    IdentityWitness,
    ContinuityWitness,
    DeviceBinding,
    InstitutionalLink,
    AuthorityEvidence,
    RecoveryEvidence,
    RiskSignal,
    AccessDecisionEvidence,
    DisputeEvidence,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpisodeRelation {
    pub id: RelationId,
    pub source_episode_id: ProblemEpisodeId,
    pub target_episode_id: ProblemEpisodeId,
    pub relation_type: EpisodeRelationType,
    pub asserted_by: Author,
    pub asserted_at: TemporalAnchor,
    pub status: EpisodeRelationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpisodeRelationType {
    PartOf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodeRelationStatus {
    Active,
    Retracted {
        retracted_by: Author,
        retracted_at: TemporalAnchor,
    },
}
