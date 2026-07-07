use crate::fen::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub id: SubjectId,
    pub subject_kind: SubjectKind,
    pub status: SubjectStatus,
    pub created_at: Timestamp,
    pub created_by: Author,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKind {
    HumanPerson,
    Organization,
    Device,
    SystemAgent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectStatus {
    Active,
    Superseded {
        superseded_by: SubjectId,
        reason: SubjectSupersessionReason,
    },
    EnteredInError,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSupersessionReason {
    DuplicateSubject,
    IncorrectMergeCorrection,
    AdministrativeCorrection,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableIdentityProfile {
    pub legal_name: Option<String>,
    pub date_of_birth: Option<Date>,
    pub demographic_attributes: Vec<IdentityAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAttribute {
    LegalName,
    DateOfBirth,
    Address,
    PhoneNumber,
    Email,
    SexAdministrative,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAttributeValue {
    StringValue(String),
    DateValue(Date),
    CodedValue(CodedValue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParticipationRole {
    RecordSubject,
    Actor,
    Delegate,
    Caregiver,
    ParentGuardian,
    LegalRepresentative,
    Clinician,
    OrganizationAgent,
    Witness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchConfidence {
    Low,
    Medium,
    High,
    Exact,
    Ambiguous,
    Conflicting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityWitnessType {
    GovernmentIdVerification,
    SelfieLivenessCheck,
    BiometricContinuityCheck,
    PatientPortalLoginProof,
    ProviderAttestation,
    InPersonClinicVerification,
    PayerVerification,
    InsuranceCardVerification,
    DemographicMatch,
    DeviceBoundPasskeyAssertion,
    RecoveryKeyPresentation,
    LegalDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityWitnessResult {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationAttackDetectionResult {
    Passed,
    Failed,
    Inconclusive,
    NotPerformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityWitnessContext {
    pub witness_result: Option<IdentityWitnessResult>,
    pub challenge_nonce: Option<String>,
    pub device_ref: Option<DeviceRef>,
    pub pad_result: Option<PresentationAttackDetectionResult>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatorType {
    Passkey,
    PlatformBiometric,
    HardwareSecurityKey,
    AppPushMfa,
    RecoveryKey,
    Password,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricModality {
    Face,
    Fingerprint,
    Voice,
    Palm,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityCheckResult {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityVerificationRejectionReason {
    InvalidSignature,
    UnknownVerificationKey,
    KeyNotAuthorizedForProvider,
    UnknownNonce,
    ExpiredNonce,
    ReusedNonce,
    EnrollmentReferenceMismatch,
    TimestampOutsideAllowedWindow,
    ModalityNotAllowed,
    PolicyRejectedAssuranceMapping,
    MalformedAssertion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAssertionResult {
    Succeeded,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskEvaluationResult {
    Passed,
    Failed,
    RequiresStepUp,
    RequiresManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecisionResult {
    Allowed,
    Denied,
    StepUpRequired,
    ManualReviewRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityType {
    SelfAuthority,
    CaregiverDelegation,
    ParentGuardian,
    LegalProxy,
    PowerOfAttorney,
    AttorneyClientRepresentative,
    EmergencyAccess,
    ProviderTreatmentAuthority,
    OrganizationAgentAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityScope {
    pub permitted_actions: Vec<AuthorizedAction>,
    pub constrained_by_policy: Vec<PolicyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedAction {
    ViewRecord,
    UploadDocument,
    ShareRecord,
    ScheduleCare,
    ManageBilling,
    LinkProvider,
    ExportRecord,
    AuthorizeDataTransaction,
    DelegateAuthority,
    RevokeAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveAction {
    ViewRecord,
    ShareRecord,
    ExportCompleteRecord,
    LinkProvider,
    LinkPayer,
    ChangeRecoveryMethod,
    DelegateAuthority,
    RevokeAuthority,
    AuthorizeDataTransaction,
    EmergencyAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMethod {
    ExistingTrustedDevice,
    RecoveryKey,
    GovernmentIdAndLiveness,
    ProviderAttestation,
    PayerVerification,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryResult {
    Approved,
    Denied,
    PendingManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeResolutionOutcome {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectGraphCorrectionReason {
    DuplicateSubject,
    IncorrectMerge,
    AdministrativeCorrection,
    StrongerIdentityEvidence,
    Other(String),
}
