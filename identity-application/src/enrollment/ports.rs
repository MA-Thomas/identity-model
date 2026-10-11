use super::{evidence::EvidenceFingerprints, ServiceError};
use identity_contract::{changes::*, evidence::*, *};
use identity_model::{fen::SubjectId, login::ProductLoginIdentity};
use std::future::Future;

pub struct EnrollmentScope<'a> {
    pub product: &'a str,
    pub intent: &'a EnrollmentIntent,
    pub login: (&'a str, &'a str),
    /// The applicant's evidence, when the bank confirmed ownership. Storage returns the
    /// product's other enrollments that share any fingerprint with it as candidates.
    pub evidence: Option<&'a EvidenceFingerprints>,
}
pub struct ChangeScope<'a> {
    pub product: &'a str,
    pub intent: &'a ChangeIntent,
    pub login: (&'a str, &'a str),
}
pub struct PriorAttempt {
    pub intent: EnrollmentIntent,
    pub digest: Vec<u8>,
    pub response: Response,
}
pub struct EnrollmentOwner {
    pub account: String,
    pub subject_ref: String,
    pub confirmed: bool,
}
pub struct LoginOwner {
    pub identity: ProductLoginIdentity,
    pub status: String,
    pub product_ref: ProductSubjectRef,
}
/// Another enrollment of the product whose evidence may overlap the applicant's.
pub struct EvidenceCandidate {
    pub account: String,
    pub fingerprints: EvidenceFingerprints,
}
/// The evidence state of this enrollment operation and its possible overlaps. Adapters
/// serialize reads of this context with the product's other enrollments.
pub struct ScreeningContext {
    /// Evidence already recorded for this operation; it cannot change.
    pub recorded: Option<EvidenceFingerprints>,
    pub case: Option<ReviewCase>,
    pub candidates: Vec<EvidenceCandidate>,
}
pub struct EnrollmentContext {
    pub prior: Option<PriorAttempt>,
    pub enrollment: Option<EnrollmentOwner>,
    pub login: Option<LoginOwner>,
    pub screening: ScreeningContext,
}
pub struct ChangeContext {
    pub version: u64,
    pub subject: SubjectId,
    pub status: String,
    pub confirmed: bool,
    pub login: Option<ProductLoginIdentity>,
    pub old_key: [u8; 32],
    pub old_bank: [u8; 32],
    pub prior: Option<(Vec<u8>, SignedSecurityEvent)>,
}
pub struct EnrollmentWrites {
    pub subject: Option<(SubjectId, String)>,
    pub login: Option<ProductLoginIdentity>,
    pub product_ref: Option<(SubjectId, ProductSubjectRef)>,
    pub enrollment: Option<EnrollmentBinding>,
    /// The applicant's evidence, recorded once per operation.
    pub evidence: Option<(String, EvidenceFingerprints)>,
    /// A newly opened review case.
    pub review: Option<ReviewCase>,
    pub attempt: PriorAttempt,
}
pub struct EnrollmentBinding {
    pub account: String,
    pub subject: SubjectId,
    pub subject_ref: ProductSubjectRef,
}
pub struct EnrollmentDecision {
    pub(crate) response: Response,
    pub(crate) writes: Option<EnrollmentWrites>,
}
impl EnrollmentDecision {
    pub fn into_parts(self) -> (Response, Option<EnrollmentWrites>) {
        (self.response, self.writes)
    }
}
/// The latest attempt's response for an operation and its review case, if any.
pub struct LookupRecord {
    pub response: Option<Response>,
    pub case: Option<ReviewCase>,
}
/// A reviewer's decision to record on an open case.
pub struct ResolutionDecision {
    pub(crate) case: ReviewCase,
    pub(crate) decision: Option<ReviewDecision>,
}
impl ResolutionDecision {
    /// The case as it stands after the decision, and the decision to record, if new.
    pub fn into_parts(self) -> (ReviewCase, Option<ReviewDecision>) {
        (self.case, self.decision)
    }
}
pub struct ChangeWrites {
    pub event: SignedSecurityEvent,
    pub digest: [u8; 32],
}
pub struct ChangeDecision {
    pub(crate) response: Response,
    pub(crate) writes: Option<ChangeWrites>,
}
impl ChangeDecision {
    pub fn into_parts(self) -> (Response, Option<ChangeWrites>) {
        (self.response, self.writes)
    }
}
/// Adapters hold identity ownership/attempt/version protection through callback and commit.
/// A product has exactly one login per subject and each external login belongs to
/// one subject within that product. Account bindings must reference that same subject.
/// Missing product-login and product-reference rows must be protected too. Callbacks run once,
/// after every required lock and read, do no I/O, and their responses are released only
/// after all writes commit. Confirmation must serialize with enrollment renewal.
pub trait EnrollmentStore: Send + Sync {
    fn existing(
        &self,
        intent: &EnrollmentIntent,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Response>, ServiceError>> + Send;
    fn existing_change(
        &self,
        product: &str,
        operation: &str,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Response>, ServiceError>> + Send;
    fn lookup(
        &self,
        product: &str,
        operation: &str,
    ) -> impl Future<Output = Result<LookupRecord, ServiceError>> + Send;
    /// Open review cases, oldest first.
    fn reviews(
        &self,
        product: &str,
    ) -> impl Future<Output = Result<Vec<ReviewCase>, ServiceError>> + Send;
    /// Records a reviewer's decision. Adapters serialize it with enrollment attempts of
    /// the case's operation and record a decision at most once.
    fn resolve(
        &self,
        product: &str,
        case: &ReviewCaseId,
        decide: impl FnOnce(ReviewCase) -> Result<ResolutionDecision, ServiceError> + Send,
    ) -> impl Future<Output = Result<ReviewCase, ServiceError>> + Send;
    fn confirm(
        &self,
        product: &str,
        decision: &SignedDecision,
    ) -> impl Future<Output = Result<Response, ServiceError>> + Send;
    fn security_events(
        &self,
        product: &str,
        subject: &ProductSubjectRef,
        after: u64,
    ) -> impl Future<Output = Result<Response, ServiceError>> + Send;
    fn record(
        &self,
        scope: EnrollmentScope<'_>,
        decide: impl FnOnce(EnrollmentContext) -> Result<EnrollmentDecision, ServiceError> + Send,
    ) -> impl Future<Output = Result<Response, ServiceError>> + Send;
    fn change(
        &self,
        scope: ChangeScope<'_>,
        decide: impl FnOnce(ChangeContext) -> Result<ChangeDecision, ServiceError> + Send,
    ) -> impl Future<Output = Result<Response, ServiceError>> + Send;
}
