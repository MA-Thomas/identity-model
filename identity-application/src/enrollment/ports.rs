use super::ServiceError;
use identity_contract::{changes::*, *};
use std::future::Future;

pub struct EnrollmentScope<'a> {
    pub product: &'a str,
    pub intent: &'a EnrollmentIntent,
    pub login: (&'a str, &'a str),
}
pub struct ChangeScope<'a> {
    pub product: &'a str,
    pub intent: &'a ChangeIntent,
    pub login: (&'a str, &'a str),
    pub new_login: Option<(&'a str, &'a str)>,
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
    pub subject: String,
    pub status: String,
    pub product_ref: Option<String>,
}
pub struct EnrollmentContext {
    pub prior: Option<PriorAttempt>,
    pub enrollment: Option<EnrollmentOwner>,
    pub login: Option<LoginOwner>,
}
pub struct ChangeContext {
    pub version: u64,
    pub subject: String,
    pub status: String,
    pub confirmed: bool,
    pub login_owned: bool,
    pub new_login_owner: Option<String>,
    pub old_key: [u8; 32],
    pub old_bank: [u8; 32],
    pub prior: Option<(Vec<u8>, SignedSecurityEvent)>,
}
pub struct EnrollmentWrites {
    pub subject: Option<(String, String)>,
    pub login: Option<(String, String, String)>,
    pub product_ref: Option<(String, String)>,
    pub enrollment: Option<(String, String)>,
    pub attempt: PriorAttempt,
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
pub struct ChangeWrites {
    pub event: SignedSecurityEvent,
    pub digest: [u8; 32],
    pub login: Option<(String, String, String)>,
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
/// Missing login and product-reference rows must be protected too. Callbacks run once,
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
    ) -> impl Future<Output = Result<Response, ServiceError>> + Send;
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
