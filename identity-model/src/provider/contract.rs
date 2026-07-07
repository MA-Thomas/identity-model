use crate::continuity::*;
use crate::fen::*;
use crate::identity::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityProviderCapabilities {
    pub provider_name: String,
    pub supported_modalities: Vec<BiometricModality>,
    pub supports_liveness: bool,
    pub signs_assertions: bool,
    pub owns_template_storage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityEnrollmentRequest {
    pub subject_id: SubjectId,
    pub modality: BiometricModality,
    pub requested_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityEnrollment {
    pub subject_id: SubjectId,
    pub biometric_system: String,
    pub enrollment_ref: String,
    pub modality: BiometricModality,
    pub provider_metadata: ContinuityProviderMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityProviderError {
    UnsupportedModality,
    EnrollmentFailed(String),
    ChallengePreparationFailed(String),
    AssertionUnavailable(String),
    ProviderUnavailable,
}

pub trait ContinuityVaultProvider {
    fn capabilities(&self) -> ContinuityProviderCapabilities;

    fn enroll(
        &self,
        request: ContinuityEnrollmentRequest,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError>;

    fn prepare_challenge(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityProviderError>;

    fn signed_assertion(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<SignedContinuityAssertion, ContinuityProviderError>;
}
