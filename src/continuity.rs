use crate::fen::*;
use crate::identity::*;
use std::collections::HashMap;

mod canonical;
#[cfg(feature = "ed25519-dalek-verifier")]
mod ed25519;
pub use canonical::*;
#[cfg(feature = "ed25519-dalek-verifier")]
pub use ed25519::*;

typed_id!(ChallengeId);
pub type Nonce = String;
pub type Signature = Vec<u8>;
pub type VerificationKeyId = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityChallenge {
    pub challenge_id: ChallengeId,
    pub subject_id: SubjectId,
    pub enrollment_ref: String,
    pub nonce: Nonce,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub intended_action: Option<SensitiveAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityAssertion {
    pub enrollment_ref: String,
    pub challenge_nonce: Nonce,
    pub timestamp: Timestamp,
    pub result: ContinuityCheckResult,
    pub derived_assurance: AssuranceLevel,
    pub modality: BiometricModality,
    pub model_version: Option<String>,
    pub pad_result: PresentationAttackDetectionResult,
    pub provider_metadata: ContinuityProviderMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContinuityAssertion {
    pub assertion: ContinuityAssertion,
    pub signature: Signature,
    pub key_id: VerificationKeyId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    pub key_id: VerificationKeyId,
    pub provider_name: String,
    pub key_material: Vec<u8>,
    pub status: VerificationKeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKeyStatus {
    Active,
    Retired,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationKeyRegistry {
    keys_by_id: HashMap<VerificationKeyId, VerificationKey>,
}

impl VerificationKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_keys(keys: impl IntoIterator<Item = VerificationKey>) -> Self {
        let mut registry = Self::new();
        registry.register_many(keys);
        registry
    }

    pub fn register(&mut self, key: VerificationKey) {
        self.keys_by_id.insert(key.key_id.clone(), key);
    }

    pub fn register_many(&mut self, keys: impl IntoIterator<Item = VerificationKey>) {
        for key in keys {
            self.register(key);
        }
    }

    pub fn get(&self, key_id: &VerificationKeyId) -> Option<&VerificationKey> {
        self.keys_by_id.get(key_id)
    }

    pub fn retire(
        &mut self,
        key_id: &VerificationKeyId,
    ) -> Result<(), ContinuityAssertionRejectionReason> {
        let key = self
            .keys_by_id
            .get_mut(key_id)
            .ok_or(ContinuityAssertionRejectionReason::UnknownVerificationKey)?;
        key.status = VerificationKeyStatus::Retired;
        Ok(())
    }

    pub fn active_keys_for_provider(&self, provider_name: &str) -> Vec<VerificationKey> {
        self.keys_for_provider_with_status(provider_name, VerificationKeyStatus::Active)
    }

    pub fn retired_keys_for_provider(&self, provider_name: &str) -> Vec<VerificationKey> {
        self.keys_for_provider_with_status(provider_name, VerificationKeyStatus::Retired)
    }

    fn keys_for_provider_with_status(
        &self,
        provider_name: &str,
        status: VerificationKeyStatus,
    ) -> Vec<VerificationKey> {
        self.keys_by_id
            .values()
            .filter(|key| key.provider_name == provider_name && key.status == status)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityProviderMetadata {
    pub provider_name: String,
    pub provider_event_id: Option<String>,
    pub provider_subject_ref: Option<String>,
    pub sdk_or_api_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityAssertionVerificationResult {
    Verified {
        assertion: ContinuityAssertion,
        assurance_level: AssuranceLevel,
    },
    Rejected {
        reason: ContinuityAssertionRejectionReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityAssertionRejectionReason {
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

impl From<ContinuityAssertionRejectionReason> for ContinuityVerificationRejectionReason {
    fn from(reason: ContinuityAssertionRejectionReason) -> Self {
        match reason {
            ContinuityAssertionRejectionReason::InvalidSignature => Self::InvalidSignature,
            ContinuityAssertionRejectionReason::UnknownVerificationKey => {
                Self::UnknownVerificationKey
            }
            ContinuityAssertionRejectionReason::KeyNotAuthorizedForProvider => {
                Self::KeyNotAuthorizedForProvider
            }
            ContinuityAssertionRejectionReason::UnknownNonce => Self::UnknownNonce,
            ContinuityAssertionRejectionReason::ExpiredNonce => Self::ExpiredNonce,
            ContinuityAssertionRejectionReason::ReusedNonce => Self::ReusedNonce,
            ContinuityAssertionRejectionReason::EnrollmentReferenceMismatch => {
                Self::EnrollmentReferenceMismatch
            }
            ContinuityAssertionRejectionReason::TimestampOutsideAllowedWindow => {
                Self::TimestampOutsideAllowedWindow
            }
            ContinuityAssertionRejectionReason::ModalityNotAllowed => Self::ModalityNotAllowed,
            ContinuityAssertionRejectionReason::PolicyRejectedAssuranceMapping => {
                Self::PolicyRejectedAssuranceMapping
            }
            ContinuityAssertionRejectionReason::MalformedAssertion => Self::MalformedAssertion,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceStatus {
    Issued,
    Used { used_at: Timestamp },
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedContinuityChallenge {
    pub challenge: ContinuityChallenge,
    pub status: NonceStatus,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryNonceLifecycle {
    challenges_by_nonce: HashMap<Nonce, TrackedContinuityChallenge>,
}

impl InMemoryNonceLifecycle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue_challenge(
        &mut self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityAssertionRejectionReason> {
        if self.challenges_by_nonce.contains_key(&challenge.nonce) {
            return Err(ContinuityAssertionRejectionReason::ReusedNonce);
        }

        self.challenges_by_nonce.insert(
            challenge.nonce.clone(),
            TrackedContinuityChallenge {
                challenge: challenge.clone(),
                status: NonceStatus::Issued,
            },
        );

        Ok(challenge)
    }

    pub fn status(&self, nonce: &Nonce) -> Option<&NonceStatus> {
        self.challenges_by_nonce
            .get(nonce)
            .map(|tracked| &tracked.status)
    }

    pub fn verify_and_consume(
        &mut self,
        assertion: &ContinuityAssertion,
        verified_at: &Timestamp,
    ) -> Result<ContinuityChallenge, ContinuityAssertionRejectionReason> {
        let tracked = self
            .challenges_by_nonce
            .get_mut(&assertion.challenge_nonce)
            .ok_or(ContinuityAssertionRejectionReason::UnknownNonce)?;

        match tracked.status {
            NonceStatus::Used { .. } => {
                return Err(ContinuityAssertionRejectionReason::ReusedNonce);
            }
            NonceStatus::Expired => {
                return Err(ContinuityAssertionRejectionReason::ExpiredNonce);
            }
            NonceStatus::Issued => {}
        }

        if verified_at > &tracked.challenge.expires_at {
            tracked.status = NonceStatus::Expired;
            return Err(ContinuityAssertionRejectionReason::ExpiredNonce);
        }

        if assertion.enrollment_ref != tracked.challenge.enrollment_ref {
            return Err(ContinuityAssertionRejectionReason::EnrollmentReferenceMismatch);
        }

        tracked.status = NonceStatus::Used {
            used_at: verified_at.clone(),
        };

        Ok(tracked.challenge.clone())
    }
}

pub trait ContinuitySignatureVerifier {
    fn verify_signature(
        &self,
        signed_assertion: &SignedContinuityAssertion,
    ) -> Result<(), ContinuityAssertionRejectionReason>;
}

pub trait ContinuityAssuranceMapper {
    fn map_assurance(
        &self,
        assertion: &ContinuityAssertion,
    ) -> Result<AssuranceLevel, ContinuityAssertionRejectionReason>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSignatureVerifier {
    pub trusted_key_id: VerificationKeyId,
    pub expected_signature: Signature,
}

impl ContinuitySignatureVerifier for ExpectedSignatureVerifier {
    fn verify_signature(
        &self,
        signed_assertion: &SignedContinuityAssertion,
    ) -> Result<(), ContinuityAssertionRejectionReason> {
        if signed_assertion.key_id != self.trusted_key_id {
            return Err(ContinuityAssertionRejectionReason::UnknownVerificationKey);
        }

        if signed_assertion.signature != self.expected_signature {
            return Err(ContinuityAssertionRejectionReason::InvalidSignature);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryBackedSignatureVerifier {
    pub key_registry: VerificationKeyRegistry,
}

impl ContinuitySignatureVerifier for RegistryBackedSignatureVerifier {
    fn verify_signature(
        &self,
        signed_assertion: &SignedContinuityAssertion,
    ) -> Result<(), ContinuityAssertionRejectionReason> {
        if signed_assertion.signature.is_empty() {
            return Err(ContinuityAssertionRejectionReason::MalformedAssertion);
        }

        let key = self
            .key_registry
            .get(&signed_assertion.key_id)
            .ok_or(ContinuityAssertionRejectionReason::UnknownVerificationKey)?;

        if key.status != VerificationKeyStatus::Active {
            return Err(ContinuityAssertionRejectionReason::UnknownVerificationKey);
        }

        if key.provider_name != signed_assertion.assertion.provider_metadata.provider_name {
            return Err(ContinuityAssertionRejectionReason::KeyNotAuthorizedForProvider);
        }

        let expected_signature =
            deterministic_signature_for_test(&signed_assertion.assertion, &key.key_material);
        if signed_assertion.signature != expected_signature {
            return Err(ContinuityAssertionRejectionReason::InvalidSignature);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultBasedAssuranceMapper;

impl ContinuityAssuranceMapper for ResultBasedAssuranceMapper {
    fn map_assurance(
        &self,
        assertion: &ContinuityAssertion,
    ) -> Result<AssuranceLevel, ContinuityAssertionRejectionReason> {
        match (assertion.result, assertion.pad_result) {
            (ContinuityCheckResult::Passed, PresentationAttackDetectionResult::Passed) => {
                Ok(assertion.derived_assurance)
            }
            (ContinuityCheckResult::Passed, _) => Ok(AssuranceLevel::Medium),
            (ContinuityCheckResult::Failed, _) => Ok(AssuranceLevel::Low),
            (ContinuityCheckResult::Inconclusive, _) => Ok(AssuranceLevel::Low),
        }
    }
}

pub fn verify_signed_continuity_assertion(
    signed_assertion: SignedContinuityAssertion,
    nonce_lifecycle: &mut InMemoryNonceLifecycle,
    signature_verifier: &impl ContinuitySignatureVerifier,
    assurance_mapper: &impl ContinuityAssuranceMapper,
    verified_at: Timestamp,
) -> ContinuityAssertionVerificationResult {
    if let Err(reason) = signature_verifier.verify_signature(&signed_assertion) {
        return ContinuityAssertionVerificationResult::Rejected { reason };
    }

    if let Err(reason) =
        nonce_lifecycle.verify_and_consume(&signed_assertion.assertion, &verified_at)
    {
        return ContinuityAssertionVerificationResult::Rejected { reason };
    }

    match assurance_mapper.map_assurance(&signed_assertion.assertion) {
        Ok(assurance_level) => ContinuityAssertionVerificationResult::Verified {
            assertion: signed_assertion.assertion,
            assurance_level,
        },
        Err(reason) => ContinuityAssertionVerificationResult::Rejected { reason },
    }
}

impl ContinuityAssertion {
    pub fn to_biometric_continuity_fact_payload(
        &self,
        assurance_level: AssuranceLevel,
    ) -> FactPayload {
        FactPayload::BiometricContinuityCheck {
            biometric_system: self.provider_metadata.provider_name.clone(),
            enrollment_ref: self.enrollment_ref.clone(),
            result: self.result,
            assurance_level,
        }
    }
}
