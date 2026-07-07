use super::contract::*;
use crate::continuity::*;
use crate::fen::*;
use crate::identity::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct MockPhase1ContinuityProvider {
    pub provider_name: String,
    pub sdk_or_api_version: String,
    pub key_id: VerificationKeyId,
    pub signature: Signature,
    pub result: ContinuityCheckResult,
    pub pad_result: PresentationAttackDetectionResult,
    pub derived_assurance: AssuranceLevel,
    // AtomicU64 rather than Cell<u64> so the provider is Sync: the runtime
    // server shares its config across worker threads.
    event_counter: AtomicU64,
}

impl Clone for MockPhase1ContinuityProvider {
    fn clone(&self) -> Self {
        Self {
            provider_name: self.provider_name.clone(),
            sdk_or_api_version: self.sdk_or_api_version.clone(),
            key_id: self.key_id.clone(),
            signature: self.signature.clone(),
            result: self.result,
            pad_result: self.pad_result,
            derived_assurance: self.derived_assurance,
            event_counter: AtomicU64::new(self.event_counter.load(Ordering::Relaxed)),
        }
    }
}

impl MockPhase1ContinuityProvider {
    pub fn successful() -> Self {
        Self::new(
            ContinuityCheckResult::Passed,
            PresentationAttackDetectionResult::Passed,
            AssuranceLevel::High,
        )
    }

    pub fn failed() -> Self {
        Self::new(
            ContinuityCheckResult::Failed,
            PresentationAttackDetectionResult::Failed,
            AssuranceLevel::Low,
        )
    }

    pub fn inconclusive() -> Self {
        Self::new(
            ContinuityCheckResult::Inconclusive,
            PresentationAttackDetectionResult::Inconclusive,
            AssuranceLevel::Low,
        )
    }

    pub fn new(
        result: ContinuityCheckResult,
        pad_result: PresentationAttackDetectionResult,
        derived_assurance: AssuranceLevel,
    ) -> Self {
        Self {
            provider_name: "MockPhase1Vault".to_string(),
            sdk_or_api_version: "mock-phase1-v1".to_string(),
            key_id: "mock-phase1-key".to_string(),
            signature: b"mock-phase1-signature".to_vec(),
            result,
            pad_result,
            derived_assurance,
            event_counter: AtomicU64::new(0),
        }
    }

    pub fn signature_verifier(&self) -> ExpectedSignatureVerifier {
        ExpectedSignatureVerifier {
            trusted_key_id: self.key_id.clone(),
            expected_signature: self.signature.clone(),
        }
    }

    fn next_event_id(&self, prefix: &str) -> String {
        let next = self.event_counter.fetch_add(1, Ordering::Relaxed) + 1;
        format!("{prefix}-{next}")
    }

    fn provider_subject_ref(subject_id: &SubjectId) -> String {
        format!("mock-subject-{}", subject_id.0)
    }
}

impl ContinuityVaultProvider for MockPhase1ContinuityProvider {
    fn capabilities(&self) -> ContinuityProviderCapabilities {
        ContinuityProviderCapabilities {
            provider_name: self.provider_name.clone(),
            supported_modalities: vec![BiometricModality::Face],
            supports_liveness: true,
            signs_assertions: true,
            owns_template_storage: true,
        }
    }

    fn enroll(
        &self,
        request: ContinuityEnrollmentRequest,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError> {
        if request.modality != BiometricModality::Face {
            return Err(ContinuityProviderError::UnsupportedModality);
        }

        Ok(ContinuityEnrollment {
            subject_id: request.subject_id.clone(),
            biometric_system: self.provider_name.clone(),
            enrollment_ref: format!("mock-enrollment-{}", request.subject_id.0),
            modality: request.modality,
            provider_metadata: ContinuityProviderMetadata {
                provider_name: self.provider_name.clone(),
                provider_event_id: Some(self.next_event_id("mock-enrollment")),
                provider_subject_ref: Some(Self::provider_subject_ref(&request.subject_id)),
                sdk_or_api_version: Some(self.sdk_or_api_version.clone()),
            },
        })
    }

    fn prepare_challenge(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityProviderError> {
        Ok(challenge)
    }

    fn signed_assertion(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<SignedContinuityAssertion, ContinuityProviderError> {
        Ok(SignedContinuityAssertion {
            assertion: ContinuityAssertion {
                enrollment_ref: challenge.enrollment_ref,
                challenge_nonce: challenge.nonce,
                timestamp: challenge.issued_at,
                result: self.result,
                derived_assurance: self.derived_assurance,
                modality: BiometricModality::Face,
                model_version: Some("mock-face-match-v1".to_string()),
                pad_result: self.pad_result,
                provider_metadata: ContinuityProviderMetadata {
                    provider_name: self.provider_name.clone(),
                    provider_event_id: Some(self.next_event_id("mock-continuity")),
                    provider_subject_ref: Some(Self::provider_subject_ref(&challenge.subject_id)),
                    sdk_or_api_version: Some(self.sdk_or_api_version.clone()),
                },
            },
            signature: self.signature.clone(),
            key_id: self.key_id.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MockHostedContinuityProvider {
    inner: MockPhase1ContinuityProvider,
}

impl MockHostedContinuityProvider {
    pub fn successful() -> Self {
        let mut inner = MockPhase1ContinuityProvider::successful();
        inner.provider_name = "MockHostedVault".to_string();
        inner.sdk_or_api_version = "mock-hosted-v2".to_string();
        inner.key_id = "mock-hosted-key".to_string();
        inner.signature = b"mock-hosted-signature".to_vec();
        Self { inner }
    }

    pub fn signature_verifier(&self) -> ExpectedSignatureVerifier {
        self.inner.signature_verifier()
    }
}

impl ContinuityVaultProvider for MockHostedContinuityProvider {
    fn capabilities(&self) -> ContinuityProviderCapabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.owns_template_storage = false;
        capabilities
    }

    fn enroll(
        &self,
        request: ContinuityEnrollmentRequest,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError> {
        self.inner.enroll(request)
    }

    fn prepare_challenge(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityProviderError> {
        self.inner.prepare_challenge(challenge)
    }

    fn signed_assertion(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<SignedContinuityAssertion, ContinuityProviderError> {
        self.inner.signed_assertion(challenge)
    }
}
