use super::contract::*;
use crate::continuity::*;
use crate::fen::*;
use crate::identity::*;
#[cfg(feature = "ed25519-dalek-verifier")]
use ed25519_dalek::{Signer, SigningKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedContinuityProviderConfig {
    pub provider_name: String,
    pub sdk_or_api_version: String,
    pub supported_modalities: Vec<BiometricModality>,
    pub supports_liveness: bool,
    pub owns_template_storage: bool,
    pub signing_key_id: VerificationKeyId,
    pub signing_key_material: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedEnrollmentRequest {
    pub external_subject_ref: String,
    pub modality: BiometricModality,
    pub requested_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedEnrollmentResponse {
    pub external_enrollment_id: String,
    pub provider_event_id: String,
    pub provider_subject_ref: String,
    pub modality: BiometricModality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedContinuityChallengeRequest {
    pub external_enrollment_id: String,
    pub challenge_nonce: Nonce,
    pub intended_action: Option<SensitiveAction>,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedContinuityEvent {
    pub external_enrollment_id: String,
    pub provider_event_id: String,
    pub provider_subject_ref: String,
    pub challenge_nonce: Nonce,
    pub observed_at: Timestamp,
    pub result: ContinuityCheckResult,
    pub derived_assurance: AssuranceLevel,
    pub modality: BiometricModality,
    pub model_version: Option<String>,
    pub pad_result: PresentationAttackDetectionResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedProviderErrorCode {
    UnsupportedModality,
    EnrollmentRejected,
    ChallengeRejected,
    AssertionNotReady,
    TemporarilyUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedHostedContinuityAdapter {
    pub config: HostedContinuityProviderConfig,
    pub enrollment_response: Result<HostedEnrollmentResponse, HostedProviderErrorCode>,
    pub continuity_result: Result<HostedContinuityEvent, HostedProviderErrorCode>,
}

impl ScriptedHostedContinuityAdapter {
    pub fn successful(provider_name: &str) -> Self {
        Self {
            config: HostedContinuityProviderConfig {
                provider_name: provider_name.to_string(),
                sdk_or_api_version: "hosted-api-v1".to_string(),
                supported_modalities: vec![BiometricModality::Face],
                supports_liveness: true,
                owns_template_storage: false,
                signing_key_id: format!("{provider_name}-key-1"),
                signing_key_material: format!("{provider_name}-key-material").into_bytes(),
            },
            enrollment_response: Ok(HostedEnrollmentResponse {
                external_enrollment_id: "hosted-enrollment-demo".to_string(),
                provider_event_id: "hosted-enrollment-event-1".to_string(),
                provider_subject_ref: "hosted-subject-demo".to_string(),
                modality: BiometricModality::Face,
            }),
            continuity_result: Ok(HostedContinuityEvent {
                external_enrollment_id: "hosted-enrollment-demo".to_string(),
                provider_event_id: "hosted-continuity-event-1".to_string(),
                provider_subject_ref: "hosted-subject-demo".to_string(),
                challenge_nonce: "nonce-export-step-up".to_string(),
                observed_at: Timestamp("2026-05-29T00:00:00Z".to_string()),
                result: ContinuityCheckResult::Passed,
                derived_assurance: AssuranceLevel::High,
                modality: BiometricModality::Face,
                model_version: Some("hosted-face-match-v1".to_string()),
                pad_result: PresentationAttackDetectionResult::Passed,
            }),
        }
    }

    pub fn signature_verifier(&self) -> RegistryBackedSignatureVerifier {
        let mut key_registry = VerificationKeyRegistry::new();
        key_registry.register(VerificationKey {
            key_id: self.config.signing_key_id.clone(),
            provider_name: self.config.provider_name.clone(),
            key_material: self.config.signing_key_material.clone(),
            status: VerificationKeyStatus::Active,
        });

        RegistryBackedSignatureVerifier { key_registry }
    }

    pub fn enrollment_request(
        &self,
        request: &ContinuityEnrollmentRequest,
    ) -> HostedEnrollmentRequest {
        HostedEnrollmentRequest {
            external_subject_ref: format!("fen-subject-{}", request.subject_id.0),
            modality: request.modality.clone(),
            requested_at: request.requested_at.clone(),
        }
    }

    pub fn challenge_request(
        &self,
        challenge: &ContinuityChallenge,
    ) -> HostedContinuityChallengeRequest {
        HostedContinuityChallengeRequest {
            external_enrollment_id: challenge.enrollment_ref.clone(),
            challenge_nonce: challenge.nonce.clone(),
            intended_action: challenge.intended_action,
            expires_at: challenge.expires_at.clone(),
        }
    }
}

impl ContinuityVaultProvider for ScriptedHostedContinuityAdapter {
    fn capabilities(&self) -> ContinuityProviderCapabilities {
        ContinuityProviderCapabilities {
            provider_name: self.config.provider_name.clone(),
            supported_modalities: self.config.supported_modalities.clone(),
            supports_liveness: self.config.supports_liveness,
            signs_assertions: true,
            owns_template_storage: self.config.owns_template_storage,
        }
    }

    fn enroll(
        &self,
        request: ContinuityEnrollmentRequest,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError> {
        let hosted_request = self.enrollment_request(&request);
        if !self
            .config
            .supported_modalities
            .contains(&hosted_request.modality)
        {
            return Err(ContinuityProviderError::UnsupportedModality);
        }

        self.enrollment_response
            .clone()
            .map_err(map_hosted_error)?
            .into_enrollment(request.subject_id, &self.config)
    }

    fn prepare_challenge(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityProviderError> {
        let _hosted_request = self.challenge_request(&challenge);
        Ok(challenge)
    }

    fn signed_assertion(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<SignedContinuityAssertion, ContinuityProviderError> {
        let event = self.continuity_result.clone().map_err(map_hosted_error)?;
        let assertion = event.into_assertion(challenge, &self.config)?;
        let signature =
            deterministic_signature_for_test(&assertion, &self.config.signing_key_material);

        Ok(SignedContinuityAssertion {
            assertion,
            signature,
            key_id: self.config.signing_key_id.clone(),
        })
    }
}

#[cfg(feature = "ed25519-dalek-verifier")]
#[derive(Clone)]
pub struct FenNativeEd25519HostedContinuityAdapter {
    pub config: HostedContinuityProviderConfig,
    signing_key: SigningKey,
    retired_verification_keys: Vec<VerificationKey>,
    pub enrollment_response: Result<HostedEnrollmentResponse, HostedProviderErrorCode>,
    pub continuity_result: Result<HostedContinuityEvent, HostedProviderErrorCode>,
}

#[cfg(feature = "ed25519-dalek-verifier")]
impl FenNativeEd25519HostedContinuityAdapter {
    pub fn successful(
        provider_name: &str,
        signing_key_id: &str,
        signing_key_seed: [u8; 32],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&signing_key_seed);
        Self {
            config: HostedContinuityProviderConfig {
                provider_name: provider_name.to_string(),
                sdk_or_api_version: "fen-native-ed25519-hosted-v1".to_string(),
                supported_modalities: vec![BiometricModality::Face],
                supports_liveness: true,
                owns_template_storage: false,
                signing_key_id: signing_key_id.to_string(),
                signing_key_material: signing_key.verifying_key().to_bytes().to_vec(),
            },
            signing_key,
            retired_verification_keys: Vec::new(),
            enrollment_response: Ok(HostedEnrollmentResponse {
                external_enrollment_id: "hosted-enrollment-demo".to_string(),
                provider_event_id: "hosted-enrollment-event-1".to_string(),
                provider_subject_ref: "hosted-subject-demo".to_string(),
                modality: BiometricModality::Face,
            }),
            continuity_result: Ok(HostedContinuityEvent {
                external_enrollment_id: "hosted-enrollment-demo".to_string(),
                provider_event_id: "hosted-continuity-event-1".to_string(),
                provider_subject_ref: "hosted-subject-demo".to_string(),
                challenge_nonce: "nonce-export-step-up".to_string(),
                observed_at: Timestamp("2026-05-29T00:00:00Z".to_string()),
                result: ContinuityCheckResult::Passed,
                derived_assurance: AssuranceLevel::High,
                modality: BiometricModality::Face,
                model_version: Some("fen-native-face-match-v1".to_string()),
                pad_result: PresentationAttackDetectionResult::Passed,
            }),
        }
    }

    pub fn with_rotated_signing_key(
        mut self,
        signing_key_id: &str,
        signing_key_seed: [u8; 32],
    ) -> Self {
        let mut retired_key = self.current_verification_key();
        retired_key.status = VerificationKeyStatus::Retired;
        self.retired_verification_keys.push(retired_key);

        self.signing_key = SigningKey::from_bytes(&signing_key_seed);
        self.config.signing_key_id = signing_key_id.to_string();
        self.config.signing_key_material = self.signing_key.verifying_key().to_bytes().to_vec();
        self
    }

    pub fn current_verification_key(&self) -> VerificationKey {
        VerificationKey {
            key_id: self.config.signing_key_id.clone(),
            provider_name: self.config.provider_name.clone(),
            key_material: self.config.signing_key_material.clone(),
            status: VerificationKeyStatus::Active,
        }
    }

    pub fn verification_keys(&self) -> Vec<VerificationKey> {
        let mut keys = self.retired_verification_keys.clone();
        keys.push(self.current_verification_key());
        keys
    }

    pub fn verification_key_registry(&self) -> VerificationKeyRegistry {
        VerificationKeyRegistry::from_keys(self.verification_keys())
    }

    pub fn signature_verifier(&self) -> Ed25519StrictSignatureVerifier {
        Ed25519StrictSignatureVerifier {
            key_registry: self.verification_key_registry(),
        }
    }

    pub fn enrollment_request(
        &self,
        request: &ContinuityEnrollmentRequest,
    ) -> HostedEnrollmentRequest {
        HostedEnrollmentRequest {
            external_subject_ref: format!("fen-subject-{}", request.subject_id.0),
            modality: request.modality.clone(),
            requested_at: request.requested_at.clone(),
        }
    }

    pub fn challenge_request(
        &self,
        challenge: &ContinuityChallenge,
    ) -> HostedContinuityChallengeRequest {
        HostedContinuityChallengeRequest {
            external_enrollment_id: challenge.enrollment_ref.clone(),
            challenge_nonce: challenge.nonce.clone(),
            intended_action: challenge.intended_action,
            expires_at: challenge.expires_at.clone(),
        }
    }
}

#[cfg(feature = "ed25519-dalek-verifier")]
impl ContinuityVaultProvider for FenNativeEd25519HostedContinuityAdapter {
    fn capabilities(&self) -> ContinuityProviderCapabilities {
        ContinuityProviderCapabilities {
            provider_name: self.config.provider_name.clone(),
            supported_modalities: self.config.supported_modalities.clone(),
            supports_liveness: self.config.supports_liveness,
            signs_assertions: true,
            owns_template_storage: self.config.owns_template_storage,
        }
    }

    fn enroll(
        &self,
        request: ContinuityEnrollmentRequest,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError> {
        let hosted_request = self.enrollment_request(&request);
        if !self
            .config
            .supported_modalities
            .contains(&hosted_request.modality)
        {
            return Err(ContinuityProviderError::UnsupportedModality);
        }

        self.enrollment_response
            .clone()
            .map_err(map_hosted_error)?
            .into_enrollment(request.subject_id, &self.config)
    }

    fn prepare_challenge(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<ContinuityChallenge, ContinuityProviderError> {
        let _hosted_request = self.challenge_request(&challenge);
        Ok(challenge)
    }

    fn signed_assertion(
        &self,
        challenge: ContinuityChallenge,
    ) -> Result<SignedContinuityAssertion, ContinuityProviderError> {
        let event = self.continuity_result.clone().map_err(map_hosted_error)?;
        let assertion = event.into_assertion(challenge, &self.config)?;
        let canonical = canonical_continuity_assertion_bytes(&assertion).map_err(|_| {
            ContinuityProviderError::AssertionUnavailable(
                "FEN-native assertion could not be canonicalized".to_string(),
            )
        })?;
        let signature = self.signing_key.sign(&canonical).to_bytes().to_vec();

        Ok(SignedContinuityAssertion {
            assertion,
            signature,
            key_id: self.config.signing_key_id.clone(),
        })
    }
}

impl HostedEnrollmentResponse {
    pub fn into_enrollment(
        self,
        subject_id: SubjectId,
        config: &HostedContinuityProviderConfig,
    ) -> Result<ContinuityEnrollment, ContinuityProviderError> {
        if !config.supported_modalities.contains(&self.modality) {
            return Err(ContinuityProviderError::UnsupportedModality);
        }

        Ok(ContinuityEnrollment {
            subject_id,
            biometric_system: config.provider_name.clone(),
            enrollment_ref: self.external_enrollment_id,
            modality: self.modality,
            provider_metadata: ContinuityProviderMetadata {
                provider_name: config.provider_name.clone(),
                provider_event_id: Some(self.provider_event_id),
                provider_subject_ref: Some(self.provider_subject_ref),
                sdk_or_api_version: Some(config.sdk_or_api_version.clone()),
            },
        })
    }
}

impl HostedContinuityEvent {
    pub fn into_assertion(
        self,
        challenge: ContinuityChallenge,
        config: &HostedContinuityProviderConfig,
    ) -> Result<ContinuityAssertion, ContinuityProviderError> {
        if self.external_enrollment_id != challenge.enrollment_ref {
            return Err(ContinuityProviderError::AssertionUnavailable(
                "provider event enrollment did not match challenge".to_string(),
            ));
        }

        if self.challenge_nonce != challenge.nonce {
            return Err(ContinuityProviderError::AssertionUnavailable(
                "provider event nonce did not match challenge".to_string(),
            ));
        }

        Ok(ContinuityAssertion {
            enrollment_ref: self.external_enrollment_id,
            challenge_nonce: self.challenge_nonce,
            timestamp: self.observed_at,
            result: self.result,
            derived_assurance: self.derived_assurance,
            modality: self.modality,
            model_version: self.model_version,
            pad_result: self.pad_result,
            provider_metadata: ContinuityProviderMetadata {
                provider_name: config.provider_name.clone(),
                provider_event_id: Some(self.provider_event_id),
                provider_subject_ref: Some(self.provider_subject_ref),
                sdk_or_api_version: Some(config.sdk_or_api_version.clone()),
            },
        })
    }
}

fn map_hosted_error(error: HostedProviderErrorCode) -> ContinuityProviderError {
    match error {
        HostedProviderErrorCode::UnsupportedModality => {
            ContinuityProviderError::UnsupportedModality
        }
        HostedProviderErrorCode::EnrollmentRejected => ContinuityProviderError::EnrollmentFailed(
            "hosted provider rejected enrollment".to_string(),
        ),
        HostedProviderErrorCode::ChallengeRejected => {
            ContinuityProviderError::ChallengePreparationFailed(
                "hosted provider rejected challenge".to_string(),
            )
        }
        HostedProviderErrorCode::AssertionNotReady => {
            ContinuityProviderError::AssertionUnavailable(
                "hosted provider assertion not ready".to_string(),
            )
        }
        HostedProviderErrorCode::TemporarilyUnavailable => {
            ContinuityProviderError::ProviderUnavailable
        }
    }
}
