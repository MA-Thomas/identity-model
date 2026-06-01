use crate::continuity::ContinuityProviderMetadata;
use crate::device::VerifiedAppAttestAssertion;
use crate::fen::*;
use crate::identity::*;
use crate::time;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessCeremonyVerificationRequest {
    pub assertion: String,
    pub challenge_nonce: String,
    pub expected_device_ref: Option<DeviceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLivenessCeremony {
    pub provider_metadata: ContinuityProviderMetadata,
    pub challenge_nonce: String,
    pub device_ref: DeviceRef,
    pub observed_at: Timestamp,
    pub expires_at: Timestamp,
    pub result: IdentityWitnessResult,
    pub assurance_level: AssuranceLevel,
    pub pad_result: PresentationAttackDetectionResult,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl VerifiedLivenessCeremony {
    pub fn source_system(&self) -> String {
        self.provider_metadata.provider_name.clone()
    }

    pub fn identity_witness_context(&self) -> IdentityWitnessContext {
        IdentityWitnessContext {
            witness_result: Some(self.result),
            challenge_nonce: Some(self.challenge_nonce.clone()),
            device_ref: Some(self.device_ref.clone()),
            pad_result: Some(self.pad_result),
            retention_policy_refs: self.retention_policy_refs.clone(),
        }
    }

    pub fn external_refs(&self) -> Vec<ExternalRef> {
        let mut refs = Vec::new();

        if let Some(provider_event_id) = &self.provider_metadata.provider_event_id {
            refs.push(ExternalRef {
                system: ExternalSystem::ContinuityProvider,
                resource_type: Some("liveness_ceremony_event".to_string()),
                resource_id: provider_event_id.clone(),
                uri: None,
            });
        }

        if let Some(provider_subject_ref) = &self.provider_metadata.provider_subject_ref {
            refs.push(ExternalRef {
                system: ExternalSystem::ContinuityProvider,
                resource_type: Some("liveness_provider_subject".to_string()),
                resource_id: provider_subject_ref.clone(),
                uri: None,
            });
        }

        refs
    }

    pub fn passed(&self) -> bool {
        self.result == IdentityWitnessResult::Passed
            && self.pad_result == PresentationAttackDetectionResult::Passed
    }
}

pub trait LivenessCeremonyVerifier {
    fn verify_liveness_ceremony(
        &self,
        request: &LivenessCeremonyVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedLivenessCeremony, LivenessCeremonyVerificationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLivenessCeremonyVerifier {
    pub expected_assertion: String,
    pub verified_ceremony: VerifiedLivenessCeremony,
}

impl StaticLivenessCeremonyVerifier {
    pub fn new(
        expected_assertion: impl Into<String>,
        verified_ceremony: VerifiedLivenessCeremony,
    ) -> Self {
        Self {
            expected_assertion: expected_assertion.into(),
            verified_ceremony,
        }
    }
}

impl LivenessCeremonyVerifier for StaticLivenessCeremonyVerifier {
    fn verify_liveness_ceremony(
        &self,
        request: &LivenessCeremonyVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedLivenessCeremony, LivenessCeremonyVerificationError> {
        if request.assertion != self.expected_assertion {
            return Err(LivenessCeremonyVerificationError::InvalidAssertion);
        }

        validate_liveness_ceremony_context(&self.verified_ceremony, request, observed_at)?;

        Ok(self.verified_ceremony.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessCeremonyVerificationError {
    InvalidAssertion,
    MissingChallengeNonce,
    MissingDeviceRef,
    ChallengeMismatch,
    DeviceRefMismatch,
    AppAttestChallengeMismatch,
    AppAttestDeviceMismatch,
    Expired,
    InvalidTimestamp,
}

pub fn validate_liveness_ceremony_context(
    ceremony: &VerifiedLivenessCeremony,
    request: &LivenessCeremonyVerificationRequest,
    observed_at: &Timestamp,
) -> Result<(), LivenessCeremonyVerificationError> {
    if ceremony.challenge_nonce.is_empty() || request.challenge_nonce.is_empty() {
        return Err(LivenessCeremonyVerificationError::MissingChallengeNonce);
    }
    if ceremony.device_ref.is_empty() {
        return Err(LivenessCeremonyVerificationError::MissingDeviceRef);
    }
    if ceremony.challenge_nonce != request.challenge_nonce {
        return Err(LivenessCeremonyVerificationError::ChallengeMismatch);
    }
    if request
        .expected_device_ref
        .as_ref()
        .is_some_and(|device_ref| device_ref != &ceremony.device_ref)
    {
        return Err(LivenessCeremonyVerificationError::DeviceRefMismatch);
    }

    let expired = time::timestamp_at_or_after(observed_at, &ceremony.expires_at)
        .map_err(|_| LivenessCeremonyVerificationError::InvalidTimestamp)?;
    if expired {
        return Err(LivenessCeremonyVerificationError::Expired);
    }

    Ok(())
}

pub fn validate_liveness_bound_to_app_attest(
    ceremony: &VerifiedLivenessCeremony,
    app_attest: &VerifiedAppAttestAssertion,
) -> Result<(), LivenessCeremonyVerificationError> {
    if ceremony.challenge_nonce != app_attest.challenge_nonce {
        return Err(LivenessCeremonyVerificationError::AppAttestChallengeMismatch);
    }
    if ceremony.device_ref != app_attest.device_ref {
        return Err(LivenessCeremonyVerificationError::AppAttestDeviceMismatch);
    }

    Ok(())
}
