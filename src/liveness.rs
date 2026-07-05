use crate::continuity::ContinuityProviderMetadata;
use crate::device::VerifiedAppAttestAssertion;
use crate::device::{AppAttestClientConfig, AppAttestEnvironment};
use crate::fen::*;
use crate::identity::*;
use crate::time;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

typed_id!(LivePresenceChallengeId);

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessProviderCallbackVerificationRequest {
    pub provider_metadata: ContinuityProviderMetadata,
    pub assertion: String,
    pub challenge_nonce: String,
    pub device_ref: DeviceRef,
    pub observed_at: Timestamp,
    pub expires_at: Timestamp,
    pub result: IdentityWitnessResult,
    pub assurance_level: AssuranceLevel,
    pub pad_result: PresentationAttackDetectionResult,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl LivenessProviderCallbackVerificationRequest {
    pub fn into_verified_ceremony(self) -> VerifiedLivenessCeremony {
        VerifiedLivenessCeremony {
            provider_metadata: self.provider_metadata,
            challenge_nonce: self.challenge_nonce,
            device_ref: self.device_ref,
            observed_at: self.observed_at,
            expires_at: self.expires_at,
            result: self.result,
            assurance_level: self.assurance_level,
            pad_result: self.pad_result,
            retention_policy_refs: self.retention_policy_refs,
        }
    }
}

pub trait LivenessProviderCallbackVerifier {
    fn verify_liveness_provider_callback(
        &self,
        request: LivenessProviderCallbackVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedLivenessCeremony, LivenessProviderCallbackVerificationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLivenessProviderCallbackVerifier {
    pub expected_provider_name: String,
    pub expected_assertion: String,
}

impl StaticLivenessProviderCallbackVerifier {
    pub fn new(
        expected_provider_name: impl Into<String>,
        expected_assertion: impl Into<String>,
    ) -> Self {
        Self {
            expected_provider_name: expected_provider_name.into(),
            expected_assertion: expected_assertion.into(),
        }
    }
}

impl LivenessProviderCallbackVerifier for StaticLivenessProviderCallbackVerifier {
    fn verify_liveness_provider_callback(
        &self,
        request: LivenessProviderCallbackVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedLivenessCeremony, LivenessProviderCallbackVerificationError> {
        if request.provider_metadata.provider_name != self.expected_provider_name {
            return Err(LivenessProviderCallbackVerificationError::ProviderMismatch);
        }
        if request.assertion != self.expected_assertion {
            return Err(LivenessProviderCallbackVerificationError::InvalidAssertion);
        }
        validate_liveness_provider_callback_request(&request, observed_at)?;
        Ok(request.into_verified_ceremony())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessProviderCallbackVerificationError {
    InvalidAssertion,
    ProviderMismatch,
    MissingProviderName,
    MissingChallengeNonce,
    MissingDeviceRef,
    FutureObservedAt,
    Expired,
    InvalidTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePresenceExpectedAppContext {
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: AppAttestEnvironment,
}

impl LivePresenceExpectedAppContext {
    pub fn from_app_attest_config(config: &AppAttestClientConfig) -> Self {
        Self {
            team_id: config.team_id.clone(),
            bundle_id: config.bundle_id.clone(),
            app_id: config.app_id.clone(),
            environment: config.environment,
        }
    }

    pub fn from_verified_app_attest(assertion: &VerifiedAppAttestAssertion) -> Self {
        Self {
            team_id: assertion.team_id.clone(),
            bundle_id: assertion.bundle_id.clone(),
            app_id: assertion.app_id.clone(),
            environment: assertion.environment,
        }
    }

    pub fn matches_app_attest(&self, assertion: &VerifiedAppAttestAssertion) -> bool {
        self.team_id == assertion.team_id
            && self.bundle_id == assertion.bundle_id
            && self.app_id == assertion.app_id
            && self.environment == assertion.environment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePresenceChallengeWorkflow {
    MobileIdentityOnboarding,
    AccountRecovery,
    SensitiveActionStepUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePresenceChallenge {
    pub challenge_id: LivePresenceChallengeId,
    pub challenge_nonce: String,
    pub intended_workflow: LivePresenceChallengeWorkflow,
    pub expected_subject_id: Option<SubjectId>,
    pub expected_device_ref: Option<DeviceRef>,
    pub expected_app: Option<LivePresenceExpectedAppContext>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub status: LivePresenceChallengeStatus,
    pub retry_policy_refs: Vec<PolicyRef>,
    pub manual_review_policy_refs: Vec<PolicyRef>,
    pub retention_policy_refs: Vec<PolicyRef>,
}

impl LivePresenceChallenge {
    pub fn onboarding(
        challenge_id: LivePresenceChallengeId,
        challenge_nonce: impl Into<String>,
        expected_subject_id: Option<SubjectId>,
        expected_device_ref: Option<DeviceRef>,
        expected_app: Option<LivePresenceExpectedAppContext>,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            challenge_id,
            challenge_nonce: challenge_nonce.into(),
            intended_workflow: LivePresenceChallengeWorkflow::MobileIdentityOnboarding,
            expected_subject_id,
            expected_device_ref,
            expected_app,
            issued_at,
            expires_at,
            status: LivePresenceChallengeStatus::Issued,
            retry_policy_refs: Vec::new(),
            manual_review_policy_refs: Vec::new(),
            retention_policy_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePresenceChallengeStatus {
    Issued,
    Used {
        used_at: Timestamp,
        provider_event_id: Option<String>,
    },
    Expired {
        expired_at: Timestamp,
    },
    Failed {
        failed_at: Timestamp,
        reason: LivePresenceChallengeFailureReason,
        provider_event_id: Option<String>,
    },
    ManualReview {
        referred_at: Timestamp,
        reason: LivePresenceChallengeManualReviewReason,
        provider_event_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePresenceChallengeFailureReason {
    LivenessFailed,
    PresentationAttackDetected,
    ChallengeMismatch,
    SubjectMismatch,
    DeviceMismatch,
    AppContextMismatch,
    ProviderRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePresenceChallengeManualReviewReason {
    LivenessInconclusive,
    PresentationAttackInconclusive,
    RetryOrReviewPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePresenceChallengeError {
    DuplicateChallengeId,
    DuplicateChallengeNonce,
    MissingChallengeNonce,
    UnknownChallenge,
    ChallengeAlreadyConsumed,
    ChallengeExpired,
    ChallengeNonceMismatch,
    SubjectMismatch,
    DeviceMismatch,
    AppContextMismatch,
    InvalidTimestamp,
    StorageUnavailable,
}

pub trait LivePresenceChallengeStore {
    fn issue_live_presence_challenge(
        &self,
        challenge: LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError>;

    fn live_presence_challenge_by_nonce(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError>;

    fn record_live_presence_challenge_status(
        &self,
        challenge_nonce: &str,
        status: LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError>;

    fn consume_verified_live_presence_challenge(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryLivePresenceChallengeStore {
    inner: Arc<Mutex<InMemoryLivePresenceChallengeStoreInner>>,
}

#[derive(Debug, Default)]
struct InMemoryLivePresenceChallengeStoreInner {
    challenges_by_nonce: BTreeMap<String, LivePresenceChallenge>,
    challenge_ids: HashSet<LivePresenceChallengeId>,
}

impl InMemoryLivePresenceChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LivePresenceChallengeStore for InMemoryLivePresenceChallengeStore {
    fn issue_live_presence_challenge(
        &self,
        challenge: LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        if challenge.challenge_nonce.is_empty() {
            return Err(LivePresenceChallengeError::MissingChallengeNonce);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        if inner.challenge_ids.contains(&challenge.challenge_id) {
            return Err(LivePresenceChallengeError::DuplicateChallengeId);
        }
        if inner
            .challenges_by_nonce
            .contains_key(&challenge.challenge_nonce)
        {
            return Err(LivePresenceChallengeError::DuplicateChallengeNonce);
        }
        inner.challenge_ids.insert(challenge.challenge_id.clone());
        inner
            .challenges_by_nonce
            .insert(challenge.challenge_nonce.clone(), challenge.clone());
        Ok(challenge)
    }

    fn live_presence_challenge_by_nonce(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        Ok(inner.challenges_by_nonce.get(challenge_nonce).cloned())
    }

    fn record_live_presence_challenge_status(
        &self,
        challenge_nonce: &str,
        status: LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        let challenge = inner
            .challenges_by_nonce
            .get_mut(challenge_nonce)
            .ok_or(LivePresenceChallengeError::UnknownChallenge)?;
        if !matches!(challenge.status, LivePresenceChallengeStatus::Issued) {
            return Err(LivePresenceChallengeError::ChallengeAlreadyConsumed);
        }
        challenge.status = status;
        Ok(challenge.clone())
    }

    fn consume_verified_live_presence_challenge(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        let challenge = inner
            .challenges_by_nonce
            .get_mut(&ceremony.challenge_nonce)
            .ok_or(LivePresenceChallengeError::UnknownChallenge)?;

        if let Err(error) = validate_live_presence_challenge_context(
            challenge,
            ceremony,
            app_attest,
            subject_id,
            observed_at,
        ) {
            if let Some(status) =
                terminal_live_presence_challenge_status_for_error(error, observed_at.clone())
            {
                challenge.status = status;
            }
            return Err(error);
        }

        challenge.status =
            terminal_live_presence_challenge_status_for_ceremony(ceremony, observed_at.clone());
        Ok(challenge.clone())
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
    pub bind_request_challenge_nonce: bool,
    pub bind_request_device_ref: bool,
}

impl StaticLivenessCeremonyVerifier {
    pub fn new(
        expected_assertion: impl Into<String>,
        verified_ceremony: VerifiedLivenessCeremony,
    ) -> Self {
        Self {
            expected_assertion: expected_assertion.into(),
            verified_ceremony,
            bind_request_challenge_nonce: false,
            bind_request_device_ref: false,
        }
    }

    pub fn with_request_challenge_nonce(mut self) -> Self {
        self.bind_request_challenge_nonce = true;
        self
    }

    // Rebinds the verified ceremony's device ref to the request's expected device
    // ref, mirroring `with_request_challenge_nonce`. In apple_assertion mode the
    // device ref is dynamic (a real per-install phone value), so pinning it in the
    // static template would fail the downstream ceremony/App-Attest device binding.
    pub fn with_request_device_ref(mut self) -> Self {
        self.bind_request_device_ref = true;
        self
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

        let mut verified_ceremony = self.verified_ceremony.clone();
        if self.bind_request_challenge_nonce {
            verified_ceremony.challenge_nonce = request.challenge_nonce.clone();
        }
        if self.bind_request_device_ref {
            if let Some(device_ref) = request.expected_device_ref.clone() {
                verified_ceremony.device_ref = device_ref;
            }
        }

        validate_liveness_ceremony_context(&verified_ceremony, request, observed_at)?;

        Ok(verified_ceremony)
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

pub fn validate_live_presence_challenge_context(
    challenge: &LivePresenceChallenge,
    ceremony: &VerifiedLivenessCeremony,
    app_attest: &VerifiedAppAttestAssertion,
    subject_id: &SubjectId,
    observed_at: &Timestamp,
) -> Result<(), LivePresenceChallengeError> {
    if challenge.challenge_nonce.is_empty() || ceremony.challenge_nonce.is_empty() {
        return Err(LivePresenceChallengeError::MissingChallengeNonce);
    }
    if challenge.challenge_nonce != ceremony.challenge_nonce
        || challenge.challenge_nonce != app_attest.challenge_nonce
    {
        return Err(LivePresenceChallengeError::ChallengeNonceMismatch);
    }
    match challenge.status {
        LivePresenceChallengeStatus::Issued => {}
        LivePresenceChallengeStatus::Expired { .. } => {
            return Err(LivePresenceChallengeError::ChallengeExpired);
        }
        _ => return Err(LivePresenceChallengeError::ChallengeAlreadyConsumed),
    }
    let expired = time::timestamp_at_or_after(observed_at, &challenge.expires_at)
        .map_err(|_| LivePresenceChallengeError::InvalidTimestamp)?;
    if expired {
        return Err(LivePresenceChallengeError::ChallengeExpired);
    }
    if challenge
        .expected_subject_id
        .as_ref()
        .is_some_and(|expected| expected != subject_id)
    {
        return Err(LivePresenceChallengeError::SubjectMismatch);
    }
    if challenge
        .expected_device_ref
        .as_ref()
        .is_some_and(|expected| {
            expected != &ceremony.device_ref || expected != &app_attest.device_ref
        })
    {
        return Err(LivePresenceChallengeError::DeviceMismatch);
    }
    if ceremony.device_ref != app_attest.device_ref {
        return Err(LivePresenceChallengeError::DeviceMismatch);
    }
    if challenge
        .expected_app
        .as_ref()
        .is_some_and(|expected| !expected.matches_app_attest(app_attest))
    {
        return Err(LivePresenceChallengeError::AppContextMismatch);
    }

    Ok(())
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

pub fn validate_liveness_provider_callback_request(
    request: &LivenessProviderCallbackVerificationRequest,
    observed_at: &Timestamp,
) -> Result<(), LivenessProviderCallbackVerificationError> {
    if request.provider_metadata.provider_name.trim().is_empty() {
        return Err(LivenessProviderCallbackVerificationError::MissingProviderName);
    }
    if request.challenge_nonce.is_empty() {
        return Err(LivenessProviderCallbackVerificationError::MissingChallengeNonce);
    }
    if request.device_ref.is_empty() {
        return Err(LivenessProviderCallbackVerificationError::MissingDeviceRef);
    }

    time::timestamp_to_unix_seconds(observed_at)
        .map_err(|_| LivenessProviderCallbackVerificationError::InvalidTimestamp)?;
    let callback_after_observed = time::timestamp_after(&request.observed_at, observed_at)
        .map_err(|_| LivenessProviderCallbackVerificationError::InvalidTimestamp)?;
    if callback_after_observed {
        return Err(LivenessProviderCallbackVerificationError::FutureObservedAt);
    }

    let expired = time::timestamp_at_or_after(observed_at, &request.expires_at)
        .map_err(|_| LivenessProviderCallbackVerificationError::InvalidTimestamp)?;
    if expired {
        return Err(LivenessProviderCallbackVerificationError::Expired);
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

pub fn terminal_live_presence_challenge_status_for_ceremony(
    ceremony: &VerifiedLivenessCeremony,
    observed_at: Timestamp,
) -> LivePresenceChallengeStatus {
    let provider_event_id = ceremony.provider_metadata.provider_event_id.clone();
    if ceremony.passed() {
        return LivePresenceChallengeStatus::Used {
            used_at: observed_at,
            provider_event_id,
        };
    }
    if ceremony.result == IdentityWitnessResult::Inconclusive {
        return LivePresenceChallengeStatus::ManualReview {
            referred_at: observed_at,
            reason: LivePresenceChallengeManualReviewReason::LivenessInconclusive,
            provider_event_id,
        };
    }
    if ceremony.pad_result == PresentationAttackDetectionResult::Inconclusive {
        return LivePresenceChallengeStatus::ManualReview {
            referred_at: observed_at,
            reason: LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive,
            provider_event_id,
        };
    }
    let reason = if ceremony.pad_result == PresentationAttackDetectionResult::Failed {
        LivePresenceChallengeFailureReason::PresentationAttackDetected
    } else {
        LivePresenceChallengeFailureReason::LivenessFailed
    };
    LivePresenceChallengeStatus::Failed {
        failed_at: observed_at,
        reason,
        provider_event_id,
    }
}

fn terminal_live_presence_challenge_status_for_error(
    error: LivePresenceChallengeError,
    observed_at: Timestamp,
) -> Option<LivePresenceChallengeStatus> {
    match error {
        LivePresenceChallengeError::ChallengeExpired => {
            Some(LivePresenceChallengeStatus::Expired {
                expired_at: observed_at,
            })
        }
        LivePresenceChallengeError::ChallengeNonceMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::ChallengeMismatch,
                provider_event_id: None,
            })
        }
        LivePresenceChallengeError::SubjectMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::SubjectMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::DeviceMismatch => Some(LivePresenceChallengeStatus::Failed {
            failed_at: observed_at,
            reason: LivePresenceChallengeFailureReason::DeviceMismatch,
            provider_event_id: None,
        }),
        LivePresenceChallengeError::AppContextMismatch => {
            Some(LivePresenceChallengeStatus::Failed {
                failed_at: observed_at,
                reason: LivePresenceChallengeFailureReason::AppContextMismatch,
                provider_event_id: None,
            })
        }
        _ => None,
    }
}
