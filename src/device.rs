use crate::fen::*;
use crate::identity::*;
use crate::time;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestClientConfig {
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: AppAttestEnvironment,
}

impl AppAttestClientConfig {
    pub fn ios_app(
        team_id: impl Into<String>,
        bundle_id: impl Into<String>,
        environment: AppAttestEnvironment,
    ) -> Self {
        let team_id = team_id.into();
        let bundle_id = bundle_id.into();
        Self {
            app_id: format!("{team_id}.{bundle_id}"),
            team_id,
            bundle_id,
            environment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestEnvironment {
    Development,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestAssertionVerificationRequest {
    pub assertion: String,
    pub challenge_nonce: String,
    pub config: AppAttestClientConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAppAttestAssertion {
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: AppAttestEnvironment,
    pub device_ref: DeviceRef,
    pub key_id: String,
    pub challenge_nonce: String,
    pub sign_count: u64,
    pub asserted_at: Timestamp,
    pub expires_at: Timestamp,
    pub assurance_level: AssuranceLevel,
}

impl VerifiedAppAttestAssertion {
    pub fn source_system(&self) -> String {
        format!("AppleAppAttest:{}", self.app_id)
    }

    pub fn external_refs(&self) -> Vec<ExternalRef> {
        vec![
            ExternalRef {
                system: ExternalSystem::Other("AppleAppAttest".to_string()),
                resource_type: Some("app_attest_key".to_string()),
                resource_id: self.key_id.clone(),
                uri: None,
            },
            ExternalRef {
                system: ExternalSystem::Other("AppleAppAttest".to_string()),
                resource_type: Some("app_id".to_string()),
                resource_id: self.app_id.clone(),
                uri: None,
            },
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestKeyStateStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestKeyState {
    pub key_id: String,
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: AppAttestEnvironment,
    pub device_ref: DeviceRef,
    pub status: AppAttestKeyStateStatus,
    pub registered_at: Timestamp,
    pub last_asserted_at: Timestamp,
    pub last_sign_count: u64,
    pub last_challenge_nonce: Option<String>,
}

impl AppAttestKeyState {
    pub fn active_from_assertion(assertion: &VerifiedAppAttestAssertion) -> Self {
        Self {
            key_id: assertion.key_id.clone(),
            team_id: assertion.team_id.clone(),
            bundle_id: assertion.bundle_id.clone(),
            app_id: assertion.app_id.clone(),
            environment: assertion.environment,
            device_ref: assertion.device_ref.clone(),
            status: AppAttestKeyStateStatus::Active,
            registered_at: assertion.asserted_at.clone(),
            last_asserted_at: assertion.asserted_at.clone(),
            last_sign_count: assertion.sign_count,
            last_challenge_nonce: Some(assertion.challenge_nonce.clone()),
        }
    }

    pub fn matches_assertion_context(&self, assertion: &VerifiedAppAttestAssertion) -> bool {
        self.key_id == assertion.key_id
            && self.team_id == assertion.team_id
            && self.bundle_id == assertion.bundle_id
            && self.app_id == assertion.app_id
            && self.environment == assertion.environment
            && self.device_ref == assertion.device_ref
    }

    pub fn mark_revoked(&mut self) {
        self.status = AppAttestKeyStateStatus::Revoked;
    }
}

pub trait AppAttestKeyStateStore {
    fn record_verified_app_attest_assertion(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError>;

    fn app_attest_key_state(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError>;

    fn app_attest_challenge_nonce_seen(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryAppAttestKeyStateStore {
    inner: Arc<Mutex<InMemoryAppAttestKeyStateStoreInner>>,
}

#[derive(Debug, Default)]
struct InMemoryAppAttestKeyStateStoreInner {
    keys: BTreeMap<String, AppAttestKeyState>,
    used_challenge_nonces: BTreeSet<(String, String)>,
}

impl InMemoryAppAttestKeyStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke_app_attest_key(
        &self,
        key_id: &str,
    ) -> Result<(), AppAttestAssertionVerificationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        let state = inner
            .keys
            .get_mut(key_id)
            .ok_or(AppAttestAssertionVerificationError::MissingKeyId)?;
        state.mark_revoked();
        Ok(())
    }
}

impl AppAttestKeyStateStore for InMemoryAppAttestKeyStateStore {
    fn record_verified_app_attest_assertion(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        let nonce_key = (assertion.key_id.clone(), assertion.challenge_nonce.clone());
        if inner.used_challenge_nonces.contains(&nonce_key) {
            return Err(AppAttestAssertionVerificationError::ChallengeReplay);
        }

        let updated = match inner.keys.get_mut(&assertion.key_id) {
            Some(state) => {
                if state.status == AppAttestKeyStateStatus::Revoked {
                    return Err(AppAttestAssertionVerificationError::KeyRevoked);
                }
                if !state.matches_assertion_context(assertion) {
                    return Err(AppAttestAssertionVerificationError::KeyContextMismatch);
                }
                if assertion.sign_count <= state.last_sign_count {
                    return Err(AppAttestAssertionVerificationError::SignCountNotAdvanced);
                }
                state.last_sign_count = assertion.sign_count;
                state.last_asserted_at = assertion.asserted_at.clone();
                state.last_challenge_nonce = Some(assertion.challenge_nonce.clone());
                state.clone()
            }
            None => {
                let state = AppAttestKeyState::active_from_assertion(assertion);
                inner.keys.insert(assertion.key_id.clone(), state.clone());
                state
            }
        };

        inner.used_challenge_nonces.insert(nonce_key);
        Ok(updated)
    }

    fn app_attest_key_state(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        Ok(inner.keys.get(key_id).cloned())
    }

    fn app_attest_challenge_nonce_seen(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        Ok(inner
            .used_challenge_nonces
            .contains(&(key_id.to_string(), challenge_nonce.to_string())))
    }
}

#[derive(Debug, Clone)]
pub struct StatefulAppAttestAssertionVerifier<V, S = InMemoryAppAttestKeyStateStore> {
    verifier: V,
    key_state_store: S,
}

impl<V> StatefulAppAttestAssertionVerifier<V, InMemoryAppAttestKeyStateStore> {
    pub fn with_in_memory_store(verifier: V) -> Self {
        Self::new(verifier, InMemoryAppAttestKeyStateStore::new())
    }
}

impl<V, S> StatefulAppAttestAssertionVerifier<V, S> {
    pub fn new(verifier: V, key_state_store: S) -> Self {
        Self {
            verifier,
            key_state_store,
        }
    }

    pub fn key_state_store(&self) -> &S {
        &self.key_state_store
    }
}

impl<V, S> AppAttestAssertionVerifier for StatefulAppAttestAssertionVerifier<V, S>
where
    V: AppAttestAssertionVerifier,
    S: AppAttestKeyStateStore,
{
    fn verify_app_attest_assertion(
        &self,
        request: &AppAttestAssertionVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedAppAttestAssertion, AppAttestAssertionVerificationError> {
        let assertion = self
            .verifier
            .verify_app_attest_assertion(request, observed_at)?;
        self.key_state_store
            .record_verified_app_attest_assertion(&assertion)?;
        Ok(assertion)
    }
}

pub trait AppAttestAssertionVerifier {
    fn verify_app_attest_assertion(
        &self,
        request: &AppAttestAssertionVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedAppAttestAssertion, AppAttestAssertionVerificationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAppAttestAssertionVerifier {
    pub expected_assertion: String,
    pub verified_assertion: VerifiedAppAttestAssertion,
}

impl StaticAppAttestAssertionVerifier {
    pub fn new(
        expected_assertion: impl Into<String>,
        verified_assertion: VerifiedAppAttestAssertion,
    ) -> Self {
        Self {
            expected_assertion: expected_assertion.into(),
            verified_assertion,
        }
    }
}

impl AppAttestAssertionVerifier for StaticAppAttestAssertionVerifier {
    fn verify_app_attest_assertion(
        &self,
        request: &AppAttestAssertionVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedAppAttestAssertion, AppAttestAssertionVerificationError> {
        if request.assertion != self.expected_assertion {
            return Err(AppAttestAssertionVerificationError::InvalidAssertion);
        }

        validate_app_attest_assertion_context(
            &self.verified_assertion,
            &request.config,
            &request.challenge_nonce,
            observed_at,
        )?;

        Ok(self.verified_assertion.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestAssertionVerificationError {
    InvalidAssertion,
    MissingChallengeNonce,
    MissingDeviceRef,
    MissingKeyId,
    TeamMismatch,
    BundleMismatch,
    AppIdMismatch,
    EnvironmentMismatch,
    ChallengeMismatch,
    Expired,
    InvalidTimestamp,
    KeyStateUnavailable,
    KeyRevoked,
    KeyContextMismatch,
    ChallengeReplay,
    SignCountNotAdvanced,
}

pub fn validate_app_attest_assertion_context(
    assertion: &VerifiedAppAttestAssertion,
    config: &AppAttestClientConfig,
    challenge_nonce: &str,
    observed_at: &Timestamp,
) -> Result<(), AppAttestAssertionVerificationError> {
    if assertion.challenge_nonce.is_empty() || challenge_nonce.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingChallengeNonce);
    }
    if assertion.device_ref.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingDeviceRef);
    }
    if assertion.key_id.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingKeyId);
    }
    if assertion.team_id != config.team_id {
        return Err(AppAttestAssertionVerificationError::TeamMismatch);
    }
    if assertion.bundle_id != config.bundle_id {
        return Err(AppAttestAssertionVerificationError::BundleMismatch);
    }
    if assertion.app_id != config.app_id {
        return Err(AppAttestAssertionVerificationError::AppIdMismatch);
    }
    if assertion.environment != config.environment {
        return Err(AppAttestAssertionVerificationError::EnvironmentMismatch);
    }
    if assertion.challenge_nonce != challenge_nonce {
        return Err(AppAttestAssertionVerificationError::ChallengeMismatch);
    }
    let expired = time::timestamp_at_or_after(observed_at, &assertion.expires_at)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidTimestamp)?;
    if expired {
        return Err(AppAttestAssertionVerificationError::Expired);
    }

    Ok(())
}
