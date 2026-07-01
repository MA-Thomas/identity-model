use crate::fen::*;
use crate::identity::*;
use crate::time;
#[cfg(feature = "production-crypto")]
use ring::{digest, signature};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestKeyRegistration {
    pub key_id: String,
    pub team_id: String,
    pub bundle_id: String,
    pub app_id: String,
    pub environment: AppAttestEnvironment,
    pub device_ref: DeviceRef,
    pub public_key_bytes: Vec<u8>,
    pub registered_at: Timestamp,
    pub attestation_challenge_nonce: String,
    pub attestation_format: String,
}

impl AppAttestKeyRegistration {
    pub fn matches_assertion_context(&self, assertion: &VerifiedAppAttestAssertion) -> bool {
        self.key_id == assertion.key_id
            && self.team_id == assertion.team_id
            && self.bundle_id == assertion.bundle_id
            && self.app_id == assertion.app_id
            && self.environment == assertion.environment
            && self.device_ref == assertion.device_ref
    }
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

pub trait AppAttestKeyRegistrationStore {
    fn record_app_attest_key_registration(
        &self,
        registration: &AppAttestKeyRegistration,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError>;

    fn app_attest_key_registration(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyRegistration>, AppAttestAssertionVerificationError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryAppAttestKeyStateStore {
    inner: Arc<Mutex<InMemoryAppAttestKeyStateStoreInner>>,
}

#[derive(Debug, Default)]
struct InMemoryAppAttestKeyStateStoreInner {
    keys: BTreeMap<String, AppAttestKeyState>,
    registrations: BTreeMap<String, AppAttestKeyRegistration>,
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

impl AppAttestKeyRegistrationStore for InMemoryAppAttestKeyStateStore {
    fn record_app_attest_key_registration(
        &self,
        registration: &AppAttestKeyRegistration,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError> {
        validate_app_attest_key_registration(registration)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        match inner.registrations.get(&registration.key_id) {
            Some(existing) if existing == registration => Ok(existing.clone()),
            Some(_) => Err(AppAttestAssertionVerificationError::KeyContextMismatch),
            None => {
                inner
                    .registrations
                    .insert(registration.key_id.clone(), registration.clone());
                Ok(registration.clone())
            }
        }
    }

    fn app_attest_key_registration(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyRegistration>, AppAttestAssertionVerificationError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?;
        Ok(inner.registrations.get(key_id).cloned())
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
    pub bind_request_challenge_nonce: bool,
}

impl StaticAppAttestAssertionVerifier {
    pub fn new(
        expected_assertion: impl Into<String>,
        verified_assertion: VerifiedAppAttestAssertion,
    ) -> Self {
        Self {
            expected_assertion: expected_assertion.into(),
            verified_assertion,
            bind_request_challenge_nonce: false,
        }
    }

    pub fn with_request_challenge_nonce(mut self) -> Self {
        self.bind_request_challenge_nonce = true;
        self
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

        let mut verified_assertion = self.verified_assertion.clone();
        if self.bind_request_challenge_nonce {
            verified_assertion.challenge_nonce = request.challenge_nonce.clone();
        }

        validate_app_attest_assertion_context(
            &verified_assertion,
            &request.config,
            &request.challenge_nonce,
            observed_at,
        )?;

        Ok(verified_assertion)
    }
}

#[cfg(feature = "production-crypto")]
pub trait AppAttestPublicKeyResolver {
    fn app_attest_public_key_bytes(
        &self,
        key_id: &str,
    ) -> Result<Vec<u8>, AppAttestAssertionVerificationError>;
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticAppAttestPublicKeyResolver {
    public_key_bytes_by_key_id: BTreeMap<String, Vec<u8>>,
}

#[cfg(feature = "production-crypto")]
impl StaticAppAttestPublicKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_key(
        mut self,
        key_id: impl Into<String>,
        public_key_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        self.public_key_bytes_by_key_id
            .insert(key_id.into(), public_key_bytes.into());
        self
    }
}

#[cfg(feature = "production-crypto")]
impl AppAttestPublicKeyResolver for StaticAppAttestPublicKeyResolver {
    fn app_attest_public_key_bytes(
        &self,
        key_id: &str,
    ) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
        self.public_key_bytes_by_key_id
            .get(key_id)
            .cloned()
            .ok_or(AppAttestAssertionVerificationError::MissingPublicKey)
    }
}

#[cfg(feature = "production-crypto")]
impl<T> AppAttestPublicKeyResolver for T
where
    T: AppAttestKeyRegistrationStore,
{
    fn app_attest_public_key_bytes(
        &self,
        key_id: &str,
    ) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
        self.app_attest_key_registration(key_id)?
            .map(|registration| registration.public_key_bytes)
            .ok_or(AppAttestAssertionVerificationError::MissingPublicKey)
    }
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestKeyRegistrationVerificationRequest {
    pub key_id: String,
    pub device_ref: DeviceRef,
    pub public_key_bytes: Vec<u8>,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub challenge_nonce: String,
    pub registered_at: Timestamp,
    pub attestation_format: String,
    pub config: AppAttestClientConfig,
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestAttestationObject {
    pub fmt: String,
    pub authenticator_data: Vec<u8>,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub receipt: Option<Vec<u8>>,
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestAttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
}

#[cfg(feature = "production-crypto")]
impl AppleAppAttestKeyRegistrationVerificationRequest {
    pub fn from_attestation_object_envelope(
        envelope: &str,
        config: AppAttestClientConfig,
    ) -> Result<Self, AppAttestAssertionVerificationError> {
        let mut parts = envelope.split('|');
        if parts.next() != Some(APPLE_APP_ATTEST_REGISTRATION_OBJECT_PREFIX) {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        let key_id = utf8_field(parts.next())?;
        let device_ref = utf8_field(parts.next())?;
        let attestation_object = hex_field(parts.next())?;
        let challenge_nonce = utf8_field(parts.next())?;
        let registered_at = Timestamp(utf8_field(parts.next())?);
        if parts.next().is_some() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        let attestation_object = parse_apple_app_attest_attestation_object(&attestation_object)?;
        Self::from_attestation_object(
            key_id,
            device_ref,
            challenge_nonce,
            registered_at,
            config,
            attestation_object,
        )
    }

    pub fn from_attestation_object(
        key_id: String,
        device_ref: DeviceRef,
        challenge_nonce: String,
        registered_at: Timestamp,
        config: AppAttestClientConfig,
        attestation_object: AppleAppAttestAttestationObject,
    ) -> Result<Self, AppAttestAssertionVerificationError> {
        if attestation_object.fmt != APPLE_APP_ATTEST_CBOR_FORMAT {
            return Err(AppAttestAssertionVerificationError::UnsupportedAttestationFormat);
        }
        let attested_credential = parse_apple_app_attest_attested_credential_data(
            &attestation_object.authenticator_data,
            &config,
        )?;

        Ok(Self {
            key_id,
            device_ref,
            public_key_bytes: attested_credential.public_key_bytes,
            certificate_chain_der: attestation_object.certificate_chain_der,
            credential_id: attested_credential.credential_id,
            authenticator_data: attestation_object.authenticator_data,
            client_data_hash: apple_app_attest_client_data_hash(&challenge_nonce),
            challenge_nonce,
            registered_at,
            attestation_format: APPLE_APP_ATTEST_REGISTRATION_FORMAT.to_string(),
            config,
        })
    }

    pub fn to_attestation_object_envelope(&self) -> String {
        let attestation_object = encode_apple_app_attest_attestation_object(
            &self.authenticator_data,
            &self.certificate_chain_der,
            None,
        );
        [
            APPLE_APP_ATTEST_REGISTRATION_OBJECT_PREFIX.to_string(),
            hex_encode(self.key_id.as_bytes()),
            hex_encode(self.device_ref.as_bytes()),
            hex_encode(&attestation_object),
            hex_encode(self.challenge_nonce.as_bytes()),
            hex_encode(self.registered_at.0.as_bytes()),
        ]
        .join("|")
    }
}

#[cfg(feature = "production-crypto")]
pub trait AppAttestKeyRegistrationVerifier {
    fn verify_app_attest_key_registration(
        &self,
        request: &AppleAppAttestKeyRegistrationVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError>;
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestKeyRegistrationVerifier {
    expected_config: AppAttestClientConfig,
    trusted_root_certificates_der: Vec<Vec<u8>>,
}

#[cfg(feature = "production-crypto")]
impl AppleAppAttestKeyRegistrationVerifier {
    pub fn new(expected_config: AppAttestClientConfig) -> Self {
        Self {
            expected_config,
            trusted_root_certificates_der: vec![apple_app_attest_root_ca_der()],
        }
    }

    pub fn with_trusted_root_certificates(
        expected_config: AppAttestClientConfig,
        trusted_root_certificates_der: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            expected_config,
            trusted_root_certificates_der,
        }
    }
}

#[cfg(feature = "production-crypto")]
impl AppAttestKeyRegistrationVerifier for AppleAppAttestKeyRegistrationVerifier {
    fn verify_app_attest_key_registration(
        &self,
        request: &AppleAppAttestKeyRegistrationVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError> {
        validate_app_attest_request_config(&request.config, &self.expected_config)?;
        validate_apple_app_attest_key_registration_request(
            request,
            &self.expected_config,
            observed_at,
            &self.trusted_root_certificates_der,
        )?;

        Ok(AppAttestKeyRegistration {
            key_id: request.key_id.clone(),
            team_id: self.expected_config.team_id.clone(),
            bundle_id: self.expected_config.bundle_id.clone(),
            app_id: self.expected_config.app_id.clone(),
            environment: self.expected_config.environment,
            device_ref: request.device_ref.clone(),
            public_key_bytes: request.public_key_bytes.clone(),
            registered_at: request.registered_at.clone(),
            attestation_challenge_nonce: request.challenge_nonce.clone(),
            attestation_format: request.attestation_format.clone(),
        })
    }
}

#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_ASSERTION_PREFIX: &str = "apple-app-attest-assertion-v1";
#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_ASSERTION_OBJECT_PREFIX: &str = "apple-app-attest-assertion-object-v1";
#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_REGISTRATION_OBJECT_PREFIX: &str = "apple-app-attest-registration-object-v1";
#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_CBOR_FORMAT: &str = "apple-appattest";
#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_REGISTRATION_FORMAT: &str = "apple-app-attest";

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestAssertionEvidence {
    pub device_ref: DeviceRef,
    pub key_id: String,
    pub authenticator_data: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub signature_der: Vec<u8>,
    pub asserted_at: Timestamp,
    pub expires_at: Timestamp,
    pub assurance_level: AssuranceLevel,
}

#[cfg(feature = "production-crypto")]
impl AppleAppAttestAssertionEvidence {
    pub fn to_compact_assertion(&self) -> String {
        [
            APPLE_APP_ATTEST_ASSERTION_PREFIX.to_string(),
            hex_encode(self.key_id.as_bytes()),
            hex_encode(self.device_ref.as_bytes()),
            hex_encode(&self.authenticator_data),
            hex_encode(&self.client_data_hash),
            hex_encode(&self.signature_der),
            hex_encode(self.asserted_at.0.as_bytes()),
            hex_encode(self.expires_at.0.as_bytes()),
            assurance_level_label(self.assurance_level).to_string(),
        ]
        .join("|")
    }

    pub fn from_compact_assertion(
        assertion: &str,
    ) -> Result<Self, AppAttestAssertionVerificationError> {
        let mut parts = assertion.split('|');
        if parts.next() != Some(APPLE_APP_ATTEST_ASSERTION_PREFIX) {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        let key_id = utf8_field(parts.next())?;
        let device_ref = utf8_field(parts.next())?;
        let authenticator_data = hex_field(parts.next())?;
        let client_data_hash = hex_field(parts.next())?;
        let signature_der = hex_field(parts.next())?;
        let asserted_at = Timestamp(utf8_field(parts.next())?);
        let expires_at = Timestamp(utf8_field(parts.next())?);
        let assurance_level = parse_assurance_level(
            parts
                .next()
                .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        )?;

        if parts.next().is_some() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        Ok(Self {
            device_ref,
            key_id,
            authenticator_data,
            client_data_hash,
            signature_der,
            asserted_at,
            expires_at,
            assurance_level,
        })
    }

    pub fn to_assertion_object_envelope(&self) -> String {
        let assertion_object =
            encode_apple_app_attest_assertion_object(&self.authenticator_data, &self.signature_der);
        [
            APPLE_APP_ATTEST_ASSERTION_OBJECT_PREFIX.to_string(),
            hex_encode(self.key_id.as_bytes()),
            hex_encode(self.device_ref.as_bytes()),
            hex_encode(&assertion_object),
            hex_encode(self.asserted_at.0.as_bytes()),
            hex_encode(self.expires_at.0.as_bytes()),
            assurance_level_label(self.assurance_level).to_string(),
        ]
        .join("|")
    }

    pub fn from_assertion_object_envelope(
        assertion: &str,
        challenge_nonce: &str,
    ) -> Result<Self, AppAttestAssertionVerificationError> {
        let mut parts = assertion.split('|');
        if parts.next() != Some(APPLE_APP_ATTEST_ASSERTION_OBJECT_PREFIX) {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        let key_id = utf8_field(parts.next())?;
        let device_ref = utf8_field(parts.next())?;
        let assertion_object = hex_field(parts.next())?;
        let asserted_at = Timestamp(utf8_field(parts.next())?);
        let expires_at = Timestamp(utf8_field(parts.next())?);
        let assurance_level = parse_assurance_level(
            parts
                .next()
                .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        )?;

        if parts.next().is_some() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }

        let assertion_object = parse_apple_app_attest_assertion_object(&assertion_object)?;
        Ok(Self {
            device_ref,
            key_id,
            authenticator_data: assertion_object.authenticator_data,
            client_data_hash: apple_app_attest_client_data_hash(challenge_nonce),
            signature_der: assertion_object.signature_der,
            asserted_at,
            expires_at,
            assurance_level,
        })
    }

    pub fn from_request_assertion(
        assertion: &str,
        challenge_nonce: &str,
    ) -> Result<Self, AppAttestAssertionVerificationError> {
        if assertion.starts_with(APPLE_APP_ATTEST_ASSERTION_PREFIX) {
            return Self::from_compact_assertion(assertion);
        }
        if assertion.starts_with(APPLE_APP_ATTEST_ASSERTION_OBJECT_PREFIX) {
            return Self::from_assertion_object_envelope(assertion, challenge_nonce);
        }
        Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding)
    }
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestAssertionObject {
    pub authenticator_data: Vec<u8>,
    pub signature_der: Vec<u8>,
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestAssertionVerifier<R = StaticAppAttestPublicKeyResolver> {
    expected_config: AppAttestClientConfig,
    public_key_resolver: R,
}

#[cfg(feature = "production-crypto")]
impl<R> AppleAppAttestAssertionVerifier<R> {
    pub fn new(expected_config: AppAttestClientConfig, public_key_resolver: R) -> Self {
        Self {
            expected_config,
            public_key_resolver,
        }
    }
}

#[cfg(feature = "production-crypto")]
impl AppleAppAttestAssertionVerifier<StaticAppAttestPublicKeyResolver> {
    pub fn with_static_public_key(
        expected_config: AppAttestClientConfig,
        key_id: impl Into<String>,
        public_key_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            expected_config,
            StaticAppAttestPublicKeyResolver::new().with_public_key(key_id, public_key_bytes),
        )
    }
}

#[cfg(feature = "production-crypto")]
impl<R> AppAttestAssertionVerifier for AppleAppAttestAssertionVerifier<R>
where
    R: AppAttestPublicKeyResolver,
{
    fn verify_app_attest_assertion(
        &self,
        request: &AppAttestAssertionVerificationRequest,
        observed_at: &Timestamp,
    ) -> Result<VerifiedAppAttestAssertion, AppAttestAssertionVerificationError> {
        validate_app_attest_request_config(&request.config, &self.expected_config)?;
        let evidence = AppleAppAttestAssertionEvidence::from_request_assertion(
            &request.assertion,
            &request.challenge_nonce,
        )?;
        let public_key_bytes = self
            .public_key_resolver
            .app_attest_public_key_bytes(&evidence.key_id)?;
        validate_apple_app_attest_assertion_evidence(
            &evidence,
            &self.expected_config,
            &request.challenge_nonce,
            &public_key_bytes,
        )?;

        let assertion = VerifiedAppAttestAssertion {
            team_id: self.expected_config.team_id.clone(),
            bundle_id: self.expected_config.bundle_id.clone(),
            app_id: self.expected_config.app_id.clone(),
            environment: self.expected_config.environment,
            device_ref: evidence.device_ref,
            key_id: evidence.key_id,
            challenge_nonce: request.challenge_nonce.clone(),
            sign_count: app_attest_sign_count_from_authenticator_data(
                &evidence.authenticator_data,
            )?,
            asserted_at: evidence.asserted_at,
            expires_at: evidence.expires_at,
            assurance_level: evidence.assurance_level,
        };

        validate_app_attest_assertion_context(
            &assertion,
            &self.expected_config,
            &request.challenge_nonce,
            observed_at,
        )?;

        Ok(assertion)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestAssertionVerificationError {
    InvalidAssertion,
    InvalidAssertionEncoding,
    InvalidAuthenticatorData,
    AppIdHashMismatch,
    ClientDataHashMismatch,
    InvalidSignature,
    MissingPublicKey,
    CredentialIdMismatch,
    UnsupportedAttestationFormat,
    CertificateChainMismatch,
    CertificateNonceMismatch,
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

pub fn validate_app_attest_key_registration(
    registration: &AppAttestKeyRegistration,
) -> Result<(), AppAttestAssertionVerificationError> {
    if registration.key_id.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingKeyId);
    }
    if registration.device_ref.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingDeviceRef);
    }
    if registration.public_key_bytes.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingPublicKey);
    }
    if registration.attestation_challenge_nonce.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingChallengeNonce);
    }
    if registration.attestation_format != "apple-app-attest" {
        return Err(AppAttestAssertionVerificationError::UnsupportedAttestationFormat);
    }
    Ok(())
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

pub fn validate_app_attest_request_config(
    request_config: &AppAttestClientConfig,
    expected_config: &AppAttestClientConfig,
) -> Result<(), AppAttestAssertionVerificationError> {
    if request_config.team_id != expected_config.team_id {
        return Err(AppAttestAssertionVerificationError::TeamMismatch);
    }
    if request_config.bundle_id != expected_config.bundle_id {
        return Err(AppAttestAssertionVerificationError::BundleMismatch);
    }
    if request_config.app_id != expected_config.app_id {
        return Err(AppAttestAssertionVerificationError::AppIdMismatch);
    }
    if request_config.environment != expected_config.environment {
        return Err(AppAttestAssertionVerificationError::EnvironmentMismatch);
    }
    Ok(())
}

#[cfg(feature = "production-crypto")]
pub fn apple_app_attest_client_data_hash(challenge_nonce: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, challenge_nonce.as_bytes())
        .as_ref()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
pub fn apple_app_attest_app_id_hash(config: &AppAttestClientConfig) -> Vec<u8> {
    digest::digest(&digest::SHA256, config.app_id.as_bytes())
        .as_ref()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
fn validate_apple_app_attest_key_registration_request(
    request: &AppleAppAttestKeyRegistrationVerificationRequest,
    config: &AppAttestClientConfig,
    observed_at: &Timestamp,
    trusted_root_certificates_der: &[Vec<u8>],
) -> Result<(), AppAttestAssertionVerificationError> {
    if request.key_id.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingKeyId);
    }
    if request.device_ref.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingDeviceRef);
    }
    if request.public_key_bytes.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingPublicKey);
    }
    if request.challenge_nonce.is_empty() {
        return Err(AppAttestAssertionVerificationError::MissingChallengeNonce);
    }
    if request.attestation_format != APPLE_APP_ATTEST_REGISTRATION_FORMAT {
        return Err(AppAttestAssertionVerificationError::UnsupportedAttestationFormat);
    }
    if !apple_app_attest_credential_id_matches_key_id(&request.credential_id, &request.key_id) {
        return Err(AppAttestAssertionVerificationError::CredentialIdMismatch);
    }
    if request.authenticator_data.len() < 37 {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }
    if request.authenticator_data[..32] != apple_app_attest_app_id_hash(config) {
        return Err(AppAttestAssertionVerificationError::AppIdHashMismatch);
    }
    if request.client_data_hash != apple_app_attest_client_data_hash(&request.challenge_nonce) {
        return Err(AppAttestAssertionVerificationError::ClientDataHashMismatch);
    }
    let expected_nonce =
        apple_app_attest_attestation_nonce(&request.authenticator_data, &request.client_data_hash);
    validate_apple_app_attest_certificate_chain(
        &request.certificate_chain_der,
        &request.public_key_bytes,
        &expected_nonce,
        observed_at,
        trusted_root_certificates_der,
    )?;
    let registered_after_observed = time::timestamp_after(&request.registered_at, observed_at)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidTimestamp)?;
    if registered_after_observed {
        return Err(AppAttestAssertionVerificationError::InvalidTimestamp);
    }
    Ok(())
}

#[cfg(feature = "production-crypto")]
pub fn parse_apple_app_attest_attestation_object(
    attestation_object: &[u8],
) -> Result<AppleAppAttestAttestationObject, AppAttestAssertionVerificationError> {
    let mut reader = CborReader::new(attestation_object);
    let entry_count = reader.read_len(5)?;
    let mut fmt = None;
    let mut authenticator_data = None;
    let mut certificate_chain_der = None;
    let mut receipt = None;

    for _ in 0..entry_count {
        let key = reader.read_text()?;
        match key.as_str() {
            "fmt" => fmt = Some(reader.read_text()?),
            "authData" => authenticator_data = Some(reader.read_bytes()?),
            "attStmt" => {
                let att_stmt = parse_apple_app_attest_attestation_statement(&mut reader)?;
                certificate_chain_der = Some(att_stmt.0);
                receipt = att_stmt.1;
            }
            _ => reader.skip_value()?,
        }
    }

    if !reader.is_finished() {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    Ok(AppleAppAttestAttestationObject {
        fmt: fmt.ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        authenticator_data: authenticator_data
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        certificate_chain_der: certificate_chain_der
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        receipt,
    })
}

#[cfg(feature = "production-crypto")]
pub fn parse_apple_app_attest_attested_credential_data(
    authenticator_data: &[u8],
    config: &AppAttestClientConfig,
) -> Result<AppleAppAttestAttestedCredentialData, AppAttestAssertionVerificationError> {
    const ATTESTED_CREDENTIAL_DATA_FLAG: u8 = 0x40;
    const ATTESTED_CREDENTIAL_DATA_OFFSET: usize = 37;
    const AAGUID_LEN: usize = 16;
    const CREDENTIAL_ID_LEN_BYTES: usize = 2;

    if authenticator_data.len()
        < ATTESTED_CREDENTIAL_DATA_OFFSET + AAGUID_LEN + CREDENTIAL_ID_LEN_BYTES
    {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }
    if authenticator_data[..32] != apple_app_attest_app_id_hash(config) {
        return Err(AppAttestAssertionVerificationError::AppIdHashMismatch);
    }
    if authenticator_data[32] & ATTESTED_CREDENTIAL_DATA_FLAG == 0 {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }

    let mut offset = ATTESTED_CREDENTIAL_DATA_OFFSET;
    let aaguid = authenticator_data[offset..offset + AAGUID_LEN].to_vec();
    validate_apple_app_attest_aaguid(&aaguid, config.environment)?;
    offset += AAGUID_LEN;
    let credential_id_len =
        u16::from_be_bytes([authenticator_data[offset], authenticator_data[offset + 1]]) as usize;
    offset += CREDENTIAL_ID_LEN_BYTES;
    let credential_id_end = offset
        .checked_add(credential_id_len)
        .ok_or(AppAttestAssertionVerificationError::InvalidAuthenticatorData)?;
    if credential_id_end > authenticator_data.len() {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }
    let credential_id = authenticator_data[offset..credential_id_end].to_vec();
    let public_key_bytes =
        parse_apple_app_attest_cose_p256_public_key(&authenticator_data[credential_id_end..])?;

    Ok(AppleAppAttestAttestedCredentialData {
        aaguid,
        credential_id,
        public_key_bytes,
    })
}

#[cfg(feature = "production-crypto")]
fn parse_apple_app_attest_attestation_statement(
    reader: &mut CborReader<'_>,
) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>), AppAttestAssertionVerificationError> {
    let entry_count = reader.read_len(5)?;
    let mut certificate_chain_der = None;
    let mut receipt = None;

    for _ in 0..entry_count {
        let key = reader.read_text()?;
        match key.as_str() {
            "x5c" => {
                let certificate_count = reader.read_len(4)?;
                let mut certificates = Vec::with_capacity(certificate_count);
                for _ in 0..certificate_count {
                    certificates.push(reader.read_bytes()?);
                }
                certificate_chain_der = Some(certificates);
            }
            "receipt" => receipt = Some(reader.read_bytes()?),
            _ => reader.skip_value()?,
        }
    }

    Ok((
        certificate_chain_der
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        receipt,
    ))
}

#[cfg(feature = "production-crypto")]
fn parse_apple_app_attest_cose_p256_public_key(
    cose_key: &[u8],
) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let mut reader = CborReader::new(cose_key);
    let entry_count = reader.read_len(5)?;
    let mut key_type = None;
    let mut algorithm = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;

    for _ in 0..entry_count {
        let key = reader.read_i64()?;
        match key {
            1 => key_type = Some(reader.read_i64()?),
            3 => algorithm = Some(reader.read_i64()?),
            -1 => curve = Some(reader.read_i64()?),
            -2 => x = Some(reader.read_bytes()?),
            -3 => y = Some(reader.read_bytes()?),
            _ => reader.skip_value()?,
        }
    }
    if !reader.is_finished() {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    if key_type != Some(2) || algorithm != Some(-7) || curve != Some(1) {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    let x = x.ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
    let y = y.ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);
    Ok(public_key)
}

#[cfg(feature = "production-crypto")]
fn validate_apple_app_attest_aaguid(
    aaguid: &[u8],
    environment: AppAttestEnvironment,
) -> Result<(), AppAttestAssertionVerificationError> {
    let expected: Vec<u8> = match environment {
        AppAttestEnvironment::Development => b"appattestdevelop".to_vec(),
        AppAttestEnvironment::Production => {
            let mut bytes = b"appattest".to_vec();
            bytes.extend_from_slice(&[0_u8; 7]);
            bytes
        }
    };
    if aaguid == expected {
        Ok(())
    } else {
        Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData)
    }
}

#[cfg(feature = "production-crypto")]
fn apple_app_attest_credential_id_matches_key_id(credential_id: &[u8], key_id: &str) -> bool {
    credential_id == key_id.as_bytes()
        || base64_decode(key_id.as_bytes()).is_ok_and(|decoded| decoded == credential_id)
        || base64_url_decode(key_id.as_bytes()).is_ok_and(|decoded| decoded == credential_id)
}

#[cfg(feature = "production-crypto")]
fn validate_apple_app_attest_certificate_chain(
    certificate_chain_der: &[Vec<u8>],
    public_key_bytes: &[u8],
    expected_nonce: &[u8],
    observed_at: &Timestamp,
    trusted_root_certificates_der: &[Vec<u8>],
) -> Result<(), AppAttestAssertionVerificationError> {
    if certificate_chain_der.len() < 2 {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    if trusted_root_certificates_der.is_empty() {
        return Err(AppAttestAssertionVerificationError::CertificateChainMismatch);
    }
    let certificates = certificate_chain_der
        .iter()
        .map(|certificate| parse_x509_certificate(certificate))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_roots = trusted_root_certificates_der
        .iter()
        .map(|certificate| parse_x509_certificate(certificate))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certificates
        .first()
        .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
    if leaf.subject_public_key_bytes != public_key_bytes {
        eprintln!(
            "App Attest certificate diagnostic: leaf public key did not match credential public key (leaf {} bytes, credential {} bytes)",
            leaf.subject_public_key_bytes.len(),
            public_key_bytes.len()
        );
        Err(AppAttestAssertionVerificationError::InvalidSignature)
    } else if leaf.apple_app_attest_nonce.as_deref() != Some(expected_nonce) {
        eprintln!(
            "App Attest certificate diagnostic: leaf nonce extension did not match expected nonce"
        );
        Err(AppAttestAssertionVerificationError::CertificateNonceMismatch)
    } else {
        for certificate in &certificates {
            validate_x509_certificate_valid_at(certificate, observed_at)?;
        }
        for (index, chain_pair) in certificates.windows(2).enumerate() {
            let child = &chain_pair[0];
            let issuer = &chain_pair[1];
            if child.issuer_der != issuer.subject_der {
                eprintln!(
                    "App Attest certificate diagnostic: chain pair {index} issuer/subject mismatch"
                );
                return Err(AppAttestAssertionVerificationError::CertificateChainMismatch);
            }
            verify_x509_certificate_signature(child, &issuer.subject_public_key_bytes).map_err(
                |error| {
                    eprintln!(
                        "App Attest certificate diagnostic: chain pair {index} signature verification failed with {:?} (algorithm {:?}, issuer key {} bytes, signature {} bytes)",
                        error,
                        child.signature_algorithm,
                        issuer.subject_public_key_bytes.len(),
                        child.signature_der.len()
                    );
                    error
                },
            )?;
        }

        let terminal = certificates
            .last()
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        if trusted_roots.iter().any(|root| {
            terminal.subject_der == root.subject_der
                && terminal.subject_public_key_bytes == root.subject_public_key_bytes
        }) {
            return Ok(());
        }
        for root in &trusted_roots {
            validate_x509_certificate_valid_at(root, observed_at)?;
            if terminal.issuer_der == root.subject_der {
                if verify_x509_certificate_signature(terminal, &root.subject_public_key_bytes)
                    .is_ok()
                {
                    return Ok(());
                } else {
                    eprintln!(
                        "App Attest certificate diagnostic: terminal signature did not verify against trusted root (algorithm {:?}, root key {} bytes, signature {} bytes)",
                        terminal.signature_algorithm,
                        root.subject_public_key_bytes.len(),
                        terminal.signature_der.len()
                    );
                }
            }
        }

        Err(AppAttestAssertionVerificationError::CertificateChainMismatch)
    }
}

#[cfg(feature = "production-crypto")]
fn apple_app_attest_attestation_nonce(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
) -> Vec<u8> {
    let mut nonce_input = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    nonce_input.extend_from_slice(authenticator_data);
    nonce_input.extend_from_slice(client_data_hash);
    digest::digest(&digest::SHA256, &nonce_input)
        .as_ref()
        .to_vec()
}

#[cfg(feature = "production-crypto")]
pub fn app_attest_sign_count_from_authenticator_data(
    authenticator_data: &[u8],
) -> Result<u64, AppAttestAssertionVerificationError> {
    if authenticator_data.len() < 37 {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }

    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&authenticator_data[33..37]);
    Ok(u32::from_be_bytes(bytes) as u64)
}

#[cfg(feature = "production-crypto")]
fn validate_apple_app_attest_assertion_evidence(
    evidence: &AppleAppAttestAssertionEvidence,
    config: &AppAttestClientConfig,
    challenge_nonce: &str,
    public_key_bytes: &[u8],
) -> Result<(), AppAttestAssertionVerificationError> {
    if evidence.authenticator_data.len() < 37 {
        return Err(AppAttestAssertionVerificationError::InvalidAuthenticatorData);
    }
    if evidence.client_data_hash != apple_app_attest_client_data_hash(challenge_nonce) {
        return Err(AppAttestAssertionVerificationError::ClientDataHashMismatch);
    }
    if evidence.authenticator_data[..32] != apple_app_attest_app_id_hash(config) {
        return Err(AppAttestAssertionVerificationError::AppIdHashMismatch);
    }

    let mut signed_bytes =
        Vec::with_capacity(evidence.authenticator_data.len() + evidence.client_data_hash.len());
    signed_bytes.extend_from_slice(&evidence.authenticator_data);
    signed_bytes.extend_from_slice(&evidence.client_data_hash);
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_bytes);
    public_key
        .verify(&signed_bytes, &evidence.signature_der)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidSignature)
}

#[cfg(feature = "production-crypto")]
pub fn parse_apple_app_attest_assertion_object(
    assertion_object: &[u8],
) -> Result<AppleAppAttestAssertionObject, AppAttestAssertionVerificationError> {
    let mut reader = CborReader::new(assertion_object);
    let entry_count = reader.read_len(5)?;
    let mut authenticator_data = None;
    let mut signature_der = None;

    for _ in 0..entry_count {
        let key = reader.read_text()?;
        let value = reader.read_bytes()?;
        match key.as_str() {
            "authenticatorData" | "authData" => authenticator_data = Some(value),
            "signature" => signature_der = Some(value),
            _ => {}
        }
    }

    if !reader.is_finished() {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    Ok(AppleAppAttestAssertionObject {
        authenticator_data: authenticator_data
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
        signature_der: signature_der
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?,
    })
}

#[cfg(feature = "production-crypto")]
fn parse_der_subject_public_key_info(
    subject_public_key_info: &[u8],
) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let mut reader = DerReader::new(subject_public_key_info);
    reader.skip_element()?;
    let subject_public_key = reader.read_element_with_tag(0x03)?;
    if !reader.is_finished()
        || subject_public_key.contents.first() != Some(&0)
        || subject_public_key.contents[1] != 0x04
    {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    if !matches!(subject_public_key.contents.len(), 66 | 98) {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    Ok(subject_public_key.contents[1..].to_vec())
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedX509Certificate {
    tbs_certificate_der: Vec<u8>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    not_before: Timestamp,
    not_after: Timestamp,
    subject_public_key_bytes: Vec<u8>,
    signature_algorithm: X509SignatureAlgorithm,
    signature_der: Vec<u8>,
    apple_app_attest_nonce: Option<Vec<u8>>,
}

#[cfg(feature = "production-crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X509SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

#[cfg(feature = "production-crypto")]
fn parse_x509_certificate(
    certificate_der: &[u8],
) -> Result<ParsedX509Certificate, AppAttestAssertionVerificationError> {
    let mut certificate = DerReader::new(certificate_der);
    let certificate_sequence = certificate.read_element_with_tag(0x30).map_err(|error| {
        eprintln!(
            "App Attest X.509 diagnostic: top-level certificate sequence parse failed for {} bytes: {error:?}",
            certificate_der.len()
        );
        error
    })?;
    if !certificate.is_finished() {
        eprintln!(
            "App Attest X.509 diagnostic: trailing bytes after top-level certificate sequence"
        );
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    let mut certificate_sequence = DerReader::new(certificate_sequence.contents);
    let tbs_certificate = certificate_sequence
        .read_element_with_tag(0x30)
        .map_err(|error| {
            eprintln!("App Attest X.509 diagnostic: tbsCertificate parse failed: {error:?}");
            error
        })?;
    let signature_algorithm_element = certificate_sequence
        .read_element_with_tag(0x30)
        .map_err(|error| {
            eprintln!(
                "App Attest X.509 diagnostic: outer signatureAlgorithm parse failed: {error:?}"
            );
            error
        })?;
    let signature_algorithm =
        parse_x509_signature_algorithm(signature_algorithm_element.contents).map_err(|error| {
            eprintln!(
                "App Attest X.509 diagnostic: outer signatureAlgorithm unsupported/unparseable: {error:?}"
            );
            error
        })?;
    let signature = certificate_sequence
        .read_element_with_tag(0x03)
        .map_err(|error| {
            eprintln!("App Attest X.509 diagnostic: certificate signature parse failed: {error:?}");
            error
        })?;
    if !certificate_sequence.is_finished() {
        eprintln!("App Attest X.509 diagnostic: trailing bytes after certificate sequence");
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    let signature_der = parse_der_bit_string(signature.contents).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: signature bit string parse failed: {error:?}");
        error
    })?;

    let mut tbs_reader = DerReader::new(tbs_certificate.contents);
    if tbs_reader.peek_tag() == Some(0xa0) {
        tbs_reader.skip_element().map_err(|error| {
            eprintln!("App Attest X.509 diagnostic: explicit version parse failed: {error:?}");
            error
        })?;
    }
    tbs_reader.skip_element().map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: serialNumber parse failed: {error:?}");
        error
    })?;
    tbs_reader.skip_element().map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: inner signature parse failed: {error:?}");
        error
    })?;
    let issuer = tbs_reader.read_element_with_tag(0x30).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: issuer parse failed: {error:?}");
        error
    })?;
    let validity = tbs_reader.read_element_with_tag(0x30).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: validity parse failed: {error:?}");
        error
    })?;
    let (not_before, not_after) = parse_x509_validity(validity.contents).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: validity time parse failed: {error:?}");
        error
    })?;
    let subject = tbs_reader.read_element_with_tag(0x30).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: subject parse failed: {error:?}");
        error
    })?;
    let subject_public_key_info = tbs_reader.read_element_with_tag(0x30).map_err(|error| {
        eprintln!("App Attest X.509 diagnostic: subjectPublicKeyInfo parse failed: {error:?}");
        error
    })?;
    let subject_public_key_bytes =
        parse_der_subject_public_key_info(subject_public_key_info.contents).map_err(|error| {
            eprintln!(
                "App Attest X.509 diagnostic: subject public key parse failed: {error:?}"
            );
            error
        })?;
    let mut apple_app_attest_nonce = None;
    while !tbs_reader.is_finished() {
        let element = tbs_reader.read_element().map_err(|error| {
            eprintln!("App Attest X.509 diagnostic: optional TBS element parse failed: {error:?}");
            error
        })?;
        if element.tag == 0xa3 {
            apple_app_attest_nonce =
                parse_x509_extensions_for_app_attest_nonce(element.contents).map_err(|error| {
                    eprintln!(
                        "App Attest X.509 diagnostic: extensions/App Attest nonce parse failed: {error:?}"
                    );
                    error
                })?;
        }
    }

    Ok(ParsedX509Certificate {
        tbs_certificate_der: tbs_certificate.encoded.to_vec(),
        issuer_der: issuer.encoded.to_vec(),
        subject_der: subject.encoded.to_vec(),
        not_before,
        not_after,
        subject_public_key_bytes,
        signature_algorithm,
        signature_der,
        apple_app_attest_nonce,
    })
}

#[cfg(feature = "production-crypto")]
fn parse_x509_signature_algorithm(
    algorithm_identifier: &[u8],
) -> Result<X509SignatureAlgorithm, AppAttestAssertionVerificationError> {
    let mut reader = DerReader::new(algorithm_identifier);
    let oid = reader.read_element_with_tag(0x06)?;
    while !reader.is_finished() {
        reader.skip_element()?;
    }
    match oid.contents {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => {
            Ok(X509SignatureAlgorithm::EcdsaP256Sha256)
        }
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => {
            Ok(X509SignatureAlgorithm::EcdsaP384Sha384)
        }
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    }
}

#[cfg(feature = "production-crypto")]
fn apple_app_attest_root_ca_der() -> Vec<u8> {
    pem_certificate_der(APPLE_APP_ATTEST_ROOT_CA_PEM)
        .expect("embedded Apple App Attestation Root CA PEM must decode")
}

#[cfg(feature = "production-crypto")]
const APPLE_APP_ATTEST_ROOT_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n\
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n\
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n\
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n\
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n\
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n\
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n\
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n\
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n\
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n\
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n\
oyFraWVIyd/dganmrduC1bmTBGwD\n\
-----END CERTIFICATE-----\n";

#[cfg(feature = "production-crypto")]
fn parse_x509_validity(
    validity: &[u8],
) -> Result<(Timestamp, Timestamp), AppAttestAssertionVerificationError> {
    let mut reader = DerReader::new(validity);
    let not_before = reader.read_element()?;
    let not_before = parse_der_time(not_before.tag, not_before.contents)?;
    let not_after = reader.read_element()?;
    let not_after = parse_der_time(not_after.tag, not_after.contents)?;
    if !reader.is_finished() {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    Ok((not_before, not_after))
}

#[cfg(feature = "production-crypto")]
fn parse_x509_extensions_for_app_attest_nonce(
    explicit_extensions: &[u8],
) -> Result<Option<Vec<u8>>, AppAttestAssertionVerificationError> {
    let mut explicit_reader = DerReader::new(explicit_extensions);
    let extensions = explicit_reader.read_element_with_tag(0x30)?;
    if !explicit_reader.is_finished() {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    let mut extensions_reader = DerReader::new(extensions.contents);
    while !extensions_reader.is_finished() {
        let extension = extensions_reader.read_element_with_tag(0x30)?;
        let mut extension_reader = DerReader::new(extension.contents);
        let oid = extension_reader.read_element_with_tag(0x06)?;
        if extension_reader.peek_tag() == Some(0x01) {
            extension_reader.skip_element()?;
        }
        let value = extension_reader.read_element_with_tag(0x04)?;
        if !extension_reader.is_finished() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        if oid.contents == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02] {
            return Ok(Some(parse_apple_app_attest_nonce_extension(
                value.contents,
            )?));
        }
    }
    Ok(None)
}

#[cfg(feature = "production-crypto")]
fn parse_apple_app_attest_nonce_extension(
    extension_value: &[u8],
) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let mut reader = DerReader::new(extension_value);
    if reader.peek_tag() == Some(0x30) {
        let sequence = reader.read_element_with_tag(0x30)?;
        if !reader.is_finished() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        let mut sequence_reader = DerReader::new(sequence.contents);
        let nonce = read_apple_app_attest_nonce_extension_element(&mut sequence_reader)?;
        if !sequence_reader.is_finished() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        Ok(nonce)
    } else {
        let nonce = read_apple_app_attest_nonce_extension_element(&mut reader)?;
        if !reader.is_finished() {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        Ok(nonce)
    }
}

#[cfg(feature = "production-crypto")]
fn read_apple_app_attest_nonce_extension_element(
    reader: &mut DerReader<'_>,
) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let element = reader.read_element()?;
    match element.tag {
        0x04 => Ok(element.contents.to_vec()),
        0xa0 | 0xa1 => {
            let mut explicit_reader = DerReader::new(element.contents);
            let nonce = explicit_reader.read_element_with_tag(0x04)?;
            if !explicit_reader.is_finished() {
                return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
            }
            Ok(nonce.contents.to_vec())
        }
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    }
}

#[cfg(feature = "production-crypto")]
fn parse_der_bit_string(bit_string: &[u8]) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    if bit_string.first() != Some(&0) {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    Ok(bit_string[1..].to_vec())
}

#[cfg(feature = "production-crypto")]
fn parse_der_time(tag: u8, value: &[u8]) -> Result<Timestamp, AppAttestAssertionVerificationError> {
    let value = std::str::from_utf8(value)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
    let timestamp = match tag {
        0x17 => {
            if value.len() != 13 || !value.ends_with('Z') {
                return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
            }
            let year = value[0..2]
                .parse::<u16>()
                .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
            let full_year = if year >= 50 { 1900 + year } else { 2000 + year };
            format!(
                "{full_year:04}-{}-{}T{}:{}:{}Z",
                &value[2..4],
                &value[4..6],
                &value[6..8],
                &value[8..10],
                &value[10..12]
            )
        }
        0x18 => {
            if value.len() != 15 || !value.ends_with('Z') {
                return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
            }
            format!(
                "{}-{}-{}T{}:{}:{}Z",
                &value[0..4],
                &value[4..6],
                &value[6..8],
                &value[8..10],
                &value[10..12],
                &value[12..14]
            )
        }
        _ => return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    };
    Ok(Timestamp(timestamp))
}

#[cfg(feature = "production-crypto")]
fn validate_x509_certificate_valid_at(
    certificate: &ParsedX509Certificate,
    observed_at: &Timestamp,
) -> Result<(), AppAttestAssertionVerificationError> {
    let before_not_before = time::timestamp_after(&certificate.not_before, observed_at)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidTimestamp)?;
    let after_not_after = time::timestamp_after(observed_at, &certificate.not_after)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidTimestamp)?;
    if before_not_before || after_not_after {
        Err(AppAttestAssertionVerificationError::Expired)
    } else {
        Ok(())
    }
}

#[cfg(feature = "production-crypto")]
fn verify_x509_certificate_signature(
    certificate: &ParsedX509Certificate,
    issuer_public_key_bytes: &[u8],
) -> Result<(), AppAttestAssertionVerificationError> {
    // A certificate's signatureAlgorithm OID only encodes the message digest
    // (SHA-256 vs SHA-384). The elliptic curve used to verify the signature is
    // determined by the *issuer's* public key, not by the child certificate's
    // signature OID. Apple's real App Attest chain signs a P-256 leaf with the
    // P-384 "Apple App Attestation CA 1" intermediate using ecdsa-with-SHA256,
    // so the verifying curve (P-384, from the issuer key) and the digest
    // (SHA-256, from the leaf's signature OID) come from different certificates
    // and must be paired independently. Selecting the curve from the child's OID
    // (as an earlier version did) fed a P-384 issuer key to a P-256 verifier and
    // always failed real-device attestations with InvalidSignature.
    let digest_is_sha384 = matches!(
        certificate.signature_algorithm,
        X509SignatureAlgorithm::EcdsaP384Sha384
    );
    let algorithm: &'static signature::EcdsaVerificationAlgorithm =
        match (issuer_public_key_bytes.len(), digest_is_sha384) {
            (65, false) => &signature::ECDSA_P256_SHA256_ASN1,
            (65, true) => &signature::ECDSA_P256_SHA384_ASN1,
            (97, false) => &signature::ECDSA_P384_SHA256_ASN1,
            (97, true) => &signature::ECDSA_P384_SHA384_ASN1,
            _ => return Err(AppAttestAssertionVerificationError::InvalidSignature),
        };
    signature::UnparsedPublicKey::new(algorithm, issuer_public_key_bytes)
        .verify(&certificate.tbs_certificate_der, &certificate.signature_der)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidSignature)
}

#[cfg(feature = "production-crypto")]
fn encode_apple_app_attest_assertion_object(
    authenticator_data: &[u8],
    signature_der: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    cbor_write_len(&mut output, 5, 2);
    cbor_write_text(&mut output, "authenticatorData");
    cbor_write_bytes(&mut output, authenticator_data);
    cbor_write_text(&mut output, "signature");
    cbor_write_bytes(&mut output, signature_der);
    output
}

#[cfg(feature = "production-crypto")]
fn encode_apple_app_attest_attestation_object(
    authenticator_data: &[u8],
    certificate_chain_der: &[Vec<u8>],
    receipt: Option<&[u8]>,
) -> Vec<u8> {
    let mut output = Vec::new();
    cbor_write_len(&mut output, 5, 3);
    cbor_write_text(&mut output, "fmt");
    cbor_write_text(&mut output, APPLE_APP_ATTEST_CBOR_FORMAT);
    cbor_write_text(&mut output, "authData");
    cbor_write_bytes(&mut output, authenticator_data);
    cbor_write_text(&mut output, "attStmt");
    cbor_write_len(&mut output, 5, if receipt.is_some() { 2 } else { 1 });
    cbor_write_text(&mut output, "x5c");
    cbor_write_len(&mut output, 4, certificate_chain_der.len());
    for certificate in certificate_chain_der {
        cbor_write_bytes(&mut output, certificate);
    }
    if let Some(receipt) = receipt {
        cbor_write_text(&mut output, "receipt");
        cbor_write_bytes(&mut output, receipt);
    }
    output
}

#[cfg(feature = "production-crypto")]
struct CborReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

#[cfg(feature = "production-crypto")]
impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_text(&mut self) -> Result<String, AppAttestAssertionVerificationError> {
        let len = self.read_len(3)?;
        String::from_utf8(self.read_exact(len)?.to_vec())
            .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
        let len = self.read_len(2)?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_i64(&mut self) -> Result<i64, AppAttestAssertionVerificationError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = self.read_cbor_uint_argument(additional)?;
        match major {
            0 => i64::try_from(value)
                .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding),
            1 => {
                let value = i64::try_from(value)
                    .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
                Ok(-1 - value)
            }
            _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
        }
    }

    fn read_len(
        &mut self,
        expected_major: u8,
    ) -> Result<usize, AppAttestAssertionVerificationError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        if major != expected_major {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        let additional = initial & 0x1f;
        usize::try_from(self.read_cbor_uint_argument(additional)?)
            .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)
    }

    fn skip_value(&mut self) -> Result<(), AppAttestAssertionVerificationError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 | 1 => {
                self.read_cbor_uint_argument(additional)?;
                Ok(())
            }
            2 | 3 => {
                let len = usize::try_from(self.read_cbor_uint_argument(additional)?)
                    .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
                self.read_exact(len)?;
                Ok(())
            }
            4 => {
                let len = self.read_cbor_uint_argument(additional)?;
                for _ in 0..len {
                    self.skip_value()?;
                }
                Ok(())
            }
            5 => {
                let len = self.read_cbor_uint_argument(additional)?;
                for _ in 0..len {
                    self.skip_value()?;
                    self.skip_value()?;
                }
                Ok(())
            }
            6 => {
                self.read_cbor_uint_argument(additional)?;
                self.skip_value()
            }
            7 => match additional {
                20..=23 => Ok(()),
                24 => {
                    self.read_u8()?;
                    Ok(())
                }
                25 => {
                    self.read_exact(2)?;
                    Ok(())
                }
                26 => {
                    self.read_exact(4)?;
                    Ok(())
                }
                27 => {
                    self.read_exact(8)?;
                    Ok(())
                }
                _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
            },
            _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
        }
    }

    fn read_cbor_uint_argument(
        &mut self,
        additional: u8,
    ) -> Result<u64, AppAttestAssertionVerificationError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => Ok(self.read_u8()? as u64),
            25 => {
                let bytes = self.read_exact(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            26 => {
                let bytes = self.read_exact(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            27 => {
                let bytes = self.read_exact(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
        }
    }

    fn read_u8(&mut self) -> Result<u8, AppAttestAssertionVerificationError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        self.position += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], AppAttestAssertionVerificationError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        self.position = end;
        Ok(bytes)
    }
}

#[cfg(feature = "production-crypto")]
struct DerElement<'a> {
    tag: u8,
    encoded: &'a [u8],
    contents: &'a [u8],
}

#[cfg(feature = "production-crypto")]
struct DerReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

#[cfg(feature = "production-crypto")]
impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn skip_element(&mut self) -> Result<(), AppAttestAssertionVerificationError> {
        self.read_element()?;
        Ok(())
    }

    fn read_element_with_tag(
        &mut self,
        expected_tag: u8,
    ) -> Result<DerElement<'a>, AppAttestAssertionVerificationError> {
        let element = self.read_element()?;
        if element.tag != expected_tag {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        Ok(element)
    }

    fn read_element(&mut self) -> Result<DerElement<'a>, AppAttestAssertionVerificationError> {
        let start = self.position;
        let tag = self.read_u8()?;
        let len = self.read_der_len()?;
        let end = self
            .position
            .checked_add(len)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        let encoded = self
            .bytes
            .get(start..end)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        let contents = self
            .bytes
            .get(self.position..end)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        self.position = end;
        Ok(DerElement {
            tag,
            encoded,
            contents,
        })
    }

    fn read_der_len(&mut self) -> Result<usize, AppAttestAssertionVerificationError> {
        let first = self.read_u8()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let len_len = (first & 0x7f) as usize;
        if len_len == 0 || len_len > 4 {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
        let mut len = 0_usize;
        for _ in 0..len_len {
            len = (len << 8) | self.read_u8()? as usize;
        }
        Ok(len)
    }

    fn read_u8(&mut self) -> Result<u8, AppAttestAssertionVerificationError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?;
        self.position += 1;
        Ok(byte)
    }
}

#[cfg(feature = "production-crypto")]
fn cbor_write_text(output: &mut Vec<u8>, value: &str) {
    cbor_write_len(output, 3, value.len());
    output.extend_from_slice(value.as_bytes());
}

#[cfg(feature = "production-crypto")]
fn cbor_write_bytes(output: &mut Vec<u8>, value: &[u8]) {
    cbor_write_len(output, 2, value.len());
    output.extend_from_slice(value);
}

#[cfg(feature = "production-crypto")]
fn cbor_write_len(output: &mut Vec<u8>, major: u8, len: usize) {
    let prefix = major << 5;
    if len <= 23 {
        output.push(prefix | len as u8);
    } else if u8::try_from(len).is_ok() {
        output.push(prefix | 24);
        output.push(len as u8);
    } else if u16::try_from(len).is_ok() {
        output.push(prefix | 25);
        output.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        let len = u32::try_from(len).expect("CBOR writer supports values up to u32::MAX");
        output.push(prefix | 26);
        output.extend_from_slice(&len.to_be_bytes());
    }
}

#[cfg(feature = "production-crypto")]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(feature = "production-crypto")]
fn hex_field(value: Option<&str>) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    hex_decode(value.ok_or(AppAttestAssertionVerificationError::InvalidAssertionEncoding)?)
}

#[cfg(feature = "production-crypto")]
fn utf8_field(value: Option<&str>) -> Result<String, AppAttestAssertionVerificationError> {
    String::from_utf8(hex_field(value)?)
        .map_err(|_| AppAttestAssertionVerificationError::InvalidAssertionEncoding)
}

#[cfg(feature = "production-crypto")]
fn hex_decode(value: &str) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    if value.len() % 2 != 0 {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg(feature = "production-crypto")]
fn pem_certificate_der(pem: &str) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let base64 = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.bytes().filter(|byte| !byte.is_ascii_whitespace()))
        .collect::<Vec<_>>();
    base64_decode(&base64)
}

#[cfg(feature = "production-crypto")]
fn base64_decode(value: &[u8]) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    if value.len() % 4 != 0 {
        return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
    }
    let mut decoded = Vec::with_capacity(value.len() / 4 * 3);
    for chunk in value.chunks_exact(4) {
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third = if chunk[2] == b'=' {
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let fourth = if chunk[3] == b'=' {
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        decoded.push(((first as u16) << 2 | (second as u16) >> 4) as u8);
        if let Some(third) = third {
            decoded.push(((second as u16) << 4 | (third as u16) >> 2) as u8);
            if let Some(fourth) = fourth {
                decoded.push(((third as u16) << 6 | fourth as u16) as u8);
            } else if chunk[3] != b'=' {
                return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
            }
        } else if chunk[3] != b'=' {
            return Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding);
        }
    }
    Ok(decoded)
}

#[cfg(feature = "production-crypto")]
fn base64_url_decode(value: &[u8]) -> Result<Vec<u8>, AppAttestAssertionVerificationError> {
    let mut normalized = Vec::with_capacity(value.len() + ((4 - value.len() % 4) % 4));
    for byte in value {
        normalized.push(match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        });
    }
    normalized.extend(std::iter::repeat_n(b'=', (4 - normalized.len() % 4) % 4));
    base64_decode(&normalized)
}

#[cfg(feature = "production-crypto")]
fn base64_value(byte: u8) -> Result<u8, AppAttestAssertionVerificationError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    }
}

#[cfg(feature = "production-crypto")]
fn hex_nibble(byte: u8) -> Result<u8, AppAttestAssertionVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    }
}

#[cfg(feature = "production-crypto")]
fn assurance_level_label(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Low => "low",
        AssuranceLevel::Medium => "medium",
        AssuranceLevel::High => "high",
        AssuranceLevel::VeryHigh => "very_high",
    }
}

#[cfg(feature = "production-crypto")]
fn parse_assurance_level(
    value: &str,
) -> Result<AssuranceLevel, AppAttestAssertionVerificationError> {
    match value {
        "low" => Ok(AssuranceLevel::Low),
        "medium" => Ok(AssuranceLevel::Medium),
        "high" => Ok(AssuranceLevel::High),
        "very_high" => Ok(AssuranceLevel::VeryHigh),
        _ => Err(AppAttestAssertionVerificationError::InvalidAssertionEncoding),
    }
}
