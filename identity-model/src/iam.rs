use crate::fen::*;
use crate::identity::*;
use crate::time;

#[cfg(feature = "oidc-jwks-verifier")]
mod jwks;
#[cfg(feature = "oidc-jwks-verifier")]
pub use jwks::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClientConfig {
    pub provider_name: String,
    pub issuer: String,
    pub client_id: String,
}

impl OidcClientConfig {
    pub fn keycloak(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            provider_name: "Keycloak".to_string(),
            issuer: issuer.into(),
            client_id: client_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidcSession {
    pub provider_name: String,
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub authorized_party: Option<String>,
    pub session_id: Option<String>,
    pub nonce: Option<String>,
    pub auth_time: Option<Timestamp>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub display_name: Option<String>,
}

impl VerifiedOidcSession {
    pub fn keycloak(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        client_id: impl Into<String>,
        session_id: impl Into<String>,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        let client_id = client_id.into();
        Self {
            provider_name: "Keycloak".to_string(),
            issuer: issuer.into(),
            subject: subject.into(),
            audiences: vec![client_id.clone()],
            authorized_party: Some(client_id),
            session_id: Some(session_id.into()),
            nonce: None,
            auth_time: None,
            issued_at,
            expires_at,
            acr: None,
            amr: Vec::new(),
            email: None,
            email_verified: false,
            preferred_username: None,
            display_name: None,
        }
    }

    pub fn with_amr(mut self, amr: Vec<String>) -> Self {
        self.amr = amr;
        self
    }

    pub fn with_acr(mut self, acr: impl Into<String>) -> Self {
        self.acr = Some(acr.into());
        self
    }

    pub fn with_verified_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self.email_verified = true;
        self
    }

    pub fn with_unverified_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self.email_verified = false;
        self
    }

    pub fn with_preferred_username(mut self, preferred_username: impl Into<String>) -> Self {
        self.preferred_username = Some(preferred_username.into());
        self
    }

    pub fn with_display_label(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn source_system(&self) -> String {
        format!("{}:{}", self.provider_name, self.issuer)
    }

    pub fn account_resource_id(&self) -> String {
        format!("{}#{}", self.issuer, self.subject)
    }

    pub fn verified_email(&self) -> Option<&str> {
        self.email.as_deref().filter(|_| self.email_verified)
    }

    pub fn identity_provider_external_refs(&self) -> Vec<ExternalRef> {
        let mut refs = vec![ExternalRef {
            system: ExternalSystem::IdentityProvider,
            resource_type: Some("oidc_subject".to_string()),
            resource_id: self.account_resource_id(),
            uri: Some(self.issuer.clone()),
        }];

        if let Some(session_id) = &self.session_id {
            refs.push(ExternalRef {
                system: ExternalSystem::IdentityProvider,
                resource_type: Some("oidc_session".to_string()),
                resource_id: format!("{}#{}", self.issuer, session_id),
                uri: None,
            });
        }

        if let Some(client_id) = &self.authorized_party {
            refs.push(ExternalRef {
                system: ExternalSystem::IdentityProvider,
                resource_type: Some("oidc_client".to_string()),
                resource_id: client_id.clone(),
                uri: None,
            });
        }

        refs
    }

    fn matches_client(&self, client_id: &str) -> bool {
        self.audiences.iter().any(|audience| audience == client_id)
            || self.authorized_party.as_deref() == Some(client_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcCredentialEvidence {
    pub authenticator_type: AuthenticatorType,
    pub assurance_level: AssuranceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcAssurancePolicy {
    pub password_assurance: AssuranceLevel,
    pub mfa_assurance: AssuranceLevel,
    pub passkey_assurance: AssuranceLevel,
    pub high_acr_values: Vec<String>,
    pub very_high_acr_values: Vec<String>,
}

impl Default for OidcAssurancePolicy {
    fn default() -> Self {
        Self {
            password_assurance: AssuranceLevel::Low,
            mfa_assurance: AssuranceLevel::Medium,
            passkey_assurance: AssuranceLevel::Medium,
            high_acr_values: Vec::new(),
            very_high_acr_values: Vec::new(),
        }
    }
}

impl OidcAssurancePolicy {
    pub fn classify(&self, session: &VerifiedOidcSession) -> OidcCredentialEvidence {
        let mut evidence = if has_any_amr(session, &["webauthn", "passkey", "fido2"]) {
            OidcCredentialEvidence {
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: self.passkey_assurance,
            }
        } else if has_any_amr(session, &["faceid", "touchid", "platform_biometric"]) {
            OidcCredentialEvidence {
                authenticator_type: AuthenticatorType::PlatformBiometric,
                assurance_level: self.mfa_assurance,
            }
        } else if has_any_amr(session, &["mfa", "otp", "totp", "sms", "push"]) {
            OidcCredentialEvidence {
                authenticator_type: AuthenticatorType::AppPushMfa,
                assurance_level: self.mfa_assurance,
            }
        } else if has_any_amr(session, &["pwd", "password"]) {
            OidcCredentialEvidence {
                authenticator_type: AuthenticatorType::Password,
                assurance_level: self.password_assurance,
            }
        } else {
            OidcCredentialEvidence {
                authenticator_type: AuthenticatorType::Other("oidc_session".to_string()),
                assurance_level: AssuranceLevel::Low,
            }
        };

        if let Some(acr) = &session.acr {
            if contains_label(&self.very_high_acr_values, acr) {
                evidence.assurance_level = AssuranceLevel::VeryHigh;
            } else if contains_label(&self.high_acr_values, acr) {
                evidence.assurance_level = evidence.assurance_level.max(AssuranceLevel::High);
            }
        }

        evidence
    }
}

pub trait OidcSessionVerifier {
    fn verify_session(
        &self,
        token: &str,
        config: &OidcClientConfig,
        observed_at: &Timestamp,
    ) -> Result<VerifiedOidcSession, OidcSessionVerificationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOidcSessionVerifier {
    pub expected_token: String,
    pub session: VerifiedOidcSession,
}

impl StaticOidcSessionVerifier {
    pub fn new(expected_token: impl Into<String>, session: VerifiedOidcSession) -> Self {
        Self {
            expected_token: expected_token.into(),
            session,
        }
    }
}

impl OidcSessionVerifier for StaticOidcSessionVerifier {
    fn verify_session(
        &self,
        token: &str,
        config: &OidcClientConfig,
        observed_at: &Timestamp,
    ) -> Result<VerifiedOidcSession, OidcSessionVerificationError> {
        if token != self.expected_token {
            return Err(OidcSessionVerificationError::InvalidToken);
        }

        validate_oidc_session_context(&self.session, config, observed_at)?;

        Ok(self.session.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcSessionVerificationError {
    InvalidToken,
    MissingSubject,
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    InvalidObservedTimestamp,
    InvalidSessionTimestamp,
    DiscoveryFetchFailed,
    DiscoveryIssuerMismatch,
    MissingJwksUri,
    JwksFetchFailed,
    MissingKeyId,
    UnknownKeyId,
    UnsupportedAlgorithm,
    JwtRejected,
}

pub fn validate_oidc_session_context(
    session: &VerifiedOidcSession,
    config: &OidcClientConfig,
    observed_at: &Timestamp,
) -> Result<(), OidcSessionVerificationError> {
    if session.subject.is_empty() {
        return Err(OidcSessionVerificationError::MissingSubject);
    }

    if session.issuer != config.issuer {
        return Err(OidcSessionVerificationError::IssuerMismatch);
    }

    if !session.matches_client(&config.client_id) {
        return Err(OidcSessionVerificationError::AudienceMismatch);
    }

    let expired = time::timestamp_at_or_after(observed_at, &session.expires_at).map_err(|_| {
        if time::timestamp_to_unix_seconds(observed_at).is_err() {
            OidcSessionVerificationError::InvalidObservedTimestamp
        } else {
            OidcSessionVerificationError::InvalidSessionTimestamp
        }
    })?;
    if expired {
        return Err(OidcSessionVerificationError::Expired);
    }

    Ok(())
}

fn has_any_amr(session: &VerifiedOidcSession, expected: &[&str]) -> bool {
    session
        .amr
        .iter()
        .any(|actual| expected.iter().any(|expected| actual == expected))
}

fn contains_label(values: &[String], label: &str) -> bool {
    values.iter().any(|value| value == label)
}
