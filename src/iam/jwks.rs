use super::*;
use crate::time::{timestamp_to_unix_seconds, unix_seconds_to_timestamp};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct OidcJwksSessionVerifier;

impl OidcJwksSessionVerifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_session_with_jwks(
        &self,
        token: &str,
        config: &OidcClientConfig,
        observed_at: &Timestamp,
        jwks: &JwkSet,
    ) -> Result<VerifiedOidcSession, OidcSessionVerificationError> {
        let header =
            decode_header(token).map_err(|_| OidcSessionVerificationError::InvalidToken)?;
        let kid = header
            .kid
            .as_deref()
            .ok_or(OidcSessionVerificationError::MissingKeyId)?;
        let algorithm = supported_asymmetric_algorithm(header.alg)?;
        let jwk = jwks
            .find(kid)
            .ok_or(OidcSessionVerificationError::UnknownKeyId)?;
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|_| OidcSessionVerificationError::UnsupportedAlgorithm)?;
        let claims =
            decode::<JwtOidcClaims>(token, &key, &validation_for_oidc_claims(algorithm, config))
                .map_err(|_| OidcSessionVerificationError::JwtRejected)?
                .claims;
        let session = claims.into_verified_session(config.provider_name.clone(), observed_at)?;

        validate_oidc_session_context(&session, config, observed_at)?;

        Ok(session)
    }

    fn discovery_document(
        &self,
        config: &OidcClientConfig,
    ) -> Result<OidcDiscoveryDocument, OidcSessionVerificationError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscoveryDocument = self
            .fetch_json(&discovery_url)
            .map_err(|_| OidcSessionVerificationError::DiscoveryFetchFailed)?;

        if discovery.issuer != config.issuer {
            return Err(OidcSessionVerificationError::DiscoveryIssuerMismatch);
        }

        if discovery.jwks_uri.is_empty() {
            return Err(OidcSessionVerificationError::MissingJwksUri);
        }

        Ok(discovery)
    }

    fn jwks(&self, jwks_uri: &str) -> Result<JwkSet, OidcSessionVerificationError> {
        self.fetch_json(jwks_uri)
            .map_err(|_| OidcSessionVerificationError::JwksFetchFailed)
    }

    fn fetch_json<T>(&self, url: &str) -> Result<T, ()>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let url = url.to_string();
        std::thread::spawn(move || {
            reqwest::blocking::Client::new()
                .get(url)
                .send()
                .map_err(|_| ())?
                .error_for_status()
                .map_err(|_| ())?
                .json()
                .map_err(|_| ())
        })
        .join()
        .unwrap_or(Err(()))
    }
}

impl Default for OidcJwksSessionVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcSessionVerifier for OidcJwksSessionVerifier {
    fn verify_session(
        &self,
        token: &str,
        config: &OidcClientConfig,
        observed_at: &Timestamp,
    ) -> Result<VerifiedOidcSession, OidcSessionVerificationError> {
        let discovery = self.discovery_document(config)?;
        let jwks = self.jwks(&discovery.jwks_uri)?;

        self.verify_session_with_jwks(token, config, observed_at, &jwks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct JwtOidcClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: Option<AudienceClaim>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    auth_time: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
    exp: i64,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

impl JwtOidcClaims {
    fn into_verified_session(
        self,
        provider_name: String,
        observed_at: &Timestamp,
    ) -> Result<VerifiedOidcSession, OidcSessionVerificationError> {
        let observed_at = timestamp_to_unix_seconds(observed_at)
            .map_err(|_| OidcSessionVerificationError::InvalidObservedTimestamp)?;
        if self.exp <= observed_at {
            return Err(OidcSessionVerificationError::Expired);
        }

        Ok(VerifiedOidcSession {
            provider_name,
            issuer: self.iss,
            subject: self.sub,
            audiences: self.aud.map_or_else(Vec::new, AudienceClaim::into_vec),
            authorized_party: self.azp,
            session_id: self.sid,
            nonce: self.nonce,
            auth_time: self.auth_time.map(unix_seconds_to_timestamp),
            issued_at: self.iat.map_or_else(
                || unix_seconds_to_timestamp(observed_at),
                unix_seconds_to_timestamp,
            ),
            expires_at: unix_seconds_to_timestamp(self.exp),
            acr: self.acr,
            amr: self.amr,
            email: self.email,
            email_verified: self.email_verified.unwrap_or(false),
            preferred_username: self.preferred_username,
            display_name: self.name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

fn validation_for_oidc_claims(algorithm: Algorithm, config: &OidcClientConfig) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[config.issuer.clone()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation
}

fn supported_asymmetric_algorithm(
    algorithm: Algorithm,
) -> Result<Algorithm, OidcSessionVerificationError> {
    match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => Ok(algorithm),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Err(OidcSessionVerificationError::UnsupportedAlgorithm)
        }
    }
}
