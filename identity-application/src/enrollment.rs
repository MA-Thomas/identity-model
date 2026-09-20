//! Shared identity enrollment with explicit application, policy and transport boundaries.
#![forbid(unsafe_code)]
mod decisions;
mod error;
mod policy;
pub mod ports;
pub use decisions::DecisionSigner;
pub use error::ServiceError;
use identity_contract::*;
use identity_model::{OidcClientConfig, OidcSessionVerifier};
use ports::EnrollmentStore;
use std::sync::Arc;

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<i64, Error>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<i64, Error> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs()
            .try_into()
            .map_err(|_| Error::Unavailable)
    }
}
#[derive(Clone)]
pub struct Config {
    pub issuer: String,
    pub product: String,
    pub oidc: OidcClientConfig,
    pub product_key: [u8; 32],
    pub bank_key: [u8; 32],
}
pub struct EnrollmentService<R, V, C> {
    repository: R,
    signer: DecisionSigner,
    config: Config,
    verifier: Arc<V>,
    clock: C,
}
impl<R: EnrollmentStore, V: OidcSessionVerifier + Send + Sync + 'static, C: Clock>
    EnrollmentService<R, V, C>
{
    /// Hosts assemble persistence, verification, trusted time and signing.
    pub fn new(
        repository: R,
        config: Config,
        verifier: V,
        clock: C,
        signer: DecisionSigner,
    ) -> Result<Self, ServiceError> {
        if !config.product.starts_with("cs-mail/")
            || config.product.len() <= 8
            || config.issuer.is_empty()
            || config.oidc.issuer.is_empty()
            || config.oidc.client_id.is_empty()
        {
            return Err(Error::Invalid.into());
        }
        for key in [config.product_key, config.bank_key] {
            ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| Error::Invalid)?;
        }
        Ok(Self {
            repository,
            signer,
            config,
            verifier: Arc::new(verifier),
            clock,
        })
    }
    pub async fn handle(&self, request: &SignedRequest) -> Result<Response, ServiceError> {
        request.verify(&self.config.product, &self.config.product_key)?;
        match &request.request {
            Request::SecurityEvents {
                after_version,
                subject_ref,
            } => {
                self.repository
                    .security_events(&self.config.product, subject_ref, *after_version)
                    .await
            }
            Request::ChangeIdentity {
                intent,
                oidc_token,
                bank,
                device_proof,
                new_login_token,
            } => {
                let now = self.clock.now()?;
                let hash = digest("identity/change-request/v1", request)?;
                if let Some(response) = self
                    .repository
                    .existing_change(&self.config.product, &intent.authorization.operation, &hash)
                    .await?
                {
                    return Ok(response);
                }
                intent.validate(now)?;
                if intent.authorization.product != self.config.product {
                    return Err(Error::Context.into());
                }
                let verifier = self.verifier.clone();
                let config = self.config.clone();
                let authority = intent.authorization.clone();
                let token = oidc_token.clone();
                let bank_copy = bank.clone();
                let proof = device_proof.clone();
                let new_token = new_login_token.clone();
                let (evidence, new_login) = tokio::task::spawn_blocking(move || {
                    let evidence = policy::verify(
                        &*verifier, &config, &authority, &token, &bank_copy, &proof, now,
                    )?;
                    let new_login = if let Some(token) = new_token {
                        let at = identity_model::time::unix_seconds_to_timestamp(now);
                        let session = verifier
                            .verify_session(&token, &config.oidc, &at)
                            .map_err(|_| Error::Unauthorized)?;
                        identity_model::validate_oidc_session_context(&session, &config.oidc, &at)
                            .map_err(|_| Error::Unauthorized)?;
                        let authenticated = session
                            .auth_time
                            .as_ref()
                            .and_then(|at| identity_model::time::timestamp_to_unix_seconds(at).ok())
                            .ok_or(Error::Unauthorized)?;
                        if session.nonce.as_deref() != Some(&authority.challenge)
                            || authenticated > now
                            || now - authenticated > MAX_LIFETIME
                        {
                            return Err(Error::Unauthorized);
                        }
                        Some(session)
                    } else {
                        None
                    };
                    Ok::<_, Error>((evidence, new_login))
                })
                .await??;
                self.repository
                    .change(
                        ports::ChangeScope {
                            product: &self.config.product,
                            intent,
                            login: (&evidence.session.issuer, &evidence.session.subject),
                            new_login: new_login
                                .as_ref()
                                .map(|s| (s.issuer.as_str(), s.subject.as_str())),
                        },
                        |context| {
                            decisions::change(
                                decisions::DecisionAuthority {
                                    config: &self.config,
                                    signer: &self.signer,
                                    clock: &self.clock,
                                },
                                intent,
                                &evidence,
                                new_login.as_ref(),
                                &bank.claims.evidence_ref,
                                &hash,
                                context,
                            )
                        },
                    )
                    .await
            }
            Request::Lookup { operation } => {
                self.repository
                    .lookup(&self.config.product, operation)
                    .await
            }
            Request::Confirm { decision } => {
                self.repository
                    .confirm(&self.config.product, decision)
                    .await
            }
            Request::Enroll {
                intent,
                oidc_token,
                bank,
                device_proof,
            } => {
                if intent.product != self.config.product {
                    return Err(Error::Context.into());
                }
                let hash = digest("identity/enrollment-request/v1", request)?;
                if let Some(response) = self.repository.existing(intent, &hash).await? {
                    return Ok(response);
                }
                let verifier = self.verifier.clone();
                let config = self.config.clone();
                let intent_copy = intent.clone();
                let token = oidc_token.clone();
                let bank_copy = bank.clone();
                let device = device_proof.clone();
                let started = self.clock.now()?;
                // Only the synchronous OIDC adapter runs on the blocking pool. No database lock spans I/O.
                let evidence = tokio::task::spawn_blocking(move || {
                    policy::verify(
                        &*verifier,
                        &config,
                        &intent_copy,
                        &token,
                        &bank_copy,
                        &device,
                        started,
                    )
                })
                .await??;
                self.repository
                    .record(
                        ports::EnrollmentScope {
                            product: &self.config.product,
                            intent,
                            login: (&evidence.session.issuer, &evidence.session.subject),
                        },
                        |context| {
                            decisions::enroll(
                                decisions::DecisionAuthority {
                                    config: &self.config,
                                    signer: &self.signer,
                                    clock: &self.clock,
                                },
                                intent,
                                &evidence,
                                &bank.claims.evidence_ref,
                                &hash,
                                context,
                            )
                        },
                    )
                    .await
            }
        }
    }
}
