//! Shared identity enrollment with explicit application, policy and transport boundaries.
#![forbid(unsafe_code)]
mod decisions;
mod error;
pub mod evidence;
mod policy;
pub mod ports;
pub use decisions::DecisionSigner;
pub use error::ServiceError;
use evidence::{EvidenceKey, EvidencePolicy};
use identity_contract::*;
use identity_model::{
    fen::SubjectId, login::ProductLoginIdentity, OidcClientConfig, OidcSessionVerifier,
};
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
    policy: EvidencePolicy,
    evidence_key: EvidenceKey,
    verifier: Arc<V>,
    clock: C,
}
impl<R: EnrollmentStore, V: OidcSessionVerifier + Send + Sync + 'static, C: Clock>
    EnrollmentService<R, V, C>
{
    /// Hosts assemble persistence, verification, trusted time, signing and the evidence
    /// key. The product's evidence policy follows from the configured product.
    pub fn new(
        repository: R,
        config: Config,
        verifier: V,
        clock: C,
        signer: DecisionSigner,
        evidence_key: EvidenceKey,
    ) -> Result<Self, ServiceError> {
        let policy = EvidencePolicy::for_product(&config.product).ok_or(Error::Invalid)?;
        if config.issuer.is_empty()
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
            policy,
            evidence_key,
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
                let evidence = tokio::task::spawn_blocking(move || {
                    policy::verify(
                        &*verifier, &config, &authority, &token, &bank_copy, &proof, now,
                    )
                })
                .await??;
                self.repository
                    .change(
                        ports::ChangeScope {
                            product: &self.config.product,
                            intent,
                            login: (&evidence.session.issuer, &evidence.session.subject),
                        },
                        |context| {
                            decisions::change(
                                decisions::DecisionAuthority {
                                    config: &self.config,
                                    policy: self.policy,
                                    signer: &self.signer,
                                    now: self.clock.now()?,
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
            Request::Lookup { operation } => Ok(decisions::lookup(
                self.repository
                    .lookup(&self.config.product, operation)
                    .await?,
            )),
            Request::Reviews => Ok(Response::Reviews(
                self.repository.reviews(&self.config.product).await?,
            )),
            Request::ResolveReview {
                case,
                resolution,
                reviewer,
                authorization,
            } => {
                let case = self
                    .repository
                    .resolve(&self.config.product, case, |case| {
                        decisions::resolve(
                            case,
                            *resolution,
                            reviewer,
                            authorization,
                            // Sample trusted time only after protected reads.
                            self.clock.now()?,
                        )
                    })
                    .await?;
                Ok(Response::ReviewResolved(Box::new(case)))
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
                applicant,
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
                // Evidence is established only when the bank confirmed ownership; the
                // decision records and screens it.
                let fingerprints = if evidence.ownership == Ownership::Confirmed {
                    Some(
                        self.policy
                            .establish(applicant, &bank.claims)?
                            .fingerprints(&self.evidence_key, &self.config.product)?,
                    )
                } else {
                    None
                };
                // Allocate candidates before acquiring persistence protection. The
                // deterministic decision discards them when a product login exists.
                let fresh = decisions::NewProductLogin {
                    identity: ProductLoginIdentity::new(
                        self.config.product.clone(),
                        SubjectId(random_id()?),
                        evidence.session.issuer.clone(),
                        evidence.session.subject.clone(),
                    )
                    .map_err(|_| Error::Invalid)?,
                    subject_ref: random_id()?.try_into()?,
                };
                self.repository
                    .record(
                        ports::EnrollmentScope {
                            product: &self.config.product,
                            intent,
                            login: (&evidence.session.issuer, &evidence.session.subject),
                            evidence: fingerprints.as_ref(),
                        },
                        |context| {
                            decisions::enroll(
                                decisions::DecisionAuthority {
                                    config: &self.config,
                                    policy: self.policy,
                                    signer: &self.signer,
                                    // Sample trusted time only after protected reads.
                                    now: self.clock.now()?,
                                },
                                decisions::EnrollAttempt {
                                    intent,
                                    evidence: &evidence,
                                    fingerprints: fingerprints.as_ref(),
                                    evidence_ref: &bank.claims.evidence_ref,
                                    hash: &hash,
                                },
                                context,
                                fresh,
                            )
                        },
                    )
                    .await
            }
        }
    }
}
