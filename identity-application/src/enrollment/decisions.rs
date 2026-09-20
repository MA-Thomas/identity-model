use super::{policy::Evidence, ports::*, Clock, Config, ServiceError};
use identity_contract::{changes::*, *};
/// Local signing is an application dependency. Storage never receives a signing secret.
pub struct DecisionSigner {
    secret: [u8; 32],
}
impl DecisionSigner {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }
    fn decision(&self, claims: DecisionClaims) -> Result<SignedDecision, Error> {
        SignedDecision::sign(claims, &self.secret)
    }
    fn event(&self, event: SecurityEvent) -> Result<SignedSecurityEvent, Error> {
        SignedSecurityEvent::sign(event, &self.secret)
    }
}
pub(super) struct DecisionAuthority<'a, C> {
    pub config: &'a Config,
    pub signer: &'a DecisionSigner,
    pub clock: &'a C,
}
pub(super) fn enroll(
    authority: DecisionAuthority<'_, impl Clock>,
    intent: &EnrollmentIntent,
    evidence: &Evidence,
    evidence_ref: &str,
    hash: &[u8; 32],
    context: EnrollmentContext,
) -> Result<EnrollmentDecision, ServiceError> {
    let DecisionAuthority {
        config,
        signer,
        clock,
    } = authority;
    if let Some(prior) = context.prior {
        if prior.intent.challenge == intent.challenge {
            if prior.digest != hash {
                return Err(Error::Conflict.into());
            }
            return Ok(EnrollmentDecision {
                response: prior.response,
                writes: None,
            });
        }
        if !prior.intent.same_enrollment(intent) || intent.created_at < prior.intent.expires_at {
            return Err(Error::Conflict.into());
        }
    }
    if context.enrollment.as_ref().is_some_and(|e| e.confirmed) {
        return Err(Error::Conflict.into());
    }
    let now = clock.now()?;
    intent.validate(now)?;
    if now >= evidence.expires_at {
        return Err(Error::Expired.into());
    }
    let mut subject_write = None;
    let mut login_write = None;
    let mut reference_write = None;
    let mut enrollment_write = None;
    let response = match evidence.ownership {
        Ownership::Denied => Response::Denied,
        Ownership::ReviewRequired => Response::ReviewRequired,
        Ownership::Confirmed => {
            let (subject, reference) = if let Some(login) = context.login {
                if login.status != "active" {
                    return Err(Error::Unauthorized.into());
                }
                (login.subject, login.product_ref)
            } else {
                let subject = random_id()?;
                subject_write = Some((subject.clone(), "active".into()));
                login_write = Some((
                    evidence.session.issuer.clone(),
                    evidence.session.subject.clone(),
                    subject.clone(),
                ));
                (subject, None)
            };
            let reference = if let Some(reference) = reference {
                reference
            } else {
                let reference = random_id()?;
                reference_write = Some((subject, reference.clone()));
                reference
            };
            if let Some(owner) = context.enrollment {
                if owner.account != intent.account || owner.subject_ref != reference {
                    return Err(Error::Conflict.into());
                }
            } else {
                enrollment_write = Some((intent.account.clone(), reference.clone()));
            }
            Response::Eligible(Box::new(signer.decision(DecisionClaims {
                issuer: config.issuer.clone(),
                intent: intent.clone(),
                subject_ref: reference.try_into()?,
                binding_version: 1,
                security_version: 1,
                policy: CS_MAIL_POLICY.into(),
                evidence_ref: evidence_ref.into(),
                issued_at: now,
                expires_at: evidence.expires_at,
            })?))
        }
    };
    Ok(EnrollmentDecision {
        response: response.clone(),
        writes: Some(EnrollmentWrites {
            subject: subject_write,
            login: login_write,
            product_ref: reference_write,
            enrollment: enrollment_write,
            attempt: PriorAttempt {
                intent: intent.clone(),
                digest: hash.to_vec(),
                response,
            },
        }),
    })
}
pub(super) fn change(
    authority: DecisionAuthority<'_, impl Clock>,
    intent: &ChangeIntent,
    evidence: &Evidence,
    new_login: Option<&identity_model::VerifiedOidcSession>,
    evidence_ref: &str,
    hash: &[u8; 32],
    context: ChangeContext,
) -> Result<ChangeDecision, ServiceError> {
    let DecisionAuthority {
        config,
        signer,
        clock,
    } = authority;
    if let Some((digest, event)) = context.prior {
        if digest != hash {
            return Err(Error::Conflict.into());
        }
        return Ok(ChangeDecision {
            response: Response::IdentityChanged(Box::new(event)),
            writes: None,
        });
    }
    if context.version != intent.expected_security_version {
        return Err(Error::Conflict.into());
    }
    if !context.login_owned || context.status != "active" || !context.confirmed {
        return Err(Error::Unauthorized.into());
    }
    let authorization = &intent.authorization;
    let mut login_write = None;
    match &intent.change {
        IdentityChange::RecoverDevice { .. } if authorization.bank_digest != context.old_bank => {
            return Err(Error::Context.into())
        }
        IdentityChange::RebindBank
            if authorization.initial_key != context.old_key
                || authorization.bank_digest == context.old_bank =>
        {
            return Err(Error::Context.into())
        }
        IdentityChange::LinkLogin => {
            if authorization.initial_key != context.old_key
                || authorization.bank_digest != context.old_bank
            {
                return Err(Error::Context.into());
            }
            let login = new_login.ok_or(Error::Unauthorized)?;
            if let Some(owner) = context.new_login_owner {
                if owner != context.subject {
                    return Err(Error::Conflict.into());
                }
            } else {
                login_write = Some((login.issuer.clone(), login.subject.clone(), context.subject));
            }
        }
        _ => {}
    }
    let now = clock.now()?;
    intent.validate(now)?;
    if now >= evidence.expires_at || evidence.ownership != Ownership::Confirmed {
        return Err(Error::Unauthorized.into());
    }
    if let Some(login) = new_login {
        if identity_model::time::timestamp_to_unix_seconds(&login.expires_at)
            .map_err(|_| Error::Invalid)?
            <= now
        {
            return Err(Error::Expired.into());
        }
    }
    let event = signer.event(SecurityEvent {
        id: authorization.operation.clone(),
        issuer: config.issuer.clone(),
        product: config.product.clone(),
        account: authorization.account.clone(),
        subject_ref: intent.subject_ref.clone(),
        security_version: context.version.checked_add(1).ok_or(Error::Invalid)?,
        occurred_at: now,
        policy: "cs-mail.account-change.v1".into(),
        evidence_ref: evidence_ref.into(),
        change: intent.change.clone(),
        initial_key: authorization.initial_key,
        bank_digest: authorization.bank_digest,
    })?;
    Ok(ChangeDecision {
        response: Response::IdentityChanged(Box::new(event.clone())),
        writes: Some(ChangeWrites {
            event,
            digest: *hash,
            login: login_write,
        }),
    })
}
