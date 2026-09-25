//! Explicit account-change ceremonies and ordered product security notifications.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityChange {
    RecoverDevice {
        key_reference: String,
        persona: String,
    },
    RebindBank,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeIntent {
    pub authorization: EnrollmentIntent,
    pub subject_ref: ProductSubjectRef,
    pub expected_security_version: u64,
    pub change: IdentityChange,
}
impl ChangeIntent {
    pub fn validate(&self, now: i64) -> Result<(), Error> {
        self.authorization.validate(now)?;
        if self.expected_security_version == 0
            || self.authorization.enrollment_digest
                != digest(
                    "identity/change-intent/v1",
                    &(
                        &self.subject_ref,
                        self.expected_security_version,
                        &self.change,
                    ),
                )?
        {
            return Err(Error::Context);
        }
        match &self.change {
            IdentityChange::RecoverDevice {
                key_reference,
                persona,
            } if !text_valid(key_reference) || !text_valid(persona) => Err(Error::Invalid),
            _ => Ok(()),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub id: String,
    pub issuer: String,
    pub product: String,
    pub account: String,
    pub subject_ref: ProductSubjectRef,
    pub security_version: u64,
    pub occurred_at: i64,
    pub policy: String,
    pub evidence_ref: String,
    pub change: IdentityChange,
    pub initial_key: [u8; 32],
    pub bank_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSecurityEvent {
    pub signing_key: String,
    pub event: SecurityEvent,
    pub signature: Vec<u8>,
}
impl SignedSecurityEvent {
    pub fn sign(event: SecurityEvent, secret: &[u8; 32]) -> Result<Self, Error> {
        let signing_key =
            decision_key_id(&SigningKey::from_bytes(secret).verifying_key().to_bytes())?;
        let signature = super::sign(
            "identity/security-event/v1",
            &(&signing_key, &event),
            secret,
        )?;
        Ok(Self {
            signing_key,
            event,
            signature,
        })
    }
}
#[derive(Debug, Clone)]
pub struct VerifiedSecurityEvent(SecurityEvent);
impl VerifiedSecurityEvent {
    pub fn event(&self) -> &SecurityEvent {
        &self.0
    }
}
impl DecisionVerifier {
    pub fn verify_security_event(
        &self,
        signed: &SignedSecurityEvent,
        now: i64,
    ) -> Result<VerifiedSecurityEvent, Error> {
        let event = &signed.event;
        let key = self.key_at(&signed.signing_key, event.occurred_at, now)?;
        super::verify(
            "identity/security-event/v1",
            &(&signed.signing_key, event),
            &signed.signature,
            key,
        )?;
        if event.issuer != self.issuer
            || event.product != self.product
            || event.security_version < 2
            || event.occurred_at > now
            || event.occurred_at < 0
            || !text_valid(&event.id)
            || !text_valid(&event.account)
            || !text_valid(&event.evidence_ref)
            || event.policy != "cs-mail.account-change.v1"
        {
            return Err(Error::Context);
        }
        Ok(VerifiedSecurityEvent(event.clone()))
    }
}
