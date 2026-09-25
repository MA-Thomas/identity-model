//! One durable login identity per product and subject. Authentication methods are
//! managed by the configured identity provider without changing its external subject.
use crate::fen::SubjectId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidProductLogin;

/// The stable identity is `(product, subject)`. The provider login is its binding,
/// not another person or an authentication method. Only enrollment establishes it.
/// Construction validates a record; persistence must enforce exclusive ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductLoginIdentity {
    product: String,
    subject: SubjectId,
    issuer: String,
    external_subject: String,
}

impl ProductLoginIdentity {
    pub fn new(
        product: String,
        subject: SubjectId,
        issuer: String,
        external_subject: String,
    ) -> Result<Self, InvalidProductLogin> {
        if [&product, &subject.0, &issuer, &external_subject]
            .iter()
            .any(|value| value.is_empty() || value.chars().any(char::is_control))
        {
            return Err(InvalidProductLogin);
        }
        Ok(Self {
            product,
            subject,
            issuer,
            external_subject,
        })
    }

    pub fn product(&self) -> &str {
        &self.product
    }
    pub fn subject(&self) -> &SubjectId {
        &self.subject
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn external_subject(&self) -> &str {
        &self.external_subject
    }

    /// Compares a provider binding; the caller must independently verify the session.
    pub fn matches_login(&self, product: &str, issuer: &str, external_subject: &str) -> bool {
        self.product == product
            && self.issuer == issuer
            && self.external_subject == external_subject
    }
}
