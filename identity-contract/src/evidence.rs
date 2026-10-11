//! Person evidence presented at enrollment, and operator review of an enrollment whose
//! evidence overlaps another enrollment's. Which fields a product requires and which
//! overlaps need review are that product's policy, decided by the identity service.
use super::*;

/// One kind of person evidence a product's policy may compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceField {
    Name,
    DateOfBirth,
    BankAccount,
    Address,
    Phone,
}
impl EvidenceField {
    pub const ALL: [Self; 5] = [
        Self::Name,
        Self::DateOfBirth,
        Self::BankAccount,
        Self::Address,
        Self::Phone,
    ];
    /// Stable storage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::DateOfBirth => "date_of_birth",
            Self::BankAccount => "bank_account",
            Self::Address => "address",
            Self::Phone => "phone",
        }
    }
    /// # Errors
    /// Rejects an unknown storage name.
    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str() == value)
            .ok_or(Error::Invalid)
    }
}

/// What the bank integration reports about one owner of the verified account, as the
/// bank holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedOwner {
    pub names: Vec<String>,
    pub addresses: Vec<String>,
    pub phones: Vec<String>,
}

/// What the applicant states about themselves. The identity service checks the name,
/// address and phone against the bank's report; the date of birth is the applicant's
/// statement.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicantClaims {
    pub name: String,
    pub date_of_birth: String,
    pub address: String,
    pub phone: String,
}
impl fmt::Debug for ApplicantClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicantClaims(..)")
    }
}

/// One review case within a product. There is at most one per enrollment operation, so
/// its identifier derives from the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReviewCaseId(String);
impl ReviewCaseId {
    /// # Errors
    /// Rejects values that cannot be encoded.
    pub fn for_operation(product: &str, operation: &str) -> Result<Self, Error> {
        Ok(Self(
            digest("identity/review-case/v1", &(product, operation))?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for ReviewCaseId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid);
        }
        Ok(Self(value))
    }
}
impl From<ReviewCaseId> for String {
    fn from(value: ReviewCaseId) -> Self {
        value.0
    }
}

/// Another enrollment whose evidence overlaps the applicant's, and the fields that match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewMatch {
    /// The other enrollment's product account.
    pub account: String,
    pub fields: Vec<EvidenceField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewResolution {
    Approve,
    Deny,
}

/// A product reviewer's decision and the product's record of authorizing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDecision {
    pub resolution: ReviewResolution,
    /// Who decided, in the product's terms (for cs-mail, the operator key).
    pub reviewer: String,
    /// The product's reference to the authorization it verified (for cs-mail, the
    /// digest of the signed operator command).
    pub authorization: String,
    pub decided_at: i64,
}

/// An enrollment held for review: opened when its evidence overlapped another
/// enrollment's as the product's policy defines, and resolved once by the product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCase {
    pub id: ReviewCaseId,
    pub operation: String,
    /// The applicant's product account.
    pub account: String,
    pub opened_at: i64,
    pub matches: Vec<ReviewMatch>,
    pub decision: Option<ReviewDecision>,
}
impl ReviewDecision {
    /// # Errors
    /// Rejects reviewer or authorization text that is empty, too long or has control
    /// characters.
    pub fn new(
        resolution: ReviewResolution,
        reviewer: String,
        authorization: String,
        decided_at: i64,
    ) -> Result<Self, Error> {
        if !text_valid(&reviewer) || !text_valid(&authorization) || decided_at < 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            resolution,
            reviewer,
            authorization,
            decided_at,
        })
    }
}
