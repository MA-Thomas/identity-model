//! Product evidence policies. A policy names the person evidence a product requires,
//! how it is normalized for exact comparison, and which overlaps with another
//! enrollment of the same product require review. Evidence is kept only as keyed
//! fingerprints, scoped to the product, so enrollments of different products are never
//! compared and stored values do not disclose the evidence.
use hmac::{Hmac, KeyInit, Mac};
use identity_contract::{evidence::*, *};
use sha2::Sha256;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

/// The enrollment evidence policy of one product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePolicy {
    /// Name, date of birth, bank account, address and phone. Name, address and phone
    /// must be ones the bank reports for an owner of the verified account. Review is
    /// required when a shared bank account, or any two fields, match another enrollment.
    CsMail,
}
impl EvidencePolicy {
    /// The policy a product's enrollments are decided under.
    pub fn for_product(product: &str) -> Option<Self> {
        product
            .strip_prefix("cs-mail/")
            .filter(|environment| !environment.is_empty())
            .map(|_| Self::CsMail)
    }
    /// The policy identifier carried by decisions made under it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::CsMail => CS_MAIL_POLICY,
        }
    }
    /// Whether matching `fields` with another enrollment requires review.
    pub fn requires_review(self, fields: &[EvidenceField]) -> bool {
        match self {
            Self::CsMail => fields.len() >= 2 || fields.contains(&EvidenceField::BankAccount),
        }
    }
    /// Establishes the applicant's evidence from their claims and the bank's report.
    /// # Errors
    /// `Context` when the claims are not what the bank reports for one owner of the
    /// account; `Invalid` for claims that cannot be normalized.
    pub fn establish(
        self,
        applicant: &ApplicantClaims,
        bank: &BankOwnershipClaims,
    ) -> Result<PersonEvidence, Error> {
        match self {
            Self::CsMail => {
                let name = text(&applicant.name)?;
                let address = text(&applicant.address)?;
                let phone = phone(&applicant.phone)?;
                let reported = bank.owners.iter().any(|owner| {
                    reports(&owner.names, &name, text)
                        && reports(&owner.addresses, &address, text)
                        && reports(&owner.phones, &phone, self::phone)
                });
                if !reported || bank.account_token == [0; 32] {
                    return Err(Error::Context);
                }
                Ok(PersonEvidence(BTreeMap::from([
                    (EvidenceField::Name, name),
                    (EvidenceField::DateOfBirth, date(&applicant.date_of_birth)?),
                    (EvidenceField::BankAccount, hex(&bank.account_token)),
                    (EvidenceField::Address, address),
                    (EvidenceField::Phone, phone),
                ])))
            }
        }
    }
}
fn reports(
    values: &[String],
    expected: &str,
    normalize: fn(&str) -> Result<String, Error>,
) -> bool {
    values
        .iter()
        .any(|value| normalize(value).is_ok_and(|value| value == expected))
}

/// An applicant's normalized evidence, established under a product's policy.
pub struct PersonEvidence(BTreeMap<EvidenceField, String>);
impl PersonEvidence {
    /// Keyed fingerprints of each field, scoped to `product`.
    /// # Errors
    /// Rejects an unusable key.
    pub fn fingerprints(
        &self,
        key: &EvidenceKey,
        product: &str,
    ) -> Result<EvidenceFingerprints, Error> {
        let mut fingerprints = BTreeMap::new();
        for (field, value) in &self.0 {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).map_err(|_| Error::Invalid)?;
            for part in ["identity/evidence/v1", product, field.as_str(), value] {
                // Length-prefixed parts cannot be confused with one another.
                mac.update(&(part.len() as u64).to_be_bytes());
                mac.update(part.as_bytes());
            }
            fingerprints.insert(*field, mac.finalize().into_bytes().into());
        }
        Ok(EvidenceFingerprints(fingerprints))
    }
}

/// The identity service's secret for evidence fingerprints. Never logged.
pub struct EvidenceKey([u8; 32]);
impl EvidenceKey {
    pub const fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }
}

/// One enrollment's evidence as keyed fingerprints, one per field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceFingerprints(BTreeMap<EvidenceField, [u8; 32]>);
impl EvidenceFingerprints {
    /// Restores recorded fingerprints.
    /// # Errors
    /// Rejects a repeated field.
    pub fn from_recorded(
        rows: impl IntoIterator<Item = (EvidenceField, [u8; 32])>,
    ) -> Result<Self, Error> {
        let mut fingerprints = BTreeMap::new();
        for (field, value) in rows {
            if fingerprints.insert(field, value).is_some() {
                return Err(Error::Invalid);
            }
        }
        Ok(Self(fingerprints))
    }
    pub fn iter(&self) -> impl Iterator<Item = (EvidenceField, &[u8; 32])> {
        self.0.iter().map(|(field, value)| (*field, value))
    }
    /// The fields whose fingerprints are equal in both.
    pub fn matching(&self, other: &Self) -> Vec<EvidenceField> {
        self.0
            .iter()
            .filter(|(field, value)| other.0.get(field) == Some(value))
            .map(|(field, _)| *field)
            .collect()
    }
}

/// Case, accents' composed form and spacing are not distinctions; punctuation is removed.
fn text(value: &str) -> Result<String, Error> {
    let normalized = value
        .nfkc()
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() || normalized.len() > 256 {
        return Err(Error::Invalid);
    }
    Ok(normalized)
}
/// E.164 digits. A ten-digit number without a country code is a North American number.
fn phone(value: &str) -> Result<String, Error> {
    let international = value.trim_start().starts_with('+');
    if value
        .chars()
        .any(|c| !(c.is_ascii_digit() || " +-().".contains(c)))
    {
        return Err(Error::Invalid);
    }
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    let digits = match (international, digits.len()) {
        (false, 10) => format!("1{digits}"),
        (false, 11) if digits.starts_with('1') => digits,
        (true, 8..=15) if !digits.starts_with('0') => digits,
        _ => return Err(Error::Invalid),
    };
    Ok(format!("+{digits}"))
}
/// A calendar date written YYYY-MM-DD.
fn date(value: &str) -> Result<String, Error> {
    let parts: Vec<&str> = value.trim().split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return Err(Error::Invalid);
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return Err(Error::Invalid);
    }
    let number = |part: &str| part.parse::<u32>().map_err(|_| Error::Invalid);
    let (y, m, d) = (number(year)?, number(month)?, number(day)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(Error::Invalid),
    };
    if !(1900..=9999).contains(&y) || d == 0 || d > days {
        return Err(Error::Invalid);
    }
    Ok(format!("{y:04}-{m:02}-{d:02}"))
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fingerprints(fields: &[(EvidenceField, u8)]) -> EvidenceFingerprints {
        EvidenceFingerprints::from_recorded(fields.iter().map(|(f, v)| (*f, [*v; 32]))).unwrap()
    }
    /// Claim: cs-mail's policy requires review exactly when a shared bank account, or any
    /// two fields, match another enrollment. Falsified by a pair of evidence sets whose
    /// review outcome differs from that rule; it matters because the rule is the only
    /// gate between one person and a second account.
    #[test]
    fn cs_mail_review_follows_the_agreed_rule() {
        let policy = EvidencePolicy::CsMail;
        let applicant = fingerprints(&EvidenceField::ALL.map(|f| (f, 1)));
        for (i, first) in EvidenceField::ALL.into_iter().enumerate() {
            let single =
                fingerprints(&EvidenceField::ALL.map(|f| (f, if f == first { 1 } else { 2 })));
            assert_eq!(
                policy.requires_review(&applicant.matching(&single)),
                first == EvidenceField::BankAccount,
                "{first:?} alone"
            );
            for second in &EvidenceField::ALL[i + 1..] {
                let pair = fingerprints(
                    &EvidenceField::ALL
                        .map(|f| (f, if f == first || f == *second { 1 } else { 2 })),
                );
                assert!(policy.requires_review(&applicant.matching(&pair)));
            }
        }
    }
}
