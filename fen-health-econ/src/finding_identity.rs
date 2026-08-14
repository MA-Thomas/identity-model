//! Deterministic finding identity
//! (FEN_RECONCILIATION_RULE_ENGINE.md §D, sequencing step 3).
//!
//! Re-evaluation must be idempotent: re-running rules over unchanged inputs
//! must not append duplicate `BillingDiscrepancy` facts. A finding's
//! [`FactId`] is therefore derived from its semantic identity, not generated:
//!
//! ```text
//! finding_fact_id = H(subject_id, rule_ref /* id@version */, kind,
//!                     sorted(derived_from.fact_ids))
//! ```
//!
//! Consequences, all intended: same inputs + same rule version → same
//! `FactId`, so the envelope store's existing duplicate-fact-id rejection
//! dedupes the re-append for free; a new rule version over the same inputs
//! is a *new* finding (conclusions are versioned); changed inputs produce a
//! new finding that supersedes the old one via
//! `SupersessionReason::RuleReEvaluation`.
//!
//! # The durable hash contract
//!
//! This encoding becomes part of the durable contract the moment the first
//! production finding is appended. It is pinned by a golden test
//! (`tests/finding_identity.rs`), like the AAD canonicalization. Frozen:
//!
//! - **Hash**: SHA-256.
//! - **Preimage**: the concatenation of length-prefixed fields, each encoded
//!   as an 8-byte big-endian byte length followed by the UTF-8 bytes (the
//!   `push_bytes` convention the AAD canonicalization uses), in this order:
//!   1. the domain tag `fen.health_econ.reconciliation_finding.fact_id.v1`
//!   2. the subject ID string
//!   3. the versioned rule ref string (`rule-id@version`)
//!   4. the discrepancy-kind identity label
//!      ([`discrepancy_kind_identity_label`])
//!   5. the decimal count of cited fact IDs
//!   6. each cited fact ID string, sorted ascending by byte order
//!      (duplicates, if ever cited, are preserved)
//! - **Rendering**: `finding-` followed by the lowercase hex digest.
//!
//! Changing any of this changes what "the same finding" *means* across rule
//! versions and corrected inputs; it requires a new domain-tag version and
//! the same review weight as a persisted-label change.

use identity_model::{FactId, SubjectId};
use sha2::{Digest, Sha256};

use crate::reconcile::ReconciliationFinding;
use crate::schema::{DiscrepancyKind, RuleArtifactRef};

const FINDING_FACT_ID_DOMAIN_TAG: &str = "fen.health_econ.reconciliation_finding.fact_id.v1";

/// Frozen identity labels for [`DiscrepancyKind`]. These participate in the
/// finding-identity preimage and are as frozen as persisted labels: renaming
/// a variant must not change its label.
pub fn discrepancy_kind_identity_label(kind: &DiscrepancyKind) -> String {
    match kind {
        DiscrepancyKind::BillVsEobMismatch => "bill_vs_eob_mismatch".to_string(),
        DiscrepancyKind::DuplicateCharge => "duplicate_charge".to_string(),
        DiscrepancyKind::AboveAllowedAmount => "above_allowed_amount".to_string(),
        DiscrepancyKind::AppealableDenial => "appealable_denial".to_string(),
        DiscrepancyKind::Other(label) => format!("other:{label}"),
    }
}

/// The deterministic [`FactId`] for a finding's semantic identity. See the
/// module docs for the frozen encoding.
pub fn finding_fact_id(
    subject_id: &SubjectId,
    rule_ref: &RuleArtifactRef,
    kind: &DiscrepancyKind,
    fact_ids: &[FactId],
) -> FactId {
    let mut sorted_ids: Vec<&str> = fact_ids.iter().map(|id| id.0.as_str()).collect();
    sorted_ids.sort_unstable();

    let mut preimage = Vec::new();
    push_bytes(&mut preimage, FINDING_FACT_ID_DOMAIN_TAG.as_bytes());
    push_bytes(&mut preimage, subject_id.0.as_bytes());
    push_bytes(&mut preimage, rule_ref.0.as_bytes());
    push_bytes(
        &mut preimage,
        discrepancy_kind_identity_label(kind).as_bytes(),
    );
    push_bytes(&mut preimage, sorted_ids.len().to_string().as_bytes());
    for id in sorted_ids {
        push_bytes(&mut preimage, id.as_bytes());
    }

    let digest = Sha256::digest(&preimage);
    let mut rendered = String::with_capacity(8 + digest.len() * 2);
    rendered.push_str("finding-");
    for byte in digest {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    FactId(rendered)
}

impl ReconciliationFinding {
    /// The deterministic fact ID this finding appends under: a pure function
    /// of subject, versioned rule, kind, and the cited fact IDs. Everything
    /// else on the finding (summary, amounts, `evaluated_at`) is derived
    /// content, not identity.
    pub fn fact_id(&self) -> FactId {
        finding_fact_id(
            &self.subject_id,
            &self.derived_from.rule_ref,
            &self.kind,
            &self.derived_from.fact_ids,
        )
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The `push_bytes` length-prefix convention shared with the identity
/// crate's AAD canonicalization: 8-byte big-endian length, then the bytes.
fn push_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}
