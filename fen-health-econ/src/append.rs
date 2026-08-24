//! Findings enter the fact graph through the normal append path
//! (FEN_RECONCILIATION_RULE_ENGINE.md §C, sequencing step 4).
//!
//! The engine's [`ReconciliationFinding`] values become facts only by going
//! back through the same encrypted append path as every other fact — as
//! `Inference`-tier [`HealthEconFact`]s whose provenance is
//! `AuthorType::System`, whose payload is the candidate
//! `BillingDiscrepancy`, and whose [`FactId`] is the deterministic finding
//! identity from [`crate::finding_identity`]. There is no special write path
//! for conclusions.
//!
//! Supersession: when changed inputs (a corrected bill) produce a finding
//! with a new identity, the old finding is marked
//! `FactStatus::Superseded { reason: RuleReEvaluation, replaced_by: <new> }`.
//! As in the identity crate's dispute flow, the superseded status travels
//! with the fact through the append/workflow slice that records the
//! re-evaluation; a stored envelope's status is part of its authenticated
//! associated data and is never mutated in place.

use fen_core::{
    Author, AuthorType, FactId, FactStatus, Provenance, ProvenanceTier, SupersessionReason,
    TemporalAnchor, Timestamp,
};

use crate::reconcile::ReconciliationFinding;
use crate::schema::HealthEconFact;
use crate::schema::HealthEconFactPayload;

/// The system author every engine-produced fact carries. The *analytical*
/// authorship is in `DerivedFrom.rule_ref`; this is just the actor type.
fn engine_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: None,
        display_name: Some("reconciliation-engine".to_string()),
    }
}

/// Converts a finding into the `Inference`-tier fact it appends as:
/// deterministic finding ID, `BillingDiscrepancy` payload with its
/// `DerivedFrom`, system authorship, no authorization basis (a derivation is
/// not an ingestion), and `occurred_at` = the evaluation instant.
pub fn finding_to_inference_fact(
    finding: &ReconciliationFinding,
    imported_at: Timestamp,
) -> HealthEconFact {
    HealthEconFact {
        id: finding.fact_id(),
        subject_id: finding.subject_id.clone(),
        occurred_at: TemporalAnchor::Point(finding.evaluated_at.clone()),
        code: None,
        payload: HealthEconFactPayload::BillingDiscrepancy(
            finding.to_billing_discrepancy_payload(),
        ),
        status: FactStatus::Active,
        provenance: Provenance {
            source_system: None,
            source_document: None,
            imported_at,
            author: engine_author(),
            tier: ProvenanceTier::Inference,
            content_hash: None,
            authorization_basis: None,
        },
        external_refs: Vec::new(),
    }
}

/// The status a superseded finding carries once a re-evaluation over changed
/// inputs replaced it: system-authored, `RuleReEvaluation`, pointing at the
/// replacing finding.
pub fn re_evaluation_supersession(
    replaced_by: FactId,
    superseded_at: Timestamp,
) -> FactStatus {
    FactStatus::Superseded {
        superseded_by: engine_author(),
        superseded_at: TemporalAnchor::Point(superseded_at),
        replaced_by: Some(replaced_by),
        reason: SupersessionReason::RuleReEvaluation,
    }
}
