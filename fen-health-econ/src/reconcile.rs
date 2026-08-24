//! The pure reconciliation rule engine
//! (FEN_RECONCILIATION_RULE_ENGINE.md §C/§E, sequencing step 2).
//!
//! Deterministic, synchronous, no I/O. The engine never sees ciphertext,
//! envelopes, or rows: input is the subject's replayed, policy-gated
//! materialized health-economic facts; output is [`ReconciliationFinding`]
//! values — candidate `BillingDiscrepancy` payloads plus their `DerivedFrom`
//! citing exactly the facts read and the versioned rule that produced them.
//! Findings become facts only by going back through the normal encrypted
//! append path as `Inference`-tier facts (sequencing step 4).
//!
//! Matching is an explicit engine concept, not logic buried inside rule
//! variants: a false positive here is a false accusation against a provider,
//! the one failure mode billing defense cannot afford. Phase 1 pairs a
//! `ProviderBill` with an `Adjudication` **only** on [`FactMatchBasis::SharedClaimRef`],
//! and only when the match is unambiguous (exactly one active adjudication
//! shares the claim ref). Unmatched bills are not discrepancies; surfacing
//! them is a read-model concern, not a rule finding.
//!
//! Determinism contract: output is a pure function of the argument values.
//! Findings are emitted in rule order, then input fact order. Facts that are
//! not `FactStatus::Active` are ignored. Amounts are compared only when
//! currencies agree (including the rule's tolerance currency); anything the
//! engine cannot compare honestly produces no finding — conservative by
//! construction.

use fen_core::time::seconds_between;
use fen_core::{CodingSystem, ExternalRef, FactStatus, SubjectId, Timestamp};

use crate::rules::{ActiveReconciliationRule, ReconciliationRuleDefinition};
use crate::schema::{
    AdjudicationOutcome, AdjudicationPayload, BillingDiscrepancyPayload, ClaimLineItem,
    ClaimPayload, DerivedFrom, DiscrepancyKind, HealthEconFact, HealthEconFactPayload, Money,
    ProviderBillPayload,
};

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Why the engine believed two documents describe the same care (spec §E).
/// Recorded in the finding so every finding can explain not just what
/// disagreed but why the comparison was legitimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactMatchBasis {
    /// Both facts reference the same claim: `ProviderBill.related_claim`
    /// agrees with `Adjudication.claim_ref` (same `ExternalSystem`,
    /// resource type, and resource ID).
    SharedClaimRef,
    // Deferred: ProviderNpiAndServicePeriod, service-code overlap tiers —
    // fuzzy matching needs its own review before it can accuse anyone.
}

/// A candidate `BillingDiscrepancy` produced by rule evaluation. Not yet a
/// fact: it becomes one through the normal encrypted append path
/// (`Inference` tier, sequencing step 4), with deterministic finding
/// identity assigned in sequencing step 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationFinding {
    pub subject_id: SubjectId,
    pub kind: DiscrepancyKind,
    /// What the evidence says the member should owe.
    pub expected: Option<Money>,
    /// What the member is actually being asked to pay.
    pub observed: Option<Money>,
    /// `None` for single-document rules (`AppealableDenial`,
    /// `DuplicateCharge`); `Some` for bill-vs-adjudication comparisons.
    pub match_basis: Option<FactMatchBasis>,
    pub summary: String,
    /// Exactly the facts compared — no more — plus the versioned rule.
    pub derived_from: DerivedFrom,
    pub evaluated_at: Timestamp,
}

impl ReconciliationFinding {
    /// The candidate `BillingDiscrepancy` payload this finding appends as
    /// (sequencing step 4 wires the append itself).
    pub fn to_billing_discrepancy_payload(&self) -> BillingDiscrepancyPayload {
        BillingDiscrepancyPayload {
            kind: self.kind.clone(),
            expected: self.expected.clone(),
            observed: self.observed.clone(),
            summary: Some(self.summary.clone()),
            derived_from: self.derived_from.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Evaluates resolved, active-versioned rules over one subject's
/// materialized facts. Pure: same arguments, same findings, in the same
/// order. `as_of` is recorded on each finding as `evaluated_at`; rule
/// effective-window resolution happens in the store, before this call.
pub fn evaluate_reconciliation_rules(
    rules: &[ActiveReconciliationRule],
    facts: &[HealthEconFact],
    as_of: &Timestamp,
) -> Vec<ReconciliationFinding> {
    let active: Vec<&HealthEconFact> = facts
        .iter()
        .filter(|fact| matches!(fact.status, FactStatus::Active))
        .collect();
    let pairs = shared_claim_ref_pairs(&active);

    let mut findings = Vec::new();
    for rule in rules {
        match &rule.definition {
            ReconciliationRuleDefinition::BillVsEobMismatch { tolerance } => {
                evaluate_bill_vs_eob(rule, tolerance.as_ref(), &pairs, as_of, &mut findings);
            }
            ReconciliationRuleDefinition::AboveAllowedAmount { tolerance } => {
                evaluate_above_allowed(rule, tolerance.as_ref(), &pairs, as_of, &mut findings);
            }
            ReconciliationRuleDefinition::DuplicateCharge { match_window_days } => {
                evaluate_duplicate_charge(rule, *match_window_days, &active, as_of, &mut findings);
            }
            ReconciliationRuleDefinition::AppealableDenial {
                appealable_carc_codes,
            } => {
                evaluate_appealable_denial(rule, appealable_carc_codes, &active, as_of, &mut findings);
            }
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Matching (spec §E)
// ---------------------------------------------------------------------------

struct MatchedPair<'a> {
    bill_fact: &'a HealthEconFact,
    bill: &'a ProviderBillPayload,
    adjudication_fact: &'a HealthEconFact,
    adjudication: &'a AdjudicationPayload,
}

/// Same claim resource: `ExternalSystem`, resource type, and resource ID all
/// agree. `uri` is presentation detail and deliberately ignored.
fn same_claim_resource(left: &ExternalRef, right: &ExternalRef) -> bool {
    left.system == right.system
        && left.resource_type == right.resource_type
        && left.resource_id == right.resource_id
}

/// Unambiguous `SharedClaimRef` pairs. Skipped, and therefore never a
/// finding: bills with no `related_claim` (unmatched), bills whose claim ref
/// matches zero or more than one active adjudication (unmatched/ambiguous),
/// and cash-pay bills (never adjudicated; a "match" would be contradictory
/// evidence, not a comparison).
fn shared_claim_ref_pairs<'a>(active: &[&'a HealthEconFact]) -> Vec<MatchedPair<'a>> {
    let adjudications: Vec<(&HealthEconFact, &AdjudicationPayload)> = active
        .iter()
        .filter_map(|fact| match &fact.payload {
            HealthEconFactPayload::Adjudication(payload) => Some((*fact, payload)),
            _ => None,
        })
        .collect();

    let mut pairs = Vec::new();
    for fact in active {
        let HealthEconFactPayload::ProviderBill(bill) = &fact.payload else {
            continue;
        };
        if bill.cash_pay {
            continue;
        }
        let Some(claim_ref) = &bill.related_claim else {
            continue;
        };
        let matches: Vec<&(&HealthEconFact, &AdjudicationPayload)> = adjudications
            .iter()
            .filter(|(_, adjudication)| same_claim_resource(&adjudication.claim_ref, claim_ref))
            .collect();
        if let [single] = matches.as_slice() {
            let (adjudication_fact, adjudication) = **single;
            pairs.push(MatchedPair {
                bill_fact: *fact,
                bill,
                adjudication_fact,
                adjudication,
            });
        }
    }
    pairs
}

// ---------------------------------------------------------------------------
// Rule evaluators (spec §B)
// ---------------------------------------------------------------------------

fn evaluate_bill_vs_eob(
    rule: &ActiveReconciliationRule,
    tolerance: Option<&Money>,
    pairs: &[MatchedPair<'_>],
    as_of: &Timestamp,
    findings: &mut Vec<ReconciliationFinding>,
) {
    for pair in pairs {
        let Some(patient_responsibility) = &pair.adjudication.patient_responsibility else {
            continue;
        };
        let Some(difference) =
            comparable_difference(patient_responsibility, &pair.bill.amount_due, tolerance)
        else {
            continue;
        };
        if difference.abs() <= tolerance_minor_units(tolerance) {
            continue;
        }
        findings.push(ReconciliationFinding {
            subject_id: pair.bill_fact.subject_id.clone(),
            kind: DiscrepancyKind::BillVsEobMismatch,
            expected: Some(patient_responsibility.clone()),
            observed: Some(pair.bill.amount_due.clone()),
            match_basis: Some(FactMatchBasis::SharedClaimRef),
            summary: format!(
                "provider bill {} asks {} but the matched adjudication {} puts patient \
                 responsibility at {} (shared claim ref {})",
                pair.bill_fact.id.0,
                money_label(&pair.bill.amount_due),
                pair.adjudication_fact.id.0,
                money_label(patient_responsibility),
                pair.adjudication.claim_ref.resource_id,
            ),
            derived_from: pair_derived_from(rule, pair),
            evaluated_at: as_of.clone(),
        });
    }
}

fn evaluate_above_allowed(
    rule: &ActiveReconciliationRule,
    tolerance: Option<&Money>,
    pairs: &[MatchedPair<'_>],
    as_of: &Timestamp,
    findings: &mut Vec<ReconciliationFinding>,
) {
    for pair in pairs {
        let Some(allowed_amount) = &pair.adjudication.allowed_amount else {
            continue;
        };
        let Some(difference) =
            comparable_difference(allowed_amount, &pair.bill.amount_due, tolerance)
        else {
            continue;
        };
        // Directional: only billing *above* allowed is a discrepancy.
        if difference <= tolerance_minor_units(tolerance) {
            continue;
        }
        findings.push(ReconciliationFinding {
            subject_id: pair.bill_fact.subject_id.clone(),
            kind: DiscrepancyKind::AboveAllowedAmount,
            expected: Some(allowed_amount.clone()),
            observed: Some(pair.bill.amount_due.clone()),
            match_basis: Some(FactMatchBasis::SharedClaimRef),
            summary: format!(
                "provider bill {} asks {} which exceeds the matched adjudication {}'s allowed \
                 amount {} (shared claim ref {})",
                pair.bill_fact.id.0,
                money_label(&pair.bill.amount_due),
                pair.adjudication_fact.id.0,
                money_label(allowed_amount),
                pair.adjudication.claim_ref.resource_id,
            ),
            derived_from: pair_derived_from(rule, pair),
            evaluated_at: as_of.clone(),
        });
    }
}

fn evaluate_appealable_denial(
    rule: &ActiveReconciliationRule,
    appealable_carc_codes: &[String],
    active: &[&HealthEconFact],
    as_of: &Timestamp,
    findings: &mut Vec<ReconciliationFinding>,
) {
    for fact in active {
        let HealthEconFactPayload::Adjudication(adjudication) = &fact.payload else {
            continue;
        };
        if adjudication.outcome != AdjudicationOutcome::Denied {
            continue;
        }
        let Some(reason) = &adjudication.denial_reason else {
            continue;
        };
        if reason.system != CodingSystem::Carc
            || !appealable_carc_codes.iter().any(|code| code == &reason.code)
        {
            continue;
        }
        findings.push(ReconciliationFinding {
            subject_id: fact.subject_id.clone(),
            kind: DiscrepancyKind::AppealableDenial,
            expected: None,
            observed: None,
            match_basis: None,
            summary: format!(
                "adjudication {} denied with CARC {} ({}), which is on the reviewed appealable \
                 list",
                fact.id.0, reason.code, reason.display,
            ),
            derived_from: DerivedFrom {
                fact_ids: vec![fact.id.clone()],
                rule_ref: rule.rule_ref.clone(),
                catalog_ref: None,
            },
            evaluated_at: as_of.clone(),
        });
    }
}

fn evaluate_duplicate_charge(
    rule: &ActiveReconciliationRule,
    match_window_days: u32,
    active: &[&HealthEconFact],
    as_of: &Timestamp,
    findings: &mut Vec<ReconciliationFinding>,
) {
    let lines: Vec<(&HealthEconFact, &ClaimPayload, &ClaimLineItem)> = active
        .iter()
        .filter_map(|fact| match &fact.payload {
            HealthEconFactPayload::Claim(claim) => Some((*fact, claim)),
            _ => None,
        })
        .flat_map(|(fact, claim)| claim.line_items.iter().map(move |line| (fact, claim, line)))
        .collect();
    let window_seconds = i64::from(match_window_days) * 86_400;

    for (index, (fact_a, _, line_a)) in lines.iter().enumerate() {
        for (fact_b, _, line_b) in lines.iter().skip(index + 1) {
            let same_fact = fact_a.id == fact_b.id;
            if same_fact && line_a.sequence == line_b.sequence {
                continue; // the same line, not a duplicate of it
            }
            if line_a.service.system != line_b.service.system
                || line_a.service.code != line_b.service.code
            {
                continue;
            }
            let (Some(period_a), Some(period_b)) =
                (&line_a.serviced_period, &line_b.serviced_period)
            else {
                continue; // cannot honestly window undated services
            };
            let Ok(gap) = seconds_between(&period_a.start, &period_b.start) else {
                continue; // unparseable dates: no accusation
            };
            if gap.abs() > window_seconds {
                continue;
            }
            let fact_ids = if same_fact {
                vec![fact_a.id.clone()]
            } else {
                vec![fact_a.id.clone(), fact_b.id.clone()]
            };
            let summary = if same_fact {
                format!(
                    "claim {} bills service {} more than once (lines {} and {}) within {} days",
                    fact_a.id.0, line_a.service.code, line_a.sequence, line_b.sequence,
                    match_window_days,
                )
            } else {
                format!(
                    "service {} billed on claim {} and again on claim {} within {} days",
                    line_a.service.code, fact_a.id.0, fact_b.id.0, match_window_days,
                )
            };
            findings.push(ReconciliationFinding {
                subject_id: fact_a.subject_id.clone(),
                kind: DiscrepancyKind::DuplicateCharge,
                expected: None,
                observed: None,
                match_basis: None,
                summary,
                derived_from: DerivedFrom {
                    fact_ids,
                    rule_ref: rule.rule_ref.clone(),
                    catalog_ref: None,
                },
                evaluated_at: as_of.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Money comparison helpers
// ---------------------------------------------------------------------------

/// `observed - expected` in minor units, or `None` when the comparison
/// cannot be made honestly: currency mismatch between the amounts, or a
/// tolerance whose currency does not match the amounts compared.
fn comparable_difference(
    expected: &Money,
    observed: &Money,
    tolerance: Option<&Money>,
) -> Option<i64> {
    if expected.currency != observed.currency {
        return None;
    }
    if let Some(tolerance) = tolerance {
        if tolerance.currency != expected.currency {
            return None;
        }
    }
    Some(observed.amount_minor_units - expected.amount_minor_units)
}

fn tolerance_minor_units(tolerance: Option<&Money>) -> i64 {
    tolerance.map_or(0, |tolerance| tolerance.amount_minor_units)
}

fn money_label(money: &Money) -> String {
    format!("{} {} (minor units)", money.amount_minor_units, money.currency)
}

fn pair_derived_from(rule: &ActiveReconciliationRule, pair: &MatchedPair<'_>) -> DerivedFrom {
    DerivedFrom {
        // Documented citation order: bill first, adjudication second.
        fact_ids: vec![pair.bill_fact.id.clone(), pair.adjudication_fact.id.clone()],
        rule_ref: rule.rule_ref.clone(),
        catalog_ref: None,
    }
}
