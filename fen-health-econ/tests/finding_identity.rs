//! Sequencing step 3 of FEN_RECONCILIATION_RULE_ENGINE.md: the deterministic
//! finding-identity contract, pinned with golden values the way the AAD
//! canonicalization is. If any of these assertions changes, what "the same
//! finding" means has changed — that is a durable-contract break, not a
//! refactor.

use fen_health_econ::{
    discrepancy_kind_identity_label, evaluate_reconciliation_rules, finding_fact_id,
    ActiveReconciliationRule, AdjudicationOutcome, AdjudicationPayload, DiscrepancyKind,
    HealthEconFact, HealthEconFactPayload, Money, ProviderBillPayload, ProviderRef,
    ReconciliationRuleDefinition, RuleArtifactRef,
};
use identity_model::{
    Author, AuthorType, AuthorizationBasis, ExternalRef, ExternalSystem, FactId, FactStatus,
    Provenance, ProvenanceTier, SubjectId, TemporalAnchor, Timestamp,
};

const SUBJECT: &str = "subject-billing-defense";

// The golden values below were computed once from the frozen encoding
// (module docs of `fen_health_econ::finding_identity`) and must never
// change for these inputs.
const GOLDEN_PAIR_FINDING_ID: &str =
    "finding-93c4d3edd9c6e31c11f11ed3d14c7c2e65c910bf7d83c743c9e5c7bd73335acb";
const GOLDEN_DENIAL_FINDING_ID: &str =
    "finding-ca0e7bc4e16a7767c18ab12d9a889f1a7fec759e492d1c4b10e8c1ebd48edf9c";

fn subject() -> SubjectId {
    SubjectId::new(SUBJECT)
}

fn ids(values: &[&str]) -> Vec<FactId> {
    values.iter().map(|value| FactId::new(*value)).collect()
}

#[test]
fn golden_finding_fact_ids_are_pinned() {
    assert_eq!(
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
            &DiscrepancyKind::BillVsEobMismatch,
            &ids(&["fact-bill-1", "fact-adj-1"]),
        ),
        FactId::new(GOLDEN_PAIR_FINDING_ID)
    );
    assert_eq!(
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("appealable-denials@v1"),
            &DiscrepancyKind::AppealableDenial,
            &ids(&["fact-adj-1"]),
        ),
        FactId::new(GOLDEN_DENIAL_FINDING_ID)
    );
}

#[test]
fn cited_fact_order_does_not_change_identity() {
    let forward = finding_fact_id(
        &subject(),
        &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
        &DiscrepancyKind::BillVsEobMismatch,
        &ids(&["fact-bill-1", "fact-adj-1"]),
    );
    let reversed = finding_fact_id(
        &subject(),
        &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
        &DiscrepancyKind::BillVsEobMismatch,
        &ids(&["fact-adj-1", "fact-bill-1"]),
    );
    assert_eq!(forward, reversed);
}

#[test]
fn identity_distinguishes_rule_version_kind_inputs_and_subject() {
    let base = finding_fact_id(
        &subject(),
        &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
        &DiscrepancyKind::BillVsEobMismatch,
        &ids(&["fact-bill-1", "fact-adj-1"]),
    );

    // A new rule version over the same inputs is a *new* finding:
    // conclusions are versioned.
    assert_ne!(
        base,
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("eob-bill-reconciliation@v2"),
            &DiscrepancyKind::BillVsEobMismatch,
            &ids(&["fact-bill-1", "fact-adj-1"]),
        )
    );
    // Changed inputs (a corrected bill arrives) produce a new finding.
    assert_ne!(
        base,
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
            &DiscrepancyKind::BillVsEobMismatch,
            &ids(&["fact-bill-2", "fact-adj-1"]),
        )
    );
    // A different mechanism is a different finding.
    assert_ne!(
        base,
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
            &DiscrepancyKind::AboveAllowedAmount,
            &ids(&["fact-bill-1", "fact-adj-1"]),
        )
    );
    // A different subject is a different finding.
    assert_ne!(
        base,
        finding_fact_id(
            &SubjectId::new("subject-other"),
            &RuleArtifactRef::new("eob-bill-reconciliation@v1"),
            &DiscrepancyKind::BillVsEobMismatch,
            &ids(&["fact-bill-1", "fact-adj-1"]),
        )
    );
}

#[test]
fn discrepancy_kind_identity_labels_are_frozen() {
    assert_eq!(
        discrepancy_kind_identity_label(&DiscrepancyKind::BillVsEobMismatch),
        "bill_vs_eob_mismatch"
    );
    assert_eq!(
        discrepancy_kind_identity_label(&DiscrepancyKind::DuplicateCharge),
        "duplicate_charge"
    );
    assert_eq!(
        discrepancy_kind_identity_label(&DiscrepancyKind::AboveAllowedAmount),
        "above_allowed_amount"
    );
    assert_eq!(
        discrepancy_kind_identity_label(&DiscrepancyKind::AppealableDenial),
        "appealable_denial"
    );
    assert_eq!(
        discrepancy_kind_identity_label(&DiscrepancyKind::Other("late-fee".to_string())),
        "other:late-fee"
    );
    // Distinct `Other` labels are distinct identities.
    assert_ne!(
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("custom@v1"),
            &DiscrepancyKind::Other("a".to_string()),
            &ids(&["fact-1"]),
        ),
        finding_fact_id(
            &subject(),
            &RuleArtifactRef::new("custom@v1"),
            &DiscrepancyKind::Other("b".to_string()),
            &ids(&["fact-1"]),
        )
    );
}

// -- The engine's findings carry the same identity ------------------------------

fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test-fixture".to_string()),
        source_document: None,
        imported_at: Timestamp("2026-07-01T00:00:00Z".to_string()),
        author: Author {
            author_type: AuthorType::System,
            author_id: None,
            display_name: None,
        },
        tier: ProvenanceTier::EmployeeUpload,
        content_hash: None,
        authorization_basis: Some(AuthorizationBasis::SelfHeld),
    }
}

fn claim_ref(resource_id: &str) -> ExternalRef {
    ExternalRef {
        system: ExternalSystem::Edi,
        resource_type: Some("Claim".to_string()),
        resource_id: resource_id.to_string(),
        uri: None,
    }
}

fn fact(id: &str, payload: HealthEconFactPayload) -> HealthEconFact {
    HealthEconFact {
        id: FactId::new(id),
        subject_id: subject(),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-06-15T00:00:00Z".to_string())),
        code: None,
        payload,
        status: FactStatus::Active,
        provenance: provenance(),
        external_refs: Vec::new(),
    }
}

#[test]
fn engine_findings_hash_to_the_golden_identity() {
    // The same fixture as the engine's golden hit test: the finding the
    // engine produces must carry exactly the pinned identity.
    let facts = vec![
        fact(
            "fact-bill-1",
            HealthEconFactPayload::ProviderBill(ProviderBillPayload {
                billing_provider: ProviderRef {
                    npi: None,
                    display: None,
                    reference: None,
                },
                related_claim: Some(claim_ref("claim-77")),
                statement_date: None,
                amount_due: Money::new("USD", 12_000),
                collection_status: None,
                cash_pay: false,
            }),
        ),
        fact(
            "fact-adj-1",
            HealthEconFactPayload::Adjudication(AdjudicationPayload {
                claim_ref: claim_ref("claim-77"),
                outcome: AdjudicationOutcome::Paid,
                allowed_amount: None,
                paid_amount: None,
                patient_responsibility: Some(Money::new("USD", 10_000)),
                denial_reason: None,
            }),
        ),
    ];
    let rules = [ActiveReconciliationRule {
        rule_ref: RuleArtifactRef::new("eob-bill-reconciliation@v1"),
        definition: ReconciliationRuleDefinition::BillVsEobMismatch { tolerance: None },
    }];
    let findings = evaluate_reconciliation_rules(
        &rules,
        &facts,
        &Timestamp("2026-07-08T12:00:00Z".to_string()),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].fact_id(), FactId::new(GOLDEN_PAIR_FINDING_ID));
    // Re-evaluation over unchanged inputs reproduces the identical fact ID:
    // idempotence is a property of the identity, before any store is involved.
    let re_evaluated = evaluate_reconciliation_rules(
        &rules,
        &facts,
        &Timestamp("2026-07-09T12:00:00Z".to_string()),
    );
    assert_eq!(re_evaluated[0].fact_id(), findings[0].fact_id());
}
