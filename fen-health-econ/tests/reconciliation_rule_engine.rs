//! Sequencing step 2 of FEN_RECONCILIATION_RULE_ENGINE.md: golden fixtures
//! for the pure engine — per rule variant a hit, a miss, a tolerance edge,
//! and the unmatched-bill non-finding, plus the matching conservatism the
//! spec makes explicit (ambiguous matches, cash-pay bills, superseded facts
//! never produce findings). Fixtures in, findings out: the engine is a pure
//! function and these tests exercise it with no store, no I/O, no envelope.

use fen_health_econ::{
    evaluate_reconciliation_rules, ActiveReconciliationRule, AdjudicationOutcome,
    AdjudicationPayload, ClaimLineItem, ClaimPayload, ClaimType, DiscrepancyKind, FactMatchBasis,
    HealthEconFact, HealthEconFactPayload, Money, ProviderBillPayload, ProviderRef,
    ReconciliationRuleDefinition, RuleArtifactRef,
};
use identity_model::{
    Author, AuthorType, AuthorizationBasis, CodedValue, CodingSystem, ExternalRef, ExternalSystem,
    FactId, FactStatus, Provenance, ProvenanceTier, SubjectId, SupersessionReason, TemporalAnchor,
    TimeInterval, Timestamp,
};

const SUBJECT: &str = "subject-billing-defense";
const AS_OF: &str = "2026-07-08T12:00:00Z";

// -- Fixture builders ---------------------------------------------------------

fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

fn as_of() -> Timestamp {
    ts(AS_OF)
}

fn usd(amount_minor_units: i64) -> Money {
    Money::new("USD", amount_minor_units)
}

fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test-fixture".to_string()),
        source_document: None,
        imported_at: ts("2026-07-01T00:00:00Z"),
        author: Author {
            author_type: AuthorType::System,
            author_id: None,
            display_name: Some("fixtures".to_string()),
        },
        tier: ProvenanceTier::EmployeeUpload,
        content_hash: None,
        authorization_basis: Some(AuthorizationBasis::SelfHeld),
    }
}

fn fact(id: &str, payload: HealthEconFactPayload) -> HealthEconFact {
    HealthEconFact {
        id: FactId::new(id),
        subject_id: SubjectId::new(SUBJECT),
        occurred_at: TemporalAnchor::Point(ts("2026-06-15T00:00:00Z")),
        code: None,
        payload,
        status: FactStatus::Active,
        provenance: provenance(),
        external_refs: Vec::new(),
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

fn provider_bill(id: &str, related_claim: Option<&str>, amount_due: Money) -> HealthEconFact {
    fact(
        id,
        HealthEconFactPayload::ProviderBill(ProviderBillPayload {
            billing_provider: ProviderRef {
                npi: Some("1234567890".to_string()),
                display: Some("Example Medical Group".to_string()),
                reference: None,
            },
            related_claim: related_claim.map(claim_ref),
            statement_date: None,
            amount_due,
            collection_status: None,
            cash_pay: false,
        }),
    )
}

fn adjudication(
    id: &str,
    claim: &str,
    outcome: AdjudicationOutcome,
    allowed_amount: Option<Money>,
    patient_responsibility: Option<Money>,
    denial_reason: Option<CodedValue>,
) -> HealthEconFact {
    fact(
        id,
        HealthEconFactPayload::Adjudication(AdjudicationPayload {
            claim_ref: claim_ref(claim),
            outcome,
            allowed_amount,
            paid_amount: None,
            patient_responsibility,
            denial_reason,
        }),
    )
}

fn claim_with_lines(id: &str, lines: &[(u32, &str, &str)]) -> HealthEconFact {
    // (sequence, service code, serviced date)
    fact(
        id,
        HealthEconFactPayload::Claim(ClaimPayload {
            claim_type: ClaimType::Professional,
            billable_period: None,
            billing_provider: None,
            diagnoses: Vec::new(),
            line_items: lines
                .iter()
                .map(|(sequence, code, date)| ClaimLineItem {
                    sequence: *sequence,
                    service: CodedValue {
                        system: CodingSystem::Cpt,
                        code: (*code).to_string(),
                        display: format!("service {code}"),
                    },
                    serviced_period: Some(TimeInterval {
                        start: ts(&format!("{date}T00:00:00Z")),
                        end: ts(&format!("{date}T00:00:00Z")),
                    }),
                    quantity: Some(1),
                    charge: None,
                })
                .collect(),
            total_charge: None,
        }),
    )
}

fn rule(id_at_version: &str, definition: ReconciliationRuleDefinition) -> ActiveReconciliationRule {
    ActiveReconciliationRule {
        rule_ref: RuleArtifactRef::new(id_at_version),
        definition,
    }
}

fn bill_vs_eob_rule(tolerance_minor_units: Option<i64>) -> ActiveReconciliationRule {
    rule(
        "eob-bill-reconciliation@v1",
        ReconciliationRuleDefinition::BillVsEobMismatch {
            tolerance: tolerance_minor_units.map(usd),
        },
    )
}

fn above_allowed_rule(tolerance_minor_units: Option<i64>) -> ActiveReconciliationRule {
    rule(
        "above-allowed-amount@v1",
        ReconciliationRuleDefinition::AboveAllowedAmount {
            tolerance: tolerance_minor_units.map(usd),
        },
    )
}

fn duplicate_charge_rule(match_window_days: u32) -> ActiveReconciliationRule {
    rule(
        "duplicate-charge@v1",
        ReconciliationRuleDefinition::DuplicateCharge { match_window_days },
    )
}

fn appealable_denial_rule(codes: &[&str]) -> ActiveReconciliationRule {
    rule(
        "appealable-denials@v1",
        ReconciliationRuleDefinition::AppealableDenial {
            appealable_carc_codes: codes.iter().map(|code| code.to_string()).collect(),
        },
    )
}

fn carc(code: &str) -> CodedValue {
    CodedValue {
        system: CodingSystem::Carc,
        code: code.to_string(),
        display: format!("CARC {code}"),
    }
}

// -- BillVsEobMismatch ---------------------------------------------------------

#[test]
fn bill_vs_eob_mismatch_hit() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), usd(12_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            Some(usd(20_000)),
            Some(usd(10_000)),
            None,
        ),
    ];
    let findings = evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of());

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.subject_id, SubjectId::new(SUBJECT));
    assert_eq!(finding.kind, DiscrepancyKind::BillVsEobMismatch);
    assert_eq!(finding.expected, Some(usd(10_000)));
    assert_eq!(finding.observed, Some(usd(12_000)));
    assert_eq!(finding.match_basis, Some(FactMatchBasis::SharedClaimRef));
    assert_eq!(finding.evaluated_at, as_of());
    // DerivedFrom cites exactly the facts compared — bill first, adjudication
    // second — and the versioned rule.
    assert_eq!(
        finding.derived_from.fact_ids,
        vec![FactId::new("fact-bill-1"), FactId::new("fact-adj-1")]
    );
    assert_eq!(
        finding.derived_from.rule_ref,
        RuleArtifactRef::new("eob-bill-reconciliation@v1")
    );
    assert_eq!(finding.derived_from.catalog_ref, None);
    // The summary explains the disagreement and the match.
    assert!(finding.summary.contains("fact-bill-1"));
    assert!(finding.summary.contains("fact-adj-1"));
    assert!(finding.summary.contains("claim-77"));

    // Candidate payload conversion carries the full audit chain.
    let payload = finding.to_billing_discrepancy_payload();
    assert_eq!(payload.kind, DiscrepancyKind::BillVsEobMismatch);
    assert_eq!(payload.derived_from, finding.derived_from);
    assert_eq!(payload.summary.as_deref(), Some(finding.summary.as_str()));
}

#[test]
fn bill_vs_eob_agreeing_amounts_are_not_a_finding() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), usd(10_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
    ];
    let findings = evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of());
    assert!(findings.is_empty());
}

#[test]
fn bill_vs_eob_tolerance_edge() {
    let facts = |due: i64| {
        vec![
            provider_bill("fact-bill-1", Some("claim-77"), usd(due)),
            adjudication(
                "fact-adj-1",
                "claim-77",
                AdjudicationOutcome::Paid,
                None,
                Some(usd(10_000)),
                None,
            ),
        ]
    };
    let rule = bill_vs_eob_rule(Some(100));
    // Exactly at tolerance: no finding.
    assert!(
        evaluate_reconciliation_rules(&[rule.clone()], &facts(10_100), &as_of()).is_empty()
    );
    // One minor unit beyond: finding. Symmetric in both directions.
    assert_eq!(
        evaluate_reconciliation_rules(&[rule.clone()], &facts(10_101), &as_of()).len(),
        1
    );
    assert!(
        evaluate_reconciliation_rules(&[rule.clone()], &facts(9_900), &as_of()).is_empty()
    );
    assert_eq!(
        evaluate_reconciliation_rules(&[rule], &facts(9_899), &as_of()).len(),
        1
    );
}

#[test]
fn currency_mismatch_is_not_compared() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), Money::new("EUR", 12_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
    ];
    // The engine cannot honestly compare across currencies: no finding.
    assert!(
        evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of()).is_empty()
    );
}

// -- Matching conservatism (spec §E) --------------------------------------------

#[test]
fn unmatched_bill_is_not_a_finding() {
    let facts = vec![
        // No related claim at all.
        provider_bill("fact-bill-1", None, usd(12_000)),
        // Related claim with no adjudication in hand.
        provider_bill("fact-bill-2", Some("claim-unseen"), usd(12_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
    ];
    let findings = evaluate_reconciliation_rules(
        &[bill_vs_eob_rule(None), above_allowed_rule(None)],
        &facts,
        &as_of(),
    );
    // Unmatched bills are simply unmatched — a read-model concern, never a
    // discrepancy.
    assert!(findings.is_empty());
}

#[test]
fn ambiguous_claim_match_is_not_a_finding() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), usd(12_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
        adjudication(
            "fact-adj-2",
            "claim-77",
            AdjudicationOutcome::Partial,
            None,
            Some(usd(11_000)),
            None,
        ),
    ];
    // Two active adjudications share the claim ref: the pairing is ambiguous
    // and the engine must not guess which one to accuse the provider with.
    assert!(
        evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of()).is_empty()
    );
}

#[test]
fn cash_pay_bills_are_never_paired() {
    let mut bill = provider_bill("fact-bill-1", Some("claim-77"), usd(12_000));
    if let HealthEconFactPayload::ProviderBill(payload) = &mut bill.payload {
        payload.cash_pay = true;
    }
    let facts = vec![
        bill,
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
    ];
    assert!(
        evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of()).is_empty()
    );
}

#[test]
fn superseded_facts_are_ignored() {
    let mut old_bill = provider_bill("fact-bill-old", Some("claim-77"), usd(15_000));
    old_bill.status = FactStatus::Superseded {
        superseded_by: Author {
            author_type: AuthorType::System,
            author_id: None,
            display_name: None,
        },
        superseded_at: TemporalAnchor::Point(ts("2026-07-01T00:00:00Z")),
        replaced_by: Some(FactId::new("fact-bill-new")),
        reason: SupersessionReason::AdministrativeCorrection,
    };
    let facts = vec![
        old_bill,
        provider_bill("fact-bill-new", Some("claim-77"), usd(10_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            None,
            Some(usd(10_000)),
            None,
        ),
    ];
    // The superseded bill would have produced a mismatch; the corrected bill
    // agrees. Only active facts are evaluated: no findings.
    assert!(
        evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &facts, &as_of()).is_empty()
    );
}

// -- AboveAllowedAmount ----------------------------------------------------------

#[test]
fn above_allowed_amount_hit() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), usd(25_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Paid,
            Some(usd(20_000)),
            None,
            None,
        ),
    ];
    let findings =
        evaluate_reconciliation_rules(&[above_allowed_rule(None)], &facts, &as_of());
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.kind, DiscrepancyKind::AboveAllowedAmount);
    assert_eq!(finding.expected, Some(usd(20_000)));
    assert_eq!(finding.observed, Some(usd(25_000)));
    assert_eq!(finding.match_basis, Some(FactMatchBasis::SharedClaimRef));
    assert_eq!(
        finding.derived_from.fact_ids,
        vec![FactId::new("fact-bill-1"), FactId::new("fact-adj-1")]
    );
    assert_eq!(
        finding.derived_from.rule_ref,
        RuleArtifactRef::new("above-allowed-amount@v1")
    );
}

#[test]
fn billing_at_or_below_allowed_is_not_a_finding() {
    let facts = |due: i64| {
        vec![
            provider_bill("fact-bill-1", Some("claim-77"), usd(due)),
            adjudication(
                "fact-adj-1",
                "claim-77",
                AdjudicationOutcome::Paid,
                Some(usd(20_000)),
                None,
                None,
            ),
        ]
    };
    let rule = above_allowed_rule(Some(100));
    // Below, at allowed, and at allowed + tolerance: no finding. The rule is
    // directional — billing under allowed is not a discrepancy.
    assert!(evaluate_reconciliation_rules(&[rule.clone()], &facts(15_000), &as_of()).is_empty());
    assert!(evaluate_reconciliation_rules(&[rule.clone()], &facts(20_000), &as_of()).is_empty());
    assert!(evaluate_reconciliation_rules(&[rule.clone()], &facts(20_100), &as_of()).is_empty());
    // One minor unit beyond tolerance: finding.
    assert_eq!(
        evaluate_reconciliation_rules(&[rule], &facts(20_101), &as_of()).len(),
        1
    );
}

// -- DuplicateCharge --------------------------------------------------------------

#[test]
fn duplicate_charge_across_claims_within_window_hit() {
    let facts = vec![
        claim_with_lines("fact-claim-1", &[(1, "99213", "2026-06-10")]),
        claim_with_lines("fact-claim-2", &[(1, "99213", "2026-06-12")]),
    ];
    let findings =
        evaluate_reconciliation_rules(&[duplicate_charge_rule(7)], &facts, &as_of());
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.kind, DiscrepancyKind::DuplicateCharge);
    assert_eq!(finding.expected, None);
    assert_eq!(finding.observed, None);
    // Single-document family rule: no bill/adjudication match basis.
    assert_eq!(finding.match_basis, None);
    assert_eq!(
        finding.derived_from.fact_ids,
        vec![FactId::new("fact-claim-1"), FactId::new("fact-claim-2")]
    );
    assert_eq!(
        finding.derived_from.rule_ref,
        RuleArtifactRef::new("duplicate-charge@v1")
    );
    assert!(finding.summary.contains("99213"));
}

#[test]
fn duplicate_charge_within_one_claim_cites_the_fact_once() {
    let facts = vec![claim_with_lines(
        "fact-claim-1",
        &[(1, "99213", "2026-06-10"), (2, "99213", "2026-06-10")],
    )];
    let findings =
        evaluate_reconciliation_rules(&[duplicate_charge_rule(7)], &facts, &as_of());
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].derived_from.fact_ids,
        vec![FactId::new("fact-claim-1")]
    );
}

#[test]
fn duplicate_charge_misses() {
    // Different service codes: no finding.
    let different_codes = vec![
        claim_with_lines("fact-claim-1", &[(1, "99213", "2026-06-10")]),
        claim_with_lines("fact-claim-2", &[(1, "99214", "2026-06-10")]),
    ];
    assert!(evaluate_reconciliation_rules(
        &[duplicate_charge_rule(7)],
        &different_codes,
        &as_of()
    )
    .is_empty());

    // Same code outside the window: no finding.
    let outside_window = vec![
        claim_with_lines("fact-claim-1", &[(1, "99213", "2026-06-01")]),
        claim_with_lines("fact-claim-2", &[(1, "99213", "2026-06-20")]),
    ];
    assert!(evaluate_reconciliation_rules(
        &[duplicate_charge_rule(7)],
        &outside_window,
        &as_of()
    )
    .is_empty());
}

#[test]
fn duplicate_charge_window_edge() {
    let facts = |second_date: &str| {
        vec![
            claim_with_lines("fact-claim-1", &[(1, "99213", "2026-06-10")]),
            claim_with_lines("fact-claim-2", &[(1, "99213", second_date)]),
        ]
    };
    // Exactly 7 days apart with a 7-day window: inside (closed window).
    assert_eq!(
        evaluate_reconciliation_rules(&[duplicate_charge_rule(7)], &facts("2026-06-17"), &as_of())
            .len(),
        1
    );
    // 8 days apart: outside.
    assert!(evaluate_reconciliation_rules(
        &[duplicate_charge_rule(7)],
        &facts("2026-06-18"),
        &as_of()
    )
    .is_empty());
}

#[test]
fn undated_services_are_never_flagged_as_duplicates() {
    let mut claim = claim_with_lines(
        "fact-claim-1",
        &[(1, "99213", "2026-06-10"), (2, "99213", "2026-06-10")],
    );
    if let HealthEconFactPayload::Claim(payload) = &mut claim.payload {
        for line in &mut payload.line_items {
            line.serviced_period = None;
        }
    }
    // The engine cannot honestly window undated services: no accusation.
    assert!(
        evaluate_reconciliation_rules(&[duplicate_charge_rule(7)], &[claim], &as_of()).is_empty()
    );
}

// -- AppealableDenial --------------------------------------------------------------

#[test]
fn appealable_denial_hit() {
    let facts = vec![adjudication(
        "fact-adj-1",
        "claim-77",
        AdjudicationOutcome::Denied,
        None,
        None,
        Some(carc("197")),
    )];
    let findings = evaluate_reconciliation_rules(
        &[appealable_denial_rule(&["50", "197"])],
        &facts,
        &as_of(),
    );
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.kind, DiscrepancyKind::AppealableDenial);
    assert_eq!(finding.expected, None);
    assert_eq!(finding.observed, None);
    assert_eq!(finding.match_basis, None);
    assert_eq!(finding.derived_from.fact_ids, vec![FactId::new("fact-adj-1")]);
    assert_eq!(
        finding.derived_from.rule_ref,
        RuleArtifactRef::new("appealable-denials@v1")
    );
    assert!(finding.summary.contains("197"));
}

#[test]
fn appealable_denial_misses() {
    let rule = appealable_denial_rule(&["50", "197"]);

    // CARC code not on the reviewed list.
    let off_list = vec![adjudication(
        "fact-adj-1",
        "claim-77",
        AdjudicationOutcome::Denied,
        None,
        None,
        Some(carc("45")),
    )];
    assert!(evaluate_reconciliation_rules(&[rule.clone()], &off_list, &as_of()).is_empty());

    // Same code string but not a CARC coding system.
    let wrong_system = vec![adjudication(
        "fact-adj-2",
        "claim-78",
        AdjudicationOutcome::Denied,
        None,
        None,
        Some(CodedValue {
            system: CodingSystem::Local,
            code: "197".to_string(),
            display: "local 197".to_string(),
        }),
    )];
    assert!(evaluate_reconciliation_rules(&[rule.clone()], &wrong_system, &as_of()).is_empty());

    // Listed code on a non-denied adjudication.
    let not_denied = vec![adjudication(
        "fact-adj-3",
        "claim-79",
        AdjudicationOutcome::Partial,
        None,
        None,
        Some(carc("197")),
    )];
    assert!(evaluate_reconciliation_rules(&[rule], &not_denied, &as_of()).is_empty());
}

// -- Engine-wide behavior -------------------------------------------------------

#[test]
fn evaluation_is_deterministic_and_ordered_by_rule_then_fact() {
    let facts = vec![
        provider_bill("fact-bill-1", Some("claim-77"), usd(12_000)),
        adjudication(
            "fact-adj-1",
            "claim-77",
            AdjudicationOutcome::Denied,
            Some(usd(9_000)),
            Some(usd(10_000)),
            Some(carc("197")),
        ),
    ];
    let rules = vec![
        appealable_denial_rule(&["197"]),
        bill_vs_eob_rule(None),
        above_allowed_rule(None),
    ];

    let first = evaluate_reconciliation_rules(&rules, &facts, &as_of());
    let second = evaluate_reconciliation_rules(&rules, &facts, &as_of());
    // Pure function: same inputs, same findings, same order.
    assert_eq!(first, second);

    // Findings arrive in rule order.
    assert_eq!(
        first
            .iter()
            .map(|finding| finding.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            DiscrepancyKind::AppealableDenial,
            DiscrepancyKind::BillVsEobMismatch,
            DiscrepancyKind::AboveAllowedAmount,
        ]
    );
    // Every finding cites its own rule version.
    assert_eq!(
        first
            .iter()
            .map(|finding| finding.derived_from.rule_ref.0.as_str())
            .collect::<Vec<_>>(),
        vec![
            "appealable-denials@v1",
            "eob-bill-reconciliation@v1",
            "above-allowed-amount@v1",
        ]
    );
}

#[test]
fn no_rules_no_findings() {
    let facts = vec![provider_bill("fact-bill-1", Some("claim-77"), usd(12_000))];
    assert!(evaluate_reconciliation_rules(&[], &facts, &as_of()).is_empty());
    assert!(evaluate_reconciliation_rules(&[bill_vs_eob_rule(None)], &[], &as_of()).is_empty());
}
