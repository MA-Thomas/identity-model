//! Sequencing step 4 of FEN_RECONCILIATION_RULE_ENGINE.md: findings become
//! facts only through the normal encrypted append path — `Inference`-tier
//! `BillingDiscrepancy` facts with deterministic IDs — and the envelope
//! store's existing duplicate-fact-id rejection makes re-evaluation
//! idempotent for free. Changed inputs produce a new finding that supersedes
//! the old one via `SupersessionReason::RuleReEvaluation`, whose persisted
//! label is pinned here through the authenticated associated data.

use fen_health_econ::{
    evaluate_reconciliation_rules, finding_to_inference_fact, re_evaluation_supersession,
    ActiveReconciliationRule, AdjudicationOutcome, AdjudicationPayload, HealthEconFact,
    HealthEconFactPayload, HealthEconFactPayloadType, HealthEconPayloadFamily, Money,
    ProviderBillPayload, ProviderRef, ReconciliationRuleDefinition, RuleArtifactRef,
};
use identity_model::{
    canonical_encrypted_fact_associated_data_in_family, encrypt_fact_envelope_in_family,
    materialize_encrypted_fact_in_family, AccessDecisionResult, Author, AuthorType,
    AuthorizationBasis, DeterministicTestFactEncryptor, ExternalRef, ExternalSystem,
    FactDataEncryptionKey, FactEncryptionMetadata, FactId, FactStatus,
    InMemoryEncryptedFactEnvelopeRepository, InMemoryEncryptedFactPlaintextCodec,
    PersistenceTransactionId, PolicyEvaluation, PolicyRef, Provenance, ProvenanceTier,
    RepositoryError, SensitiveAction, StaticFactKeyResolver, StoredEncryptedFactEnvelope,
    SubjectId, SupersessionReason, TemporalAnchor, Timestamp,
};

const KEY_ID: &str = "health-econ-fact-key";
const SUBJECT: &str = "subject-billing-defense";

type HealthEconEncryptor =
    DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec<HealthEconFactPayload>>;
type HealthEconEnvelopeRepository =
    InMemoryEncryptedFactEnvelopeRepository<HealthEconFactPayloadType>;

fn encryptor() -> HealthEconEncryptor {
    DeterministicTestFactEncryptor::with_codec(InMemoryEncryptedFactPlaintextCodec::<
        HealthEconFactPayload,
    >::new())
}

fn active_key() -> FactDataEncryptionKey {
    FactDataEncryptionKey::active(KEY_ID, b"test-key-material".to_vec())
}

fn encryption(nonce: &str) -> FactEncryptionMetadata {
    FactEncryptionMetadata::deterministic_test(KEY_ID, nonce.as_bytes().to_vec())
}

fn allowed_policy() -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Allowed,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs: vec![PolicyRef::new("health-econ-materialization-policy@v1")],
    }
}

fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test-fixture".to_string()),
        source_document: None,
        imported_at: ts("2026-07-01T00:00:00Z"),
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

fn input_fact(id: &str, payload: HealthEconFactPayload) -> HealthEconFact {
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

fn provider_bill(id: &str, amount_due: i64) -> HealthEconFact {
    input_fact(
        id,
        HealthEconFactPayload::ProviderBill(ProviderBillPayload {
            billing_provider: ProviderRef {
                npi: None,
                display: None,
                reference: None,
            },
            related_claim: Some(claim_ref("claim-77")),
            statement_date: None,
            amount_due: Money::new("USD", amount_due),
            collection_status: None,
            cash_pay: false,
        }),
    )
}

fn adjudication(id: &str, patient_responsibility: i64) -> HealthEconFact {
    input_fact(
        id,
        HealthEconFactPayload::Adjudication(AdjudicationPayload {
            claim_ref: claim_ref("claim-77"),
            outcome: AdjudicationOutcome::Paid,
            allowed_amount: None,
            paid_amount: None,
            patient_responsibility: Some(Money::new("USD", patient_responsibility)),
            denial_reason: None,
        }),
    )
}

fn rules() -> Vec<ActiveReconciliationRule> {
    vec![ActiveReconciliationRule {
        rule_ref: RuleArtifactRef::new("eob-bill-reconciliation@v1"),
        definition: ReconciliationRuleDefinition::BillVsEobMismatch { tolerance: None },
    }]
}

// The deterministic test codec registers plaintexts at encode time, so each
// test threads one encryptor instance through both encryption and
// materialization (as the encrypted-roundtrip tests do).
fn encrypt(
    fact: &HealthEconFact,
    sequence: u64,
    nonce: &str,
    encryptor: &HealthEconEncryptor,
) -> StoredEncryptedFactEnvelope<HealthEconFactPayloadType> {
    encrypt_fact_envelope_in_family::<HealthEconPayloadFamily>(
        fact,
        sequence,
        PersistenceTransactionId::new("tx-reconciliation-findings"),
        ts("2026-07-08T12:00:01Z"),
        vec![PolicyRef::new("health-econ-materialization-policy@v1")],
        encryption(nonce),
        &active_key(),
        encryptor,
    )
    .expect("finding fact should encrypt")
}

#[test]
fn findings_append_as_inference_facts_and_re_evaluation_dedupes() {
    let inputs = vec![provider_bill("fact-bill-1", 12_000), adjudication("fact-adj-1", 10_000)];
    let as_of = ts("2026-07-08T12:00:00Z");
    let findings = evaluate_reconciliation_rules(&rules(), &inputs, &as_of);
    assert_eq!(findings.len(), 1);

    let inference_fact = finding_to_inference_fact(&findings[0], ts("2026-07-08T12:00:01Z"));
    // The appended fact is a normal Inference-tier fact: deterministic ID,
    // system authorship, DerivedFrom in the payload, no special path.
    assert_eq!(inference_fact.id, findings[0].fact_id());
    assert_eq!(inference_fact.subject_id, SubjectId::new(SUBJECT));
    assert_eq!(inference_fact.provenance.tier, ProvenanceTier::Inference);
    assert_eq!(
        inference_fact.provenance.author.author_type,
        AuthorType::System
    );
    assert_eq!(
        inference_fact.occurred_at,
        TemporalAnchor::Point(as_of.clone())
    );
    let HealthEconFactPayload::BillingDiscrepancy(payload) = &inference_fact.payload else {
        panic!("finding must append as a BillingDiscrepancy payload");
    };
    assert_eq!(payload.derived_from, findings[0].derived_from);

    // Append through the shared envelope store.
    let encryptor = encryptor();
    let mut repository = HealthEconEnvelopeRepository::new();
    let envelope = encrypt(&inference_fact, 1, "nonce-finding-1", &encryptor);
    assert_eq!(
        envelope.payload_type,
        HealthEconFactPayloadType::BillingDiscrepancy
    );
    repository
        .append_encrypted_fact_envelope(envelope.clone())
        .expect("first append should succeed");

    // Re-evaluate over unchanged inputs: identical finding, identical fact
    // ID — the store's existing duplicate-fact-id rejection dedupes the
    // re-append. No migration machinery, no read-before-write.
    let re_evaluated =
        evaluate_reconciliation_rules(&rules(), &inputs, &ts("2026-07-09T12:00:00Z"));
    let re_appended = finding_to_inference_fact(&re_evaluated[0], ts("2026-07-09T12:00:01Z"));
    assert_eq!(re_appended.id, inference_fact.id);
    assert!(matches!(
        repository.append_encrypted_fact_envelope(encrypt(
            &re_appended,
            2,
            "nonce-finding-2",
            &encryptor
        )),
        Err(RepositoryError::DuplicateFactId)
    ));

    // The stored finding materializes back through the policy gate intact.
    let stored = repository.encrypted_fact_envelopes_for_subject(&SubjectId::new(SUBJECT));
    assert_eq!(stored.len(), 1);
    let materialized = materialize_encrypted_fact_in_family::<HealthEconPayloadFamily>(
        &stored[0],
        &allowed_policy(),
        &StaticFactKeyResolver::from_keys([active_key()]),
        &encryptor,
    )
    .expect("authorized finding should materialize");
    assert_eq!(materialized, inference_fact);
}

#[test]
fn corrected_inputs_produce_a_superseding_finding() {
    let as_of = ts("2026-07-08T12:00:00Z");
    let encryptor = encryptor();
    let mut repository = HealthEconEnvelopeRepository::new();

    // First evaluation: the original bill disagrees with the EOB.
    let original_inputs =
        vec![provider_bill("fact-bill-1", 12_000), adjudication("fact-adj-1", 10_000)];
    let original_findings = evaluate_reconciliation_rules(&rules(), &original_inputs, &as_of);
    let original_fact = finding_to_inference_fact(&original_findings[0], ts("2026-07-08T12:00:01Z"));
    repository
        .append_encrypted_fact_envelope(encrypt(&original_fact, 1, "nonce-original", &encryptor))
        .expect("original finding should append");

    // A corrected bill arrives as a new fact (the old bill is superseded in
    // its own right); re-evaluation reads the corrected graph.
    let corrected_inputs =
        vec![provider_bill("fact-bill-2", 13_000), adjudication("fact-adj-1", 10_000)];
    let corrected_findings = evaluate_reconciliation_rules(&rules(), &corrected_inputs, &as_of);
    let corrected_fact =
        finding_to_inference_fact(&corrected_findings[0], ts("2026-07-10T12:00:01Z"));

    // Changed inputs → new identity → a normal append, not a duplicate.
    assert_ne!(corrected_fact.id, original_fact.id);
    repository
        .append_encrypted_fact_envelope(encrypt(&corrected_fact, 2, "nonce-corrected", &encryptor))
        .expect("corrected finding should append");

    // The old finding is superseded by rule re-evaluation. The status is
    // typed, system-authored, and points at the replacing finding.
    let supersession =
        re_evaluation_supersession(corrected_fact.id.clone(), ts("2026-07-10T12:00:01Z"));
    let FactStatus::Superseded {
        ref superseded_by,
        ref replaced_by,
        ref reason,
        ..
    } = supersession
    else {
        panic!("re-evaluation supersession must be FactStatus::Superseded");
    };
    assert_eq!(superseded_by.author_type, AuthorType::System);
    assert_eq!(replaced_by.as_ref(), Some(&corrected_fact.id));
    assert_eq!(*reason, SupersessionReason::RuleReEvaluation);

    // The superseded status travels with the fact through the append path,
    // inside the authenticated associated data. This pins the persisted
    // `rule_re_evaluation` label the same way the AAD golden checks pin the
    // payload-type labels. (A stored envelope's status is part of its AAD
    // and is never mutated in place; the refreshed fact is written by the
    // re-evaluation's own transaction.)
    let mut superseded_fact = original_fact.clone();
    superseded_fact.status = supersession;
    let superseded_envelope = encrypt(&superseded_fact, 3, "nonce-superseded", &encryptor);
    let associated_data = String::from_utf8(
        canonical_encrypted_fact_associated_data_in_family::<HealthEconPayloadFamily>(
            &superseded_envelope,
        ),
    )
    .expect("associated data should be utf-8 labels");
    assert!(associated_data.contains("reason=18:rule_re_evaluation"));
    assert!(associated_data.contains("payload_type=31:health_econ.billing_discrepancy"));
}
