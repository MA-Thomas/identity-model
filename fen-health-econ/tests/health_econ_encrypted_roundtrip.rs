//! Append/replay health-economic facts through the *existing* in-memory
//! encrypted facade, proving the health-economic [`PayloadFamily`] reuses the
//! shared envelope store without a schema fork
//! (FEN_HEALTH_ECON_EXTENSIONS.md).

use fen_core::{
    Author, AuthorType, AuthorizationBasis, CodedValue, CodingSystem, ExternalRef, ExternalSystem,
    FactId, FactStatus, PolicyRef, Provenance, ProvenanceTier, SubjectId, TemporalAnchor,
    TimeInterval, Timestamp,
};
use fen_health_econ::{
    BillingDiscrepancyPayload, ClaimLineItem, ClaimPayload, ClaimType, DerivedFrom,
    DiscrepancyKind, HealthEconFact, HealthEconFactPayload, HealthEconFactPayloadType,
    HealthEconPayloadFamily, Money, ProviderRef, RecordRequestPayload, RequestedDocument,
    RuleArtifactRef,
};
use fen_store::{
    canonical_encrypted_fact_associated_data_in_family, encrypt_fact_envelope_in_family,
    materialize_encrypted_fact_in_family, materialize_encrypted_facts_in_family,
    DeterministicTestFactEncryptor, FactDataEncryptionKey, FactEncryptionMetadata,
    FactMaterializationError, InMemoryEncryptedFactPlaintextCodec, MaterializationAuthorization,
    PersistenceTransactionId, StaticFactKeyResolver,
};

const KEY_ID: &str = "health-econ-fact-key";
const SUBJECT: &str = "subject-billing-defense";

type HealthEconEncryptor =
    DeterministicTestFactEncryptor<InMemoryEncryptedFactPlaintextCodec<HealthEconFactPayload>>;

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

fn policy_refs() -> Vec<PolicyRef> {
    vec![PolicyRef::new("health-econ-materialization-policy@v1")]
}

fn allowed_policy() -> MaterializationAuthorization {
    MaterializationAuthorization::authorized(policy_refs())
}

fn denied_policy() -> MaterializationAuthorization {
    MaterializationAuthorization::denied(policy_refs())
}

fn provenance(tier: ProvenanceTier) -> Provenance {
    Provenance {
        source_system: Some("bluebutton-sandbox".to_string()),
        source_document: None,
        imported_at: Timestamp("2026-07-08T00:00:00Z".to_string()),
        author: Author {
            author_type: AuthorType::System,
            author_id: None,
            display_name: Some("claims-sync".to_string()),
        },
        tier,
        content_hash: None,
        authorization_basis: Some(AuthorizationBasis::HipaaRightOfAccess),
    }
}

fn icd10(code: &str, display: &str) -> CodedValue {
    CodedValue {
        system: CodingSystem::Icd10,
        code: code.to_string(),
        display: display.to_string(),
    }
}

fn day(date: &str) -> TimeInterval {
    TimeInterval {
        start: Timestamp(format!("{date}T00:00:00Z")),
        end: Timestamp(format!("{date}T23:59:59Z")),
    }
}

fn claim_fact() -> HealthEconFact {
    HealthEconFact {
        id: FactId::new("health-econ-claim-1"),
        subject_id: SubjectId::new(SUBJECT),
        occurred_at: TemporalAnchor::Period(day("2026-03-01")),
        code: Some(icd10("C50.911", "Malignant neoplasm of breast")),
        payload: HealthEconFactPayload::Claim(ClaimPayload {
            claim_type: ClaimType::Professional,
            billable_period: Some(day("2026-03-01")),
            billing_provider: Some(ProviderRef {
                npi: Some("1234567890".to_string()),
                display: Some("Example Oncology".to_string()),
                reference: None,
            }),
            diagnoses: vec![icd10("C50.911", "Malignant neoplasm of breast")],
            line_items: vec![ClaimLineItem {
                sequence: 1,
                service: CodedValue {
                    system: CodingSystem::Cpt,
                    code: "96413".to_string(),
                    display: "Chemotherapy administration".to_string(),
                },
                serviced_period: Some(day("2026-03-01")),
                quantity: Some(1),
                charge: Some(Money::new("USD", 250_000)),
            }],
            total_charge: Some(Money::new("USD", 250_000)),
        }),
        status: FactStatus::Active,
        provenance: provenance(ProvenanceTier::ApiSourced),
        external_refs: vec![ExternalRef {
            system: ExternalSystem::Fhir,
            resource_type: Some("ExplanationOfBenefit".to_string()),
            resource_id: "eob-1".to_string(),
            uri: None,
        }],
    }
}

fn record_request_fact() -> HealthEconFact {
    HealthEconFact {
        id: FactId::new("health-econ-record-request-1"),
        subject_id: SubjectId::new(SUBJECT),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-03-05T12:00:00Z".to_string())),
        code: None,
        payload: HealthEconFactPayload::RecordRequest(RecordRequestPayload {
            target_provider: ProviderRef {
                npi: Some("1234567890".to_string()),
                display: Some("Example Oncology".to_string()),
                reference: None,
            },
            requested_document: RequestedDocument::ItemizedBill,
            reason: Some("EOB patient responsibility disagrees with statement".to_string()),
            requested_period: Some(day("2026-03-01")),
        }),
        status: FactStatus::Active,
        provenance: provenance(ProvenanceTier::EmployeeUpload),
        external_refs: Vec::new(),
    }
}

/// An `Inference`-tier reconciliation finding carrying `DerivedFrom`:
/// provenance for conclusions (FEN_HEALTH_ECON_EXTENSIONS.md C).
fn discrepancy_fact() -> HealthEconFact {
    HealthEconFact {
        id: FactId::new("health-econ-discrepancy-1"),
        subject_id: SubjectId::new(SUBJECT),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-03-06T09:00:00Z".to_string())),
        code: None,
        payload: HealthEconFactPayload::BillingDiscrepancy(BillingDiscrepancyPayload {
            kind: DiscrepancyKind::BillVsEobMismatch,
            expected: Some(Money::new("USD", 40_000)),
            observed: Some(Money::new("USD", 62_500)),
            summary: Some("Statement exceeds EOB patient responsibility".to_string()),
            derived_from: DerivedFrom {
                fact_ids: vec![
                    FactId::new("health-econ-claim-1"),
                    FactId::new("health-econ-provider-bill-1"),
                ],
                rule_ref: RuleArtifactRef::new("eob-bill-reconciliation@v1"),
                catalog_ref: None,
            },
        }),
        status: FactStatus::Active,
        provenance: provenance(ProvenanceTier::Inference),
        external_refs: Vec::new(),
    }
}

#[test]
fn health_econ_claim_round_trips_through_shared_encrypted_facade() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = encryptor();
    let fact = claim_fact();

    let envelope = encrypt_fact_envelope_in_family::<HealthEconPayloadFamily>(
        &fact,
        1,
        PersistenceTransactionId::new("tx-health-econ-claim"),
        Timestamp("2026-07-08T00:00:01Z".to_string()),
        policy_refs(),
        encryption("nonce-health-econ-claim"),
        &key,
        &encryptor,
    )
    .expect("health-econ claim should encrypt");

    assert_eq!(envelope.fact_id, fact.id);
    assert_eq!(envelope.subject_id, fact.subject_id);
    assert_eq!(envelope.payload_type, HealthEconFactPayloadType::Claim);
    assert!(!envelope.ciphertext.is_empty());

    let materialized = materialize_encrypted_fact_in_family::<HealthEconPayloadFamily>(
        &envelope,
        &allowed_policy(),
        &resolver,
        &encryptor,
    )
    .expect("authorized health-econ claim should decrypt");
    assert_eq!(materialized, fact);

    let associated_data = String::from_utf8(canonical_encrypted_fact_associated_data_in_family::<
        HealthEconPayloadFamily,
    >(&envelope))
    .expect("associated data should be utf-8 labels");
    assert!(associated_data.contains("profile=18:fen-encrypted-fact"));
    assert!(associated_data.contains("payload_type=17:health_econ.claim"));
}

#[test]
fn health_econ_facts_batch_replays_and_preserves_payload_types() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = encryptor();
    let facts = [claim_fact(), record_request_fact(), discrepancy_fact()];

    let envelopes: Vec<_> = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| {
            encrypt_fact_envelope_in_family::<HealthEconPayloadFamily>(
                fact,
                index as u64 + 1,
                PersistenceTransactionId::new("tx-health-econ-batch"),
                Timestamp("2026-07-08T00:00:01Z".to_string()),
                policy_refs(),
                encryption(&format!("nonce-health-econ-batch-{index}")),
                &key,
                &encryptor,
            )
            .expect("health-econ fact should encrypt")
        })
        .collect();

    assert_eq!(envelopes[0].payload_type, HealthEconFactPayloadType::Claim);
    assert_eq!(
        envelopes[1].payload_type,
        HealthEconFactPayloadType::RecordRequest
    );
    assert_eq!(
        envelopes[2].payload_type,
        HealthEconFactPayloadType::BillingDiscrepancy
    );

    let materialized = materialize_encrypted_facts_in_family::<HealthEconPayloadFamily>(
        &envelopes,
        &allowed_policy(),
        &resolver,
        &encryptor,
    )
    .expect("authorized health-econ facts should decrypt");
    assert_eq!(materialized, facts.to_vec());
}

#[test]
fn health_econ_materialization_is_policy_gated_and_context_authenticated() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = encryptor();
    let fact = claim_fact();

    let envelope = encrypt_fact_envelope_in_family::<HealthEconPayloadFamily>(
        &fact,
        1,
        PersistenceTransactionId::new("tx-health-econ-guard"),
        Timestamp("2026-07-08T00:00:01Z".to_string()),
        policy_refs(),
        encryption("nonce-health-econ-guard"),
        &key,
        &encryptor,
    )
    .expect("health-econ claim should encrypt");

    assert_eq!(
        materialize_encrypted_fact_in_family::<HealthEconPayloadFamily>(
            &envelope,
            &denied_policy(),
            &resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::PolicyDenied)
    );

    let mut tampered = envelope.clone();
    tampered.subject_id = SubjectId::new("subject-swapped");
    assert_eq!(
        materialize_encrypted_fact_in_family::<HealthEconPayloadFamily>(
            &tampered,
            &allowed_policy(),
            &resolver,
            &encryptor,
        ),
        Err(FactMaterializationError::AuthenticationFailed)
    );
}

#[test]
fn health_econ_payload_type_labels_round_trip() {
    let variants = [
        HealthEconFactPayloadType::Claim,
        HealthEconFactPayloadType::Adjudication,
        HealthEconFactPayloadType::Payment,
        HealthEconFactPayloadType::Coverage,
        HealthEconFactPayloadType::PreAuthRequest,
        HealthEconFactPayloadType::PreAuthDecision,
        HealthEconFactPayloadType::Appeal,
        HealthEconFactPayloadType::ProviderBill,
        HealthEconFactPayloadType::AccumulatorSnapshot,
        HealthEconFactPayloadType::BenefitMatch,
        HealthEconFactPayloadType::BillingDiscrepancy,
        HealthEconFactPayloadType::RecordRequest,
        HealthEconFactPayloadType::RecordReceived,
    ];
    for variant in variants {
        let label = variant.as_str();
        assert!(
            label.starts_with("health_econ."),
            "label {label} must live in the health_econ.* namespace"
        );
        assert_eq!(
            HealthEconFactPayloadType::from_str_label(label),
            Some(variant)
        );
    }
    assert_eq!(
        HealthEconFactPayloadType::from_str_label("clinical.claim"),
        None,
        "clinical.* stays reserved for the future clinical family"
    );
}
