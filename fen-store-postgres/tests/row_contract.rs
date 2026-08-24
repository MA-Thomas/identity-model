use fen_core::{
    Author, AuthorType, AuthorizationBasis, FactId, FactStatus, PolicyRef, Provenance,
    ProvenanceTier, SubjectId, TemporalAnchor, Timestamp,
};
use fen_store::{
    EncryptedFactPlaintextOf, FactEncryptionMetadata, FactMaterializationAuditEvent,
    FactMaterializationAuditOutcome, FactMaterializationError, PayloadFamily,
    PersistenceTransactionId, StoredEncryptedFactEnvelope,
};
use fen_store_postgres::{
    EncryptedFactPostgresRow, FenStorePostgresError, MaterializationAuditPostgresRow,
    FEN_ENCRYPTED_FACTS_MIGRATION_SQL,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestFact {
    id: FactId,
    subject_id: SubjectId,
    occurred_at: TemporalAnchor,
    status: FactStatus,
    payload: TestPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TestPayload {
    Example,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestPayloadType {
    Example,
}

struct TestFamily;

impl PayloadFamily for TestFamily {
    type Fact = TestFact;
    type Payload = TestPayload;
    type PayloadType = TestPayloadType;

    fn payload_type_label(_payload_type: Self::PayloadType) -> &'static str {
        "test.example"
    }

    fn payload_type_from_label(label: &str) -> Option<Self::PayloadType> {
        (label == "test.example").then_some(TestPayloadType::Example)
    }

    fn payload_type_of_payload(_payload: &Self::Payload) -> Self::PayloadType {
        TestPayloadType::Example
    }

    fn payload_type_variants() -> &'static [Self::PayloadType] {
        &[TestPayloadType::Example]
    }

    fn fact_id(fact: &Self::Fact) -> &FactId {
        &fact.id
    }

    fn subject_id(fact: &Self::Fact) -> &SubjectId {
        &fact.subject_id
    }

    fn occurred_at(fact: &Self::Fact) -> &TemporalAnchor {
        &fact.occurred_at
    }

    fn status(fact: &Self::Fact) -> &FactStatus {
        &fact.status
    }

    fn plaintext_from_fact(fact: &Self::Fact) -> EncryptedFactPlaintextOf<Self::Payload> {
        EncryptedFactPlaintextOf {
            code: None,
            payload: fact.payload.clone(),
            provenance: provenance(),
            external_refs: Vec::new(),
        }
    }

    fn fact_from_plaintext(
        plaintext: EncryptedFactPlaintextOf<Self::Payload>,
        envelope: &StoredEncryptedFactEnvelope<Self::PayloadType>,
    ) -> Self::Fact {
        TestFact {
            id: envelope.fact_id.clone(),
            subject_id: envelope.subject_id.clone(),
            occurred_at: envelope.occurred_at.clone(),
            status: envelope.status.clone(),
            payload: plaintext.payload,
        }
    }
}

fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test".to_string()),
        source_document: None,
        imported_at: Timestamp("2026-08-14T00:00:00Z".to_string()),
        author: Author {
            author_type: AuthorType::System,
            author_id: None,
            display_name: None,
        },
        tier: ProvenanceTier::Inference,
        content_hash: None,
        authorization_basis: Some(AuthorizationBasis::SelfHeld),
    }
}

fn envelope() -> StoredEncryptedFactEnvelope<TestPayloadType> {
    StoredEncryptedFactEnvelope {
        append_sequence: 7,
        transaction_id: PersistenceTransactionId::new("tx-test"),
        committed_at: Timestamp("2026-08-14T00:00:00Z".to_string()),
        fact_id: FactId::new("fact-test"),
        subject_id: SubjectId::new("subject-test"),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-08-13T00:00:00Z".to_string())),
        payload_type: TestPayloadType::Example,
        status: FactStatus::Active,
        materialization_policy_refs: vec![PolicyRef::new("policy@v1")],
        encryption: FactEncryptionMetadata::deterministic_test("key-1", b"nonce".to_vec()),
        ciphertext: vec![1, 2, 3],
    }
}

#[test]
fn envelope_row_round_trip_is_family_scoped() {
    let _payload_contract = TestPayload::Example;
    let envelope = envelope();
    let row = EncryptedFactPostgresRow::try_from_envelope_in_family::<TestFamily>(&envelope)
        .expect("envelope should map to the shared PostgreSQL row");
    assert_eq!(row.payload_type, "test.example");
    assert_eq!(
        row.clone()
            .try_into_envelope_in_family::<TestFamily>()
            .expect("row should map back into its family"),
        envelope
    );

    let mut invalid = row;
    invalid.payload_type = "another.example".to_string();
    assert_eq!(
        invalid.try_into_envelope_in_family::<TestFamily>(),
        Err(FenStorePostgresError::UnknownPayloadType(
            "another.example".to_string()
        ))
    );
}

#[test]
fn materialization_audit_row_round_trips_without_payload_data() {
    let event = FactMaterializationAuditEvent {
        subject_id: SubjectId::new("subject-test"),
        fact_ids: vec![FactId::new("fact-test")],
        materialization_policy_refs: vec![PolicyRef::new("required@v1")],
        evaluated_policy_refs: vec![PolicyRef::new("evaluated@v2")],
        caller: Some("employee-7".to_string()),
        purpose: Some("billing-defense".to_string()),
        requested_at: Some(Timestamp("2026-08-14T00:00:00Z".to_string())),
        outcome: FactMaterializationAuditOutcome::DecryptionFailed,
        error: Some(FactMaterializationError::AuthenticationFailed),
    };
    let row = MaterializationAuditPostgresRow::from_event(&event);
    assert_eq!(row.try_into_event().expect("audit row should parse"), event);
}

#[test]
fn migration_preserves_the_deployed_legacy_table_names() {
    assert!(FEN_ENCRYPTED_FACTS_MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS identity_facts"));
    assert!(FEN_ENCRYPTED_FACTS_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS identity_fact_materialization_audit"));
}
