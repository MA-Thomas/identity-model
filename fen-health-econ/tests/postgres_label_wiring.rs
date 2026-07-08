//! PostgreSQL label wiring for the health-economic family.
//!
//! The identity crate's envelope table is payload-agnostic; what this file
//! pins is the family-owned part of the durable contract:
//!
//! - the `health_econ.*` label strings are frozen (they land in stored rows
//!   and in the authenticated associated data, so they can never change once
//!   a production row exists),
//! - every label round-trips through the shared `PostgresEncryptedFactRow`
//!   mapping via the family-generic conversions,
//! - family scoping is real: a row carrying another family's label is a hard
//!   `UnknownPayloadType` error for this family (query-level scoping is what
//!   keeps such rows out of family-typed replay in the first place),
//! - (env-gated) a live PostgreSQL round trip proves one subject can hold
//!   identity and health-economic facts in the same table with each family's
//!   replay seeing only its own rows.

use fen_health_econ::{HealthEconFactPayloadType, HealthEconPayloadFamily};
use identity_model::{
    FactEncryptionMetadata, FactId, FactPayloadType, FactStatus, IdentityPayloadFamily,
    PersistenceTransactionId, PolicyRef, PostgresAdapterError, PostgresEncryptedFactRow,
    StoredEncryptedFactEnvelope, SubjectId, TemporalAnchor, Timestamp,
};

const KEY_ID: &str = "health-econ-fact-key";

/// The frozen `health_econ.*` label table. Adding a variant appends a row
/// here; changing or removing a persisted label is forbidden.
const FROZEN_LABELS: [(HealthEconFactPayloadType, &str); 13] = [
    (HealthEconFactPayloadType::Claim, "health_econ.claim"),
    (
        HealthEconFactPayloadType::Adjudication,
        "health_econ.adjudication",
    ),
    (HealthEconFactPayloadType::Payment, "health_econ.payment"),
    (HealthEconFactPayloadType::Coverage, "health_econ.coverage"),
    (
        HealthEconFactPayloadType::PreAuthRequest,
        "health_econ.preauth_request",
    ),
    (
        HealthEconFactPayloadType::PreAuthDecision,
        "health_econ.preauth_decision",
    ),
    (HealthEconFactPayloadType::Appeal, "health_econ.appeal"),
    (
        HealthEconFactPayloadType::ProviderBill,
        "health_econ.provider_bill",
    ),
    (
        HealthEconFactPayloadType::AccumulatorSnapshot,
        "health_econ.accumulator_snapshot",
    ),
    (
        HealthEconFactPayloadType::BenefitMatch,
        "health_econ.benefit_match",
    ),
    (
        HealthEconFactPayloadType::BillingDiscrepancy,
        "health_econ.billing_discrepancy",
    ),
    (
        HealthEconFactPayloadType::RecordRequest,
        "health_econ.record_request",
    ),
    (
        HealthEconFactPayloadType::RecordReceived,
        "health_econ.record_received",
    ),
];

fn envelope<T: Copy>(
    append_sequence: u64,
    fact_id: &str,
    subject_id: &str,
    payload_type: T,
) -> StoredEncryptedFactEnvelope<T> {
    StoredEncryptedFactEnvelope {
        append_sequence,
        transaction_id: PersistenceTransactionId("tx-health-econ-label-wiring".to_string()),
        committed_at: Timestamp("2026-07-08T00:00:00Z".to_string()),
        fact_id: FactId::new(fact_id),
        subject_id: SubjectId::new(subject_id),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-07-08T00:00:00Z".to_string())),
        payload_type,
        status: FactStatus::Active,
        materialization_policy_refs: vec![PolicyRef::new(
            "health-econ-materialization-policy@v1",
        )],
        encryption: FactEncryptionMetadata::deterministic_test(KEY_ID, b"nonce-1".to_vec()),
        ciphertext: vec![1, 2, 3],
    }
}

#[test]
fn health_econ_payload_type_labels_are_closed_and_frozen() {
    assert_eq!(
        HealthEconFactPayloadType::ALL.len(),
        FROZEN_LABELS.len(),
        "HealthEconFactPayloadType::ALL and the frozen label table must cover the same variants"
    );

    for (index, (payload_type, label)) in FROZEN_LABELS.iter().enumerate() {
        assert_eq!(
            HealthEconFactPayloadType::ALL[index], *payload_type,
            "ALL must list every variant in declaration order"
        );
        assert_eq!(
            payload_type.as_str(),
            *label,
            "persisted labels are frozen forever once a production AAD contains them"
        );
        assert_eq!(
            HealthEconFactPayloadType::from_str_label(label),
            Some(*payload_type),
            "every frozen label must parse back to its variant"
        );
        assert!(
            label.starts_with("health_econ."),
            "family labels stay inside the health_econ.* namespace"
        );
    }

    let mut labels: Vec<&str> = FROZEN_LABELS.iter().map(|(_, label)| *label).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), FROZEN_LABELS.len(), "labels must be unique");

    assert_eq!(HealthEconFactPayloadType::from_str_label("claim"), None);
    assert_eq!(
        HealthEconFactPayloadType::from_str_label("clinical.claim"),
        None,
        "the clinical.* namespace stays reserved for the future clinical family"
    );
}

#[test]
fn postgres_row_round_trips_every_health_econ_label() {
    for (index, (payload_type, label)) in FROZEN_LABELS.iter().enumerate() {
        let stored = envelope(
            index as u64,
            &format!("fact-health-econ-row-{index}"),
            "subject-health-econ-rows",
            *payload_type,
        );

        let row = PostgresEncryptedFactRow::try_from_envelope_in_family::<HealthEconPayloadFamily>(
            &stored,
        )
        .expect("health-econ envelope should map onto the shared row shape");
        assert_eq!(
            row.payload_type, *label,
            "the row column must carry the frozen family label"
        );

        let replayed = row
            .try_into_envelope_in_family::<HealthEconPayloadFamily>()
            .expect("the row must parse back through the family's closed label set");
        assert_eq!(replayed, stored);
    }
}

#[test]
fn postgres_row_rejects_labels_outside_the_family() {
    let health_econ_row =
        PostgresEncryptedFactRow::try_from_envelope_in_family::<HealthEconPayloadFamily>(
            &envelope(
                0,
                "fact-health-econ-cross-family",
                "subject-health-econ-cross-family",
                HealthEconFactPayloadType::Claim,
            ),
        )
        .expect("health-econ envelope should map onto the shared row shape");

    assert_eq!(
        health_econ_row
            .clone()
            .try_into_envelope_in_family::<IdentityPayloadFamily>(),
        Err(PostgresAdapterError::UnknownPayloadType(
            "health_econ.claim".to_string()
        )),
        "the identity family must not parse health_econ.* rows"
    );

    let identity_row = PostgresEncryptedFactRow::try_from_envelope_in_family::<
        IdentityPayloadFamily,
    >(&envelope(
        1,
        "fact-identity-cross-family",
        "subject-health-econ-cross-family",
        FactPayloadType::SubjectCreated,
    ))
    .expect("identity envelope should map onto the shared row shape");

    assert_eq!(
        identity_row
            .clone()
            .try_into_envelope_in_family::<HealthEconPayloadFamily>(),
        Err(PostgresAdapterError::UnknownPayloadType(
            "subject_created".to_string()
        )),
        "the health-econ family must not parse identity rows"
    );

    let mut corrupt_row = identity_row;
    corrupt_row.payload_type = "not_a_label_in_any_family".to_string();
    assert_eq!(
        corrupt_row
            .try_into_envelope_in_family::<HealthEconPayloadFamily>(),
        Err(PostgresAdapterError::UnknownPayloadType(
            "not_a_label_in_any_family".to_string()
        )),
        "a label outside every family's set stays a hard error, never a skipped row"
    );
}

#[cfg(feature = "postgres-adapter")]
mod live {
    use super::*;
    use identity_model::{AppendSequence, SqlxPostgresEncryptedFactRepository};

    const POSTGRES_URL_ENV: &str = "IDENTITY_MODEL_POSTGRES_URL";

    async fn next_live_append_sequence(pool: &sqlx::PgPool) -> AppendSequence {
        let next_sequence: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_facts")
                .fetch_one(pool)
                .await
                .expect("next append sequence query should succeed");
        next_sequence as AppendSequence
    }

    async fn cleanup_live_facts(pool: &sqlx::PgPool, fact_ids: &[&str]) {
        sqlx::query("DELETE FROM identity_facts WHERE fact_id = ANY($1)")
            .bind(fact_ids)
            .execute(pool)
            .await
            .expect("live fact cleanup should succeed");
    }

    /// One subject, two families, one shared envelope table: identity replay
    /// sees only identity rows, health-econ replay sees only `health_econ.*`
    /// rows, and neither errors on the other's labels.
    #[test]
    fn live_postgres_scopes_mixed_family_subject_replay_when_env_is_set() {
        let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
            eprintln!(
                "skipping live PostgreSQL health-econ label test; set {POSTGRES_URL_ENV} to run it"
            );
            return;
        };

        sqlx::test_block_on(async {
            let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
                .await
                .expect("live PostgreSQL repository should connect");
            repository
                .run_migration()
                .await
                .expect("migration should run against live PostgreSQL");

            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
                .to_string();
            let subject = format!("subject-live-health-econ-{suffix}");
            let identity_fact_id = format!("fact-live-health-econ-{suffix}-identity");
            let claim_fact_id = format!("fact-live-health-econ-{suffix}-claim");

            cleanup_live_facts(repository.pool(), &[&identity_fact_id, &claim_fact_id]).await;

            let base_sequence = next_live_append_sequence(repository.pool()).await;
            let identity_envelope = envelope(
                base_sequence,
                &identity_fact_id,
                &subject,
                FactPayloadType::SubjectCreated,
            );
            let claim_envelope = envelope(
                base_sequence + 1,
                &claim_fact_id,
                &subject,
                HealthEconFactPayloadType::Claim,
            );

            repository
                .append_encrypted_fact(&identity_envelope)
                .await
                .expect("identity fact should append to the shared envelope table");
            repository
                .append_encrypted_fact_in_family::<HealthEconPayloadFamily>(&claim_envelope)
                .await
                .expect("health-econ fact should append to the shared envelope table");

            let identity_rows = repository
                .encrypted_facts_for_subject(&SubjectId::new(&subject))
                .await
                .expect("identity subject replay should not error on health_econ.* rows");
            assert_eq!(identity_rows, vec![identity_envelope]);

            let health_econ_rows = repository
                .encrypted_facts_for_subject_in_family::<HealthEconPayloadFamily>(
                    &SubjectId::new(&subject),
                )
                .await
                .expect("health-econ subject replay should not error on identity rows");
            assert_eq!(health_econ_rows, vec![claim_envelope.clone()]);
            assert_eq!(
                health_econ_rows[0].payload_type,
                HealthEconFactPayloadType::Claim
            );

            let all_health_econ = repository
                .all_encrypted_facts_in_family::<HealthEconPayloadFamily>()
                .await
                .expect("family-scoped full replay should succeed");
            assert!(all_health_econ.contains(&claim_envelope));
            assert!(all_health_econ
                .iter()
                .all(|stored| stored.fact_id.0 != identity_fact_id));

            cleanup_live_facts(repository.pool(), &[&identity_fact_id, &claim_fact_id]).await;
        });
    }
}
