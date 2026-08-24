//! Sequencing step 5 of FEN_RECONCILIATION_RULE_ENGINE.md: durable rule
//! storage. The label tests pin the persisted vocabulary; the env-gated live
//! harness proves the PostgreSQL store preserves the in-memory store's
//! semantics — uniqueness, review-recording activation, lifecycle gates,
//! effective-window resolution, and versions kept forever — against a real
//! database (same convention as `postgres_label_wiring.rs`).

#![cfg(feature = "postgres-adapter")]

use fen_health_econ::{
    discrepancy_kind_identity_label, postgres_rule_definition_type_label,
    postgres_rule_status_label, DiscrepancyKind, Money, PostgresRuleStoreError,
    ReconciliationRuleArtifact, ReconciliationRuleDefinition, RuleArtifactRef,
    RuleArtifactStatus, RuleReview, RuleStoreError,
};
use identity_model::{Author, AuthorId, AuthorType, TimeInterval, Timestamp};

fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

fn review() -> RuleReview {
    RuleReview {
        reviewed_by: Author {
            author_type: AuthorType::System,
            author_id: Some(AuthorId::new("reviewer-1")),
            display_name: Some("rules-review".to_string()),
        },
        reviewed_at: ts("2026-07-01T00:00:00Z"),
        notes: Some("initial review".to_string()),
    }
}

fn draft(id: &str, version: &str, definition: ReconciliationRuleDefinition) -> ReconciliationRuleArtifact {
    ReconciliationRuleArtifact {
        id: RuleArtifactRef::new(id),
        version: version.to_string(),
        title: "live rule".to_string(),
        description: Some("live-harness rule artifact".to_string()),
        status: RuleArtifactStatus::Draft,
        effective_period: None,
        review: None,
        definition,
    }
}

#[test]
fn postgres_rule_labels_are_pinned_and_match_the_identity_labels() {
    assert_eq!(postgres_rule_status_label(RuleArtifactStatus::Draft), "draft");
    assert_eq!(postgres_rule_status_label(RuleArtifactStatus::Active), "active");
    assert_eq!(postgres_rule_status_label(RuleArtifactStatus::Retired), "retired");

    // The definition-type column carries exactly the frozen discrepancy-kind
    // identity labels: one vocabulary from rule review to finding identity.
    let pairs = [
        (
            ReconciliationRuleDefinition::BillVsEobMismatch { tolerance: None },
            DiscrepancyKind::BillVsEobMismatch,
        ),
        (
            ReconciliationRuleDefinition::DuplicateCharge {
                match_window_days: 7,
            },
            DiscrepancyKind::DuplicateCharge,
        ),
        (
            ReconciliationRuleDefinition::AboveAllowedAmount { tolerance: None },
            DiscrepancyKind::AboveAllowedAmount,
        ),
        (
            ReconciliationRuleDefinition::AppealableDenial {
                appealable_carc_codes: Vec::new(),
            },
            DiscrepancyKind::AppealableDenial,
        ),
    ];
    for (definition, kind) in &pairs {
        assert_eq!(
            postgres_rule_definition_type_label(definition),
            discrepancy_kind_identity_label(kind),
        );
    }
}

mod live {
    use super::*;
    use fen_health_econ::PostgresReconciliationRuleStore;
    use fen_store_postgres::SqlxPostgresEnvelopeStore;

    const POSTGRES_URL_ENV: &str = "IDENTITY_MODEL_POSTGRES_URL";

    async fn cleanup(pool: &sqlx::PgPool, rule_id: &str) {
        sqlx::query(
            "DELETE FROM health_econ_reconciliation_rule_artifacts WHERE rule_id = $1",
        )
        .bind(rule_id)
        .execute(pool)
        .await
        .expect("live rule cleanup should succeed");
    }

    #[test]
    fn live_postgres_rule_store_preserves_in_memory_semantics_when_env_is_set() {
        let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
            eprintln!(
                "skipping live PostgreSQL rule store test; set {POSTGRES_URL_ENV} to run it"
            );
            return;
        };

        sqlx::test_block_on(async {
            let repository = SqlxPostgresEnvelopeStore::connect(&database_url)
                .await
                .expect("live PostgreSQL repository should connect");
            repository
                .run_migrations()
                .await
                .expect("migration should run against live PostgreSQL");
            let store = PostgresReconciliationRuleStore::from_pool(repository.pool().clone());
            store
                .run_migration()
                .await
                .expect("health-economic rule migration should run");

            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
                .to_string();
            let rule_id = format!("live-rule-{suffix}");
            let id = RuleArtifactRef::new(&rule_id);
            let v1_ref = RuleArtifactRef::new(format!("{rule_id}@v1"));
            let v2_ref = RuleArtifactRef::new(format!("{rule_id}@v2"));
            let as_of = ts("2026-07-08T12:00:00Z");

            cleanup(store.pool(), &rule_id).await;

            // Insert a draft; (rule_id, version) uniqueness is enforced by
            // the database and surfaces as the in-memory store's error.
            let v1 = draft(
                &rule_id,
                "v1",
                ReconciliationRuleDefinition::BillVsEobMismatch {
                    tolerance: Some(Money::new("USD", 100)),
                },
            );
            store
                .insert_rule_artifact(&v1)
                .await
                .expect("draft v1 should insert");
            assert_eq!(
                store.insert_rule_artifact(&v1).await.unwrap_err(),
                PostgresRuleStoreError::Store(RuleStoreError::DuplicateIdVersion {
                    id: id.clone(),
                    version: "v1".to_string(),
                })
            );

            // Drafts are never resolved for evaluation.
            let resolved = store.active_rules(&as_of).await.expect("resolution should succeed");
            assert!(resolved.iter().all(|rule| rule.rule_ref != v1_ref));

            // Activation records the review and makes the rule resolvable
            // under its versioned citation ref.
            store
                .activate(&id, "v1", review())
                .await
                .expect("draft v1 should activate");
            let stored = store
                .get_rule_artifact(&id, "v1")
                .await
                .expect("get should succeed")
                .expect("v1 should exist");
            assert_eq!(stored.status, RuleArtifactStatus::Active);
            assert_eq!(stored.review, Some(review()));
            assert_eq!(stored.definition, v1.definition);
            assert_eq!(
                store.activate(&id, "v1", review()).await.unwrap_err(),
                PostgresRuleStoreError::Store(RuleStoreError::InvalidLifecycleTransition {
                    id: id.clone(),
                    version: "v1".to_string(),
                    from: RuleArtifactStatus::Active,
                })
            );
            let resolved = store.active_rules(&as_of).await.expect("resolution should succeed");
            let live_v1 = resolved
                .iter()
                .find(|rule| rule.rule_ref == v1_ref)
                .expect("active v1 should resolve");
            assert_eq!(live_v1.definition, v1.definition);

            // A second version with an effective window: gated in Rust by
            // the same closed-interval semantics as the in-memory store.
            let mut v2 = draft(
                &rule_id,
                "v2",
                ReconciliationRuleDefinition::AppealableDenial {
                    appealable_carc_codes: vec!["50".to_string(), "197".to_string()],
                },
            );
            v2.effective_period = Some(TimeInterval {
                start: ts("2026-07-01T00:00:00Z"),
                end: ts("2026-07-31T23:59:59Z"),
            });
            store
                .insert_rule_artifact(&v2)
                .await
                .expect("draft v2 should insert");
            store
                .activate(&id, "v2", review())
                .await
                .expect("draft v2 should activate");

            let inside = store.active_rules(&as_of).await.expect("resolution should succeed");
            assert!(inside.iter().any(|rule| rule.rule_ref == v2_ref));
            let before_window = store
                .active_rules(&ts("2026-06-01T00:00:00Z"))
                .await
                .expect("resolution should succeed");
            assert!(before_window.iter().all(|rule| rule.rule_ref != v2_ref));
            assert!(before_window.iter().any(|rule| rule.rule_ref == v1_ref));

            // Retire v1: gone from resolution, kept as history.
            store.retire(&id, "v1").await.expect("active v1 should retire");
            let after_retire = store.active_rules(&as_of).await.expect("resolution should succeed");
            assert!(after_retire.iter().all(|rule| rule.rule_ref != v1_ref));
            assert!(after_retire.iter().any(|rule| rule.rule_ref == v2_ref));
            assert_eq!(
                store.retire(&id, "v1").await.unwrap_err(),
                PostgresRuleStoreError::Store(RuleStoreError::InvalidLifecycleTransition {
                    id: id.clone(),
                    version: "v1".to_string(),
                    from: RuleArtifactStatus::Retired,
                })
            );
            assert_eq!(
                store.retire(&id, "v9").await.unwrap_err(),
                PostgresRuleStoreError::Store(RuleStoreError::UnknownArtifact {
                    id: id.clone(),
                    version: "v9".to_string(),
                })
            );

            // Both versions remain rows, in insertion order.
            let versions = store.versions_of(&id).await.expect("versions query should succeed");
            assert_eq!(
                versions
                    .iter()
                    .map(|artifact| (artifact.version.as_str(), artifact.status))
                    .collect::<Vec<_>>(),
                vec![
                    ("v1", RuleArtifactStatus::Retired),
                    ("v2", RuleArtifactStatus::Active),
                ]
            );

            cleanup(store.pool(), &rule_id).await;
        });
    }
}
