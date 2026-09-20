//! Sequencing step 1 of FEN_RECONCILIATION_RULE_ENGINE.md: rule artifact
//! lifecycle and the in-memory rule store, with the `rule-id@version`
//! citation shape pinned by tests (mirroring the policy-artifact contract).

use fen_health_econ::{
    versioned_rule_artifact_ref, InMemoryReconciliationRuleStore, Money,
    ReconciliationRuleArtifact, ReconciliationRuleDefinition, RuleArtifactRef, RuleArtifactStatus,
    RuleReview, RuleStoreError,
};
use identity_model::{Author, AuthorType, TimeInterval, Timestamp};

fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

fn reviewer() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: None,
        display_name: Some("rules-review".to_string()),
    }
}

fn review() -> RuleReview {
    RuleReview {
        reviewed_by: reviewer(),
        reviewed_at: ts("2026-07-01T00:00:00Z"),
        notes: Some("initial review".to_string()),
    }
}

fn draft_artifact(id: &str, version: &str) -> ReconciliationRuleArtifact {
    ReconciliationRuleArtifact {
        id: RuleArtifactRef::new(id),
        version: version.to_string(),
        title: "Bill vs EOB reconciliation".to_string(),
        description: None,
        status: RuleArtifactStatus::Draft,
        effective_period: None,
        review: None,
        definition: ReconciliationRuleDefinition::BillVsEobMismatch {
            tolerance: Some(Money::new("USD", 100)),
        },
    }
}

// -- Citation shape (golden) -------------------------------------------------

#[test]
fn citation_ref_is_rule_id_at_version() {
    // The `rule-id@version` shape is the durable citation contract; findings
    // cite it verbatim in `DerivedFrom.rule_ref`. Pinned as a golden string.
    let artifact = draft_artifact("eob-bill-reconciliation", "v1");
    assert_eq!(
        artifact.citation_ref(),
        RuleArtifactRef::new("eob-bill-reconciliation@v1")
    );
    assert_eq!(
        versioned_rule_artifact_ref(&RuleArtifactRef::new("appealable-denials"), "v3"),
        RuleArtifactRef::new("appealable-denials@v3")
    );
}

// -- Uniqueness ---------------------------------------------------------------

#[test]
fn duplicate_id_version_is_rejected() {
    let mut store = InMemoryReconciliationRuleStore::new();
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();
    let err = store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap_err();
    assert_eq!(
        err,
        RuleStoreError::DuplicateIdVersion {
            id: RuleArtifactRef::new("eob-bill-reconciliation"),
            version: "v1".to_string(),
        }
    );
    // A second version of the same rule ID is fine.
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v2"))
        .unwrap();
    assert_eq!(
        store
            .versions_of(&RuleArtifactRef::new("eob-bill-reconciliation"))
            .len(),
        2
    );
}

// -- Lifecycle ----------------------------------------------------------------

#[test]
fn draft_rules_are_not_resolved_for_evaluation() {
    let mut store = InMemoryReconciliationRuleStore::new();
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();
    let resolved = store.active_rules(&ts("2026-07-08T00:00:00Z")).unwrap();
    assert!(resolved.is_empty());
}

#[test]
fn activation_records_review_and_makes_the_rule_resolvable() {
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();
    store.activate(&id, "v1", review()).unwrap();

    let stored = store.get(&id, "v1").unwrap();
    assert_eq!(stored.status, RuleArtifactStatus::Active);
    assert_eq!(stored.review, Some(review()));

    let resolved = store.active_rules(&ts("2026-07-08T00:00:00Z")).unwrap();
    assert_eq!(resolved.len(), 1);
    // The resolved rule carries the versioned citation ref, not the bare ID.
    assert_eq!(
        resolved[0].rule_ref,
        RuleArtifactRef::new("eob-bill-reconciliation@v1")
    );
    assert_eq!(
        resolved[0].definition,
        ReconciliationRuleDefinition::BillVsEobMismatch {
            tolerance: Some(Money::new("USD", 100)),
        }
    );
}

#[test]
fn retiring_removes_from_resolution_but_keeps_history() {
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();
    store.activate(&id, "v1", review()).unwrap();
    store.retire(&id, "v1").unwrap();

    assert!(store
        .active_rules(&ts("2026-07-08T00:00:00Z"))
        .unwrap()
        .is_empty());
    // Retired artifacts remain part of history: findings cite them.
    assert_eq!(
        store.get(&id, "v1").unwrap().status,
        RuleArtifactStatus::Retired
    );
}

#[test]
fn new_version_replaces_old_without_mutation() {
    // Editing a rule means activating a new version and retiring the old
    // one, never mutating in place.
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();
    store.activate(&id, "v1", review()).unwrap();

    let mut v2 = draft_artifact("eob-bill-reconciliation", "v2");
    v2.definition = ReconciliationRuleDefinition::BillVsEobMismatch {
        tolerance: Some(Money::new("USD", 500)),
    };
    store.insert(v2).unwrap();
    store.activate(&id, "v2", review()).unwrap();
    store.retire(&id, "v1").unwrap();

    let resolved = store.active_rules(&ts("2026-07-08T00:00:00Z")).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        resolved[0].rule_ref,
        RuleArtifactRef::new("eob-bill-reconciliation@v2")
    );
}

#[test]
fn invalid_lifecycle_transitions_are_rejected() {
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    store
        .insert(draft_artifact("eob-bill-reconciliation", "v1"))
        .unwrap();

    // Retire a draft: rejected.
    assert_eq!(
        store.retire(&id, "v1").unwrap_err(),
        RuleStoreError::InvalidLifecycleTransition {
            id: id.clone(),
            version: "v1".to_string(),
            from: RuleArtifactStatus::Draft,
        }
    );

    store.activate(&id, "v1", review()).unwrap();

    // Re-activate an active artifact: rejected (activation is one review event).
    assert_eq!(
        store.activate(&id, "v1", review()).unwrap_err(),
        RuleStoreError::InvalidLifecycleTransition {
            id: id.clone(),
            version: "v1".to_string(),
            from: RuleArtifactStatus::Active,
        }
    );

    store.retire(&id, "v1").unwrap();

    // Reactivate a retired artifact: rejected — activate a new version instead.
    assert_eq!(
        store.activate(&id, "v1", review()).unwrap_err(),
        RuleStoreError::InvalidLifecycleTransition {
            id: id.clone(),
            version: "v1".to_string(),
            from: RuleArtifactStatus::Retired,
        }
    );

    // Unknown artifact: typed error, not a silent no-op.
    assert_eq!(
        store.retire(&id, "v9").unwrap_err(),
        RuleStoreError::UnknownArtifact {
            id: id.clone(),
            version: "v9".to_string(),
        }
    );
}

// -- Effective windows ----------------------------------------------------------

#[test]
fn effective_window_gates_resolution() {
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    let mut artifact = draft_artifact("eob-bill-reconciliation", "v1");
    artifact.effective_period = Some(TimeInterval {
        start: ts("2026-07-01T00:00:00Z"),
        end: ts("2026-07-31T23:59:59Z"),
    });
    store.insert(artifact).unwrap();
    store.activate(&id, "v1", review()).unwrap();

    // Before the window, after the window: not resolved.
    assert!(store
        .active_rules(&ts("2026-06-30T23:59:59Z"))
        .unwrap()
        .is_empty());
    assert!(store
        .active_rules(&ts("2026-08-01T00:00:00Z"))
        .unwrap()
        .is_empty());
    // Inside (closed interval, boundaries included): resolved.
    assert_eq!(
        store
            .active_rules(&ts("2026-07-01T00:00:00Z"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .active_rules(&ts("2026-07-15T12:00:00Z"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .active_rules(&ts("2026-07-31T23:59:59Z"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn malformed_effective_period_is_an_error_not_a_silent_skip() {
    let mut store = InMemoryReconciliationRuleStore::new();
    let id = RuleArtifactRef::new("eob-bill-reconciliation");
    let mut artifact = draft_artifact("eob-bill-reconciliation", "v1");
    artifact.effective_period = Some(TimeInterval {
        start: ts("not-a-timestamp"),
        end: ts("2026-07-31T23:59:59Z"),
    });
    store.insert(artifact).unwrap();
    store.activate(&id, "v1", review()).unwrap();

    let err = store.active_rules(&ts("2026-07-08T00:00:00Z")).unwrap_err();
    assert!(matches!(
        err,
        RuleStoreError::MalformedEffectivePeriod { id: ref bad_id, ref version, .. }
            if *bad_id == id && version == "v1"
    ));
}
