use identity_model::*;

mod common;
use common::*;

#[test]
fn high_risk_action_requires_continuity_step_up() {
    let policy = default_policy_for_action(
        SensitiveAction::ExportCompleteRecord,
        id("complete-record-export-policy"),
    );
    let evidence = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: None,
        continuity_fact_id: None,
        continuity_assurance: None,
        continuity_observed_at: None,
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: None,
    };

    let evaluation = evaluate_action_policy(&policy, &evidence);

    assert_eq!(evaluation.decision, AccessDecisionResult::StepUpRequired);
    assert_eq!(
        evaluation.reasons,
        vec![PolicyEvaluationReason::RequiredContinuityMissing]
    );
    assert_eq!(evaluation.relied_on_facts.len(), 2);
}

#[test]
fn high_risk_action_allows_sufficient_evidence() {
    let policy = default_policy_for_action(
        SensitiveAction::ExportCompleteRecord,
        id("complete-record-export-policy"),
    );
    let evidence = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: None,
        continuity_fact_id: Some(id("continuity-fact")),
        continuity_assurance: Some(AssuranceLevel::High),
        continuity_observed_at: None,
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: None,
    };

    let evaluation = evaluate_action_policy(&policy, &evidence);

    assert_eq!(evaluation.decision, AccessDecisionResult::Allowed);
    assert!(evaluation.reasons.is_empty());
    assert_eq!(evaluation.relied_on_facts.len(), 3);
}

#[test]
fn policy_artifacts_generate_versioned_refs_for_access_decisions() {
    let artifact = PolicyArtifact::sensitive_action(
        id("complete-record-export-policy"),
        "v1",
        SensitiveAction::ExportCompleteRecord,
        Some(TimeInterval {
            start: ts("2026-05-29T00:00:00Z"),
            end: ts("2026-12-31T23:59:59Z"),
        }),
    )
    .with_title("Complete record export")
    .with_description("Requires fresh continuity before full-record export")
    .with_review(PolicyReview {
        reviewed_by: system_author(),
        reviewed_at: ts("2026-05-28T00:00:00Z"),
        notes: Some("approved for fixture testing".to_string()),
    });
    let evidence = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        continuity_fact_id: Some(id("continuity-fact")),
        continuity_assurance: Some(AssuranceLevel::High),
        continuity_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: Some(ts("2026-05-29T00:00:00Z")),
    };

    let evaluation = evaluate_policy_artifact_with_context(
        &artifact,
        &evidence,
        &PolicyEvaluationContext::new(Some(ts("2026-05-29T00:01:00Z"))),
    );

    assert_eq!(artifact.id, id("complete-record-export-policy"));
    assert_eq!(artifact.version, "v1");
    assert_eq!(artifact.title, "Complete record export");
    assert!(artifact.review.is_some());
    assert_eq!(
        evaluation.policy_refs,
        vec![id("complete-record-export-policy@v1")]
    );
    assert_eq!(evaluation.decision, AccessDecisionResult::Allowed);
}

#[test]
fn policy_artifacts_carry_action_specific_definitions() {
    let freshness = EvidenceFreshnessRequirements {
        credential: Some(FreshnessRequirement {
            max_age_seconds: 5 * 60,
        }),
        continuity: Some(FreshnessRequirement {
            max_age_seconds: 60,
        }),
        risk: Some(FreshnessRequirement {
            max_age_seconds: 60,
        }),
    };
    let delegation = PolicyArtifact::delegation_constraints(
        id("caregiver-delegation-policy"),
        "v3",
        None,
        DelegationConstraintsPolicyDefinition {
            authority_type: AuthorityType::CaregiverDelegation,
            permitted_actions: vec![AuthorizedAction::ViewRecord, AuthorizedAction::ShareRecord],
            requires_target_subject_continuity: true,
            max_validity_seconds: Some(30 * 24 * 60 * 60),
            freshness,
        },
    );
    let recovery = PolicyArtifact::recovery_method_change(
        id("recovery-method-change-policy"),
        "v1",
        None,
        RecoveryMethodChangePolicyDefinition {
            allowed_methods: vec![
                RecoveryMethod::ExistingTrustedDevice,
                RecoveryMethod::GovernmentIdAndLiveness,
            ],
            revoke_replaced_devices: true,
            requires_manual_review_for_low_assurance: true,
            freshness,
        },
    );
    let break_glass = PolicyArtifact::break_glass(
        id("break-glass-policy"),
        "v1",
        None,
        BreakGlassPolicyDefinition {
            action: SensitiveAction::EmergencyAccess,
            required_assurance: AssuranceLevel::High,
            freshness,
            max_session_seconds: 15 * 60,
            requires_post_access_review: true,
        },
    );

    assert!(matches!(
        delegation.definition(),
        PolicyArtifactDefinition::DelegationConstraints(definition)
            if definition.authority_type == AuthorityType::CaregiverDelegation
                && definition.permitted_actions.contains(&AuthorizedAction::ShareRecord)
    ));
    assert_eq!(
        delegation.action_policy().action,
        SensitiveAction::DelegateAuthority
    );
    assert!(delegation.action_policy().requires_fresh_continuity);
    assert!(matches!(
        recovery.definition(),
        PolicyArtifactDefinition::RecoveryMethodChange(definition)
            if definition.revoke_replaced_devices
    ));
    assert_eq!(
        recovery.action_policy().action,
        SensitiveAction::ChangeRecoveryMethod
    );
    assert!(matches!(
        break_glass.definition(),
        PolicyArtifactDefinition::BreakGlass(definition)
            if definition.requires_post_access_review && definition.max_session_seconds == 900
    ));
    assert_eq!(
        break_glass.action_policy().policy_ref,
        id("break-glass-policy@v1")
    );
}

#[test]
fn policy_artifact_effective_period_and_status_gate_evaluation() {
    let evidence = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        continuity_fact_id: Some(id("continuity-fact")),
        continuity_assurance: Some(AssuranceLevel::High),
        continuity_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: Some(ts("2026-05-29T00:00:00Z")),
    };
    let retired = PolicyArtifact::sensitive_action(
        id("complete-record-export-policy"),
        "v0",
        SensitiveAction::ExportCompleteRecord,
        Some(TimeInterval {
            start: ts("2026-01-01T00:00:00Z"),
            end: ts("2026-01-31T23:59:59Z"),
        }),
    )
    .with_status(PolicyArtifactStatus::Retired);

    let evaluation = evaluate_policy_artifact_with_context(
        &retired,
        &evidence,
        &PolicyEvaluationContext::new(Some(ts("2026-05-29T00:01:00Z"))),
    );

    assert_eq!(
        evaluation.decision,
        AccessDecisionResult::ManualReviewRequired
    );
    assert_eq!(
        evaluation.reasons,
        vec![
            PolicyEvaluationReason::PolicyArtifactNotActive,
            PolicyEvaluationReason::PolicyExpired,
        ]
    );
}

#[test]
fn policy_artifact_invalid_effective_period_forces_manual_review() {
    let evidence = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        continuity_fact_id: Some(id("continuity-fact")),
        continuity_assurance: Some(AssuranceLevel::High),
        continuity_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: Some(ts("2026-05-29T00:00:00Z")),
    };
    let artifact = PolicyArtifact::sensitive_action(
        id("complete-record-export-policy"),
        "v1",
        SensitiveAction::ExportCompleteRecord,
        Some(TimeInterval {
            start: ts("2026-02-31T00:00:00Z"),
            end: ts("2026-12-31T23:59:59Z"),
        }),
    );

    let evaluation = evaluate_policy_artifact_with_context(
        &artifact,
        &evidence,
        &PolicyEvaluationContext::new(Some(ts("2026-05-29T00:01:00Z"))),
    );

    assert_eq!(
        evaluation.decision,
        AccessDecisionResult::ManualReviewRequired
    );
    assert_eq!(
        evaluation.reasons,
        vec![PolicyEvaluationReason::PolicyTimestampInvalid]
    );
}

#[test]
fn policy_freshness_windows_force_step_up_for_stale_evidence() {
    let policy = default_policy_for_action(
        SensitiveAction::ExportCompleteRecord,
        id("complete-record-export-policy"),
    );
    let stale_continuity = EvidenceSummary {
        credential_fact_id: Some(id("credential-fact")),
        credential_assurance: Some(AssuranceLevel::Medium),
        credential_observed_at: Some(ts("2026-05-29T00:10:00Z")),
        continuity_fact_id: Some(id("continuity-fact")),
        continuity_assurance: Some(AssuranceLevel::High),
        continuity_observed_at: Some(ts("2026-05-29T00:00:00Z")),
        risk_fact_id: Some(id("risk-fact")),
        risk_result: Some(RiskEvaluationResult::Passed),
        risk_observed_at: Some(ts("2026-05-29T00:10:00Z")),
    };
    let fresh = EvidenceSummary {
        continuity_observed_at: Some(ts("2026-05-29T00:07:00Z")),
        ..stale_continuity.clone()
    };

    let stale_evaluation = evaluate_action_policy_at(
        &policy,
        &stale_continuity,
        Some(&ts("2026-05-29T00:10:01Z")),
    );
    assert_eq!(
        stale_evaluation.decision,
        AccessDecisionResult::StepUpRequired
    );
    assert_eq!(
        stale_evaluation.reasons,
        vec![PolicyEvaluationReason::ContinuityStale]
    );
    assert_eq!(
        evaluate_action_policy_at(&policy, &fresh, Some(&ts("2026-05-29T00:10:01Z"))).decision,
        AccessDecisionResult::Allowed
    );
}

#[test]
fn timestamp_helper_returns_explicit_errors_for_unsupported_shapes() {
    assert_eq!(
        timestamp_to_unix_seconds(&ts("2026-05-29T00:00:00")),
        Err(TimestampParseError::MissingUtcSuffix)
    );
    assert_eq!(
        timestamp_to_unix_seconds(&ts("2026-05-29 00:00:00Z")),
        Err(TimestampParseError::MissingDateTimeSeparator)
    );
    assert_eq!(
        timestamp_to_unix_seconds(&ts("2026-02-31T00:00:00Z")),
        Err(TimestampParseError::InvalidDate)
    );
    assert_eq!(
        timestamp_in_closed_interval(
            &ts("2026-02-31T00:00:00Z"),
            &ts("2026-01-01T00:00:00Z"),
            &ts("2026-12-31T23:59:59Z")
        ),
        Err(TimestampParseError::InvalidDate)
    );
    assert_eq!(
        seconds_between(&ts("2026-05-29T00:00:00Z"), &ts("2026-05-29T00:05:00Z")),
        Ok(300)
    );
}
