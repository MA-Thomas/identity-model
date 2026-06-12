use identity_model::*;

mod common;
use common::*;

#[test]
fn access_authorization_episode_memberships_keep_evidence_roles_explicit() {
    let subject_id: SubjectId = id("subject-1");
    let episode = access_authorization_episode(
        id("episode-export"),
        subject_id,
        SensitiveAction::ExportCompleteRecord,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );

    let membership = episode_membership(
        id("membership-continuity"),
        id("continuity-fact"),
        episode.id.clone(),
        FactRole::ContinuityWitness,
        system_author(),
        ts("2026-05-29T00:01:00Z"),
    );

    assert_eq!(
        episode.episode_kind,
        EpisodeKind::AccessAuthorizationWorkflow
    );
    assert_eq!(membership.role, FactRole::ContinuityWitness);
}

#[test]
fn mock_onboarding_slice_records_core_identity_facts_and_memberships() {
    let subject_id: SubjectId = id("subject-onboarding");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let provider = MockPhase1ContinuityProvider::successful();

    let slice = onboarding_vertical_slice(
        subject_id,
        &provider,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("onboarding slice should build");

    assert_eq!(
        slice.episode.episode_kind,
        EpisodeKind::IdentityVerificationWorkflow
    );
    assert_eq!(slice.facts.len(), 6);
    assert_eq!(slice.memberships.len(), slice.facts.len());
    assert!(slice
        .facts
        .iter()
        .any(|fact| matches!(fact.payload, FactPayload::SubjectCreated { .. })));
    assert!(slice.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::BiometricEnrollmentReferenceAdded { .. }
    )));
    assert!(slice.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::ClinicalIdentityLinkEstablished { .. }
    )));
    assert!(slice.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::PayerIdentityLinkEstablished { .. }
    )));
}

#[test]
fn complete_record_export_step_up_allows_passed_continuity_and_steps_up_failed_checks() {
    let subject_id: SubjectId = id("subject-step-up");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let provider = MockPhase1ContinuityProvider::successful();
    let mut lifecycle = InMemoryNonceLifecycle::new();
    let allowed_slice = complete_record_export_step_up_slice(
        subject_id.clone(),
        "enrollment-step-up".to_string(),
        &provider,
        &mut lifecycle,
        &provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("successful step-up should build");

    let allowed_decision = allowed_slice
        .facts
        .iter()
        .find_map(|fact| match &fact.payload {
            FactPayload::AccessDecision { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("access decision should exist");
    assert_eq!(allowed_decision, AccessDecisionResult::Allowed);

    let failed_provider = MockPhase1ContinuityProvider::failed();
    let mut failed_lifecycle = InMemoryNonceLifecycle::new();
    let failed_slice = complete_record_export_step_up_slice(
        subject_id,
        "enrollment-step-up".to_string(),
        &failed_provider,
        &mut failed_lifecycle,
        &failed_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("failed continuity should still produce auditable facts");
    let failed_continuity = failed_slice
        .facts
        .iter()
        .find_map(|fact| match &fact.payload {
            FactPayload::BiometricContinuityCheck {
                result,
                assurance_level,
                ..
            } => Some((*result, *assurance_level)),
            _ => None,
        })
        .expect("continuity fact should exist");
    assert_eq!(
        failed_continuity,
        (ContinuityCheckResult::Failed, AssuranceLevel::Low)
    );
    let failed_decision = failed_slice
        .facts
        .iter()
        .find_map(|fact| match &fact.payload {
            FactPayload::AccessDecision { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("access decision should exist");
    assert_eq!(failed_decision, AccessDecisionResult::StepUpRequired);

    let invalid_signature_provider = MockPhase1ContinuityProvider::successful();
    let invalid_signature_verifier = ExpectedSignatureVerifier {
        trusted_key_id: invalid_signature_provider.key_id.clone(),
        expected_signature: b"wrong-signature".to_vec(),
    };
    let mut invalid_signature_lifecycle = InMemoryNonceLifecycle::new();
    let invalid_signature_slice = complete_record_export_step_up_slice(
        id("subject-step-up-invalid-signature"),
        "enrollment-step-up".to_string(),
        &invalid_signature_provider,
        &mut invalid_signature_lifecycle,
        &invalid_signature_verifier,
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("rejected continuity verification should still produce auditable facts");
    let rejection_fact_id = invalid_signature_slice
        .facts
        .iter()
        .find_map(|fact| match &fact.payload {
            FactPayload::ContinuityVerificationRejected { reason, .. } => {
                Some((fact.id.clone(), *reason))
            }
            _ => None,
        })
        .expect("continuity rejection fact should exist");
    assert_eq!(
        rejection_fact_id,
        (
            id("fact-export-continuity"),
            ContinuityVerificationRejectionReason::InvalidSignature
        )
    );
    assert!(invalid_signature_slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::AccessDecision {
            decision: AccessDecisionResult::StepUpRequired,
            relied_on_facts,
            ..
        } if relied_on_facts.contains(&id("fact-export-continuity"))
    )));
}

#[test]
fn delegation_and_recovery_slices_preserve_audit_history_and_projection_rules() {
    let actor_subject_id: SubjectId = id("caregiver-1");
    let target_subject_id: SubjectId = id("patient-1");
    let translator = FenTranslator {
        system_author: system_author(),
    };

    let delegation = delegation_vertical_slice(
        actor_subject_id.clone(),
        target_subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert_eq!(
        delegation.episode.episode_kind,
        EpisodeKind::DelegationWorkflow
    );
    assert!(delegation.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AuthorityRelationshipRevoked { .. }
    )));
    assert!(delegation.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccessDecision {
            decision: AccessDecisionResult::Allowed,
            ..
        }
    )));

    let mut facts_before_revocation = delegation.facts.clone();
    facts_before_revocation.retain(|fact| {
        !matches!(
            fact.payload,
            FactPayload::AuthorityRelationshipRevoked { .. }
        )
    });
    let before_state = materialize_identity_state_at(
        target_subject_id.clone(),
        &facts_before_revocation,
        &ts("2026-06-01T00:00:00Z"),
    );
    assert!(authority_permits_action(
        &before_state,
        &actor_subject_id,
        AuthorizedAction::ShareRecord
    ));

    let after_state = materialize_identity_state_at(
        target_subject_id.clone(),
        &delegation.facts,
        &ts("2026-06-01T00:00:00Z"),
    );
    assert!(!authority_permits_action(
        &after_state,
        &actor_subject_id,
        AuthorizedAction::ShareRecord
    ));
    assert_eq!(after_state.latest_access_decisions.len(), 1);

    let recovery = manual_review_recovery_slice(
        target_subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert_eq!(
        recovery.episode.episode_kind,
        EpisodeKind::AccountRecoveryWorkflow
    );
    assert!(recovery.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccountRecoveryEvent {
            result: RecoveryResult::PendingManualReview,
            ..
        }
    )));
    assert!(recovery
        .facts
        .iter()
        .any(|fact| matches!(fact.payload, FactPayload::DeviceBindingRevoked { .. })));
}

#[test]
fn dispute_merge_split_and_witness_supersession_slices_change_projection_without_losing_audit() {
    let subject_id: SubjectId = id("patient-dispute");
    let translator = FenTranslator {
        system_author: system_author(),
    };

    let rejected = contested_provider_link_resolution_slice(
        subject_id.clone(),
        DisputeResolutionOutcome::Rejected,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let rejected_state = materialize_identity_state(subject_id.clone(), &rejected.facts);
    assert!(rejected_state.active_clinical_links.is_empty());
    assert!(rejected_state.unresolved_disputes.is_empty());
    assert!(rejected.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::ClinicalIdentityLinkContested { .. }
    )));

    let confirmed = contested_provider_link_resolution_slice(
        subject_id.clone(),
        DisputeResolutionOutcome::Confirmed,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let confirmed_state = materialize_identity_state(subject_id.clone(), &confirmed.facts);
    assert_eq!(confirmed_state.active_clinical_links.len(), 1);
    assert!(confirmed_state.unresolved_disputes.is_empty());

    let merge = duplicate_subject_merge_slice(
        subject_id.clone(),
        id("duplicate-subject"),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert!(merge.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::DuplicateSubjectMergeRecorded { .. }
    )));

    let split = incorrect_merge_split_slice(
        subject_id.clone(),
        vec![id("restored-a"), id("restored-b")],
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert!(split.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::IncorrectMergeSplitRecorded { .. }
    )));

    let supersession = witness_supersession_slice(
        subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let supersession_state = materialize_identity_state(subject_id, &supersession.facts);
    assert_eq!(supersession_state.assurance_level, AssuranceLevel::High);
    assert!(matches!(
        supersession.facts[0].status,
        FactStatus::Superseded { .. }
    ));
}

#[test]
fn recovery_slices_cover_approved_denied_and_trusted_device_paths() {
    let subject_id: SubjectId = id("patient-recovery");
    let translator = FenTranslator {
        system_author: system_author(),
    };

    let approved = approved_recovery_slice(
        subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let approved_state = materialize_identity_state(subject_id.clone(), &approved.facts);
    assert_eq!(
        approved_state.active_devices,
        vec!["device-passkey-replacement".to_string()]
    );
    assert!(approved.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccessDecision {
            action: SensitiveAction::ChangeRecoveryMethod,
            decision: AccessDecisionResult::Allowed,
            ..
        }
    )));

    let denied = denied_recovery_slice(
        subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert!(denied.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccountRecoveryEvent {
            result: RecoveryResult::Denied,
            ..
        }
    )));
    assert!(denied.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccessDecision {
            decision: AccessDecisionResult::Denied,
            ..
        }
    )));

    let trusted = trusted_device_recovery_slice(
        subject_id,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    assert!(trusted.facts.iter().any(|fact| matches!(
        fact.payload,
        FactPayload::AccountRecoveryEvent {
            method: RecoveryMethod::ExistingTrustedDevice,
            result: RecoveryResult::Approved,
            ..
        }
    )));
}

#[test]
fn deterministic_id_generator_keeps_fixture_ids_stable() {
    let mut ids = DeterministicIdGenerator::new();

    assert_eq!(ids.next_fact_id("fact-demo"), id("fact-demo-0"));
    assert_eq!(ids.next_fact_id("fact-demo"), id("fact-demo-1"));
    assert_eq!(
        ids.next_membership_id("membership-demo"),
        id("membership-demo-0")
    );
    assert_eq!(ids.next_subject_id("subject-demo"), id("subject-demo-0"));
}
