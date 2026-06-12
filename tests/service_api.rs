use identity_model::*;

mod common;
use common::*;

#[test]
fn service_facade_returns_workflow_projection_and_narrative() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let subject_id: SubjectId = id("subject-service-onboarding");

    let outcome = service
        .enroll_subject(
            OnboardingRequest::fixture(subject_id.clone(), author, ts("2026-05-29T00:00:00Z")),
            &provider,
        )
        .expect("service onboarding should build");

    assert_eq!(outcome.projection.subject_id, subject_id);
    assert_eq!(outcome.projection.assurance_level, AssuranceLevel::High);
    assert!(outcome
        .narrative
        .iter()
        .any(|line| line.contains("identity_verification")));
}

#[test]
fn service_detailed_onboarding_surfaces_core_fact_ids() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let detailed_provider = MockPhase1ContinuityProvider::successful();
    let compatibility_provider = MockPhase1ContinuityProvider::successful();
    let request = OnboardingRequest::fixture(
        id("subject-service-onboarding-detailed"),
        author,
        ts("2026-05-29T00:00:00Z"),
    );

    let detailed = service
        .enroll_subject_detailed(request.clone(), &detailed_provider)
        .expect("detailed onboarding should build");
    let compatibility = service
        .enroll_subject(request, &compatibility_provider)
        .expect("compatibility onboarding should build");

    assert_eq!(detailed.workflow, compatibility);
    assert_eq!(detailed.subject_fact_id, id("fact-onboarding-0"));
    assert_eq!(detailed.device_binding_fact_id, id("fact-onboarding-1"));
    assert_eq!(detailed.identity_witness_fact_id, id("fact-onboarding-2"));
    assert_eq!(detailed.enrollment_fact_id, id("fact-onboarding-3"));
    assert_eq!(detailed.clinical_link_fact_id, id("fact-onboarding-4"));
    assert_eq!(detailed.payer_link_fact_id, id("fact-onboarding-5"));
}

#[test]
fn service_split_onboarding_steps_do_not_require_provider_or_payer_links() {
    let author = system_author();
    let subject_id: SubjectId = id("subject-service-split-onboarding");
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::successful();

    let subject = service.register_subject(RegisterSubjectRequest::fixture(
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    ));
    let device = service.bind_device(BindDeviceRequest::fixture(
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:01:00Z"),
    ));
    let continuity = service
        .enroll_continuity_reference(
            EnrollContinuityRequest::fixture(
                subject_id.clone(),
                author.clone(),
                ts("2026-05-29T00:02:00Z"),
            ),
            &provider,
        )
        .expect("continuity enrollment should build");

    assert_eq!(subject.subject_fact_id, id("fact-register-subject-0"));
    assert_eq!(subject.subject_id, subject_id);
    assert_eq!(device.device_binding_fact_id, id("fact-bind-device-0"));
    assert_eq!(
        continuity.enrollment_fact_id,
        id("fact-enroll-continuity-0")
    );
    assert_eq!(
        continuity.enrollment_ref,
        "mock-enrollment-subject-service-split-onboarding"
    );

    let mut facts = Vec::new();
    facts.extend(subject.workflow.slice.facts.clone());
    facts.extend(device.workflow.slice.facts.clone());
    facts.extend(continuity.workflow.slice.facts.clone());
    let projection = materialize_identity_state(subject_id.clone(), &facts);

    assert_eq!(projection.subject_id, subject_id);
    assert_eq!(
        projection.active_devices,
        vec!["device-passkey-1".to_string()]
    );
    assert!(projection.active_clinical_links.is_empty());
    assert!(projection.active_payer_links.is_empty());
}

#[test]
fn service_core_onboarding_uses_generated_ids_without_provider_or_payer_links() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let mut ids = DeterministicIdGenerator::new();

    let outcome = service
        .onboard_core_identity(
            CoreIdentityOnboardingRequest {
                subject_id: None,
                subject_id_prefix: "subject-production".to_string(),
                id_namespace: "core-onboarding".to_string(),
                authored_by: author,
                registered_at: ts("2026-05-29T00:00:00Z"),
                device_bound_at: ts("2026-05-29T00:01:00Z"),
                continuity_enrolled_at: ts("2026-05-29T00:02:00Z"),
                subject_kind: SubjectKind::HumanPerson,
                stable_profile: StableIdentityProfile {
                    legal_name: Some("Production Patient".to_string()),
                    date_of_birth: Some(Date("1991-02-03".to_string())),
                    demographic_attributes: Vec::new(),
                },
                device_ref: "device-production-passkey".to_string(),
                authenticator_type: AuthenticatorType::Passkey,
                device_assurance_level: AssuranceLevel::Medium,
                device_source_system: Some("AccountBootstrap".to_string()),
                modality: BiometricModality::Face,
            },
            &provider,
            &mut ids,
        )
        .expect("core onboarding should build");

    assert_eq!(outcome.subject_id, id("subject-production-0"));
    assert_eq!(
        outcome.registration.subject_fact_id,
        id("fact-core-onboarding-register-subject-0")
    );
    assert_eq!(
        outcome.device_binding.device_binding_fact_id,
        id("fact-core-onboarding-bind-device-0")
    );
    assert_eq!(
        outcome.continuity_enrollment.enrollment_fact_id,
        id("fact-core-onboarding-enroll-continuity-0")
    );
    assert_eq!(
        outcome.projection.active_devices,
        vec!["device-production-passkey".to_string()]
    );
    assert!(outcome.projection.active_clinical_links.is_empty());
    assert!(outcome.projection.active_payer_links.is_empty());
}

#[test]
fn service_core_onboarding_returns_parent_episode_with_child_part_of_relations() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let mut ids = DeterministicIdGenerator::new();

    let outcome = service
        .onboard_core_identity(
            CoreIdentityOnboardingRequest {
                subject_id: Some(id("subject-composed-onboarding")),
                subject_id_prefix: "subject-unused".to_string(),
                id_namespace: "composed-onboarding".to_string(),
                authored_by: author,
                registered_at: ts("2026-05-29T00:00:00Z"),
                device_bound_at: ts("2026-05-29T00:01:00Z"),
                continuity_enrolled_at: ts("2026-05-29T00:02:00Z"),
                subject_kind: SubjectKind::HumanPerson,
                stable_profile: StableIdentityProfile {
                    legal_name: Some("Composed Patient".to_string()),
                    date_of_birth: None,
                    demographic_attributes: Vec::new(),
                },
                device_ref: "device-composed-passkey".to_string(),
                authenticator_type: AuthenticatorType::Passkey,
                device_assurance_level: AssuranceLevel::Medium,
                device_source_system: Some("AccountBootstrap".to_string()),
                modality: BiometricModality::Face,
            },
            &provider,
            &mut ids,
        )
        .expect("core onboarding should build");

    let parent_id = id("episode-composed-onboarding-parent-0");
    let child_episode_ids = vec![
        outcome.registration.workflow.slice.episode.id.clone(),
        outcome.device_binding.workflow.slice.episode.id.clone(),
        outcome
            .continuity_enrollment
            .workflow
            .slice
            .episode
            .id
            .clone(),
    ];

    assert_eq!(outcome.parent_episode.id, parent_id);
    assert_eq!(
        outcome.parent_episode.label,
        "Initial identity onboarding".to_string()
    );
    assert_eq!(
        outcome
            .episode_relations
            .iter()
            .map(|relation| relation.id.clone())
            .collect::<Vec<_>>(),
        vec![
            id("relation-composed-onboarding-0"),
            id("relation-composed-onboarding-1"),
            id("relation-composed-onboarding-2"),
        ]
    );
    assert_eq!(
        outcome
            .episode_relations
            .iter()
            .map(|relation| relation.source_episode_id.clone())
            .collect::<Vec<_>>(),
        child_episode_ids
    );
    assert!(outcome.episode_relations.iter().all(|relation| {
        relation.target_episode_id == parent_id
            && relation.relation_type == EpisodeRelationType::PartOf
            && matches!(relation.status, EpisodeRelationStatus::Active)
    }));

    let mut facts = Vec::new();
    facts.extend(outcome.registration.workflow.slice.facts.clone());
    facts.extend(outcome.device_binding.workflow.slice.facts.clone());
    facts.extend(outcome.continuity_enrollment.workflow.slice.facts.clone());
    assert_eq!(
        outcome.projection,
        materialize_identity_state(id("subject-composed-onboarding"), &facts)
    );

    let mut repository = InMemoryIdentityRepository::new();
    repository
        .append_episode(outcome.parent_episode.clone())
        .expect("parent episode should append");
    repository
        .append_workflow_slice(outcome.registration.workflow.slice.clone())
        .expect("registration slice should append");
    repository
        .append_workflow_slice(outcome.device_binding.workflow.slice.clone())
        .expect("device slice should append");
    repository
        .append_workflow_slice(outcome.continuity_enrollment.workflow.slice.clone())
        .expect("continuity slice should append");
    for relation in outcome.episode_relations.clone() {
        repository
            .append_episode_relation(relation)
            .expect("episode relation should append");
    }

    assert_eq!(
        repository.child_episode_ids_for_parent(&parent_id, EpisodeRelationType::PartOf),
        child_episode_ids
    );
    assert_eq!(
        replay_identity_state_from_repository(id("subject-composed-onboarding"), &repository),
        outcome.projection
    );
}

#[test]
fn service_can_append_core_onboarding_composition_and_replay_repository_state() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let mut ids = DeterministicIdGenerator::new();
    let mut repository = InMemoryIdentityRepository::new();

    let onboarding = service
        .onboard_core_identity(
            CoreIdentityOnboardingRequest {
                subject_id: Some(id("subject-service-composition-append")),
                subject_id_prefix: "subject-unused".to_string(),
                id_namespace: "service-composition-append".to_string(),
                authored_by: author,
                registered_at: ts("2026-05-29T00:00:00Z"),
                device_bound_at: ts("2026-05-29T00:01:00Z"),
                continuity_enrolled_at: ts("2026-05-29T00:02:00Z"),
                subject_kind: SubjectKind::HumanPerson,
                stable_profile: StableIdentityProfile {
                    legal_name: Some("Composition Patient".to_string()),
                    date_of_birth: None,
                    demographic_attributes: Vec::new(),
                },
                device_ref: "device-service-composition".to_string(),
                authenticator_type: AuthenticatorType::Passkey,
                device_assurance_level: AssuranceLevel::Medium,
                device_source_system: Some("AccountBootstrap".to_string()),
                modality: BiometricModality::Face,
            },
            &provider,
            &mut ids,
        )
        .expect("core onboarding should build");
    let parent_id = onboarding.parent_episode.id.clone();
    let child_episode_ids = vec![
        onboarding.registration.workflow.slice.episode.id.clone(),
        onboarding.device_binding.workflow.slice.episode.id.clone(),
        onboarding
            .continuity_enrollment
            .workflow
            .slice
            .episode
            .id
            .clone(),
    ];

    let persisted = service
        .append_core_onboarding_and_replay(onboarding, &mut repository)
        .expect("composition should append and replay");

    assert_eq!(
        persisted.replayed_projection,
        persisted.onboarding.projection
    );
    assert_eq!(
        repository.child_episode_ids_for_parent(&parent_id, EpisodeRelationType::PartOf),
        child_episode_ids
    );
    assert_eq!(
        repository.all_episode_relations(),
        persisted.onboarding.episode_relations
    );
}

#[test]
fn service_can_append_workflows_and_replay_repository_state() {
    let author = system_author();
    let subject_id: SubjectId = id("subject-service-repository-replay");
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let mut repository = InMemoryIdentityRepository::new();
    let mut registration_ids = DeterministicIdGenerator::new();
    let mut device_ids = DeterministicIdGenerator::new();

    let registration = service.register_subject(RegisterSubjectRequest::with_generated_ids(
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
        SubjectKind::HumanPerson,
        StableIdentityProfile {
            legal_name: Some("Repository Patient".to_string()),
            date_of_birth: None,
            demographic_attributes: Vec::new(),
        },
        "repository-registration",
        &mut registration_ids,
    ));
    let device = service.bind_device(BindDeviceRequest::with_generated_ids(
        subject_id.clone(),
        author,
        ts("2026-05-29T00:01:00Z"),
        "device-repository-passkey".to_string(),
        AuthenticatorType::Passkey,
        AssuranceLevel::Medium,
        Some("AccountBootstrap".to_string()),
        "repository-device",
        &mut device_ids,
    ));

    let after_registration = service
        .append_workflow_and_replay(registration.workflow, &mut repository)
        .expect("registration should append");
    assert!(after_registration
        .replayed_projection
        .active_devices
        .is_empty());

    let after_device = service
        .append_workflow_and_replay(device.workflow, &mut repository)
        .expect("device binding should append");
    assert_eq!(
        after_device.replayed_projection.active_devices,
        vec!["device-repository-passkey".to_string()]
    );
    assert_eq!(
        after_device.replayed_projection,
        replay_identity_state_from_repository(subject_id, &repository)
    );
}

#[test]
fn service_can_assign_subject_id_during_registration() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let mut ids = DeterministicIdGenerator::new();
    let mut request = RegisterNewSubjectRequest::fixture(author, ts("2026-05-29T00:00:00Z"));
    request.subject_id_prefix = "subject-generated".to_string();
    request.id_namespace = "generated-registration".to_string();

    let outcome = service.register_new_subject(request, &mut ids);

    assert_eq!(outcome.subject_id, id("subject-generated-0"));
    assert_eq!(
        outcome.workflow.slice.episode.id,
        id("episode-generated-registration-0")
    );
    assert_eq!(outcome.subject_fact_id, id("fact-generated-registration-0"));
    assert_eq!(outcome.workflow.projection.subject_id, outcome.subject_id);
    assert!(outcome.workflow.slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::SubjectCreated {
            subject_kind: SubjectKind::HumanPerson,
            ..
        }
    )));
}

#[test]
fn service_links_provider_and_payer_identity_as_independent_optional_steps() {
    let author = system_author();
    let subject_id: SubjectId = id("subject-service-optional-links");
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });

    let provider_link = service.link_provider_identity(LinkProviderIdentityRequest::fixture(
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:03:00Z"),
    ));
    let payer_link = service.link_payer_identity(LinkPayerIdentityRequest::fixture(
        subject_id.clone(),
        author,
        ts("2026-05-29T00:04:00Z"),
    ));

    assert_eq!(
        provider_link.provider_link_fact_id,
        id("fact-link-provider-0")
    );
    assert_eq!(payer_link.payer_link_fact_id, id("fact-link-payer-0"));

    let mut facts = Vec::new();
    facts.extend(provider_link.workflow.slice.facts.clone());
    facts.extend(payer_link.workflow.slice.facts.clone());
    let projection = materialize_identity_state(subject_id, &facts);

    assert_eq!(projection.active_clinical_links.len(), 1);
    assert_eq!(projection.active_payer_links.len(), 1);
}

#[test]
fn service_facade_can_issue_and_verify_continuity_challenges() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author,
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let mut lifecycle = InMemoryNonceLifecycle::new();

    let challenge = service
        .issue_continuity_challenge(
            ContinuityChallengeRequest {
                challenge_id: id("challenge-service"),
                subject_id: id("subject-service-continuity"),
                enrollment_ref: "enrollment-service".to_string(),
                nonce: "nonce-service".to_string(),
                issued_at: ts("2026-05-29T00:00:00Z"),
                expires_at: ts("2026-05-29T00:10:00Z"),
                intended_action: Some(SensitiveAction::ExportCompleteRecord),
            },
            &mut lifecycle,
        )
        .expect("challenge should issue");
    let signed = provider
        .signed_assertion(challenge)
        .expect("mock provider should produce an assertion");

    assert!(matches!(
        service.verify_continuity_assertion(
            signed,
            &mut lifecycle,
            &provider.signature_verifier(),
            &ResultBasedAssuranceMapper,
            ts("2026-05-29T00:01:00Z"),
        ),
        ContinuityAssertionVerificationResult::Verified { .. }
    ));
}

#[test]
fn service_continuity_verification_can_emit_auditable_rejection_fact() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author,
    });
    let provider = MockPhase1ContinuityProvider::successful();
    let mut lifecycle = InMemoryNonceLifecycle::new();
    let challenge = service
        .issue_continuity_challenge(
            ContinuityChallengeRequest {
                challenge_id: id("challenge-service-rejection"),
                subject_id: id("subject-service-rejection"),
                enrollment_ref: "enrollment-service-rejection".to_string(),
                nonce: "nonce-service-rejection".to_string(),
                issued_at: ts("2026-05-29T00:00:00Z"),
                expires_at: ts("2026-05-29T00:10:00Z"),
                intended_action: Some(SensitiveAction::ExportCompleteRecord),
            },
            &mut lifecycle,
        )
        .expect("challenge should issue");
    let signed = provider
        .signed_assertion(challenge)
        .expect("mock provider should produce an assertion");
    let wrong_verifier = ExpectedSignatureVerifier {
        trusted_key_id: provider.key_id.clone(),
        expected_signature: b"wrong-signature".to_vec(),
    };

    let outcome = service.verify_continuity_assertion_with_audit(
        signed,
        ContinuityAssertionVerificationAuditRequest {
            subject_id: id("subject-service-rejection"),
            rejected_fact_id: id("fact-service-continuity-rejection"),
            verified_at: ts("2026-05-29T00:01:00Z"),
        },
        &mut lifecycle,
        &wrong_verifier,
        &ResultBasedAssuranceMapper,
    );

    assert_eq!(
        outcome.verification,
        ContinuityAssertionVerificationResult::Rejected {
            reason: ContinuityAssertionRejectionReason::InvalidSignature
        }
    );
    assert!(matches!(
        outcome
            .rejection_fact
            .expect("rejection fact should exist")
            .payload,
        FactPayload::ContinuityVerificationRejected {
            reason: ContinuityVerificationRejectionReason::InvalidSignature,
            ..
        }
    ));
}

#[test]
fn service_access_authorization_surfaces_policy_reasons_and_access_fact() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let provider = MockPhase1ContinuityProvider::failed();
    let mut lifecycle = InMemoryNonceLifecycle::new();

    let outcome = service
        .authorize_complete_record_export_step_up_detailed(
            CompleteRecordExportStepUpRequest::fixture(
                id("subject-service-access"),
                "enrollment-step-up".to_string(),
                author,
                ts("2026-05-29T00:00:00Z"),
            ),
            &provider,
            &mut lifecycle,
            &provider.signature_verifier(),
            &ResultBasedAssuranceMapper,
        )
        .expect("failed continuity still produces auditable access outcome");

    assert_eq!(
        outcome.policy_evaluation.decision,
        AccessDecisionResult::StepUpRequired
    );
    assert_eq!(
        outcome.policy_evaluation.reasons,
        vec![PolicyEvaluationReason::InsufficientContinuityAssurance]
    );
    assert_eq!(
        outcome.access_decision_fact_id,
        id("fact-export-access-decision")
    );
    assert!(outcome.workflow.slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::AccessDecision { decision, .. }
            if *decision == outcome.policy_evaluation.decision
    )));
}

#[test]
fn service_detailed_access_outcome_matches_compatibility_slice_shape() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let detailed_provider = MockPhase1ContinuityProvider::successful();
    let compatibility_provider = MockPhase1ContinuityProvider::successful();
    let mut detailed_lifecycle = InMemoryNonceLifecycle::new();
    let mut compatibility_lifecycle = InMemoryNonceLifecycle::new();
    let request = CompleteRecordExportStepUpRequest::fixture(
        id("subject-service-access-compat"),
        "enrollment-step-up".to_string(),
        author,
        ts("2026-05-29T00:00:00Z"),
    );

    let detailed = service
        .authorize_complete_record_export_step_up_detailed(
            request.clone(),
            &detailed_provider,
            &mut detailed_lifecycle,
            &detailed_provider.signature_verifier(),
            &ResultBasedAssuranceMapper,
        )
        .expect("detailed service call should build");
    let compatibility = service
        .authorize_complete_record_export_step_up(
            request,
            &compatibility_provider,
            &mut compatibility_lifecycle,
            &compatibility_provider.signature_verifier(),
            &ResultBasedAssuranceMapper,
        )
        .expect("compatibility service call should build");

    assert_eq!(detailed.workflow.slice, compatibility.slice);
    assert_eq!(detailed.workflow.projection, compatibility.projection);
    assert_eq!(detailed.workflow.narrative, compatibility.narrative);
}

#[test]
fn service_detailed_recovery_surfaces_path_and_follow_on_fact_ids() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let request = RecoveryRequest::approved_government_id_and_liveness(
        id("subject-service-recovery-detailed"),
        author,
        ts("2026-05-29T00:00:00Z"),
    );

    let detailed = service.recover_account_detailed(request.clone());
    let compatibility = service.recover_account(request);

    assert_eq!(detailed.workflow, compatibility);
    assert_eq!(detailed.path, RecoveryPath::ApprovedGovernmentIdAndLiveness);
    assert_eq!(
        detailed.recovery_event_fact_ids,
        vec![id("fact-recovery-approved-1")]
    );
    assert_eq!(
        detailed.access_decision_fact_id,
        Some(id("fact-recovery-approved-4"))
    );
    assert_eq!(
        detailed.device_revocation_fact_ids,
        vec![id("fact-recovery-approved-2")]
    );
    assert_eq!(
        detailed.device_establishment_fact_ids,
        vec![id("fact-recovery-approved-3")]
    );
}

#[test]
fn service_detailed_delegation_surfaces_authority_decision_and_revocation_ids() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let request = DelegationRequest::fixture(
        id("caregiver-service-detailed"),
        id("patient-service-detailed"),
        author,
        ts("2026-05-29T00:00:00Z"),
    );

    let detailed = service.delegate_authority_detailed(request.clone());
    let compatibility = service.delegate_authority(request);

    assert_eq!(detailed.workflow, compatibility);
    assert_eq!(
        detailed.authority_fact_id,
        Some(id("fact-delegation-authority"))
    );
    assert_eq!(
        detailed.access_decision_fact_id,
        Some(id("fact-delegation-3"))
    );
    assert_eq!(detailed.revocation_fact_id, Some(id("fact-delegation-4")));
}

#[test]
fn service_detailed_dispute_surfaces_reviewable_resolution_ids() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let request = IdentityDisputeResolutionRequest::contested_provider_link(
        id("subject-service-dispute-detailed"),
        DisputeResolutionOutcome::Rejected,
        author,
        ts("2026-05-29T00:00:00Z"),
    );

    let detailed = service.resolve_identity_dispute_detailed(request.clone());
    let compatibility = service.resolve_identity_dispute(request);

    assert_eq!(detailed.workflow, compatibility);
    assert_eq!(
        detailed.kind,
        IdentityDisputeResolutionKind::ContestedProviderLink {
            outcome: DisputeResolutionOutcome::Rejected
        }
    );
    assert_eq!(
        detailed.institutional_link_fact_ids,
        vec![id("fact-provider-link-dispute-0")]
    );
    assert_eq!(
        detailed.dispute_evidence_fact_ids,
        vec![
            id("fact-provider-link-dispute-1"),
            id("fact-provider-link-dispute-2"),
            id("fact-provider-link-dispute-3"),
        ]
    );
    assert_eq!(detailed.subject_graph_correction_fact_id, None);
    assert_eq!(detailed.witness_supersession_fact_id, None);
    assert_eq!(detailed.access_decision_fact_id, None);
}

#[test]
fn workflow_id_plan_controls_cross_fact_references() {
    let author = system_author();
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: author.clone(),
    });
    let mut request = DelegationRequest::fixture(
        id("caregiver-service"),
        id("patient-service"),
        author,
        ts("2026-05-29T00:00:00Z"),
    );
    request.id_plan =
        WorkflowIdPlan::deterministic("delegation-service", id("episode-delegation-service"), 5);

    let outcome = service.delegate_authority(request);
    let authority_fact_id = id("fact-delegation-service-2");
    assert!(outcome
        .slice
        .facts
        .iter()
        .any(|fact| fact.id == authority_fact_id));
    assert!(outcome.slice.facts.iter().any(|fact| matches!(
        &fact.payload,
        FactPayload::AccessDecision { relied_on_facts, .. }
            if relied_on_facts == &vec![authority_fact_id.clone()]
    )));
}

#[test]
fn clock_context_drives_policy_freshness() {
    let policy = default_policy_for_action(
        SensitiveAction::ExportCompleteRecord,
        id("complete-record-export-policy"),
    );
    let evidence = EvidenceSummary {
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
    let clock = FixedClock::new(ts("2026-05-29T00:10:01Z"));
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: system_author(),
    });

    let evaluation = service.evaluate_sensitive_action(SensitiveActionEvaluationRequest {
        policy,
        evidence,
        context: PolicyEvaluationContext::from_clock(&clock),
    });

    assert_eq!(evaluation.decision, AccessDecisionResult::StepUpRequired);
    assert_eq!(
        evaluation.reasons,
        vec![PolicyEvaluationReason::ContinuityStale]
    );
}

#[test]
fn service_evaluates_sensitive_action_from_policy_artifact() {
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: system_author(),
    });
    let artifact = PolicyArtifact::sensitive_action(
        id("complete-record-export-policy"),
        "v2",
        SensitiveAction::ExportCompleteRecord,
        Some(TimeInterval {
            start: ts("2026-05-01T00:00:00Z"),
            end: ts("2026-12-31T23:59:59Z"),
        }),
    )
    .with_title("Complete record export")
    .with_review(PolicyReview {
        reviewed_by: system_author(),
        reviewed_at: ts("2026-04-30T00:00:00Z"),
        notes: Some("approved for service boundary test".to_string()),
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

    let evaluation = service.evaluate_sensitive_action_policy_artifact(
        SensitiveActionPolicyArtifactEvaluationRequest {
            policy_artifact: artifact,
            evidence,
            context: PolicyEvaluationContext::new(Some(ts("2026-05-29T00:01:00Z"))),
        },
    );

    assert_eq!(evaluation.decision, AccessDecisionResult::Allowed);
    assert!(evaluation.reasons.is_empty());
    assert_eq!(
        evaluation.policy_refs,
        vec![id("complete-record-export-policy@v2")]
    );
}

#[test]
fn service_policy_artifact_evaluation_applies_artifact_lifecycle_gates() {
    let service = IdentityWorkflowService::new(FenTranslator {
        system_author: system_author(),
    });
    let artifact = PolicyArtifact::sensitive_action(
        id("complete-record-export-policy"),
        "draft",
        SensitiveAction::ExportCompleteRecord,
        Some(TimeInterval {
            start: ts("2026-06-01T00:00:00Z"),
            end: ts("2026-12-31T23:59:59Z"),
        }),
    )
    .with_status(PolicyArtifactStatus::Draft);
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

    let evaluation = service.evaluate_sensitive_action_policy_artifact(
        SensitiveActionPolicyArtifactEvaluationRequest {
            policy_artifact: artifact,
            evidence,
            context: PolicyEvaluationContext::new(Some(ts("2026-05-29T00:01:00Z"))),
        },
    );

    assert_eq!(
        evaluation.decision,
        AccessDecisionResult::ManualReviewRequired
    );
    assert_eq!(
        evaluation.reasons,
        vec![
            PolicyEvaluationReason::PolicyArtifactNotActive,
            PolicyEvaluationReason::PolicyNotYetEffective,
        ]
    );
}
