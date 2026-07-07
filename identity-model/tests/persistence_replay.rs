use identity_model::*;

mod common;
use common::*;

#[test]
fn append_only_repository_replays_workflow_facts_into_projection() {
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let provider = MockPhase1ContinuityProvider::successful();
    let subject_id: SubjectId = id("subject-replay-onboarding");
    let onboarding = onboarding_vertical_slice(
        subject_id.clone(),
        &provider,
        &translator,
        author,
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("onboarding slice should build");

    let mut repository = InMemoryIdentityRepository::new();
    repository
        .append_workflow_slice(onboarding.clone())
        .expect("slice should append");

    let replayed = replay_identity_state_from_repository(subject_id.clone(), &repository);
    let direct = materialize_identity_state(subject_id, &onboarding.facts);

    assert_eq!(replayed, direct);
    assert_eq!(repository.all_episodes(), vec![onboarding.episode.clone()]);
    assert_eq!(repository.all_memberships(), onboarding.memberships);
}

#[test]
fn workflow_slice_append_rejects_duplicates_atomically() {
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let provider = MockPhase1ContinuityProvider::successful();
    let subject_id: SubjectId = id("subject-replay-atomic");
    let onboarding = onboarding_vertical_slice(
        subject_id.clone(),
        &provider,
        &translator,
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("onboarding slice should build");
    let mut conflicting = bind_device_slice_from_request(
        BindDeviceRequest::fixture(subject_id, author, ts("2026-05-29T00:01:00Z")),
        &translator,
    );
    conflicting.episode.id = id("episode-conflicting-device");
    conflicting.facts[0].id = onboarding.facts[0].id.clone();

    let mut repository = InMemoryIdentityRepository::new();
    repository
        .append_workflow_slice(onboarding.clone())
        .expect("initial slice should append");
    let original_episodes = repository.all_episodes();
    let original_facts = repository.all_facts();
    let original_memberships = repository.all_memberships();

    assert_eq!(
        repository.append_workflow_slice(conflicting),
        Err(RepositoryError::DuplicateFactId)
    );
    assert_eq!(repository.all_episodes(), original_episodes);
    assert_eq!(repository.all_facts(), original_facts);
    assert_eq!(repository.all_memberships(), original_memberships);
}

#[test]
fn append_only_repository_rejects_duplicate_ids_without_mutating_history() {
    let subject_id: SubjectId = id("subject-replay-duplicates");
    let first = fact(
        "duplicate-fact",
        subject_id.clone(),
        FactPayload::DeviceBindingEstablished {
            device_ref: "device-1".to_string(),
            authenticator_type: AuthenticatorType::Passkey,
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let second = fact(
        "duplicate-fact",
        subject_id.clone(),
        FactPayload::DeviceBindingRevoked {
            device_ref: "device-1".to_string(),
            reason: Some("lost".to_string()),
        },
    );
    let mut repository = InMemoryIdentityRepository::new();

    assert_eq!(repository.append_fact(first.clone()), Ok(()));
    assert_eq!(
        repository.append_fact(second),
        Err(RepositoryError::DuplicateFactId)
    );
    assert_eq!(repository.all_facts(), vec![first]);
}

#[test]
fn membership_repository_finds_episode_edges_for_a_fact() {
    let subject_id: SubjectId = id("subject-membership-lookup");
    let author = system_author();
    let mut repository = InMemoryIdentityRepository::new();
    let episode_a = access_authorization_episode(
        id("episode-access-a"),
        subject_id.clone(),
        SensitiveAction::ExportCompleteRecord,
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let episode_b = access_authorization_episode(
        id("episode-access-b"),
        subject_id,
        SensitiveAction::ShareRecord,
        author.clone(),
        ts("2026-05-29T00:05:00Z"),
    );
    let fact_id: FactId = id("shared-continuity-fact");
    let membership_a = episode_membership(
        id("membership-a"),
        fact_id.clone(),
        episode_a.id.clone(),
        FactRole::ContinuityWitness,
        author.clone(),
        ts("2026-05-29T00:01:00Z"),
    );
    let membership_b = episode_membership(
        id("membership-b"),
        fact_id.clone(),
        episode_b.id.clone(),
        FactRole::ContinuityWitness,
        author,
        ts("2026-05-29T00:06:00Z"),
    );

    repository
        .append_episode(episode_a)
        .expect("episode a should append");
    repository
        .append_episode(episode_b)
        .expect("episode b should append");
    repository
        .append_membership(membership_a.clone())
        .expect("membership a should append");
    repository
        .append_membership(membership_b.clone())
        .expect("membership b should append");

    assert_eq!(
        repository.memberships_for_fact(&fact_id),
        vec![membership_a, membership_b]
    );
}

#[test]
fn episode_relation_repository_tracks_part_of_children_for_parent_episode() {
    let subject_id: SubjectId = id("subject-relation-lookup");
    let author = system_author();
    let parent = identity_verification_episode(
        id("episode-onboarding-parent"),
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let registration = identity_verification_episode(
        id("episode-register-subject"),
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:01:00Z"),
    );
    let device = identity_verification_episode(
        id("episode-bind-device"),
        subject_id,
        author.clone(),
        ts("2026-05-29T00:02:00Z"),
    );
    let registration_part_of = episode_relation(
        id("relation-registration-parent"),
        registration.id.clone(),
        parent.id.clone(),
        EpisodeRelationType::PartOf,
        author.clone(),
        ts("2026-05-29T00:01:00Z"),
    );
    let device_part_of = episode_relation(
        id("relation-device-parent"),
        device.id.clone(),
        parent.id.clone(),
        EpisodeRelationType::PartOf,
        author,
        ts("2026-05-29T00:02:00Z"),
    );
    let mut repository = InMemoryIdentityRepository::new();

    repository
        .append_episode(parent.clone())
        .expect("parent episode should append");
    repository
        .append_episode(registration.clone())
        .expect("registration episode should append");
    repository
        .append_episode(device.clone())
        .expect("device episode should append");
    repository
        .append_episode_relation(registration_part_of.clone())
        .expect("registration relation should append");
    repository
        .append_episode_relation(device_part_of.clone())
        .expect("device relation should append");

    assert_eq!(
        repository.relations_for_parent_episode(&parent.id),
        vec![registration_part_of.clone(), device_part_of]
    );
    assert_eq!(
        repository.relations_for_child_episode(&registration.id),
        vec![registration_part_of]
    );
    assert_eq!(
        repository.child_episode_ids_for_parent(&parent.id, EpisodeRelationType::PartOf),
        vec![registration.id, device.id]
    );
}

#[test]
fn episode_relation_repository_rejects_duplicate_relation_ids_without_mutating_history() {
    let author = system_author();
    let first = episode_relation(
        id("relation-duplicate"),
        id("episode-child-a"),
        id("episode-parent"),
        EpisodeRelationType::PartOf,
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let duplicate = episode_relation(
        id("relation-duplicate"),
        id("episode-child-b"),
        id("episode-parent"),
        EpisodeRelationType::PartOf,
        author,
        ts("2026-05-29T00:01:00Z"),
    );
    let mut repository = InMemoryIdentityRepository::new();

    assert_eq!(repository.append_episode_relation(first.clone()), Ok(()));
    assert_eq!(
        repository.append_episode_relation(duplicate),
        Err(RepositoryError::DuplicateRelationId)
    );
    assert_eq!(repository.all_episode_relations(), vec![first]);
}

#[test]
fn episode_composition_append_persists_parent_children_and_relations_atomically() {
    let subject_id: SubjectId = id("subject-composition-append");
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let parent = parent_onboarding_episode(
        id("episode-composition-parent"),
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let registration = register_subject_slice_from_request(
        RegisterSubjectRequest::fixture(
            subject_id.clone(),
            author.clone(),
            ts("2026-05-29T00:01:00Z"),
        ),
        &translator,
    );
    let device = bind_device_slice_from_request(
        BindDeviceRequest::fixture(
            subject_id.clone(),
            author.clone(),
            ts("2026-05-29T00:02:00Z"),
        ),
        &translator,
    );
    let relations = vec![
        episode_relation(
            id("relation-registration-composition"),
            registration.episode.id.clone(),
            parent.id.clone(),
            EpisodeRelationType::PartOf,
            author.clone(),
            ts("2026-05-29T00:01:00Z"),
        ),
        episode_relation(
            id("relation-device-composition"),
            device.episode.id.clone(),
            parent.id.clone(),
            EpisodeRelationType::PartOf,
            author,
            ts("2026-05-29T00:02:00Z"),
        ),
    ];
    let expected_projection = materialize_identity_state(
        subject_id.clone(),
        &[registration.facts.clone(), device.facts.clone()].concat(),
    );
    let mut repository = InMemoryIdentityRepository::new();

    repository
        .append_episode_composition(
            parent.clone(),
            vec![registration.clone(), device.clone()],
            relations.clone(),
        )
        .expect("composition should append");

    assert_eq!(
        repository.all_episodes(),
        vec![
            parent.clone(),
            registration.episode.clone(),
            device.episode.clone()
        ]
    );
    assert_eq!(repository.all_episode_relations(), relations);
    assert_eq!(
        repository.child_episode_ids_for_parent(&parent.id, EpisodeRelationType::PartOf),
        vec![registration.episode.id, device.episode.id]
    );
    assert_eq!(
        replay_identity_state_from_repository(subject_id, &repository),
        expected_projection
    );
}

#[test]
fn episode_composition_append_rejects_duplicate_parent_episode_without_mutating_history() {
    let subject_id: SubjectId = id("subject-composition-parent-duplicate");
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let parent = parent_onboarding_episode(
        id("episode-composition-duplicate-parent"),
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let registration = register_subject_slice_from_request(
        RegisterSubjectRequest::fixture(
            subject_id.clone(),
            author.clone(),
            ts("2026-05-29T00:01:00Z"),
        ),
        &translator,
    );
    let relation = episode_relation(
        id("relation-duplicate-parent-composition"),
        registration.episode.id.clone(),
        parent.id.clone(),
        EpisodeRelationType::PartOf,
        author,
        ts("2026-05-29T00:01:00Z"),
    );
    let mut repository = InMemoryIdentityRepository::new();
    repository
        .append_episode(parent.clone())
        .expect("existing parent should append");
    let original_episodes = repository.all_episodes();
    let original_facts = repository.all_facts();
    let original_memberships = repository.all_memberships();
    let original_relations = repository.all_episode_relations();

    assert_eq!(
        repository.append_episode_composition(parent, vec![registration], vec![relation]),
        Err(RepositoryError::DuplicateEpisodeId)
    );
    assert_eq!(repository.all_episodes(), original_episodes);
    assert_eq!(repository.all_facts(), original_facts);
    assert_eq!(repository.all_memberships(), original_memberships);
    assert_eq!(repository.all_episode_relations(), original_relations);
}

#[test]
fn episode_composition_append_rejects_duplicate_relation_ids_without_mutating_history() {
    let subject_id: SubjectId = id("subject-composition-relation-duplicate");
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let parent = parent_onboarding_episode(
        id("episode-composition-relation-parent"),
        subject_id.clone(),
        author.clone(),
        ts("2026-05-29T00:00:00Z"),
    );
    let registration = register_subject_slice_from_request(
        RegisterSubjectRequest::fixture(subject_id, author.clone(), ts("2026-05-29T00:01:00Z")),
        &translator,
    );
    let relations = vec![
        episode_relation(
            id("relation-duplicate-in-composition"),
            registration.episode.id.clone(),
            parent.id.clone(),
            EpisodeRelationType::PartOf,
            author.clone(),
            ts("2026-05-29T00:01:00Z"),
        ),
        episode_relation(
            id("relation-duplicate-in-composition"),
            registration.episode.id.clone(),
            parent.id.clone(),
            EpisodeRelationType::PartOf,
            author,
            ts("2026-05-29T00:02:00Z"),
        ),
    ];
    let mut repository = InMemoryIdentityRepository::new();

    assert_eq!(
        repository.append_episode_composition(parent, vec![registration], relations),
        Err(RepositoryError::DuplicateRelationId)
    );
    assert!(repository.all_episodes().is_empty());
    assert!(repository.all_facts().is_empty());
    assert!(repository.all_memberships().is_empty());
    assert!(repository.all_episode_relations().is_empty());
}

#[test]
fn replay_respects_revoked_contested_expired_and_superseded_history() {
    let subject_id: SubjectId = id("subject-replay-history");
    let clinical_link_id: FactId = id("clinical-link-replay");
    let active_witness = fact(
        "active-witness",
        subject_id.clone(),
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::GovernmentIdVerification,
            target_subject_id: subject_id.clone(),
            assurance_level: AssuranceLevel::High,
            evidence_ref: None,
            expires_at: None,
            context: IdentityWitnessContext::default(),
        },
    );
    let mut superseded_witness = fact(
        "superseded-witness",
        subject_id.clone(),
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::DemographicMatch,
            target_subject_id: subject_id.clone(),
            assurance_level: AssuranceLevel::Medium,
            evidence_ref: None,
            expires_at: None,
            context: IdentityWitnessContext::default(),
        },
    );
    superseded_witness.status = FactStatus::Superseded {
        superseded_by: system_author(),
        superseded_at: TemporalAnchor::Point(ts("2026-05-29T00:00:00Z")),
        replaced_by: Some(id("active-witness")),
        reason: SupersessionReason::StrongerIdentityEvidence,
    };
    let facts = vec![
        superseded_witness,
        active_witness,
        fact(
            "device-binding",
            subject_id.clone(),
            FactPayload::DeviceBindingEstablished {
                device_ref: "device-replay".to_string(),
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: AssuranceLevel::Medium,
            },
        ),
        fact(
            "device-revocation",
            subject_id.clone(),
            FactPayload::DeviceBindingRevoked {
                device_ref: "device-replay".to_string(),
                reason: Some("lost".to_string()),
            },
        ),
        fact(
            "clinical-link-replay",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkEstablished {
                provider_org: "Example Health".to_string(),
                external_patient_ref: ExternalRef {
                    system: ExternalSystem::Fhir,
                    resource_type: Some("Patient".to_string()),
                    resource_id: "patient-replay".to_string(),
                    uri: None,
                },
                match_confidence: MatchConfidence::High,
            },
        ),
        fact(
            "clinical-link-contested",
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id: clinical_link_id.clone(),
                reason: Some("wrong chart suspected".to_string()),
            },
        ),
        fact(
            "expired-payer",
            subject_id.clone(),
            FactPayload::PayerIdentityLinkEstablished {
                payer: "Example Payer".to_string(),
                member_ref: "member-replay".to_string(),
                effective_period: Some(TimeInterval {
                    start: ts("2026-01-01T00:00:00Z"),
                    end: ts("2026-01-31T23:59:59Z"),
                }),
            },
        ),
    ];
    let mut repository = InMemoryIdentityRepository::new();
    for fact in facts {
        repository.append_fact(fact).expect("fact should append");
    }

    let replayed = replay_identity_state_from_repository_at(
        subject_id,
        &repository,
        &ts("2026-06-01T00:00:00Z"),
    );

    assert_eq!(replayed.assurance_level, AssuranceLevel::High);
    assert!(replayed.active_devices.is_empty());
    assert!(replayed.active_clinical_links.is_empty());
    assert!(replayed.active_payer_links.is_empty());
    assert_eq!(replayed.unresolved_disputes, vec![clinical_link_id]);
}
