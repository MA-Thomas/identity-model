use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityDisputeResolutionKind {
    ContestedProviderLink {
        outcome: DisputeResolutionOutcome,
    },
    DuplicateSubjectMerge {
        duplicate_subject_id: SubjectId,
    },
    IncorrectMergeSplit {
        restored_subject_ids: Vec<SubjectId>,
    },
    WitnessSupersession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDisputeResolutionRequest {
    pub subject_id: SubjectId,
    pub kind: IdentityDisputeResolutionKind,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
}

impl IdentityDisputeResolutionRequest {
    pub fn with_generated_ids(
        subject_id: SubjectId,
        kind: IdentityDisputeResolutionKind,
        authored_by: Author,
        started_at: Timestamp,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        let fact_count = kind.fact_count();

        Self {
            subject_id,
            kind,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, fact_count),
        }
    }

    pub fn contested_provider_link(
        subject_id: SubjectId,
        outcome: DisputeResolutionOutcome,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id,
            kind: IdentityDisputeResolutionKind::ContestedProviderLink { outcome },
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "provider-link-dispute",
                ProblemEpisodeId("episode-provider-link-dispute".to_string()),
                4,
            ),
        }
    }

    pub fn duplicate_subject_merge(
        surviving_subject_id: SubjectId,
        duplicate_subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id: surviving_subject_id,
            kind: IdentityDisputeResolutionKind::DuplicateSubjectMerge {
                duplicate_subject_id,
            },
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "subject-merge",
                ProblemEpisodeId("episode-duplicate-subject-merge".to_string()),
                2,
            ),
        }
    }

    pub fn incorrect_merge_split(
        prior_subject_id: SubjectId,
        restored_subject_ids: Vec<SubjectId>,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id: prior_subject_id,
            kind: IdentityDisputeResolutionKind::IncorrectMergeSplit {
                restored_subject_ids,
            },
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "subject-split",
                ProblemEpisodeId("episode-incorrect-merge-split".to_string()),
                2,
            ),
        }
    }

    pub fn witness_supersession(
        subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            subject_id,
            kind: IdentityDisputeResolutionKind::WitnessSupersession,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::deterministic(
                "witness-supersession",
                ProblemEpisodeId("episode-witness-supersession".to_string()),
                3,
            ),
        }
    }
}

impl IdentityDisputeResolutionKind {
    fn fact_count(&self) -> usize {
        match self {
            IdentityDisputeResolutionKind::ContestedProviderLink { .. } => 4,
            IdentityDisputeResolutionKind::DuplicateSubjectMerge { .. } => 2,
            IdentityDisputeResolutionKind::IncorrectMergeSplit { .. } => 2,
            IdentityDisputeResolutionKind::WitnessSupersession => 3,
        }
    }
}

pub fn identity_dispute_resolution_slice_from_request(
    request: IdentityDisputeResolutionRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = dispute_resolution_episode(
        request.id_plan.episode_id.clone(),
        request.subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );

    match request.kind.clone() {
        IdentityDisputeResolutionKind::ContestedProviderLink { outcome } => {
            contested_provider_link_slice(request, outcome, episode, translator)
        }
        IdentityDisputeResolutionKind::DuplicateSubjectMerge {
            duplicate_subject_id,
        } => duplicate_subject_merge_slice_from_request(
            request,
            duplicate_subject_id.clone(),
            episode,
            translator,
        ),
        IdentityDisputeResolutionKind::IncorrectMergeSplit {
            restored_subject_ids,
        } => incorrect_merge_split_slice_from_request(
            request,
            restored_subject_ids.clone(),
            episode,
            translator,
        ),
        IdentityDisputeResolutionKind::WitnessSupersession => {
            witness_supersession_slice_from_request(request, episode, translator)
        }
    }
}

pub fn contested_provider_link_resolution_slice(
    subject_id: SubjectId,
    outcome: DisputeResolutionOutcome,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    identity_dispute_resolution_slice_from_request(
        IdentityDisputeResolutionRequest::contested_provider_link(
            subject_id,
            outcome,
            authored_by,
            started_at,
        ),
        translator,
    )
}

pub fn duplicate_subject_merge_slice(
    surviving_subject_id: SubjectId,
    duplicate_subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    identity_dispute_resolution_slice_from_request(
        IdentityDisputeResolutionRequest::duplicate_subject_merge(
            surviving_subject_id,
            duplicate_subject_id,
            authored_by,
            started_at,
        ),
        translator,
    )
}

pub fn incorrect_merge_split_slice(
    prior_subject_id: SubjectId,
    restored_subject_ids: Vec<SubjectId>,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    identity_dispute_resolution_slice_from_request(
        IdentityDisputeResolutionRequest::incorrect_merge_split(
            prior_subject_id,
            restored_subject_ids,
            authored_by,
            started_at,
        ),
        translator,
    )
}

pub fn witness_supersession_slice(
    subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    identity_dispute_resolution_slice_from_request(
        IdentityDisputeResolutionRequest::witness_supersession(subject_id, authored_by, started_at),
        translator,
    )
}

fn contested_provider_link_slice(
    request: IdentityDisputeResolutionRequest,
    outcome: DisputeResolutionOutcome,
    episode: ProblemEpisode,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let link_fact_id = request.id_plan.fact_id(0);
    let drafts = vec![
        translator.clinical_identity_link_established(
            request.subject_id.clone(),
            request.started_at.clone(),
            "Example Health".to_string(),
            ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-possibly-incorrect".to_string(),
                uri: None,
            },
            MatchConfidence::Ambiguous,
            Some("FHIRLinker".to_string()),
        ),
        translator.clinical_identity_link_contested(
            request.subject_id.clone(),
            request.started_at.clone(),
            link_fact_id.clone(),
            Some("patient reports wrong chart link".to_string()),
        ),
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::InPersonClinicVerification,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("clinic-resolution-note".to_string()),
            None,
            Some("ClinicStaff".to_string()),
        ),
        translator.clinical_identity_link_dispute_resolved(
            request.subject_id.clone(),
            request.started_at.clone(),
            link_fact_id,
            outcome,
            Some("resolved by clinic registration staff".to_string()),
        ),
    ];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![
            FactRole::InstitutionalLink,
            FactRole::DisputeEvidence,
            FactRole::IdentityWitness,
            FactRole::DisputeEvidence,
        ],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

fn duplicate_subject_merge_slice_from_request(
    request: IdentityDisputeResolutionRequest,
    duplicate_subject_id: SubjectId,
    episode: ProblemEpisode,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let drafts = vec![
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::DemographicMatch,
            request.subject_id.clone(),
            AssuranceLevel::Medium,
            Some("duplicate-subject-review".to_string()),
            None,
            Some("FENIdentityResolution".to_string()),
        ),
        translator.duplicate_subject_merge_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.subject_id.clone(),
            vec![duplicate_subject_id],
            SubjectGraphCorrectionReason::DuplicateSubject,
            vec!["duplicate-subject-review".to_string()],
        ),
    ];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::DisputeEvidence, FactRole::DisputeEvidence],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

fn incorrect_merge_split_slice_from_request(
    request: IdentityDisputeResolutionRequest,
    restored_subject_ids: Vec<SubjectId>,
    episode: ProblemEpisode,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let drafts = vec![
        translator.identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::ProviderAttestation,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("incorrect-merge-review".to_string()),
            None,
            Some("ClinicStaff".to_string()),
        ),
        translator.incorrect_merge_split_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            request.subject_id.clone(),
            restored_subject_ids,
            SubjectGraphCorrectionReason::IncorrectMerge,
            vec!["incorrect-merge-review".to_string()],
        ),
    ];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![FactRole::DisputeEvidence, FactRole::DisputeEvidence],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

fn witness_supersession_slice_from_request(
    request: IdentityDisputeResolutionRequest,
    episode: ProblemEpisode,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let old_witness = translator
        .identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::DemographicMatch,
            request.subject_id.clone(),
            AssuranceLevel::Medium,
            Some("weak-demographic-match".to_string()),
            None,
            Some("FENIdentityResolution".to_string()),
        )
        .into_fact(request.id_plan.fact_id(0));
    let new_witness = translator
        .identity_witness_recorded(
            request.subject_id.clone(),
            request.started_at.clone(),
            IdentityWitnessType::GovernmentIdVerification,
            request.subject_id.clone(),
            AssuranceLevel::High,
            Some("government-id-document".to_string()),
            None,
            Some("IdentityProofingVendor".to_string()),
        )
        .into_fact(request.id_plan.fact_id(1));
    let supersession = translator
        .identity_witness_superseded(
            request.subject_id,
            request.started_at.clone(),
            old_witness.id.clone(),
            new_witness.id.clone(),
            SupersessionReason::StrongerIdentityEvidence,
        )
        .into_fact(request.id_plan.fact_id(2));

    let mut facts = vec![old_witness, new_witness, supersession];
    facts[0].status = FactStatus::Superseded {
        superseded_by: request.authored_by.clone(),
        superseded_at: TemporalAnchor::Point(request.started_at.clone()),
        replaced_by: Some(facts[1].id.clone()),
        reason: SupersessionReason::StrongerIdentityEvidence,
    };

    let memberships = facts
        .iter()
        .zip([
            FactRole::IdentityWitness,
            FactRole::IdentityWitness,
            FactRole::DisputeEvidence,
        ])
        .enumerate()
        .map(|(index, (fact, role))| {
            episode_membership(
                request.id_plan.membership_id(index),
                fact.id.clone(),
                episode.id.clone(),
                role,
                request.authored_by.clone(),
                request.started_at.clone(),
            )
        })
        .collect();

    IdentityWorkflowSlice {
        episode,
        facts,
        memberships,
    }
}
