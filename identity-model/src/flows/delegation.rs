use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRequest {
    pub actor_subject_id: SubjectId,
    pub target_subject_id: SubjectId,
    pub authored_by: Author,
    pub started_at: Timestamp,
    pub id_plan: WorkflowIdPlan,
    pub scope: AuthorityScope,
    pub valid_period: Option<TimeInterval>,
    pub evidence_ref: Option<DocumentRef>,
}

impl DelegationRequest {
    pub fn with_generated_ids(
        actor_subject_id: SubjectId,
        target_subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
        scope: AuthorityScope,
        valid_period: Option<TimeInterval>,
        evidence_ref: Option<DocumentRef>,
        id_namespace: &str,
        id_generator: &mut impl IdGenerator,
    ) -> Self {
        Self {
            actor_subject_id,
            target_subject_id,
            authored_by,
            started_at,
            id_plan: WorkflowIdPlan::generated(id_generator, id_namespace, 5),
            scope,
            valid_period,
            evidence_ref,
        }
    }

    pub fn fixture(
        actor_subject_id: SubjectId,
        target_subject_id: SubjectId,
        authored_by: Author,
        started_at: Timestamp,
    ) -> Self {
        Self {
            actor_subject_id,
            target_subject_id,
            authored_by,
            started_at: started_at.clone(),
            id_plan: WorkflowIdPlan::deterministic_with_fact_overrides(
                "delegation",
                ProblemEpisodeId("episode-delegation".to_string()),
                5,
                vec![(2, FactId("fact-delegation-authority".to_string()))],
            ),
            scope: AuthorityScope {
                permitted_actions: vec![
                    AuthorizedAction::ViewRecord,
                    AuthorizedAction::ShareRecord,
                ],
                constrained_by_policy: vec![PolicyRef("caregiver-delegation-policy".to_string())],
            },
            valid_period: Some(TimeInterval {
                start: started_at,
                end: Timestamp("2026-12-31T23:59:59Z".to_string()),
            }),
            evidence_ref: Some("delegation-document".to_string()),
        }
    }
}

pub fn delegation_vertical_slice_from_request(
    request: DelegationRequest,
    translator: &FenTranslator,
) -> IdentityWorkflowSlice {
    let episode = delegation_episode(
        request.id_plan.episode_id.clone(),
        request.target_subject_id.clone(),
        request.authored_by.clone(),
        request.started_at.clone(),
    );
    let authority_fact_id = request.id_plan.fact_id(2);
    let policy_refs = request.scope.constrained_by_policy.clone();

    let drafts = vec![
        translator.subject_created(
            request.actor_subject_id.clone(),
            SubjectKind::HumanPerson,
            StableIdentityProfile {
                legal_name: Some("Example Caregiver".to_string()),
                date_of_birth: None,
                demographic_attributes: Vec::new(),
            },
            request.started_at.clone(),
        ),
        translator.subject_created(
            request.target_subject_id.clone(),
            SubjectKind::HumanPerson,
            StableIdentityProfile {
                legal_name: Some("Example Patient".to_string()),
                date_of_birth: None,
                demographic_attributes: Vec::new(),
            },
            request.started_at.clone(),
        ),
        translator.authority_relationship_established(
            request.target_subject_id.clone(),
            request.started_at.clone(),
            request.actor_subject_id,
            request.target_subject_id.clone(),
            AuthorityType::CaregiverDelegation,
            request.scope,
            request.valid_period,
            request.evidence_ref,
        ),
        translator.access_decision(
            request.target_subject_id.clone(),
            request.started_at.clone(),
            SensitiveAction::ShareRecord,
            AccessDecisionResult::Allowed,
            vec![authority_fact_id.clone()],
            policy_refs,
        ),
        translator.authority_relationship_revoked(
            request.target_subject_id,
            request.started_at.clone(),
            authority_fact_id,
            Some("caregiver access ended".to_string()),
        ),
    ];

    slice_from_drafts_with_id_plan(
        episode,
        drafts,
        vec![
            FactRole::IdentityAnchor,
            FactRole::IdentityAnchor,
            FactRole::AuthorityEvidence,
            FactRole::AccessDecisionEvidence,
            FactRole::AuthorityEvidence,
        ],
        request.authored_by,
        request.started_at,
        &request.id_plan,
    )
}

pub fn delegation_vertical_slice(
    actor_subject_id: SubjectId,
    target_subject_id: SubjectId,
    translator: &FenTranslator,
    authored_by: Author,
    started_at: Timestamp,
) -> IdentityWorkflowSlice {
    delegation_vertical_slice_from_request(
        DelegationRequest::fixture(actor_subject_id, target_subject_id, authored_by, started_at),
        translator,
    )
}
