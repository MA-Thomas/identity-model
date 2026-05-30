use super::*;

pub(super) fn slice_from_drafts_with_id_plan(
    episode: ProblemEpisode,
    drafts: Vec<FactDraft>,
    roles: Vec<FactRole>,
    authored_by: Author,
    authored_at: Timestamp,
    id_plan: &WorkflowIdPlan,
) -> IdentityWorkflowSlice {
    debug_assert_eq!(drafts.len(), roles.len());
    debug_assert_eq!(drafts.len(), id_plan.fact_ids.len());
    debug_assert_eq!(drafts.len(), id_plan.membership_ids.len());

    let facts: Vec<Fact> = drafts
        .into_iter()
        .enumerate()
        .map(|(index, draft)| draft.into_fact(id_plan.fact_id(index)))
        .collect();
    let memberships = facts
        .iter()
        .zip(roles)
        .enumerate()
        .map(|(index, (fact, role))| {
            episode_membership(
                id_plan.membership_id(index),
                fact.id.clone(),
                episode.id.clone(),
                role,
                authored_by.clone(),
                authored_at.clone(),
            )
        })
        .collect();

    IdentityWorkflowSlice {
        episode,
        facts,
        memberships,
    }
}
