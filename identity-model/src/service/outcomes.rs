use super::WorkflowOutcome;
use crate::fen::{FactId, FactPayload, SubjectId};
use crate::flows::IdentityWorkflowSlice;
use crate::materialized::project_identity_history;
use crate::narrative::workflow_narrative_lines;

pub(super) fn workflow_outcome(
    subject_id: SubjectId,
    slice: IdentityWorkflowSlice,
) -> WorkflowOutcome {
    let projection = project_identity_history(subject_id, &slice.facts);
    let narrative = workflow_narrative_lines(&slice);

    WorkflowOutcome {
        slice,
        projection,
        narrative,
    }
}

pub(super) fn first_fact_id_matching(
    slice: &IdentityWorkflowSlice,
    matches_payload: impl Fn(&FactPayload) -> bool,
) -> Option<FactId> {
    slice
        .facts
        .iter()
        .find(|fact| matches_payload(&fact.payload))
        .map(|fact| fact.id.clone())
}

pub(super) fn required_fact_id_matching(
    slice: &IdentityWorkflowSlice,
    matches_payload: impl Fn(&FactPayload) -> bool,
) -> FactId {
    first_fact_id_matching(slice, matches_payload)
        .expect("workflow should include expected fact payload")
}

pub(super) fn fact_ids_matching(
    slice: &IdentityWorkflowSlice,
    matches_payload: impl Fn(&FactPayload) -> bool,
) -> Vec<FactId> {
    slice
        .facts
        .iter()
        .filter(|fact| matches_payload(&fact.payload))
        .map(|fact| fact.id.clone())
        .collect()
}
