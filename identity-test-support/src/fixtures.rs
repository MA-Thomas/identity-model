//! Example output is diagnostic, not a serialized product contract.
use identity_model::*;
#[derive(Debug)]
pub struct WorkflowFixture {
    pub title: String,
    pub slice: IdentityWorkflowSlice,
    pub projection: Option<IdentityHistory>,
}
pub fn materialized_fixture_from_state(state: &IdentityHistory) -> IdentityHistory {
    state.clone()
}
pub fn render_workflow_fixture(fixture: &WorkflowFixture) -> String {
    format!(
        "# {}\n\n{}\n{:#?}\n",
        fixture.title,
        workflow_narrative_lines(&fixture.slice).join("\n"),
        fixture.projection
    )
}
