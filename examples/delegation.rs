use identity_model::*;

fn main() {
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let service = IdentityWorkflowService::new(translator);

    let workflow = service
        .delegate_authority_detailed(DelegationRequest::fixture(
            SubjectId("subject-demo-caregiver".to_string()),
            SubjectId("subject-demo-patient".to_string()),
            author,
            authored_at,
        ))
        .workflow;

    print!(
        "{}",
        render_workflow_fixture(&WorkflowFixture {
            title: "Delegation".to_string(),
            projection: Some(materialized_fixture_from_state(&workflow.projection)),
            slice: workflow.slice,
        })
    );
}

fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(AuthorId("author-fen-demo".to_string())),
        display_name: Some("FEN Demo".to_string()),
    }
}
