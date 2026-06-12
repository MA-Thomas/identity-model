use identity_model::*;

fn main() {
    let subject_id = SubjectId("subject-demo-export".to_string());
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let service = IdentityWorkflowService::new(translator);
    let provider = MockPhase1ContinuityProvider::successful();
    let mapper = ResultBasedAssuranceMapper;
    let mut lifecycle = InMemoryNonceLifecycle::new();

    let workflow = service
        .authorize_complete_record_export_step_up_detailed(
            CompleteRecordExportStepUpRequest::fixture(
                subject_id,
                "demo-enrollment".to_string(),
                author,
                authored_at,
            ),
            &provider,
            &mut lifecycle,
            &provider.signature_verifier(),
            &mapper,
        )
        .expect("export step-up example should build")
        .workflow;

    print!(
        "{}",
        render_workflow_fixture(&WorkflowFixture {
            title: "Complete Record Export Step-Up".to_string(),
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
