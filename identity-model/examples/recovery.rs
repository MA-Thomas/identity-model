use identity_model::*;

fn main() {
    let subject_id = SubjectId("subject-demo-recovery".to_string());
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let service = IdentityWorkflowService::new(translator);

    let approved =
        service.recover_account_detailed(RecoveryRequest::approved_government_id_and_liveness(
            subject_id.clone(),
            author.clone(),
            authored_at.clone(),
        ));
    let denied = service.recover_account_detailed(RecoveryRequest::denied_provider_attestation(
        subject_id.clone(),
        author.clone(),
        authored_at.clone(),
    ));
    let trusted_device = service.recover_account_detailed(RecoveryRequest::trusted_device(
        subject_id,
        author,
        authored_at,
    ));

    print_fixture("Approved Recovery", approved.workflow);
    print_fixture("Denied Recovery", denied.workflow);
    print_fixture("Trusted Device Recovery", trusted_device.workflow);
}

fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(AuthorId("author-fen-demo".to_string())),
        display_name: Some("FEN Demo".to_string()),
    }
}

fn print_fixture(title: &str, workflow: WorkflowOutcome) {
    print!(
        "{}",
        render_workflow_fixture(&WorkflowFixture {
            title: title.to_string(),
            projection: Some(materialized_fixture_from_state(&workflow.projection)),
            slice: workflow.slice,
        })
    );
}
