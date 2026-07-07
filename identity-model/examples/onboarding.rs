use identity_model::*;

fn main() {
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let service = IdentityWorkflowService::new(translator);
    let provider = MockPhase1ContinuityProvider::successful();
    let mut id_generator = DeterministicIdGenerator::new();

    let registered = service.register_new_subject(
        RegisterNewSubjectRequest::fixture(author.clone(), authored_at.clone()),
        &mut id_generator,
    );
    let subject_id = registered.subject_id.clone();
    let device = service.bind_device(BindDeviceRequest::fixture(
        subject_id.clone(),
        author.clone(),
        authored_at.clone(),
    ));
    let continuity = service
        .enroll_continuity_reference(
            EnrollContinuityRequest::fixture(subject_id.clone(), author.clone(), authored_at),
            &provider,
        )
        .expect("continuity enrollment example should build");

    print_fixture("Register Subject", registered.workflow);
    print_fixture("Bind Device", device.workflow);
    print_fixture("Enroll Continuity", continuity.workflow);
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
