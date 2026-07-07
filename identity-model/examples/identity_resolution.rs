use identity_model::*;

fn main() {
    let subject_id = SubjectId("subject-demo-resolution".to_string());
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let service = IdentityWorkflowService::new(translator);

    let rejected_link = service.resolve_identity_dispute_detailed(
        IdentityDisputeResolutionRequest::contested_provider_link(
            subject_id.clone(),
            DisputeResolutionOutcome::Rejected,
            author.clone(),
            authored_at.clone(),
        ),
    );
    let confirmed_link = service.resolve_identity_dispute_detailed(
        IdentityDisputeResolutionRequest::contested_provider_link(
            subject_id.clone(),
            DisputeResolutionOutcome::Confirmed,
            author.clone(),
            authored_at.clone(),
        ),
    );
    let merge = service.resolve_identity_dispute_detailed(
        IdentityDisputeResolutionRequest::duplicate_subject_merge(
            subject_id.clone(),
            SubjectId("subject-demo-duplicate".to_string()),
            author.clone(),
            authored_at.clone(),
        ),
    );
    let split = service.resolve_identity_dispute_detailed(
        IdentityDisputeResolutionRequest::incorrect_merge_split(
            subject_id.clone(),
            vec![
                SubjectId("subject-demo-restored-a".to_string()),
                SubjectId("subject-demo-restored-b".to_string()),
            ],
            author.clone(),
            authored_at.clone(),
        ),
    );
    let witness_supersession = service.resolve_identity_dispute_detailed(
        IdentityDisputeResolutionRequest::witness_supersession(
            subject_id.clone(),
            author,
            authored_at,
        ),
    );

    print_fixture("Rejected Provider Link Dispute", rejected_link.workflow);
    print_fixture("Confirmed Provider Link Dispute", confirmed_link.workflow);
    print_fixture("Duplicate Subject Merge", merge.workflow);
    print_fixture("Incorrect Merge Split", split.workflow);
    print_fixture("Witness Supersession", witness_supersession.workflow);
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
