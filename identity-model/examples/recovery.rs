use fixtures::*;
use identity_model::*;
use identity_test_support::fixtures;
use identity_test_support::recovery;
use recovery::*;

fn main() {
    let subject_id = SubjectId("subject-demo-recovery".to_string());
    let authored_at = Timestamp("2026-05-29T00:00:00Z".to_string());
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    for (title, slice) in [
        (
            "Simulated Approved Recovery",
            approved_recovery_slice(
                subject_id.clone(),
                &translator,
                author.clone(),
                authored_at.clone(),
            ),
        ),
        (
            "Simulated Denied Recovery",
            denied_recovery_slice(
                subject_id.clone(),
                &translator,
                author.clone(),
                authored_at.clone(),
            ),
        ),
        (
            "Simulated Trusted Device Recovery",
            trusted_device_recovery_slice(subject_id, &translator, author, authored_at),
        ),
    ] {
        let projection = project_identity_history(slice.episode.subject_id.clone(), &slice.facts);
        print!(
            "{}",
            render_workflow_fixture(&WorkflowFixture {
                title: title.into(),
                projection: Some(materialized_fixture_from_state(&projection)),
                slice
            })
        );
    }
}

fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(AuthorId("author-fen-demo".to_string())),
        display_name: Some("FEN Demo".to_string()),
    }
}
