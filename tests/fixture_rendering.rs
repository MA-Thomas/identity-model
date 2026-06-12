use identity_model::*;

mod common;
use common::*;

#[test]
fn workflow_fixture_renderer_produces_stable_demo_output() {
    let subject_id: SubjectId = id("subject-fixture");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let provider = MockPhase1ContinuityProvider::successful();
    let slice = onboarding_vertical_slice(
        subject_id.clone(),
        &provider,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("onboarding should build");
    let projection = materialize_identity_state(subject_id, &slice.facts);
    let output = render_workflow_fixture(&WorkflowFixture {
        title: "Onboarding Fixture".to_string(),
        slice,
        projection: Some(materialized_fixture_from_state(&projection)),
    });

    assert!(output.starts_with("# Onboarding Fixture\n\n[episode]\n"));
    assert!(output.contains("[narrative]\n"));
    assert!(output.contains("identity_verification anchors=1 witnesses=2 institutional_links=2\n"));
    assert!(output.contains("payload=SubjectCreated kind=human_person\n"));
    assert!(output.contains("role=continuity_witness status=active\n"));
    assert!(output.contains("[projection]\n"));
    assert!(output.contains("assurance=high\n"));
}

#[test]
fn workflow_examples_match_golden_fixture_contract() {
    assert_eq!(
        render_workflow_example_fixtures(),
        include_str!("golden/workflow_examples.txt")
    );
}

#[test]
fn workflow_narratives_explain_access_recovery_delegation_and_disputes() {
    let subject_id: SubjectId = id("subject-narrative");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let provider = MockPhase1ContinuityProvider::successful();
    let mut lifecycle = InMemoryNonceLifecycle::new();
    let access = complete_record_export_step_up_slice(
        subject_id.clone(),
        "enrollment-narrative".to_string(),
        &provider,
        &mut lifecycle,
        &provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("access slice should build");
    let access_lines = workflow_narrative_lines(&access);
    assert!(access_lines.iter().any(|line| line.contains(
        "access_decision fact=fact-export-access-decision action=export_complete_record decision=allowed"
    )));
    assert!(access_lines.iter().any(|line| {
        line.contains("evidence fact=fact-export-continuity BiometricContinuityCheck")
    }));

    let recovery = approved_recovery_slice(
        subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let recovery_lines = workflow_narrative_lines(&recovery);
    assert!(recovery_lines
        .iter()
        .any(|line| line.contains("recovery fact=fact-recovery-approved-1")));
    assert!(recovery_lines.iter().any(|line| line.contains(
        "device_change fact=fact-recovery-approved-3 established=device-passkey-replacement"
    )));

    let delegation = delegation_vertical_slice(
        id("caregiver-narrative"),
        subject_id.clone(),
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let delegation_lines = workflow_narrative_lines(&delegation);
    assert!(delegation_lines
        .iter()
        .any(|line| line.contains("authority_established fact=fact-delegation-authority")));
    assert!(delegation_lines
        .iter()
        .any(|line| line.contains("actions=view_record,share_record")));

    let dispute = contested_provider_link_resolution_slice(
        subject_id,
        DisputeResolutionOutcome::Rejected,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    );
    let dispute_lines = workflow_narrative_lines(&dispute);
    assert!(dispute_lines
        .iter()
        .any(|line| line.contains("clinical_link_contested")));
    assert!(dispute_lines
        .iter()
        .any(|line| line.contains("outcome=rejected")));
}

fn render_workflow_example_fixtures() -> String {
    let authored_at = ts("2026-05-29T00:00:00Z");
    let author = system_author();
    let translator = FenTranslator {
        system_author: author.clone(),
    };
    let mut output = String::new();

    let onboarding_subject: SubjectId = id("subject-demo-onboarding");
    let onboarding_provider = MockPhase1ContinuityProvider::successful();
    let onboarding = onboarding_vertical_slice(
        onboarding_subject.clone(),
        &onboarding_provider,
        &translator,
        author.clone(),
        authored_at.clone(),
    )
    .expect("onboarding fixture should build");
    output.push_str(&render_fixture(
        "Onboarding",
        onboarding_subject,
        onboarding,
    ));

    let export_subject: SubjectId = id("subject-demo-export");
    let export_provider = MockPhase1ContinuityProvider::successful();
    let mut lifecycle = InMemoryNonceLifecycle::new();
    let export = complete_record_export_step_up_slice(
        export_subject.clone(),
        "demo-enrollment".to_string(),
        &export_provider,
        &mut lifecycle,
        &export_provider.signature_verifier(),
        &ResultBasedAssuranceMapper,
        &translator,
        author.clone(),
        authored_at.clone(),
    )
    .expect("export fixture should build");
    output.push_str(&render_fixture(
        "Complete Record Export Step-Up",
        export_subject,
        export,
    ));

    let delegation = delegation_vertical_slice(
        id("subject-demo-caregiver"),
        id("subject-demo-patient"),
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    output.push_str(&render_fixture(
        "Delegation",
        id("subject-demo-patient"),
        delegation,
    ));

    let recovery_subject: SubjectId = id("subject-demo-recovery");
    let approved = approved_recovery_slice(
        recovery_subject.clone(),
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let denied = denied_recovery_slice(
        recovery_subject.clone(),
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let trusted_device = trusted_device_recovery_slice(
        recovery_subject.clone(),
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    output.push_str(&render_fixture(
        "Approved Recovery",
        recovery_subject.clone(),
        approved,
    ));
    output.push_str(&render_fixture(
        "Denied Recovery",
        recovery_subject.clone(),
        denied,
    ));
    output.push_str(&render_fixture(
        "Trusted Device Recovery",
        recovery_subject,
        trusted_device,
    ));

    let resolution_subject: SubjectId = id("subject-demo-resolution");
    let rejected_link = contested_provider_link_resolution_slice(
        resolution_subject.clone(),
        DisputeResolutionOutcome::Rejected,
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let confirmed_link = contested_provider_link_resolution_slice(
        resolution_subject.clone(),
        DisputeResolutionOutcome::Confirmed,
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let merge = duplicate_subject_merge_slice(
        resolution_subject.clone(),
        id("subject-demo-duplicate"),
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let split = incorrect_merge_split_slice(
        resolution_subject.clone(),
        vec![id("subject-demo-restored-a"), id("subject-demo-restored-b")],
        &translator,
        author.clone(),
        authored_at.clone(),
    );
    let witness_supersession =
        witness_supersession_slice(resolution_subject.clone(), &translator, author, authored_at);
    output.push_str(&render_fixture(
        "Rejected Provider Link Dispute",
        resolution_subject.clone(),
        rejected_link,
    ));
    output.push_str(&render_fixture(
        "Confirmed Provider Link Dispute",
        resolution_subject.clone(),
        confirmed_link,
    ));
    output.push_str(&render_fixture(
        "Duplicate Subject Merge",
        resolution_subject.clone(),
        merge,
    ));
    output.push_str(&render_fixture(
        "Incorrect Merge Split",
        resolution_subject.clone(),
        split,
    ));
    output.push_str(&render_fixture(
        "Witness Supersession",
        resolution_subject,
        witness_supersession,
    ));

    output
}

fn render_fixture(title: &str, subject_id: SubjectId, slice: IdentityWorkflowSlice) -> String {
    let projection = materialize_identity_state(subject_id, &slice.facts);
    render_workflow_fixture(&WorkflowFixture {
        title: title.to_string(),
        slice,
        projection: Some(materialized_fixture_from_state(&projection)),
    })
}
