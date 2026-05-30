use identity_model::*;

mod common;
use common::*;

#[test]
fn provider_swap_preserves_canonical_continuity_and_policy_shape() {
    let subject_id = id("subject-provider-swap");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let phase1_provider = MockPhase1ContinuityProvider::successful();
    let hosted_provider = MockHostedContinuityProvider::successful();

    let mut phase1_lifecycle = InMemoryNonceLifecycle::new();
    let phase1_slice = complete_record_export_step_up_slice(
        subject_id.clone(),
        "enrollment-provider-swap".to_string(),
        &phase1_provider,
        &mut phase1_lifecycle,
        &phase1_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("phase 1 provider should drive step-up");

    let mut hosted_lifecycle = InMemoryNonceLifecycle::new();
    let hosted_slice = complete_record_export_step_up_slice(
        subject_id,
        "enrollment-provider-swap".to_string(),
        &hosted_provider,
        &mut hosted_lifecycle,
        &hosted_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("hosted provider should drive the same step-up shape");

    let phase1_continuity = continuity_result_shape(&phase1_slice.facts);
    let hosted_continuity = continuity_result_shape(&hosted_slice.facts);
    assert_eq!(phase1_continuity, hosted_continuity);
    assert_eq!(
        access_decision_shape(&phase1_slice.facts),
        access_decision_shape(&hosted_slice.facts)
    );
}

#[test]
fn scripted_hosted_adapter_maps_provider_shapes_without_changing_fen_facts() {
    let subject_id = id("subject-scripted-hosted");
    let translator = FenTranslator {
        system_author: system_author(),
    };
    let mapper = ResultBasedAssuranceMapper;
    let mock_provider = MockPhase1ContinuityProvider::successful();
    let hosted_adapter = ScriptedHostedContinuityAdapter::successful("ScriptedHostedVault");

    let enrollment = hosted_adapter
        .enroll(ContinuityEnrollmentRequest {
            subject_id: subject_id.clone(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        })
        .expect("hosted enrollment should map");
    assert_eq!(enrollment.enrollment_ref, "hosted-enrollment-demo");
    assert_eq!(
        hosted_adapter.enrollment_request(&ContinuityEnrollmentRequest {
            subject_id: subject_id.clone(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        }),
        HostedEnrollmentRequest {
            external_subject_ref: "fen-subject-subject-scripted-hosted".to_string(),
            modality: BiometricModality::Face,
            requested_at: ts("2026-05-29T00:00:00Z"),
        }
    );

    let mut mock_lifecycle = InMemoryNonceLifecycle::new();
    let mock_slice = complete_record_export_step_up_slice(
        subject_id.clone(),
        "hosted-enrollment-demo".to_string(),
        &mock_provider,
        &mut mock_lifecycle,
        &mock_provider.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("mock provider should drive step-up");

    let mut hosted_lifecycle = InMemoryNonceLifecycle::new();
    let hosted_slice = complete_record_export_step_up_slice(
        subject_id,
        "hosted-enrollment-demo".to_string(),
        &hosted_adapter,
        &mut hosted_lifecycle,
        &hosted_adapter.signature_verifier(),
        &mapper,
        &translator,
        system_author(),
        ts("2026-05-29T00:00:00Z"),
    )
    .expect("scripted hosted provider should drive step-up");

    assert_eq!(
        continuity_result_shape(&mock_slice.facts),
        continuity_result_shape(&hosted_slice.facts)
    );
    assert_eq!(
        access_decision_shape(&mock_slice.facts),
        access_decision_shape(&hosted_slice.facts)
    );
}
