//! Canonical byte serialization for continuity assertions.
//!
//! This is intentionally boundary code. The rest of the identity model should
//! carry typed Rust enums; these stable string labels exist only because signed
//! payloads need deterministic bytes across process and provider boundaries.

use super::*;

pub const CONTINUITY_ASSERTION_PROFILE_NAME: &str = "fen-continuity-assertion";
pub const CONTINUITY_ASSERTION_PROFILE_VERSION: &str = "v1";

pub fn canonical_continuity_assertion_bytes(
    assertion: &ContinuityAssertion,
) -> Result<Vec<u8>, ContinuityAssertionRejectionReason> {
    if assertion.enrollment_ref.is_empty()
        || assertion.challenge_nonce.is_empty()
        || assertion.timestamp.0.is_empty()
        || assertion.provider_metadata.provider_name.is_empty()
    {
        return Err(ContinuityAssertionRejectionReason::MalformedAssertion);
    }

    let mut canonical = String::new();
    push_field(&mut canonical, "profile", CONTINUITY_ASSERTION_PROFILE_NAME);
    push_field(
        &mut canonical,
        "profile_version",
        CONTINUITY_ASSERTION_PROFILE_VERSION,
    );
    push_field(&mut canonical, "enrollment_ref", &assertion.enrollment_ref);
    push_field(
        &mut canonical,
        "challenge_nonce",
        &assertion.challenge_nonce,
    );
    push_field(&mut canonical, "timestamp", &assertion.timestamp.0);
    push_field(
        &mut canonical,
        "result",
        continuity_result_canonical_label(assertion.result),
    );
    push_field(
        &mut canonical,
        "derived_assurance",
        assurance_level_canonical_label(assertion.derived_assurance),
    );
    push_field(
        &mut canonical,
        "modality",
        modality_canonical_label(&assertion.modality),
    );
    push_field(
        &mut canonical,
        "model_version",
        assertion.model_version.as_deref().unwrap_or(""),
    );
    push_field(
        &mut canonical,
        "pad_result",
        pad_result_canonical_label(assertion.pad_result),
    );
    push_field(
        &mut canonical,
        "provider_name",
        &assertion.provider_metadata.provider_name,
    );
    push_field(
        &mut canonical,
        "provider_event_id",
        assertion
            .provider_metadata
            .provider_event_id
            .as_deref()
            .unwrap_or(""),
    );
    push_field(
        &mut canonical,
        "provider_subject_ref",
        assertion
            .provider_metadata
            .provider_subject_ref
            .as_deref()
            .unwrap_or(""),
    );
    push_field(
        &mut canonical,
        "sdk_or_api_version",
        assertion
            .provider_metadata
            .sdk_or_api_version
            .as_deref()
            .unwrap_or(""),
    );

    Ok(canonical.into_bytes())
}

pub fn deterministic_signature_for_test(
    assertion: &ContinuityAssertion,
    key_material: &[u8],
) -> Signature {
    let canonical = canonical_continuity_assertion_bytes(assertion).unwrap_or_default();
    let mut state = 0xcbf2_9ce4_8422_2325_u64;

    for byte in key_material.iter().chain(canonical.iter()) {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }

    state.to_be_bytes().to_vec()
}

fn push_field(target: &mut String, name: &str, value: &str) {
    target.push_str(name);
    target.push('=');
    target.push_str(&value.len().to_string());
    target.push(':');
    target.push_str(value);
    target.push('\n');
}

fn continuity_result_canonical_label(result: ContinuityCheckResult) -> &'static str {
    match result {
        ContinuityCheckResult::Passed => "passed",
        ContinuityCheckResult::Failed => "failed",
        ContinuityCheckResult::Inconclusive => "inconclusive",
    }
}

fn assurance_level_canonical_label(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Low => "low",
        AssuranceLevel::Medium => "medium",
        AssuranceLevel::High => "high",
        AssuranceLevel::VeryHigh => "very_high",
    }
}

fn modality_canonical_label(modality: &BiometricModality) -> &'static str {
    match modality {
        BiometricModality::Face => "face",
        BiometricModality::Fingerprint => "fingerprint",
        BiometricModality::Voice => "voice",
        BiometricModality::Palm => "palm",
        BiometricModality::Other => "other",
    }
}

fn pad_result_canonical_label(result: PresentationAttackDetectionResult) -> &'static str {
    match result {
        PresentationAttackDetectionResult::Passed => "passed",
        PresentationAttackDetectionResult::Failed => "failed",
        PresentationAttackDetectionResult::Inconclusive => "inconclusive",
        PresentationAttackDetectionResult::NotPerformed => "not_performed",
    }
}
