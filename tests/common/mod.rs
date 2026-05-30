#![allow(dead_code)]

use identity_model::*;

pub fn id(value: &str) -> Id {
    Id(value.to_string())
}

pub fn ts(value: &str) -> Timestamp {
    Timestamp(value.to_string())
}

pub fn system_author() -> Author {
    Author {
        author_type: AuthorType::System,
        author_id: Some(id("author-system")),
        display_name: Some("FEN".to_string()),
    }
}

pub fn provenance() -> Provenance {
    Provenance {
        source_system: Some("test".to_string()),
        source_document: None,
        imported_at: ts("2026-05-29T00:00:00Z"),
        author: system_author(),
    }
}

pub fn fact(id_value: &str, subject_id: SubjectId, payload: FactPayload) -> Fact {
    Fact {
        id: id(id_value),
        subject_id,
        occurred_at: TemporalAnchor::Point(ts("2026-05-29T00:00:00Z")),
        code: None,
        payload,
        status: FactStatus::Active,
        provenance: provenance(),
        external_refs: Vec::new(),
    }
}

pub fn continuity_result_shape(
    facts: &[Fact],
) -> Option<(String, ContinuityCheckResult, AssuranceLevel)> {
    facts.iter().find_map(|fact| match &fact.payload {
        FactPayload::BiometricContinuityCheck {
            enrollment_ref,
            result,
            assurance_level,
            ..
        } => Some((enrollment_ref.clone(), *result, *assurance_level)),
        _ => None,
    })
}

pub fn access_decision_shape(
    facts: &[Fact],
) -> Option<(SensitiveAction, AccessDecisionResult, Vec<PolicyRef>)> {
    facts.iter().find_map(|fact| match &fact.payload {
        FactPayload::AccessDecision {
            action,
            decision,
            policy_refs,
            ..
        } => Some((*action, *decision, policy_refs.clone())),
        _ => None,
    })
}
