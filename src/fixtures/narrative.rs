use super::*;

pub fn workflow_narrative_lines(slice: &IdentityWorkflowSlice) -> Vec<String> {
    let mut lines = Vec::new();

    match slice.episode.episode_kind {
        EpisodeKind::IdentityVerificationWorkflow => {
            push_identity_verification_narrative(slice, &mut lines)
        }
        EpisodeKind::AccessAuthorizationWorkflow => {
            push_access_authorization_narrative(slice, &mut lines)
        }
        EpisodeKind::AccountRecoveryWorkflow => push_recovery_narrative(slice, &mut lines),
        EpisodeKind::DelegationWorkflow => push_delegation_narrative(slice, &mut lines),
        EpisodeKind::DisputeResolutionWorkflow => push_dispute_narrative(slice, &mut lines),
        _ => {}
    }

    lines
}
fn push_identity_verification_narrative(slice: &IdentityWorkflowSlice, lines: &mut Vec<String>) {
    let mut anchors = 0;
    let mut witnesses = 0;
    let mut institutional_links = 0;

    for membership in &slice.memberships {
        match membership.role {
            FactRole::IdentityAnchor => anchors += 1,
            FactRole::IdentityWitness | FactRole::ContinuityWitness => witnesses += 1,
            FactRole::InstitutionalLink => institutional_links += 1,
            _ => {}
        }
    }

    lines.push(format!(
        "identity_verification anchors={anchors} witnesses={witnesses} institutional_links={institutional_links}"
    ));
}

fn push_access_authorization_narrative(slice: &IdentityWorkflowSlice, lines: &mut Vec<String>) {
    for fact in &slice.facts {
        if let FactPayload::AccessDecision {
            action,
            decision,
            relied_on_facts,
            policy_refs,
        } = &fact.payload
        {
            lines.push(format!(
                "access_decision fact={} action={} decision={} policy_refs={} relied_on={}",
                fact.id.0,
                sensitive_action_name(*action),
                access_decision_name(*decision),
                join_ids(policy_refs),
                join_ids(relied_on_facts)
            ));

            for relied_on_fact_id in relied_on_facts {
                if let Some(relied_on_fact) = find_fact(&slice.facts, relied_on_fact_id) {
                    lines.push(format!(
                        "evidence fact={} {}",
                        relied_on_fact.id.0,
                        fact_payload_summary(&relied_on_fact.payload)
                    ));
                }
            }
        }
    }
}

fn push_recovery_narrative(slice: &IdentityWorkflowSlice, lines: &mut Vec<String>) {
    for fact in &slice.facts {
        match &fact.payload {
            FactPayload::AccountRecoveryEvent {
                method,
                result,
                assurance_level,
            } => lines.push(format!(
                "recovery fact={} method={} result={} assurance={}",
                fact.id.0,
                recovery_method_name(method),
                recovery_result_name(*result),
                assurance_level_name(*assurance_level)
            )),
            FactPayload::DeviceBindingEstablished { device_ref, .. } => lines.push(format!(
                "device_change fact={} established={device_ref}",
                fact.id.0
            )),
            FactPayload::DeviceBindingRevoked { device_ref, .. } => lines.push(format!(
                "device_change fact={} revoked={device_ref}",
                fact.id.0
            )),
            FactPayload::AccessDecision {
                action,
                decision,
                relied_on_facts,
                policy_refs,
            } => lines.push(format!(
                "recovery_access_decision fact={} action={} decision={} policy_refs={} relied_on={}",
                fact.id.0,
                sensitive_action_name(*action),
                access_decision_name(*decision),
                join_ids(policy_refs),
                join_ids(relied_on_facts)
            )),
            _ => {}
        }
    }
}

fn push_delegation_narrative(slice: &IdentityWorkflowSlice, lines: &mut Vec<String>) {
    for fact in &slice.facts {
        match &fact.payload {
            FactPayload::AuthorityRelationshipEstablished {
                actor_subject_id,
                target_subject_id,
                authority_type,
                scope,
                ..
            } => lines.push(format!(
                "authority_established fact={} actor={} target={} type={} actions={}",
                fact.id.0,
                actor_subject_id.0,
                target_subject_id.0,
                authority_type_name(authority_type),
                authorized_actions_summary(&scope.permitted_actions)
            )),
            FactPayload::AuthorityRelationshipRevoked {
                relationship_fact_id,
                ..
            } => lines.push(format!(
                "authority_revoked fact={} relationship={}",
                fact.id.0, relationship_fact_id.0
            )),
            FactPayload::AccessDecision {
                action,
                decision,
                relied_on_facts,
                policy_refs,
            } => lines.push(format!(
                "delegation_access_decision fact={} action={} decision={} policy_refs={} relied_on={}",
                fact.id.0,
                sensitive_action_name(*action),
                access_decision_name(*decision),
                join_ids(policy_refs),
                join_ids(relied_on_facts)
            )),
            _ => {}
        }
    }
}

fn push_dispute_narrative(slice: &IdentityWorkflowSlice, lines: &mut Vec<String>) {
    for fact in &slice.facts {
        match &fact.payload {
            FactPayload::ClinicalIdentityLinkContested { link_fact_id, .. } => lines.push(format!(
                "clinical_link_contested fact={} link={}",
                fact.id.0, link_fact_id.0
            )),
            FactPayload::ClinicalIdentityLinkDisputeResolved {
                link_fact_id,
                outcome,
                ..
            } => lines.push(format!(
                "clinical_link_dispute_resolved fact={} link={} outcome={}",
                fact.id.0,
                link_fact_id.0,
                dispute_outcome_name(*outcome)
            )),
            FactPayload::PayerIdentityLinkContested { link_fact_id, .. } => lines.push(format!(
                "payer_link_contested fact={} link={}",
                fact.id.0, link_fact_id.0
            )),
            FactPayload::PayerIdentityLinkDisputeResolved {
                link_fact_id,
                outcome,
                ..
            } => lines.push(format!(
                "payer_link_dispute_resolved fact={} link={} outcome={}",
                fact.id.0,
                link_fact_id.0,
                dispute_outcome_name(*outcome)
            )),
            FactPayload::DuplicateSubjectMergeRecorded {
                surviving_subject_id,
                merged_subject_ids,
                ..
            } => lines.push(format!(
                "subject_merge fact={} surviving={} merged={}",
                fact.id.0,
                surviving_subject_id.0,
                join_ids(merged_subject_ids)
            )),
            FactPayload::IncorrectMergeSplitRecorded {
                prior_subject_id,
                restored_subject_ids,
                ..
            } => lines.push(format!(
                "subject_split fact={} prior={} restored={}",
                fact.id.0,
                prior_subject_id.0,
                join_ids(restored_subject_ids)
            )),
            FactPayload::IdentityWitnessSuperseded {
                superseded_witness_fact_id,
                replacement_witness_fact_id,
                ..
            } => lines.push(format!(
                "witness_superseded fact={} old={} replacement={}",
                fact.id.0, superseded_witness_fact_id.0, replacement_witness_fact_id.0
            )),
            _ => {}
        }
    }
}

fn find_fact<'a>(facts: &'a [Fact], fact_id: &FactId) -> Option<&'a Fact> {
    facts.iter().find(|fact| &fact.id == fact_id)
}

fn authorized_actions_summary(actions: &[AuthorizedAction]) -> String {
    actions
        .iter()
        .map(authorized_action_name)
        .collect::<Vec<_>>()
        .join(",")
}
