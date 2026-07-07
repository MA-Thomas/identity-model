use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowFixture {
    pub title: String,
    pub slice: IdentityWorkflowSlice,
    pub projection: Option<MaterializedFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFixture {
    pub subject_id: SubjectId,
    pub assurance_level: AssuranceLevel,
    pub active_devices: Vec<DeviceRef>,
    pub active_clinical_link_fact_ids: Vec<FactId>,
    pub active_payer_link_fact_ids: Vec<FactId>,
    pub active_authority_fact_ids: Vec<FactId>,
    pub unresolved_disputes: Vec<FactId>,
    pub latest_access_decisions: Vec<(SensitiveAction, AccessDecisionResult, FactId)>,
}

pub fn render_workflow_fixture(fixture: &WorkflowFixture) -> String {
    let mut output = String::new();

    push_line(&mut output, &format!("# {}", fixture.title));
    push_line(&mut output, "");
    push_line(&mut output, "[episode]");
    push_line(&mut output, &format!("id={}", fixture.slice.episode.id.0));
    push_line(
        &mut output,
        &format!("subject={}", fixture.slice.episode.subject_id.0),
    );
    push_line(
        &mut output,
        &format!(
            "kind={}",
            episode_kind_name(fixture.slice.episode.episode_kind)
        ),
    );
    push_line(
        &mut output,
        &format!("label={}", fixture.slice.episode.label),
    );
    push_line(
        &mut output,
        &format!(
            "status={}",
            episode_status_name(&fixture.slice.episode.status)
        ),
    );

    let narrative = workflow_narrative_lines(&fixture.slice);
    if !narrative.is_empty() {
        push_line(&mut output, "");
        push_line(&mut output, "[narrative]");
        for line in narrative {
            push_line(&mut output, &line);
        }
    }

    push_line(&mut output, "");
    push_line(&mut output, "[facts]");
    for fact in &fixture.slice.facts {
        push_line(
            &mut output,
            &format!(
                "{} subject={} status={} payload={}",
                fact.id.0,
                fact.subject_id.0,
                fact_status_name(&fact.status),
                fact_payload_summary(&fact.payload)
            ),
        );
    }

    push_line(&mut output, "");
    push_line(&mut output, "[memberships]");
    for membership in &fixture.slice.memberships {
        push_line(
            &mut output,
            &format!(
                "{} fact={} episode={} role={} status={}",
                membership.id.0,
                membership.fact_id.0,
                membership.episode_id.0,
                fact_role_name(&membership.role),
                membership_status_name(&membership.status)
            ),
        );
    }

    if let Some(projection) = &fixture.projection {
        push_line(&mut output, "");
        push_line(&mut output, "[projection]");
        push_line(&mut output, &format!("subject={}", projection.subject_id.0));
        push_line(
            &mut output,
            &format!(
                "assurance={}",
                assurance_level_name(projection.assurance_level)
            ),
        );
        push_line(
            &mut output,
            &format!(
                "active_devices={}",
                join_strings(&projection.active_devices)
            ),
        );
        push_line(
            &mut output,
            &format!(
                "active_clinical_links={}",
                join_ids(&projection.active_clinical_link_fact_ids)
            ),
        );
        push_line(
            &mut output,
            &format!(
                "active_payer_links={}",
                join_ids(&projection.active_payer_link_fact_ids)
            ),
        );
        push_line(
            &mut output,
            &format!(
                "active_authorities={}",
                join_ids(&projection.active_authority_fact_ids)
            ),
        );
        push_line(
            &mut output,
            &format!(
                "unresolved_disputes={}",
                join_ids(&projection.unresolved_disputes)
            ),
        );
        for (action, decision, fact_id) in &projection.latest_access_decisions {
            push_line(
                &mut output,
                &format!(
                    "latest_access_decision action={} decision={} fact={}",
                    sensitive_action_name(*action),
                    access_decision_name(*decision),
                    fact_id.0
                ),
            );
        }
    }

    output
}

pub fn materialized_fixture_from_state(
    state: &crate::materialized::MaterializedIdentityState,
) -> MaterializedFixture {
    MaterializedFixture {
        subject_id: state.subject_id.clone(),
        assurance_level: state.assurance_level,
        active_devices: state.active_devices.clone(),
        active_clinical_link_fact_ids: state
            .active_clinical_links
            .iter()
            .map(|link| link.source_fact_id.clone())
            .collect(),
        active_payer_link_fact_ids: state
            .active_payer_links
            .iter()
            .map(|link| link.source_fact_id.clone())
            .collect(),
        active_authority_fact_ids: state
            .active_authorities
            .iter()
            .map(|authority| authority.source_fact_id.clone())
            .collect(),
        unresolved_disputes: state.unresolved_disputes.clone(),
        latest_access_decisions: state
            .latest_access_decisions
            .iter()
            .map(|decision| {
                (
                    decision.action,
                    decision.decision,
                    decision.source_fact_id.clone(),
                )
            })
            .collect(),
    }
}
