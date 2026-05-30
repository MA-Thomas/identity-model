use crate::fen::*;
use crate::identity::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedIdentityState {
    pub subject_id: SubjectId,
    pub assurance_level: AssuranceLevel,
    pub active_devices: Vec<DeviceRef>,
    pub active_clinical_links: Vec<ClinicalIdentityLinkView>,
    pub active_payer_links: Vec<PayerIdentityLinkView>,
    pub active_authorities: Vec<AuthorityRelationshipView>,
    pub unresolved_disputes: Vec<FactId>,
    pub last_continuity_check: Option<FactId>,
    pub last_successful_continuity_check: Option<FactId>,
    pub latest_access_decisions: Vec<AccessDecisionView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClinicalIdentityLinkView {
    pub provider_org: OrganizationRef,
    pub external_patient_ref: ExternalRef,
    pub match_confidence: MatchConfidence,
    pub source_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayerIdentityLinkView {
    pub payer: String,
    pub member_ref: String,
    pub effective_period: Option<TimeInterval>,
    pub source_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRelationshipView {
    pub actor_subject_id: SubjectId,
    pub target_subject_id: SubjectId,
    pub authority_type: AuthorityType,
    pub scope: AuthorityScope,
    pub valid_period: Option<TimeInterval>,
    pub source_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecisionView {
    pub action: SensitiveAction,
    pub decision: AccessDecisionResult,
    pub relied_on_facts: Vec<FactId>,
    pub policy_refs: Vec<PolicyRef>,
    pub source_fact_id: FactId,
}

pub fn materialize_identity_state(
    subject_id: SubjectId,
    facts: &[Fact],
) -> MaterializedIdentityState {
    materialize_identity_state_for(subject_id, facts, None)
}

pub fn materialize_identity_state_at(
    subject_id: SubjectId,
    facts: &[Fact],
    as_of: &Timestamp,
) -> MaterializedIdentityState {
    materialize_identity_state_for(subject_id, facts, Some(as_of))
}

fn materialize_identity_state_for(
    subject_id: SubjectId,
    facts: &[Fact],
    as_of: Option<&Timestamp>,
) -> MaterializedIdentityState {
    let mut state = MaterializedIdentityState {
        subject_id: subject_id.clone(),
        assurance_level: AssuranceLevel::Low,
        active_devices: Vec::new(),
        active_clinical_links: Vec::new(),
        active_payer_links: Vec::new(),
        active_authorities: Vec::new(),
        unresolved_disputes: Vec::new(),
        last_continuity_check: None,
        last_successful_continuity_check: None,
        latest_access_decisions: Vec::new(),
    };

    let active_facts: Vec<&Fact> = facts
        .iter()
        .filter(|fact| fact.subject_id == subject_id)
        .filter(|fact| matches!(fact.status, FactStatus::Active))
        .collect();

    for fact in &active_facts {
        match &fact.payload {
            FactPayload::IdentityWitnessRecorded {
                assurance_level,
                expires_at,
                ..
            } if is_optional_expiration_active(expires_at, as_of) => {
                state.assurance_level = state.assurance_level.max(*assurance_level);
            }
            FactPayload::DeviceBindingEstablished {
                assurance_level, ..
            }
            | FactPayload::CredentialAssertion {
                assurance_level, ..
            }
            | FactPayload::AccountRecoveryEvent {
                assurance_level, ..
            } => {
                state.assurance_level = state.assurance_level.max(*assurance_level);
            }
            FactPayload::BiometricContinuityCheck {
                result: ContinuityCheckResult::Passed,
                assurance_level,
                ..
            } => {
                state.assurance_level = state.assurance_level.max(*assurance_level);
            }
            _ => {}
        }
    }

    for fact in &active_facts {
        match &fact.payload {
            FactPayload::DeviceBindingEstablished { device_ref, .. } => {
                if !is_device_revoked(device_ref, &active_facts) {
                    state.active_devices.push(device_ref.clone());
                }
            }
            FactPayload::ClinicalIdentityLinkEstablished {
                provider_org,
                external_patient_ref,
                match_confidence,
            } => {
                if is_link_active(&fact.id, &active_facts) {
                    state.active_clinical_links.push(ClinicalIdentityLinkView {
                        provider_org: provider_org.clone(),
                        external_patient_ref: external_patient_ref.clone(),
                        match_confidence: *match_confidence,
                        source_fact_id: fact.id.clone(),
                    });
                }
            }
            FactPayload::PayerIdentityLinkEstablished {
                payer,
                member_ref,
                effective_period,
            } => {
                if is_link_active(&fact.id, &active_facts)
                    && is_optional_period_active(effective_period, as_of)
                {
                    state.active_payer_links.push(PayerIdentityLinkView {
                        payer: payer.clone(),
                        member_ref: member_ref.clone(),
                        effective_period: effective_period.clone(),
                        source_fact_id: fact.id.clone(),
                    });
                }
            }
            FactPayload::AuthorityRelationshipEstablished {
                actor_subject_id,
                target_subject_id,
                authority_type,
                scope,
                valid_period,
                ..
            } => {
                if !is_authority_revoked(&fact.id, &active_facts)
                    && is_optional_period_active(valid_period, as_of)
                {
                    state.active_authorities.push(AuthorityRelationshipView {
                        actor_subject_id: actor_subject_id.clone(),
                        target_subject_id: target_subject_id.clone(),
                        authority_type: authority_type.clone(),
                        scope: scope.clone(),
                        valid_period: valid_period.clone(),
                        source_fact_id: fact.id.clone(),
                    });
                }
            }
            FactPayload::ClinicalIdentityLinkContested { link_fact_id, .. }
            | FactPayload::PayerIdentityLinkContested { link_fact_id, .. } => {
                if link_resolution_outcome(link_fact_id, &active_facts).is_none() {
                    state.unresolved_disputes.push(link_fact_id.clone());
                }
            }
            FactPayload::BiometricContinuityCheck {
                result: ContinuityCheckResult::Passed,
                ..
            } => {
                state.last_successful_continuity_check = Some(fact.id.clone());
                state.last_continuity_check = Some(fact.id.clone());
            }
            FactPayload::BiometricContinuityCheck { .. } => {
                state.last_continuity_check = Some(fact.id.clone());
            }
            FactPayload::AccessDecision {
                action,
                decision,
                relied_on_facts,
                policy_refs,
            } => {
                replace_latest_access_decision(
                    &mut state.latest_access_decisions,
                    AccessDecisionView {
                        action: *action,
                        decision: *decision,
                        relied_on_facts: relied_on_facts.clone(),
                        policy_refs: policy_refs.clone(),
                        source_fact_id: fact.id.clone(),
                    },
                );
            }
            _ => {}
        }
    }

    state
}

pub fn authority_permits_action(
    state: &MaterializedIdentityState,
    actor_subject_id: &SubjectId,
    action: AuthorizedAction,
) -> bool {
    state.active_authorities.iter().any(|authority| {
        &authority.actor_subject_id == actor_subject_id
            && authority.scope.permitted_actions.contains(&action)
    })
}

fn is_device_revoked(device_ref: &DeviceRef, facts: &[&Fact]) -> bool {
    facts.iter().any(|fact| {
        matches!(
            &fact.payload,
            FactPayload::DeviceBindingRevoked { device_ref: revoked, .. } if revoked == device_ref
        )
    })
}

fn is_link_active(link_fact_id: &FactId, facts: &[&Fact]) -> bool {
    match link_resolution_outcome(link_fact_id, facts) {
        Some(DisputeResolutionOutcome::Confirmed) => true,
        Some(DisputeResolutionOutcome::Rejected | DisputeResolutionOutcome::Inconclusive) => false,
        None => !is_link_contested(link_fact_id, facts),
    }
}

fn is_link_contested(link_fact_id: &FactId, facts: &[&Fact]) -> bool {
    facts.iter().any(|fact| {
        matches!(
            &fact.payload,
            FactPayload::ClinicalIdentityLinkContested { link_fact_id: contested, .. }
                | FactPayload::PayerIdentityLinkContested { link_fact_id: contested, .. }
                if contested == link_fact_id
        )
    })
}

fn link_resolution_outcome(
    link_fact_id: &FactId,
    facts: &[&Fact],
) -> Option<DisputeResolutionOutcome> {
    facts.iter().rev().find_map(|fact| match &fact.payload {
        FactPayload::ClinicalIdentityLinkDisputeResolved {
            link_fact_id: resolved,
            outcome,
            ..
        }
        | FactPayload::PayerIdentityLinkDisputeResolved {
            link_fact_id: resolved,
            outcome,
            ..
        } if resolved == link_fact_id => Some(*outcome),
        _ => None,
    })
}

fn is_authority_revoked(relationship_fact_id: &FactId, facts: &[&Fact]) -> bool {
    facts.iter().any(|fact| {
        matches!(
            &fact.payload,
            FactPayload::AuthorityRelationshipRevoked { relationship_fact_id: revoked, .. }
                if revoked == relationship_fact_id
        )
    })
}

fn is_optional_period_active(period: &Option<TimeInterval>, as_of: Option<&Timestamp>) -> bool {
    match (period, as_of) {
        (Some(period), Some(as_of)) => &period.start <= as_of && as_of <= &period.end,
        (None, _) => true,
        (_, None) => true,
    }
}

fn is_optional_expiration_active(
    expires_at: &Option<Timestamp>,
    as_of: Option<&Timestamp>,
) -> bool {
    match (expires_at, as_of) {
        (Some(expires_at), Some(as_of)) => as_of <= expires_at,
        (None, _) => true,
        (_, None) => true,
    }
}

fn replace_latest_access_decision(
    latest_access_decisions: &mut Vec<AccessDecisionView>,
    view: AccessDecisionView,
) {
    if let Some(existing) = latest_access_decisions
        .iter_mut()
        .find(|existing| existing.action == view.action)
    {
        *existing = view;
    } else {
        latest_access_decisions.push(view);
    }
}
