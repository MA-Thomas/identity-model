use crate::fen::*;
use crate::identity::*;
use crate::time;
use std::collections::{HashMap, HashSet};

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
    let fact_index = MaterializationFactIndex::from_active_facts(&active_facts);

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

    let mut emitted_devices = HashSet::new();
    let mut emitted_clinical_links = HashSet::new();
    let mut emitted_payer_links = HashSet::new();
    let mut emitted_authorities = HashSet::new();
    let mut emitted_unresolved_disputes = HashSet::new();

    for fact in &active_facts {
        match &fact.payload {
            FactPayload::DeviceBindingEstablished { device_ref, .. } => {
                if fact_index.is_device_active(device_ref)
                    && emitted_devices.insert(device_ref.clone())
                {
                    state.active_devices.push(device_ref.clone());
                }
            }
            FactPayload::ClinicalIdentityLinkEstablished {
                provider_org,
                external_patient_ref,
                match_confidence,
            } => {
                if fact_index.is_link_active(&fact.id)
                    && emitted_clinical_links.insert(fact.id.clone())
                {
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
                if fact_index.is_link_active(&fact.id)
                    && is_optional_period_active(effective_period, as_of)
                    && emitted_payer_links.insert(fact.id.clone())
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
                if fact_index.is_authority_active(&fact.id)
                    && is_optional_period_active(valid_period, as_of)
                    && emitted_authorities.insert(fact.id.clone())
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
                if fact_index.is_unresolved_dispute(link_fact_id)
                    && emitted_unresolved_disputes.insert(link_fact_id.clone())
                {
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

#[derive(Debug, Default)]
struct MaterializationFactIndex {
    revoked_devices: HashSet<DeviceRef>,
    contested_links: HashSet<FactId>,
    link_resolution_outcomes: HashMap<FactId, DisputeResolutionOutcome>,
    revoked_authorities: HashSet<FactId>,
}

impl MaterializationFactIndex {
    fn from_active_facts(facts: &[&Fact]) -> Self {
        let mut index = Self::default();
        for fact in facts {
            match &fact.payload {
                FactPayload::DeviceBindingRevoked { device_ref, .. } => {
                    index.revoked_devices.insert(device_ref.clone());
                }
                FactPayload::ClinicalIdentityLinkContested { link_fact_id, .. }
                | FactPayload::PayerIdentityLinkContested { link_fact_id, .. } => {
                    index.contested_links.insert(link_fact_id.clone());
                }
                FactPayload::ClinicalIdentityLinkDisputeResolved {
                    link_fact_id,
                    outcome,
                    ..
                }
                | FactPayload::PayerIdentityLinkDisputeResolved {
                    link_fact_id,
                    outcome,
                    ..
                } => {
                    index
                        .link_resolution_outcomes
                        .insert(link_fact_id.clone(), *outcome);
                }
                FactPayload::AuthorityRelationshipRevoked {
                    relationship_fact_id,
                    ..
                } => {
                    index
                        .revoked_authorities
                        .insert(relationship_fact_id.clone());
                }
                _ => {}
            }
        }
        index
    }

    fn is_device_active(&self, device_ref: &DeviceRef) -> bool {
        !self.revoked_devices.contains(device_ref)
    }

    fn is_link_active(&self, link_fact_id: &FactId) -> bool {
        match self.link_resolution_outcomes.get(link_fact_id) {
            Some(DisputeResolutionOutcome::Confirmed) => true,
            Some(DisputeResolutionOutcome::Rejected | DisputeResolutionOutcome::Inconclusive) => {
                false
            }
            None => !self.contested_links.contains(link_fact_id),
        }
    }

    fn is_unresolved_dispute(&self, link_fact_id: &FactId) -> bool {
        self.contested_links.contains(link_fact_id)
            && !self.link_resolution_outcomes.contains_key(link_fact_id)
    }

    fn is_authority_active(&self, relationship_fact_id: &FactId) -> bool {
        !self.revoked_authorities.contains(relationship_fact_id)
    }
}

fn is_optional_period_active(period: &Option<TimeInterval>, as_of: Option<&Timestamp>) -> bool {
    match (period, as_of) {
        (Some(period), Some(as_of)) => {
            time::timestamp_in_closed_interval(as_of, &period.start, &period.end).unwrap_or(false)
        }
        (None, _) => true,
        (_, None) => true,
    }
}

fn is_optional_expiration_active(
    expires_at: &Option<Timestamp>,
    as_of: Option<&Timestamp>,
) -> bool {
    match (expires_at, as_of) {
        (Some(expires_at), Some(as_of)) => {
            time::timestamp_at_or_after(expires_at, as_of).unwrap_or(false)
        }
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
