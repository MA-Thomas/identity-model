//! Pure, proposal-bound authority decisions. The application loads evidence from trusted owners.
use crate::fen::{FactId, PolicyRef, SubjectId, TimeInterval, Timestamp};
use crate::identity::{
    AccessDecisionResult, AuthorityScope, AuthorityType, AuthorizedAction, SensitiveAction,
};
use crate::policy::{
    evaluate_action_policy_with_context, EvidenceSummary, PolicyArtifact, PolicyArtifactDefinition,
    PolicyArtifactStatus, PolicyEvaluationContext,
};
use crate::time::timestamp_to_unix_seconds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantTerms {
    pub actor: SubjectId,
    pub target: SubjectId,
    pub authority_type: AuthorityType,
    pub scope: AuthorityScope,
    pub validity: TimeInterval,
}
/// Names are policy-owned; new witness requirements do not require new domain variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRequirement(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessResult {
    Satisfied,
    Rejected,
    ReviewRequired,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessAssessment {
    pub requirement: WitnessRequirement,
    pub terms: GrantTerms,
    pub policy: PolicyRef,
    pub source: FactId,
    pub assessed_at: Timestamp,
    pub expires_at: Timestamp,
    pub result: WitnessResult,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationProposal {
    pub id: FactId,
    pub terms: GrantTerms,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDecision {
    NeedsEvidence(Vec<WitnessRequirement>),
    NeedsReview,
    Denied,
    Approved(Box<AuthorityGrant>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityGrant {
    id: FactId,
    terms: GrantTerms,
    policy: PolicyRef,
    evidence: Vec<FactId>,
    granted_at: Timestamp,
    revoked_at: Option<Timestamp>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidInput,
    InvalidTime,
    WrongPolicy,
    Conflict,
    Unauthorized,
}
impl AuthorityGrant {
    pub fn id(&self) -> &FactId {
        &self.id
    }
    pub fn terms(&self) -> &GrantTerms {
        &self.terms
    }
    pub fn policy(&self) -> &PolicyRef {
        &self.policy
    }
    pub fn evidence(&self) -> &[FactId] {
        &self.evidence
    }
    pub fn granted_at(&self) -> &Timestamp {
        &self.granted_at
    }
    pub fn permits(
        &self,
        actor: &SubjectId,
        target: &SubjectId,
        action: &AuthorizedAction,
        at: &Timestamp,
    ) -> bool {
        let Ok(now) = timestamp_to_unix_seconds(at) else {
            return false;
        };
        let Ok(start) = timestamp_to_unix_seconds(&self.terms.validity.start) else {
            return false;
        };
        let Ok(end) = timestamp_to_unix_seconds(&self.terms.validity.end) else {
            return false;
        };
        let Ok(granted) = timestamp_to_unix_seconds(&self.granted_at) else {
            return false;
        };
        let revoked = self
            .revoked_at
            .as_ref()
            .is_some_and(|t| timestamp_to_unix_seconds(t).map_or(true, |t| t <= now));
        !revoked
            && granted <= now
            && start <= now
            && now < end
            && actor == &self.terms.actor
            && target == &self.terms.target
            && self.terms.scope.permitted_actions.contains(action)
    }
    /// Converts an approved grant into the existing append-only fact representation.
    pub fn established_fact(
        &self,
        provenance: crate::fen::Provenance,
    ) -> Result<crate::fen::Fact, AuthorityError> {
        if self.revoked_at.is_some() {
            return Err(AuthorityError::Conflict);
        }
        if timestamp_to_unix_seconds(&provenance.imported_at)
            .map_err(|_| AuthorityError::InvalidTime)?
            < timestamp_to_unix_seconds(&self.granted_at)
                .map_err(|_| AuthorityError::InvalidTime)?
        {
            return Err(AuthorityError::InvalidTime);
        }
        Ok(crate::fen::Fact {
            id: self.id.clone(),
            subject_id: self.terms.target.clone(),
            occurred_at: crate::fen::TemporalAnchor::Point(self.granted_at.clone()),
            code: None,
            payload: crate::fen::FactPayload::AuthorityRelationshipEstablished {
                actor_subject_id: self.terms.actor.clone(),
                target_subject_id: self.terms.target.clone(),
                authority_type: self.terms.authority_type.clone(),
                scope: self.terms.scope.clone(),
                valid_period: Some(self.terms.validity.clone()),
                evidence_ref: None,
            },
            status: crate::fen::FactStatus::Active,
            provenance,
            external_refs: Vec::new(),
        })
    }
    pub fn revocation_fact(
        &self,
        id: FactId,
        provenance: crate::fen::Provenance,
    ) -> Result<crate::fen::Fact, AuthorityError> {
        let at = self.revoked_at.clone().ok_or(AuthorityError::Conflict)?;
        if id == self.id
            || id.0.is_empty()
            || timestamp_to_unix_seconds(&provenance.imported_at)
                .map_err(|_| AuthorityError::InvalidTime)?
                < timestamp_to_unix_seconds(&at).map_err(|_| AuthorityError::InvalidTime)?
        {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(crate::fen::Fact {
            id,
            subject_id: self.terms.target.clone(),
            occurred_at: crate::fen::TemporalAnchor::Point(at),
            code: None,
            payload: crate::fen::FactPayload::AuthorityRelationshipRevoked {
                relationship_fact_id: self.id.clone(),
                reason: Some("target-authorized revocation".into()),
            },
            status: crate::fen::FactStatus::Active,
            provenance,
            external_refs: Vec::new(),
        })
    }
    /// Revocation is a separate decision by the target; evidence is authenticated by the application.
    pub fn revoke(
        &mut self,
        target: &SubjectId,
        policy: &PolicyArtifact,
        evidence: &EvidenceSummary,
        at: &Timestamp,
    ) -> Result<(), AuthorityError> {
        if target != &self.terms.target
            || policy.action_policy().action != SensitiveAction::RevokeAuthority
        {
            return Err(AuthorityError::Unauthorized);
        }
        validate_policy(policy, at)?;
        let decision = evaluate_action_policy_with_context(
            &policy.action_policy(),
            evidence,
            &PolicyEvaluationContext::new(at.clone()),
        );
        if decision.decision != AccessDecisionResult::Allowed {
            return Err(AuthorityError::Unauthorized);
        }
        if timestamp_to_unix_seconds(at).map_err(|_| AuthorityError::InvalidTime)?
            < timestamp_to_unix_seconds(&self.granted_at)
                .map_err(|_| AuthorityError::InvalidTime)?
        {
            return Err(AuthorityError::InvalidTime);
        }
        if self.revoked_at.is_some() {
            return Err(AuthorityError::Conflict);
        }
        self.revoked_at = Some(at.clone());
        self.evidence.extend(decision.relied_on_facts);
        Ok(())
    }
}
fn validate_policy(policy: &PolicyArtifact, at: &Timestamp) -> Result<(), AuthorityError> {
    let now = timestamp_to_unix_seconds(at).map_err(|_| AuthorityError::InvalidTime)?;
    if policy.status != PolicyArtifactStatus::Active
        || policy.version.is_empty()
        || policy.id.0.is_empty()
    {
        return Err(AuthorityError::WrongPolicy);
    }
    if let Some(period) = &policy.effective_period {
        let start =
            timestamp_to_unix_seconds(&period.start).map_err(|_| AuthorityError::InvalidTime)?;
        let end =
            timestamp_to_unix_seconds(&period.end).map_err(|_| AuthorityError::InvalidTime)?;
        if now < start || now >= end {
            return Err(AuthorityError::WrongPolicy);
        }
    }
    Ok(())
}
pub fn evaluate_delegation(
    proposal: &DelegationProposal,
    policy: &PolicyArtifact,
    assessments: &[WitnessAssessment],
    target_evidence: crate::policy::PrincipalEvidence<'_>,
    at: &Timestamp,
) -> Result<GrantDecision, AuthorityError> {
    validate_policy(policy, at)?;
    let PolicyArtifactDefinition::DelegationConstraints(constraints) = &policy.definition else {
        return Err(AuthorityError::WrongPolicy);
    };
    if target_evidence.principal != &proposal.terms.target {
        return Err(AuthorityError::Unauthorized);
    }
    let requirements = &constraints.witness_requirements;
    let t = &proposal.terms;
    let now = timestamp_to_unix_seconds(at).map_err(|_| AuthorityError::InvalidTime)?;
    let start =
        timestamp_to_unix_seconds(&t.validity.start).map_err(|_| AuthorityError::InvalidTime)?;
    let end =
        timestamp_to_unix_seconds(&t.validity.end).map_err(|_| AuthorityError::InvalidTime)?;
    if proposal.id.0.is_empty()
        || t.actor.0.is_empty()
        || t.target.0.is_empty()
        || t.actor == t.target
        || start < now
        || end <= start
        || t.scope.permitted_actions.is_empty()
    {
        return Err(AuthorityError::InvalidInput);
    }
    if t.authority_type != constraints.authority_type
        || t.scope
            .permitted_actions
            .iter()
            .any(|a| !constraints.permitted_actions.contains(a))
        || constraints
            .max_validity_seconds
            .is_some_and(|max| max <= 0 || end - start > max)
    {
        return Ok(GrantDecision::Denied);
    }
    let reference = crate::policy::versioned_policy_ref(&policy.id, &policy.version);
    if t.scope.constrained_by_policy != vec![reference.clone()] {
        return Err(AuthorityError::WrongPolicy);
    }
    if requirements
        .iter()
        .enumerate()
        .any(|(i, r)| r.0.is_empty() || requirements[..i].contains(r))
    {
        return Err(AuthorityError::InvalidInput);
    }
    let mut sources = Vec::new();
    let mut missing = Vec::new();
    for required in requirements {
        let candidates: Vec<_> = assessments
            .iter()
            .filter(|a| &a.requirement == required && a.terms == *t && a.policy == reference)
            .collect();
        if candidates.len() > 1 {
            return Err(AuthorityError::Conflict);
        }
        let Some(assessment) = candidates.first() else {
            missing.push(required.clone());
            continue;
        };
        let issued = timestamp_to_unix_seconds(&assessment.assessed_at)
            .map_err(|_| AuthorityError::InvalidTime)?;
        let expires = timestamp_to_unix_seconds(&assessment.expires_at)
            .map_err(|_| AuthorityError::InvalidTime)?;
        if assessment.source.0.is_empty() || now < issued || now >= expires {
            missing.push(required.clone());
            continue;
        }
        match assessment.result {
            WitnessResult::Rejected => return Ok(GrantDecision::Denied),
            WitnessResult::ReviewRequired => return Ok(GrantDecision::NeedsReview),
            WitnessResult::Satisfied => sources.push(assessment.source.clone()),
        }
    }
    if !missing.is_empty() {
        return Ok(GrantDecision::NeedsEvidence(missing));
    }
    let evaluation = evaluate_action_policy_with_context(
        &policy.action_policy(),
        target_evidence.evidence,
        &PolicyEvaluationContext::new(at.clone()),
    );
    match evaluation.decision {
        AccessDecisionResult::Denied => return Ok(GrantDecision::Denied),
        AccessDecisionResult::ManualReviewRequired => return Ok(GrantDecision::NeedsReview),
        AccessDecisionResult::StepUpRequired => {
            return Ok(GrantDecision::NeedsEvidence(vec![WitnessRequirement(
                "target-step-up".into(),
            )]))
        }
        AccessDecisionResult::Allowed => {}
    }
    sources.extend(evaluation.relied_on_facts);
    Ok(GrantDecision::Approved(Box::new(AuthorityGrant {
        id: proposal.id.clone(),
        terms: t.clone(),
        policy: reference,
        evidence: sources,
        granted_at: at.clone(),
        revoked_at: None,
    })))
}
