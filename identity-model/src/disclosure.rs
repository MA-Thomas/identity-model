//! Purpose-bound authorization for disclosing stored identity facts.
use crate::authority::AuthorityGrant;
use crate::fen::{FactId, PolicyRef, SubjectId, TimeInterval, Timestamp};
use crate::identity::{AccessDecisionResult, AuthorizedAction, SensitiveAction};
use crate::persistence::FactMaterializationAuditContext;
use crate::policy::{
    evaluate_policy_artifact_with_context, PolicyArtifact, PolicyEvaluation,
    PolicyEvaluationContext,
};
use crate::time::timestamp_to_unix_seconds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosurePurpose {
    AccountInspection,
    IdentifierExport,
    ProviderLink,
}
#[derive(Debug, Clone)]
pub struct DisclosureRequest {
    pub requester: SubjectId,
    pub subject: SubjectId,
    pub purpose: DisclosurePurpose,
    pub facts: Vec<FactId>,
}
/// Loaded from the consent owner, including current revocation state.
#[derive(Debug, Clone)]
pub struct DisclosureConsent {
    pub id: FactId,
    pub requester: SubjectId,
    pub subject: SubjectId,
    pub purpose: DisclosurePurpose,
    pub policy: PolicyRef,
    pub validity: TimeInterval,
    pub revoked: bool,
}
use crate::policy::PrincipalEvidence;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureError {
    InvalidContext,
    ConsentRequired,
    AuthorityRequired,
    StepUpRequired,
}
#[derive(Debug, Clone)]
pub struct AuthorizedDisclosure {
    request: DisclosureRequest,
    evaluated_at: Timestamp,
    expires_at: Timestamp,
    evaluation: PolicyEvaluation,
    consent: FactId,
}
impl AuthorizedDisclosure {
    pub fn request(&self) -> &DisclosureRequest {
        &self.request
    }
    pub fn evaluated_at(&self) -> &Timestamp {
        &self.evaluated_at
    }
    pub fn evaluation(&self) -> &PolicyEvaluation {
        &self.evaluation
    }
    pub fn consent(&self) -> &FactId {
        &self.consent
    }
    pub fn permits(&self, subject: &SubjectId, fact: &FactId, at: &Timestamp) -> bool {
        let (Ok(now), Ok(start), Ok(end)) = (
            timestamp_to_unix_seconds(at),
            timestamp_to_unix_seconds(&self.evaluated_at),
            timestamp_to_unix_seconds(&self.expires_at),
        ) else {
            return false;
        };
        subject == &self.request.subject
            && self.request.facts.contains(fact)
            && start <= now
            && now < end
    }
    pub fn audit_context(&self) -> FactMaterializationAuditContext {
        FactMaterializationAuditContext::new(
            Some(self.request.requester.0.clone()),
            Some(format!(
                "{:?};consent={}",
                self.request.purpose, self.consent.0
            )),
            Some(self.evaluated_at.clone()),
        )
    }
}
pub fn authorize_disclosure(
    request: DisclosureRequest,
    principal: PrincipalEvidence<'_>,
    consent: &DisclosureConsent,
    policy: &PolicyArtifact,
    authority: Option<&AuthorityGrant>,
    at: &Timestamp,
) -> Result<AuthorizedDisclosure, DisclosureError> {
    let now = timestamp_to_unix_seconds(at).map_err(|_| DisclosureError::InvalidContext)?;
    if request.requester != *principal.principal
        || request.facts.is_empty()
        || request.facts.iter().any(|id| id.0.is_empty())
    {
        return Err(DisclosureError::InvalidContext);
    }
    let action = match request.purpose {
        DisclosurePurpose::AccountInspection => SensitiveAction::ViewRecord,
        DisclosurePurpose::IdentifierExport => SensitiveAction::ExportCompleteRecord,
        DisclosurePurpose::ProviderLink => SensitiveAction::LinkProvider,
    };
    let disclosure_policy = policy.action_policy();
    if !disclosure_policy.requires_fresh_continuity
        || disclosure_policy
            .continuity_freshness
            .is_none_or(|freshness| {
                freshness.max_age_seconds <= 0 || freshness.max_age_seconds > 300
            })
        || disclosure_policy
            .credential_freshness
            .is_none_or(|freshness| {
                freshness.max_age_seconds <= 0 || freshness.max_age_seconds > 900
            })
        || principal
            .evidence
            .credential_fact_id
            .as_ref()
            .is_none_or(|id| id.0.is_empty())
        || principal
            .evidence
            .continuity_fact_id
            .as_ref()
            .is_none_or(|id| id.0.is_empty())
        || principal
            .evidence
            .continuity_assurance
            .is_none_or(|level| level < crate::identity::AssuranceLevel::High)
    {
        return Err(DisclosureError::StepUpRequired);
    }
    if policy.action_policy().action != action {
        return Err(DisclosureError::InvalidContext);
    }
    let delegated_action = match request.purpose {
        DisclosurePurpose::AccountInspection => AuthorizedAction::ViewRecord,
        DisclosurePurpose::IdentifierExport => AuthorizedAction::ExportRecord,
        DisclosurePurpose::ProviderLink => AuthorizedAction::LinkProvider,
    };
    if request.requester != request.subject
        && !authority.is_some_and(|grant| {
            grant.permits(&request.requester, &request.subject, &delegated_action, at)
        })
    {
        return Err(DisclosureError::AuthorityRequired);
    }
    let reference = crate::policy::versioned_policy_ref(&policy.id, &policy.version);
    let start = timestamp_to_unix_seconds(&consent.validity.start)
        .map_err(|_| DisclosureError::InvalidContext)?;
    let end = timestamp_to_unix_seconds(&consent.validity.end)
        .map_err(|_| DisclosureError::InvalidContext)?;
    if consent.revoked
        || consent.id.0.is_empty()
        || consent.requester != request.requester
        || consent.subject != request.subject
        || consent.purpose != request.purpose
        || consent.policy != reference
        || now < start
        || now >= end
    {
        return Err(DisclosureError::ConsentRequired);
    }
    let evaluation = evaluate_policy_artifact_with_context(
        policy,
        principal.evidence,
        &PolicyEvaluationContext::new(at.clone()),
    );
    if evaluation.decision != AccessDecisionResult::Allowed {
        return Err(DisclosureError::StepUpRequired);
    }
    // A permit authorizes this immediate read, not a reusable session capability.
    let mut expires = end.min(now.checked_add(30).ok_or(DisclosureError::InvalidContext)?);
    if let Some(period) = &policy.effective_period {
        expires = expires.min(
            timestamp_to_unix_seconds(&period.end).map_err(|_| DisclosureError::InvalidContext)?,
        );
    }
    let action_policy = policy.action_policy();
    for (observed, freshness) in [
        (
            &principal.evidence.credential_observed_at,
            action_policy.credential_freshness,
        ),
        (
            &principal.evidence.continuity_observed_at,
            action_policy.continuity_freshness,
        ),
        (
            &principal.evidence.risk_observed_at,
            action_policy.risk_freshness,
        ),
    ] {
        if let (Some(observed), Some(freshness)) = (observed, freshness) {
            expires = expires.min(
                timestamp_to_unix_seconds(observed)
                    .map_err(|_| DisclosureError::InvalidContext)?
                    .checked_add(freshness.max_age_seconds)
                    .ok_or(DisclosureError::InvalidContext)?,
            );
        }
    }
    if expires <= now {
        return Err(DisclosureError::StepUpRequired);
    }
    let expires_at = crate::time::unix_seconds_to_timestamp(expires);
    Ok(AuthorizedDisclosure {
        request,
        evaluated_at: at.clone(),
        expires_at,
        evaluation,
        consent: consent.id.clone(),
    })
}
