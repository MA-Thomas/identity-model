use crate::clock::Clock;
use crate::fen::*;
use crate::identity::*;
use crate::time;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPolicy {
    pub policy_ref: PolicyRef,
    pub action: SensitiveAction,
    pub required_assurance: AssuranceLevel,
    pub requires_fresh_continuity: bool,
    pub requires_manual_review: bool,
    pub credential_freshness: Option<FreshnessRequirement>,
    pub continuity_freshness: Option<FreshnessRequirement>,
    pub risk_freshness: Option<FreshnessRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub credential_fact_id: Option<FactId>,
    pub credential_assurance: Option<AssuranceLevel>,
    pub credential_observed_at: Option<Timestamp>,
    pub continuity_fact_id: Option<FactId>,
    pub continuity_assurance: Option<AssuranceLevel>,
    pub continuity_observed_at: Option<Timestamp>,
    pub risk_fact_id: Option<FactId>,
    pub risk_result: Option<RiskEvaluationResult>,
    pub risk_observed_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessRequirement {
    pub max_age_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceFreshnessRequirements {
    pub credential: Option<FreshnessRequirement>,
    pub continuity: Option<FreshnessRequirement>,
    pub risk: Option<FreshnessRequirement>,
}

impl EvidenceFreshnessRequirements {
    pub fn from_action_policy(policy: &ActionPolicy) -> Self {
        Self {
            credential: policy.credential_freshness,
            continuity: policy.continuity_freshness,
            risk: policy.risk_freshness,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyArtifactDefinition {
    SensitiveAction(SensitiveActionPolicyDefinition),
    EmergencyAccess(EmergencyAccessPolicyDefinition),
    DelegationConstraints(DelegationConstraintsPolicyDefinition),
    RecoveryMethodChange(RecoveryMethodChangePolicyDefinition),
    BreakGlass(BreakGlassPolicyDefinition),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveActionPolicyDefinition {
    pub action: SensitiveAction,
    pub required_assurance: AssuranceLevel,
    pub requires_fresh_continuity: bool,
    pub requires_manual_review: bool,
    pub freshness: EvidenceFreshnessRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyAccessPolicyDefinition {
    pub required_assurance: AssuranceLevel,
    pub freshness: EvidenceFreshnessRequirements,
    pub requires_manual_review: bool,
    pub allowed_authority_types: Vec<AuthorityType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationConstraintsPolicyDefinition {
    pub authority_type: AuthorityType,
    pub permitted_actions: Vec<AuthorizedAction>,
    pub requires_target_subject_continuity: bool,
    pub max_validity_seconds: Option<i64>,
    pub freshness: EvidenceFreshnessRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMethodChangePolicyDefinition {
    pub allowed_methods: Vec<RecoveryMethod>,
    pub revoke_replaced_devices: bool,
    pub requires_manual_review_for_low_assurance: bool,
    pub freshness: EvidenceFreshnessRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassPolicyDefinition {
    pub action: SensitiveAction,
    pub required_assurance: AssuranceLevel,
    pub freshness: EvidenceFreshnessRequirements,
    pub max_session_seconds: i64,
    pub requires_post_access_review: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub action: SensitiveAction,
    pub decision: AccessDecisionResult,
    pub reasons: Vec<PolicyEvaluationReason>,
    pub relied_on_facts: Vec<FactId>,
    pub policy_refs: Vec<PolicyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyArtifact {
    pub id: PolicyRef,
    pub version: String,
    pub title: String,
    pub description: Option<String>,
    pub status: PolicyArtifactStatus,
    pub effective_period: Option<TimeInterval>,
    pub review: Option<PolicyReview>,
    pub definition: PolicyArtifactDefinition,
    pub action_policy: ActionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyArtifactStatus {
    Draft,
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReview {
    pub reviewed_by: Author,
    pub reviewed_at: Timestamp,
    pub notes: Option<String>,
}

impl PolicyArtifact {
    pub fn sensitive_action(
        id: PolicyRef,
        version: impl Into<String>,
        action: SensitiveAction,
        effective_period: Option<TimeInterval>,
    ) -> Self {
        let version = version.into();
        let action_policy = default_policy_for_action(action, versioned_policy_ref(&id, &version));
        let definition = PolicyArtifactDefinition::SensitiveAction(
            SensitiveActionPolicyDefinition::from_action_policy(&action_policy),
        );

        Self {
            id,
            version,
            title: "Sensitive action policy".to_string(),
            description: None,
            status: PolicyArtifactStatus::Active,
            effective_period,
            review: None,
            definition,
            action_policy,
        }
    }

    pub fn emergency_access(
        id: PolicyRef,
        version: impl Into<String>,
        effective_period: Option<TimeInterval>,
        definition: EmergencyAccessPolicyDefinition,
    ) -> Self {
        Self::from_definition(
            id,
            version,
            "Emergency access policy",
            effective_period,
            PolicyArtifactDefinition::EmergencyAccess(definition),
        )
    }

    pub fn delegation_constraints(
        id: PolicyRef,
        version: impl Into<String>,
        effective_period: Option<TimeInterval>,
        definition: DelegationConstraintsPolicyDefinition,
    ) -> Self {
        Self::from_definition(
            id,
            version,
            "Delegation constraints policy",
            effective_period,
            PolicyArtifactDefinition::DelegationConstraints(definition),
        )
    }

    pub fn recovery_method_change(
        id: PolicyRef,
        version: impl Into<String>,
        effective_period: Option<TimeInterval>,
        definition: RecoveryMethodChangePolicyDefinition,
    ) -> Self {
        Self::from_definition(
            id,
            version,
            "Recovery method change policy",
            effective_period,
            PolicyArtifactDefinition::RecoveryMethodChange(definition),
        )
    }

    pub fn break_glass(
        id: PolicyRef,
        version: impl Into<String>,
        effective_period: Option<TimeInterval>,
        definition: BreakGlassPolicyDefinition,
    ) -> Self {
        Self::from_definition(
            id,
            version,
            "Break-glass policy",
            effective_period,
            PolicyArtifactDefinition::BreakGlass(definition),
        )
    }

    pub fn definition(&self) -> &PolicyArtifactDefinition {
        &self.definition
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_status(mut self, status: PolicyArtifactStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_review(mut self, review: PolicyReview) -> Self {
        self.review = Some(review);
        self
    }

    pub fn action_policy(&self) -> &ActionPolicy {
        &self.action_policy
    }

    pub fn into_action_policy(self) -> ActionPolicy {
        self.action_policy
    }

    fn from_definition(
        id: PolicyRef,
        version: impl Into<String>,
        title: impl Into<String>,
        effective_period: Option<TimeInterval>,
        definition: PolicyArtifactDefinition,
    ) -> Self {
        let version = version.into();
        let action_policy = definition.to_action_policy(versioned_policy_ref(&id, &version));

        Self {
            id,
            version,
            title: title.into(),
            description: None,
            status: PolicyArtifactStatus::Active,
            effective_period,
            review: None,
            definition,
            action_policy,
        }
    }
}

impl SensitiveActionPolicyDefinition {
    pub fn from_action_policy(policy: &ActionPolicy) -> Self {
        Self {
            action: policy.action,
            required_assurance: policy.required_assurance,
            requires_fresh_continuity: policy.requires_fresh_continuity,
            requires_manual_review: policy.requires_manual_review,
            freshness: EvidenceFreshnessRequirements::from_action_policy(policy),
        }
    }
}

impl PolicyArtifactDefinition {
    fn to_action_policy(&self, policy_ref: PolicyRef) -> ActionPolicy {
        match self {
            PolicyArtifactDefinition::SensitiveAction(definition) => ActionPolicy {
                policy_ref,
                action: definition.action,
                required_assurance: definition.required_assurance,
                requires_fresh_continuity: definition.requires_fresh_continuity,
                requires_manual_review: definition.requires_manual_review,
                credential_freshness: definition.freshness.credential,
                continuity_freshness: definition.freshness.continuity,
                risk_freshness: definition.freshness.risk,
            },
            PolicyArtifactDefinition::EmergencyAccess(definition) => ActionPolicy {
                policy_ref,
                action: SensitiveAction::EmergencyAccess,
                required_assurance: definition.required_assurance,
                requires_fresh_continuity: true,
                requires_manual_review: definition.requires_manual_review,
                credential_freshness: definition.freshness.credential,
                continuity_freshness: definition.freshness.continuity,
                risk_freshness: definition.freshness.risk,
            },
            PolicyArtifactDefinition::DelegationConstraints(definition) => ActionPolicy {
                policy_ref,
                action: SensitiveAction::DelegateAuthority,
                required_assurance: AssuranceLevel::High,
                requires_fresh_continuity: definition.requires_target_subject_continuity,
                requires_manual_review: false,
                credential_freshness: definition.freshness.credential,
                continuity_freshness: definition.freshness.continuity,
                risk_freshness: definition.freshness.risk,
            },
            PolicyArtifactDefinition::RecoveryMethodChange(definition) => ActionPolicy {
                policy_ref,
                action: SensitiveAction::ChangeRecoveryMethod,
                required_assurance: AssuranceLevel::High,
                requires_fresh_continuity: true,
                requires_manual_review: definition.requires_manual_review_for_low_assurance,
                credential_freshness: definition.freshness.credential,
                continuity_freshness: definition.freshness.continuity,
                risk_freshness: definition.freshness.risk,
            },
            PolicyArtifactDefinition::BreakGlass(definition) => ActionPolicy {
                policy_ref,
                action: definition.action,
                required_assurance: definition.required_assurance,
                requires_fresh_continuity: true,
                requires_manual_review: definition.requires_post_access_review,
                credential_freshness: definition.freshness.credential,
                continuity_freshness: definition.freshness.continuity,
                risk_freshness: definition.freshness.risk,
            },
        }
    }
}

pub fn versioned_policy_ref(policy_id: &PolicyRef, version: &str) -> PolicyRef {
    PolicyRef(format!("{}@{}", policy_id.0, version))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvaluationReason {
    ManualReviewRequired,
    RiskFailed,
    RiskRequiresManualReview,
    RiskRequiresStepUp,
    CredentialStale,
    ContinuityStale,
    RiskStale,
    RequiredContinuityMissing,
    InsufficientCredentialAssurance,
    InsufficientContinuityAssurance,
    PolicyArtifactNotActive,
    PolicyNotYetEffective,
    PolicyExpired,
    PolicyTimestampInvalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyEvaluationContext {
    pub evaluated_at: Option<Timestamp>,
}

impl PolicyEvaluationContext {
    pub fn new(evaluated_at: Option<Timestamp>) -> Self {
        Self { evaluated_at }
    }

    pub fn from_clock(clock: &impl Clock) -> Self {
        Self {
            evaluated_at: Some(clock.now()),
        }
    }
}

pub fn evaluate_action_policy(
    policy: &ActionPolicy,
    evidence: &EvidenceSummary,
) -> PolicyEvaluation {
    evaluate_action_policy_at(policy, evidence, None)
}

pub fn evaluate_action_policy_with_context(
    policy: &ActionPolicy,
    evidence: &EvidenceSummary,
    context: &PolicyEvaluationContext,
) -> PolicyEvaluation {
    evaluate_action_policy_at(policy, evidence, context.evaluated_at.as_ref())
}

pub fn evaluate_policy_artifact_with_context(
    artifact: &PolicyArtifact,
    evidence: &EvidenceSummary,
    context: &PolicyEvaluationContext,
) -> PolicyEvaluation {
    let mut evaluation =
        evaluate_action_policy_with_context(artifact.action_policy(), evidence, context);
    let mut artifact_reasons = policy_artifact_reasons(artifact, context.evaluated_at.as_ref());

    if !artifact_reasons.is_empty() {
        artifact_reasons.append(&mut evaluation.reasons);
        evaluation.reasons = artifact_reasons;
        evaluation.decision = AccessDecisionResult::ManualReviewRequired;
    }

    evaluation
}

pub fn evaluate_action_policy_at(
    policy: &ActionPolicy,
    evidence: &EvidenceSummary,
    evaluated_at: Option<&Timestamp>,
) -> PolicyEvaluation {
    let mut relied_on_facts = Vec::new();
    let mut reasons = Vec::new();

    if let Some(fact_id) = &evidence.credential_fact_id {
        relied_on_facts.push(fact_id.clone());
    }
    if let Some(fact_id) = &evidence.continuity_fact_id {
        relied_on_facts.push(fact_id.clone());
    }
    if let Some(fact_id) = &evidence.risk_fact_id {
        relied_on_facts.push(fact_id.clone());
    }

    if policy.requires_manual_review {
        reasons.push(PolicyEvaluationReason::ManualReviewRequired);
    }
    match evidence.risk_result {
        Some(RiskEvaluationResult::Failed) => reasons.push(PolicyEvaluationReason::RiskFailed),
        Some(RiskEvaluationResult::RequiresManualReview) => {
            reasons.push(PolicyEvaluationReason::RiskRequiresManualReview)
        }
        Some(RiskEvaluationResult::RequiresStepUp) => {
            reasons.push(PolicyEvaluationReason::RiskRequiresStepUp)
        }
        Some(RiskEvaluationResult::Passed) | None => {}
    }

    if is_stale(
        evidence.credential_observed_at.as_ref(),
        evaluated_at,
        policy.credential_freshness,
    ) {
        reasons.push(PolicyEvaluationReason::CredentialStale);
    }
    if is_stale(
        evidence.continuity_observed_at.as_ref(),
        evaluated_at,
        policy.continuity_freshness,
    ) {
        reasons.push(PolicyEvaluationReason::ContinuityStale);
    }
    if is_stale(
        evidence.risk_observed_at.as_ref(),
        evaluated_at,
        policy.risk_freshness,
    ) {
        reasons.push(PolicyEvaluationReason::RiskStale);
    }

    if policy.requires_fresh_continuity
        && !meets_required_assurance(evidence.continuity_assurance, policy.required_assurance)
    {
        if evidence.continuity_fact_id.is_none() || evidence.continuity_assurance.is_none() {
            reasons.push(PolicyEvaluationReason::RequiredContinuityMissing);
        } else {
            reasons.push(PolicyEvaluationReason::InsufficientContinuityAssurance);
        }
    }

    if !meets_required_assurance(evidence.credential_assurance, AssuranceLevel::Medium) {
        reasons.push(PolicyEvaluationReason::InsufficientCredentialAssurance);
    }

    let decision = if reasons.iter().any(|reason| {
        matches!(
            reason,
            PolicyEvaluationReason::ManualReviewRequired
                | PolicyEvaluationReason::RiskFailed
                | PolicyEvaluationReason::RiskRequiresManualReview
        )
    }) {
        AccessDecisionResult::ManualReviewRequired
    } else if !reasons.is_empty() {
        AccessDecisionResult::StepUpRequired
    } else {
        AccessDecisionResult::Allowed
    };

    PolicyEvaluation {
        action: policy.action,
        decision,
        reasons,
        relied_on_facts,
        policy_refs: vec![policy.policy_ref.clone()],
    }
}

fn policy_artifact_reasons(
    artifact: &PolicyArtifact,
    evaluated_at: Option<&Timestamp>,
) -> Vec<PolicyEvaluationReason> {
    let mut reasons = Vec::new();

    if artifact.status != PolicyArtifactStatus::Active {
        reasons.push(PolicyEvaluationReason::PolicyArtifactNotActive);
    }

    if let (Some(period), Some(evaluated_at)) = (&artifact.effective_period, evaluated_at) {
        match (
            time::timestamp_before(evaluated_at, &period.start),
            time::timestamp_after(evaluated_at, &period.end),
        ) {
            (Ok(true), _) => reasons.push(PolicyEvaluationReason::PolicyNotYetEffective),
            (Ok(false), Ok(true)) => reasons.push(PolicyEvaluationReason::PolicyExpired),
            (Ok(false), Ok(false)) => {}
            _ => reasons.push(PolicyEvaluationReason::PolicyTimestampInvalid),
        }
    }

    reasons
}

fn meets_required_assurance(observed: Option<AssuranceLevel>, required: AssuranceLevel) -> bool {
    observed.is_some_and(|observed| observed >= required)
}

pub fn default_policy_for_action(action: SensitiveAction, policy_ref: PolicyRef) -> ActionPolicy {
    match action {
        SensitiveAction::ViewRecord => ActionPolicy {
            policy_ref,
            action,
            required_assurance: AssuranceLevel::Medium,
            requires_fresh_continuity: false,
            requires_manual_review: false,
            credential_freshness: Some(FreshnessRequirement {
                max_age_seconds: 12 * 60 * 60,
            }),
            continuity_freshness: None,
            risk_freshness: Some(FreshnessRequirement {
                max_age_seconds: 60 * 60,
            }),
        },
        SensitiveAction::ExportCompleteRecord
        | SensitiveAction::DelegateAuthority
        | SensitiveAction::RevokeAuthority
        | SensitiveAction::AuthorizeDataTransaction
        | SensitiveAction::ChangeRecoveryMethod
        | SensitiveAction::LinkProvider
        | SensitiveAction::LinkPayer => ActionPolicy {
            policy_ref,
            action,
            required_assurance: AssuranceLevel::High,
            requires_fresh_continuity: true,
            requires_manual_review: false,
            credential_freshness: Some(FreshnessRequirement {
                max_age_seconds: 15 * 60,
            }),
            continuity_freshness: Some(FreshnessRequirement {
                max_age_seconds: 5 * 60,
            }),
            risk_freshness: Some(FreshnessRequirement {
                max_age_seconds: 5 * 60,
            }),
        },
        SensitiveAction::EmergencyAccess => ActionPolicy {
            policy_ref,
            action,
            required_assurance: AssuranceLevel::High,
            requires_fresh_continuity: true,
            requires_manual_review: true,
            credential_freshness: Some(FreshnessRequirement {
                max_age_seconds: 5 * 60,
            }),
            continuity_freshness: Some(FreshnessRequirement {
                max_age_seconds: 5 * 60,
            }),
            risk_freshness: Some(FreshnessRequirement {
                max_age_seconds: 60,
            }),
        },
        SensitiveAction::ShareRecord => ActionPolicy {
            policy_ref,
            action,
            required_assurance: AssuranceLevel::High,
            requires_fresh_continuity: true,
            requires_manual_review: false,
            credential_freshness: Some(FreshnessRequirement {
                max_age_seconds: 30 * 60,
            }),
            continuity_freshness: Some(FreshnessRequirement {
                max_age_seconds: 10 * 60,
            }),
            risk_freshness: Some(FreshnessRequirement {
                max_age_seconds: 10 * 60,
            }),
        },
    }
}

fn is_stale(
    observed_at: Option<&Timestamp>,
    evaluated_at: Option<&Timestamp>,
    requirement: Option<FreshnessRequirement>,
) -> bool {
    match (observed_at, evaluated_at, requirement) {
        (Some(observed_at), Some(evaluated_at), Some(requirement)) => {
            time::seconds_between(observed_at, evaluated_at)
                .map_or(true, |age| age > requirement.max_age_seconds)
        }
        (None, Some(_), Some(_)) => true,
        _ => false,
    }
}
