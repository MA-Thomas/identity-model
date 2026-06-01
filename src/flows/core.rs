use super::*;
use episode_labels::access_authorization_label;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityWorkflowSlice {
    pub episode: ProblemEpisode,
    pub facts: Vec<Fact>,
    pub memberships: Vec<EpisodeMembership>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerticalSliceError {
    Provider(ContinuityProviderError),
    Verification(ContinuityAssertionRejectionReason),
}

impl From<ContinuityProviderError> for VerticalSliceError {
    fn from(error: ContinuityProviderError) -> Self {
        Self::Provider(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowIdPlan {
    pub episode_id: ProblemEpisodeId,
    pub fact_ids: Vec<FactId>,
    pub membership_ids: Vec<MembershipId>,
    pub challenge_id: Option<ChallengeId>,
    pub nonce: Option<Nonce>,
}

impl WorkflowIdPlan {
    pub fn generated(
        id_generator: &mut impl IdGenerator,
        id_namespace: &str,
        fact_count: usize,
    ) -> Self {
        let episode_id = id_generator.next_episode_id(&format!("episode-{id_namespace}"));
        let fact_ids = (0..fact_count)
            .map(|_| id_generator.next_fact_id(&format!("fact-{id_namespace}")))
            .collect();
        let membership_ids = (0..fact_count)
            .map(|_| id_generator.next_membership_id(&format!("membership-{id_namespace}")))
            .collect();

        Self {
            episode_id,
            fact_ids,
            membership_ids,
            challenge_id: None,
            nonce: None,
        }
    }

    pub fn deterministic(
        id_namespace: &str,
        episode_id: ProblemEpisodeId,
        fact_count: usize,
    ) -> Self {
        Self::deterministic_with_fact_overrides(id_namespace, episode_id, fact_count, Vec::new())
    }

    pub fn deterministic_with_fact_overrides(
        id_namespace: &str,
        episode_id: ProblemEpisodeId,
        fact_count: usize,
        overrides: Vec<(usize, FactId)>,
    ) -> Self {
        let mut id_generator = DeterministicIdGenerator::new();
        let fact_id_prefix = format!("fact-{id_namespace}");
        let membership_id_prefix = format!("membership-{id_namespace}");
        let mut overrides: BTreeMap<usize, FactId> = overrides.into_iter().collect();
        let fact_ids = (0..fact_count)
            .map(|index| {
                let generated = id_generator.next_fact_id(&fact_id_prefix);
                overrides.remove(&index).unwrap_or(generated)
            })
            .collect();
        let membership_ids = (0..fact_count)
            .map(|_| id_generator.next_membership_id(&membership_id_prefix))
            .collect();

        Self {
            episode_id,
            fact_ids,
            membership_ids,
            challenge_id: None,
            nonce: None,
        }
    }

    pub fn with_challenge(mut self, challenge_id: ChallengeId, nonce: Nonce) -> Self {
        self.challenge_id = Some(challenge_id);
        self.nonce = Some(nonce);
        self
    }

    pub fn fact_id(&self, index: usize) -> FactId {
        self.fact_ids[index].clone()
    }

    pub fn membership_id(&self, index: usize) -> MembershipId {
        self.membership_ids[index].clone()
    }

    pub fn challenge_id_or(&self, fallback: ChallengeId) -> ChallengeId {
        self.challenge_id.clone().unwrap_or(fallback)
    }

    pub fn nonce_or(&self, fallback: Nonce) -> Nonce {
        self.nonce.clone().unwrap_or(fallback)
    }
}

pub fn identity_verification_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::IdentityVerificationWorkflow,
        label: "Initial patient identity binding".to_string(),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn parent_onboarding_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::IdentityVerificationWorkflow,
        label: "Initial identity onboarding".to_string(),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn access_authorization_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    action: SensitiveAction,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::AccessAuthorizationWorkflow,
        label: access_authorization_label(action),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn account_recovery_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::AccountRecoveryWorkflow,
        label: "Account recovery".to_string(),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn delegation_episode(
    id: ProblemEpisodeId,
    target_subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id: target_subject_id,
        episode_kind: EpisodeKind::DelegationWorkflow,
        label: "Authority delegation".to_string(),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn dispute_resolution_episode(
    id: ProblemEpisodeId,
    subject_id: SubjectId,
    authored_by: Author,
    authored_at: Timestamp,
) -> ProblemEpisode {
    ProblemEpisode {
        id,
        subject_id,
        episode_kind: EpisodeKind::DisputeResolutionWorkflow,
        label: "Identity dispute resolution".to_string(),
        problem_code: None,
        status: EpisodeStatus::Active,
        onset: None,
        authored_by,
        authored_at,
        notes: None,
    }
}

pub fn episode_membership(
    id: MembershipId,
    fact_id: FactId,
    episode_id: ProblemEpisodeId,
    role: FactRole,
    asserted_by: Author,
    asserted_at: Timestamp,
) -> EpisodeMembership {
    EpisodeMembership {
        id,
        fact_id,
        episode_id,
        role,
        asserted_by,
        asserted_at: TemporalAnchor::Point(asserted_at),
        status: MembershipStatus::Active,
    }
}

pub fn episode_relation(
    id: RelationId,
    source_episode_id: ProblemEpisodeId,
    target_episode_id: ProblemEpisodeId,
    relation_type: EpisodeRelationType,
    asserted_by: Author,
    asserted_at: Timestamp,
) -> EpisodeRelation {
    EpisodeRelation {
        id,
        source_episode_id,
        target_episode_id,
        relation_type,
        asserted_by,
        asserted_at: TemporalAnchor::Point(asserted_at),
        status: EpisodeRelationStatus::Active,
    }
}
