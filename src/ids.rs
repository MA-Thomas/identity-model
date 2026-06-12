use crate::continuity::ChallengeId;
use crate::fen::{FactId, MembershipId, ProblemEpisodeId, RelationId, SubjectId};
use std::collections::BTreeMap;

pub trait IdGenerator {
    fn next_fact_id(&mut self, prefix: &str) -> FactId;
    fn next_episode_id(&mut self, prefix: &str) -> ProblemEpisodeId;
    fn next_membership_id(&mut self, prefix: &str) -> MembershipId;
    fn next_relation_id(&mut self, prefix: &str) -> RelationId {
        // Default implementation shares the membership counter sequence but
        // returns a distinct RelationId; the kinds no longer unify silently.
        RelationId(self.next_membership_id(prefix).0)
    }
    fn next_subject_id(&mut self, prefix: &str) -> SubjectId;
    fn next_challenge_id(&mut self, prefix: &str) -> ChallengeId {
        // Default implementation shares the episode counter sequence, which
        // preserves the exact ID strings produced before challenge IDs became
        // a distinct type (callers previously used next_episode_id directly).
        ChallengeId(self.next_episode_id(prefix).0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeterministicIdGenerator {
    counters_by_prefix: BTreeMap<String, u64>,
}

impl DeterministicIdGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&mut self, prefix: &str) -> String {
        let next = self
            .counters_by_prefix
            .entry(prefix.to_string())
            .and_modify(|counter| *counter += 1)
            .or_insert(0);

        format!("{prefix}-{next}")
    }
}

impl IdGenerator for DeterministicIdGenerator {
    fn next_fact_id(&mut self, prefix: &str) -> FactId {
        FactId(self.next_id(prefix))
    }

    fn next_episode_id(&mut self, prefix: &str) -> ProblemEpisodeId {
        ProblemEpisodeId(self.next_id(prefix))
    }

    fn next_membership_id(&mut self, prefix: &str) -> MembershipId {
        MembershipId(self.next_id(prefix))
    }

    fn next_relation_id(&mut self, prefix: &str) -> RelationId {
        RelationId(self.next_id(prefix))
    }

    fn next_subject_id(&mut self, prefix: &str) -> SubjectId {
        SubjectId(self.next_id(prefix))
    }
}
