use crate::fen::{FactId, Id, MembershipId, ProblemEpisodeId, RelationId, SubjectId};
use std::collections::BTreeMap;

pub trait IdGenerator {
    fn next_fact_id(&mut self, prefix: &str) -> FactId;
    fn next_episode_id(&mut self, prefix: &str) -> ProblemEpisodeId;
    fn next_membership_id(&mut self, prefix: &str) -> MembershipId;
    fn next_relation_id(&mut self, prefix: &str) -> RelationId {
        self.next_membership_id(prefix)
    }
    fn next_subject_id(&mut self, prefix: &str) -> SubjectId;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeterministicIdGenerator {
    counters_by_prefix: BTreeMap<String, u64>,
}

impl DeterministicIdGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&mut self, prefix: &str) -> Id {
        let next = self
            .counters_by_prefix
            .entry(prefix.to_string())
            .and_modify(|counter| *counter += 1)
            .or_insert(0);

        Id(format!("{prefix}-{next}"))
    }
}

impl IdGenerator for DeterministicIdGenerator {
    fn next_fact_id(&mut self, prefix: &str) -> FactId {
        self.next_id(prefix)
    }

    fn next_episode_id(&mut self, prefix: &str) -> ProblemEpisodeId {
        self.next_id(prefix)
    }

    fn next_membership_id(&mut self, prefix: &str) -> MembershipId {
        self.next_id(prefix)
    }

    fn next_relation_id(&mut self, prefix: &str) -> RelationId {
        self.next_id(prefix)
    }

    fn next_subject_id(&mut self, prefix: &str) -> SubjectId {
        self.next_id(prefix)
    }
}
