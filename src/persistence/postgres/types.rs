use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProblemEpisode {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub episode: ProblemEpisode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeMembership {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub membership: EpisodeMembership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeRelation {
    pub append_sequence: AppendSequence,
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub relation: EpisodeRelation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentityWorkflowSlice {
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub episode: StoredProblemEpisode,
    pub encrypted_facts: Vec<StoredEncryptedFact>,
    pub memberships: Vec<StoredEpisodeMembership>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpisodeComposition {
    pub transaction_id: PersistenceTransactionId,
    pub committed_at: Timestamp,
    pub parent_episode: StoredProblemEpisode,
    pub child_slices: Vec<StoredIdentityWorkflowSlice>,
    pub episode_relations: Vec<StoredEpisodeRelation>,
}
