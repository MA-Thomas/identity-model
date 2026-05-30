use crate::fen::*;
use crate::flows::IdentityWorkflowSlice;
use crate::materialized::*;
use crate::workflows::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryError {
    DuplicateFactId,
    DuplicateEpisodeId,
    DuplicateMembershipId,
}

pub trait AppendOnlyFactRepository {
    fn append_fact(&mut self, fact: Fact) -> Result<(), RepositoryError>;
    fn all_facts(&self) -> Vec<Fact>;
    fn facts_for_subject(&self, subject_id: &SubjectId) -> Vec<Fact>;
}

pub trait AppendOnlyEpisodeRepository {
    fn append_episode(&mut self, episode: ProblemEpisode) -> Result<(), RepositoryError>;
    fn all_episodes(&self) -> Vec<ProblemEpisode>;
    fn episodes_for_subject(&self, subject_id: &SubjectId) -> Vec<ProblemEpisode>;
}

pub trait AppendOnlyMembershipRepository {
    fn append_membership(&mut self, membership: EpisodeMembership) -> Result<(), RepositoryError>;
    fn all_memberships(&self) -> Vec<EpisodeMembership>;
    fn memberships_for_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeMembership>;
    fn memberships_for_fact(&self, fact_id: &FactId) -> Vec<EpisodeMembership>;
}

pub trait IdentityWorkflowRepository:
    AppendOnlyFactRepository + AppendOnlyEpisodeRepository + AppendOnlyMembershipRepository
{
    fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryIdentityRepository {
    facts: Vec<Fact>,
    episodes: Vec<ProblemEpisode>,
    memberships: Vec<EpisodeMembership>,
}

impl InMemoryIdentityRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        append_workflow_slice_atomically(self, slice)
    }
}

impl IdentityWorkflowRepository for InMemoryIdentityRepository {
    fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        append_workflow_slice_atomically(self, slice)
    }
}

impl AppendOnlyFactRepository for InMemoryIdentityRepository {
    fn append_fact(&mut self, fact: Fact) -> Result<(), RepositoryError> {
        if self.facts.iter().any(|existing| existing.id == fact.id) {
            return Err(RepositoryError::DuplicateFactId);
        }

        self.facts.push(fact);
        Ok(())
    }

    fn all_facts(&self) -> Vec<Fact> {
        self.facts.clone()
    }

    fn facts_for_subject(&self, subject_id: &SubjectId) -> Vec<Fact> {
        self.facts
            .iter()
            .filter(|fact| &fact.subject_id == subject_id)
            .cloned()
            .collect()
    }
}

impl AppendOnlyEpisodeRepository for InMemoryIdentityRepository {
    fn append_episode(&mut self, episode: ProblemEpisode) -> Result<(), RepositoryError> {
        if self
            .episodes
            .iter()
            .any(|existing| existing.id == episode.id)
        {
            return Err(RepositoryError::DuplicateEpisodeId);
        }

        self.episodes.push(episode);
        Ok(())
    }

    fn all_episodes(&self) -> Vec<ProblemEpisode> {
        self.episodes.clone()
    }

    fn episodes_for_subject(&self, subject_id: &SubjectId) -> Vec<ProblemEpisode> {
        self.episodes
            .iter()
            .filter(|episode| &episode.subject_id == subject_id)
            .cloned()
            .collect()
    }
}

impl AppendOnlyMembershipRepository for InMemoryIdentityRepository {
    fn append_membership(&mut self, membership: EpisodeMembership) -> Result<(), RepositoryError> {
        if self
            .memberships
            .iter()
            .any(|existing| existing.id == membership.id)
        {
            return Err(RepositoryError::DuplicateMembershipId);
        }

        self.memberships.push(membership);
        Ok(())
    }

    fn all_memberships(&self) -> Vec<EpisodeMembership> {
        self.memberships.clone()
    }

    fn memberships_for_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeMembership> {
        self.memberships
            .iter()
            .filter(|membership| &membership.episode_id == episode_id)
            .cloned()
            .collect()
    }

    fn memberships_for_fact(&self, fact_id: &FactId) -> Vec<EpisodeMembership> {
        self.memberships
            .iter()
            .filter(|membership| &membership.fact_id == fact_id)
            .cloned()
            .collect()
    }
}

pub fn replay_identity_state(subject_id: SubjectId, facts: &[Fact]) -> MaterializedIdentityState {
    materialize_identity_state(subject_id, facts)
}

pub fn replay_identity_state_at(
    subject_id: SubjectId,
    facts: &[Fact],
    as_of: &Timestamp,
) -> MaterializedIdentityState {
    materialize_identity_state_at(subject_id, facts, as_of)
}

pub fn replay_identity_state_from_repository(
    subject_id: SubjectId,
    repository: &impl AppendOnlyFactRepository,
) -> MaterializedIdentityState {
    let facts = repository.facts_for_subject(&subject_id);
    replay_identity_state(subject_id, &facts)
}

pub fn replay_identity_state_from_repository_at(
    subject_id: SubjectId,
    repository: &impl AppendOnlyFactRepository,
    as_of: &Timestamp,
) -> MaterializedIdentityState {
    let facts = repository.facts_for_subject(&subject_id);
    replay_identity_state_at(subject_id, &facts, as_of)
}

fn append_workflow_slice_atomically(
    repository: &mut InMemoryIdentityRepository,
    slice: IdentityWorkflowSlice,
) -> Result<(), RepositoryError> {
    repository.validate_workflow_slice_append(&slice)?;

    repository.episodes.push(slice.episode);
    repository.facts.extend(slice.facts);
    repository.memberships.extend(slice.memberships);

    Ok(())
}

impl InMemoryIdentityRepository {
    fn validate_workflow_slice_append(
        &self,
        slice: &IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        if self
            .episodes
            .iter()
            .any(|existing| existing.id == slice.episode.id)
        {
            return Err(RepositoryError::DuplicateEpisodeId);
        }

        for (index, fact) in slice.facts.iter().enumerate() {
            if self.facts.iter().any(|existing| existing.id == fact.id)
                || slice.facts[..index]
                    .iter()
                    .any(|existing| existing.id == fact.id)
            {
                return Err(RepositoryError::DuplicateFactId);
            }
        }

        for (index, membership) in slice.memberships.iter().enumerate() {
            if self
                .memberships
                .iter()
                .any(|existing| existing.id == membership.id)
                || slice.memberships[..index]
                    .iter()
                    .any(|existing| existing.id == membership.id)
            {
                return Err(RepositoryError::DuplicateMembershipId);
            }
        }

        Ok(())
    }
}
