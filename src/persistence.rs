use crate::fen::*;
use crate::flows::IdentityWorkflowSlice;
use crate::materialized::*;
use crate::workflows::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryError {
    DuplicateFactId,
    DuplicateEpisodeId,
    DuplicateMembershipId,
    DuplicateRelationId,
    DuplicateAppendSequence,
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

pub trait AppendOnlyEpisodeRelationRepository {
    fn append_episode_relation(&mut self, relation: EpisodeRelation)
        -> Result<(), RepositoryError>;
    fn all_episode_relations(&self) -> Vec<EpisodeRelation>;
    fn relations_for_parent_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeRelation>;
    fn relations_for_child_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeRelation>;

    fn child_episode_ids_for_parent(
        &self,
        episode_id: &ProblemEpisodeId,
        relation_type: EpisodeRelationType,
    ) -> Vec<ProblemEpisodeId> {
        self.relations_for_parent_episode(episode_id)
            .into_iter()
            .filter(|relation| relation.relation_type == relation_type)
            .filter(|relation| matches!(relation.status, EpisodeRelationStatus::Active))
            .map(|relation| relation.source_episode_id)
            .collect()
    }
}

pub trait IdentityWorkflowRepository:
    AppendOnlyFactRepository
    + AppendOnlyEpisodeRepository
    + AppendOnlyMembershipRepository
    + AppendOnlyEpisodeRelationRepository
{
    fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError>;

    fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
    ) -> Result<(), RepositoryError>;
}

mod encrypted;
mod postgres;
pub use encrypted::*;
pub use postgres::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryIdentityRepository {
    facts: Vec<Fact>,
    episodes: Vec<ProblemEpisode>,
    memberships: Vec<EpisodeMembership>,
    episode_relations: Vec<EpisodeRelation>,
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

    pub fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
    ) -> Result<(), RepositoryError> {
        append_episode_composition_atomically(self, parent_episode, child_slices, episode_relations)
    }
}

impl IdentityWorkflowRepository for InMemoryIdentityRepository {
    fn append_workflow_slice(
        &mut self,
        slice: IdentityWorkflowSlice,
    ) -> Result<(), RepositoryError> {
        append_workflow_slice_atomically(self, slice)
    }

    fn append_episode_composition(
        &mut self,
        parent_episode: ProblemEpisode,
        child_slices: Vec<IdentityWorkflowSlice>,
        episode_relations: Vec<EpisodeRelation>,
    ) -> Result<(), RepositoryError> {
        append_episode_composition_atomically(self, parent_episode, child_slices, episode_relations)
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

impl AppendOnlyEpisodeRelationRepository for InMemoryIdentityRepository {
    fn append_episode_relation(
        &mut self,
        relation: EpisodeRelation,
    ) -> Result<(), RepositoryError> {
        if self
            .episode_relations
            .iter()
            .any(|existing| existing.id == relation.id)
        {
            return Err(RepositoryError::DuplicateRelationId);
        }

        self.episode_relations.push(relation);
        Ok(())
    }

    fn all_episode_relations(&self) -> Vec<EpisodeRelation> {
        self.episode_relations.clone()
    }

    fn relations_for_parent_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeRelation> {
        self.episode_relations
            .iter()
            .filter(|relation| &relation.target_episode_id == episode_id)
            .cloned()
            .collect()
    }

    fn relations_for_child_episode(&self, episode_id: &ProblemEpisodeId) -> Vec<EpisodeRelation> {
        self.episode_relations
            .iter()
            .filter(|relation| &relation.source_episode_id == episode_id)
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

fn append_episode_composition_atomically(
    repository: &mut InMemoryIdentityRepository,
    parent_episode: ProblemEpisode,
    child_slices: Vec<IdentityWorkflowSlice>,
    episode_relations: Vec<EpisodeRelation>,
) -> Result<(), RepositoryError> {
    repository.validate_episode_composition_append(
        &parent_episode,
        &child_slices,
        &episode_relations,
    )?;

    repository.episodes.push(parent_episode);
    for slice in child_slices {
        repository.episodes.push(slice.episode);
        repository.facts.extend(slice.facts);
        repository.memberships.extend(slice.memberships);
    }
    repository.episode_relations.extend(episode_relations);

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

    fn validate_episode_composition_append(
        &self,
        parent_episode: &ProblemEpisode,
        child_slices: &[IdentityWorkflowSlice],
        episode_relations: &[EpisodeRelation],
    ) -> Result<(), RepositoryError> {
        if self
            .episodes
            .iter()
            .any(|existing| existing.id == parent_episode.id)
        {
            return Err(RepositoryError::DuplicateEpisodeId);
        }

        for (slice_index, slice) in child_slices.iter().enumerate() {
            if slice.episode.id == parent_episode.id
                || self
                    .episodes
                    .iter()
                    .any(|existing| existing.id == slice.episode.id)
                || child_slices[..slice_index]
                    .iter()
                    .any(|existing| existing.episode.id == slice.episode.id)
            {
                return Err(RepositoryError::DuplicateEpisodeId);
            }

            for (fact_index, fact) in slice.facts.iter().enumerate() {
                if self.facts.iter().any(|existing| existing.id == fact.id)
                    || slice.facts[..fact_index]
                        .iter()
                        .any(|existing| existing.id == fact.id)
                    || child_slices[..slice_index].iter().any(|previous_slice| {
                        previous_slice
                            .facts
                            .iter()
                            .any(|existing| existing.id == fact.id)
                    })
                {
                    return Err(RepositoryError::DuplicateFactId);
                }
            }

            for (membership_index, membership) in slice.memberships.iter().enumerate() {
                if self
                    .memberships
                    .iter()
                    .any(|existing| existing.id == membership.id)
                    || slice.memberships[..membership_index]
                        .iter()
                        .any(|existing| existing.id == membership.id)
                    || child_slices[..slice_index].iter().any(|previous_slice| {
                        previous_slice
                            .memberships
                            .iter()
                            .any(|existing| existing.id == membership.id)
                    })
                {
                    return Err(RepositoryError::DuplicateMembershipId);
                }
            }
        }

        for (relation_index, relation) in episode_relations.iter().enumerate() {
            if self
                .episode_relations
                .iter()
                .any(|existing| existing.id == relation.id)
                || episode_relations[..relation_index]
                    .iter()
                    .any(|existing| existing.id == relation.id)
            {
                return Err(RepositoryError::DuplicateRelationId);
            }
        }

        Ok(())
    }
}
