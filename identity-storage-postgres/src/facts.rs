#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[derive(Debug, Clone)]
pub struct SqlxPostgresEncryptedFactRepository {
    pool: PgPool,
    envelope_store: fen_store_postgres::SqlxPostgresEnvelopeStore,
}

impl SqlxPostgresEncryptedFactRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            envelope_store: fen_store_postgres::SqlxPostgresEnvelopeStore::from_pool(pool.clone()),
            pool,
        }
    }

    pub async fn connect(database_url: &str) -> Result<Self, PostgresAdapterError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migration(&self) -> Result<(), PostgresAdapterError> {
        self.envelope_store
            .run_migrations()
            .await
            .map_err(fen_store_postgres_error)?;
        for migration in IDENTITY_POSTGRES_MIGRATIONS {
            sqlx::raw_sql(migration.sql)
                .execute(&self.pool)
                .await
                .map_err(sqlx_error)?;
        }
        Ok(())
    }

    pub async fn append_encrypted_fact(
        &self,
        envelope: &StoredEncryptedFact,
    ) -> Result<(), PostgresAdapterError> {
        self.append_encrypted_fact_in_family::<IdentityPayloadFamily>(envelope)
            .await
    }

    /// Family-generic append onto the shared payload-agnostic envelope table.
    /// Sibling families (e.g. `fen-health-econ`) reuse the same table, row
    /// shape, and append-sequence domain; only the payload-type label
    /// namespace is family-owned.
    pub async fn append_encrypted_fact_in_family<F: PayloadFamily>(
        &self,
        envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    ) -> Result<(), PostgresAdapterError> {
        self.envelope_store
            .append_encrypted_fact_in_family::<F>(envelope)
            .await
            .map_err(fen_store_postgres_error)
    }

    pub async fn all_encrypted_facts(
        &self,
    ) -> Result<Vec<StoredEncryptedFact>, PostgresAdapterError> {
        self.all_encrypted_facts_in_family::<IdentityPayloadFamily>()
            .await
    }

    /// Family-generic replay query, scoped in SQL to the family's closed
    /// label set. Sibling families share the envelope table, so an unscoped
    /// scan would surface labels the requested family cannot parse; scoping
    /// by exact labels keeps any label outside *every* family's set a hard
    /// error instead of a silently skipped row.
    pub async fn all_encrypted_facts_in_family<F: PayloadFamily>(
        &self,
    ) -> Result<Vec<StoredEncryptedFactEnvelope<F::PayloadType>>, PostgresAdapterError> {
        self.envelope_store
            .all_encrypted_facts_in_family::<F>()
            .await
            .map_err(fen_store_postgres_error)
    }

    pub async fn encrypted_facts_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredEncryptedFact>, PostgresAdapterError> {
        self.encrypted_facts_for_subject_in_family::<IdentityPayloadFamily>(subject_id)
            .await
    }

    /// Family-generic subject-scoped replay query; see
    /// [`Self::all_encrypted_facts_in_family`] for the label-scoping
    /// rationale (one subject can hold facts from several families).
    pub async fn encrypted_facts_for_subject_in_family<F: PayloadFamily>(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredEncryptedFactEnvelope<F::PayloadType>>, PostgresAdapterError> {
        self.envelope_store
            .encrypted_facts_for_subject_in_family::<F>(subject_id)
            .await
            .map_err(fen_store_postgres_error)
    }

    pub async fn record_materialization_audit_event(
        &self,
        event: &FactMaterializationAuditEvent,
    ) -> Result<(), PostgresAdapterError> {
        self.envelope_store
            .record_materialization_audit_event(event)
            .await
            .map_err(fen_store_postgres_error)
    }

    pub async fn append_stored_workflow_slice(
        &self,
        workflow_slice: &StoredIdentityWorkflowSlice,
    ) -> Result<(), PostgresAdapterError> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        insert_stored_workflow_slice_rows(&mut transaction, workflow_slice).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    pub async fn append_stored_episode_composition(
        &self,
        composition: &StoredEpisodeComposition,
    ) -> Result<(), PostgresAdapterError> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        insert_stored_episode_composition_rows(&mut transaction, composition).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    pub async fn all_stored_episodes(
        &self,
    ) -> Result<Vec<StoredProblemEpisode>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_PROBLEM_EPISODE_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(problem_episode_from_pg_row).collect()
    }

    pub async fn stored_episodes_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredProblemEpisode>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_PROBLEM_EPISODE_COLUMNS_SQL} WHERE subject_id = $1 ORDER BY append_sequence"
        ))
        .bind(&subject_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(problem_episode_from_pg_row).collect()
    }

    pub async fn all_stored_memberships(
        &self,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn stored_memberships_for_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} WHERE episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn stored_memberships_for_fact(
        &self,
        fact_id: &FactId,
    ) -> Result<Vec<StoredEpisodeMembership>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL} WHERE fact_id = $1 ORDER BY append_sequence"
        ))
        .bind(&fact_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(episode_membership_from_pg_row)
            .collect()
    }

    pub async fn all_stored_episode_relations(
        &self,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} ORDER BY append_sequence"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }

    pub async fn stored_relations_for_parent_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} WHERE target_episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }

    pub async fn stored_relations_for_child_episode(
        &self,
        episode_id: &ProblemEpisodeId,
    ) -> Result<Vec<StoredEpisodeRelation>, PostgresAdapterError> {
        let rows = sqlx::query(&format!(
            "{SELECT_EPISODE_RELATION_COLUMNS_SQL} WHERE source_episode_id = $1 ORDER BY append_sequence"
        ))
        .bind(&episode_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter().map(episode_relation_from_pg_row).collect()
    }
}
