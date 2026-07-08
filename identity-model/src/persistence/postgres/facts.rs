#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct SqlxPostgresEncryptedFactRepository {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
impl SqlxPostgresEncryptedFactRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
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
        let row = PostgresEncryptedFactRow::try_from_envelope_in_family::<F>(envelope)?;
        self.append_encrypted_fact_row(row).await
    }

    async fn append_encrypted_fact_row(
        &self,
        row: PostgresEncryptedFactRow,
    ) -> Result<(), PostgresAdapterError> {
        let status_payload = row.status_payload_json()?;

        sqlx::query(
            r#"
            INSERT INTO identity_facts (
              append_sequence,
              transaction_id,
              committed_at,
              fact_id,
              subject_id,
              occurred_kind,
              occurred_start,
              occurred_end,
              payload_type,
              status_kind,
              status_payload,
              materialization_policy_refs,
              encryption_algorithm,
              encryption_key_id,
              wrapped_dek_ref,
              nonce,
              aad_version,
              ciphertext
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              CAST($11 AS jsonb), $12, $13, $14, $15, $16, $17, $18
            )
            "#,
        )
        .bind(row.append_sequence)
        .bind(row.transaction_id)
        .bind(row.committed_at)
        .bind(row.fact_id)
        .bind(row.subject_id)
        .bind(row.occurred_kind)
        .bind(row.occurred_start)
        .bind(row.occurred_end)
        .bind(row.payload_type)
        .bind(row.status_kind)
        .bind(status_payload)
        .bind(row.materialization_policy_refs)
        .bind(row.encryption_algorithm)
        .bind(row.encryption_key_id)
        .bind(row.wrapped_dek_ref)
        .bind(row.nonce)
        .bind(row.aad_version)
        .bind(row.ciphertext)
        .execute(&self.pool)
        .await
        .map_err(repository_sqlx_error)?;

        Ok(())
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
        let rows = sqlx::query(&format!(
            "{SELECT_ENCRYPTED_FACT_COLUMNS_SQL} WHERE payload_type = ANY($1) ORDER BY append_sequence"
        ))
        .bind(family_payload_type_labels::<F>())
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(envelope_from_pg_row_in_family::<F>)
            .collect()
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
        let rows = sqlx::query(&format!(
            "{SELECT_ENCRYPTED_FACT_COLUMNS_SQL} WHERE subject_id = $1 AND payload_type = ANY($2) ORDER BY append_sequence"
        ))
        .bind(&subject_id.0)
        .bind(family_payload_type_labels::<F>())
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(envelope_from_pg_row_in_family::<F>)
            .collect()
    }

    pub async fn record_materialization_audit_event(
        &self,
        event: &FactMaterializationAuditEvent,
    ) -> Result<(), PostgresAdapterError> {
        let row = PostgresMaterializationAuditRow::from_event(event);

        sqlx::query(
            r#"
            INSERT INTO identity_fact_materialization_audit (
              subject_id,
              fact_ids,
              materialization_policy_refs,
              evaluated_policy_refs,
              caller,
              purpose,
              requested_at,
              outcome,
              error
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(row.subject_id)
        .bind(row.fact_ids)
        .bind(row.materialization_policy_refs)
        .bind(row.evaluated_policy_refs)
        .bind(row.caller)
        .bind(row.purpose)
        .bind(row.requested_at)
        .bind(row.outcome)
        .bind(row.error)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;

        Ok(())
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

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_ENCRYPTED_FACT_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  fact_id,
  subject_id,
  occurred_kind,
  occurred_start,
  occurred_end,
  payload_type,
  status_kind,
  status_payload::text AS status_payload,
  materialization_policy_refs,
  encryption_algorithm,
  encryption_key_id,
  wrapped_dek_ref,
  nonce,
  aad_version,
  ciphertext
FROM identity_facts
"#;

/// The family's closed label set as owned strings, in the shape `sqlx`
/// binds as a `text[]` parameter for `payload_type = ANY($n)` scoping.
#[cfg(feature = "postgres-adapter")]
pub(super) fn family_payload_type_labels<F: PayloadFamily>() -> Vec<String> {
    F::payload_type_variants()
        .iter()
        .map(|payload_type| F::payload_type_label(*payload_type).to_string())
        .collect()
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn envelope_from_pg_row_in_family<F: PayloadFamily>(
    row: PgRow,
) -> Result<StoredEncryptedFactEnvelope<F::PayloadType>, PostgresAdapterError> {
    fact_row_from_pg_row(row)?.try_into_envelope_in_family::<F>()
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn fact_row_from_pg_row(
    row: PgRow,
) -> Result<PostgresEncryptedFactRow, PostgresAdapterError> {
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    Ok(PostgresEncryptedFactRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        fact_id: row.try_get("fact_id").map_err(sqlx_error)?,
        subject_id: row.try_get("subject_id").map_err(sqlx_error)?,
        occurred_kind: row.try_get("occurred_kind").map_err(sqlx_error)?,
        occurred_start: row.try_get("occurred_start").map_err(sqlx_error)?,
        occurred_end: row.try_get("occurred_end").map_err(sqlx_error)?,
        payload_type: row.try_get("payload_type").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresFactStatusPayload::from_json(&status_payload_json)?,
        materialization_policy_refs: row
            .try_get("materialization_policy_refs")
            .map_err(sqlx_error)?,
        encryption_algorithm: row.try_get("encryption_algorithm").map_err(sqlx_error)?,
        encryption_key_id: row.try_get("encryption_key_id").map_err(sqlx_error)?,
        wrapped_dek_ref: row.try_get("wrapped_dek_ref").map_err(sqlx_error)?,
        nonce: row.try_get("nonce").map_err(sqlx_error)?,
        aad_version: row.try_get("aad_version").map_err(sqlx_error)?,
        ciphertext: row.try_get("ciphertext").map_err(sqlx_error)?,
    })
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_encrypted_fact_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEncryptedFactRow,
) -> Result<(), PostgresAdapterError> {
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_facts (
          append_sequence,
          transaction_id,
          committed_at,
          fact_id,
          subject_id,
          occurred_kind,
          occurred_start,
          occurred_end,
          payload_type,
          status_kind,
          status_payload,
          materialization_policy_refs,
          encryption_algorithm,
          encryption_key_id,
          wrapped_dek_ref,
          nonce,
          aad_version,
          ciphertext
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
          CAST($11 AS jsonb), $12, $13, $14, $15, $16, $17, $18
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.fact_id)
    .bind(&row.subject_id)
    .bind(&row.occurred_kind)
    .bind(&row.occurred_start)
    .bind(&row.occurred_end)
    .bind(&row.payload_type)
    .bind(&row.status_kind)
    .bind(status_payload)
    .bind(&row.materialization_policy_refs)
    .bind(&row.encryption_algorithm)
    .bind(&row.encryption_key_id)
    .bind(&row.wrapped_dek_ref)
    .bind(&row.nonce)
    .bind(&row.aad_version)
    .bind(&row.ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}
