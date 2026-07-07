#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_PROBLEM_EPISODE_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  episode_id,
  subject_id,
  episode_kind,
  label,
  problem_code::text AS problem_code,
  status_kind,
  status_payload::text AS status_payload,
  onset::text AS onset,
  authored_by::text AS authored_by,
  authored_at,
  notes
FROM identity_episodes
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_EPISODE_MEMBERSHIP_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  membership_id,
  fact_id,
  episode_id,
  role,
  asserted_by::text AS asserted_by,
  asserted_kind,
  asserted_start,
  asserted_end,
  status_kind,
  status_payload::text AS status_payload
FROM identity_episode_memberships
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_EPISODE_RELATION_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence,
  transaction_id,
  committed_at,
  relation_id,
  source_episode_id,
  target_episode_id,
  relation_type,
  asserted_by::text AS asserted_by,
  asserted_kind,
  asserted_start,
  asserted_end,
  status_kind,
  status_payload::text AS status_payload
FROM identity_episode_relations
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_problem_episode_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresProblemEpisodeRow,
) -> Result<(), PostgresAdapterError> {
    let problem_code = row.problem_code_json()?;
    let status_payload = row.status_payload_json()?;
    let onset = row.onset_json()?;
    let authored_by = row.authored_by_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episodes (
          append_sequence,
          transaction_id,
          committed_at,
          episode_id,
          subject_id,
          episode_kind,
          label,
          problem_code,
          status_kind,
          status_payload,
          onset,
          authored_by,
          authored_at,
          notes
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          CAST($10 AS jsonb), CAST($11 AS jsonb), CAST($12 AS jsonb), $13, $14
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.episode_id)
    .bind(&row.subject_id)
    .bind(&row.episode_kind)
    .bind(&row.label)
    .bind(problem_code)
    .bind(&row.status_kind)
    .bind(status_payload)
    .bind(onset)
    .bind(authored_by)
    .bind(&row.authored_at)
    .bind(&row.notes)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_episode_membership_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEpisodeMembershipRow,
) -> Result<(), PostgresAdapterError> {
    let asserted_by = row.asserted_by_json()?;
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episode_memberships (
          append_sequence,
          transaction_id,
          committed_at,
          membership_id,
          fact_id,
          episode_id,
          role,
          asserted_by,
          asserted_kind,
          asserted_start,
          asserted_end,
          status_kind,
          status_payload
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          $10, $11, $12, CAST($13 AS jsonb)
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.membership_id)
    .bind(&row.fact_id)
    .bind(&row.episode_id)
    .bind(&row.role)
    .bind(asserted_by)
    .bind(&row.asserted_kind)
    .bind(&row.asserted_start)
    .bind(&row.asserted_end)
    .bind(&row.status_kind)
    .bind(status_payload)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_episode_relation_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresEpisodeRelationRow,
) -> Result<(), PostgresAdapterError> {
    let asserted_by = row.asserted_by_json()?;
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_episode_relations (
          append_sequence,
          transaction_id,
          committed_at,
          relation_id,
          source_episode_id,
          target_episode_id,
          relation_type,
          asserted_by,
          asserted_kind,
          asserted_start,
          asserted_end,
          status_kind,
          status_payload
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9,
          $10, $11, $12, CAST($13 AS jsonb)
        )
        "#,
    )
    .bind(row.append_sequence)
    .bind(&row.transaction_id)
    .bind(&row.committed_at)
    .bind(&row.relation_id)
    .bind(&row.source_episode_id)
    .bind(&row.target_episode_id)
    .bind(&row.relation_type)
    .bind(asserted_by)
    .bind(&row.asserted_kind)
    .bind(&row.asserted_start)
    .bind(&row.asserted_end)
    .bind(&row.status_kind)
    .bind(status_payload)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn problem_episode_from_pg_row(
    row: PgRow,
) -> Result<StoredProblemEpisode, PostgresAdapterError> {
    let problem_code_json: Option<String> = row.try_get("problem_code").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    let onset_json: Option<String> = row.try_get("onset").map_err(sqlx_error)?;
    let authored_by_json: String = row.try_get("authored_by").map_err(sqlx_error)?;
    PostgresProblemEpisodeRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        episode_id: row.try_get("episode_id").map_err(sqlx_error)?,
        subject_id: row.try_get("subject_id").map_err(sqlx_error)?,
        episode_kind: row.try_get("episode_kind").map_err(sqlx_error)?,
        label: row.try_get("label").map_err(sqlx_error)?,
        problem_code: problem_code_json
            .as_deref()
            .map(PostgresCodedValueRecord::from_json)
            .transpose()?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresEpisodeStatusPayload::from_json(&status_payload_json)?,
        onset: onset_json
            .as_deref()
            .map(PostgresApproximateDateRecord::from_json)
            .transpose()?,
        authored_by: PostgresAuthorRecord::from_json(&authored_by_json)?,
        authored_at: row.try_get("authored_at").map_err(sqlx_error)?,
        notes: row.try_get("notes").map_err(sqlx_error)?,
    }
    .try_into_stored()
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn episode_membership_from_pg_row(
    row: PgRow,
) -> Result<StoredEpisodeMembership, PostgresAdapterError> {
    let asserted_by_json: String = row.try_get("asserted_by").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    PostgresEpisodeMembershipRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        membership_id: row.try_get("membership_id").map_err(sqlx_error)?,
        fact_id: row.try_get("fact_id").map_err(sqlx_error)?,
        episode_id: row.try_get("episode_id").map_err(sqlx_error)?,
        role: row.try_get("role").map_err(sqlx_error)?,
        asserted_by: PostgresAuthorRecord::from_json(&asserted_by_json)?,
        asserted_kind: row.try_get("asserted_kind").map_err(sqlx_error)?,
        asserted_start: row.try_get("asserted_start").map_err(sqlx_error)?,
        asserted_end: row.try_get("asserted_end").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresMembershipStatusPayload::from_json(&status_payload_json)?,
    }
    .try_into_stored()
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn episode_relation_from_pg_row(
    row: PgRow,
) -> Result<StoredEpisodeRelation, PostgresAdapterError> {
    let asserted_by_json: String = row.try_get("asserted_by").map_err(sqlx_error)?;
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    PostgresEpisodeRelationRow {
        append_sequence: row.try_get("append_sequence").map_err(sqlx_error)?,
        transaction_id: row.try_get("transaction_id").map_err(sqlx_error)?,
        committed_at: row.try_get("committed_at").map_err(sqlx_error)?,
        relation_id: row.try_get("relation_id").map_err(sqlx_error)?,
        source_episode_id: row.try_get("source_episode_id").map_err(sqlx_error)?,
        target_episode_id: row.try_get("target_episode_id").map_err(sqlx_error)?,
        relation_type: row.try_get("relation_type").map_err(sqlx_error)?,
        asserted_by: PostgresAuthorRecord::from_json(&asserted_by_json)?,
        asserted_kind: row.try_get("asserted_kind").map_err(sqlx_error)?,
        asserted_start: row.try_get("asserted_start").map_err(sqlx_error)?,
        asserted_end: row.try_get("asserted_end").map_err(sqlx_error)?,
        status_kind: row.try_get("status_kind").map_err(sqlx_error)?,
        status_payload: PostgresEpisodeRelationStatusPayload::from_json(&status_payload_json)?,
    }
    .try_into_stored()
}
