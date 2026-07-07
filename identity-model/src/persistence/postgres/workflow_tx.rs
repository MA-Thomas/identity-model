#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[cfg(feature = "postgres-adapter")]
pub(super) const IDENTITY_WORKFLOW_SEQUENCE_LOCK_KEY: i64 = 3_601_170_001;

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_stored_workflow_slice_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workflow_slice: &StoredIdentityWorkflowSlice,
) -> Result<(), PostgresAdapterError> {
    insert_workflow_transaction_row(
        transaction,
        &PostgresWorkflowTransactionRow::workflow_slice(
            &workflow_slice.transaction_id,
            &workflow_slice.committed_at,
        ),
    )
    .await?;
    insert_problem_episode_row(
        transaction,
        &PostgresProblemEpisodeRow::try_from_stored(&workflow_slice.episode)?,
    )
    .await?;
    for envelope in &workflow_slice.encrypted_facts {
        insert_encrypted_fact_row(
            transaction,
            &PostgresEncryptedFactRow::try_from_envelope(envelope)?,
        )
        .await?;
    }
    for membership in &workflow_slice.memberships {
        insert_episode_membership_row(
            transaction,
            &PostgresEpisodeMembershipRow::try_from_stored(membership)?,
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_stored_episode_composition_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    composition: &StoredEpisodeComposition,
) -> Result<(), PostgresAdapterError> {
    insert_workflow_transaction_row(
        transaction,
        &PostgresWorkflowTransactionRow::episode_composition(
            &composition.transaction_id,
            &composition.committed_at,
        ),
    )
    .await?;
    insert_problem_episode_row(
        transaction,
        &PostgresProblemEpisodeRow::try_from_stored(&composition.parent_episode)?,
    )
    .await?;
    for child_slice in &composition.child_slices {
        insert_problem_episode_row(
            transaction,
            &PostgresProblemEpisodeRow::try_from_stored(&child_slice.episode)?,
        )
        .await?;
        for envelope in &child_slice.encrypted_facts {
            insert_encrypted_fact_row(
                transaction,
                &PostgresEncryptedFactRow::try_from_envelope(envelope)?,
            )
            .await?;
        }
        for membership in &child_slice.memberships {
            insert_episode_membership_row(
                transaction,
                &PostgresEpisodeMembershipRow::try_from_stored(membership)?,
            )
            .await?;
        }
    }
    for relation in &composition.episode_relations {
        insert_episode_relation_row(
            transaction,
            &PostgresEpisodeRelationRow::try_from_stored(relation)?,
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn acquire_workflow_sequence_lock(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PostgresAdapterError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(IDENTITY_WORKFLOW_SEQUENCE_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn next_workflow_sequence_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<EncryptedWorkflowAppendSequenceState, PostgresAdapterError> {
    Ok(
        EncryptedWorkflowAppendSequenceState::with_relation_append_sequence(
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_facts",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episodes",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_memberships",
            )
            .await?,
            next_append_sequence_from_sql(
                transaction,
                "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_relations",
            )
            .await?,
        ),
    )
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn next_append_sequence_from_sql(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sql: &str,
) -> Result<AppendSequence, PostgresAdapterError> {
    let next_sequence: i64 = sqlx::query_scalar(sql)
        .fetch_one(&mut **transaction)
        .await
        .map_err(sqlx_error)?;
    if next_sequence < 0 {
        return Err(PostgresAdapterError::NegativeAppendSequence);
    }
    AppendSequence::try_from(next_sequence)
        .map_err(|_| PostgresAdapterError::AppendSequenceOutOfRange)
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_workflow_transaction_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresWorkflowTransactionRow,
) -> Result<(), PostgresAdapterError> {
    sqlx::query(
        r#"
        INSERT INTO identity_workflow_transactions (
          transaction_id,
          transaction_kind,
          committed_at
        )
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&row.transaction_id)
    .bind(&row.transaction_kind)
    .bind(&row.committed_at)
    .execute(&mut **transaction)
    .await
    .map_err(repository_sqlx_error)?;
    Ok(())
}
