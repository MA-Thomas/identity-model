use crate::{
    EncryptedFactPostgresRow, EncryptedFactPostgresRowWithoutStatusPayload, FenStorePostgresError,
    MaterializationAuditPostgresRow, FEN_STORE_POSTGRES_MIGRATIONS,
};
use fen_core::SubjectId;
use fen_store::{
    EncryptedFactStoreError, FactMaterializationAuditEvent, PayloadFamily,
    StoredEncryptedFactEnvelope,
};
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[derive(Debug, Clone)]
pub struct SqlxPostgresEnvelopeStore {
    pool: PgPool,
}

impl SqlxPostgresEnvelopeStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, FenStorePostgresError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migrations(&self) -> Result<(), FenStorePostgresError> {
        for migration in FEN_STORE_POSTGRES_MIGRATIONS {
            sqlx::raw_sql(migration.sql)
                .execute(&self.pool)
                .await
                .map_err(sqlx_error)?;
        }
        Ok(())
    }

    pub async fn append_encrypted_fact_in_family<F: PayloadFamily>(
        &self,
        envelope: &StoredEncryptedFactEnvelope<F::PayloadType>,
    ) -> Result<(), FenStorePostgresError> {
        let row = EncryptedFactPostgresRow::try_from_envelope_in_family::<F>(envelope)?;
        insert_encrypted_fact_row_on(&self.pool, &row).await
    }

    pub async fn all_encrypted_facts_in_family<F: PayloadFamily>(
        &self,
    ) -> Result<Vec<StoredEncryptedFactEnvelope<F::PayloadType>>, FenStorePostgresError> {
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

    pub async fn encrypted_facts_for_subject_in_family<F: PayloadFamily>(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Vec<StoredEncryptedFactEnvelope<F::PayloadType>>, FenStorePostgresError> {
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
    ) -> Result<(), FenStorePostgresError> {
        let row = MaterializationAuditPostgresRow::from_event(event);
        sqlx::query(
            r#"
            INSERT INTO identity_fact_materialization_audit (
              subject_id, fact_ids, materialization_policy_refs,
              evaluated_policy_refs, caller, purpose, requested_at, outcome, error
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
}

pub const SELECT_ENCRYPTED_FACT_COLUMNS_SQL: &str = r#"
SELECT
  append_sequence, transaction_id, committed_at, fact_id, subject_id,
  occurred_kind, occurred_start, occurred_end, payload_type, status_kind,
  status_payload::text AS status_payload, materialization_policy_refs,
  encryption_algorithm, encryption_key_id, wrapped_dek_ref, nonce,
  aad_version, ciphertext
FROM identity_facts
"#;

pub fn family_payload_type_labels<F: PayloadFamily>() -> Vec<String> {
    F::payload_type_variants()
        .iter()
        .map(|payload_type| F::payload_type_label(*payload_type).to_string())
        .collect()
}

pub async fn insert_encrypted_fact_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &EncryptedFactPostgresRow,
) -> Result<(), FenStorePostgresError> {
    insert_encrypted_fact_row_on(&mut **transaction, row).await
}

async fn insert_encrypted_fact_row_on<'e, E>(
    executor: E,
    row: &EncryptedFactPostgresRow,
) -> Result<(), FenStorePostgresError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let status_payload = row.status_payload_json()?;
    sqlx::query(
        r#"
        INSERT INTO identity_facts (
          append_sequence, transaction_id, committed_at, fact_id, subject_id,
          occurred_kind, occurred_start, occurred_end, payload_type, status_kind,
          status_payload, materialization_policy_refs, encryption_algorithm,
          encryption_key_id, wrapped_dek_ref, nonce, aad_version, ciphertext
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
    .execute(executor)
    .await
    .map_err(store_sqlx_error)?;
    Ok(())
}

fn envelope_from_pg_row_in_family<F: PayloadFamily>(
    row: PgRow,
) -> Result<StoredEncryptedFactEnvelope<F::PayloadType>, FenStorePostgresError> {
    encrypted_fact_row_from_pg_row(row)?.try_into_envelope_in_family::<F>()
}

fn encrypted_fact_row_from_pg_row(
    row: PgRow,
) -> Result<EncryptedFactPostgresRow, FenStorePostgresError> {
    let status_payload_json: String = row.try_get("status_payload").map_err(sqlx_error)?;
    EncryptedFactPostgresRow::with_status_payload_json(
        &status_payload_json,
        EncryptedFactPostgresRowWithoutStatusPayload {
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
            materialization_policy_refs: row
                .try_get("materialization_policy_refs")
                .map_err(sqlx_error)?,
            encryption_algorithm: row.try_get("encryption_algorithm").map_err(sqlx_error)?,
            encryption_key_id: row.try_get("encryption_key_id").map_err(sqlx_error)?,
            wrapped_dek_ref: row.try_get("wrapped_dek_ref").map_err(sqlx_error)?,
            nonce: row.try_get("nonce").map_err(sqlx_error)?,
            aad_version: row.try_get("aad_version").map_err(sqlx_error)?,
            ciphertext: row.try_get("ciphertext").map_err(sqlx_error)?,
        },
    )
}

fn sqlx_error(error: sqlx::Error) -> FenStorePostgresError {
    FenStorePostgresError::Sqlx(error.to_string())
}

fn store_sqlx_error(error: sqlx::Error) -> FenStorePostgresError {
    if let sqlx::Error::Database(database_error) = &error {
        match database_error.constraint() {
            Some("identity_facts_pkey") => {
                return FenStorePostgresError::Store(EncryptedFactStoreError::DuplicateFactId)
            }
            Some("identity_facts_append_sequence_key") => {
                return FenStorePostgresError::Store(
                    EncryptedFactStoreError::DuplicateAppendSequence,
                )
            }
            _ => {}
        }
    }
    sqlx_error(error)
}
