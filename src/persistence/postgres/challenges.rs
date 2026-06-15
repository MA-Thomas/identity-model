#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct PostgresLivePresenceChallengeStore {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
impl PostgresLivePresenceChallengeStore {
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

    pub async fn issue_live_presence_challenge_async(
        &self,
        challenge: &LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        if challenge.challenge_nonce.is_empty() {
            return Err(LivePresenceChallengeError::MissingChallengeNonce);
        }
        let row = PostgresLivePresenceChallengeRow::try_from_challenge(challenge)
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        let status_payload = row
            .status_payload
            .status_payload_json()
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
        sqlx::query(
            r#"
            INSERT INTO identity_live_presence_challenges (
              challenge_id,
              challenge_nonce,
              intended_workflow,
              expected_subject_id,
              expected_device_ref,
              expected_team_id,
              expected_bundle_id,
              expected_app_id,
              expected_environment,
              issued_at,
              expires_at,
              status_kind,
              status_payload,
              retry_policy_refs,
              manual_review_policy_refs,
              retention_policy_refs
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              $11, $12, CAST($13 AS jsonb), $14, $15, $16
            )
            "#,
        )
        .bind(&row.challenge_id)
        .bind(&row.challenge_nonce)
        .bind(&row.intended_workflow)
        .bind(&row.expected_subject_id)
        .bind(&row.expected_device_ref)
        .bind(&row.expected_team_id)
        .bind(&row.expected_bundle_id)
        .bind(&row.expected_app_id)
        .bind(&row.expected_environment)
        .bind(&row.issued_at)
        .bind(&row.expires_at)
        .bind(&row.status_kind)
        .bind(status_payload)
        .bind(&row.retry_policy_refs)
        .bind(&row.manual_review_policy_refs)
        .bind(&row.retention_policy_refs)
        .execute(&self.pool)
        .await
        .map_err(live_presence_challenge_sqlx_error)?;
        Ok(challenge.clone())
    }

    pub async fn live_presence_challenge_by_nonce_async(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError> {
        let sql =
            format!("{SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL} WHERE challenge_nonce = $1");
        let row = sqlx::query(&sql)
            .bind(challenge_nonce)
            .fetch_optional(&self.pool)
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        row.map(live_presence_challenge_from_pg_row).transpose()
    }

    pub async fn record_live_presence_challenge_status_async(
        &self,
        challenge_nonce: &str,
        status: &LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let challenge =
            locked_live_presence_challenge_by_nonce(&mut transaction, challenge_nonce).await?;
        if !matches!(challenge.status, LivePresenceChallengeStatus::Issued) {
            return Err(LivePresenceChallengeError::ChallengeAlreadyConsumed);
        }
        update_live_presence_challenge_status(&mut transaction, challenge_nonce, status).await?;
        transaction
            .commit()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let mut updated = challenge;
        updated.status = status.clone();
        Ok(updated)
    }

    pub async fn consume_verified_live_presence_challenge_async(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        let mut challenge =
            locked_live_presence_challenge_by_nonce(&mut transaction, &ceremony.challenge_nonce)
                .await?;

        if let Err(error) = validate_live_presence_challenge_context(
            &challenge,
            ceremony,
            app_attest,
            subject_id,
            observed_at,
        ) {
            if let Some(status) = postgres_terminal_live_presence_challenge_status_for_error(
                error,
                observed_at.clone(),
            ) {
                update_live_presence_challenge_status(
                    &mut transaction,
                    &ceremony.challenge_nonce,
                    &status,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(live_presence_challenge_sqlx_error)?;
            }
            return Err(error);
        }

        let status =
            terminal_live_presence_challenge_status_for_ceremony(ceremony, observed_at.clone());
        update_live_presence_challenge_status(&mut transaction, &ceremony.challenge_nonce, &status)
            .await?;
        transaction
            .commit()
            .await
            .map_err(live_presence_challenge_sqlx_error)?;
        challenge.status = status;
        Ok(challenge)
    }
}

#[cfg(feature = "postgres-adapter")]
impl LivePresenceChallengeStore for PostgresLivePresenceChallengeStore {
    fn issue_live_presence_challenge(
        &self,
        challenge: LivePresenceChallenge,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        run_live_presence_challenge_store_blocking(move || async move {
            store.issue_live_presence_challenge_async(&challenge).await
        })
    }

    fn live_presence_challenge_by_nonce(
        &self,
        challenge_nonce: &str,
    ) -> Result<Option<LivePresenceChallenge>, LivePresenceChallengeError> {
        let store = self.clone();
        let challenge_nonce = challenge_nonce.to_string();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .live_presence_challenge_by_nonce_async(&challenge_nonce)
                .await
        })
    }

    fn record_live_presence_challenge_status(
        &self,
        challenge_nonce: &str,
        status: LivePresenceChallengeStatus,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        let challenge_nonce = challenge_nonce.to_string();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .record_live_presence_challenge_status_async(&challenge_nonce, &status)
                .await
        })
    }

    fn consume_verified_live_presence_challenge(
        &self,
        ceremony: &VerifiedLivenessCeremony,
        app_attest: &VerifiedAppAttestAssertion,
        subject_id: &SubjectId,
        observed_at: &Timestamp,
    ) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
        let store = self.clone();
        let ceremony = ceremony.clone();
        let app_attest = app_attest.clone();
        let subject_id = subject_id.clone();
        let observed_at = observed_at.clone();
        run_live_presence_challenge_store_blocking(move || async move {
            store
                .consume_verified_live_presence_challenge_async(
                    &ceremony,
                    &app_attest,
                    &subject_id,
                    &observed_at,
                )
                .await
        })
    }
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn live_presence_challenge_from_pg_row(
    row: PgRow,
) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
    let status_payload_json: String = row
        .try_get("status_payload")
        .map_err(live_presence_challenge_sqlx_error)?;
    PostgresLivePresenceChallengeRow {
        challenge_id: row
            .try_get("challenge_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        challenge_nonce: row
            .try_get("challenge_nonce")
            .map_err(live_presence_challenge_sqlx_error)?,
        intended_workflow: row
            .try_get("intended_workflow")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_subject_id: row
            .try_get("expected_subject_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_device_ref: row
            .try_get("expected_device_ref")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_team_id: row
            .try_get("expected_team_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_bundle_id: row
            .try_get("expected_bundle_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_app_id: row
            .try_get("expected_app_id")
            .map_err(live_presence_challenge_sqlx_error)?,
        expected_environment: row
            .try_get("expected_environment")
            .map_err(live_presence_challenge_sqlx_error)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(live_presence_challenge_sqlx_error)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(live_presence_challenge_sqlx_error)?,
        status_kind: row
            .try_get("status_kind")
            .map_err(live_presence_challenge_sqlx_error)?,
        status_payload: PostgresLivePresenceChallengeStatusPayload::from_json(&status_payload_json)
            .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?,
        retry_policy_refs: row
            .try_get("retry_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
        manual_review_policy_refs: row
            .try_get("manual_review_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
        retention_policy_refs: row
            .try_get("retention_policy_refs")
            .map_err(live_presence_challenge_sqlx_error)?,
    }
    .try_into_challenge()
    .map_err(|_| LivePresenceChallengeError::StorageUnavailable)
}

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL: &str = r#"
SELECT
  challenge_id,
  challenge_nonce,
  intended_workflow,
  expected_subject_id,
  expected_device_ref,
  expected_team_id,
  expected_bundle_id,
  expected_app_id,
  expected_environment,
  issued_at,
  expires_at,
  status_kind,
  status_payload::text AS status_payload,
  retry_policy_refs,
  manual_review_policy_refs,
  retention_policy_refs
FROM identity_live_presence_challenges
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) async fn locked_live_presence_challenge_by_nonce(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_nonce: &str,
) -> Result<LivePresenceChallenge, LivePresenceChallengeError> {
    let sql = format!(
        "{SELECT_LIVE_PRESENCE_CHALLENGE_COLUMNS_SQL} WHERE challenge_nonce = $1 FOR UPDATE"
    );
    let row = sqlx::query(&sql)
        .bind(challenge_nonce)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(live_presence_challenge_sqlx_error)?;
    row.map(live_presence_challenge_from_pg_row)
        .transpose()?
        .ok_or(LivePresenceChallengeError::UnknownChallenge)
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn update_live_presence_challenge_status(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_nonce: &str,
    status: &LivePresenceChallengeStatus,
) -> Result<(), LivePresenceChallengeError> {
    let (status_kind, status_payload) = postgres_live_presence_challenge_status_parts(status);
    let status_payload = status_payload
        .status_payload_json()
        .map_err(|_| LivePresenceChallengeError::StorageUnavailable)?;
    let updated = sqlx::query(
        r#"
        UPDATE identity_live_presence_challenges
        SET status_kind = $1,
            status_payload = CAST($2 AS jsonb)
        WHERE challenge_nonce = $3
        "#,
    )
    .bind(status_kind)
    .bind(status_payload)
    .bind(challenge_nonce)
    .execute(&mut **transaction)
    .await
    .map_err(live_presence_challenge_sqlx_error)?
    .rows_affected();
    if updated == 0 {
        return Err(LivePresenceChallengeError::UnknownChallenge);
    }
    Ok(())
}
