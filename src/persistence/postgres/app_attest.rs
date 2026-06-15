#[allow(unused_imports)]
use super::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

#[cfg(feature = "postgres-adapter")]
#[derive(Debug, Clone)]
pub struct PostgresAppAttestKeyStateStore {
    pool: PgPool,
}

#[cfg(feature = "postgres-adapter")]
impl PostgresAppAttestKeyStateStore {
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

    pub async fn record_verified_app_attest_assertion_async(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
        record_verified_app_attest_assertion_in_postgres(&self.pool, assertion).await
    }

    pub async fn app_attest_key_state_async(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError> {
        let row = sqlx::query(SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL)
            .bind(key_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(app_attest_sqlx_error)?;
        row.map(app_attest_key_state_from_pg_row).transpose()
    }

    pub async fn record_app_attest_key_registration_async(
        &self,
        registration: &AppAttestKeyRegistration,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError> {
        validate_app_attest_key_registration(registration)?;
        let existing = self
            .app_attest_key_registration_async(&registration.key_id)
            .await?;
        match existing {
            Some(existing) if &existing == registration => Ok(existing),
            Some(_) => Err(AppAttestAssertionVerificationError::KeyContextMismatch),
            None => {
                insert_app_attest_key_registration_row(
                    &self.pool,
                    &PostgresAppAttestKeyRegistrationRow::try_from_registration(registration)
                        .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
                )
                .await?;
                Ok(registration.clone())
            }
        }
    }

    pub async fn app_attest_key_registration_async(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyRegistration>, AppAttestAssertionVerificationError> {
        let row = sqlx::query(SELECT_APP_ATTEST_KEY_REGISTRATION_COLUMNS_SQL)
            .bind(key_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(app_attest_sqlx_error)?;
        row.map(app_attest_key_registration_from_pg_row).transpose()
    }

    pub async fn app_attest_challenge_nonce_seen_async(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError> {
        let seen: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
              SELECT 1
              FROM identity_app_attest_challenge_nonces
              WHERE key_id = $1
                AND challenge_nonce = $2
            )
            "#,
        )
        .bind(key_id)
        .bind(challenge_nonce)
        .fetch_one(&self.pool)
        .await
        .map_err(app_attest_sqlx_error)?;
        Ok(seen)
    }

    pub async fn revoke_app_attest_key_async(
        &self,
        key_id: &str,
    ) -> Result<(), AppAttestAssertionVerificationError> {
        let updated = sqlx::query(
            r#"
            UPDATE identity_app_attest_keys
            SET status = 'revoked'
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .execute(&self.pool)
        .await
        .map_err(app_attest_sqlx_error)?
        .rows_affected();
        if updated == 0 {
            return Err(AppAttestAssertionVerificationError::MissingKeyId);
        }
        Ok(())
    }
}

#[cfg(feature = "postgres-adapter")]
impl AppAttestKeyStateStore for PostgresAppAttestKeyStateStore {
    fn record_verified_app_attest_assertion(
        &self,
        assertion: &VerifiedAppAttestAssertion,
    ) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let assertion = assertion.clone();
        run_app_attest_store_blocking(move || async move {
            store
                .record_verified_app_attest_assertion_async(&assertion)
                .await
        })
    }

    fn app_attest_key_state(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyState>, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let key_id = key_id.to_string();
        run_app_attest_store_blocking(move || async move {
            store.app_attest_key_state_async(&key_id).await
        })
    }

    fn app_attest_challenge_nonce_seen(
        &self,
        key_id: &str,
        challenge_nonce: &str,
    ) -> Result<bool, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let key_id = key_id.to_string();
        let challenge_nonce = challenge_nonce.to_string();
        run_app_attest_store_blocking(move || async move {
            store
                .app_attest_challenge_nonce_seen_async(&key_id, &challenge_nonce)
                .await
        })
    }
}

#[cfg(feature = "postgres-adapter")]
impl AppAttestKeyRegistrationStore for PostgresAppAttestKeyStateStore {
    fn record_app_attest_key_registration(
        &self,
        registration: &AppAttestKeyRegistration,
    ) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let registration = registration.clone();
        run_app_attest_store_blocking(move || async move {
            store
                .record_app_attest_key_registration_async(&registration)
                .await
        })
    }

    fn app_attest_key_registration(
        &self,
        key_id: &str,
    ) -> Result<Option<AppAttestKeyRegistration>, AppAttestAssertionVerificationError> {
        let store = self.clone();
        let key_id = key_id.to_string();
        run_app_attest_store_blocking(move || async move {
            store.app_attest_key_registration_async(&key_id).await
        })
    }
}

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL: &str = r#"
SELECT
  key_id,
  team_id,
  bundle_id,
  app_id,
  environment,
  device_ref,
  status,
  registered_at,
  last_asserted_at,
  last_sign_count,
  last_challenge_nonce
FROM identity_app_attest_keys
WHERE key_id = $1
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) const SELECT_APP_ATTEST_KEY_REGISTRATION_COLUMNS_SQL: &str = r#"
SELECT
  key_id,
  team_id,
  bundle_id,
  app_id,
  environment,
  device_ref,
  public_key_bytes,
  registered_at,
  attestation_challenge_nonce,
  attestation_format
FROM identity_app_attest_key_registrations
WHERE key_id = $1
"#;

#[cfg(feature = "postgres-adapter")]
pub(super) fn app_attest_key_state_from_pg_row(
    row: PgRow,
) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
    PostgresAppAttestKeyStateRow {
        key_id: row
            .try_get("key_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        team_id: row
            .try_get("team_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        bundle_id: row
            .try_get("bundle_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        app_id: row
            .try_get("app_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        environment: row
            .try_get("environment")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        device_ref: row
            .try_get("device_ref")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        status: row
            .try_get("status")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        registered_at: row
            .try_get("registered_at")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_asserted_at: row
            .try_get("last_asserted_at")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_sign_count: row
            .try_get("last_sign_count")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        last_challenge_nonce: row
            .try_get("last_challenge_nonce")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
    }
    .try_into_key_state()
    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn app_attest_key_registration_from_pg_row(
    row: PgRow,
) -> Result<AppAttestKeyRegistration, AppAttestAssertionVerificationError> {
    PostgresAppAttestKeyRegistrationRow {
        key_id: row
            .try_get("key_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        team_id: row
            .try_get("team_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        bundle_id: row
            .try_get("bundle_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        app_id: row
            .try_get("app_id")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        environment: row
            .try_get("environment")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        device_ref: row
            .try_get("device_ref")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        public_key_bytes: row
            .try_get("public_key_bytes")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        registered_at: row
            .try_get("registered_at")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        attestation_challenge_nonce: row
            .try_get("attestation_challenge_nonce")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
        attestation_format: row
            .try_get("attestation_format")
            .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
    }
    .try_into_registration()
    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn record_verified_app_attest_assertion_in_postgres(
    pool: &PgPool,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<AppAttestKeyState, AppAttestAssertionVerificationError> {
    let mut transaction = pool.begin().await.map_err(app_attest_sqlx_error)?;
    let existing = sqlx::query(&format!(
        "{SELECT_APP_ATTEST_KEY_STATE_COLUMNS_SQL} FOR UPDATE"
    ))
    .bind(&assertion.key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(app_attest_sqlx_error)?
    .map(app_attest_key_state_from_pg_row)
    .transpose()?;
    let nonce_seen: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
          SELECT 1
          FROM identity_app_attest_challenge_nonces
          WHERE key_id = $1
            AND challenge_nonce = $2
        )
        "#,
    )
    .bind(&assertion.key_id)
    .bind(&assertion.challenge_nonce)
    .fetch_one(&mut *transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    if nonce_seen {
        return Err(AppAttestAssertionVerificationError::ChallengeReplay);
    }

    let updated = match existing {
        Some(mut state) => {
            validate_app_attest_key_state_transition(&state, assertion)?;
            insert_app_attest_challenge_nonce(&mut transaction, assertion).await?;
            state.last_sign_count = assertion.sign_count;
            state.last_asserted_at = assertion.asserted_at.clone();
            state.last_challenge_nonce = Some(assertion.challenge_nonce.clone());
            update_app_attest_key_state_row(
                &mut transaction,
                &PostgresAppAttestKeyStateRow::try_from_key_state(&state)
                    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
            )
            .await?;
            state
        }
        None => {
            let state = AppAttestKeyState::active_from_assertion(assertion);
            insert_app_attest_key_state_row(
                &mut transaction,
                &PostgresAppAttestKeyStateRow::try_from_key_state(&state)
                    .map_err(|_| AppAttestAssertionVerificationError::KeyStateUnavailable)?,
            )
            .await?;
            insert_app_attest_challenge_nonce(&mut transaction, assertion).await?;
            state
        }
    };

    transaction.commit().await.map_err(app_attest_sqlx_error)?;
    Ok(updated)
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_app_attest_key_registration_row(
    pool: &PgPool,
    row: &PostgresAppAttestKeyRegistrationRow,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        INSERT INTO identity_app_attest_key_registrations (
          key_id,
          team_id,
          bundle_id,
          app_id,
          environment,
          device_ref,
          public_key_bytes,
          registered_at,
          attestation_challenge_nonce,
          attestation_format
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(&row.key_id)
    .bind(&row.team_id)
    .bind(&row.bundle_id)
    .bind(&row.app_id)
    .bind(&row.environment)
    .bind(&row.device_ref)
    .bind(&row.public_key_bytes)
    .bind(&row.registered_at)
    .bind(&row.attestation_challenge_nonce)
    .bind(&row.attestation_format)
    .execute(pool)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) fn validate_app_attest_key_state_transition(
    state: &AppAttestKeyState,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<(), AppAttestAssertionVerificationError> {
    if state.status == AppAttestKeyStateStatus::Revoked {
        return Err(AppAttestAssertionVerificationError::KeyRevoked);
    }
    if !state.matches_assertion_context(assertion) {
        return Err(AppAttestAssertionVerificationError::KeyContextMismatch);
    }
    if assertion.sign_count <= state.last_sign_count {
        return Err(AppAttestAssertionVerificationError::SignCountNotAdvanced);
    }
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_app_attest_key_state_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresAppAttestKeyStateRow,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        INSERT INTO identity_app_attest_keys (
          key_id,
          team_id,
          bundle_id,
          app_id,
          environment,
          device_ref,
          status,
          registered_at,
          last_asserted_at,
          last_sign_count,
          last_challenge_nonce
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(&row.key_id)
    .bind(&row.team_id)
    .bind(&row.bundle_id)
    .bind(&row.app_id)
    .bind(&row.environment)
    .bind(&row.device_ref)
    .bind(&row.status)
    .bind(&row.registered_at)
    .bind(&row.last_asserted_at)
    .bind(row.last_sign_count)
    .bind(&row.last_challenge_nonce)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn update_app_attest_key_state_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PostgresAppAttestKeyStateRow,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        UPDATE identity_app_attest_keys
        SET last_asserted_at = $2,
            last_sign_count = $3,
            last_challenge_nonce = $4,
            status = $5
        WHERE key_id = $1
        "#,
    )
    .bind(&row.key_id)
    .bind(&row.last_asserted_at)
    .bind(row.last_sign_count)
    .bind(&row.last_challenge_nonce)
    .bind(&row.status)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}

#[cfg(feature = "postgres-adapter")]
pub(super) async fn insert_app_attest_challenge_nonce(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    assertion: &VerifiedAppAttestAssertion,
) -> Result<(), AppAttestAssertionVerificationError> {
    sqlx::query(
        r#"
        INSERT INTO identity_app_attest_challenge_nonces (
          key_id,
          challenge_nonce,
          first_seen_at
        )
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&assertion.key_id)
    .bind(&assertion.challenge_nonce)
    .bind(&assertion.asserted_at.0)
    .execute(&mut **transaction)
    .await
    .map_err(app_attest_sqlx_error)?;
    Ok(())
}
