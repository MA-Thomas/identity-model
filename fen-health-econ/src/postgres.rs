//! Durable PostgreSQL storage for reconciliation rule artifacts
//! (FEN_RECONCILIATION_RULE_ENGINE.md §A, sequencing step 5).
//!
//! Rule artifacts are plan-shaped reference data, so they live in an
//! operational table (`health_econ_reconciliation_rule_artifacts`,
//! migration 0006) versioned like policy artifacts — not in the fact graph.
//! This adapter preserves the in-memory store's semantics exactly:
//! `(rule_id, version)` is unique and historically stable, lifecycle moves
//! only `Draft -> Active -> Retired`, activation records the review, there
//! is no API for editing a definition in place, and effective-window gating
//! happens in Rust through the same parsed-timestamp helpers — the database
//! stores governance inputs, it does not evaluate them.
//!
//! The `definition_type` column carries the frozen discrepancy-kind identity
//! labels (the same strings the finding-identity hash uses); definition
//! parameters are normalized columns, so the reviewable definition
//! reconstructs without parsing rendered output.

use fen_core::time::timestamp_in_closed_interval;
use fen_core::{Author, AuthorId, AuthorType, TimeInterval, Timestamp};
use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};

use crate::rules::{
    ActiveReconciliationRule, ReconciliationRuleArtifact, ReconciliationRuleDefinition,
    RuleArtifactStatus, RuleReview, RuleStoreError,
};
use crate::schema::{Money, RuleArtifactRef};

pub const HEALTH_ECON_RECONCILIATION_RULES_MIGRATION_SQL: &str =
    include_str!("../migrations/0001_reconciliation_rule_artifacts.sql");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresRuleStoreError {
    /// The same typed errors the in-memory store raises, so callers see one
    /// vocabulary across adapters.
    Store(RuleStoreError),
    /// A stored row that cannot reconstruct a typed artifact is a hard
    /// error, never a silently skipped row.
    MalformedRow(String),
    Storage(String),
}

fn storage(error: sqlx::Error) -> PostgresRuleStoreError {
    PostgresRuleStoreError::Storage(error.to_string())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}

// -- Frozen labels -------------------------------------------------------------

pub fn postgres_rule_status_label(status: RuleArtifactStatus) -> &'static str {
    match status {
        RuleArtifactStatus::Draft => "draft",
        RuleArtifactStatus::Active => "active",
        RuleArtifactStatus::Retired => "retired",
    }
}

fn rule_status_from_postgres(value: &str) -> Result<RuleArtifactStatus, PostgresRuleStoreError> {
    match value {
        "draft" => Ok(RuleArtifactStatus::Draft),
        "active" => Ok(RuleArtifactStatus::Active),
        "retired" => Ok(RuleArtifactStatus::Retired),
        other => Err(PostgresRuleStoreError::MalformedRow(format!(
            "unknown rule artifact status label: {other}"
        ))),
    }
}

/// One label per closed definition variant — the same frozen strings as the
/// discrepancy-kind identity labels, because the variants map one-to-one
/// onto `DiscrepancyKind` mechanisms (spec §B).
pub fn postgres_rule_definition_type_label(
    definition: &ReconciliationRuleDefinition,
) -> &'static str {
    match definition {
        ReconciliationRuleDefinition::BillVsEobMismatch { .. } => "bill_vs_eob_mismatch",
        ReconciliationRuleDefinition::DuplicateCharge { .. } => "duplicate_charge",
        ReconciliationRuleDefinition::AboveAllowedAmount { .. } => "above_allowed_amount",
        ReconciliationRuleDefinition::AppealableDenial { .. } => "appealable_denial",
    }
}

fn author_type_label(author_type: AuthorType) -> &'static str {
    match author_type {
        AuthorType::Patient => "patient",
        AuthorType::Clinician => "clinician",
        AuthorType::System => "system",
        AuthorType::AiAssisted => "ai_assisted",
    }
}

fn author_type_from_postgres(value: &str) -> Result<AuthorType, PostgresRuleStoreError> {
    match value {
        "patient" => Ok(AuthorType::Patient),
        "clinician" => Ok(AuthorType::Clinician),
        "system" => Ok(AuthorType::System),
        "ai_assisted" => Ok(AuthorType::AiAssisted),
        other => Err(PostgresRuleStoreError::MalformedRow(format!(
            "unknown reviewer author type label: {other}"
        ))),
    }
}

// -- The store -------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PostgresReconciliationRuleStore {
    pool: PgPool,
}

impl PostgresReconciliationRuleStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, PostgresRuleStoreError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(storage)?;
        Ok(Self::from_pool(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migration(&self) -> Result<(), PostgresRuleStoreError> {
        sqlx::raw_sql(HEALTH_ECON_RECONCILIATION_RULES_MIGRATION_SQL)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    pub async fn insert_rule_artifact(
        &self,
        artifact: &ReconciliationRuleArtifact,
    ) -> Result<(), PostgresRuleStoreError> {
        let (tolerance_currency, tolerance_amount, match_window_days, carc_codes) =
            definition_columns(&artifact.definition);
        let result = sqlx::query(
            r#"
            INSERT INTO health_econ_reconciliation_rule_artifacts (
              rule_id,
              version,
              versioned_rule_ref,
              title,
              description,
              status,
              effective_start,
              effective_end,
              reviewed_by_author_type,
              reviewed_by_author_id,
              reviewed_by_display_name,
              reviewed_at,
              review_notes,
              definition_type,
              tolerance_currency,
              tolerance_amount_minor_units,
              match_window_days,
              appealable_carc_codes
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              $11, $12, $13, $14, $15, $16, $17, $18
            )
            "#,
        )
        .bind(&artifact.id.0)
        .bind(&artifact.version)
        .bind(&artifact.citation_ref().0)
        .bind(&artifact.title)
        .bind(&artifact.description)
        .bind(postgres_rule_status_label(artifact.status))
        .bind(artifact.effective_period.as_ref().map(|period| period.start.0.clone()))
        .bind(artifact.effective_period.as_ref().map(|period| period.end.0.clone()))
        .bind(
            artifact
                .review
                .as_ref()
                .map(|review| author_type_label(review.reviewed_by.author_type.clone())),
        )
        .bind(
            artifact
                .review
                .as_ref()
                .and_then(|review| review.reviewed_by.author_id.as_ref().map(|id| id.0.clone())),
        )
        .bind(
            artifact
                .review
                .as_ref()
                .and_then(|review| review.reviewed_by.display_name.clone()),
        )
        .bind(artifact.review.as_ref().map(|review| review.reviewed_at.0.clone()))
        .bind(artifact.review.as_ref().and_then(|review| review.notes.clone()))
        .bind(postgres_rule_definition_type_label(&artifact.definition))
        .bind(tolerance_currency)
        .bind(tolerance_amount)
        .bind(match_window_days)
        .bind(carc_codes)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(error) if is_unique_violation(&error) => Err(PostgresRuleStoreError::Store(
                RuleStoreError::DuplicateIdVersion {
                    id: artifact.id.clone(),
                    version: artifact.version.clone(),
                },
            )),
            Err(error) => Err(storage(error)),
        }
    }

    pub async fn get_rule_artifact(
        &self,
        id: &RuleArtifactRef,
        version: &str,
    ) -> Result<Option<ReconciliationRuleArtifact>, PostgresRuleStoreError> {
        let row = sqlx::query(
            "SELECT * FROM health_econ_reconciliation_rule_artifacts \
             WHERE rule_id = $1 AND version = $2",
        )
        .bind(&id.0)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.as_ref().map(artifact_from_row).transpose()
    }

    /// All versions for a rule ID in insertion order; retired versions are
    /// never deleted because findings cite them.
    pub async fn versions_of(
        &self,
        id: &RuleArtifactRef,
    ) -> Result<Vec<ReconciliationRuleArtifact>, PostgresRuleStoreError> {
        let rows = sqlx::query(
            "SELECT * FROM health_econ_reconciliation_rule_artifacts \
             WHERE rule_id = $1 ORDER BY insertion_order",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter().map(artifact_from_row).collect()
    }

    /// Activation is the review step: `Draft -> Active` only, recording who
    /// reviewed the version, when, and any notes, inside one transaction.
    pub async fn activate(
        &self,
        id: &RuleArtifactRef,
        version: &str,
        review: RuleReview,
    ) -> Result<(), PostgresRuleStoreError> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let status = self
            .locked_status(&mut tx, id, version)
            .await?;
        if status != RuleArtifactStatus::Draft {
            return Err(PostgresRuleStoreError::Store(
                RuleStoreError::InvalidLifecycleTransition {
                    id: id.clone(),
                    version: version.to_string(),
                    from: status,
                },
            ));
        }
        sqlx::query(
            "UPDATE health_econ_reconciliation_rule_artifacts \
             SET status = 'active', \
                 reviewed_by_author_type = $3, \
                 reviewed_by_author_id = $4, \
                 reviewed_by_display_name = $5, \
                 reviewed_at = $6, \
                 review_notes = $7 \
             WHERE rule_id = $1 AND version = $2",
        )
        .bind(&id.0)
        .bind(version)
        .bind(author_type_label(review.reviewed_by.author_type.clone()))
        .bind(review.reviewed_by.author_id.as_ref().map(|author_id| author_id.0.clone()))
        .bind(review.reviewed_by.display_name.clone())
        .bind(&review.reviewed_at.0)
        .bind(&review.notes)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    /// `Active -> Retired` only. Retired artifacts remain rows forever.
    pub async fn retire(
        &self,
        id: &RuleArtifactRef,
        version: &str,
    ) -> Result<(), PostgresRuleStoreError> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let status = self
            .locked_status(&mut tx, id, version)
            .await?;
        if status != RuleArtifactStatus::Active {
            return Err(PostgresRuleStoreError::Store(
                RuleStoreError::InvalidLifecycleTransition {
                    id: id.clone(),
                    version: version.to_string(),
                    from: status,
                },
            ));
        }
        sqlx::query(
            "UPDATE health_econ_reconciliation_rule_artifacts \
             SET status = 'retired' WHERE rule_id = $1 AND version = $2",
        )
        .bind(&id.0)
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    /// Resolves the rules eligible for evaluation at `as_of`, with the same
    /// semantics as the in-memory store: status `Active` in the database,
    /// effective-window gating in Rust through the parsed-timestamp helpers,
    /// and a malformed window on an active artifact is an error, not a skip.
    pub async fn active_rules(
        &self,
        as_of: &Timestamp,
    ) -> Result<Vec<ActiveReconciliationRule>, PostgresRuleStoreError> {
        let rows = sqlx::query(
            "SELECT * FROM health_econ_reconciliation_rule_artifacts \
             WHERE status = 'active' ORDER BY insertion_order",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;

        let mut resolved = Vec::new();
        for row in &rows {
            let artifact = artifact_from_row(row)?;
            if let Some(period) = &artifact.effective_period {
                let in_window = timestamp_in_closed_interval(as_of, &period.start, &period.end)
                    .map_err(|error| {
                        PostgresRuleStoreError::Store(RuleStoreError::MalformedEffectivePeriod {
                            id: artifact.id.clone(),
                            version: artifact.version.clone(),
                            error,
                        })
                    })?;
                if !in_window {
                    continue;
                }
            }
            resolved.push(ActiveReconciliationRule {
                rule_ref: artifact.citation_ref(),
                definition: artifact.definition.clone(),
            });
        }
        Ok(resolved)
    }

    async fn locked_status(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: &RuleArtifactRef,
        version: &str,
    ) -> Result<RuleArtifactStatus, PostgresRuleStoreError> {
        let row = sqlx::query(
            "SELECT status FROM health_econ_reconciliation_rule_artifacts \
             WHERE rule_id = $1 AND version = $2 FOR UPDATE",
        )
        .bind(&id.0)
        .bind(version)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?;
        let Some(row) = row else {
            return Err(PostgresRuleStoreError::Store(
                RuleStoreError::UnknownArtifact {
                    id: id.clone(),
                    version: version.to_string(),
                },
            ));
        };
        let status: String = row.try_get("status").map_err(storage)?;
        rule_status_from_postgres(&status)
    }
}

// -- Row mapping -------------------------------------------------------------------

type DefinitionColumns = (
    Option<String>,      // tolerance_currency
    Option<i64>,         // tolerance_amount_minor_units
    Option<i32>,         // match_window_days
    Option<Vec<String>>, // appealable_carc_codes
);

fn definition_columns(definition: &ReconciliationRuleDefinition) -> DefinitionColumns {
    match definition {
        ReconciliationRuleDefinition::BillVsEobMismatch { tolerance }
        | ReconciliationRuleDefinition::AboveAllowedAmount { tolerance } => (
            tolerance.as_ref().map(|money| money.currency.clone()),
            tolerance.as_ref().map(|money| money.amount_minor_units),
            None,
            None,
        ),
        ReconciliationRuleDefinition::DuplicateCharge { match_window_days } => {
            (None, None, Some(*match_window_days as i32), None)
        }
        ReconciliationRuleDefinition::AppealableDenial {
            appealable_carc_codes,
        } => (None, None, None, Some(appealable_carc_codes.clone())),
    }
}

fn artifact_from_row(
    row: &PgRow,
) -> Result<ReconciliationRuleArtifact, PostgresRuleStoreError> {
    let rule_id: String = row.try_get("rule_id").map_err(storage)?;
    let version: String = row.try_get("version").map_err(storage)?;
    let title: String = row.try_get("title").map_err(storage)?;
    let description: Option<String> = row.try_get("description").map_err(storage)?;
    let status_label: String = row.try_get("status").map_err(storage)?;
    let status = rule_status_from_postgres(&status_label)?;

    let effective_start: Option<String> = row.try_get("effective_start").map_err(storage)?;
    let effective_end: Option<String> = row.try_get("effective_end").map_err(storage)?;
    let effective_period = match (effective_start, effective_end) {
        (Some(start), Some(end)) => Some(TimeInterval {
            start: Timestamp(start),
            end: Timestamp(end),
        }),
        (None, None) => None,
        _ => {
            return Err(PostgresRuleStoreError::MalformedRow(format!(
                "rule {rule_id}@{version} stores half an effective period"
            )))
        }
    };

    let reviewed_at: Option<String> = row.try_get("reviewed_at").map_err(storage)?;
    let reviewed_by_author_type: Option<String> =
        row.try_get("reviewed_by_author_type").map_err(storage)?;
    let review = match (reviewed_at, reviewed_by_author_type) {
        (Some(reviewed_at), Some(author_type_label)) => {
            let author_id: Option<String> =
                row.try_get("reviewed_by_author_id").map_err(storage)?;
            let display_name: Option<String> =
                row.try_get("reviewed_by_display_name").map_err(storage)?;
            let notes: Option<String> = row.try_get("review_notes").map_err(storage)?;
            Some(RuleReview {
                reviewed_by: Author {
                    author_type: author_type_from_postgres(&author_type_label)?,
                    author_id: author_id.map(AuthorId::new),
                    display_name,
                },
                reviewed_at: Timestamp(reviewed_at),
                notes,
            })
        }
        (None, None) => None,
        _ => {
            return Err(PostgresRuleStoreError::MalformedRow(format!(
                "rule {rule_id}@{version} stores half a review"
            )))
        }
    };

    let definition_type: String = row.try_get("definition_type").map_err(storage)?;
    let tolerance_currency: Option<String> =
        row.try_get("tolerance_currency").map_err(storage)?;
    let tolerance_amount: Option<i64> = row
        .try_get("tolerance_amount_minor_units")
        .map_err(storage)?;
    let tolerance = match (tolerance_currency, tolerance_amount) {
        (Some(currency), Some(amount_minor_units)) => Some(Money {
            currency,
            amount_minor_units,
        }),
        (None, None) => None,
        _ => {
            return Err(PostgresRuleStoreError::MalformedRow(format!(
                "rule {rule_id}@{version} stores half a tolerance"
            )))
        }
    };
    let definition = match definition_type.as_str() {
        "bill_vs_eob_mismatch" => ReconciliationRuleDefinition::BillVsEobMismatch { tolerance },
        "above_allowed_amount" => ReconciliationRuleDefinition::AboveAllowedAmount { tolerance },
        "duplicate_charge" => {
            let match_window_days: Option<i32> =
                row.try_get("match_window_days").map_err(storage)?;
            let Some(match_window_days) = match_window_days else {
                return Err(PostgresRuleStoreError::MalformedRow(format!(
                    "duplicate-charge rule {rule_id}@{version} has no match window"
                )));
            };
            let match_window_days = u32::try_from(match_window_days).map_err(|_| {
                PostgresRuleStoreError::MalformedRow(format!(
                    "duplicate-charge rule {rule_id}@{version} has a negative match window"
                ))
            })?;
            ReconciliationRuleDefinition::DuplicateCharge { match_window_days }
        }
        "appealable_denial" => {
            let appealable_carc_codes: Option<Vec<String>> =
                row.try_get("appealable_carc_codes").map_err(storage)?;
            let Some(appealable_carc_codes) = appealable_carc_codes else {
                return Err(PostgresRuleStoreError::MalformedRow(format!(
                    "appealable-denial rule {rule_id}@{version} has no CARC list"
                )));
            };
            ReconciliationRuleDefinition::AppealableDenial {
                appealable_carc_codes,
            }
        }
        other => {
            return Err(PostgresRuleStoreError::MalformedRow(format!(
                "unknown rule definition type label: {other}"
            )))
        }
    };

    Ok(ReconciliationRuleArtifact {
        id: RuleArtifactRef::new(rule_id),
        version,
        title,
        description,
        status,
        effective_period,
        review,
        definition,
    })
}
