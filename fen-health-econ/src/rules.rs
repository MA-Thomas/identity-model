//! Reconciliation rule artifacts and the in-memory rule store
//! (FEN_RECONCILIATION_RULE_ENGINE.md §A/§B, sequencing step 1).
//!
//! A reconciliation rule is a reviewed, versioned governance input with the
//! same lifecycle shape as a `PolicyArtifact` — and a deliberately separate
//! type. Policies gate access; rules produce conclusions. They have different
//! owners, review cadences, and failure modes; sharing the discipline is the
//! point, sharing the type would couple the two review processes forever.
//!
//! Rule artifacts are plan-shaped **reference data, not facts**: there is no
//! `SubjectId` to anchor them to, so they live in an operational store
//! versioned like `PolicyArtifact` — in-memory first (this module), a
//! PostgreSQL adapter later (sequencing step 5).
//!
//! Findings cite `rule-id@version` ([`ReconciliationRuleArtifact::citation_ref`]).
//! The cited version is frozen the moment a production finding references it:
//! this store deliberately exposes **no** API for editing a definition in
//! place. Changing a rule means inserting a new version, activating it, and
//! retiring the old one.

use identity_model::time::{timestamp_in_closed_interval, TimestampParseError};
use identity_model::{Author, TimeInterval, Timestamp};

use crate::schema::{Money, RuleArtifactRef};

// ---------------------------------------------------------------------------
// Artifact types
// ---------------------------------------------------------------------------

/// A reviewed, versioned reconciliation rule (mirrors `PolicyArtifact`;
/// deliberately does not reuse it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationRuleArtifact {
    /// The stable rule ID. Findings cite the versioned form `rule-id@version`
    /// produced by [`Self::citation_ref`].
    pub id: RuleArtifactRef,
    pub version: String,
    pub title: String,
    pub description: Option<String>,
    pub status: RuleArtifactStatus,
    pub effective_period: Option<TimeInterval>,
    pub review: Option<RuleReview>,
    pub definition: ReconciliationRuleDefinition,
}

impl ReconciliationRuleArtifact {
    /// The versioned reference findings cite, e.g.
    /// `"eob-bill-reconciliation@v1"` (same shape as `versioned_policy_ref`).
    pub fn citation_ref(&self) -> RuleArtifactRef {
        versioned_rule_artifact_ref(&self.id, &self.version)
    }
}

/// `rule-id@version`, the citation shape pinned by the policy-artifact
/// contract's `policy-id@version` convention.
pub fn versioned_rule_artifact_ref(rule_id: &RuleArtifactRef, version: &str) -> RuleArtifactRef {
    RuleArtifactRef(format!("{}@{}", rule_id.0, version))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleArtifactStatus {
    /// Editable review candidate; never evaluated in production.
    Draft,
    /// Eligible for evaluation, subject to the effective window.
    Active,
    /// Part of history; retained because findings cite it, never deleted.
    Retired,
}

/// Review metadata recorded at activation (mirrors `PolicyReview`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleReview {
    pub reviewed_by: Author,
    pub reviewed_at: Timestamp,
    pub notes: Option<String>,
}

/// The closed, typed rule vocabulary — one variant per `DiscrepancyKind`
/// mechanism, parameters in the definition so the version captures them
/// (spec §B). Deliberately not a DSL: a reviewer approves a specific,
/// readable mechanism, the compiler forces every rule to have an evaluator,
/// and golden fixtures pin each variant's behavior.
///
/// Deliberately absent: `BenefitMatch` — it needs the versioned
/// benefit-catalog reference-data store (Extension E) and lands with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationRuleDefinition {
    /// `ProviderBill.amount_due` vs the matched Adjudication's
    /// `patient_responsibility`, beyond tolerance (`None` = exact).
    BillVsEobMismatch { tolerance: Option<Money> },
    /// The same service billed more than once inside the window.
    DuplicateCharge { match_window_days: u32 },
    /// Billed above the adjudication's allowed amount, beyond tolerance.
    AboveAllowedAmount { tolerance: Option<Money> },
    /// A denial whose CARC reason code is on the reviewed appealable list.
    /// The list is reviewed and versioned as part of the rule artifact.
    AppealableDenial { appealable_carc_codes: Vec<String> },
}

// ---------------------------------------------------------------------------
// Resolved rules (engine input)
// ---------------------------------------------------------------------------

/// An active rule resolved for evaluation: the versioned citation ref plus
/// the definition, nothing else. This is the engine's rule input shape —
/// the engine never sees lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveReconciliationRule {
    /// Versioned `rule-id@version`, cited verbatim in `DerivedFrom.rule_ref`.
    pub rule_ref: RuleArtifactRef,
    pub definition: ReconciliationRuleDefinition,
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleStoreError {
    /// `(rule_id, version)` must be unique; a used version is historically
    /// stable and is never overwritten.
    DuplicateIdVersion {
        id: RuleArtifactRef,
        version: String,
    },
    UnknownArtifact {
        id: RuleArtifactRef,
        version: String,
    },
    /// Lifecycle moves only `Draft -> Active -> Retired`.
    InvalidLifecycleTransition {
        id: RuleArtifactRef,
        version: String,
        from: RuleArtifactStatus,
    },
    /// An active artifact carried an effective period that does not parse;
    /// resolution fails loudly instead of silently including or excluding it.
    MalformedEffectivePeriod {
        id: RuleArtifactRef,
        version: String,
        error: TimestampParseError,
    },
}

/// The in-memory rule store: versioned like `PolicyArtifact` storage, with
/// activation as an intentional, review-recording step. `insert` accepts any
/// status so an adapter can reconstruct persisted artifacts; the lifecycle
/// methods enforce transitions for artifacts managed through this store.
#[derive(Debug, Default)]
pub struct InMemoryReconciliationRuleStore {
    artifacts: Vec<ReconciliationRuleArtifact>,
}

impl InMemoryReconciliationRuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, artifact: ReconciliationRuleArtifact) -> Result<(), RuleStoreError> {
        if self.get(&artifact.id, &artifact.version).is_some() {
            return Err(RuleStoreError::DuplicateIdVersion {
                id: artifact.id.clone(),
                version: artifact.version.clone(),
            });
        }
        self.artifacts.push(artifact);
        Ok(())
    }

    pub fn get(
        &self,
        id: &RuleArtifactRef,
        version: &str,
    ) -> Option<&ReconciliationRuleArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.id == *id && artifact.version == version)
    }

    /// All versions for a rule ID, in insertion order (history stays
    /// available for audit; retired versions are never deleted).
    pub fn versions_of(&self, id: &RuleArtifactRef) -> Vec<&ReconciliationRuleArtifact> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.id == *id)
            .collect()
    }

    /// Activation is the review step: it records who reviewed the version,
    /// when, and any notes. Only `Draft` artifacts can be activated.
    pub fn activate(
        &mut self,
        id: &RuleArtifactRef,
        version: &str,
        review: RuleReview,
    ) -> Result<(), RuleStoreError> {
        let artifact = self.get_mut(id, version)?;
        if artifact.status != RuleArtifactStatus::Draft {
            return Err(RuleStoreError::InvalidLifecycleTransition {
                id: id.clone(),
                version: version.to_string(),
                from: artifact.status,
            });
        }
        artifact.status = RuleArtifactStatus::Active;
        artifact.review = Some(review);
        Ok(())
    }

    /// Only `Active` artifacts can be retired. Retired artifacts remain in
    /// the store: past findings cite them.
    pub fn retire(&mut self, id: &RuleArtifactRef, version: &str) -> Result<(), RuleStoreError> {
        let artifact = self.get_mut(id, version)?;
        if artifact.status != RuleArtifactStatus::Active {
            return Err(RuleStoreError::InvalidLifecycleTransition {
                id: id.clone(),
                version: version.to_string(),
                from: artifact.status,
            });
        }
        artifact.status = RuleArtifactStatus::Retired;
        Ok(())
    }

    /// Resolves the rules eligible for evaluation at `as_of`: status
    /// `Active`, and — when an effective period is present — `as_of` inside
    /// the closed interval. Draft and retired artifacts are never resolved;
    /// an unparseable effective period on an active artifact is an error,
    /// not a silent skip.
    pub fn active_rules(
        &self,
        as_of: &Timestamp,
    ) -> Result<Vec<ActiveReconciliationRule>, RuleStoreError> {
        let mut resolved = Vec::new();
        for artifact in &self.artifacts {
            if artifact.status != RuleArtifactStatus::Active {
                continue;
            }
            if let Some(period) = &artifact.effective_period {
                let in_window = timestamp_in_closed_interval(as_of, &period.start, &period.end)
                    .map_err(|error| RuleStoreError::MalformedEffectivePeriod {
                        id: artifact.id.clone(),
                        version: artifact.version.clone(),
                        error,
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

    fn get_mut(
        &mut self,
        id: &RuleArtifactRef,
        version: &str,
    ) -> Result<&mut ReconciliationRuleArtifact, RuleStoreError> {
        self.artifacts
            .iter_mut()
            .find(|artifact| artifact.id == *id && artifact.version == version)
            .ok_or_else(|| RuleStoreError::UnknownArtifact {
                id: id.clone(),
                version: version.to_string(),
            })
    }
}
