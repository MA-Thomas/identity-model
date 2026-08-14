-- Reconciliation rule artifacts: reviewed, versioned governance inputs for
-- the health-economic reconciliation rule engine
-- (FEN_RECONCILIATION_RULE_ENGINE.md, sequencing step 5).
--
-- Rule artifacts are plan-shaped reference data, not facts: no subject_id,
-- no envelope, an operational table versioned like policy artifacts. A
-- (rule_id, version) pair is historically stable once cited by a finding:
-- rows move Draft -> Active -> Retired and are never deleted or redefined.
--
-- definition_type carries the frozen discrepancy-kind identity labels (the
-- same strings the finding-identity hash uses); definition parameters are
-- normalized columns so the reviewable definition needs no JSON parsing.

CREATE TABLE IF NOT EXISTS health_econ_reconciliation_rule_artifacts (
  rule_id TEXT NOT NULL,
  version TEXT NOT NULL,
  versioned_rule_ref TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
  effective_start TEXT,
  effective_end TEXT,
  reviewed_by_author_type TEXT CHECK (
    reviewed_by_author_type IS NULL
    OR reviewed_by_author_type IN ('patient', 'clinician', 'system', 'ai_assisted')
  ),
  reviewed_by_author_id TEXT,
  reviewed_by_display_name TEXT,
  reviewed_at TEXT,
  review_notes TEXT,
  definition_type TEXT NOT NULL CHECK (
    definition_type IN (
      'bill_vs_eob_mismatch',
      'duplicate_charge',
      'above_allowed_amount',
      'appealable_denial'
    )
  ),
  tolerance_currency TEXT,
  tolerance_amount_minor_units BIGINT,
  match_window_days INTEGER CHECK (match_window_days IS NULL OR match_window_days >= 0),
  appealable_carc_codes TEXT[],
  insertion_order BIGSERIAL,

  PRIMARY KEY (rule_id, version),

  -- An effective window is stored whole or not at all.
  CHECK (
    (effective_start IS NULL AND effective_end IS NULL)
    OR (effective_start IS NOT NULL AND effective_end IS NOT NULL)
  ),

  -- Review metadata is stored whole or not at all (notes stay optional).
  CHECK (
    (reviewed_at IS NULL AND reviewed_by_author_type IS NULL)
    OR (reviewed_at IS NOT NULL AND reviewed_by_author_type IS NOT NULL)
  ),

  -- Tolerance is a whole Money value or absent.
  CHECK (
    (tolerance_currency IS NULL AND tolerance_amount_minor_units IS NULL)
    OR (tolerance_currency IS NOT NULL AND tolerance_amount_minor_units IS NOT NULL)
  ),

  -- Each definition variant carries exactly its own parameters.
  CHECK (
    (definition_type IN ('bill_vs_eob_mismatch', 'above_allowed_amount')
      AND match_window_days IS NULL
      AND appealable_carc_codes IS NULL)
    OR (definition_type = 'duplicate_charge'
      AND match_window_days IS NOT NULL
      AND tolerance_currency IS NULL
      AND tolerance_amount_minor_units IS NULL
      AND appealable_carc_codes IS NULL)
    OR (definition_type = 'appealable_denial'
      AND appealable_carc_codes IS NOT NULL
      AND match_window_days IS NULL
      AND tolerance_currency IS NULL
      AND tolerance_amount_minor_units IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS health_econ_reconciliation_rule_artifacts_status_idx
  ON health_econ_reconciliation_rule_artifacts (status);

CREATE INDEX IF NOT EXISTS health_econ_reconciliation_rule_artifacts_rule_id_idx
  ON health_econ_reconciliation_rule_artifacts (rule_id);
