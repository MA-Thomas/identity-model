CREATE TABLE IF NOT EXISTS identity_facts (
  append_sequence BIGINT NOT NULL UNIQUE CHECK (append_sequence >= 0),
  transaction_id TEXT NOT NULL,
  committed_at TEXT NOT NULL,

  fact_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  occurred_kind TEXT NOT NULL CHECK (occurred_kind IN ('point', 'period')),
  occurred_start TEXT NOT NULL,
  occurred_end TEXT,
  payload_type TEXT NOT NULL,
  status_kind TEXT NOT NULL CHECK (status_kind IN ('active', 'superseded', 'entered_in_error')),
  status_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  materialization_policy_refs TEXT[] NOT NULL,

  encryption_algorithm TEXT NOT NULL,
  encryption_key_id TEXT NOT NULL,
  wrapped_dek_ref TEXT,
  nonce BYTEA NOT NULL,
  aad_version TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,

  CHECK (
    (occurred_kind = 'point' AND occurred_end IS NULL)
    OR
    (occurred_kind = 'period' AND occurred_end IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS identity_facts_subject_append_idx
  ON identity_facts (subject_id, append_sequence);

CREATE INDEX IF NOT EXISTS identity_facts_payload_type_idx
  ON identity_facts (payload_type);

CREATE INDEX IF NOT EXISTS identity_facts_status_kind_idx
  ON identity_facts (status_kind);

CREATE INDEX IF NOT EXISTS identity_facts_policy_refs_idx
  ON identity_facts USING GIN (materialization_policy_refs);

CREATE TABLE IF NOT EXISTS identity_fact_materialization_audit (
  audit_sequence BIGSERIAL PRIMARY KEY,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  subject_id TEXT NOT NULL,
  fact_ids TEXT[] NOT NULL,
  materialization_policy_refs TEXT[] NOT NULL,
  evaluated_policy_refs TEXT[] NOT NULL,
  caller TEXT,
  purpose TEXT,
  requested_at TEXT,
  outcome TEXT NOT NULL,
  error TEXT
);

CREATE INDEX IF NOT EXISTS identity_fact_materialization_audit_subject_idx
  ON identity_fact_materialization_audit (subject_id, audit_sequence);

CREATE INDEX IF NOT EXISTS identity_fact_materialization_audit_fact_ids_idx
  ON identity_fact_materialization_audit USING GIN (fact_ids);

CREATE INDEX IF NOT EXISTS identity_fact_materialization_audit_outcome_idx
  ON identity_fact_materialization_audit (outcome);
