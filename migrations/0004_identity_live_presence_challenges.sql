CREATE TABLE IF NOT EXISTS identity_live_presence_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge_nonce TEXT NOT NULL UNIQUE,
  intended_workflow TEXT NOT NULL CHECK (
    intended_workflow IN (
      'mobile_identity_onboarding',
      'account_recovery',
      'sensitive_action_step_up'
    )
  ),
  expected_subject_id TEXT,
  expected_device_ref TEXT,
  expected_team_id TEXT,
  expected_bundle_id TEXT,
  expected_app_id TEXT,
  expected_environment TEXT CHECK (
    expected_environment IS NULL
    OR expected_environment IN ('development', 'production')
  ),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status_kind TEXT NOT NULL CHECK (
    status_kind IN ('issued', 'used', 'expired', 'failed', 'manual_review')
  ),
  status_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  retry_policy_refs TEXT[] NOT NULL,
  manual_review_policy_refs TEXT[] NOT NULL,
  retention_policy_refs TEXT[] NOT NULL,

  CHECK (
    (expected_team_id IS NULL AND expected_bundle_id IS NULL AND expected_app_id IS NULL AND expected_environment IS NULL)
    OR
    (expected_team_id IS NOT NULL AND expected_bundle_id IS NOT NULL AND expected_app_id IS NOT NULL AND expected_environment IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS identity_live_presence_challenges_subject_idx
  ON identity_live_presence_challenges (expected_subject_id);

CREATE INDEX IF NOT EXISTS identity_live_presence_challenges_device_idx
  ON identity_live_presence_challenges (expected_device_ref);

CREATE INDEX IF NOT EXISTS identity_live_presence_challenges_status_idx
  ON identity_live_presence_challenges (status_kind);

CREATE INDEX IF NOT EXISTS identity_live_presence_challenges_expires_idx
  ON identity_live_presence_challenges (expires_at);
