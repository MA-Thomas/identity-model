CREATE TABLE IF NOT EXISTS identity_app_attest_keys (
  key_id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('development', 'production')),
  device_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  registered_at TEXT NOT NULL,
  last_asserted_at TEXT NOT NULL,
  last_sign_count BIGINT NOT NULL CHECK (last_sign_count >= 0),
  last_challenge_nonce TEXT
);

CREATE INDEX IF NOT EXISTS identity_app_attest_keys_device_idx
  ON identity_app_attest_keys (device_ref);

CREATE INDEX IF NOT EXISTS identity_app_attest_keys_status_idx
  ON identity_app_attest_keys (status);

CREATE TABLE IF NOT EXISTS identity_app_attest_challenge_nonces (
  key_id TEXT NOT NULL REFERENCES identity_app_attest_keys(key_id) ON DELETE CASCADE,
  challenge_nonce TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY (key_id, challenge_nonce)
);

CREATE INDEX IF NOT EXISTS identity_app_attest_challenge_nonces_seen_idx
  ON identity_app_attest_challenge_nonces (first_seen_at);
