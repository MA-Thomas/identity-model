CREATE TABLE IF NOT EXISTS identity_app_attest_key_registrations (
  key_id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('development', 'production')),
  device_ref TEXT NOT NULL,
  public_key_bytes BYTEA NOT NULL,
  registered_at TEXT NOT NULL,
  attestation_challenge_nonce TEXT NOT NULL,
  attestation_format TEXT NOT NULL CHECK (attestation_format IN ('apple-app-attest'))
);

CREATE INDEX IF NOT EXISTS identity_app_attest_key_registrations_device_idx
  ON identity_app_attest_key_registrations (device_ref);

CREATE INDEX IF NOT EXISTS identity_app_attest_key_registrations_registered_idx
  ON identity_app_attest_key_registrations (registered_at);
