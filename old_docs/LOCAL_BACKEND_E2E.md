# Local Backend E2E

This guide runs the mounted runtime server through the composed identity-onboarding endpoint:

```text
local Keycloak token
  + static App Attest-shaped evidence
  + Persona-normalized proofing evidence
  + provider-normalized static live-presence callback result
  + POST /mobile/identity-onboarding/live-presence-challenge
  -> POST /mobile/identity-onboarding/live-presence-callback
  -> POST /mobile/identity-onboarding
  -> encrypted PostgreSQL facts, workflow rows, audit rows, and safe summary
```

The harness is still intentionally backend-only. By default it does not require a real iPhone, Apple App Attest, Persona API access, or a liveness SDK.

## 1. Start PostgreSQL

Using Docker:

```sh
docker run --name fen-postgres-dev \
  -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=fen \
  -e POSTGRES_PASSWORD=fen \
  -e POSTGRES_DB=fen_identity_dev \
  postgres:16
```

Export the database URL:

```sh
export IDENTITY_MODEL_POSTGRES_URL="postgres://fen:fen@127.0.0.1:5432/fen_identity_dev"
```

Use a disposable database. The harness runs migrations, writes live rows, verifies them, and cleans up its own subject/challenge/key rows on success.

If local port `5432` is already occupied, map the container to another loopback port and use that port in `IDENTITY_MODEL_POSTGRES_URL`, for example:

```sh
docker run --name fen-postgres-e2e \
  -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=fen \
  -e POSTGRES_PASSWORD=fen \
  -e POSTGRES_DB=fen_identity_e2e \
  postgres:16

export IDENTITY_MODEL_POSTGRES_URL="postgres://fen:fen@127.0.0.1:15432/fen_identity_e2e"
```

## 2. Start Keycloak And Get A Token

Follow `LOCAL_KEYCLOAK_DEV.md` through the token step, then export:

```sh
export IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev"
export IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev"
export IDENTITY_MODEL_KEYCLOAK_TOKEN="$TOKEN"
```

Use a fresh token. The harness validates it against the current clock.

## 3. Run The Runtime Server E2E Harness

```sh
cargo test --features runtime-server \
  live_runtime_server_identity_onboarding_e2e_when_env_is_set \
  -- --nocapture
```

The test will:

- run PostgreSQL migrations
- start `mobile_onboarding_server` on a temporary local port
- wait for `/ready`
- issue a durable live-presence challenge through `POST /mobile/identity-onboarding/live-presence-challenge`
- map provider-normalized live-presence callback evidence through `POST /mobile/identity-onboarding/live-presence-callback`
- submit `POST /mobile/identity-onboarding`
- verify the accepted safe summary
- verify encrypted fact rows, materialization audit rows, App Attest key-state rows, and a used live-presence challenge

This harness has passed locally against disposable PostgreSQL and Keycloak services with a fresh Keycloak token.

## Optional: Apple Assertion Verifier Mode

The runtime server can opt into the production-crypto Apple assertion verifier:

```sh
export IDENTITY_MODEL_APP_ATTEST_VERIFIER="apple_assertion"
export IDENTITY_MODEL_APP_ATTEST_TEAM_ID="TEAMID1234"
export IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID="com.fen.identity"
export IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT="development"
```

Before sending assertions in this mode, the key ID in the assertion must already exist in `identity_app_attest_key_registrations`. The runtime now exposes a proof-app registration path for that:

```text
POST /mobile/app-attest/key-registration-challenge
POST /mobile/app-attest/key-registration
```

The first route returns a CSPRNG-generated registration nonce and the configured expected Apple app identity. The signed iOS app should call `DCAppAttestService.attestKey` with the SHA-256 hash of that nonce, then post the native attestation object as hex to the registration route. The registration route verifies the Apple attestation object and stores the trusted P-256 public key bytes in PostgreSQL.

Because `apple_assertion` mode does not have a static App Attest template to borrow from, also set `IDENTITY_MODEL_LIVENESS_CHALLENGE_NONCE`, `IDENTITY_MODEL_LIVENESS_DEVICE_REF`, `IDENTITY_MODEL_LIVENESS_OBSERVED_AT`, and `IDENTITY_MODEL_LIVENESS_EXPIRES_AT` when using the current static liveness verifier.

In this mode the submitted onboarding assertion can use either the compact decoded assertion envelope accepted by `AppleAppAttestAssertionVerifier` or the raw `DCAppAttestService` assertion-object envelope. The verifier checks the configured app identity, app-ID hash, challenge-bound client-data hash, and P-256 signature before the PostgreSQL key-state guard checks replay and sign-count monotonicity.

See `IOS_APP_ATTEST_PROOF.md` for the signed proof-app sequence and Swift-side envelope shape. The remaining App Attest work after the proof app is deciding how to store/use Apple attestation receipts for fraud-risk telemetry and keeping development/production environment behavior explicit.

## Common Problems

### The Harness Skips

Set all four required env vars:

```text
IDENTITY_MODEL_POSTGRES_URL
IDENTITY_MODEL_KEYCLOAK_ISSUER
IDENTITY_MODEL_KEYCLOAK_CLIENT_ID
IDENTITY_MODEL_KEYCLOAK_TOKEN
```

### The Token Fails

Refresh `IDENTITY_MODEL_KEYCLOAK_TOKEN`. Keycloak access tokens are short-lived in the local dev setup.

### Port Conflicts

The harness picks a temporary server port automatically. PostgreSQL and Keycloak still need their configured ports to be free.

## Stop Local Containers

```sh
docker rm -f fen-postgres-dev
docker rm -f fen-keycloak-dev
```
