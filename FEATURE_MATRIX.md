# Feature Matrix

The default crate should stay dependency-light. Optional integrations should compile and test in
their own feature combinations so production wiring does not regress behind a disabled feature.

## Core Checks

Run these before handing off local work:

```sh
cargo test
cargo test --features mobile-http
cargo test --features postgres-adapter
cargo test --features oidc-jwks-verifier
cargo test --features ed25519-dalek-verifier
cargo test --features production-crypto
cargo test --features "mobile-http postgres-adapter"
cargo test --features runtime-server
```

## Live Harnesses

The live harnesses are env-gated. They compile under the feature above and skip unless their
environment variables are present.

PostgreSQL:

```sh
IDENTITY_MODEL_POSTGRES_URL="postgres://USER:PASSWORD@127.0.0.1:5432/DATABASE" \
cargo test --features postgres-adapter live_postgres -- --nocapture
```

PostgreSQL App Attest key state:

```sh
IDENTITY_MODEL_POSTGRES_URL="postgres://USER:PASSWORD@127.0.0.1:5432/DATABASE" \
cargo test --features postgres-adapter \
  live_postgres_app_attest_key_state_store_rejects_replay_when_env_is_set \
  -- --nocapture
```

Keycloak/OIDC:

```sh
IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev" \
IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev" \
IDENTITY_MODEL_KEYCLOAK_TOKEN="$TOKEN" \
cargo test --features oidc-jwks-verifier \
  live_keycloak_token_can_bootstrap_append_and_replay_when_env_is_set \
  -- --nocapture
```

Mobile HTTP plus PostgreSQL:

```sh
IDENTITY_MODEL_POSTGRES_URL="postgres://USER:PASSWORD@127.0.0.1:5432/DATABASE" \
cargo test --features "mobile-http postgres-adapter" \
  live_postgres_mobile_onboarding_http_endpoint_uses_durable_encrypted_facade_when_env_is_set \
  -- --nocapture
```

Runtime server compile path:

```sh
cargo check --features runtime-server --bin mobile_onboarding_server
```

## Boundary Rule

Adding a production dependency should usually mean adding or extending a feature-gated check here.
The default `cargo test` path should keep proving the domain model, deterministic fixtures, policy,
translation, and in-memory persistence without requiring PostgreSQL, Keycloak, Apple services, or a
production crypto provider.
