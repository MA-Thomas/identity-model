# Local Keycloak Dev Setup

This guide starts a throwaway Keycloak realm on your machine and uses it to run the repo's live OIDC/JWKS smoke test.

The goal is only to prove this path works:

```text
Keycloak token -> JWKS verification -> FEN account-session facts -> append/replay
```

This is not a production Keycloak configuration.

## Prerequisites

- Docker or Podman
- `curl`
- optional but convenient: `jq`

The commands below use Docker. Replace `docker` with `podman` if that is your local container tool.

## 1. Start Keycloak

```sh
docker run --name fen-keycloak-dev \
  -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.6.1 \
  start-dev
```

Leave this terminal running.

Open the admin console:

```text
http://127.0.0.1:8080/admin/
```

Log in with:

```text
username: admin
password: admin
```

## 2. Create A Realm

In the admin console:

1. Open the realm selector.
2. Choose **Create realm**.
3. Set **Realm name** to `fen-dev`.
4. Save.

The issuer for this local realm is:

```text
http://127.0.0.1:8080/realms/fen-dev
```

Use `127.0.0.1` consistently. Mixing `localhost` and `127.0.0.1` can make issuer checks fail.

## 3. Create A Client

Inside the `fen-dev` realm:

1. Go to **Clients**.
2. Choose **Create client**.
3. Set **Client type** to `OpenID Connect`.
4. Set **Client ID** to `fen-identity-dev`.
5. Save.
6. Keep **Client authentication** off for this local public-client smoke test.
7. Enable **Direct access grants**.
8. Save.

The test will use this client ID:

```text
fen-identity-dev
```

## 4. Create A User

Inside the `fen-dev` realm:

1. Go to **Users**.
2. Choose **Create new user**.
3. Set **Username** to `marcus`.
4. Set **Email** to any test email.
5. Turn **Email verified** on if you want the FEN flow to emit a verified-email identity attribute fact.
6. Save.
7. Open the **Credentials** tab.
8. Set a password, for example `local-password`.
9. Turn **Temporary** off.
10. Save.

## 5. Get A Token

In a new terminal from the repo root:

```sh
TOKEN="$(curl -s \
  -X POST "http://127.0.0.1:8080/realms/fen-dev/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=fen-identity-dev" \
  -d "username=marcus" \
  -d "password=local-password" \
  | jq -r '.access_token')"
```

If you do not have `jq`, run the same `curl` command without the pipe and copy the `access_token` value manually:

```sh
curl -s \
  -X POST "http://127.0.0.1:8080/realms/fen-dev/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=fen-identity-dev" \
  -d "username=marcus" \
  -d "password=local-password"
```

## 6. Run The Live Keycloak Smoke Test

```sh
IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev" \
IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev" \
IDENTITY_MODEL_KEYCLOAK_TOKEN="$TOKEN" \
cargo test --features oidc-jwks-verifier \
  live_keycloak_token_can_bootstrap_append_and_replay_when_env_is_set \
  -- --nocapture
```

If it passes, the repo has proven that it can:

- fetch Keycloak discovery metadata
- fetch Keycloak JWKS keys
- verify the token signature and issuer/client context
- translate the login into FEN facts
- append the workflow
- replay the materialized identity state

## Common Problems

### The Token Is Empty

Check that the user password is not temporary, the username/password are correct, and **Direct access grants** is enabled for the client.

### Issuer Mismatch

Use this exact issuer:

```text
http://127.0.0.1:8080/realms/fen-dev
```

Do not mix `localhost` and `127.0.0.1`.

### Token Expired

Get a fresh token and rerun the test.

### Port 8080 Is Already In Use

Stop the process using port 8080 or map Keycloak to a different local port, then update the issuer and token endpoint commands to match that port.

## Stop And Remove The Local Container

```sh
docker rm -f fen-keycloak-dev
```

## References

- Keycloak Docker getting started: https://www.keycloak.org/getting-started/getting-started-docker
- Keycloak container development mode: https://www.keycloak.org/server/containers
