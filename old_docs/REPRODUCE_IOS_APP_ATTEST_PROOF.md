# Reproducing a Real-Device Apple App Attest Proof — Step-by-Step Runbook

This memo walks through everything needed to exercise a **real** Apple App Attest
key registration and assertion from a physical iPhone against the local FEN
runtime. It is written to be followed top to bottom. Each step says *what* to do
and *why* it matters, and the final section lists every failure we actually hit
and how to fix it.

If you just want the fast path, jump to [Quick checklist (returning users)](#quick-checklist-returning-users).

---

## What you are building

The iPhone app (`FenAppAttestProof`) asks Apple's Secure Enclave to generate and
attest a hardware-backed key. Apple returns cryptographic evidence. The FEN
backend verifies that evidence, stores the trusted public key in PostgreSQL, and
later verifies challenge-bound assertions from that registered key.

The phone can't talk to `localhost` on your Mac directly, and App Attest requires
HTTPS. So the request path is:

```
iPhone app  ──HTTPS──▶  Cloudflare quick tunnel  ──HTTP──▶  backend (127.0.0.1:3000)  ──▶  PostgreSQL (127.0.0.1:15432)
```

Four processes must be alive at the same time: **PostgreSQL**, the **backend**,
the **cloudflared tunnel**, and the **app on the phone**. Most failures below are
just one of these being down, stale, or pointed at the wrong place.

---

## Prerequisites (one time)

- macOS with **Xcode** installed and opened at least once (so command-line tools
  and a simulator runtime are set up).
- An **Apple Developer account** with a Team ID. This project uses team
  `FT36N9P233`. App Attest needs a real signing team; a free personal team will
  not issue the App Attest entitlement reliably.
- A **physical iPhone** (App Attest does not work on the Simulator — the Secure
  Enclave is required).
- **Docker Desktop** (for a throwaway PostgreSQL).
- **cloudflared** (`brew install cloudflared`) for the HTTPS tunnel.
- **Rust toolchain** (`cargo`) to build and run the backend.

Two identifiers must match **exactly** between the app and the backend:

| Setting              | Value used here                     |
|----------------------|-------------------------------------|
| Apple Team ID        | `FT36N9P233`                        |
| Bundle identifier    | `com.marcusthomas.fenappattestproof`|
| App Attest environment | `development` (Debug builds)      |

If any of these differ between the phone and the backend, Apple's attestation
will not verify.

---

## Step 1 — Start PostgreSQL

The backend stores registered keys and challenges here. Use a disposable
container so state is easy to reset.

```sh
docker rm -f fen-postgres-dev 2>/dev/null
docker run -d --name fen-postgres-dev \
  -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=fen \
  -e POSTGRES_PASSWORD=fen \
  -e POSTGRES_DB=fen_identity_dev \
  postgres:16
```

**Why port 15432 and not 5432?** This Mac already runs a native PostgreSQL on
`5432`. Binding the container to `5432` fails with *"address already in use"*, so
we map it to `15432` and point the backend there. (If you ever want to check
what's on 5432: `lsof -nP -iTCP:5432 -sTCP:LISTEN`.)

Confirm it booted:

```sh
docker logs fen-postgres-dev | tail -5    # expect: "database system is ready to accept connections"
```

---

## Step 2 — Set the backend environment

Everything below must run in the **same terminal window**. `export` only lives for
that one shell session — open a new tab and you lose it (a very common cause of
"it worked yesterday" failures).

In `apple_assertion` mode the server validates its whole config at startup, so it
needs more than just the App Attest identity: an encrypted-fact key, a
materialization policy ref, and (because there is no static App Attest template to
borrow from) the static liveness ceremony fields. This one block is enough for
both the registration run and the composed-onboarding run in Step 8.

```sh
# --- Database ---
export IDENTITY_MODEL_POSTGRES_URL="postgres://fen:fen@127.0.0.1:15432/fen_identity_dev"

# --- App Attest (real device / apple_assertion mode) ---
export IDENTITY_MODEL_APP_ATTEST_VERIFIER="apple_assertion"
export IDENTITY_MODEL_APP_ATTEST_TEAM_ID="FT36N9P233"
export IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID="com.marcusthomas.fenappattestproof"
export IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT="development"

# --- Encrypted fact key + materialization (required at boot) ---
export IDENTITY_MODEL_FACT_KEY_ID="real-device-key"
export IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export IDENTITY_MODEL_FACT_NONCE_DOMAIN_HEX="46454e32"
export IDENTITY_MODEL_MATERIALIZATION_POLICY_REFS="real-device-materialization@v1"

# --- Static liveness verifier (required at boot in apple_assertion mode) ---
# The challenge nonce AND device ref are rebound from each live request, so these
# are placeholders — you do NOT need to match the phone's Device Ref here.
# OBSERVED just needs to be in the past and EXPIRES in the future (a wide window).
export IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION="valid-live-presence"
export IDENTITY_MODEL_LIVENESS_CHALLENGE_NONCE="placeholder-rebound-per-request"
export IDENTITY_MODEL_LIVENESS_DEVICE_REF="placeholder-rebound-per-request"
export IDENTITY_MODEL_LIVENESS_OBSERVED_AT="2026-01-01T00:00:00Z"
export IDENTITY_MODEL_LIVENESS_EXPIRES_AT="2027-01-01T00:00:00Z"
export IDENTITY_MODEL_LIVENESS_PROVIDER_NAME="StaticLivePresenceProvider"
export IDENTITY_MODEL_LIVENESS_PROVIDER_EVENT_ID="liveness-event-real-device"
export IDENTITY_MODEL_LIVENESS_RESULT="passed"
export IDENTITY_MODEL_LIVENESS_ASSURANCE_LEVEL="high"
export IDENTITY_MODEL_LIVENESS_PAD_RESULT="passed"

# --- Keycloak / OIDC (issuer + client at boot; token added in Step 8) ---
export IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev"
export IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev"
```

- `apple_assertion` turns on the production-crypto verifier that checks real Apple
  attestations (instead of the static test template).
- The team/bundle/environment values are what the verifier expects the phone's
  evidence to contain.
- `IDENTITY_MODEL_LIVENESS_DEVICE_REF` is a placeholder: the server rebinds the
  liveness device ref (and challenge nonce) from each live request, so you do not
  need to match the phone's Device Ref. (Earlier this had to match by hand; the
  verifier now rebinds it, guarded by a regression test.)
- Keycloak only needs to be *running* for Step 8; the issuer/client strings are
  read at boot.

The backend runs migrations on startup by default, so the fresh container gets its
tables automatically.

---

## Step 3 — Start the backend

```sh
cargo run --features runtime-server --bin mobile_onboarding_server
```

Wait for:

```
mobile onboarding server listening on 127.0.0.1:3000
```

If it prints `could not connect to PostgreSQL: ... pool timed out`, PostgreSQL
isn't up or the URL is wrong — revisit Step 1/2. Leave this terminal running.

---

## Step 4 — Start the Cloudflare tunnel

In a **second terminal**:

```sh
cloudflared tunnel --url http://localhost:3000
```

It prints a line like:

```
https://<random-words>.trycloudflare.com
```

Copy that whole URL (including `https://`). **Each run mints a brand-new random
hostname** — the previous one is dead, so never reuse an old URL. Leave this
terminal running too; closing it kills the tunnel.

Sanity-check the tunnel reaches the backend before touching the phone:

```sh
curl -i https://<random-words>.trycloudflare.com/ready
```

A normal HTTP response means phone → Cloudflare → backend → Postgres is fully
wired. A `502 Bad Gateway` means the backend isn't answering on `localhost:3000`
(check Step 3).

---

## Step 5 — Xcode and the physical iPhone

1. Open `ios/FenAppAttestProof/FenAppAttestProof.xcodeproj` in Xcode.
2. Connect the iPhone by USB. Unlock it and tap **Trust This Computer** if
   prompted. **Developer Mode** must be on: Settings → Privacy & Security →
   Developer Mode → toggle on → reboot when prompted. This is a one-time,
   persistent setting — this phone already has it enabled, so on future runs you
   can skip it. (If the toggle isn't visible, plug the phone into Xcode once and
   it appears.)
3. Select the `FenAppAttestProof` target → **Signing & Capabilities**:
   - **Team**: the account for `FT36N9P233`.
   - **Bundle Identifier**: `com.marcusthomas.fenappattestproof`.
   - Signing is **Automatic**; let Xcode create/refresh the provisioning profile.
   - Confirm the **App Attest** capability is present (the entitlements file uses
     `$(APP_ATTEST_ENVIRONMENT)`, which is `development` for Debug builds).
4. In the top toolbar, pick your physical iPhone as the run destination (not a
   simulator).
5. Press **Run** (⌘R). Approve the developer certificate on the phone if asked
   (Settings → General → VPN & Device Management → trust your developer app).

Deployment target is iOS 16, so any modern iPhone works.

---

## Step 6 — Drive the proof in the app

With the app running on the phone:

1. Paste the current `https://<random-words>.trycloudflare.com` URL into the
   **Base URL** field (replace any old value entirely; no trailing slash).
2. Tap **Check Ready** — you want the backend to report ready.
3. Tap **Clear Local Key** (resets any previously stored key id).
4. Tap **Register New Key** — the phone generates and attests a key; the backend
   verifies the Apple attestation and stores the public key. This is the key
   moment.
5. Tap **Issue Live-Presence Challenge**.
6. Tap **Generate Assertion Envelope** — a success log like
   `Generated assertion envelope: 142 assertion bytes` means the registered key
   produced a valid assertion.
7. (Optional) Use the copy button to grab the envelope for a composed
   `POST /mobile/identity-onboarding` request (see `IOS_APP_ATTEST_PROOF.md`,
   step 5).

---

## Step 7 — Verify it landed in PostgreSQL

```sh
docker exec fen-postgres-dev psql -U fen -d fen_identity_dev \
  -c "SELECT key_id, device_ref, environment, registered_at FROM identity_app_attest_key_registrations;"
```

You should see one row with a base64 `key_id`, the app's `iphone-proof-…`
`device_ref`, `development`, and a timestamp. That row is the proof that a real
Secure Enclave key was attested and trusted end to end.

---

## Step 8 — Submit composed onboarding with the real assertion (optional)

Steps 1–7 prove **registration** and **assertion generation**. This step feeds the
real registered-key assertion through the full `POST /mobile/identity-onboarding`
pipeline, which is where the assertion verifier plus the PostgreSQL replay and
sign-count guards actually run. The assertion is bound to a single-use,
time-limited live-presence challenge, so it must be submitted **live and quickly**.

> Status: this `apple_assertion` + real-device onboarding path is being exercised
> for the first time. The most likely failure — the static liveness verifier
> pinning the device ref from env instead of the live request — has been
> pre-empted (the verifier now rebinds the device ref per request, with a
> regression test). Other real-path details may still surface, so treat a
> first-run failure as a finding, capture the backend log line, and iterate — the
> same loop that fixed registration.

Additional prerequisites:

- **Keycloak running** with a **fresh access token**. Follow `LOCAL_KEYCLOAK_DEV.md`
  through the token step, then export it in the terminal you'll run the script from:
  ```sh
  export IDENTITY_MODEL_KEYCLOAK_TOKEN="<fresh token>"
  export IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev"
  export IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev"
  export IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION="valid-live-presence"   # match the backend
  ```
- The backend from Step 3 running in `apple_assertion` mode with
  `IDENTITY_MODEL_LIVENESS_DEVICE_REF` set to this phone's Device Ref.

Then:

1. In the app, run **Register New Key** → **Issue Live-Presence Challenge** →
   **Generate Assertion Envelope** as usual.
2. Tap **Copy Onboarding Inputs**. This copies a small JSON blob (base URL,
   subject id, device ref, the live challenge nonce, timestamps, and the assertion
   envelope) to the phone's clipboard. Get it onto the Mac — AirDrop, Handoff
   universal clipboard, or paste into a note and copy on the Mac.
3. On the Mac, promptly run the submitter (it talks to `localhost:3000` directly,
   so the tunnel isn't needed here):
   ```sh
   pbpaste | python3 scripts/submit_onboarding.py
   # or:  python3 scripts/submit_onboarding.py --inputs-file inputs.json
   ```

The script performs the live-presence callback, then submits the composed
onboarding request with the real assertion, and prints the result. On success you
get `decision=accepted`, an assurance level, the active device, and a committed
fact count. The Persona identity-proofing and liveness inputs are dev-static
(normalized evidence the backend accepts as-is); only the App Attest assertion is
real hardware evidence here.

Speed matters: if the live-presence challenge expires before you submit, re-run the
three app steps to get a fresh nonce and assertion.

---

## Troubleshooting — the failures we actually hit

These are in the order you're most likely to encounter them.

### `Error: A server with the specified hostname could not be found`
The Base URL in the app points at a dead or mistyped hostname — almost always a
stale `trycloudflare.com` URL from a previous run. Start a fresh tunnel (Step 4)
and paste the new URL. If it persists, test the URL in Safari **on the phone**;
if Safari also can't reach it, the phone's Wi-Fi has no working DNS/internet or a
captive portal.

### `HTTP 502: Bad gateway` (from Cloudflare)
The tunnel is up but the backend isn't answering on `localhost:3000`. Check the
backend terminal is still on `listening on 127.0.0.1:3000`, and confirm the
tunnel targets the same port. `curl -i http://localhost:3000/ready` on the Mac
isolates backend-vs-tunnel.

### `could not connect to PostgreSQL: ... pool timed out`
PostgreSQL isn't running or the URL is wrong. Start the container (Step 1) and
confirm `IDENTITY_MODEL_POSTGRES_URL` points at `15432` in the backend's shell.

### `docker ... bind: address already in use` on 5432
The native PostgreSQL owns 5432. Don't fight it — run the container on `15432` as
in Step 1 and point the URL there.

### `HTTP 500: app_attest_registration_storage_unavailable` *(fixed in code)*
This was a backend bug: the registration/live-presence store writes ran on a
foreign Tokio runtime while the DB pool belonged to the server's main runtime, so
the connection acquire hung ~20–30s and then 500'd (no SQL ever reached Postgres).
Fixed by running those writes on the pool-owning runtime. If you ever see a
registration that *hangs for ~25s then 500s* with nothing logged in
`docker logs fen-postgres-dev`, that's this class of bug.

### `InvalidSignature` on Register New Key *(fixed in code)*
This was a certificate-chain bug: Apple's real chain is a P-256 leaf signed by a
**P-384** intermediate with `ecdsa-with-SHA256`. The verifier was selecting the
elliptic curve from the child certificate's signature OID instead of the issuer
key, feeding a P-384 key to a P-256 verifier. Fixed by choosing the curve from the
issuer key length. The tell in the backend log was
`chain pair 0 signature verification failed ... issuer key 97 bytes` (97 bytes =
P-384). Regression covered by
`apple_app_attest_key_registration_verifier_accepts_p384_intermediate_chain`.

### Composed onboarding (Step 8) fails
Work outward from the failing stage:
- **Live-presence callback error** — the `assertion` value must equal the backend's
  `IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION`; make sure the script's env matches
  the server's.
- **OIDC / token error** — the Keycloak token is stale (they're short-lived) or
  Keycloak isn't running; get a fresh one via `LOCAL_KEYCLOAK_DEV.md`.
- **Device / liveness binding error** — the verifier now rebinds both the
  challenge nonce and the device ref from each request, so `IDENTITY_MODEL_LIVENESS_DEVICE_REF`
  is a placeholder. If you still see a `DeviceMismatch`, confirm the app's Device
  Ref in the live-presence challenge matches the assertion envelope's device ref
  (both come from the same app install), and that the backend has this fix built.
- **Assertion expired / challenge already used** — the live-presence challenge is
  single-use and time-limited; re-run the three app steps for a fresh nonce and
  assertion, then submit again quickly.

### General tip
When Register New Key fails, the backend terminal prints lines starting with
`App Attest certificate diagnostic:` — that line names exactly which check tripped
and the key sizes involved. Read it first.

---

## Teardown

```sh
# stop the tunnel and backend: Ctrl-C in their terminals
docker rm -f fen-postgres-dev
```

The tunnel URL and the container are throwaway. The code fixes and tests are
permanent, so the next run is just a clean sequence.

---

## Quick checklist (returning users)

1. `docker start fen-postgres-dev` (or re-run the `docker run` from Step 1).
2. New terminal → `export` the env block from Step 2 (set `IDENTITY_MODEL_LIVENESS_DEVICE_REF` to your phone's Device Ref).
3. `cargo run --features runtime-server --bin mobile_onboarding_server` → wait for `listening`.
4. Second terminal → `cloudflared tunnel --url http://localhost:3000` → copy the new URL.
5. `curl -i <url>/ready` to confirm the path.
6. Phone: paste Base URL → **Check Ready** → **Clear Local Key** → **Register New Key** → **Issue Live-Presence Challenge** → **Generate Assertion Envelope**.
7. Verify the row with the `psql` SELECT in Step 7.
8. (Optional) Composed onboarding: export a fresh `IDENTITY_MODEL_KEYCLOAK_TOKEN`, tap **Copy Onboarding Inputs**, then `pbpaste | python3 scripts/submit_onboarding.py` promptly (Step 8).

---

## Related docs

- `IOS_APP_ATTEST_PROOF.md` — the backend contract and Swift-side envelope shape.
- `ios/FenAppAttestProof/README.md` — the app's own setup notes.
- `LOCAL_BACKEND_E2E.md` — the backend-only end-to-end harness (no phone needed).
