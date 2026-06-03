# Next Steps

## Handoff Snapshot

Start here. The repo now has twelve relevant implementation slices:

- encrypted Fact persistence and policy-gated materialization are implemented and tested in memory
- PostgreSQL migrations, row mapping, SQLx repository methods, env-gated live adapter harnesses, rollback coverage, and replay-equivalence coverage are implemented
- a higher-level encryption-aware workflow repository facade converts workflow slices into encrypted stored envelopes, owns append-sequence assignment, delegates durable append to a stored-envelope repository, and replays policy-gated materialized state
- a PostgreSQL-backed encryption-aware workflow facade now allocates append sequences inside the same SQL transaction that writes encrypted facts, episodes, memberships, and workflow transaction rows
- Keycloak/OIDC account-session bootstrap, feature-gated JWKS verification, and an env-gated live Keycloak harness are implemented
- iPhone/App Attest-shaped device evidence can now be verified at an adapter boundary and bound into the account-token bootstrap workflow as a normal device-binding fact
- a shared mobile onboarding command now wraps OIDC token verification, App Attest-shaped device evidence verification, workflow append, replay, and a safe account/device summary; a dependency-free CLI smoke harness and a feature-gated HTTP handler call the same command
- an onboarding live-presence/liveness boundary now records `IdentityWitnessRecorded { witness_type: SelfieLivenessCheck }` from a verified ceremony result, binds that result to server challenge and App Attest device context, stores provider event refs/assurance/PAD result/expiry/retention policy refs instead of raw media, and creates continuity enrollment only after a passed liveness ceremony
- a feature-gated `production-crypto` adapter now encrypts fact plaintext with AES-256-GCM through `ring`, using the existing canonical associated-data contract and append-sequence-derived 96-bit nonces
- an App Attest key-state guard now records verified key state, used challenge nonces, sign-count progress, and revocation state so synthetic or future real App Attest verification cannot replay the same challenge or move a key across app/device context
- PostgreSQL now has an App Attest key-state migration and state-store adapter, with transactional challenge replay protection, sign-count updates, key revocation state, and runtime wiring through the existing verifier guard
- a feature-gated `runtime-server` binary now loads runtime config from env, connects to PostgreSQL, optionally runs migrations, assembles `SqlxPostgresEncryptionAwareWorkflowRepository` with the AES-256-GCM adapter, selects JWKS-backed OIDC verification, wraps the current static App Attest-shaped verifier in the durable PostgreSQL key-state guard, exposes `/health` and `/ready`, and forwards `POST /mobile/onboarding` through the same framework-neutral handler

The latest hardening pass also moved security-sensitive timestamp comparisons onto parsed UTC helpers, centralized encrypted persistence labels on typed enums, indexed materialized projection checks to avoid repeated scans, deduped replayed view rows, and split workflow outcome helpers out of the service facade.

The latest local Keycloak proof is complete. A throwaway Keycloak `26.6.1` dev setup created realm `fen-dev`, client `fen-identity-dev`, and user `marcus`, obtained a real access token, verified it through discovery/JWKS, appended the FEN account-session workflow, and replayed materialized state successfully. The reproducible setup lives in `LOCAL_KEYCLOAK_DEV.md`.

The PostgreSQL live harness has now passed against a disposable PostgreSQL database in this workspace. The live proof covered migration execution, encrypted append/query, duplicate fact ID, duplicate append sequence, all-facts replay order, subject-scoped query, policy-gated materialization, materialization audit insert, workflow-slice transaction append/query, PostgreSQL-backed encrypted workflow append/replay, transaction rollback, and replay-equivalence against `MaterializedIdentityState`.

`Phoros Onboarding and Recovery Architecture.pdf` has now been folded into `build_plan.md` as a product-state addendum. The build plan keeps the existing FEN fact-graph architecture and adds follow-on milestones for contact-channel evidence, Persona-default legal identity proofing, account and authority status projections, recovery policy setup, restricted-authority recovery, durable live-presence challenges, composed onboarding HTTP, and clinical binding/import states.

Persona is the default Phase 1 legal identity-proofing provider. Treat Persona as the first concrete identity-proofing adapter, not as identity truth. The adapter should verify and normalize Persona workflow results, then translate them into FEN identity witness, asserted attribute, risk, provenance, and external-ref facts. Keep the `IdentityProofingProvider` boundary provider-neutral so ID.me, Socure, Jumio, Entrust/Onfido, Veriff, LexisNexis, government assertions, or provider-mediated assertions can replace Persona later.

The next useful handoff move is adding server-issued onboarding live-presence challenges with durable nonce lifecycle: issued, expires, used, failed, and manual-review states. In parallel or immediately after, add the Persona-shaped identity-proofing boundary so the composed onboarding command can accept legal identity evidence from the default provider. After that, expose the composed identity-onboarding command through HTTP so the product path can submit OIDC, App Attest, Persona identity-proofing evidence, and video-selfie/liveness ceremony evidence through one narrow contract.

Do not treat Keycloak, PostgreSQL, a KMS, Apple App Attest, a liveness provider, or any provider SDK as the identity source of truth. They provide evidence and durable infrastructure. FEN owns the typed fact graph, policy gates, replay semantics, and materialized projections.

## Testable MVP Priority Order

These are the most important remaining workstreams for a testable MVP. They focus on proving one real product path end to end:

```text
iPhone evidence + OIDC session + live-presence ceremony result
  + Persona legal identity-proofing evidence
  -> server-issued challenges bound to app/device context
  -> production HTTP runtime
  -> real verifier/key boundaries
  -> encrypted PostgreSQL append
  -> policy-gated materialization
  -> safe onboarding summary
```

Do not expand into broad product surface area before this path is real. The MVP should prove that FEN can accept real mobile evidence, append durable encrypted facts, replay state through policy and key gates, and explain what happened without letting the web framework, database, IAM system, device provider, or liveness provider become the identity model.

1. **Onboarding Liveness Challenge Lifecycle**

   Add a durable `LivePresenceChallenge` or equivalent onboarding challenge store. The server should issue the nonce, bind it to the intended workflow, expected device/app context, subject/account context where known, expiry, retry/manual-review policy, and one-time use. The liveness ceremony should return a structured verification result to FEN; it should not make this crate depend on raw video, face embeddings, biometric templates, vendor SDK payloads, or capture implementation.

   MVP outcome: a passed video-selfie/liveness ceremony can be trusted as fresh physical-presence evidence for onboarding because it is bound to a server challenge and attested device context; failed or inconclusive ceremony results create auditable retry/manual-review paths instead of silent denial.

2. **Production Runtime**

   Build the actual server entry point around the existing framework-neutral mobile HTTP handler. The first feature-gated runtime server shell now loads config, connects to PostgreSQL, optionally runs migrations, assembles `SqlxPostgresEncryptionAwareWorkflowRepository`, selects JWKS-backed OIDC verification, wraps the current App Attest-shaped verifier boundary in durable PostgreSQL-backed key-state replay protection, selects the AES-256-GCM encryptor/key resolver, configures policy/materialization context, exposes health/readiness checks, and keeps the web layer thin.

   Remaining runtime work: expose the composed identity-onboarding command with OIDC, App Attest, government ID witness, and liveness ceremony evidence; move from the local shell to production-grade transport concerns such as concurrency, graceful shutdown, request tracing, deployment migration policy, stricter body/timeout handling, real App Attest cryptographic verification, async-native App Attest state operations, and durable key-management storage.

3. **Real Key And Crypto Boundary**

   The first AEAD adapter now exists behind `production-crypto`: AES-256-GCM through `ring`, canonical associated data, explicit 32-byte key validation, and 96-bit nonces derived from a deployment nonce domain plus append sequence.

   Remaining key work: move key material out of env-loaded local bytes, add DEK/KEK or KMS wrapping behavior, represent wrapped key state durably, support rotation/rewrapping policy, and ensure production deployments cannot start with test-only key config.

4. **Real Apple App Attest**

   Replace the current deterministic App Attest-shaped verifier with a real Apple App Attest adapter. The key-state guard now enforces app/team/bundle/device consistency, challenge replay protection, sign-count monotonicity, and revocation state after an assertion has been synthetically verified, and the runtime persists that state in PostgreSQL. The real adapter still needs to verify Apple attestation/assertion formats, bind server-issued challenge bytes, persist any real attestation-key metadata needed for verification, and translate only verified evidence into FEN facts.

   MVP outcome: the iPhone path proves app-bound device possession with real Apple evidence before FEN appends the device-binding workflow facts.

5. **Real Liveness Provider Boundary**

   Keep `src/liveness.rs` as the FEN-facing boundary and decide later whether the actual ceremony evaluator is an external vendor, an internal service, or a separate Rust crate/application. The provider-facing implementation should return structured pass/fail/inconclusive evidence with PAD result, provider event refs, expiry, assurance, and retention policy refs. Product language should say "live presence check," "video-selfie check," or "confirm you are physically present"; reserve "biological continuity" for the signed 1:1 check against an enrollment reference.

   MVP outcome: FEN can consume liveness evidence without turning the face capture process into identity itself.

6. **Persona Identity Proofing Boundary**

   Implement Persona as the default Phase 1 legal identity-proofing provider behind a provider-neutral boundary. The first version can use Persona sandbox/static fixtures or verified webhook/API result shapes, but the domain contract should already carry provider name, workflow ID, asserted attributes, evidence types, verification result, assurance level, risk signals, timestamp, expiration policy, and audit reference.

   MVP outcome: the composed onboarding path can record legal identity proofing as FEN evidence without hard-coding Persona as the identity model.

7. **Mac/Backend End-To-End Test Path**

   Create the fastest real-ish end-to-end test path on Mac before building the iPhone app. Run the runtime server against local PostgreSQL, local Keycloak, production-shaped encrypted workflow persistence, and Persona sandbox/static identity-proofing evidence. Drive the composed onboarding HTTP endpoint from a small local client or browser-visible harness and verify the safe summary, persisted facts, materialized projection, and audit rows.

   MVP outcome: the backend product flow can be exercised outside unit tests while the iPhone-specific App Attest and camera/liveness path is still being built.

8. **Policy And Governance Storage**

   Add durable storage and review lifecycle for policy artifacts that will be cited by access decisions and materialization decisions. Keep policy refs versioned, reviewed, lifecycle-aware, and stable over time. Avoid embedding mutable policy meaning directly in route handlers, database rows, or provider adapters.

   MVP outcome: materialization and access decisions can cite durable policy refs, and later audits can explain which policy version permitted or denied reliance.

9. **Database Operationalization**

   Turn the PostgreSQL adapter from a tested storage proof into an operational database boundary. Add migration version tracking, deployment-safe migration execution, connection-pool configuration, readiness checks, backup/restore expectations, index review, live harness setup guidance, and CI/pre-production coverage for feature-enabled database tests.

   MVP outcome: the encrypted append/replay path can be run repeatedly against a real database with predictable schema state and operational diagnostics.

10. **Product Mobile Path**

   After the server contract is real, build the smallest iOS proof path that obtains a Keycloak/OIDC token, obtains App Attest evidence for a server-issued challenge, guides the user through a video-selfie/live-presence ceremony, submits the mobile onboarding request, and displays the safe onboarding summary. Keep this as a proof app or thin product slice until the backend evidence contract stabilizes.

   Treat this as a staged test boundary. Backend MVP tests can keep using fixtures, synthetic App Attest-shaped evidence, Persona sandbox/static identity-proofing evidence, and static liveness verifier results. The real-device MVP needs a minimal native iPhone app because Apple App Attest evidence is produced by `DCAppAttestService` inside a signed app on a supported device, and the video-selfie ceremony needs a real camera/capture UX or provider SDK. An investor demo on the investor's own phone likely needs a TestFlight or demo build, HTTPS access to the runtime, a prepared Keycloak login path, a configured Persona workflow, a configured liveness provider path, and deliberate handling of App Attest development versus production environment behavior.

   MVP outcome: a real phone can exercise the full onboarding path without relying on CLI-only or synthetic HTTP fixtures.

11. **Hardening**

   Finish the security and reliability pass around the MVP path: threat-model the runtime, audit logging, replay failures, key-access failures, App Attest failure modes, liveness/PAD failure modes, stale physical-presence display, timestamp and clock-skew handling, error taxonomy, rate limits, request body limits, idempotency/retry behavior, feature-matrix CI, and safe redaction of logs and responses.

   MVP outcome: the testable path is not just happy-path functional; it has explicit failure behavior, observability, and guardrails around the places where identity, keys, device evidence, and encrypted materialization can go wrong.

## Next Handoff Commands

Re-run the already-proven local Keycloak smoke test only if the next owner needs to verify the OIDC path from scratch. Follow `LOCAL_KEYCLOAK_DEV.md`, then run:

```sh
IDENTITY_MODEL_KEYCLOAK_ISSUER="http://127.0.0.1:8080/realms/fen-dev" \
IDENTITY_MODEL_KEYCLOAK_CLIENT_ID="fen-identity-dev" \
IDENTITY_MODEL_KEYCLOAK_TOKEN="$TOKEN" \
cargo test --features oidc-jwks-verifier \
  live_keycloak_token_can_bootstrap_append_and_replay_when_env_is_set \
  -- --nocapture
```

Re-run this if the next owner needs to verify all live PostgreSQL adapter proofs from scratch:

```sh
IDENTITY_MODEL_POSTGRES_URL="postgres://USER:PASSWORD@127.0.0.1:5432/DATABASE" \
cargo test --features postgres-adapter \
  live_postgres \
  -- --nocapture
```

If a local database is needed, create a disposable PostgreSQL instance, point `IDENTITY_MODEL_POSTGRES_URL` at it, and let the tests run the migrations. Keep it disposable because the harness uses live append tables and cleans up only the rows it creates.

## Intended iPhone Onboarding Shape

The real-world mobile onboarding target should look like this:

```text
iPhone app signs in with Keycloak
  -> app obtains OIDC access token
  -> app obtains Apple App Attest or device assertion evidence for a server challenge
  -> app/provider completes Persona legal identity proofing
  -> app/provider completes a guided live-presence/video-selfie ceremony for a server challenge
  -> FEN verifies token, device evidence, Persona identity-proofing evidence, and liveness result at adapter boundaries
  -> FEN appends account-session, portal-login witness, verified-email, device evidence, government ID witness, selfie-liveness witness, and enrollment-reference facts
  -> replay materializes the current account/device/onboarding state
```

Keep these evidence streams separate:

- Keycloak/OIDC proves account/session context, issuer, client/audience, subject, authentication method, and verified email when present.
- iPhone/App Attest should prove app-bound device possession through a challenge, attestation/assertion verification, replay protection, bundle/team/app allow-listing, and durable attestation-key state.
- Persona legal identity proofing is the default Phase 1 external verifier. It proves civil or institutional identity evidence through a provider workflow and should be recorded as its own witness and asserted attributes, not merged into liveness or device evidence.
- Live-presence/video-selfie liveness proves a physically present human completed a fresh capture-path/PAD challenge. It should be recorded as `SelfieLivenessCheck`, not called face authentication or treated as identity itself.
- Biological continuity after enrollment is the signed 1:1 continuity check against an enrollment reference. Keep this distinct from onboarding liveness, even if the same camera ceremony helps create the enrollment reference.
- FEN should bind the verified account-session evidence, verified device evidence, government ID witness, liveness witness, and enrollment reference through workflow facts; no single evidence source should directly own the identity graph.

Do not generalize the current Apple-specific verifier into a broad `DeviceEvidenceVerifier` until a second platform integration is real. App Attest, Play Integrity, Android key attestation, Windows Hello/passkeys, TPM attestation, and managed-device attestation are related evidence sources, but they prove different claims. When Android or desktop enters scope, add a neutral verified-device-evidence shape that platform-specific verifiers can emit into. Also do not assume Apple App Attest covers desktop Mac apps; treat iOS/iPadOS App Attest, managed Apple device attestation, consumer Mac passkey/Secure Enclave evidence, Android app/device integrity, Android hardware-backed key attestation, and Windows Hello/TPM signals as distinct adapter inputs that FEN translates into typed facts.

## Priority Now: Liveness Challenge Shape

The in-memory Rust proof for encrypted Fact persistence exists, and the PostgreSQL adapter now has migration SQL, row mapping, a feature-gated SQLx repository, and an env-gated live integration test harness for encrypted Fact envelopes and workflow-slice transaction rows. The Keycloak/OIDC-facing slice now exists too: verified OIDC session evidence can enter FEN as normal credential, portal-login witness, and verified-email attribute facts, and a feature-gated JWKS verifier can validate live Keycloak-style JWTs.

The local Keycloak harness has been run against a throwaway `fen-dev` realm on `127.0.0.1:8080`; it created a realm/client/user, obtained a token, verified the token through discovery/JWKS, appended the FEN workflow, and replayed state successfully. The PostgreSQL harness has now also been run against a disposable live database, and rollback/replay-equivalence coverage has been added. The PostgreSQL-backed encrypted workflow facade now assigns durable append sequences under a transaction-scoped advisory lock, writes the stored workflow slice atomically, and replays materialized state through policy-gated decryption. The App Attest-shaped mobile device evidence slice now exists as a deterministic adapter boundary and is bound into the account-token bootstrap path.

The shared mobile onboarding command now exists in `src/mobile.rs`, the dependency-free CLI smoke harness in `src/bin/mobile_onboarding_smoke.rs` calls the account/device command, and the feature-gated HTTP handler in `src/mobile_http.rs` exposes `POST /mobile/onboarding` as a framework-agnostic method/path/body adapter. The existing HTTP path takes OIDC token evidence, App Attest-shaped assertion evidence, challenge nonce context, and client context; verifies OIDC and App Attest evidence at adapter boundaries; rejects device-reference mismatch before append; appends account/session/device-binding facts through the workflow repository boundary; replays materialized state; and returns a narrow account/device summary instead of exposing full workflow internals.

The liveness slice now adds a second, richer command path: `execute_mobile_identity_onboarding_command` verifies OIDC, verifies App Attest, verifies a structured liveness ceremony result, binds the liveness result to the App Attest challenge/device context, records government ID and selfie-liveness witnesses, creates continuity enrollment only when liveness passed, and returns a decision that distinguishes accepted onboarding from manual review. This path is intentionally not the camera implementation. It is the FEN-facing ceremony boundary.

The next implementation priority is the durable challenge lifecycle in front of that boundary. Add a server-issued onboarding challenge record with nonce, expiry, intended workflow, expected device/app context, expected subject/account context when known, use status, retry/manual-review state, and retention/policy refs. The liveness verifier or provider can be an external service, a separate application, or a future crate; this codebase should consume the structured result and preserve the audit graph.

The Persona identity-proofing boundary should land before or alongside the composed HTTP contract. The product-facing onboarding path should eventually carry OIDC, App Attest, Persona legal identity proofing, and liveness ceremony evidence. The older account/device HTTP path can remain as a smaller smoke surface.

Before the iPhone app, create a Mac/backend end-to-end harness that runs the runtime server against local PostgreSQL and Keycloak, injects Persona sandbox/static identity-proofing evidence, submits the composed onboarding HTTP request, and verifies persisted encrypted facts plus the safe onboarding summary. This is the fastest honest way to test the product flow while real App Attest and camera/liveness capture are still pending.

The intended entry-point shape is:

```text
identity onboarding command
  input: OIDC token, App Attest evidence, Persona identity-proofing assertion, liveness ceremony result, client context
  verifies: challenge freshness, OIDC session, device evidence, legal identity proofing, liveness/PAD result, subject/device consistency
  appends: credential, portal-login witness, verified-email when present, device-binding, government ID witness, selfie-liveness witness, enrollment reference when accepted
  persists: through the encryption-aware workflow repository over durable stored-envelope storage
  returns: safe onboarding summary with accepted/manual-review decision, account status, authority status, and fresh-live-presence status
```

Keep HTTP and CLI thin. They should parse input, select verifier/config, call the shared command, and shape errors or output. They should not own identity semantics, fact construction rules, replay behavior, or policy meaning.

Do not build a mobile app before the server-side contract exists. Sequence this as: first add durable live-presence challenge issuance and the Persona identity-proofing boundary; expose the composed identity-onboarding HTTP contract; wire that handler to durable persistence and production verifier selection; run the Mac/backend E2E harness; then add a tiny iOS proof app to exercise real Keycloak, App Attest, Persona, and video-selfie/liveness evidence once the endpoint exists. The CLI remains useful after the app exists because it can smoke-test local command wiring without driving the full app.

The proven Rust shape is:

```text
typed Fact -> encrypted persistence envelope -> policy-gated materialization -> typed Fact
```

This keeps the broader FEN paradigm intact:

```text
provider/substrate produces evidence -> FEN verifies/translates -> FEN writes encrypted facts -> Rust policy permits materialization
```

The database should preserve append order, uniqueness, indexes, ciphertext, and operational metadata. Rust owns semantic interpretation, policy evaluation, key access, decryption, materialization, and materialization audit behavior.

### Completed Rust Slice

The encrypted persistence envelope and in-memory/test crypto path are implemented without adding PostgreSQL, KMS, HSM, cloud SDKs, or production database dependencies.

Implemented build targets:

- define adapter-level encrypted Fact envelope types, including append metadata, `fact_id`, `subject_id`, payload type, status, materialization policy refs, encryption metadata, associated-data version, and ciphertext
- define canonical associated-data bytes for encrypted Fact envelopes
- add small encryption/key abstractions for Fact payload encryption, key lookup, key status, and materialization-time decryption
- add a deterministic test-only encryptor/key resolver so behavior can be tested without choosing the final production KMS or AEAD provider
- add policy-gated materialization helpers that require Rust policy approval before key access and decryption
- add materialization audit shapes for attempted materialization, policy denial, key access, decryption, and success
- move encoded plaintext handling behind an explicit codec boundary so production adapters can replace the deterministic test codec
- add round-trip tests proving an encrypted envelope materializes back into the expected typed `Fact`
- add negative tests for tampered fact ID, subject ID, append sequence, payload type, status, policy refs, ciphertext, wrong key, missing key, and retired key

This slice lives in `src/persistence/encrypted.rs` and is covered by `tests/encrypted_persistence.rs`.

### Completed PostgreSQL Adapter Slice

The PostgreSQL adapter slice now exists:

- migration SQL for encrypted fact envelopes and materialization audit records
- migration SQL for workflow transactions, episodes, episode memberships, and episode relations
- row mapping between `StoredEncryptedFact` and PostgreSQL-shaped records
- row mapping between stored workflow envelopes and PostgreSQL-shaped episode, membership, and relation records
- feature-gated SQLx repository behind `postgres-adapter`
- connection/pool construction and migration execution
- encrypted Fact append, all-facts replay query, and subject-scoped query methods
- workflow-slice and episode-composition transaction append methods that write encrypted facts, episodes, memberships, and relations in one SQL transaction
- PostgreSQL-backed encrypted workflow facade that encrypts workflow slices, allocates fact/episode/membership append sequences under `pg_advisory_xact_lock`, writes the stored slice atomically, and replays through policy/key-gated materialization
- replay-oriented query methods for stored episodes, memberships, and episode relations
- materialization audit event insert method
- duplicate fact, episode, membership, relation, and append-sequence constraint mapping back into repository errors
- `bytea` storage shape for nonce and ciphertext
- `TEXT[]` policy refs for queryable materialization policy routing
- `JSONB` payload shapes for exact status, author, code, onset, and retraction reconstruction where workflow tables need typed metadata
- row sorting by append sequence for replay
- encrypted payload type, encryption algorithm, and associated-data version labels centralized on the encrypted persistence enums instead of duplicated in PostgreSQL mapping helpers
- tests proving row conversion preserves associated-data bytes and materialization behavior
- tests proving workflow row conversion preserves typed episode, membership, relation, status, retraction, and invalid-label behavior
- env-gated live adapter test harness for migration, append, duplicate handling, replay query, subject query, policy-gated materialization, materialization audit insert, and workflow-slice transaction append/query
- env-gated live rollback tests proving failed workflow-slice and episode-composition transactions do not leave partial rows behind
- env-gated live replay-equivalence test proving PostgreSQL append ordering can materialize and replay into the same `MaterializedIdentityState` as direct in-memory replay
- env-gated live encrypted workflow facade test proving PostgreSQL-backed append/replay works through the production-shaped facade

The SQLx dependency is optional and narrowed to PostgreSQL plus the Tokio/Rustls runtime so the default crate remains dependency-light.

### Completed Keycloak/OIDC Bootstrap Slice

The IAM adapter boundary now exists without adding live network or JWT dependencies to the default crate:

- generic `OidcClientConfig` and `VerifiedOidcSession` types for already-verified OIDC evidence
- Keycloak-shaped fixture constructor for issuer, subject, client, session, AMR, ACR, and email claims
- `OidcSessionVerifier` trait and deterministic `StaticOidcSessionVerifier` for tests
- context validation for token, issuer, client/audience, subject, and expiration
- OIDC assurance mapping from AMR/ACR into FEN `AuthenticatorType` and `AssuranceLevel`
- account-session bootstrap workflow that records `CredentialAssertion`, `IdentityWitnessRecorded` with `PatientPortalLoginProof`, and `IdentityAttributeAsserted` for email only when the OIDC session marks the email verified
- external references that preserve IdP subject, session, and client refs without making Keycloak the identity source of truth
- service facade methods for accepting already-verified sessions and accepting raw tokens through a verifier
- repository-backed token harness that verifies a token, builds the workflow, appends it, and replays materialized state
- feature-gated `OidcJwksSessionVerifier` that fetches discovery/JWKS metadata and verifies asymmetric JWTs
- env-gated live Keycloak harness controlled by `IDENTITY_MODEL_KEYCLOAK_ISSUER`, `IDENTITY_MODEL_KEYCLOAK_CLIENT_ID`, and `IDENTITY_MODEL_KEYCLOAK_TOKEN`
- local Keycloak development setup in `LOCAL_KEYCLOAK_DEV.md`
- tests covering Keycloak-style passkey login, verified email promotion, unverified email suppression, verifier rejection paths, RS256/JWKS validation, symmetric algorithm rejection, unknown key rejection, observed expiration, and append/replay behavior
- local live-run proof using a `fen-dev` realm, `fen-identity-dev` client, and `marcus` test user

### Completed iPhone/App Attest Device Evidence Slice

The mobile device-evidence boundary now exists without adding Apple SDK or production cryptographic dependencies to the default crate:

- `AppAttestClientConfig` allow-lists team ID, bundle ID, app ID, and development/production environment
- `VerifiedAppAttestAssertion` carries app-bound device evidence, key ID, challenge nonce, sign count, observed timing, and assurance level
- `AppAttestAssertionVerifier` trait and deterministic `StaticAppAttestAssertionVerifier` for tests
- context validation for assertion payload, team ID, bundle ID, app ID, environment, challenge nonce, device ref, key ID, and expiration
- `StatefulAppAttestAssertionVerifier`, `InMemoryAppAttestKeyStateStore`, and `PostgresAppAttestKeyStateStore` wrap a cryptographic/parser verifier with key-state checks for challenge replay, monotonic sign counts, app/device context drift, and revoked keys
- account-token plus App Attest service methods that verify OIDC and App Attest evidence before appending anything
- App Attest evidence translates into a normal `DeviceBindingEstablished` fact with `AuthenticatorType::Other("apple_app_attest")`, device-binding membership role, and external refs for the App Attest key/app identity
- mismatch or rejected App Attest evidence prevents repository mutation
- replayed materialized state includes the App Attest-bound device as an active device

### Completed Shared Mobile Onboarding Command Slice

The combined mobile entry-point command now exists without adding web framework, Apple SDK, production cryptography, or database dependencies to the default crate:

- `MobileOnboardingCommandRequest` groups account token evidence, App Attest-shaped assertion evidence, and client context
- `execute_mobile_onboarding_command` calls the existing service path so HTTP and CLI surfaces do not own identity semantics
- command execution verifies OIDC and App Attest evidence before append, preserves the existing device-reference mismatch guard, appends the workflow slice, replays materialized state, and returns `MobileOnboardingSummary`
- `execute_encrypted_mobile_onboarding_command` verifies the same evidence, appends through `EncryptionAwareWorkflowRepository`, replays through policy/key-gated encrypted materialization, and returns the same safe summary shape
- `MobileOnboardingEncryptedPersistenceContext` carries server-side persistence context for transaction ID, commit timestamp, and materialization policy evaluation
- the summary includes subject ID, assurance level, active devices, workflow episode ID, key fact IDs, and committed fact count, without exposing full fact payloads or workflow internals
- App Attest context validation now rejects empty challenge nonces
- `mobile_onboarding_smoke` provides a dependency-free CLI harness that reads evidence/config from environment variables and exercises the same command with deterministic verifiers
- tests cover successful command append/summary, encrypted-facade append/replay, rejection without repository mutation, empty App Attest challenge rejection, challenge replay rejection, sign-count replay rejection, key context drift rejection, and revoked-key rejection

### Completed Onboarding Liveness Boundary Slice

The live-presence ceremony boundary now exists without adding camera, biometric, vendor SDK, or raw-media dependencies to the default crate:

- `src/liveness.rs` defines the FEN-facing `LivenessCeremonyVerifier` boundary, verified ceremony result shape, static test verifier, and validation helpers
- verified liveness carries provider metadata, provider event refs, challenge nonce, device ref, observed/expiry timestamps, liveness result, PAD result, assurance level, and retention policy refs
- `IdentityWitnessContext` records witness result, challenge nonce, App Attest-bound device ref, PAD result, and retention policy refs on `IdentityWitnessRecorded`
- `SelfieLivenessCheck` is represented as an onboarding witness distinct from `GovernmentIdVerification` and later `BiometricContinuityCheck`
- raw frames, images, templates, embeddings, and provider-native capture artifacts stay outside ordinary FEN facts
- `onboarding_identity_witnesses_slice_from_request` creates government ID and selfie-liveness witnesses as a child onboarding episode
- `execute_mobile_identity_onboarding_command` composes subject registration, OIDC/App Attest account-device bootstrap, government ID witness, selfie-liveness witness, and continuity enrollment
- passed liveness can create the enrollment reference; failed or inconclusive liveness records auditable evidence and returns manual review without silently denying or creating enrollment
- tests prove successful onboarding creates account/session facts, device binding, government ID witness, selfie-liveness witness, and enrollment reference
- tests prove failed/inconclusive liveness creates a manual-review path with witness evidence and no enrollment reference
- tests prove liveness must bind to the App Attest challenge/device context before append

### Completed Mobile HTTP Endpoint Slice

The product-facing HTTP adapter shape now exists behind the optional `mobile-http` feature without making the default crate depend on JSON or a web framework:

- `handle_mobile_onboarding_http_request` handles `POST /mobile/onboarding` as a framework-agnostic method/path/body adapter
- the HTTP request body carries subject, observed time, OIDC token/config, App Attest-shaped evidence/config, expected device ref, and client context
- the handler parses JSON, constructs `MobileOnboardingCommandRequest`, calls `execute_mobile_onboarding_command`, and serializes a narrow JSON response
- `handle_encrypted_mobile_onboarding_http_request` parses the same JSON contract but calls the encrypted-facade command path instead of the plaintext in-memory workflow repository path
- HTTP adapter code owns only wire parsing, status codes, and error shaping; identity semantics stay in the shared command and service path
- success returns subject ID, assurance level, active devices, workflow episode ID, key fact IDs, and committed fact count
- invalid JSON maps to `400`, wrong method to `405`, OIDC verification failure to `401`, App Attest/device mismatch to `422`, and repository append failure to `409`
- encrypted command encryption/materialization failures map to `500` because they indicate server-side persistence, key, or policy configuration failures
- tests cover successful HTTP response JSON, encrypted-facade HTTP append, invalid request JSON, wrong method, device mismatch, and no repository mutation on rejection

This endpoint is still the account/device evidence path. It does not yet expose the composed identity-onboarding command that records government ID and selfie-liveness witnesses.

### Completed Encryption-Aware Workflow Repository Facade Slice

The selected persistence direction is now a higher-level Rust facade over the explicit stored-envelope adapter boundary:

- `EncryptionAwareWorkflowRepository` accepts an `IdentityWorkflowSlice`, transaction ID, and commit timestamp
- the facade assigns fact, episode, and membership append sequences in one workflow-level plan
- fact payloads are encrypted through a metadata planner, encryption key, and payload encryptor before storage
- stored facts carry materialization policy refs, canonical associated data, encryption metadata, and ciphertext
- workflow episodes and memberships are stored alongside the encrypted facts as durable explanation records
- storage is delegated through `StoredEncryptedWorkflowRepository`, so PostgreSQL remains an envelope store rather than the identity semantic owner
- replay and subject materialization go back through policy evaluation, key resolution, decryption, and Rust projection logic
- deterministic metadata planning and an in-memory stored-envelope repository keep the facade covered without adding production KMS or database dependencies to the default crate
- tests prove a mobile OIDC plus App Attest workflow can be encrypted, appended with explicit sequences, replayed, matched back to the direct workflow projection, and reached through the mobile HTTP adapter shape

The PostgreSQL-backed version of this facade now exists for durable append-sequence allocation and stored-envelope writes. The runtime now composes that durable facade with JWKS-backed OIDC, AES-256-GCM fact encryption, and durable App Attest key-state replay protection.

Important PostgreSQL design choices to preserve:

- store canonical timestamp fields as `TEXT`, not `TIMESTAMPTZ`, so PostgreSQL never normalizes values that participate in associated-data checks
- store nonce and ciphertext as `BYTEA`
- keep semantic `FactPayload` plaintext out of the production table shape
- use `JSONB` only for status payload metadata needed to reconstruct the envelope status
- keep `append_sequence` as an explicit unique replay order independent of `fact_id`
- keep queryable operational metadata for `subject_id`, payload type, status kind, materialization policy refs, and replay order
- keep episodes, memberships, and relations durable as append-only workflow explanation records; do not let them become identity truth
- keep policy approval, key access, decryption, plaintext decoding, and materialized projection building in Rust
- keep workflow-to-envelope conversion, encryption, sequence planning, and replay helpers in the Rust facade above the database adapter

Immediate next implementation order:

1. Add durable server-issued live-presence challenge issuance, expiry, one-time nonce use, retry/manual-review state, and binding to App Attest device context.
2. Expose the composed identity-onboarding command through an HTTP DTO/handler and encrypted PostgreSQL append/replay path.
3. Replace the synthetic App Attest parser/signature proof with real Apple App Attest attestation/assertion verification.
4. Move fact key material from env-loaded bytes into DEK/KEK or KMS-backed wrapping and rotation.
5. Move the local runtime shell toward production-grade transport and make App Attest state checks async-native when the server framework is selected.

The live PostgreSQL tests are skipped unless `IDENTITY_MODEL_POSTGRES_URL` is present; they have passed against a disposable PostgreSQL database in this workspace. The live Keycloak test is skipped unless the Keycloak env vars are present; it has passed against the local dev setup documented in `LOCAL_KEYCLOAK_DEV.md`.

PostgreSQL is the preferred first production database because it gives mature transactions, indexes, binary ciphertext storage, JSON/hybrid metadata options, and operational reliability without asking SQL to become the source of identity meaning.

## Current State

This repo contains a Rust crate implementing the first FEN identity-model foundations:

- typed FEN facts, identity primitives, workflow slices, policy evaluation, and materialized projections
- parsed UTC timestamp helpers for policy, IAM, device-evidence, and projection validity checks
- split onboarding and service APIs for subject registration, device binding, continuity enrollment, provider links, payer links, recovery, delegation, access decisions, and identity disputes
- generic OIDC/Keycloak session evidence boundary, JWKS verifier, and account-token bootstrap append/replay harness
- shared mobile onboarding command, dependency-free CLI smoke harness, and feature-gated HTTP handler for OIDC plus App Attest-shaped device evidence
- composed mobile identity-onboarding command for subject registration, account/device bootstrap, government ID witness, selfie-liveness witness, manual-review outcome, and continuity enrollment after passed liveness
- liveness ceremony verifier boundary that consumes structured live-presence/PAD results without storing raw media in FEN facts
- append-only in-memory repository traits and replay helpers for facts, episodes, memberships, and episode relations
- encrypted Fact envelope, associated-data, test encryption/key, policy-gated materialization, materialization audit, and in-memory encrypted repository boundaries
- higher-level encryption-aware workflow repository facade for converting typed workflow slices into encrypted stored envelopes and replaying them through policy/key gates
- PostgreSQL migrations, row-mapping boundaries, feature-gated SQLx repository methods, and a PostgreSQL-backed encrypted workflow facade for encrypted facts, materialization audit records, workflow transactions, episodes, memberships, and episode relations
- composed onboarding with parent/child `EpisodeRelationType::PartOf` workflow structure
- policy artifacts with versioned refs, lifecycle status, effective windows, review metadata, and action-specific definitions
- canonical continuity assertions and typed rejection reasons
- optional feature-gated strict Ed25519 verification and provider-issued Ed25519 test adapter
- documentation for persistence, policy artifacts, continuity assertions, encrypted Fact payloads, and security transitions

The stable boundary remains:

```text
providers and substrates produce evidence; FEN owns identity truth
```

Vendors, IAM systems, biometric SDKs, hosted continuity services, KMS providers, and databases are replaceable infrastructure. They do not own the FEN fact graph.

## Verified Behavior

Default suite:

```sh
cargo test
```

Passed locally after the liveness onboarding slice.

Feature-enabled Ed25519 suite:

```sh
cargo test --features ed25519-dalek-verifier
```

Last recorded as passing before the liveness slice; re-run when touching continuity verifier behavior.

Feature-enabled OIDC/JWKS suite:

```sh
cargo test --features oidc-jwks-verifier
```

Last recorded as passing before the liveness slice. One test is env-gated and no-ops unless the Keycloak issuer/client/token env vars are set.

Feature-enabled mobile HTTP suite:

```sh
cargo test --features mobile-http
```

Passed locally after the liveness onboarding slice.

Feature-enabled PostgreSQL adapter suite:

```sh
cargo test --features postgres-adapter
```

Last recorded as passing with the feature enabled when `IDENTITY_MODEL_POSTGRES_URL` is absent. Live tests are env-gated and no-op unless that URL is set; those live tests pass against a disposable PostgreSQL database when the URL is present.

Full all-features suite:

```sh
cargo test --all-features
```

Re-run before release or branch handoff if optional feature coverage is required.

The tests cover:

- continuity challenge lifecycle, replay rejection, expired nonces, unknown nonces, and enrollment mismatches
- registry-backed signature verification with unknown, retired, wrong-provider, malformed, and invalid keys/signatures
- feature-gated strict Ed25519 verification over canonical FEN assertion bytes
- provider-issued FEN-native Ed25519 assertions through the service path
- service-level access decisions, policy reasons, policy artifacts, and stale-evidence checks
- parsed timestamp comparisons for policy effective windows, stale evidence, OIDC session expiration, App Attest assertion expiration, and projection validity windows
- Keycloak/OIDC session bootstrap into credential, portal-login witness, and verified-email facts
- App Attest-shaped device evidence validation, account-token binding, device-binding fact creation, and rejection-without-append behavior
- shared mobile onboarding command summary behavior, encrypted-facade mobile command behavior, CLI harness compile path, HTTP JSON/status-code adapter behavior, encrypted-facade HTTP adapter behavior, empty App Attest challenge rejection, and invalid App Attest timestamp rejection
- composed identity onboarding with government ID witness, selfie-liveness witness, enrollment creation after passed liveness, manual-review evidence after failed/inconclusive liveness, and App Attest challenge/device binding for liveness
- feature-gated OIDC/JWKS verification, asymmetric JWT validation, env-gated live Keycloak token harness, and account-token append/replay
- split onboarding, composed onboarding, repository append/replay, and episode relations
- encrypted Fact envelope round trips, append-sequence replay, policy-before-key access, materialization audit, codec boundary, tamper detection, wrong-key, missing-key, and retired-key failures
- encryption-aware workflow repository sequence planning, encrypted workflow append, policy-gated replay, mobile workflow projection equivalence, and PostgreSQL-backed encrypted workflow append/replay
- PostgreSQL migration shape, row mapping, SQLx adapter compile path, AAD preservation, status/time reconstruction, replay sorting, and audit-row mapping
- PostgreSQL workflow transaction migration shape, typed row mapping, replay sorting, invalid-label rejection, and SQLx adapter compile path
- env-gated live PostgreSQL adapter harness for migration, append, duplicate handling, replay query, subject query, policy-gated materialization, audit insert, workflow-slice transaction append/query, PostgreSQL-backed encrypted workflow append/replay, rollback, and replay-equivalence
- materialized projections for active devices, links, disputes, witnesses, authorities, recovery, access decisions, invalid validity windows, and duplicate replayed view rows
- golden fixture rendering and presentation-only string boundaries

## Implementation Roadmap

### 1. Encrypted Fact Persistence

The dependency-light Rust proof is implemented. Keep this boundary stable while moving into the durable adapter.

Use `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md` and `PERSISTENCE_CONTRACT.md` as the controlling references.

Practical outcome:

Sensitive semantic payloads can remain encrypted at rest while FEN still preserves append-only audit history, replayability, policy explanation, and materialized projections.

### 2. PostgreSQL Persistence Adapter

The migrations, row-mapping boundary, feature-gated SQLx encrypted-fact/workflow repository methods, PostgreSQL-backed encrypted workflow facade, live database integration coverage, rollback tests, and replay-equivalence tests are implemented.

Use PostgreSQL for durable append order, transactions, uniqueness constraints, queryable operational metadata, and binary ciphertext storage. Keep identity semantics in Rust.

The chosen persistence direction is a higher-level encrypted workflow facade over the explicit stored-envelope adapter boundary. Keep PostgreSQL as the durable envelope store; let the facade own encryption, sequence planning, policy refs, workflow-to-envelope conversion, and replay helpers. For production-shaped PostgreSQL composition, use `SqlxPostgresEncryptionAwareWorkflowRepository`.

Practical outcome:

The audit graph becomes operational without turning SQL tables into identity truth.

### 3. Onboarding Liveness Challenge and HTTP Contract

The liveness verifier boundary and composed identity-onboarding command exist. The next implementation work is durable challenge issuance, one-time nonce use, expiry handling, retry/manual-review state, and a product-facing HTTP contract for the composed onboarding path.

Keep the ceremony evaluator outside the FEN identity ontology. It may become an external vendor integration, a separate service/application, or a future crate. This codebase should consume structured results and record only typed witness context, provider refs, assurance, PAD/liveness outcome, expiry, and retention policy refs.

Practical outcome:

Onboarding can prove fresh live presence without saying "face equals identity" and without storing raw media in ordinary FEN facts.

### 4. Policy Storage and Review Workflow

The in-memory `PolicyArtifact` model is ready enough for service-level evaluation. The next policy work should focus on repository traits and operational review storage only after persistence requirements are concrete.

Use `POLICY_ARTIFACT_CONTRACT.md` as the controlling reference.

Practical outcome:

Access decisions can cite stable, reviewed, versioned policy refs across time.

### 5. Live Provider Transport and Key Operations

The provider-shaped adapter boundary exists, and the feature-gated Ed25519 adapter proves provider-issued FEN-native assertions with active/retired key behavior.

Remaining work belongs in provider/infrastructure adapters:

- authenticated HTTP or SDK transport
- vendor-native signature validation at the adapter edge
- live provider key discovery and refresh
- durable verification-key storage
- operational key-rotation policy
- integration tests proving provider changes do not alter FEN fact shape

Use `CONTINUITY_ASSERTION_PROFILE.md` and `SECURITY_AND_TRANSITION_NOTES.md` as the controlling references.

Practical outcome:

FEN can trust real continuity evidence without letting provider-native payloads become identity ontology.

### 6. Threat-Model Pass

After encrypted persistence begins, update the threat model around:

- encrypted payload tampering
- associated-data swapping
- wrong-key and retired-key materialization
- key unwrap audit
- cached projection leakage
- derived export leakage
- replay and nonce abuse
- provider compromise and provider key rotation
- liveness provider compromise, replayed ceremony callbacks, stale live-presence display, and unsafe retention of biometric media
- malicious recovery, incorrect merge/split, and insider dispute-resolution scenarios

Practical outcome:

Security controls are tied to verifier behavior, policy gates, key management, persistence envelopes, projection rules, and audit records.

## Principles To Preserve

- Rust owns FEN semantics; databases store durable envelopes and operational indexes.
- Facts are append-only; corrections and revocations are represented by new facts or statuses, not destructive mutation.
- `FactPayload` semantics should not absorb database sequence fields, KMS details, provider SDK shapes, or transport-specific payloads.
- Materialized projections are rebuildable read models, not sources of truth.
- Cached projections and derived views must not bypass encrypted source facts.
- Provider-native evidence is verified at the adapter edge before translation into FEN facts.
- Live-presence/video-selfie ceremonies are witnesses, not identity foundations; raw biometric media and templates stay outside ordinary FEN facts.
- Strings belong at rendering, provider/wire, persistence, and signing boundaries; core logic should stay typed.
- Keep the core crate lean until real adapter dependencies require a workspace split.

## Reference Documents

- `PERSISTENCE_CONTRACT.md`: append-only persistence, ordering, transaction, and adapter rules
- `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md`: encrypted Fact envelopes and policy-gated materialization
- `POLICY_ARTIFACT_CONTRACT.md`: policy artifact storage, review, lifecycle, and citation rules
- `CONTINUITY_ASSERTION_PROFILE.md`: FEN-native continuity assertion profile and verifier guidance
- `SECURITY_AND_TRANSITION_NOTES.md`: security boundaries and later-phase transition notes
- `LOCAL_KEYCLOAK_DEV.md`: local Keycloak dev realm and live OIDC/JWKS smoke test setup
- `build_plan.md`: broader milestone history and rationale
