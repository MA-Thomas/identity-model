# Next Steps

## Handoff Snapshot

Start here. The repo now has twenty-one relevant implementation slices:

- encrypted Fact persistence and policy-gated materialization are implemented and tested in memory
- PostgreSQL migrations, row mapping, SQLx repository methods, env-gated live adapter harnesses, rollback coverage, and replay-equivalence coverage are implemented
- a higher-level encryption-aware workflow repository facade converts workflow slices into encrypted stored envelopes, owns append-sequence assignment, delegates durable append to a stored-envelope repository, and replays policy-gated materialized state
- a PostgreSQL-backed encryption-aware workflow facade now allocates append sequences inside the same SQL transaction that writes encrypted facts, episodes, memberships, and workflow transaction rows
- Keycloak/OIDC account-session bootstrap, feature-gated JWKS verification, and an env-gated live Keycloak harness are implemented
- iPhone/App Attest-shaped device evidence can now be verified at an adapter boundary and bound into the account-token bootstrap workflow as a normal device-binding fact; under `production-crypto`, an Apple registration verifier now accepts decoded registration evidence or a native attestation-object envelope, extracts App Attest `authData`, `x5c`, AAGUID, credential ID, and COSE P-256 public key, verifies the certificate chain to Apple's App Attestation Root CA, verifies the App Attest nonce extension, binds the key to the leaf certificate public key, records trusted public-key metadata, and the Apple assertion verifier checks the registered public key, server allow-listed app config, challenge-bound client-data hash, app-ID hash, P-256 signature, assertion expiry, and sign count before the durable key-state guard runs
- a shared mobile onboarding command now wraps OIDC token verification, App Attest-shaped device evidence verification, workflow append, replay, and a safe account/device summary; a dependency-free CLI smoke harness and a feature-gated HTTP handler call the same command
- an onboarding live-presence/liveness boundary now records `IdentityWitnessRecorded { witness_type: SelfieLivenessCheck }` from a verified ceremony result, binds that result to server challenge and App Attest device context, stores provider event refs/assurance/PAD result/expiry/retention policy refs instead of raw media, and creates continuity enrollment only after a passed liveness ceremony
- durable live-presence challenge lifecycle storage now exists in memory and PostgreSQL, including issued, used, expired, failed, and manual-review states, expected subject/device/app context, retry/manual-review/retention policy refs, one-time consumption, and tests for missing, expired, mismatched, failed, and inconclusive challenges
- a feature-gated `production-crypto` adapter now encrypts fact plaintext with AES-256-GCM through `ring`, using the existing canonical associated-data contract and append-sequence-derived 96-bit nonces
- an App Attest key-state guard now records verified key state, used challenge nonces, sign-count progress, and revocation state so synthetic or future real App Attest verification cannot replay the same challenge or move a key across app/device context
- PostgreSQL now has App Attest key-state and key-registration migrations/adapters, with transactional challenge replay protection, sign-count updates, key revocation state, durable registered public-key lookup, and runtime wiring through the existing verifier guard
- a feature-gated `runtime-server` binary now loads runtime config from env, connects to PostgreSQL, optionally runs migrations, assembles `SqlxPostgresEncryptionAwareWorkflowRepository` with the AES-256-GCM adapter, selects JWKS-backed OIDC verification, wraps either the static App Attest fixture verifier or opt-in Apple assertion verifier backed by PostgreSQL registration lookup in the durable PostgreSQL key-state guard, exposes `/health` and `/ready`, and routes both `POST /mobile/onboarding` and `POST /mobile/identity-onboarding` through the framework-neutral handlers
- a composed mobile identity-onboarding HTTP contract now exists at `POST /mobile/identity-onboarding`, with plain, encrypted, and PostgreSQL encrypted handlers plus a `PostgresEncryptedMobileIdentityOnboardingRuntime` facade mounted by the runtime server with Persona proofing, static liveness verification, durable PostgreSQL live-presence challenge storage, continuity-provider config, and encrypted workflow persistence
- a product-facing live-presence challenge issuance HTTP route now exists at `POST /mobile/identity-onboarding/live-presence-challenge`; it binds subject, device, and expected App Attest app context, writes a durable PostgreSQL challenge through the runtime server, and returns a CSPRNG-generated nonce plus expiry/policy refs for the composed onboarding request
- a provider-neutral live-presence handoff/callback HTTP shape now exists; challenge issuance returns provider handoff metadata, `POST /mobile/identity-onboarding/live-presence-callback` accepts provider-normalized liveness/PAD result evidence, verifies provider/assertion/timestamp shape, and maps the callback into the existing onboarding `liveness` input without storing raw capture media or consuming the challenge before App Attest-bound onboarding
- a signed-iOS proof-app App Attest registration path now exists in the runtime server: `POST /mobile/app-attest/key-registration-challenge` issues a server nonce and expected Apple app identity, and `POST /mobile/app-attest/key-registration` verifies a native `DCAppAttestService.attestKey` attestation object before storing the trusted P-256 public key in the App Attest registration store for later registered-key assertions
- a minimal signed-iPhone/Xcode proof target now lives at `ios/FenAppAttestProof`; it builds for a generic iOS device, stores `device_ref` and `keyId` in Keychain, calls the App Attest key-registration routes, issues a live-presence challenge, generates a registered-key App Attest assertion, wraps it in the `apple-app-attest-assertion-object-v1` envelope, and exposes the envelope for the composed onboarding request
- a provider-neutral identity-proofing boundary now exists with Persona as the default Phase 1 adapter shape; composed mobile identity onboarding verifies Persona-normalized proofing evidence, records the legal identity witness, asserted attributes, provider refs, retention refs, and optional policy-affecting risk signals, and routes failed/inconclusive/expired proofing into manual review without treating Persona as identity truth
- an env-gated backend E2E harness now starts the mounted runtime server on a temporary local port, issues a durable live-presence challenge through the HTTP route, submits `POST /mobile/identity-onboarding` with live Keycloak/JWKS token evidence plus static App Attest, Persona, and liveness evidence, and verifies the safe summary, encrypted fact rows, audit rows, App Attest key state, and used challenge state
- the FEN reconciliation rule engine (`FEN_RECONCILIATION_RULE_ENGINE.md`, sequencing steps 1–5) now lives in `fen-health-econ`: reviewed/versioned `ReconciliationRuleArtifact`s with an in-memory store and a PostgreSQL store (migration `0006_health_econ_reconciliation_rule_artifacts`, env-gated live harness); a pure, deterministic rule engine over materialized facts with `SharedClaimRef`-only matching and four typed rule variants pinned by golden fixtures; deterministic SHA-256 finding identity (`finding-<hex>` over a domain-tagged, length-prefixed preimage, golden-pinned) so re-evaluation dedupes through the envelope store's existing duplicate-fact-id rejection; the shared `SupersessionReason::RuleReEvaluation` variant with its frozen `rule_re_evaluation` label in both the AAD canonicalization and the PostgreSQL mapping; and findings appended as `Inference`-tier encrypted `BillingDiscrepancy` facts through the now family-generic in-memory envelope repository — post-ingest subject-scoped triggering stays deferred with the ingestion work

The latest hardening pass also moved security-sensitive timestamp comparisons onto parsed UTC helpers, centralized encrypted persistence labels on typed enums, indexed materialized projection checks to avoid repeated scans, deduped replayed view rows, and split workflow outcome helpers out of the service facade.

The latest local Keycloak proof is complete. A throwaway Keycloak `26.6.1` dev setup created realm `fen-dev`, client `fen-identity-dev`, and user `marcus`, obtained a real access token, verified it through discovery/JWKS, appended the FEN account-session workflow, and replayed materialized state successfully. The reproducible setup lives in `LOCAL_KEYCLOAK_DEV.md`.

The PostgreSQL live harness has now passed against a disposable PostgreSQL database in this workspace. The live proof covered migration execution, encrypted append/query, duplicate fact ID, duplicate append sequence, all-facts replay order, subject-scoped query, policy-gated materialization, materialization audit insert, workflow-slice transaction append/query, PostgreSQL-backed encrypted workflow append/replay, transaction rollback, and replay-equivalence against `MaterializedIdentityState`.

The backend runtime E2E harness has now passed against disposable local PostgreSQL and Keycloak services in this workspace. It obtained a fresh Keycloak token, started the mounted runtime server on a temporary port, issued and callback-verified a durable live-presence challenge, submitted the composed identity-onboarding HTTP request, and verified the encrypted PostgreSQL facts, materialization audit rows, App Attest key state, and used challenge state.

`Phoros Onboarding and Recovery Architecture.pdf` has now been folded into `build_plan.md` as a product-state addendum. The build plan keeps the existing FEN fact-graph architecture and adds follow-on milestones for contact-channel evidence, Persona-default legal identity proofing, account and authority status projections, recovery policy setup, restricted-authority recovery, durable live-presence challenges, composed onboarding HTTP, and clinical binding/import states.

Persona is the default Phase 1 legal identity-proofing provider. Treat Persona as the first concrete identity-proofing adapter, not as identity truth. The initial adapter verifies normalized Persona workflow results and translates them into FEN identity witness, asserted attribute, risk, provenance, and external-ref facts. Keep the `IdentityProofingProvider` boundary provider-neutral so ID.me, Socure, Jumio, Entrust/Onfido, Veriff, LexisNexis, government assertions, or provider-mediated assertions can replace Persona later.

The physical-device App Attest proof run is now complete. `ios/FenAppAttestProof` was run on a signed physical iPhone (team `FT36N9P233`, bundle `com.marcusthomas.fenappattestproof`, `development` App Attest environment) over a Cloudflare HTTPS quick tunnel to the runtime server; it registered a real Secure Enclave key, issued a live-presence challenge, and generated a registered-key assertion envelope, and the trusted P-256 public key persisted to `identity_app_attest_key_registrations` in PostgreSQL. Two backend defects that only real Apple evidence exposes were fixed in the process. First, the registration certificate-chain verifier selected the ECDSA curve from the child certificate's signature OID instead of from the issuer key, so Apple's P-256 leaf signed by the P-384 App Attestation CA intermediate (ecdsa-with-SHA256) was rejected with `InvalidSignature`; it now selects the verifying curve from the issuer public-key length. Second, the App Attest key-registration and live-presence-challenge endpoints ran their PostgreSQL writes on a freshly spawned Tokio runtime while the connection pool was owned by the server's main runtime, so the acquire hung until pool timeout and returned a 500 with no SQL sent; those writes now run on the pool-owning runtime like the onboarding endpoints. Both fixes carry regression tests (`apple_app_attest_key_registration_verifier_accepts_p384_intermediate_chain` in `tests/app_attest_key_state.rs`, and `live_runtime_server_store_write_runs_on_pool_runtime_when_env_is_set` in `tests/runtime_server_e2e.rs`), and the full reproduction runbook (Docker, tunnel, Xcode signing, phone, and troubleshooting) is in `REPRODUCE_IOS_APP_ATTEST_PROOF.md`. The next useful handoff move is to submit the composed `POST /mobile/identity-onboarding` request using that real registered-key assertion envelope, then progressively replace the remaining static/copied proof inputs with real Keycloak, Persona, and video-selfie/liveness evidence. Tooling for that submission now exists: the proof app has a "Copy Onboarding Inputs" action that exports the base URL, subject/device refs, the live challenge nonce, timestamps, and the assertion envelope, and `scripts/submit_onboarding.py` runs the live-presence callback and composed onboarding against `localhost:3000` using a fresh Keycloak token plus dev-static Persona/liveness evidence. This `apple_assertion` + real-device onboarding path has not yet been run end to end (the passing E2E uses the static App Attest verifier), so expect to iterate on the first attempt. The most likely friction point — the static liveness verifier pinning the device ref from env while the real device ref is dynamic per install — has been pre-empted: `StaticLivenessCeremonyVerifier` now supports `with_request_device_ref()` and the runtime server enables it, so the liveness device ref (like the challenge nonce) is rebound from each request. That behavior is covered by `static_liveness_verifier_rebinds_device_ref_from_request` in `tests/mobile_onboarding.rs`. `REPRODUCE_IOS_APP_ATTEST_PROOF.md` Step 8 documents the full procedure.

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

1. **Persona Identity Proofing Boundary**

   The initial Persona-shaped boundary is implemented behind a provider-neutral `IdentityProofingProvider` contract. It uses normalized Persona/static evidence shapes carrying provider name, workflow ID, asserted attributes, evidence types, verification result, assurance level, risk signals, timestamp, expiration policy, and audit reference.

   MVP outcome: the composed onboarding path can record legal identity proofing as FEN evidence without hard-coding Persona as the identity model.

2. **Production Runtime**

   The framework-neutral composed identity-onboarding HTTP handlers and `PostgresEncryptedMobileIdentityOnboardingRuntime` now exist, and the feature-gated runtime server now mounts the richer path alongside the smaller account/device smoke endpoint. The runtime builds Persona proofing, durable PostgreSQL live-presence challenge storage, static liveness verifier config, continuity-provider config, JWKS-backed OIDC verification, durable App Attest key-state protection, and encrypted PostgreSQL workflow persistence.

   Remaining runtime hardening: move from the local shell to production-grade transport concerns such as concurrency, graceful shutdown, request tracing, deployment migration policy, stricter body/timeout handling, real App Attest cryptographic verification, async-native App Attest and live-presence state operations, and durable key-management storage.

3. **Mac/Backend End-To-End Test Path**

   The fastest real-ish backend path now exists as an env-gated integration harness. It runs the mounted runtime server against local PostgreSQL, local Keycloak, production-shaped encrypted workflow persistence, durable live-presence challenges, and Persona sandbox/static identity-proofing evidence. It drives the composed onboarding HTTP endpoint, then verifies the safe summary, encrypted persisted facts, materialization audit rows, App Attest key-state rows, and used challenge state.

   MVP outcome: the backend product flow can be exercised outside unit tests while the iPhone-specific App Attest and camera/liveness path is still being built.

4. **Challenge Issuance And Provider Callback Shape**

   The durable `LivePresenceChallenge` store, one-time consumption checks, runtime-server issuance route, provider handoff metadata, and provider-normalized callback mapping exist. The route binds intended workflow, expected app/device context, subject/account context where known, expiry, retry/manual-review policy, retention refs, and a CSPRNG-generated nonce. The next challenge work is vendor-specific session creation, signed callback verification, and provider ceremony metadata hardening.

   MVP outcome: a passed video-selfie/liveness ceremony can be trusted as fresh physical-presence evidence for onboarding because it is bound to a server-issued challenge and attested device context; failed or inconclusive ceremony results create auditable retry/manual-review paths instead of silent denial.

5. **Real Key And Crypto Boundary**

   The first AEAD adapter now exists behind `production-crypto`: AES-256-GCM through `ring`, canonical associated data, explicit 32-byte key validation, and 96-bit nonces derived from a deployment nonce domain plus append sequence.

   Remaining key work: move key material out of env-loaded local bytes, add DEK/KEK or KMS wrapping behavior, represent wrapped key state durably, support rotation/rewrapping policy, and ensure production deployments cannot start with test-only key config.

6. **Real Apple App Attest**

   The first real registration/assertion verification boundary now exists behind `production-crypto`. Registration verification accepts decoded App Attest registration evidence or a native attestation-object envelope, validates server allow-listed team/bundle/environment, app-ID hash, registration challenge hash, App Attest AAGUID, credential ID, COSE P-256 public key shape, `x5c` presence, certificate validity, issuer/subject chaining, ECDSA certificate signatures up to Apple's App Attestation Root CA, App Attest nonce extension, leaf-certificate public-key binding, timestamp, and format, then records trusted public-key metadata in the registration store. The runtime server now exposes the registration challenge and registration HTTP routes a signed iOS proof app needs before it submits assertions. The `ios/FenAppAttestProof` target now drives `DCAppAttestService.generateKey`, `attestKey`, and `generateAssertion` and can produce the registered-key assertion envelope. Assertion verification resolves that registered key, binds the assertion to the server challenge through `clientDataHash`, verifies the P-256 signature over `authenticatorData || clientDataHash`, extracts the sign count, and then lets the durable key-state guard enforce challenge replay protection, sign-count monotonicity, app/device context stability, and revocation state.

   Remaining App Attest work: run the proof target on a physically signed supported iPhone against the runtime, submit the generated registered-key assertion through the composed onboarding request, decide how to store/use Apple attestation receipts for fraud-risk telemetry, and keep development/production App Attest environment handling explicit.

   MVP outcome: the iPhone path proves app-bound device possession with real Apple evidence before FEN appends the device-binding workflow facts.

7. **Real Liveness Provider Boundary**

   Keep `src/liveness.rs` as the FEN-facing boundary and decide later whether the actual ceremony evaluator is an external vendor, an internal service, or a separate Rust crate/application. The provider-facing implementation should return structured pass/fail/inconclusive evidence with PAD result, provider event refs, expiry, assurance, and retention policy refs. Product language should say "live presence check," "video-selfie check," or "confirm you are physically present"; reserve "biological continuity" for the signed 1:1 check against an enrollment reference.

   MVP outcome: FEN can consume liveness evidence without turning the face capture process into identity itself.

8. **Policy And Governance Storage**

   Add durable storage and review lifecycle for policy artifacts that will be cited by access decisions and materialization decisions. Keep policy refs versioned, reviewed, lifecycle-aware, and stable over time. Avoid embedding mutable policy meaning directly in route handlers, database rows, or provider adapters.

   MVP outcome: materialization and access decisions can cite durable policy refs, and later audits can explain which policy version permitted or denied reliance.

9. **Database Operationalization**

   Turn the PostgreSQL adapter from a tested storage proof into an operational database boundary. Add migration version tracking, deployment-safe migration execution, connection-pool configuration, readiness checks, backup/restore expectations, index review, live harness setup guidance, and CI/pre-production coverage for feature-enabled database tests.

   MVP outcome: the encrypted append/replay path can be run repeatedly against a real database with predictable schema state and operational diagnostics.

10. **Product Mobile Path**

   The first Xcode proof target now exists at `ios/FenAppAttestProof`. Its current scope is deliberately narrow: real App Attest key registration, live-presence challenge issuance, registered-key assertion generation, and envelope copying for the composed onboarding request. Keep it as a proof app or thin product slice until the backend evidence contract stabilizes.

   Treat this as a staged test boundary. Backend MVP tests can keep using fixtures, synthetic App Attest-shaped evidence, Persona sandbox/static identity-proofing evidence, and static liveness verifier results. The next product-mobile increments are direct composed-onboarding submission from the app, then real Keycloak login, Persona workflow handoff, and live-presence/video-selfie provider integration. An investor demo on the investor's own phone likely needs a TestFlight or demo build, HTTPS access to the runtime, a prepared Keycloak login path, a configured Persona workflow, a configured liveness provider path, and deliberate handling of App Attest development versus production environment behavior.

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
  -> FEN appends account-session, portal-login witness, verified-email, device evidence, legal identity-proofing witness and attributes, selfie-liveness witness, and enrollment-reference facts
  -> replay materializes the current account/device/onboarding state
```

Keep these evidence streams separate:

- Keycloak/OIDC proves account/session context, issuer, client/audience, subject, authentication method, and verified email when present.
- iPhone/App Attest should prove app-bound device possession through a challenge, attestation/assertion verification, replay protection, bundle/team/app allow-listing, and durable attestation-key state.
- Persona legal identity proofing is the default Phase 1 external verifier. It proves civil or institutional identity evidence through a provider workflow and should be recorded as its own witness and asserted attributes, not merged into liveness or device evidence.
- Live-presence/video-selfie liveness proves a physically present human completed a fresh capture-path/PAD challenge. It should be recorded as `SelfieLivenessCheck`, not called face authentication or treated as identity itself.
- Biological continuity after enrollment is the signed 1:1 continuity check against an enrollment reference. Keep this distinct from onboarding liveness, even if the same camera ceremony helps create the enrollment reference.
- FEN should bind the verified account-session evidence, verified device evidence, Persona-normalized legal identity-proofing witness and attributes, liveness witness, and enrollment reference through workflow facts; no single evidence source should directly own the identity graph.

Do not generalize the current Apple-specific verifier into a broad `DeviceEvidenceVerifier` until a second platform integration is real. App Attest, Play Integrity, Android key attestation, Windows Hello/passkeys, TPM attestation, and managed-device attestation are related evidence sources, but they prove different claims. When Android or desktop enters scope, add a neutral verified-device-evidence shape that platform-specific verifiers can emit into. Also do not assume Apple App Attest covers desktop Mac apps; treat iOS/iPadOS App Attest, managed Apple device attestation, consumer Mac passkey/Secure Enclave evidence, Android app/device integrity, Android hardware-backed key attestation, and Windows Hello/TPM signals as distinct adapter inputs that FEN translates into typed facts.

## Priority Now: Signed iOS App Attest Proof

The in-memory Rust proof for encrypted Fact persistence exists, and the PostgreSQL adapter now has migration SQL, row mapping, a feature-gated SQLx repository, and an env-gated live integration test harness for encrypted Fact envelopes and workflow-slice transaction rows. The Keycloak/OIDC-facing slice now exists too: verified OIDC session evidence can enter FEN as normal credential, portal-login witness, and verified-email attribute facts, and a feature-gated JWKS verifier can validate live Keycloak-style JWTs.

The local Keycloak harness has been run against a throwaway `fen-dev` realm on `127.0.0.1:8080`; it created a realm/client/user, obtained a token, verified the token through discovery/JWKS, appended the FEN workflow, and replayed state successfully. The PostgreSQL harness has now also been run against a disposable live database, and rollback/replay-equivalence coverage has been added. The PostgreSQL-backed encrypted workflow facade now assigns durable append sequences under a transaction-scoped advisory lock, writes the stored workflow slice atomically, and replays materialized state through policy-gated decryption. The App Attest-shaped mobile device evidence slice now exists as a deterministic adapter boundary and is bound into the account-token bootstrap path.

The shared mobile onboarding command now exists in `src/mobile.rs`, the dependency-free CLI smoke harness in `src/bin/mobile_onboarding_smoke.rs` calls the account/device command, and the feature-gated HTTP handler in `src/mobile_http.rs` exposes `POST /mobile/onboarding` as a framework-agnostic method/path/body adapter. The existing HTTP path takes OIDC token evidence, App Attest-shaped assertion evidence, challenge nonce context, and client context; verifies OIDC and App Attest evidence at adapter boundaries; rejects device-reference mismatch before append; appends account/session/device-binding facts through the workflow repository boundary; replays materialized state; and returns a narrow account/device summary instead of exposing full workflow internals.

The richer identity-onboarding path now verifies OIDC, verifies App Attest, verifies Persona-normalized identity-proofing evidence, verifies a structured liveness ceremony result, consumes a durable live-presence challenge, binds the liveness result to App Attest challenge/device/app context, records legal identity-proofing and selfie-liveness witnesses, creates continuity enrollment only when proofing and liveness pass, and returns a decision that distinguishes accepted onboarding from manual review. This path is intentionally not the camera implementation. It is the FEN-facing ceremony boundary plus workflow composition.

The composed identity-onboarding HTTP contract now exists in `src/mobile_http.rs` as `POST /mobile/identity-onboarding`. It has plain, encrypted, and PostgreSQL encrypted handler variants, and `src/runtime.rs` exposes `PostgresEncryptedMobileIdentityOnboardingRuntime` for hosts that can provide identity proofing, liveness, live-presence challenge, continuity-provider, encrypted repository, and key dependencies. The `runtime-server` binary now mounts the smaller account/device endpoint, the composed identity endpoint, and the live-presence challenge issuance endpoint with Persona proofing, static liveness verifier config, durable PostgreSQL live-presence challenge storage, and the mock Phase 1 continuity-provider boundary.

The Persona identity-proofing boundary now exists. The product-facing onboarding path carries OIDC, App Attest, Persona-normalized legal identity proofing, and liveness ceremony evidence. The composed contract accepts provider-normalized `identity_proofing` input instead of treating a raw government-ID witness input as the final provider adapter. The older account/device HTTP path can remain as a smaller smoke surface.

The backend E2E harness has now run against local PostgreSQL and Keycloak. The runtime server also has the App Attest key-registration challenge and registration routes needed by a signed iOS proof app, and `ios/FenAppAttestProof` now contains the minimal SwiftUI proof target for those routes. That signed physical-device run has now passed: the target was signed with team `FT36N9P233` / bundle `com.marcusthomas.fenappattestproof` / `development` App Attest environment, run on a physical iPhone over a Cloudflare HTTPS tunnel, and it registered a real App Attest key, issued a live-presence challenge, and generated the registered-key assertion envelope, with the trusted public key persisted in PostgreSQL. Getting there surfaced and fixed the P-256/P-384 certificate-chain curve-selection bug and the foreign-runtime PostgreSQL store hang, both now covered by regression tests. The remaining step is to submit the composed `POST /mobile/identity-onboarding` request with that real assertion envelope. `IOS_APP_ATTEST_PROOF.md`, `ios/FenAppAttestProof/README.md`, and the end-to-end `REPRODUCE_IOS_APP_ATTEST_PROOF.md` runbook are the shortest handoffs for that device-side flow.

The intended entry-point shape is:

```text
identity onboarding command
  input: OIDC token, App Attest evidence, Persona-normalized identity-proofing evidence, liveness ceremony result, client context
  verifies: live-presence challenge freshness, OIDC session, device evidence, legal identity proofing, liveness/PAD result, subject/device/app consistency
  appends: credential, portal-login witness, verified-email when present, device-binding, legal identity-proofing witness and attributes, selfie-liveness witness, enrollment reference when accepted
  persists: through the encryption-aware workflow repository over durable stored-envelope storage
  returns: safe onboarding summary with accepted/manual-review decision, account status, authority status, and fresh-live-presence status
```

Keep HTTP and CLI thin. They should parse input, select verifier/config, call the shared command, and shape errors or output. They should not own identity semantics, fact construction rules, replay behavior, or policy meaning.

The server-side product path is now testable outside unit tests through the backend E2E harness. The iOS proof app now exercises the App Attest registration/assertion portion of the real-device path; after the physical App Attest run passes, extend it to submit composed onboarding directly, then replace copied/static proof inputs with real Keycloak, Persona, and video-selfie/liveness evidence. The CLI remains useful after the app exists because it can smoke-test local command wiring without driving the full app.

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
- `AppleAppAttestAssertionVerifier` behind `production-crypto` for challenge-bound P-256 assertion verification using trusted public-key bytes
- `AppleAppAttestKeyRegistrationVerifier`, `AppAttestKeyRegistrationStore`, and PostgreSQL key-registration storage for durable trusted public-key lookup
- native App Attest registration-object parsing now accepts `fmt`, `authData`, and `attStmt.x5c`, extracts attested credential data and COSE P-256 public keys, enforces App Attest AAGUIDs, verifies certificate validity/chain signatures/root trust/nonce extension, and rejects leaf-certificate public-key mismatches
- `StaticAppAttestPublicKeyResolver` remains as a test bridge for direct assertion-verifier fixtures
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
- `LivePresenceChallenge` captures server-issued challenge nonce, intended workflow, expected subject/device/app context, issued/expiry timestamps, status, retry/manual-review policy refs, and retention refs
- `InMemoryLivePresenceChallengeStore` and `PostgresLivePresenceChallengeStore` implement challenge issue, lookup, status recording, and verified one-time consumption
- PostgreSQL migration and row mapping preserve live-presence challenge workflow labels, status payloads, expected app context, expected device/subject context, policy refs, and lifecycle timestamps
- verified liveness carries provider metadata, provider event refs, challenge nonce, device ref, observed/expiry timestamps, liveness result, PAD result, assurance level, and retention policy refs
- `IdentityWitnessContext` records witness result, challenge nonce, App Attest-bound device ref, PAD result, and retention policy refs on `IdentityWitnessRecorded`
- `SelfieLivenessCheck` is represented as an onboarding witness distinct from the legal identity-proofing witness currently carried through the `GovernmentIdVerification` label and later `BiometricContinuityCheck`
- raw frames, images, templates, embeddings, and provider-native capture artifacts stay outside ordinary FEN facts
- `onboarding_identity_witnesses_slice_from_request` creates Persona-normalized legal identity-proofing and selfie-liveness witnesses as a child onboarding episode
- `execute_mobile_identity_onboarding_command` composes subject registration, OIDC/App Attest account-device bootstrap, legal identity-proofing witness and attributes, selfie-liveness witness, and continuity enrollment after consuming a matching live-presence challenge
- passed liveness can create the enrollment reference; failed or inconclusive liveness records auditable evidence and returns manual review without silently denying or creating enrollment
- tests prove successful onboarding creates account/session facts, device binding, legal identity-proofing witness and attributes, selfie-liveness witness, and enrollment reference
- tests prove failed/inconclusive liveness creates a manual-review path with witness evidence and no enrollment reference
- tests prove liveness must bind to the App Attest challenge/device context before append
- tests prove missing, used, expired, mismatched, failed, and manual-review challenge states behave explicitly

### Completed Mobile HTTP Endpoint Slices

The product-facing HTTP adapter shape now exists behind the optional `mobile-http` feature without making the default crate depend on JSON or a web framework:

- `handle_mobile_onboarding_http_request` handles `POST /mobile/onboarding` as a framework-agnostic method/path/body adapter
- the HTTP request body carries subject, observed time, OIDC token/config, App Attest-shaped evidence/config, expected device ref, and client context
- the handler parses JSON, constructs `MobileOnboardingCommandRequest`, calls `execute_mobile_onboarding_command`, and serializes a narrow JSON response
- `handle_encrypted_mobile_onboarding_http_request` parses the same JSON contract but calls the encrypted-facade command path instead of the plaintext in-memory workflow repository path
- `handle_mobile_identity_onboarding_http_request` handles `POST /mobile/identity-onboarding` as the composed identity-onboarding method/path/body adapter
- the composed request body carries subject, observed time, OIDC token/config, App Attest-shaped evidence/config, liveness assertion/challenge nonce, government-ID witness input, expected device ref, client context, subject kind, stable profile, and continuity modality
- `handle_encrypted_mobile_identity_onboarding_http_request` and `handle_postgres_encrypted_mobile_identity_onboarding_http_request` expose the same composed wire contract through encrypted in-memory and durable PostgreSQL-backed append/replay paths
- identity-onboarding responses include accepted/manual-review decision, assurance level, active devices, parent episode ID, key fact IDs, and committed fact count
- HTTP adapter code owns only wire parsing, status codes, and error shaping; identity semantics stay in the shared command and service path
- success returns subject ID, assurance level, active devices, workflow episode ID, key fact IDs, and committed fact count
- invalid JSON maps to `400`, wrong method to `405`, OIDC verification failure to `401`, App Attest/device mismatch to `422`, and repository append failure to `409`
- liveness rejection maps to `422`; missing, expired, already-consumed, or mismatched live-presence challenges map to explicit challenge errors; encrypted command encryption/materialization failures map to `500` because they indicate server-side persistence, key, or policy configuration failures
- tests cover successful account/device HTTP response JSON, encrypted-facade account/device HTTP append, invalid request JSON, wrong method, device mismatch, successful composed identity HTTP append, explicit identity-proofing outcome fields, live-presence handoff/callback mapping, missing live-presence challenge rejection without repository mutation, and encrypted composed episode append/replay through the HTTP adapter

### Completed Encryption-Aware Workflow Repository Facade Slice

The selected persistence direction is now a higher-level Rust facade over the explicit stored-envelope adapter boundary:

- `EncryptionAwareWorkflowRepository` accepts an `IdentityWorkflowSlice`, transaction ID, and commit timestamp
- the facade assigns fact, episode, and membership append sequences in one workflow-level plan
- fact payloads are encrypted through a metadata planner, encryption key, and payload encryptor before storage
- stored facts carry materialization policy refs, canonical associated data, encryption metadata, and ciphertext
- workflow episodes and memberships are stored alongside the encrypted facts as durable explanation records
- episode-composition append stores a parent episode, child workflow slices, encrypted child facts, memberships, and episode relations under one transaction context
- storage is delegated through `StoredEncryptedWorkflowRepository`, so PostgreSQL remains an envelope store rather than the identity semantic owner
- replay and subject materialization go back through policy evaluation, key resolution, decryption, and Rust projection logic
- deterministic metadata planning and an in-memory stored-envelope repository keep the facade covered without adding production KMS or database dependencies to the default crate
- tests prove a mobile OIDC plus App Attest workflow and the composed identity-onboarding episode composition can be encrypted, appended with explicit sequences, replayed, matched back to the direct workflow projection, and reached through the mobile HTTP adapter shape

The PostgreSQL-backed version of this facade now exists for durable append-sequence allocation and stored-envelope writes for both workflow slices and episode compositions. The runtime now composes that durable facade with JWKS-backed OIDC, AES-256-GCM fact encryption, durable App Attest key-state replay protection, and the mounted identity-onboarding runtime facade.

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

1. Run `ios/FenAppAttestProof` on a physically signed iPhone against the runtime and confirm real App Attest registration plus registered-key assertion generation.
2. Extend the proof app to submit `POST /mobile/identity-onboarding` directly with the generated registered-key assertion and existing static/sandbox OIDC, Persona, and liveness proof inputs.
3. Move fact key material from env-loaded bytes into DEK/KEK or KMS-backed wrapping and rotation.
4. Move the local runtime shell toward production-grade transport and make App Attest and live-presence state checks async-native when the server framework is selected.

The live PostgreSQL tests are skipped unless `IDENTITY_MODEL_POSTGRES_URL` is present; they have passed against a disposable PostgreSQL database in this workspace. The live Keycloak test is skipped unless the Keycloak env vars are present; it has passed against the local dev setup documented in `LOCAL_KEYCLOAK_DEV.md`.

The backend E2E harness is skipped unless `IDENTITY_MODEL_POSTGRES_URL`, `IDENTITY_MODEL_KEYCLOAK_ISSUER`, `IDENTITY_MODEL_KEYCLOAK_CLIENT_ID`, and `IDENTITY_MODEL_KEYCLOAK_TOKEN` are present. It has passed against disposable local PostgreSQL and Keycloak services using the setup documented in `LOCAL_BACKEND_E2E.md`.

PostgreSQL is the preferred first production database because it gives mature transactions, indexes, binary ciphertext storage, JSON/hybrid metadata options, and operational reliability without asking SQL to become the source of identity meaning.

## Current State

This repo contains a Rust crate implementing the first FEN identity-model foundations:

- typed FEN facts, identity primitives, workflow slices, policy evaluation, and materialized projections
- parsed UTC timestamp helpers for policy, IAM, device-evidence, and projection validity checks
- split onboarding and service APIs for subject registration, device binding, continuity enrollment, provider links, payer links, recovery, delegation, access decisions, and identity disputes
- generic OIDC/Keycloak session evidence boundary, JWKS verifier, and account-token bootstrap append/replay harness
- shared mobile onboarding command, dependency-free CLI smoke harness, feature-gated HTTP handler for OIDC plus App Attest-shaped device evidence, and production-crypto Apple registration/assertion verification boundary
- composed mobile identity-onboarding command and framework-neutral HTTP handlers for subject registration, account/device bootstrap, Persona-normalized legal identity-proofing witness and attributes, selfie-liveness witness, manual-review outcome, and continuity enrollment after passed proofing and liveness
- env-gated runtime-server E2E harness for the composed identity-onboarding endpoint over real local HTTP, live PostgreSQL persistence, live Keycloak/JWKS token verification, HTTP live-presence challenge issuance/consumption, and durable App Attest key-state replay protection
- liveness ceremony verifier boundary and durable live-presence challenge stores that consume structured live-presence/PAD results without storing raw media in FEN facts
- append-only in-memory repository traits and replay helpers for facts, episodes, memberships, and episode relations
- encrypted Fact envelope, associated-data, test encryption/key, policy-gated materialization, materialization audit, and in-memory encrypted repository boundaries
- higher-level encryption-aware workflow repository facade for converting typed workflow slices and composed parent/child episodes into encrypted stored envelopes and replaying them through policy/key gates
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

Passed locally after the production-crypto Apple assertion verifier pass.

Feature-enabled Ed25519 suite:

```sh
cargo test --features ed25519-dalek-verifier
```

Previously passed locally after the composed identity HTTP/runtime slice.

Feature-enabled OIDC/JWKS suite:

```sh
cargo test --features oidc-jwks-verifier
```

Passed locally after the threaded JWKS fetch hardening. The env-gated live Keycloak test also passed against the local `fen-dev` realm when the Keycloak issuer/client/token env vars were set.

Feature-enabled mobile HTTP suite:

```sh
cargo test --features mobile-http
```

Passed locally after the Persona proofing boundary and runtime-server identity mount.

Feature-enabled production crypto focused suite:

```sh
cargo test --features production-crypto apple_app_attest
```

Passed locally after the production-crypto Apple assertion verifier pass.

Live runtime server E2E:

```sh
cargo test --features runtime-server \
  live_runtime_server_identity_onboarding_e2e_when_env_is_set \
  -- --nocapture
```

Passed locally after the threaded JWKS fetch hardening with `IDENTITY_MODEL_POSTGRES_URL`, `IDENTITY_MODEL_KEYCLOAK_ISSUER`, `IDENTITY_MODEL_KEYCLOAK_CLIENT_ID`, and a fresh `IDENTITY_MODEL_KEYCLOAK_TOKEN` set against disposable local services.

Feature-enabled runtime server suite:

```sh
cargo test --features runtime-server
```

Passed locally after the production-crypto Apple assertion verifier pass.

Runtime server binary check:

```sh
cargo check --features runtime-server --bin mobile_onboarding_server
```

Passed locally after the runtime server mounted account/device, composed identity, and live-presence challenge issuance endpoints.

Feature-enabled PostgreSQL adapter suite:

```sh
cargo test --features postgres-adapter
```

Passed locally after the Persona proofing boundary and runtime-server identity mount with `IDENTITY_MODEL_POSTGRES_URL` absent. Live tests are env-gated and no-op unless that URL is set; those live tests pass against a disposable PostgreSQL database when the URL is present.

Combined mobile HTTP plus PostgreSQL adapter suite:

```sh
cargo test --features "mobile-http postgres-adapter"
```

Passed locally after the Persona proofing boundary and runtime-server identity mount.

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
- App Attest-shaped device evidence validation, production-crypto Apple registration storage plus assertion signature/challenge/app-ID verification, account-token binding, device-binding fact creation, and rejection-without-append behavior
- shared mobile onboarding command summary behavior, encrypted-facade mobile command behavior, CLI harness compile path, account/device HTTP JSON/status-code adapter behavior, encrypted-facade account/device HTTP adapter behavior, empty App Attest challenge rejection, and invalid App Attest timestamp rejection
- composed identity onboarding with Persona-normalized legal identity-proofing witness and attributes, selfie-liveness witness, durable live-presence challenge consumption, enrollment creation after passed proofing and liveness, manual-review evidence after failed/inconclusive/expired proofing or liveness, and App Attest challenge/device/app binding for liveness
- composed identity-onboarding HTTP request/response shape, live-presence challenge issuance HTTP response shape, encrypted-facade composed HTTP append/replay, missing live-presence challenge HTTP rejection without repository mutation, and composed episode-relation persistence
- feature-gated OIDC/JWKS verification, asymmetric JWT validation, env-gated live Keycloak token harness, and account-token append/replay
- split onboarding, composed onboarding, repository append/replay, and episode relations
- encrypted Fact envelope round trips, append-sequence replay, policy-before-key access, materialization audit, codec boundary, tamper detection, wrong-key, missing-key, and retired-key failures
- encryption-aware workflow repository sequence planning, encrypted workflow append, encrypted episode-composition append, policy-gated replay, mobile workflow projection equivalence, and PostgreSQL-backed encrypted workflow append/replay
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

The liveness verifier boundary, durable challenge issuance/consumption, composed identity-onboarding command, composed HTTP contract, runtime-server routes, CSPRNG challenge nonce generation, provider handoff metadata, and provider-normalized callback mapping exist. The next implementation work is vendor-specific handoff/session creation, signed provider callback verification, and provider ceremony metadata hardening while preserving one-time nonce use, expiry, and retry/manual-review state.

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
- `IOS_APP_ATTEST_PROOF.md`: backend contract and Swift-side envelope shape for the signed proof app
- `REPRODUCE_IOS_APP_ATTEST_PROOF.md`: end-to-end runbook to reproduce a real-device App Attest proof (Docker, tunnel, Xcode, phone, troubleshooting)
- `build_plan.md`: broader milestone history and rationale
