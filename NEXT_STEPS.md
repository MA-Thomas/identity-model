# Next Steps

## Current State

This repo contains a dependency-free Rust crate implementing the first FEN identity-model foundations, provider-backed vertical slices, typed workflow commands, split onboarding/service APIs, and a small service boundary for integration work.

The stable design boundary remains:

```text
provider/substrate produces evidence -> FEN verifies/translates -> FEN writes facts
```

Vendors, IAM systems, biometric SDKs, and hosted continuity services are evidence producers. They do not own identity truth. FEN owns the typed fact graph, policy evaluation, workflow evidence, and materialized projections.

## Progress Snapshot

As of the latest implementation pass, the cleanup items that were previously blocking integration have moved from "planned" to "implemented":

- typed workflow command structs exist for onboarding, access step-up, delegation, recovery, and identity dispute resolution
- workflow IDs are planned explicitly through `WorkflowIdPlan`, including relied-on fact references
- policy freshness can run through `PolicyEvaluationContext` and a small `Clock` boundary
- `IdentityWorkflowService` provides the first application-facing API layer over workflow slices, continuity challenge issue/verify, policy evaluation, narrative rendering, and materialized projections
- compatibility wrappers still preserve existing examples and tests

A follow-on hardening pass added:

- modern Rust module entrypoints without `mod.rs` files
- detailed access-authorization service outcomes that surface policy reasons and the access-decision fact ID while preserving the existing workflow outcome API
- versioned, reviewable policy artifact support through `PolicyArtifact`, stable versioned policy refs, artifact status, effective windows, review metadata, and service-level artifact evaluation
- append-only repository traits plus an in-memory identity repository and replay helpers for rebuilding materialized identity state from stored facts
- a golden fixture contract covering onboarding, export step-up, delegation, recovery, and identity-resolution rendered examples
- detailed service outcomes for onboarding, recovery, delegation, and identity dispute resolution, so callers can retrieve reviewable fact IDs without inspecting raw workflow slices
- production-facing onboarding steps now distinguish subject registration, device binding, continuity enrollment, provider identity linking, and payer identity linking; provider and payer links are optional follow-on facts rather than required first-touch inputs
- `IdGenerator` can now assign subject IDs for new-subject registration while still allowing callers to register an externally supplied subject ID

A second integration-readiness pass added:

- generated workflow ID plans and production-facing request constructors so callers do not need to hand-build `WorkflowIdPlan` for ordinary service use
- a core onboarding orchestration helper that composes subject registration, device binding, and continuity enrollment without requiring provider or payer links
- a repository-backed service append/replay path, plus an `IdentityWorkflowRepository` append boundary for future transactional database adapters
- atomic in-memory workflow-slice append preflight, so duplicate fact or membership IDs cannot partially mutate repository history
- structured policy artifact definitions for sensitive actions, emergency access, delegation constraints, recovery-method changes, and break-glass workflows
- auditable continuity verification rejection facts for invalid signatures, nonce failures, replay, malformed assertions, and related verifier rejections

The remaining work is no longer "split the architecture apart," "separate onboarding concerns," or "hide fixture ID plans from service callers." The next step is to move into production crypto, real provider transport, database-backed persistence, policy storage/review workflow notes, and deeper threat-model coverage.

## What Exists Now

Core model:

- FEN envelope types in `src/fen.rs`
- Sparse subject and identity primitives in `src/identity.rs`
- Identity `FactPayload` variants for witnesses, continuity, continuity verifier rejections, devices, institutional links, disputes, authority, recovery, risk, and access decisions
- Identity workflow scaffolding in `src/workflows.rs`
- Materialized identity-state projection in `src/materialized.rs`
- Translation helpers from trusted provider events into FEN fact drafts in `src/translation.rs`

Continuity and providers:

- Phase-compatible continuity assertion contract in `src/continuity.rs`
- Canonical continuity assertion serialization in `src/continuity/canonical.rs`
- Continuity verifier traits, deterministic signature-verifier seam, assurance mapping, and in-memory nonce lifecycle
- Replaceable continuity provider contract in `src/provider/contract.rs`
- Scripted hosted-provider adapter in `src/provider/hosted.rs`
- Mock Phase 1 and hosted-style continuity providers in `src/provider/mocks.rs`

Policy and support boundaries:

- Sensitive-action policy evaluation in `src/policy.rs`
- Versioned policy artifacts, status/effective-window checks, and policy review metadata in `src/policy.rs`
- Structured policy artifact definitions for sensitive actions, emergency access, delegation constraints, recovery-method changes, and break-glass workflows
- Typed `PolicyEvaluationReason` values for step-up, denial, and manual-review explanations
- Timestamp parsing/freshness helper boundary in `src/time.rs`
- Clock and policy evaluation context boundary in `src/clock.rs` and `src/policy.rs`
- ID generation trait and deterministic generator in `src/ids.rs`
- Workflow ID plans for fact, episode, membership, challenge, nonce, and relied-on fact references in `src/flows/core.rs`

Persistence and replay:

- Append-only fact, episode, and membership repository traits in `src/persistence.rs`
- Transaction-shaped workflow-slice append trait plus atomic in-memory append preflight
- In-memory identity repository for tests and adapter prototyping
- Replay helpers for rebuilding `MaterializedIdentityState` from stored facts

Public service boundary:

- `IdentityWorkflowService` in `src/service.rs`
- `WorkflowOutcome` containing the workflow slice, materialized projection, and narrative lines
- detailed service outcome structs for onboarding, access authorization, recovery, delegation, and identity disputes
- Service methods for subject registration, core onboarding orchestration, device binding, continuity enrollment, optional provider/payer identity linking, bundled onboarding, repository append/replay, continuity challenge issue/verify/audit, sensitive-action policy evaluation, policy artifact evaluation, recovery, delegation, and dispute resolution

Workflow slices:

- Separated onboarding requests for subject registration, device binding, continuity enrollment, provider identity linking, and payer identity linking in `src/flows/onboarding.rs`
- Bundled demo/compatibility onboarding flow and `OnboardingRequest` in `src/flows/onboarding.rs`
- Complete-record export step-up flow and `CompleteRecordExportStepUpRequest` in `src/flows/access.rs`, including auditable verifier-rejection facts
- Delegation flow and `DelegationRequest` in `src/flows/delegation.rs`
- Recovery flows and `RecoveryRequest` in `src/flows/recovery.rs`
- Dispute, merge, split, and witness-supersession flows with `IdentityDisputeResolutionRequest` in `src/flows/disputes.rs`
- Generated-ID constructors for production-facing workflow request structs while fixture constructors remain stable for demos/tests
- Shared workflow/episode helpers in `src/flows/core.rs`, `src/flows/support.rs`, and `src/flows/episode_labels.rs`

Fixtures and examples:

- Stable fixture rendering in `src/fixtures/rendering.rs`
- Narrative rendering in `src/fixtures/narrative.rs`
- Presentation-only enum labels in `src/fixtures/fixture_labels.rs`
- Runnable service-facade examples for onboarding, export step-up, delegation, recovery, and identity resolution in `examples/`

Tests:

- Focused integration tests under `tests/`
- Service/API boundary coverage in `tests/service_api.rs`
- Architecture guard for enum-to-string label boundaries in `tests/string_boundaries.rs`

## Verified Behavior

Run:

```sh
cargo test
```

The current suite has 49 passing tests and verifies that:

- verified continuity assertions become canonical `BiometricContinuityCheck` facts
- nonce verification rejects unknown, expired, reused, and enrollment-mismatched assertions
- registry-backed continuity verification handles canonical serialization, provider-key authorization, retired keys, malformed signatures, invalid signatures, and replay attempts
- complete-record export requires step-up when fresh continuity evidence is missing
- complete-record export is allowed when credential, continuity, and risk evidence satisfy policy
- failed continuity checks remain auditable facts and produce step-up decisions
- verifier-rejected continuity assertions remain auditable facts and produce step-up decisions when used in access authorization
- service-level continuity verification can return an auditable rejection fact for invalid signatures and related verifier failures
- policy freshness windows force step-up when credential, continuity, or risk evidence is stale
- policy evaluations carry typed reason codes
- policy artifacts generate versioned refs, carry review metadata, and gate inactive or expired policies into typed manual-review outcomes
- policy artifacts carry structured action-specific definitions for delegation, recovery-method changes, and break-glass workflows
- service methods evaluate directly against supplied `PolicyArtifact` values and preserve artifact lifecycle gates
- timestamp parsing returns explicit errors for unsupported timestamp shapes
- mock onboarding produces subject, device, witness, enrollment, provider-link, payer-link, episode, and membership artifacts
- split service onboarding can register a subject, bind a device, and enroll continuity without requiring provider or payer links
- provider and payer identity links can be added as independent optional service steps
- subject registration can either use a caller-supplied subject ID or assign one through `IdGenerator`
- service core onboarding can compose subject registration, device binding, and continuity enrollment with generated IDs and without provider/payer links
- service append/replay returns repository-backed materialized state across multiple workflow slices
- access authorization workflows keep evidence roles explicit through memberships
- provider swap behavior preserves canonical continuity and access-decision fact shape
- scripted hosted-provider request/response structs map into canonical FEN enrollment and continuity artifacts
- revoked devices are excluded from materialized state
- revoked or expired authorities are excluded from active materialized authority
- contested links are excluded from active materialized links unless confirmed
- witness expiration, validity periods, failed continuity, latest access decisions, and authority scope queries are handled in projections
- approved, denied, and trusted-device recovery paths produce explicit recovery events and access decisions
- duplicate-subject merge, incorrect-merge split, and witness supersession workflows remain auditable
- typed workflow requests preserve the existing slice behavior while allowing explicit ID plans
- service facade returns workflow facts, memberships, narrative lines, and materialized projections
- detailed service access outcomes surface policy reasons and access-decision fact IDs while preserving compatibility with existing service calls
- detailed service outcomes for onboarding, recovery, delegation, and identity dispute resolution surface reviewable fact IDs while preserving compatibility with existing service calls
- service continuity challenge issue/verify covers nonce lifecycle and assertion verification
- clock-backed policy evaluation context drives freshness tests without coupling tests to wall-clock behavior
- fixture and narrative output is pinned by a golden integration contract
- append-only repository replay rebuilds materialized state while preserving revoked, superseded, contested, and expired-history behavior
- workflow-slice repository append rejects duplicate IDs atomically without partially mutating history
- enum-to-string helpers stay isolated to rendering, signing, and human-facing label boundaries

Run examples with:

```sh
cargo run --example onboarding
cargo run --example export_step_up
cargo run --example delegation
cargo run --example recovery
cargo run --example identity_resolution
```

All examples continue to render stable fixture-style output after the service and request-boundary changes.

## Completed Milestones

### 1. Architecture Cleanup

The crate has been split into visible boundaries:

- `src/lib.rs` now only exposes modules and re-exports
- tests moved out of `src/lib.rs` into focused files under `tests/`
- the former `src/flows.rs` was split into onboarding, access, delegation, recovery, disputes, core, support, and episode-label modules
- the former `src/provider.rs` was split into provider contract, hosted adapter, and mock providers
- the former `src/fixtures.rs` was split into rendering, narrative, payload summaries, presentation labels, and support helpers
- the former `src/continuity.rs` was split so canonical signing serialization lives in `src/continuity/canonical.rs`

### 2. Typed Internal Explanations

Policy evaluation now returns typed `PolicyEvaluationReason` values instead of requiring callers to infer policy meaning from strings or decision-only output.

The model remains Rust-typed internally:

```text
typed facts/policies/projections -> typed decisions and reason codes
```

### 3. Boundary-Only String Labels

Enum-to-string conversion is now explicitly boundary-only:

- fixture and narrative labels: `src/fixtures/fixture_labels.rs`
- canonical continuity signing labels: `src/continuity/canonical.rs`
- human-facing episode labels: `src/flows/episode_labels.rs`

Architecture rule:

```text
typed Rust enums internally -> string labels only at rendering, persistence, provider/wire, or signing boundaries
```

`tests/string_boundaries.rs` guards against generic label helpers creeping back into core modules.

### 4. Timestamp and ID Boundaries

Freshness logic now uses `src/time.rs` rather than private ad hoc parsing in policy code. The helper still supports a narrow dependency-free UTC timestamp shape, but parse failures are explicit.

Workflow fixture ID generation now goes through `IdGenerator` and `DeterministicIdGenerator` in `src/ids.rs`, preserving stable demo IDs while leaving room for production ID generation later.

### 5. Typed Workflow Commands

Workflow flows now have typed command/request structs:

- `OnboardingRequest`
- `CompleteRecordExportStepUpRequest`
- `RecoveryRequest`
- `DelegationRequest`
- `IdentityDisputeResolutionRequest`

Compatibility wrappers preserve the previous example and test call sites, while service and future API callers can pass typed commands through core logic without JSON-shaped or UI-shaped thinking leaking inward.

### 6. Workflow ID Plans

`WorkflowIdPlan` now centralizes episode IDs, fact IDs, membership IDs, challenge IDs, nonces, and cross-fact references such as access decisions relying on authority or evidence facts.

Stable examples use explicit fixture ID plans where human-readable demo IDs matter. Operational callers can supply generated plans, and tests verify that cross-fact references follow the supplied plan rather than hidden hard-coded IDs.

### 7. Clock and Evaluation Context

`Clock`, `FixedClock`, and `PolicyEvaluationContext` now provide a small time boundary around policy freshness evaluation. Existing explicit timestamps remain available for deterministic examples.

### 8. Initial Public Service Boundary

`IdentityWorkflowService` wraps the main flows and lower-level continuity/policy operations so applications do not need to assemble every fact, membership, projection, and narrative manually.

### 9. Split Onboarding Boundary

Production-facing onboarding is now decomposed into independently callable service steps:

- `register_subject` for caller-supplied subject IDs
- `register_new_subject` for service-assigned subject IDs through `IdGenerator`
- `bind_device`
- `enroll_continuity_reference`
- `link_provider_identity`
- `link_payer_identity`

The old bundled `OnboardingRequest` remains available as a demo/compatibility path that emits the full six-fact onboarding fixture. Provider and payer links are no longer required for first-touch subject registration, device binding, or continuity enrollment.

## Remaining Cleanup Before Integration

These are still worth doing before real provider transport, crypto, database-backed persistence, or application APIs land.

### 1. Finish Service/API Ergonomics

The service facade now exposes detailed outcomes for the main application-facing workflows, plus split onboarding methods for production-style composition. The next cleanup is mostly ergonomic: reduce places where callers must understand fixture/demo defaults, hand-build ID plans, or inspect optional fact IDs.

Recently completed:

- typed outcome structs for the remaining service workflows where callers need more than the generic workflow/projection/narrative bundle
- runnable examples now use the service facade rather than low-level slice helpers
- tests prove old wrappers and new service calls remain behaviorally equivalent
- production-facing onboarding has been separated into explicit subject registration, device binding, continuity enrollment, provider link, and payer link service steps
- generated-ID constructors hide fixture/demo ID plans for production-facing request construction
- core onboarding orchestration composes registration, device binding, and continuity enrollment without provider/payer links
- service append/replay can persist a workflow slice and return repository-backed current state

Build target:

- documentation snippets showing the detailed service outcomes in API-style usage
- tighter error/outcome shapes where service callers should not need to reason over optional fact IDs for workflows that always emit a given fact
- review whether remaining optional fact IDs should become path-specific typed outcomes

Practical outcome:

Applications can use the service API as the primary boundary, choose only the identity steps they actually have evidence for, and keep tests/demos stable through fixture helpers.

### 2. Promote Policy to Versioned Artifacts

Policy now has `PolicyArtifact` support with versioned refs, status, effective windows, review metadata, artifact-level evaluation, service-level artifact evaluation, and action-specific definition structs. The next integration-ready version should focus on storage/review workflows and migration notes rather than only in-memory artifact shape.

Recently completed:

- explicit artifact structs for emergency access, delegation constraints, recovery-method changes, and break-glass workflows
- more structured freshness requirements by evidence type and action

Build target:

- migration notes for policy artifact storage and review workflows

Practical outcome:

Access decisions become explainable against reviewed policy artifacts rather than only against helper defaults.

### 3. Keep Fixture/Narrative Rendering Presentation-Only

The renderer is split and guarded, but future contributors should keep the rule intact:

```text
typed Rust model -> rendered fixture/log/audit string
```

not:

```text
rendered string -> domain decision logic
```

If fixture output becomes an integration contract, pin it with golden files rather than parsing it back into domain behavior.

## Next Product/Architecture Milestones

### 1. Policy Hardening

Policies now have reviewable artifacts, artifact-level gating, and explicit definitions for sensitive actions, emergency access, delegation constraints, recovery-method changes, and break-glass workflows. Continue toward operational storage and review lifecycle semantics.

Build targets:

- richer policy versioning and review lifecycle states for operational storage
- tests proving access decisions cite stable policy refs, relied-on facts, and typed reasons
- migration notes for storing and reviewing policy artifacts outside the crate

Practical outcome:

Access decisions become reviewable policy artifacts, not just helper-function results.

### 2. Persistence and Replay

The crate now has append-only repository traits, a workflow-slice append trait, an in-memory repository with atomic append preflight, replay helpers, and service append/replay. Next, prepare the boundary for database-backed storage without adding database dependencies to the core model.

Build targets:

- database-backed adapter notes and storage contract boundaries
- persisted record envelopes for fact, episode, and membership append operations if needed
- stale-evidence replay tests combined with policy evaluation contexts
- migration notes for later database-backed storage

Practical outcome:

The audit graph becomes operational: facts are written once, projections can be rebuilt, and current identity state remains explainable from history.

### 3. Golden Fixtures and Integration Contracts

The rendered workflow examples are now pinned by a golden fixture test. If downstream consumers need separately distributed artifacts, split or publish those generated files as needed.

Build targets:

- generated fixture files for each example, if separate files are useful for consumers
- tests comparing example output to golden files
- documented update command for intentional fixture changes
- fixture coverage for onboarding, export step-up, delegation, recovery, and identity resolution

Practical outcome:

Other teams can integrate against concrete examples and detect accidental workflow-shape changes early.

### 4. Production Trust Boundary

Replace the deterministic test signature helper with real cryptographic verification while keeping `ContinuitySignatureVerifier` as the stable seam.

Build targets:

- selected signing format and crate
- cryptographic signature verification backend
- production verification-key storage or policy lookup
- provider key rotation behavior backed by real key material
- tests that bind canonical serialization to the selected signature algorithm
- negative tests for malformed, retired, wrong-provider, expired, replayed, and wrong-key assertions

Practical outcome:

FEN can trust continuity assertions from a real substrate without making that substrate part of the identity ontology.

### 5. Real Provider Transport

The provider-shaped adapter boundary exists. Once a vendor or hosted substrate is chosen, add real transport only at the provider edge.

Build targets:

- authenticated HTTP or SDK transport
- provider-specific request signing and response validation
- live error mapping into `ContinuityProviderError`
- integration tests reusing canonical fact-shape assertions
- proof that canonical FEN facts do not change when provider implementation changes

Practical outcome:

The rest of the identity graph can stay stable while Phase 1 vendor, hosted, or enclave-backed providers are swapped.

### 6. Threat-Model Pass

Before real biometric/provider work, explicitly model abuse cases and expected controls.

Build targets:

- replay and nonce abuse scenarios
- stale evidence and session-extension abuse
- provider compromise and key-rotation scenarios
- account takeover and malicious recovery scenarios
- incorrect merge/split and insider dispute-resolution scenarios
- emergency access misuse scenarios
- tests or notes linking each risk to controls in verifier, policy, projection, or audit

Practical outcome:

The system has a clear security posture before it starts trusting real continuity evidence.

### 7. Workspace Split When Dependencies Demand It

Do not split into many crates prematurely. Keep the current crate until real provider transport, production crypto, persistence, or API dependencies land.

Likely future shape:

```text
crates/
  identity-core/
  identity-providers/
  identity-fixtures/
  identity-api/
```

Practical outcome:

Provider SDKs, HTTP clients, crypto crates, fixture tooling, and API dependencies stay out of the core model.

## Current Principle To Preserve

Phase 1 should be implemented as the first provider adapter, not as the identity architecture.

The FEN identity graph should remain stable as the continuity substrate moves from vendor-backed to hosted to enclave-backed.

Core rule:

```text
typed Rust facts, policies, commands, and projections inside FEN;
strings only at rendering, persistence, provider/wire, and signing boundaries.
```
