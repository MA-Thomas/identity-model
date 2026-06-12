# Fable Updates

This document captures eight improvement workstreams identified in an external review
(June 2026). Each section is self-contained: it states the problem as it exists in the
current code, the proposed change, a migration path, the test impact, and the risks.
None of these change the FEN architectural thesis — providers produce evidence, FEN
verifies and translates, FEN owns the typed fact graph. They harden the implementation
around that thesis.

Sections are ordered to match the review, not by priority. A suggested execution order
is at the end.

---

## 1. Replace Stringly-Typed IDs and Timestamps With Validated Newtypes

### Problem

`src/fen.rs` defines one wrapper for every identifier:

```rust
pub struct Id(pub String);

pub type FactId = Id;
pub type SubjectId = Id;
pub type ProblemEpisodeId = Id;
pub type MembershipId = Id;
pub type PolicyRef = Id;
// ... etc.
```

Type aliases are transparent: a `MembershipId` can be passed where a `FactId` is
expected and the compiler will not object. For a codebase whose central claim is that
relied-on fact IDs and policy refs are auditable, ID-kind confusion is a real bug class
— a relied-on-facts list that silently contains an episode ID would corrupt the audit
trail without any test necessarily noticing.

Similarly, `Timestamp(pub String)` and `Date(pub String)` carry unvalidated strings into
the core. Every security-sensitive comparison goes through `src/time.rs`, which parses
on each call and returns `Result<_, TimestampParseError>`. Consequences:

- parse failure surfaces deep inside policy/freshness/expiry checks instead of at the
  evidence boundary where it belongs;
- every caller must handle a `Result` for what should be a total comparison;
- the parser accepts only `YYYY-MM-DDTHH:MM:SSZ`. Real OIDC and provider timestamps
  frequently carry fractional seconds or numeric offsets, so valid provider evidence can
  be rejected as malformed at comparison time rather than normalization time.

### Proposed change

**IDs.** Generate distinct newtypes with a small macro in `src/ids.rs`:

```rust
macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self { Self(value.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
    };
}

typed_id!(FactId);
typed_id!(SubjectId);
typed_id!(ProblemEpisodeId);
typed_id!(MembershipId);
typed_id!(RelationId);
typed_id!(PolicyRef);
// ... one per current alias
```

Where genuinely heterogeneous ID handling is needed (rendering, persistence row
mapping), add explicit conversions rather than a common base type, so crossings remain
visible in code review.

**Timestamps.** Introduce a validated type that parses once at the boundary:

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTimestamp {
    unix_seconds: i64,
    subsec_nanos: u32,
    /// Original RFC 3339 rendering, retained so canonical serialization
    /// and signature verification remain byte-stable.
    canonical: String,
}

impl UtcTimestamp {
    pub fn parse(value: &str) -> Result<Self, TimestampParseError> { /* RFC 3339 */ }
}
```

Key properties:

- `Ord`/`PartialOrd` derive from the numeric fields, so all the helper functions in
  `src/time.rs` (`compare_timestamps`, `timestamp_after`, `timestamp_in_closed_interval`,
  `seconds_between`) become infallible methods and most call-site `Result` handling
  disappears;
- parsing accepts fractional seconds and `+00:00`/`Z` offsets, then normalizes;
- the retained `canonical` string preserves the existing contract in
  `src/continuity/canonical.rs`, where signed continuity assertions serialize timestamp
  bytes — signature verification must keep seeing exactly the bytes the provider signed,
  so the canonical form must be the original string, not a re-rendering.

Invalid timestamps become unrepresentable past the boundary: HTTP deserialization in
`mobile_http.rs`, provider adapters, and persistence row mapping construct
`UtcTimestamp` (or reject the evidence with a typed translation error), and everything
inland operates on validated values.

### Status: IMPLEMENTED AND VERIFIED (June 2026)

Verified against the full `FEATURE_MATRIX.md` check sequence: `cargo test`
default plus `mobile-http`, `postgres-adapter`, combined, and `runtime-server`
feature builds — all passing, golden fixtures unchanged.

**IDs — done.** `src/fen.rs` now defines a `typed_id!` macro generating distinct
newtypes (with `new`, `as_str`, `From<String>`, `From<&str>`, `AsRef<str>`,
`Display`, and `Ord` for collection use); all eleven former aliases plus
`ChallengeId` (`continuity.rs`), `LivePresenceChallengeId` (`liveness.rs`), and
`PersistenceTransactionId` (`persistence/encrypted.rs`) are now distinct types,
and `pub struct Id` is deleted. Design choices worth knowing:

- The inner `String` stays `pub`, so existing `.0` access, pattern matching, and
  PostgreSQL row mapping keep working; this was a type-safety change, not an
  encapsulation change.
- The conversion immediately caught two real cross-kind bugs: `flows/access.rs`
  and `service.rs` both minted continuity challenge IDs with
  `next_episode_id(...)`. `IdGenerator` now has `next_challenge_id`, whose
  default implementation deliberately shares the episode counter so every
  previously generated ID string (and the golden fixtures) stays byte-identical.
  Same pattern for the `next_relation_id` default, which shares the membership
  counter but now returns a real `RelationId`.
- `tests/common::id` became generic (`fn id<T: From<String>>`), so hundreds of
  test call sites stayed untouched; only `let` bindings without an inferable
  type needed explicit annotations.
- Row-mapping in `persistence/postgres.rs` now names the concrete ID type per
  column (`FactId`, `SubjectId`, `PolicyRef`, `LivePresenceChallengeId`, ...),
  which makes the storage-to-domain boundary self-documenting.

**Timestamps — contract level done; field migration staged.** `src/time.rs` now
has `UtcTimestamp` (parsed-once, normalized-to-UTC, infallible `Ord`/`Eq`
comparisons, original string retained as `canonical()` so signed-assertion
bytes are never re-rendered). The parser accepts fractional seconds and numeric
UTC offsets and normalizes them; all existing helper functions
(`compare_timestamps`, `timestamp_after`, ...) now delegate to it, so every
security-sensitive comparison site gained the widened, validated parsing
without a signature change. Unit tests cover fractional seconds, offset
normalization, canonical-byte retention, and malformed-input rejection.
Deliberately deferred: converting the hundreds of `Timestamp` struct fields to
`UtcTimestamp` across the domain model — that is mechanical, per-module work
(boundary modules first) and was staged exactly as the migration path below
describes, to keep this change reviewable.

### Migration path

1. Land `typed_id!` and `UtcTimestamp` alongside the existing types; nothing uses them yet.
2. Convert one ID alias at a time (start with `PolicyRef`, which has the smallest
   surface). Delete the alias, follow compiler errors. One commit per alias.
3. Convert `Timestamp` last, module by module, starting at the boundaries
   (`mobile_http.rs`, `iam/jwks.rs`, `persistence/postgres.rs` row mapping) and moving
   inland to `policy.rs`, `liveness.rs`, `device.rs`.
4. Delete `src/time.rs` free functions once all callers use methods, or keep them as
   thin delegating wrappers for one release.

### Test impact

Existing tests are the safety net; the conversion is compiler-driven and should not
change behavior. Add new tests: cross-kind ID assignment fails to compile (a
`compile_fail` doc test or `trybuild` case), fractional-second and offset timestamps
parse and normalize, canonical bytes of a signed assertion are unchanged after
conversion (extend the golden fixtures in `tests/golden/`).

### Risks

The persistence layer stores ID strings and timestamp strings in PostgreSQL; row
mapping must construct the right newtype per column, which is mechanical but must be
done carefully in `src/persistence/postgres.rs`. The golden fixture renderings in
`tests/golden/workflow_examples.txt` must remain byte-identical — treat any diff there
as a regression, not a fixture refresh.

---

## 2. Make the Runtime Server Concurrent, Resilient, and Gracefully Stoppable

### Problem

`src/bin/mobile_onboarding_server.rs` accepts connections sequentially:

```rust
for stream in listener.incoming() {
    match stream {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(config.read_timeout));
            // handle_connection(&mut stream, &mut runtime, ...) — blocking, in-line
        }
        Err(error) => return Err(...),   // accept error kills the server
    }
}
```

Three production defects:

1. **Head-of-line blocking.** One client holding a connection open stalls every other
   client. The read timeout (default 5s) bounds each stall but a trickle of slow
   clients serializes into long queues — effectively a single-request-at-a-time server.
2. **Fatal accept errors.** Transient `accept()` failures (e.g. `EMFILE` under fd
   pressure) return `Err` and exit the listen loop, taking the whole server down.
3. **No graceful shutdown.** There is no signal handling; a deploy or SIGTERM kills the
   process mid-request, which matters for a server whose requests append durable
   encrypted facts.

This is the largest gap between "tested" and "deployable." Note that fixing it does
not conflict with `WEB_FRAMEWORK_THIN_ADAPTER_RATIONALE.md` — the framework-neutral
handlers stay exactly as they are; only the transport shell changes.

### Proposed change

The crate already depends on tokio (the binary holds a `tokio::runtime::Runtime` to
drive sqlx). Two viable designs:

**Option A — bounded thread pool over the existing blocking handlers (smaller step).**
Keep `std::net::TcpListener`. Spawn a fixed pool of N worker threads (configurable,
e.g. `IDENTITY_MODEL_RUNTIME_WORKER_THREADS`, default 8) consuming accepted streams
from a bounded channel. When the channel is full, respond `503` immediately rather
than queueing unboundedly. Handlers remain synchronous and unchanged.

**Option B — async transport on the tokio runtime already in the process.** Replace
the listen loop with `tokio::net::TcpListener` and `tokio::spawn` per connection,
wrapping each request in `tokio::time::timeout` for a *total* request deadline. This
also unblocks the "async-native App Attest and live-presence state operations" item
already listed in `NEXT_STEPS.md`, because handlers would no longer need
`block_on` bridges into sqlx.

Recommendation: Option A first (it is a contained change with identical handler
semantics), with Option B as the follow-on once async-native store operations land.

Either option requires the same supporting work:

- **Shared runtime state.** `handle_connection` currently takes `&mut Runtime`.
  Concurrency requires `Arc<Runtime>` with interior synchronization. Audit which parts
  are actually mutable: the PostgreSQL repositories should be usable through `&self`
  (sqlx pools are `Clone + Send + Sync`); anything genuinely mutable (in-memory
  caches, key-state guard internals) gets an explicit `Mutex`/`RwLock` with
  documented lock ordering. Prefer pushing mutability down into the stores rather
  than locking the whole `Runtime` per request, which would re-serialize everything.
- **Accept-loop resilience.** Log and continue on accept errors, with a short backoff
  for resource-exhaustion errors. Never return from the loop on a per-connection error.
- **Graceful shutdown.** Install a SIGTERM/SIGINT handler that stops accepting,
  drains in-flight requests up to a deadline (e.g. 20s), then exits. With Option A this
  is an `AtomicBool` checked by the accept loop plus joining workers; with Option B it
  is `tokio::signal` plus a `CancellationToken`.
- **Total request deadline.** Socket read/write timeouts do not bound a client that
  sends one byte per second; add a wall-clock deadline per request covering header
  read, body read, and handler execution. Also cap header section size (the body is
  already capped by `max_body_bytes`, default 65,536).

### Status: IMPLEMENTED AND VERIFIED (June 2026)

Verified: `cargo check --features runtime-server --bin mobile_onboarding_server`
and `cargo test --features runtime-server` pass. (The env-gated live E2E
harness should be re-run against local PostgreSQL/Keycloak per
`LOCAL_BACKEND_E2E.md` before the next deploy — the harness exercises the new
transport path end to end.)

`src/bin/mobile_onboarding_server.rs` now has, in place of the sequential
accept loop:

- **A bounded worker pool** (`IDENTITY_MODEL_RUNTIME_WORKER_THREADS`, default 8)
  fed by a bounded queue (`IDENTITY_MODEL_RUNTIME_QUEUE_DEPTH`, default 32).
  When the queue is full, new connections get an immediate `503` instead of
  queueing unboundedly.
- **A resilient accept loop**: transient accept errors are logged with backoff
  instead of killing the server; the listener polls non-blocking so shutdown is
  observed promptly.
- **Graceful shutdown**: SIGTERM/SIGINT (via a dedicated signal-listener thread
  on a minimal tokio runtime; the `tokio/signal` feature was added to the
  `runtime-server` feature) stops accepting, drains queued and in-flight
  requests, and exits within `IDENTITY_MODEL_RUNTIME_SHUTDOWN_GRACE_SECONDS`
  (default 20).
- **A total request deadline** (`IDENTITY_MODEL_RUNTIME_REQUEST_DEADLINE_SECONDS`,
  default 15) covering header and body reads, so a client trickling one byte
  per second gets a `408` instead of holding a worker forever; per-read socket
  timeouts now also map to `408` rather than a silently dropped connection.

Design choices worth knowing:

- **Option A from this section, with one deliberate deviation.** Handler
  execution is serialized behind a single `Mutex<Runtime>`, but socket reads
  and writes happen *outside* the lock. The head-of-line blocking that mattered
  — slow clients stalling everyone — is gone; what remains serialized is the
  database-bound handler body. That is intentional: the runtimes require
  `&mut self`, and duplicating the deterministic ID generator across workers
  would let two workers mint identical fact IDs. Parallel handler execution is
  the Option B follow-on, gated on async-native runtimes and a
  concurrency-safe ID source.
- `/health` and `/ready` never take the runtime lock — readiness probes the
  pool directly via a dedicated handle — so probes answer even while a long
  onboarding request is in flight. The live-presence challenge route similarly
  uses its own store handle.
- A poisoned runtime lock (a worker panicked mid-request) returns a structured
  `500` and refuses further stateful work instead of running on possibly
  inconsistent in-memory state.
- One library change was required for thread-safety:
  `MockPhase1ContinuityProvider`'s event counter moved from `Cell<u64>` to
  `AtomicU64` (with a manual `Clone` that snapshots the count), since the
  server config holding it is now shared across worker threads. Counter
  semantics are unchanged.

### Test impact

Add an integration test that issues K concurrent slow requests plus one fast request
and asserts the fast request completes promptly (this fails against today's binary).
Add a shutdown test: SIGTERM mid-request, assert the in-flight request completes and
the encrypted fact rows are consistent. The existing env-gated E2E harness
(`runtime_server_e2e.rs`) should pass unchanged.

### Risks

Concurrent appends will exercise the PostgreSQL append-sequence allocation under
contention for the first time. The transactional allocation described in
`NEXT_STEPS.md` should already be correct (sequence allocated inside the same SQL
transaction as the fact rows), but add an explicit concurrent-append test before
enabling concurrency, because nonce derivation depends on sequence uniqueness
(see section 8).

---

## 3. Decompose Oversized Modules

### Problem

Four files dominate the crate and will become review, merge, and navigation
bottlenecks:

| File | Lines |
|---|---|
| `src/persistence/postgres.rs` | 4,234 |
| `src/device.rs` | 2,146 |
| `src/persistence/encrypted.rs` | 2,050 |
| `src/mobile_http.rs` | 1,880 |

Each mixes several separable concerns behind one `mod`.

### Proposed change

Pure-move refactors — no behavior change, no signature change, `pub use` re-exports
from the parent module so the crate's public API is untouched.

**`src/persistence/postgres/`** split by stored entity and concern:

```text
postgres/
  mod.rs            — repository structs, pool config, pub use of submodules
  migrations.rs     — migration runner
  rows.rs           — row structs and row<->domain mapping
  facts.rs          — encrypted fact append/query
  episodes.rs       — episode, membership, relation storage
  workflow_tx.rs    — workflow transaction rows, sequence allocation
  app_attest.rs     — key-state and key-registration stores (migrations 0003/0005)
  challenges.rs     — live-presence challenge store (migration 0004)
  audit.rs          — materialization audit rows
```

**`src/persistence/encrypted/`**:

```text
encrypted/
  mod.rs
  envelope.rs       — EncryptedStoredEnvelope, canonical envelope bytes
  labels.rs         — the typed payload-label enums and string mapping
  planner.rs        — FactEncryptionMetadataPlanner impls (deterministic test, AES-GCM)
  aead.rs           — the ring AES-256-GCM encryptor (production-crypto feature)
  memory.rs         — in-memory repositories
  facade.rs         — encryption-aware workflow repository facade
```

**`src/device/`**: evidence shapes and verifier traits in `mod.rs`; the key-state
guard and its in-memory store in `key_state.rs`; the `production-crypto` Apple
registration/assertion verification (cert chain, nonce extension, COSE key handling)
in `apple.rs`.

**`src/mobile_http/`**: shared wire types and error mapping in `mod.rs`; one module
per route family (`onboarding.rs`, `identity_onboarding.rs`, `live_presence.rs`).

### Migration path

One file per commit, move-only, in this order: `postgres.rs` (worst offender),
`encrypted.rs`, `device.rs`, `mobile_http.rs`. Run the full feature matrix from
`FEATURE_MATRIX.md` after each commit. Because section 4 (explicit re-exports) touches
the same `pub use` lines, do this section first and section 4 immediately after.

### Test impact

None expected; that is the point. The feature matrix run per commit is the
verification.

### Risks

Move-only discipline is the whole risk control: resist fixing anything while moving.
Behavioral fixes found during the move get a TODO and their own later commit.

---

## 4. Replace Glob Re-Exports With an Explicit Public API

### Problem

`src/lib.rs` re-exports every module with globs:

```rust
pub use clock::*;
pub use continuity::*;
pub use device::*;
// ... ~20 more
```

Effects: every type in a 25k-line crate lands in one flat namespace; name collisions
between modules are found late (and `ambiguous_glob_reexports` situations resolve
surprisingly); it is impossible to tell from `lib.rs` what the intended public API is
versus what leaked; and any newly-`pub` item silently becomes API surface, which makes
semver discipline impossible once anything depends on this crate.

### Proposed change

1. Inventory the real surface: `cargo doc --no-deps` and grep actual usage in
   `tests/`, `examples/`, and `src/bin/` to see which items are consumed externally.
2. Replace each glob with an explicit list, module by module:

   ```rust
   pub use fen::{Fact, FactId, FactPayload, FactStatus, Provenance, Timestamp, ...};
   pub use continuity::{ContinuityAssertion, SignedContinuityAssertion,
       ContinuitySignatureVerifier, VerificationKeyRegistry, ...};
   ```

   The compiler drives this: remove one glob, fix the errors with explicit imports,
   commit, repeat.
3. Add `#![deny(ambiguous_glob_reexports)]` during the transition so remaining globs
   cannot hide collisions.
4. Optionally add `pub mod prelude` re-exporting the ~30 types that nearly every
   consumer needs (`Fact`, `FactPayload`, `SubjectId`, workflow slice types,
   `MaterializedIdentityState`), so internal tests and examples keep their ergonomics
   with `use identity_model::prelude::*;`.
5. Internal-only helpers discovered during the inventory get demoted to
   `pub(crate)`.

### Migration path

Do immediately after section 3 (the module splits rewrite the same lines). One module
per commit. Tests and examples that relied on glob visibility get explicit imports —
churn-heavy but mechanical.

### Test impact

Compile-only. The full feature matrix is the check, since several items are only
referenced under feature gates (`mobile-http`, `postgres-adapter`, `production-crypto`)
and a too-aggressive `pub(crate)` demotion will only fail under those features.

### Risks

Low. Worst case is a missed re-export caught by a feature-gated build, which is
exactly why the matrix runs per commit.

---

## 5. Split Into a Cargo Workspace and Add CI for the Feature Matrix

### Problem

The project is one crate with six features and documented guidance to run eight
`cargo test` invocations by hand (`FEATURE_MATRIX.md`). Two issues:

- The dependency-light core is enforced by convention, not structure. Nothing stops a
  future change from making a default-feature code path reach `sqlx` or `reqwest`;
  only a human running the matrix notices.
- There is no CI configuration in the repo. The matrix only holds if a human
  remembers, and feature-combination breakage is precisely the kind of regression
  humans miss locally (features are additive and unify across the dependency graph,
  so "works with `runtime-server`" proves nothing about `--no-default-features` builds
  of a single feature).

### Proposed change

**Workspace layout:**

```text
Cargo.toml                 — [workspace]
crates/
  fen-core/                — current default-feature code: fen, identity, flows,
                             policy, materialized, continuity, liveness,
                             identity_proofing, device (sans Apple verifier), service,
                             translation, workflows, fixtures, in-memory persistence.
                             Zero non-dev dependencies. Forever.
  fen-crypto/              — production-crypto: ring AEAD adapter, Apple App Attest
                             registration/assertion verification
  fen-ed25519/             — the ed25519-dalek continuity verifier
  fen-oidc/                — JWKS/OIDC verification (jsonwebtoken, reqwest)
  fen-postgres/            — sqlx adapters, migrations
  fen-http/                — framework-neutral wire types and handlers (serde)
  fen-runtime/             — the server binary; depends on all of the above
```

The matrix becomes the crate graph: `fen-core` *cannot* depend on sqlx because it does
not declare it, and `cargo test --workspace` covers what the eight invocations cover
today. Feature flags survive only where genuinely optional behavior remains inside one
crate (e.g. `fen-runtime` choosing the static fixture verifier versus the Apple
verifier).

**CI (GitHub Actions or equivalent), regardless of when the split happens:**

```yaml
jobs:
  core:        cargo test                                  # must stay dependency-light
  matrix:      cargo test --features <each of the 8 combos> # from FEATURE_MATRIX.md
  lint:        cargo fmt --check && cargo clippy --all-targets -- -D warnings
  live:        # postgres service container + Keycloak container;
               # runs the env-gated live harnesses on a schedule or on main
```

The live job reuses `LOCAL_BACKEND_E2E.md` / `LOCAL_KEYCLOAK_DEV.md` setup, which is
already scripted enough to containerize. Until then, even the first three jobs
eliminate the worst risk.

### Migration path

CI first (one PR, no code changes — immediate value). The workspace split second, one
crate at a time, extracting leaves first: `fen-ed25519`, then `fen-oidc`, then
`fen-crypto`, then `fen-postgres`, then `fen-http`, with `fen-runtime` last. The
section 3 module splits make each extraction nearly a directory move.

### Test impact

Tests move with their crates; cross-crate integration tests (e.g.
`runtime_server_e2e.rs`) live in `fen-runtime`. Total coverage is unchanged but each
test now also proves its crate's dependency boundary.

### Risks

Moderate churn in imports and paths; coordinate with sections 3 and 4 so paths move
once, not three times. Keep `identity_model` as a facade crate re-exporting the
workspace if any external consumer already depends on the current name.

---

## 6. Adopt Commit and History Discipline

### Problem

The history is six commits, all titled "updates". For a project whose architectural
thesis is auditable, explainable, append-only history, the repo's own history
currently explains nothing: there is no way to bisect a regression, correlate a code
change with a contract-document change, or identify which commit corresponded to a
passing live proof (the Keycloak proof, the PostgreSQL live harness, the backend E2E
described in `NEXT_STEPS.md` are not findable as commits).

### Proposed change

No history rewrite — the existing commits stay as they are. Going forward:

- **Conventional, scoped messages**: `feat(postgres): transactional append-sequence
  allocation`, `fix(device): reject sign-count rewind`, `docs(contracts): nonce
  uniqueness invariant`, `refactor(persistence): split postgres.rs (move-only)`.
- **One logical change per commit**, matching the slice discipline the project already
  uses in `NEXT_STEPS.md` — the handoff snapshot's "eighteen implementation slices"
  should have been eighteen findable commits.
- **Tag milestone proofs**: `proof/keycloak-live-2026-06`, `proof/backend-e2e-2026-06`,
  so "this E2E passed" is pinned to an exact tree.
- **Enforcement**: a `commit-msg` hook (committed under `.githooks/` with
  `git config core.hooksPath .githooks`) plus a CI check from section 5 validating the
  message format on PRs.

### Migration path

Immediate; this is policy, not code. Write the convention into a short
`CONTRIBUTING.md` so it survives handoff — consistent with how this repo already
documents every other contract.

### Test impact / risks

None. Cost is a few seconds per commit.

---

## 7. Remove Clinical Placeholder Variants From `FactPayload`

### Problem

`FactPayload` in `src/fen.rs` opens with seven dataless unit variants:

```rust
pub enum FactPayload {
    Measurement,
    Prescription,
    Procedure,
    Diagnosis,
    Document,
    Coverage,
    Claim,
    SubjectCreated { ... },   // real identity payloads start here
    ...
}
```

They carry no data, no workflow constructs them, and their only call sites are label
mapping in `src/persistence/encrypted.rs` (the typed label enum and its string forms
like `"measurement"`) and rendering in `src/fixtures/summary.rs`. They are vestiges of
the broader FEN clinical model (`FEN_Schema-1.pdf`), and they blur the crate's
boundary: an identity crate should not silently accept a `Diagnosis` fact appended
into an identity workflow — today that compiles, persists, and materializes without
complaint.

### Proposed change

Delete the seven variants from this crate, with two preservation steps:

1. **Reserve the label strings.** In the persistence label mapping, document
   `"measurement"`, `"prescription"`, `"procedure"`, `"diagnosis"`, `"document"`,
   `"coverage"`, `"claim"` as reserved-but-unassigned, so a future clinical crate can
   reclaim them without colliding with labels assigned in the meantime. Stored rows
   are unaffected: these variants were never constructed, so no production data can
   contain them (worth verifying with a one-line query against any long-lived dev
   database before deleting).
2. **Document the scope decision.** A short note (this section, or a
   `CLINICAL_SCOPE.md`) recording that clinical facts are future scope and belong in a
   separate crate sharing the graph machinery — episodes, memberships, provenance —
   rather than sharing the identity `FactPayload` enum. When clinical scope becomes
   real, the right shape is for the workspace (section 5) to grow a `fen-clinical`
   crate, not for the identity payload enum to grow clinical variants again.

### Migration path

One small commit: delete the variants, delete the label-enum arms and string mappings,
delete the `fixtures/summary.rs` arms, refresh any golden fixture lines that named
them.

### Test impact

A compile-driven cleanup. If any golden fixture in `tests/golden/` mentions the
removed labels, that is the test catching exactly the kind of drift this change
prevents.

### Risks

Only that some external consumer or stored row already uses these variants. The
dataless shape makes this almost impossible (there is nothing to store *in* them),
and the dev-database query in step 1 settles it.

---

## 8. Key Management: KMS Wrapping, and a Written Nonce-Uniqueness Invariant

This section is two tightly-coupled items: where the AES-256-GCM key lives, and why
the nonce scheme is only safe while a specific invariant holds.

### Problem A — key material loads from env as raw bytes

`src/bin/mobile_onboarding_server.rs` builds the fact-encryption key from
`IDENTITY_MODEL_FACT_KEY_MATERIAL` / `IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX`. The key
therefore sits in the deployment environment next to the database credentials — the
difference between "encrypted facts" and "encrypted facts whose key is stored beside
the data" is the difference this whole encryption boundary exists to create. The
envelope shape already anticipates the fix: `Aes256GcmFactEncryptionMetadataPlanner`
carries a `wrapped_dek_ref: Option<String>` that is currently always pass-through.

### Problem B — the nonce scheme has an unstated catastrophic invariant

`Aes256GcmFactEncryptionMetadataPlanner::metadata_for_fact` derives each 96-bit nonce
deterministically:

```rust
let mut nonce = Vec::with_capacity(12);
nonce.extend_from_slice(&self.nonce_domain);          // 4 bytes, from env
nonce.extend_from_slice(&append_sequence.to_be_bytes()); // 8 bytes
```

Deterministic nonces are a legitimate AES-GCM design **iff** `(key, nonce)` never
repeats. Here that means:

> **Invariant:** for a given `(key_id, nonce_domain)` pair, every fact append sequence
> is used at most once, ever, across all time, all processes, and all copies of the
> database.

Nonce reuse under the same key is not a gradual weakening — it leaks plaintext XOR
relationships and enables authentication-key recovery, breaking confidentiality and
integrity for the affected key. The invariant is currently held by the database's
transactional sequence allocation, but nothing *states* it, and three realistic
operational events violate it silently:

1. **Backup restore.** Restore the database to an earlier point; the sequence counter
   rewinds; new appends re-issue used sequences under the same key and domain.
2. **Second deployment sharing config.** A staging clone or DR replica started with
   the same `key_id`, `nonce_domain`, and an independent (or reset) database
   allocates overlapping sequences.
3. **Manual sequence repair.** An operator "fixing" the workflow-transaction table
   after an incident re-issues sequence numbers.

### Proposed change

**B first — it is cheap and urgent:**

1. Write the invariant into `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md`,
   including the three violation scenarios above and the operational rule they imply:
   *a restored or cloned database must never encrypt under the old `(key_id,
   nonce_domain)` — rotate the key or assign a fresh nonce domain as part of the
   restore runbook.*
2. Enforce it at startup. Persist `(key_id, nonce_domain, max_sequence_seen)` in a
   small operational table; on boot, refuse to start if the configured pair is
   present with a max sequence higher than the database's current allocator state
   (the rewind signature). This converts scenario 1 from silent catastrophe to a
   clear startup error.
3. Enforce it at write time. The encrypted-facts table should carry a uniqueness
   constraint on `(key_id, nonce)` — likely implied today by sequence uniqueness, but
   making it explicit means even a logic bug cannot persist a duplicate nonce.
4. Consider widening the derivation: 4 bytes of domain is small if domains are ever
   assigned per-deployment-instance. A random 4-byte domain has birthday collisions
   around ~77k assignments — fine if domains are rare and registered, dangerous if
   they proliferate. Registering domains in the operational table (step 2) makes
   assignment auditable.

**A — staged KMS adoption, using the hook that already exists:**

1. Define a `KeyProvider` trait in the crypto module with two implementations:
   `EnvKeyProvider` (current behavior, explicitly named for what it is) and a
   KMS-backed provider implementing envelope encryption — a per-deployment (or
   per-rotation-epoch) DEK generated locally, wrapped by a KMS-held KEK
   (`kms:GenerateDataKey` / `Decrypt` shape works for AWS KMS, GCP KMS, or Vault
   transit alike), with the wrapped DEK stored durably and its reference recorded in
   the already-present `wrapped_dek_ref` field of each envelope.
2. Key rotation becomes: new DEK under a new `key_id` (and fresh nonce domain), new
   appends use it, old facts remain readable because each envelope names its
   `key_id`/`wrapped_dek_ref`. Rewrapping (KEK rotation) touches only wrapped-DEK
   rows, never ciphertext. Represent key state (`active`, `retired`,
   `compromised-revoked`) in the operational table so materialization can refuse keys
   in bad states — mirroring how the continuity verification-key registry already
   models key lifecycle.
3. Make production startup refuse `EnvKeyProvider` unless an explicit
   `IDENTITY_MODEL_ALLOW_ENV_KEYS=true` escape hatch is set, so production deployments
   cannot silently run on test-only key config (this exact concern is already listed
   in `NEXT_STEPS.md` item 5).

### Migration path

B.1 (document) and B.3 (constraint) immediately; B.2 (startup guard) as a small
migration plus boot check; A as its own slice behind the existing `production-crypto`
feature, with the live PostgreSQL harness extended to cover wrapped-DEK round-trips.

### Test impact

New tests: boot-time rewind detection (simulate by lowering the allocator under a
recorded max), duplicate-nonce insert rejected by the constraint, rotation
(append under key A, rotate to key B, replay reads both), production-config refusal
of env keys. KMS calls are mocked behind `KeyProvider` in unit tests; an env-gated
live harness (matching the existing pattern in `FEATURE_MATRIX.md`) can cover a real
KMS or a local Vault container.

### Risks

The startup guard adds an operational table that must itself survive restores — store
it in the same database so it rewinds *with* the data, making the guard's comparison
against the allocator self-consistent; the failure mode then degrades to refusing to
start, which is the safe direction. KMS introduces an availability dependency at boot
and on key-unwrap; cache unwrapped DEKs in memory only.

---

## Suggested Execution Order

1. **Section 6** (commit discipline) — immediate, zero cost, makes everything after it auditable.
2. **Section 5, CI half** — one PR, locks in the feature matrix before refactoring starts.
3. **Section 8, part B** (nonce invariant: document, constraint, startup guard) — small, and it protects the crown jewels.
4. **Section 2** (concurrent server) — biggest deployability gap; do before any real traffic.
5. **Section 3 → Section 4** (module splits, then explicit re-exports) — paired refactors over the same lines.
6. **Section 1** (typed IDs, then timestamps) — large but compiler-driven; easier after files are split.
7. **Section 7** (clinical variants) — small cleanup, any time after CI exists.
8. **Section 8, part A** (KMS) — its own slice; ahead of the iOS proof app, per the review.
9. **Section 5, workspace half** — last, once modules and APIs are settled, so paths move once.
