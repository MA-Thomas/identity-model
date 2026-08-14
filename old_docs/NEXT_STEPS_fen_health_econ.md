# Next Steps: fen-health-econ

Scoped handoff for the health-economic fact family and the reconciliation
rule engine. The workspace-wide snapshot stays in `NEXT_STEPS.md`; this file
covers the `fen-health-econ` crate and the shared-crate changes it carries.

## Handoff Snapshot

As of 2026-07-08, the crate has these implementation slices, all tested:

- the health-economic schema (`FEN_HEALTH_ECON_EXTENSIONS.md` C/D/E): thirteen
  payload variants under the frozen `health_econ.*` label namespace, family
  value types (`Money`, `ApproximateDate`, `ProviderRef`, `RuleArtifactRef`,
  `ReferenceDataRef`, `DerivedFrom`), and the `HealthEconPayloadFamily` codec
  flowing through the identity crate's shared encrypted envelope machinery
- PostgreSQL label wiring through the shared payload-agnostic envelope table,
  with frozen-label pinning, cross-family rejection tests, and an env-gated
  live mixed-family replay harness (`tests/postgres_label_wiring.rs`)
- reconciliation rule artifacts (`FEN_RECONCILIATION_RULE_ENGINE.md` §A/§B,
  step 1): `ReconciliationRuleArtifact` mirroring `PolicyArtifact` as a
  deliberately separate type, the closed four-variant
  `ReconciliationRuleDefinition` enum (not a DSL), Draft→Active→Retired
  lifecycle with review-recording activation, the `rule-id@version` citation
  shape pinned by tests, and an in-memory store with no in-place-edit API
  (`src/rules.rs`, `tests/reconciliation_rule_store.rs`)
- the pure rule engine (§C/§E, step 2): deterministic, synchronous, no I/O;
  `SharedClaimRef`-only bill↔adjudication matching that skips unmatched,
  ambiguous, and cash-pay bills; superseded facts ignored; currency
  mismatches and undated services never compared; golden fixtures per
  variant — hit, miss, tolerance edge, unmatched-bill non-finding
  (`src/reconcile.rs`, `tests/reconciliation_rule_engine.rs`)
- deterministic finding identity (§D, step 3): SHA-256 over a domain-tagged,
  length-prefixed preimage, rendered `finding-<hex>`, golden-pinned; frozen
  discrepancy-kind identity labels; identity distinguishes rule version,
  kind, inputs, and subject while ignoring cited-fact order
  (`src/finding_identity.rs`, `tests/finding_identity.rs`)
- append integration (§C, step 4): `finding_to_inference_fact` (Inference
  tier, System author, no authorization basis — a derivation is not an
  ingestion) and `re_evaluation_supersession`; re-evaluation over unchanged
  inputs dedupes through the envelope store's existing duplicate-fact-id
  rejection; corrected inputs append a new finding and the old one takes
  `FactStatus::Superseded { reason: RuleReEvaluation }`
  (`src/append.rs`, `tests/reconciliation_append_roundtrip.rs`)
- durable rule storage (step 5): migration
  `0006_health_econ_reconciliation_rule_artifacts` in the shared identity
  migration registry (normalized definition columns, per-variant CHECK
  constraints, TEXT timestamps, `BIGSERIAL` insertion order) and
  `PostgresReconciliationRuleStore` preserving the in-memory store's error
  vocabulary and semantics — transactional `FOR UPDATE` lifecycle gates,
  effective-window gating in Rust, malformed rows as hard errors — with an
  env-gated live harness (`src/postgres.rs`, `tests/postgres_rule_store.rs`)

Shared identity-crate changes carried by this work, both additive:

- `SupersessionReason::RuleReEvaluation` with the frozen persisted label
  `rule_re_evaluation` in both the AAD canonicalization
  (`persistence/encrypted.rs`) and the PostgreSQL label mapping
  (`persistence/postgres/labels.rs`); the label is pinned through the AAD in
  the append roundtrip test. Commit this as its own reviewed slice.
- `InMemoryEncryptedFactRepository` generalized to
  `InMemoryEncryptedFactEnvelopeRepository<T>` exactly as the envelope
  itself was, with the identity-family alias keeping the public API
  unchanged.

All tests pass, including the env-gated live PostgreSQL harnesses (label
wiring and rule store) against a disposable local PostgreSQL.

## Durable contracts owned by this crate

Frozen the moment a production row/fact carries them:

- the `health_econ.*` payload-type labels (pinned in
  `tests/postgres_label_wiring.rs`)
- the finding-identity encoding: SHA-256; domain tag
  `fen.health_econ.reconciliation_finding.fact_id.v1`; length-prefixed
  fields (8-byte BE length ‖ UTF-8 bytes) in order — tag, subject ID,
  versioned rule ref, kind identity label, decimal fact-id count, each cited
  fact ID sorted ascending by byte order; rendering `finding-` + lowercase
  hex (golden-pinned in `tests/finding_identity.rs`). Changing any of this
  requires a new domain-tag version and label-freeze review weight.
- the discrepancy-kind identity labels (`bill_vs_eob_mismatch`,
  `duplicate_charge`, `above_allowed_amount`, `appealable_denial`,
  `other:<label>`), reused as the PostgreSQL `definition_type` labels
- the `rule-id@version` citation shape and the historical stability of any
  cited `(rule_id, version)` pair
- the `rule_re_evaluation` supersession-reason label (shared crate)

## Testable Next Workstreams, in priority order

1. **Ingestion.** The `fhir-ingest` and `claims-ingest` features are declared
   in `Cargo.toml` but unimplemented. Payer API path first (FHIR EOB/Coverage
   → `Claim`/`Adjudication`/`Coverage`/payer-reported `AccumulatorSnapshot`
   facts with `ApiSourced` provenance, content hashes, authorization basis),
   then the employee upload path (`ProviderBill`, EOBs, denial letters as
   `EmployeeUpload`-tier facts; raw artifacts to an artifact store keyed by
   `content_hash`, outside the fact graph).
2. **Post-ingest triggering** (deliberately deferred from step 5): run
   subject-scoped evaluation after each ingestion transaction commits — no
   batch scheduler. Because the engine is a pure function of replayed facts,
   activating a new rule version is replay + evaluate, and finding identity
   makes the re-append safe. This is also where the supersession write path
   gets wired: the re-evaluation transaction appends the new finding and
   refreshes the superseded one.
3. **Read models.** The reconciliation view and denial-triage flags (memo
   §16), plus surfacing unmatched bills — explicitly a read-model concern,
   never a rule finding.
4. **Versioned benefit-catalog reference data (Extension E)** and the
   deferred `BenefitMatch` rule variant, citing `catalog_ref` in
   `DerivedFrom`. Follow the rule-store trajectory: typed artifacts,
   in-memory store, PostgreSQL adapter.
5. **Fuzzy match bases** (`ProviderNpiAndServicePeriod`, service-code overlap
   tiers) only behind their own review — a false positive is a false
   accusation against a provider.

Employer-side aggregate governance (cell suppression, differencing
protection, query logging) stays deferred exactly as in
`FEN_HEALTH_ECON_EXTENSIONS.md`; nothing crosses the materialization
boundary in aggregate form.

## Running the crate's checks

```sh
cargo test -p fen-health-econ
cargo test -p fen-health-econ --features postgres-adapter

# Live harnesses (disposable local PostgreSQL):
IDENTITY_MODEL_POSTGRES_URL="postgres://postgres:dev@127.0.0.1:5432/postgres" \
cargo test -p fen-health-econ --features postgres-adapter live -- --nocapture
```

Shared-crate changes take the full `FEATURE_MATRIX.md` run.

Do not treat payer APIs, uploaded documents, or provider portals as truth:
they are evidence. The engine never fetches prices, never accuses on fuzzy
matches, and never emits a conclusion without `DerivedFrom` provenance.
