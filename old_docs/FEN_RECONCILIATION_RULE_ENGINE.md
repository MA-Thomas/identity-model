# FEN Reconciliation Rule Engine

Design spec for the reconciliation rule engine: the retarget of the D5
completeness-engine machinery called for by `FEN_HEALTH_ECON_EXTENSIONS.md`
(sequencing step 4), from "missing clinical record" to reconciliation rules
that produce `BillingDiscrepancy` facts. This is the analytical core of the
day-one wedge (memo §16): employee billing defense over documents already in
hand — an internal-consistency check, not a price lookup.

The governance shape is not new. `POLICY_ARTIFACT_CONTRACT.md` already pins
it for access decisions:

```text
reviewed policy artifact -> policy evaluation -> access decision cites policy ref
```

The rule engine is the same discipline pointed at a different output:

```text
reviewed rule artifact -> rule evaluation -> BillingDiscrepancy cites rule ref
```

Everything below is a consequence of holding that line plus the Extension C
invariant: every inference-tier fact carries a `DerivedFrom` citing exactly
the facts read and the versioned rule that produced it.

## A — Rule artifacts mirror `PolicyArtifact`; they do not reuse it

A reconciliation rule is a reviewed, versioned governance input with the same
lifecycle shape as a policy artifact — and a deliberately separate type.
Policies gate access; rules produce conclusions. They have different owners,
different review cadences, and different failure modes. Sharing the
discipline is the point; sharing the type would couple the two review
processes forever.

```rust
pub struct ReconciliationRuleArtifact {
    pub id: RuleArtifactRef,            // cited as "rule-id@version"
    pub version: String,
    pub title: String,
    pub description: Option<String>,
    pub status: RuleArtifactStatus,     // Draft | Active | Retired
    pub effective_period: Option<TimeInterval>,
    pub review: Option<RuleReview>,     // reviewed_by / reviewed_at / notes
    pub definition: ReconciliationRuleDefinition,
}
```

Rule artifacts are plan-shaped, not person-shaped — there is no `SubjectId`
to anchor them to. By the Extension E argument they are **reference data, not
facts**: an operational table versioned like `PolicyArtifact`, in-memory
first, PostgreSQL adapter after, exactly the trajectory every other boundary
in this workspace has followed. Findings cite `rule-id@version`; the cited
version is frozen the moment a production finding references it. Editing a
rule means activating a new version and retiring the old one, never mutating
in place.

## B — Rule definitions are a closed, typed enum — not a DSL

One variant per `DiscrepancyKind` mechanism, with parameters in the
definition so the version captures them:

```rust
pub enum ReconciliationRuleDefinition {
    /// ProviderBill.amount_due vs the matched Adjudication's
    /// patient_responsibility, beyond tolerance.
    BillVsEobMismatch { tolerance: Option<Money> },
    /// The same service billed more than once inside the window.
    DuplicateCharge { match_window_days: u32 },
    /// Billed above the adjudication's allowed amount.
    AboveAllowedAmount { tolerance: Option<Money> },
    /// A denial whose CARC reason code is on the reviewed appealable list.
    AppealableDenial { appealable_carc_codes: Vec<String> },
}
```

A typed enum is what makes rule review meaningful: a reviewer approves a
specific, readable mechanism with specific parameters, the compiler forces
every rule to have an evaluator, and golden fixtures pin each variant's
behavior. An expression DSL on day one would trade all three away for
flexibility nobody has asked for. If rules multiply beyond what variants
bear, a DSL can be introduced *behind* this enum later.

`AppealableDenial` is where the `Carc` coding system addition (Extension B)
pays off: the appealable list is CARC codes, reviewed as part of the rule
artifact, versioned with it.

Deliberately absent: `BenefitMatch`. It is the one inference that needs the
versioned benefit-catalog reference-data store (Extension E), so it lands
with that store, citing `catalog_ref` in its `DerivedFrom`. The four
variants above need only facts.

## C — The engine is a pure function behind the materialization boundary

```rust
pub fn evaluate_reconciliation_rules(
    rules: &[ActiveReconciliationRule],       // resolved, active-versioned
    facts: &[HealthEconFact],                  // policy-gated materialized
    as_of: &Timestamp,
) -> Vec<ReconciliationFinding>;
```

Deterministic, synchronous, no I/O — the same shape as every other piece of
domain logic in this workspace. The engine never sees ciphertext, envelopes,
or rows:

- **Input** is the subject's replayed, policy-gated materialized
  health-economic facts. Rule evaluation is a legitimate materialization
  with a normal audit trail; it gets no special read path.
- **Output** is `ReconciliationFinding` values — candidate
  `BillingDiscrepancy` payloads plus their `DerivedFrom { fact_ids, rule_ref,
  catalog_ref: None }` where `fact_ids` are exactly the facts compared, no
  more. Findings become facts only by going back through the normal encrypted
  append path as `Inference`-tier facts (`Provenance { tier: Inference,
  author: AuthorType::System, .. }`).

The audit chain for a conclusion therefore lives entirely inside the fact
graph — the same auditability discipline as materialization decisions — and
the engine itself stays trivially testable: fixtures in, findings out.

## D — Deterministic finding identity

Re-evaluation must be idempotent: re-running rules over unchanged inputs must
not append duplicate `BillingDiscrepancy` facts. The finding's `FactId` is
derived deterministically from the finding's semantic identity:

```text
finding_fact_id = H(subject_id, rule_ref /* id@version */, kind,
                    sorted(derived_from.fact_ids))
```

Consequences, all intended:

- same inputs + same rule version → same `FactId`, and the envelope store's
  existing duplicate-fact-id rejection dedupes the re-append for free;
- a new rule version over the same inputs is a *new* finding — conclusions
  are versioned, exactly as Extension C requires;
- changed inputs (a corrected bill arrives) produce a new finding that
  supersedes the old one via `FactStatus::Superseded`.

Two consequences for shared identity-crate types, both additive but both on
frozen persisted enums, so they carry label-freeze review weight:

- `SupersessionReason` has no fitting variant for "a newer evaluation of the
  same rule over changed inputs replaced this conclusion"; add one (e.g.
  `RuleReEvaluation`) with the same care as any persisted label.
- The hash function and field ordering behind the derived `FactId` become
  part of the durable contract the moment the first production finding is
  appended: document them next to the implementation and pin them with a
  golden test, like the AAD canonicalization.

This identity scheme is the piece to review hardest: it silently defines
what "the same finding" *means* across rule versions and corrected inputs.

## E — Fact matching is explicit, auditable, and conservative

Deciding *which* `ProviderBill` corresponds to *which* `Adjudication` is
harder than any of the arithmetic, and it is where a false positive becomes a
false accusation against a provider — the one failure mode billing defense
cannot afford. Matching is therefore an explicit engine concept, not logic
buried inside each rule variant:

```rust
pub enum FactMatchBasis {
    /// Both facts reference the same claim: ProviderBill.related_claim
    /// agrees with Adjudication.claim_ref (same ExternalSystem + resource).
    SharedClaimRef,
    // Deferred: ProviderNpiAndServicePeriod, service-code overlap tiers —
    // fuzzy matching needs its own review before it can accuse anyone.
}
```

Phase 1 emits findings **only on `SharedClaimRef` matches** — the
evidence-anchored key that already exists in the schema. The match basis is
recorded in the finding (feeding the human-readable `summary`, with the
matched facts in `derived_from.fact_ids`), so every finding can explain not
just what disagreed but why the engine believed the two documents describe
the same care. Unmatched bills are not discrepancies; they are simply
unmatched, and surfacing them is a read-model concern, not a rule finding.

## F — Triggering comes with ingestion, not before

Per the sequencing in `FEN_HEALTH_ECON_EXTENSIONS.md`, the engine lands
before any ingestion path exists, so triggering is deliberately out of scope
for the first slice. When ingestion lands:

- evaluation runs subject-scoped after each ingestion transaction commits —
  no batch scheduler;
- activating a new rule version needs no migration machinery: because the
  engine is a pure function of replayed facts, full re-evaluation is just
  replay + evaluate, and finding identity (D) makes the re-append safe.

## MVP restatement

The engine this spec serves: given one subject's materialized billing facts
and a reviewed set of active rules, deterministically produce the
`BillingDiscrepancy` facts behind the reconciliation view and denial-triage
flags (memo §16) — every finding citing its rule version and input facts,
appended through the same encrypted, policy-gated path as every other fact.
No prices fetched, no providers accused on fuzzy matches, no conclusion
without provenance.

## Sequencing

1. `ReconciliationRuleArtifact` types, `RuleArtifactStatus` lifecycle, and
   the in-memory rule store, with the `rule-id@version` citation shape
   pinned by tests (mirrors the policy-artifact contract).
2. The pure engine: `SharedClaimRef` matching, the four rule variants,
   `ReconciliationFinding`, and golden fixtures per variant (hit, miss,
   tolerance edge, unmatched-bill non-finding).
3. Deterministic finding identity: the hash contract, its golden pin, the
   `SupersessionReason` addition, and supersession-on-changed-inputs tests.
4. Append integration: findings → `Inference`-tier encrypted facts through
   the existing in-memory facade (the PostgreSQL path is already wired for
   `health_econ.*` labels).
5. Durable rule storage (PostgreSQL, versioned like policy artifacts) and —
   with the ingestion work — post-ingest subject-scoped triggering.

Employer-side aggregate governance stays deferred exactly as in
`FEN_HEALTH_ECON_EXTENSIONS.md`; nothing here crosses the materialization
boundary in aggregate form.
