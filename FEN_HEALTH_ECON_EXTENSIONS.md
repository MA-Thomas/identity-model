# FEN Schema Extensions: the Health-Economic Fact Family

Design spec for aligning the second fact family with the Phoros GTM strategy
(`phoros_benefits_intelligence_memo_narrative.docx`, 2026-07-07). The family is
renamed `fen-clinical` → `fen-health-econ`: the memo's core object is
*health-economic state* — the durable record of care, cost, payment, denial,
benefit use, and financial exposure (memo §14) — not clinical state, which
arrives later as its own family.

This is a clean break. Nothing is persisted in production, no crate depends on
`fen-clinical`, and the `clinical.*` labels exist only in tests, so the rename
carries no migration. The discipline that motivated the compatibility question
survives: once a payload label lands in a production AAD it is frozen forever.
We rename precisely because that clock has not started. The `clinical.*` label
namespace returns to reserved status for the future clinical family.

The architecture is unchanged. `fen-health-econ` remains a sibling
`PayloadFamily`: same `SubjectId`, `FactId`, `TemporalAnchor`, `FactStatus`,
same encrypted envelope, same policy-gated materialization. Consistency with
the Rust FEN schema is guaranteed so long as this family only *adds* payload
variants and value types and never redefines the shared envelope-relevant
fields. Five extensions follow, ordered by how deep they cut.

## A — Provenance tiers (shared-type change; the only one that crosses the trust boundary)

Memo §16: every ingestion event preserves the raw artifact, a content hash,
receipt time, source system, authorization basis, and a source→fact field
mapping; every fact carries a provenance tier. This is a graph-wide invariant
— identity facts benefit from tier + hash as much as billing facts — so it
extends the shared `Provenance` struct in `identity-model` rather than living
as a family value type.

```rust
pub struct Provenance {
    pub source_system: Option<String>,
    pub source_document: Option<DocumentId>,
    pub imported_at: Timestamp,
    pub author: Author,
    // new:
    pub tier: ProvenanceTier,
    pub content_hash: Option<ContentHash>,      // hash of the raw source artifact
    pub authorization_basis: Option<AuthorizationBasis>,
}

pub enum ProvenanceTier {
    ApiSourced,        // payer/provider API pull, employee-directed
    RecordsRequest,    // HIPAA right-of-access delivery
    PortalExport,      // member-portal download
    EmployeeUpload,    // bills, EOBs, denial letters the employee already holds
    Inference,         // Phoros-derived; MUST carry DerivedFrom (see C)
}

pub enum AuthorizationBasis {
    HipaaRightOfAccess,
    PatientDirection,        // patient-directed sharing, memo §5
    EmployerPlanContext,     // benefit catalog handed over at signing
    SelfHeld,                // material already the individual's
}
```

Raw artifacts themselves (the API resource, the PDF) live outside the fact
graph in an artifact store keyed by `content_hash`; the fact references, never
embeds. This touches the most sensitive module in the identity crate: it ships
as its own reviewed commit with the full FEATURE_MATRIX run, before anything
builds on it. Existing identity fact constructors default to
`tier: ApiSourced`/`None`s or get explicit values — decided in review.

## B — CodingSystem additions (trivial, required)

Memo §7 names four billing code systems; `CodingSystem` has two of them. Add:

```rust
pub enum CodingSystem {
    Snomed, Icd10, Loinc, RxNorm, Cpt, Local,
    // new:
    Hcpcs,   // supplies/services/procedures billing codes
    Ndc,     // drug products
    Carc,    // claim adjustment / denial reason codes (X12 CARC), for denial_reason
}
```

`ExternalSystem` gains `PayerPortal` and `Edi` variants for provenance-accurate
external refs on portal exports and 835/837-derived data.

## C — DerivedFrom: provenance for conclusions (the one genuinely new idea)

The memo requires that inferences point to the facts and rule versions that
produced them. Documents have provenance; conclusions currently do not — the
envelope has no seam for it. Add one family value type, reusing the
`PolicyRef`-style versioned-artifact pattern:

```rust
pub struct DerivedFrom {
    pub fact_ids: Vec<FactId>,          // the facts the inference read
    pub rule_ref: RuleArtifactRef,      // versioned rule that produced it
    pub catalog_ref: Option<ReferenceDataRef>,  // e.g. benefit catalog version (see E)
}
```

Every `Inference`-tier fact (`BillingDiscrepancy`, `BenefitMatch`,
Phoros-computed `AccumulatorSnapshot`) carries a `DerivedFrom`. This keeps the
audit chain inside the fact graph — the same auditability discipline as
materialization decisions — instead of in application logic.

## D — Family payload variants (additive; no shared-schema change)

Label namespace: `health_econ.*`. Carried over from the claims spine with new
labels: `Claim`, `Adjudication`, `Payment`, `PreAuthRequest`, `PreAuthDecision`,
`Appeal`, `RecordRequest`, `RecordReceived`. Two carried payloads change shape:

- `Coverage` gains plan design: `deductible: Option<Money>`,
  `oop_max: Option<Money>`, family-tier amounts as needed. Deductible tracking
  is arithmetic against these.
- `RecordRequestPayload::RequestedDocument` widens beyond clinical documents:
  add `ItemizedBill`, `Eob`, `DenialLetter`. (Clinical note variants remain;
  they become stage-two.)

New variants, the day-one wedge:

- `ProviderBill` — what the provider is still asking the member to pay:
  statement balance, payment-plan status, collection status, cash-pay charges.
  The payer sees allowed/paid/denied; only this payload sees the member-facing
  ask. Reconciliation needs both sides (memo §16).
- `AccumulatorSnapshot` — deductible / out-of-pocket position at a point in
  time. Two legitimate tiers: payer-reported (EOBs carry deductible
  application; tier `ApiSourced`) and Phoros-computed (tier `Inference` +
  `DerivedFrom`). The schema allows both; readers prefer payer-reported where
  fresh.
- `BenefitMatch` — subject-scoped inference that a benefit program applies:
  `program: ReferenceDataRef` (catalog entry + version), `derived_from:
  DerivedFrom` citing the billing facts that triggered the match.
- `BillingDiscrepancy` — inference-tier reconciliation finding:
  `kind: DiscrepancyKind` (`BillVsEobMismatch`, `DuplicateCharge`,
  `AboveAllowedAmount`, `AppealableDenial`, `Other(String)`), the contested
  amounts, and `DerivedFrom` citing the facts compared and the rule version.

The completeness engine's versioned-rule machinery is retargeted, not
discarded: from "missing clinical record" to reconciliation rules producing
`BillingDiscrepancy` facts. Missing-record detection demotes to stage two.

## E — Versioned reference data: plan-shaped objects stay out of the graph

The fact graph is person-shaped — every envelope requires a `SubjectId`. A
benefit catalog is plan-shaped: employer-scoped, not patient-level data,
nothing to anchor it to. Precedent already exists: OAuth tokens are "secrets,
not facts" and live in an operational table. Benefit catalogs are "reference
data, not facts": an operational table, versioned like `PolicyArtifact`, with
stable `ReferenceDataRef { id, version }` handles so a `BenefitMatch` can cite
exactly which catalog version it matched against. Same pattern serves future
plan-shaped objects (plan documents, vendor rosters, price references).

## MVP restatement

The product this schema serves (memo §16): employee billing defense with
employer-sponsored benefits intelligence. Employee-side: reconciliation view,
error flags (`BillingDiscrepancy`), denial triage and appeal (`Adjudication` +
`Appeal`), deductible tracking (`AccumulatorSnapshot` vs `Coverage` plan
design), benefit matching (`BenefitMatch`). Employer-side: aggregate-only
queries over the code-occurrence index, never crossing the materialization
boundary. The timeline remains the substrate; the missing-record report is no
longer the headline.

## Sequencing

1. Extension A as its own reviewed commit in `identity-model` (full feature matrix).
2. B alongside (small, shared-type, same review).
3. Crate rename + label namespace + C/D/E in `fen-health-econ`.
4. Reconciliation rule engine (retargeted D5 machinery), then ingestion
   (payer API + employee upload paths), then read models.

Employer-side aggregate governance (cell suppression, differencing protection,
query logging — memo §5/§12) is deliberately absent here: it is a query-layer
concern above the schema, deferred with its hook (the code-occurrence index)
already in place.
