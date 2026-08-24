//! The health-economic subset of the FEN schema (`FEN_Schema.tex` +
//! FEN_HEALTH_ECON_EXTENSIONS.md).
//!
//! This is the billing-defense slice: payer-adjudicated claims state,
//! provider-side balances, prior authorization, appeals, accumulator
//! position, benefit matching, and reconciliation findings, plus the
//! administrative record-request tracker (which dogfoods the append-only
//! model instead of getting a mutable status table). Clinical payloads
//! (`Diagnosis`, `LabResult`, ...), `Narrative*` entities, and
//! `DecisionPoint` belong to the future clinical family and are intentionally
//! absent.
//!
//! Health-economic facts reference the *same* [`SubjectId`] used by identity
//! and reuse `fen-core` value types (`TemporalAnchor`, `CodedValue`,
//! `CodingSystem`, `ExternalRef`, `Provenance`, `Author`, `TimeInterval`).
//! Inference-tier payloads carry a [`DerivedFrom`] citing the facts and rule
//! versions that produced them: provenance for conclusions, not just
//! documents. Plan-shaped objects (benefit catalogs) are versioned reference
//! data *outside* the fact graph, cited via [`ReferenceDataRef`].

use fen_core::{
    CodedValue, ExternalRef, FactId, FactStatus, Provenance, SubjectId, TemporalAnchor,
    TimeInterval,
};

/// A health-economic fact: this family's analogue of an identity fact,
/// `Fact`, with the same envelope-relevant fields (id, subject, temporal
/// anchor, status, provenance, external refs) so it can flow through the
/// shared encrypted envelope store unchanged. Only
/// [`HealthEconFact::payload`] differs from the identity fact shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthEconFact {
    pub id: FactId,
    pub subject_id: SubjectId,
    pub occurred_at: TemporalAnchor,
    pub code: Option<CodedValue>,
    pub payload: HealthEconFactPayload,
    pub status: FactStatus,
    pub provenance: Provenance,
    pub external_refs: Vec<ExternalRef>,
}

/// The closed health-economic payload family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthEconFactPayload {
    Claim(ClaimPayload),
    Adjudication(AdjudicationPayload),
    Payment(PaymentPayload),
    Coverage(CoveragePayload),
    PreAuthRequest(PreAuthRequestPayload),
    PreAuthDecision(PreAuthDecisionPayload),
    Appeal(AppealPayload),
    ProviderBill(ProviderBillPayload),
    AccumulatorSnapshot(AccumulatorSnapshotPayload),
    BenefitMatch(BenefitMatchPayload),
    BillingDiscrepancy(BillingDiscrepancyPayload),
    RecordRequest(RecordRequestPayload),
    RecordReceived(RecordReceivedPayload),
}

// ---------------------------------------------------------------------------
// Value types owned by the health-economic family
// ---------------------------------------------------------------------------

/// A monetary amount in minor currency units (e.g. cents), avoiding floating
/// point so adjudication arithmetic stays exact and canonical rendering is
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    pub currency: String,
    pub amount_minor_units: i64,
}

impl Money {
    pub fn new(currency: impl Into<String>, amount_minor_units: i64) -> Self {
        Self {
            currency: currency.into(),
            amount_minor_units,
        }
    }
}

/// A date known only to some precision. Claims feeds routinely carry
/// year-month or year-only dates, and the schema records that imprecision
/// rather than inventing a false day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproximateDate {
    /// A full calendar date (`YYYY-MM-DD`, ISO-8601).
    Exact(String),
    /// A year and month (`1..=12`), day unknown.
    YearMonth { year: i32, month: u8 },
    /// A year only.
    Year(i32),
}

/// A reference to a billing/servicing provider. `npi` is the US National
/// Provider Identifier when present; `reference` links to the source system's
/// provider resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRef {
    pub npi: Option<String>,
    pub display: Option<String>,
    pub reference: Option<ExternalRef>,
}

/// A versioned reference to a reconciliation/matching rule artifact, following
/// the `PolicyRef` convention (e.g. `"eob-bill-reconciliation@v3"`). Rules are
/// versioned artifacts, not code constants: every inference cites the rule
/// version that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleArtifactRef(pub String);

impl RuleArtifactRef {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// A versioned handle to plan-shaped reference data living *outside* the fact
/// graph (benefit catalogs, plan documents, vendor rosters). The fact graph is
/// person-shaped; employer-scoped objects are operational reference data,
/// versioned like `PolicyArtifact`, and facts cite them by id + version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceDataRef {
    pub id: String,
    pub version: String,
}

/// Provenance for conclusions: the facts an inference read, the versioned
/// rule that produced it, and (where applicable) the reference-data version
/// it matched against. Required on every `Inference`-tier payload
/// ([`BillingDiscrepancyPayload`], [`BenefitMatchPayload`], Phoros-computed
/// [`AccumulatorSnapshotPayload`]), keeping the audit chain inside the fact
/// graph — the same auditability discipline as materialization decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedFrom {
    pub fact_ids: Vec<FactId>,
    pub rule_ref: RuleArtifactRef,
    pub catalog_ref: Option<ReferenceDataRef>,
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPayload {
    pub claim_type: ClaimType,
    pub billable_period: Option<TimeInterval>,
    pub billing_provider: Option<ProviderRef>,
    /// Diagnosis codes (typically ICD-10) supporting the claim.
    pub diagnoses: Vec<CodedValue>,
    pub line_items: Vec<ClaimLineItem>,
    pub total_charge: Option<Money>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimType {
    Professional,
    Institutional,
    Pharmacy,
    Dental,
    Vision,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimLineItem {
    pub sequence: u32,
    /// Procedure/service/product code (CPT, HCPCS, or NDC).
    pub service: CodedValue,
    pub serviced_period: Option<TimeInterval>,
    pub quantity: Option<u32>,
    pub charge: Option<Money>,
}

// ---------------------------------------------------------------------------
// Adjudication + Payment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjudicationPayload {
    /// The claim this adjudication resolves.
    pub claim_ref: ExternalRef,
    pub outcome: AdjudicationOutcome,
    pub allowed_amount: Option<Money>,
    pub paid_amount: Option<Money>,
    pub patient_responsibility: Option<Money>,
    /// Denial/adjustment reason (typically a CARC code).
    pub denial_reason: Option<CodedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationOutcome {
    Paid,
    Denied,
    Partial,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPayload {
    pub claim_ref: Option<ExternalRef>,
    pub amount: Money,
    pub paid_date: Option<ApproximateDate>,
    pub payment_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// Coverage (with plan design, for deductible/OOP tracking)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveragePayload {
    pub payer: String,
    pub member_id: String,
    pub plan: Option<String>,
    /// Subscriber relationship (e.g. "self", "spouse", "child").
    pub relationship: Option<String>,
    pub coverage_period: Option<TimeInterval>,
    /// Individual deductible under this plan; deductible tracking is
    /// arithmetic of [`AccumulatorSnapshotPayload`] against these.
    pub deductible: Option<Money>,
    /// Individual out-of-pocket maximum under this plan.
    pub oop_max: Option<Money>,
}

// ---------------------------------------------------------------------------
// Prior authorization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthRequestPayload {
    pub requested_service: CodedValue,
    pub requested_period: Option<TimeInterval>,
    pub requesting_provider: Option<ProviderRef>,
    pub diagnoses: Vec<CodedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthDecisionPayload {
    /// The [`HealthEconFactPayload::PreAuthRequest`] fact this decides.
    pub request_fact_id: FactId,
    pub decision: PreAuthDecisionOutcome,
    pub authorized_period: Option<TimeInterval>,
    pub decision_reason: Option<CodedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreAuthDecisionOutcome {
    Approved,
    Denied,
    Partial,
    Pended,
}

// ---------------------------------------------------------------------------
// Appeal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealPayload {
    /// The adjudication/decision fact being contested.
    pub contested_fact_id: FactId,
    pub status: AppealStatus,
    pub filed_date: Option<ApproximateDate>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppealStatus {
    Filed,
    UnderReview,
    Upheld,
    Overturned,
    Withdrawn,
}

// ---------------------------------------------------------------------------
// Provider bill (the member-facing ask the payer never sees)
// ---------------------------------------------------------------------------

/// What the provider is still asking the member to pay. The payer sees
/// allowed/paid/denied/assigned; only this payload sees the statement
/// balance, payment-plan and collection status, and cash-pay charges.
/// Reconciliation needs both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBillPayload {
    pub billing_provider: ProviderRef,
    /// The claim/EOB this bill corresponds to, when it can be linked.
    pub related_claim: Option<ExternalRef>,
    pub statement_date: Option<ApproximateDate>,
    pub amount_due: Money,
    pub collection_status: Option<CollectionStatus>,
    /// True when the charge never went through insurance.
    pub cash_pay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionStatus {
    Current,
    PastDue,
    PaymentPlan,
    Collections,
    WrittenOff,
    Other(String),
}

// ---------------------------------------------------------------------------
// Accumulator snapshot (deductible / out-of-pocket position)
// ---------------------------------------------------------------------------

/// Deductible / out-of-pocket position at a point in time. Two legitimate
/// provenance tiers: payer-reported (EOBs carry deductible application;
/// `derived_from: None`) and Phoros-computed (`Inference` tier; `derived_from`
/// required, citing the adjudication facts summed). Readers prefer
/// payer-reported where fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatorSnapshotPayload {
    /// The [`HealthEconFactPayload::Coverage`] fact this position is measured
    /// against.
    pub coverage_fact_id: Option<FactId>,
    pub as_of: ApproximateDate,
    pub deductible_applied: Option<Money>,
    pub oop_applied: Option<Money>,
    pub derived_from: Option<DerivedFrom>,
}

// ---------------------------------------------------------------------------
// Benefit match (inference against versioned catalog reference data)
// ---------------------------------------------------------------------------

/// A subject-scoped inference that a benefit program applies, pushed to the
/// employee rather than searched for. The catalog itself is plan-shaped
/// reference data outside the graph; `program` cites the exact catalog entry
/// and version matched, and `derived_from` cites the billing facts that
/// triggered the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenefitMatchPayload {
    pub program: ReferenceDataRef,
    pub rationale: Option<String>,
    pub derived_from: DerivedFrom,
}

// ---------------------------------------------------------------------------
// Billing discrepancy (reconciliation findings)
// ---------------------------------------------------------------------------

/// An inference-tier reconciliation finding: an internal-consistency check on
/// documents in hand, not a price lookup. Always cites the facts compared and
/// the rule version that flagged them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingDiscrepancyPayload {
    pub kind: DiscrepancyKind,
    /// What the evidence says the member should owe.
    pub expected: Option<Money>,
    /// What the member is actually being asked to pay.
    pub observed: Option<Money>,
    pub summary: Option<String>,
    pub derived_from: DerivedFrom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscrepancyKind {
    /// Provider bill disagrees with the EOB's patient responsibility.
    BillVsEobMismatch,
    DuplicateCharge,
    /// Billed above the plan's allowed amount.
    AboveAllowedAmount,
    /// A denial that reconciliation rules flag as worth appealing.
    AppealableDenial,
    Other(String),
}

// ---------------------------------------------------------------------------
// Record-request tracker (administrative facts)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRequestPayload {
    pub target_provider: ProviderRef,
    pub requested_document: RequestedDocument,
    pub reason: Option<String>,
    pub requested_period: Option<TimeInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedDocument {
    // Billing documents — the day-one wedge.
    ItemizedBill,
    Eob,
    DenialLetter,
    // Clinical documents — stage two (appeal-packet assembly).
    OperativeNote,
    PathologyReport,
    ImagingReport,
    DischargeSummary,
    ProgressNote,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordReceivedPayload {
    /// The [`HealthEconFactPayload::RecordRequest`] fact this fulfills.
    pub request_fact_id: FactId,
    pub received_document_ref: ExternalRef,
    pub received_date: Option<ApproximateDate>,
}
