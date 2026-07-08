//! Health-economic fact family for the FEN graph.
//!
//! The identity crate owns subjects, accounts, devices, and the encrypted
//! envelope machinery. This crate owns the health-economic fact family — the
//! durable record of care, cost, payment, denial, benefit use, and financial
//! exposure that the Phoros MVP is built on: employee billing defense
//! (reconciliation, error detection, denial triage, deductible tracking,
//! benefit matching) with employer-sponsored benefits intelligence served
//! only as governed aggregates (FEN_HEALTH_ECON_EXTENSIONS.md).
//!
//! Health-economic facts reference the same `SubjectId` the identity crate
//! owns: the account layer and the state layer are one graph. The `clinical.*`
//! label namespace remains reserved for the future clinical family.

pub mod codec;
pub mod schema;

pub use codec::{HealthEconFactPayloadType, HealthEconPayloadFamily};
pub use schema::{
    AccumulatorSnapshotPayload, AdjudicationOutcome, AdjudicationPayload, AppealPayload,
    AppealStatus, ApproximateDate, BenefitMatchPayload, BillingDiscrepancyPayload, ClaimLineItem,
    ClaimPayload, ClaimType, CollectionStatus, CoveragePayload, DerivedFrom, DiscrepancyKind,
    HealthEconFact, HealthEconFactPayload, Money, PaymentPayload, PreAuthDecisionOutcome,
    PreAuthDecisionPayload, PreAuthRequestPayload, ProviderBillPayload, ProviderRef,
    RecordReceivedPayload, RecordRequestPayload, ReferenceDataRef, RequestedDocument,
    RuleArtifactRef,
};
