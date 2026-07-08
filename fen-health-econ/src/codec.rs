//! Health-economic [`PayloadFamily`] implementation: the `health_econ.*`
//! payload-type label namespace plus the fact/plaintext mapping the shared
//! encrypted envelope store needs (FEN_HEALTH_ECON_EXTENSIONS.md D).
//!
//! No new envelope tables and no schema fork: the identity crate's envelope
//! machinery (`encrypt_fact_envelope_in_family`,
//! `materialize_encrypted_fact_in_family`, the AAD canonicalization, and the
//! in-memory codec `InMemoryEncryptedFactPlaintextCodec<HealthEconFactPayload>`)
//! carries health-economic facts unchanged. The `clinical.*` namespace stays
//! reserved for the future clinical family.

use identity_model::persistence::{
    EncryptedFactPlaintextOf, PayloadFamily, StoredEncryptedFactEnvelope,
};
use identity_model::{FactId, FactStatus, SubjectId, TemporalAnchor};

use crate::schema::{HealthEconFact, HealthEconFactPayload};

/// Closed payload-type label enum for the health-economic family, mirroring
/// the identity crate's `FactPayloadType`. Stable string labels are the
/// `health_econ.*` namespace; they appear in stored envelope rows and in the
/// authenticated associated data, so they must never change once persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEconFactPayloadType {
    Claim,
    Adjudication,
    Payment,
    Coverage,
    PreAuthRequest,
    PreAuthDecision,
    Appeal,
    ProviderBill,
    AccumulatorSnapshot,
    BenefitMatch,
    BillingDiscrepancy,
    RecordRequest,
    RecordReceived,
}

impl HealthEconFactPayloadType {
    /// Every variant of this closed label enum, in declaration order.
    ///
    /// Keep in sync with the enum; the label-freeze test in
    /// `tests/postgres_label_wiring.rs` pins the length and label round-trip
    /// so an added variant cannot silently miss this list.
    pub const ALL: &'static [Self] = &[
        Self::Claim,
        Self::Adjudication,
        Self::Payment,
        Self::Coverage,
        Self::PreAuthRequest,
        Self::PreAuthDecision,
        Self::Appeal,
        Self::ProviderBill,
        Self::AccumulatorSnapshot,
        Self::BenefitMatch,
        Self::BillingDiscrepancy,
        Self::RecordRequest,
        Self::RecordReceived,
    ];

    pub fn from_payload(payload: &HealthEconFactPayload) -> Self {
        match payload {
            HealthEconFactPayload::Claim(_) => Self::Claim,
            HealthEconFactPayload::Adjudication(_) => Self::Adjudication,
            HealthEconFactPayload::Payment(_) => Self::Payment,
            HealthEconFactPayload::Coverage(_) => Self::Coverage,
            HealthEconFactPayload::PreAuthRequest(_) => Self::PreAuthRequest,
            HealthEconFactPayload::PreAuthDecision(_) => Self::PreAuthDecision,
            HealthEconFactPayload::Appeal(_) => Self::Appeal,
            HealthEconFactPayload::ProviderBill(_) => Self::ProviderBill,
            HealthEconFactPayload::AccumulatorSnapshot(_) => Self::AccumulatorSnapshot,
            HealthEconFactPayload::BenefitMatch(_) => Self::BenefitMatch,
            HealthEconFactPayload::BillingDiscrepancy(_) => Self::BillingDiscrepancy,
            HealthEconFactPayload::RecordRequest(_) => Self::RecordRequest,
            HealthEconFactPayload::RecordReceived(_) => Self::RecordReceived,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "health_econ.claim",
            Self::Adjudication => "health_econ.adjudication",
            Self::Payment => "health_econ.payment",
            Self::Coverage => "health_econ.coverage",
            Self::PreAuthRequest => "health_econ.preauth_request",
            Self::PreAuthDecision => "health_econ.preauth_decision",
            Self::Appeal => "health_econ.appeal",
            Self::ProviderBill => "health_econ.provider_bill",
            Self::AccumulatorSnapshot => "health_econ.accumulator_snapshot",
            Self::BenefitMatch => "health_econ.benefit_match",
            Self::BillingDiscrepancy => "health_econ.billing_discrepancy",
            Self::RecordRequest => "health_econ.record_request",
            Self::RecordReceived => "health_econ.record_received",
        }
    }

    pub fn from_str_label(value: &str) -> Option<Self> {
        Some(match value {
            "health_econ.claim" => Self::Claim,
            "health_econ.adjudication" => Self::Adjudication,
            "health_econ.payment" => Self::Payment,
            "health_econ.coverage" => Self::Coverage,
            "health_econ.preauth_request" => Self::PreAuthRequest,
            "health_econ.preauth_decision" => Self::PreAuthDecision,
            "health_econ.appeal" => Self::Appeal,
            "health_econ.provider_bill" => Self::ProviderBill,
            "health_econ.accumulator_snapshot" => Self::AccumulatorSnapshot,
            "health_econ.benefit_match" => Self::BenefitMatch,
            "health_econ.billing_discrepancy" => Self::BillingDiscrepancy,
            "health_econ.record_request" => Self::RecordRequest,
            "health_econ.record_received" => Self::RecordReceived,
            _ => return None,
        })
    }
}

/// The health-economic crate's payload family: [`HealthEconFact`],
/// [`HealthEconFactPayload`], and the [`HealthEconFactPayloadType`] label
/// enum. Implements [`PayloadFamily`] so health-economic facts reuse the
/// identity crate's encrypted envelope store, episodes, memberships, and
/// policy-gated materialization without a schema fork.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthEconPayloadFamily;

impl PayloadFamily for HealthEconPayloadFamily {
    type Fact = HealthEconFact;
    type Payload = HealthEconFactPayload;
    type PayloadType = HealthEconFactPayloadType;

    fn payload_type_label(payload_type: Self::PayloadType) -> &'static str {
        payload_type.as_str()
    }

    fn payload_type_from_label(label: &str) -> Option<Self::PayloadType> {
        HealthEconFactPayloadType::from_str_label(label)
    }

    fn payload_type_of_payload(payload: &Self::Payload) -> Self::PayloadType {
        HealthEconFactPayloadType::from_payload(payload)
    }

    fn payload_type_variants() -> &'static [Self::PayloadType] {
        HealthEconFactPayloadType::ALL
    }

    fn fact_id(fact: &Self::Fact) -> &FactId {
        &fact.id
    }

    fn subject_id(fact: &Self::Fact) -> &SubjectId {
        &fact.subject_id
    }

    fn occurred_at(fact: &Self::Fact) -> &TemporalAnchor {
        &fact.occurred_at
    }

    fn status(fact: &Self::Fact) -> &FactStatus {
        &fact.status
    }

    fn plaintext_from_fact(fact: &Self::Fact) -> EncryptedFactPlaintextOf<Self::Payload> {
        EncryptedFactPlaintextOf {
            code: fact.code.clone(),
            payload: fact.payload.clone(),
            provenance: fact.provenance.clone(),
            external_refs: fact.external_refs.clone(),
        }
    }

    fn fact_from_plaintext(
        plaintext: EncryptedFactPlaintextOf<Self::Payload>,
        envelope: &StoredEncryptedFactEnvelope<Self::PayloadType>,
    ) -> Self::Fact {
        HealthEconFact {
            id: envelope.fact_id.clone(),
            subject_id: envelope.subject_id.clone(),
            occurred_at: envelope.occurred_at.clone(),
            code: plaintext.code,
            payload: plaintext.payload,
            status: envelope.status.clone(),
            provenance: plaintext.provenance,
            external_refs: plaintext.external_refs,
        }
    }
}
