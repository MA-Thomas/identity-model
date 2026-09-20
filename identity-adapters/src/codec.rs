//! Versioned durable plaintext encoding, independent of process memory.
use fen_store::{EncryptedFactPlaintextCodec, EncryptedFactPlaintextOf, FactMaterializationError};
use identity_model::fen::{CodedValue, ExternalRef, FactPayload, Provenance};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plaintext {
    version: u16,
    code: Option<CodedValue>,
    payload: FactPayload,
    provenance: Provenance,
    external_refs: Vec<ExternalRef>,
}
#[derive(Debug, Default)]
pub struct IdentityPlaintextCodec;
impl EncryptedFactPlaintextCodec<FactPayload> for IdentityPlaintextCodec {
    fn encode_fact_plaintext(&self, plaintext: &EncryptedFactPlaintextOf<FactPayload>) -> Vec<u8> {
        // These record types contain only JSON-representable scalar, sequence and enum values.
        serde_json::to_vec(&Plaintext {
            version: 1,
            code: plaintext.code.clone(),
            payload: plaintext.payload.clone(),
            provenance: plaintext.provenance.clone(),
            external_refs: plaintext.external_refs.clone(),
        })
        .expect("identity plaintext contains only JSON-representable values")
    }
    fn decode_fact_plaintext(
        &self,
        encoded: &[u8],
    ) -> Result<EncryptedFactPlaintextOf<FactPayload>, FactMaterializationError> {
        let value: Plaintext = serde_json::from_slice(encoded)
            .map_err(|_| FactMaterializationError::PlaintextDecodeFailed)?;
        if value.version != 1 {
            return Err(FactMaterializationError::PlaintextDecodeFailed);
        }
        Ok(EncryptedFactPlaintextOf {
            code: value.code,
            payload: value.payload,
            provenance: value.provenance,
            external_refs: value.external_refs,
        })
    }
}
