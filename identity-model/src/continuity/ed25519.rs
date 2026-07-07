use super::*;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519StrictSignatureVerifier {
    pub key_registry: VerificationKeyRegistry,
}

impl ContinuitySignatureVerifier for Ed25519StrictSignatureVerifier {
    fn verify_signature(
        &self,
        signed_assertion: &SignedContinuityAssertion,
    ) -> Result<(), ContinuityAssertionRejectionReason> {
        if signed_assertion.signature.len() != DalekSignature::BYTE_SIZE {
            return Err(ContinuityAssertionRejectionReason::MalformedAssertion);
        }

        let key = self
            .key_registry
            .get(&signed_assertion.key_id)
            .ok_or(ContinuityAssertionRejectionReason::UnknownVerificationKey)?;

        if key.status != VerificationKeyStatus::Active {
            return Err(ContinuityAssertionRejectionReason::UnknownVerificationKey);
        }

        if key.provider_name != signed_assertion.assertion.provider_metadata.provider_name {
            return Err(ContinuityAssertionRejectionReason::KeyNotAuthorizedForProvider);
        }

        let public_key_bytes: &[u8; 32] = key
            .key_material
            .as_slice()
            .try_into()
            .map_err(|_| ContinuityAssertionRejectionReason::MalformedAssertion)?;
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|_| ContinuityAssertionRejectionReason::MalformedAssertion)?;
        let signature = DalekSignature::from_slice(&signed_assertion.signature)
            .map_err(|_| ContinuityAssertionRejectionReason::MalformedAssertion)?;
        let canonical_bytes = canonical_continuity_assertion_bytes(&signed_assertion.assertion)?;

        verifying_key
            .verify_strict(&canonical_bytes, &signature)
            .map_err(|_| ContinuityAssertionRejectionReason::InvalidSignature)
    }
}
