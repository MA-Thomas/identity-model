# Security and Transition Notes

## Security Audit Pass

The current implementation preserves the FEN security boundary in these ways:

- Ordinary FEN facts store biometric enrollment references and continuity outcomes, never raw captures, templates, embeddings, or liveness frames.
- Production storage should treat fact payloads as encrypted semantic content. Database adapters may keep minimal operational metadata queryable, but `FactPayload`, provenance, external references, and other sensitive semantic fields should be materialized only after Rust policy and key-access checks.
- Continuity verification requires a signed assertion, a known verification key, an issued nonce, a non-expired challenge, a previously unused nonce, and an enrollment-reference match.
- Continuity assertions have canonical serialization before verification, and the registry-backed verifier rejects unknown, retired, provider-mismatched, malformed, and invalid signatures.
- FEN controls the FEN-native continuity assertion profile: assertion fields, challenge binding, canonical bytes, accepted key metadata, verifier rejection semantics, and translation into continuity facts. Provider-native signatures are verified at the adapter edge before they become FEN evidence.
- Rejected nonce and signature paths return structured `ContinuityAssertionRejectionReason` values and can be translated into auditable `ContinuityVerificationRejected` facts.
- Access decisions record relied-on fact IDs and policy references, so a later export, delegation, or recovery decision can be explained from the graph.
- Access authorization can cite a verifier-rejection fact as relied-on evidence when a continuity assertion fails signature, nonce, replay, or assertion-shape checks.
- Narrative summaries are rendered from facts, memberships, and projections; they are explanatory artifacts, not an independent authority source.
- Policy evaluation can enforce freshness windows for credential, continuity, and risk evidence, so stale high-assurance evidence does not silently satisfy sensitive actions.
- Provider-specific request, response, event, and error shapes are mapped at the adapter edge before FEN facts are created, preserving the separation between substrate evidence and identity truth.
- App Attest-shaped device evidence now passes through a key-state guard after verification, so a key cannot replay a challenge nonce, reuse or rewind a sign count, drift across app/team/bundle/device context, or continue after revocation state is recorded. The runtime-backed path persists that key state and nonce history in PostgreSQL.
- Revoked devices and revoked authorities remain in audit history but are excluded from materialized active state.
- Contested clinical and payer links remain auditable; unresolved, rejected, and inconclusive disputes are excluded from active high-reliance projections, while confirmed resolutions can restore an active projection.
- The materialized identity state is rebuilt from active facts. It is a read model, not the source of truth. Cached projections must not become a plaintext bypass around encrypted facts.
- Workflow slices append through a transaction-shaped repository boundary; the in-memory adapter preflights duplicate IDs before mutating history.

## Phase 2 and Phase 3 Transition Notes

The stable FEN graph should not change as the continuity substrate matures. These changes belong outside the identity fact model:

- Hosted vendor SDK: replace the edge adapter while continuing to emit `ContinuityEnrollment` and either FEN-native `SignedContinuityAssertion` values or verified vendor-native evidence that is translated into the same FEN fact shapes.
- Provider transport: add authenticated HTTP or SDK calls inside the adapter without changing translation, policy, workflow, or materialization code.
- Vendor-native signatures: verify JWS, webhook, SDK, RSA, ECDSA, WebAuthn, or other provider-specific envelopes at the adapter edge; do not let those payload shapes become FEN identity truth.
- FEN-native assertion profile: when the substrate can sign FEN canonical assertion bytes directly, prefer strict Ed25519 verification behind `ContinuitySignatureVerifier` as the first production profile.
- Trusted gateway re-signing: when a provider only emits vendor-native signed evidence, a trusted adapter or gateway may verify the vendor payload and re-sign normalized evidence into the FEN-native profile. This adds key-custody responsibility but preserves a stable FEN verifier contract.
- Reservatory-owned enrollment namespace: change enrollment reference issuance inside the provider/substrate boundary; FEN continues to store opaque references.
- Internal template storage: keep templates out of `FactPayload`; expose only references, provider metadata, and signed outcomes.
- Confidential-computing matching: change the verifier and assertion issuer, not the `BiometricContinuityCheck` payload.
- Template-protection schemes: govern vault storage and matching internals; facts still carry no raw biometric material.
- Multimodal continuity: add modalities and assurance mapping rules while preserving the signed assertion contract.
- PAD evaluation and FAR/FRR monitoring: feed provider metadata, assurance mapping, policy, and risk evaluation, not mutable subject fields.
- Threshold governance: belongs in policy and verification configuration; access decisions continue to cite policy refs and relied-on facts.
- Fact payload encryption: belongs in persistence and key-management adapters. It should not change `FactPayload` semantics, workflow slices, policy evaluation, or materialized projection logic; it changes when and how plaintext facts may be materialized.

Owning more of the substrate introduces new risks around key custody, template isolation, attestation validity, model drift, replay prevention, and insider access to operational metadata. Encrypted fact storage adds related risks around data-encryption keys, key wrapping, associated-data tampering, materialization audit, derived-object leakage, and key retirement. Those risks should be handled by provider/substrate controls, key management, audit policy, materialization policy, and assurance mapping rather than by expanding ordinary FEN facts.

The default crate build remains dependency-light and keeps deterministic test signatures for fixtures. The optional `ed25519-dalek-verifier` feature adds the first FEN-native production verifier behind `ContinuitySignatureVerifier`, preserving canonicalization, key selection, provider authorization, and rotation-state semantics while using strict Ed25519 over canonical assertion bytes.

Under the same feature, the scripted FEN-native hosted adapter can issue provider-side Ed25519 signatures, publish active and retired verification keys, and exercise service-level rejection paths for retired keys, wrong active keys, replayed nonces, and expired nonces. Durable key discovery, storage, refresh, and operational rotation policy remain production adapter concerns.

See `CONTINUITY_ASSERTION_PROFILE.md` for the detailed trust-boundary profile and crypto crate decision rule. See `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md` for the encrypted fact-payload and policy-gated materialization boundary.
