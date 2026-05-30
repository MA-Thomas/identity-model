# Security and Transition Notes

## Security Audit Pass

The current implementation preserves the FEN security boundary in these ways:

- Ordinary FEN facts store biometric enrollment references and continuity outcomes, never raw captures, templates, embeddings, or liveness frames.
- Continuity verification requires a signed assertion, a known verification key, an issued nonce, a non-expired challenge, a previously unused nonce, and an enrollment-reference match.
- Continuity assertions have canonical serialization before verification, and the registry-backed verifier rejects unknown, retired, provider-mismatched, malformed, and invalid signatures.
- Rejected nonce and signature paths return structured `ContinuityAssertionRejectionReason` values and can be translated into auditable `ContinuityVerificationRejected` facts.
- Access decisions record relied-on fact IDs and policy references, so a later export, delegation, or recovery decision can be explained from the graph.
- Access authorization can cite a verifier-rejection fact as relied-on evidence when a continuity assertion fails signature, nonce, replay, or assertion-shape checks.
- Narrative summaries are rendered from facts, memberships, and projections; they are explanatory artifacts, not an independent authority source.
- Policy evaluation can enforce freshness windows for credential, continuity, and risk evidence, so stale high-assurance evidence does not silently satisfy sensitive actions.
- Provider-specific request, response, event, and error shapes are mapped at the adapter edge before FEN facts are created, preserving the separation between substrate evidence and identity truth.
- Revoked devices and revoked authorities remain in audit history but are excluded from materialized active state.
- Contested clinical and payer links remain auditable; unresolved, rejected, and inconclusive disputes are excluded from active high-reliance projections, while confirmed resolutions can restore an active projection.
- The materialized identity state is rebuilt from active facts. It is a read model, not the source of truth.
- Workflow slices append through a transaction-shaped repository boundary; the in-memory adapter preflights duplicate IDs before mutating history.

## Phase 2 and Phase 3 Transition Notes

The stable FEN graph should not change as the continuity substrate matures. These changes belong outside the identity fact model:

- Hosted vendor SDK: replace the edge adapter while continuing to emit `ContinuityEnrollment` and `SignedContinuityAssertion`.
- Provider transport: add authenticated HTTP or SDK calls inside the adapter without changing translation, policy, workflow, or materialization code.
- Reservatory-owned enrollment namespace: change enrollment reference issuance inside the provider/substrate boundary; FEN continues to store opaque references.
- Internal template storage: keep templates out of `FactPayload`; expose only references, provider metadata, and signed outcomes.
- Confidential-computing matching: change the verifier and assertion issuer, not the `BiometricContinuityCheck` payload.
- Template-protection schemes: govern vault storage and matching internals; facts still carry no raw biometric material.
- Multimodal continuity: add modalities and assurance mapping rules while preserving the signed assertion contract.
- PAD evaluation and FAR/FRR monitoring: feed provider metadata, assurance mapping, policy, and risk evaluation, not mutable subject fields.
- Threshold governance: belongs in policy and verification configuration; access decisions continue to cite policy refs and relied-on facts.

Owning more of the substrate introduces new risks around key custody, template isolation, attestation validity, model drift, replay prevention, and insider access to operational metadata. Those risks should be handled by provider/substrate controls, key management, audit policy, and assurance mapping rather than by expanding ordinary FEN facts.

The current crate remains dependency-free. Its registry-backed verifier therefore exercises canonicalization, key selection, provider authorization, and rotation states with deterministic test signatures; a production cryptographic verifier should be plugged in behind `ContinuitySignatureVerifier` before real continuity assertions are trusted.
