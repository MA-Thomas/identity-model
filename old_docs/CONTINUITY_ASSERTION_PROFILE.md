# Continuity Assertion Profile

## Purpose

This document explains what it means for FEN to control the continuity assertion profile, and how that differs from controlling every biometric provider, matcher, SDK, or transport.

The stable identity boundary remains:

```text
provider/substrate produces evidence -> FEN verifies/translates -> FEN writes facts
```

FEN controls the FEN-facing contract for continuity evidence. That contract says what a signed continuity assertion must contain, how it is bound to a challenge, how it is serialized, how it is verified, and how verifier failures become auditable rejection facts.

Provider systems may still have their own native APIs, event formats, risk scores, signatures, webhooks, or transport security. Those are adapter concerns. They do not become identity truth.

## What FEN Controls

For a FEN-native continuity assertion, FEN controls:

- required assertion fields
- nonce and challenge binding
- enrollment-reference binding
- canonical byte serialization
- accepted signature algorithm profile
- verification-key identity and provider authorization
- key lifecycle states such as active and retired
- replay, expiry, malformed assertion, and wrong-provider rejection semantics
- translation into `BiometricContinuityCheck` or `ContinuityVerificationRejected` facts

The current code already has the core domain seam:

- `ContinuityAssertion`
- `SignedContinuityAssertion`
- `ContinuitySignatureVerifier`
- `VerificationKeyRegistry`
- canonical assertion serialization in `src/continuity/canonical.rs`
- an optional strict Ed25519 verifier in `src/continuity/ed25519.rs`, enabled by the `ed25519-dalek-verifier` feature
- a feature-gated FEN-native hosted adapter that signs canonical assertion bytes with Ed25519 and publishes active plus retired verification keys for service-path tests
- typed rejection reasons

The deterministic verifier exists only to exercise this seam for fixtures and dependency-light tests. The Ed25519 verifier is the first FEN-native production implementation and remains feature-gated so the default core build can stay lightweight.

## What FEN Does Not Control

FEN does not need to control:

- camera capture implementation
- biometric template storage
- liveness or PAD engine internals
- matcher implementation
- vendor account identifiers
- hosted SDK request and response vocabulary
- vendor-native webhook signature formats
- provider operational risk scores

Those details can change as the substrate moves from Phase 1 vendor-backed workflows toward hosted, Reservatory-owned, or enclave-backed infrastructure. FEN should continue to receive verified, normalized continuity evidence and write the same fact shapes.

## Three Integration Shapes

### 1. Provider Emits FEN-Native Assertions

This is the cleanest production shape:

```text
FEN challenge -> substrate evaluates -> substrate signs FEN ContinuityAssertion -> FEN verifies
```

The provider or substrate signs the canonical FEN assertion bytes directly. In this case, FEN fully controls the assertion profile used by the verifier.

Recommended first production profile:

- canonical FEN continuity assertion bytes
- Ed25519 signatures
- strict Ed25519 verification
- explicit `key_id`
- provider-name authorization on each verification key
- active and retired key states

This is implemented as the optional `Ed25519StrictSignatureVerifier` behind `ContinuitySignatureVerifier`, using `ed25519-dalek` strict verification. The deterministic verifier remains for fixtures and tests.

The feature-gated FEN-native hosted adapter in `src/provider/hosted.rs` exercises the same profile from the provider side: it signs canonical assertion bytes, exposes the corresponding verification keys, supports scripted key rotation, and drives service-level verification without changing FEN fact shapes.

### 2. Provider Emits Vendor-Native Assertions

Some Phase 1 providers may sign their own payload shape:

```text
FEN challenge -> vendor evaluates -> vendor signs vendor payload -> adapter verifies -> FEN writes facts
```

In this case, FEN still controls the identity ontology and fact graph, but it does not control the provider's native cryptographic envelope. The adapter must verify the vendor-native signature correctly before translating the event into FEN evidence.

This may require protocol-specific or broader crypto support, such as:

- JWS or JWT verification
- WebAuthn-related verification
- RSA or ECDSA verification
- provider SDK verification hooks
- `aws-lc-rs` or another production crypto backend

The vendor-native signature format should stay at the provider edge. It should not leak into `FactPayload`, materialized projections, policy decisions, or rendered fixture strings.

### 3. Trusted Gateway Re-Signs Into the FEN Profile

A bridge pattern can preserve the FEN-native profile even when a vendor has its own signed event format:

```text
vendor signed event -> adapter verifies -> trusted gateway signs FEN ContinuityAssertion -> FEN verifies
```

The adapter or gateway first verifies the vendor-native evidence. It then normalizes that evidence into the FEN assertion contract and signs the canonical FEN bytes with a FEN-authorized key.

This adds an extra trust boundary and key-custody responsibility, but it gives FEN a stable verification profile while allowing provider-specific transport to vary.

## Crypto Crate Decision

The crate choice follows the integration shape.

If FEN controls the FEN-native assertion profile, use a small, specific implementation first:

```text
ContinuitySignatureVerifier -> Ed25519 strict verifier -> ed25519-dalek
```

This is the preferred first production path for the FEN-native profile because the current assertion is small, canonical, and signed as a complete message.

If a real provider controls the signature protocol, use the crate or SDK that matches that protocol:

```text
provider adapter -> vendor-native verification -> translated FEN evidence
```

For RSA, ECDSA, FIPS-sensitive deployments, or multiple public-key algorithms, `aws-lc-rs` is a likely candidate. That choice belongs in the provider adapter or production trust-boundary crate, not in ordinary identity facts.

The RustCrypto `signature` crate can be useful as an implementation helper when multiple compatible RustCrypto backends are used. It should not replace the domain-specific `ContinuitySignatureVerifier` seam, because the FEN verifier must also enforce provider authorization, key lifecycle, nonce binding, and rejection semantics.

## Domain Separation

The signed bytes must identify the FEN continuity assertion profile. Canonical serialization should make it difficult to accidentally verify a signature intended for another message family.

Recommended profile inputs include:

- profile name, such as `fen-continuity-assertion`
- profile version, such as `v1`
- assertion fields in canonical order
- provider name
- enrollment reference
- challenge nonce
- assertion timestamp
- result and assurance values
- modality and PAD result

Changing the profile semantics should create a new profile version. Old access decisions and continuity facts should remain auditable against the profile version and key metadata used at the time.

## Key and Rotation Expectations

Production verification should preserve the current model semantics:

- verification keys are addressed by `key_id`
- keys are authorized for a provider or substrate
- retired keys do not verify new assertions
- wrong-provider keys reject with a typed reason
- malformed signatures reject with a typed reason
- unknown keys reject with a typed reason
- replay and nonce failures remain separate from signature failures

Key material storage is an adapter or infrastructure concern. Domain facts should record the continuity result and relevant provider metadata, not raw private keys, raw biometric material, or provider-native signed blobs.

## Non-Goals

The continuity assertion profile should not:

- store biometric captures, templates, embeddings, or liveness frames in FEN facts
- make provider-native IDs primary identity keys
- let vendor risk vocabulary become FEN policy semantics
- parse rendered fixture or narrative strings back into verification logic
- force every provider to use the same transport
- require production crypto dependencies in the core crate before the production trust boundary is implemented

## Practical Recommendation

Use the `ed25519-dalek-verifier` feature and `Ed25519StrictSignatureVerifier` for the first FEN-native production verifier, behind `ContinuitySignatureVerifier`.

Keep deterministic signatures for default tests and examples. Use the feature-gated FEN-native hosted adapter when tests need provider-issued Ed25519 assertions, active/retired key behavior, and service-path nonce failures with real signatures.

Keep provider-native verification at the provider edge. If Phase 1 vendors require RSA, ECDSA, JWS, WebAuthn, or compliance-specific verification, implement that in the adapter path and translate only verified evidence into FEN facts.

This keeps the architecture honest: FEN controls the assertion contract it relies on, while provider integrations remain replaceable evidence producers.
