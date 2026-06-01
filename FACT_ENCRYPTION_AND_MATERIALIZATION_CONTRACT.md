# Fact Encryption and Materialization Contract

## Purpose

This document describes how FEN identity facts should be stored when `FactPayload` values are separately encrypted and only materialized after policy and key access checks.

It complements `PERSISTENCE_CONTRACT.md`. The persistence contract defines append-only storage, transaction boundaries, replay order, and repository behavior. This contract defines the storage envelope and access boundary for encrypted semantic payloads.

The core principle is:

```text
Rust owns semantic meaning -> storage preserves append-only encrypted envelopes -> Rust policy permits materialization
```

PostgreSQL or another database may enforce uniqueness, append order, transactions, and indexes. It should not become the source of identity meaning, policy evaluation, or plaintext materialization authority.

## Core Boundary

FEN facts are semantic objects. A production database adapter may store operational metadata in plaintext so facts can be found, ordered, and governed, but it should keep sensitive semantic content encrypted until materialization is authorized.

This preserves the broader FEN boundary:

```text
provider/substrate produces evidence -> FEN verifies/translates -> FEN writes encrypted facts -> FEN materializes by policy
```

The database stores bytes and routing metadata. Rust reconstructs meaning.

## What Remains Queryable in Storage

Some fields must remain queryable without decrypting the payload. These fields support append, replay, coarse routing, policy lookup, and audit:

- `append_sequence`
- `transaction_id`
- `committed_at`
- `fact_id`
- `subject_id`
- `occurred_at`
- `payload_type`
- `status`
- `materialization_policy_refs`
- encryption metadata such as `key_id`, `algorithm`, `nonce`, and `aad_version`

Adapters should keep this set intentionally small. Any plaintext column can leak information through direct inspection, logs, backups, analytics, or query patterns.

## What Must Be Encrypted

At minimum, production storage should encrypt:

- `FactPayload`
- payload-specific evidence details
- provider and payer identifiers when they are not needed for coarse routing
- document references that reveal sensitive evidence
- provider metadata that can identify a patient, account, event, or external subject

Strongly consider encrypting these along with the payload:

- `provenance`
- `external_refs`
- `code`

Some deployments may still choose to duplicate a coarse, non-sensitive `payload_type` or policy tag in plaintext for indexing. That duplicate must be treated as operational metadata, not as the domain source of truth.

## Stored Fact Envelope

A production adapter should store a persistence envelope rather than a plaintext domain struct:

```text
StoredEncryptedFact {
  append_sequence,
  transaction_id,
  committed_at,

  fact_id,
  subject_id,
  occurred_at,
  payload_type,
  status,
  materialization_policy_refs,

  encryption: {
    algorithm,
    key_id,
    wrapped_dek_ref,
    nonce,
    aad_version,
  },

  ciphertext
}
```

The decrypted plaintext should reconstruct the domain fields needed to rebuild a `Fact`, including payload, provenance, external references, and any encrypted fields omitted from the plaintext envelope.

The core `Fact` type should not gain database sequence fields or key-management implementation details unless the domain model later needs them directly.

## AEAD and Associated Data

Use authenticated encryption with associated data, not unauthenticated encryption.

The associated data should bind the ciphertext to the plaintext envelope fields that are required for routing and governance. A reasonable first associated-data profile is:

```text
profile = fen-encrypted-fact
profile_version = v1
fact_id
subject_id
occurred_at
payload_type
status
append_sequence
transaction_id
materialization_policy_refs
schema_version
```

This makes ciphertext swapping, policy-ref swapping, subject swapping, or append-order confusion detectable during decryption.

For the first production implementation, prefer a well-reviewed AEAD such as AES-GCM or ChaCha20-Poly1305 through the selected production crypto boundary. The choice belongs in an adapter or security crate, not in ordinary fact semantics.

## Materialization Flow

The expected read path is:

1. Query encrypted fact envelopes by allowed operational metadata.
2. Identify the materialization policies that govern the requested object or derived view.
3. Evaluate policy in Rust using the caller, purpose, context, consent, and requested operation.
4. If allowed, obtain or unwrap the required data-encryption key through the key-management boundary.
5. Decrypt and authenticate the payload using the envelope associated data.
6. Reconstruct typed `Fact` values.
7. Replay facts into `MaterializedIdentityState`, narratives, exports, or other derived views.
8. Audit the materialization event, including subject, fact IDs, policy refs, caller, purpose, and outcome.

A SQL read is not a semantic materialization. A semantic materialization occurs when FEN reconstructs plaintext meaning from encrypted fact envelopes.

## Key Hierarchy and Rotation

Key management should remain outside the core identity model.

Recommended first shape:

- generate a random data-encryption key for each fact, or for a small policy-equivalent batch if per-fact overhead is too high
- wrap data-encryption keys with key-encryption keys managed by KMS, HSM, or another production key-management service
- store only key identifiers, wrapped key references, and encryption metadata in the database
- rotate key-encryption keys without rewriting domain semantics
- support rewrapping encrypted fact keys without changing `FactId` or append order
- preserve archived key access for historical audit where retention policy permits it

Key deletion, revocation, and destruction are policy decisions. They must be coordinated with retention, legal hold, audit, and patient access obligations.

## Derived Projections and Cached Views

`MaterializedIdentityState` is derived from facts. If cached projections are stored, they should be treated as derived semantic objects.

Options:

- keep projections disposable and rebuild them from encrypted facts after policy approval
- encrypt projection payloads under their own materialization policy
- store only non-sensitive operational projection metadata in plaintext

Do not let cached projections become a plaintext bypass around encrypted facts.

Derived exports, narratives, timelines, and support views inherit constraints from the facts they use. A view that combines many facts may be governed by the strictest applicable policy or by a dedicated derived-object policy.

## Audit Requirements

Adapters and application services should audit:

- attempted materialization
- successful materialization
- denied materialization
- key unwrap attempts
- decryption/authentication failures
- policy refs evaluated
- fact IDs and subject IDs involved
- caller, purpose, and request context

Audit records should not store decrypted payloads.

## Non-Goals

This contract does not:

- require database dependencies in the core crate
- make SQL responsible for interpreting identity facts
- require all storage metadata to be encrypted
- store raw biometric templates, captures, embeddings, or liveness frames in FEN facts
- define the final KMS, HSM, or cloud key-management provider
- replace `PERSISTENCE_CONTRACT.md` append-order and transaction rules
- make cached projections authoritative

## Future Adapter Work

Likely implementation work:

- define encrypted persistence envelope structs in a database adapter crate
- choose the first AEAD implementation and key-management boundary
- define canonical associated-data serialization for encrypted fact envelopes
- add PostgreSQL migrations using binary ciphertext columns
- add round-trip tests for encrypted fact append, decrypt, replay, and audit
- add negative tests for tampered ciphertext, tampered associated data, wrong key, wrong subject, wrong policy refs, and retired keys
- decide whether materialization policies are stored as policy artifacts, consent artifacts, or a related governance artifact family
