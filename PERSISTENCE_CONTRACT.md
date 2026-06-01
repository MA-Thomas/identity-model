# Persistence Contract

## Purpose

This document describes the persistence contract for database-backed adapters to the FEN identity model.

The core crate stays dependency-free and domain-focused. Database adapters may add storage envelopes, transaction metadata, indexes, and operational tables, but they must preserve the append-only identity graph semantics described here.

The stable source-of-truth entities are:

- `Fact`
- `ProblemEpisode`
- `EpisodeMembership`
- `EpisodeRelation`

`MaterializedIdentityState` is a replayed read model. It may be cached, but it must remain rebuildable from stored facts.

Production adapters should also preserve the payload-encryption boundary described in `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md`: storage may keep operational metadata queryable, but sensitive semantic fact payloads should remain encrypted until Rust policy permits materialization.

## Core Boundary

The architectural boundary remains:

```text
provider/substrate produces evidence -> FEN verifies/translates -> FEN writes facts
```

Persistence must not move identity truth into provider records, mutable profile tables, rendered fixture strings, or cached projections. Provider references, policy refs, continuity results, workflow structure, and relation edges should be stored as reviewable append-only history.

Database storage should not treat plaintext `FactPayload` columns as the ordinary production representation. Instead, a database adapter should store encrypted fact payload envelopes plus the minimal plaintext metadata required for append, lookup, replay ordering, materialization-policy lookup, and audit.

## Append-Only Entities

### Facts

Facts are the durable identity evidence and decision history. They carry payloads such as subject creation, device binding, continuity checks, institutional links, authority relationships, recovery events, risk events, and access decisions.

Facts are append-only. Corrections, revocations, contestations, and supersessions are represented by new facts or fact status fields, not by deleting or rewriting historical facts.

### Episodes

Episodes represent workflows, cases, or problems. Identity workflows use `ProblemEpisode`; there is no separate workflow system.

Examples include onboarding, access authorization, recovery, delegation, and dispute resolution.

### Memberships

Memberships attach facts to episodes with explicit roles. The same fact can be relevant to more than one episode, and relevance itself has authorship and status.

### Episode Relations

Episode relations attach episodes to other episodes. They organize workflow explanation and product review surfaces; they do not contribute to materialized identity state.

For composed onboarding, `EpisodeRelationType::PartOf` uses child-to-parent direction:

```text
registration episode -> PartOf -> parent onboarding episode
device binding episode -> PartOf -> parent onboarding episode
continuity enrollment episode -> PartOf -> parent onboarding episode
```

The parent episode gives a coherent onboarding case. Child episodes preserve separate authorship, timestamps, retries, failures, evidence, and contestability.

## Write Shapes

Database adapters should support two transaction-shaped append operations.

### Workflow Slice Append

A workflow slice append writes:

- one `ProblemEpisode`
- zero or more `Fact` records
- zero or more `EpisodeMembership` records

This corresponds to `IdentityWorkflowSlice`.

The transaction must preflight all IDs and either commit the full slice or commit nothing.

### Episode Composition Append

An episode composition append writes:

- one parent `ProblemEpisode`
- one or more child workflow slices
- one or more `EpisodeRelation` records

This is the production-facing persistence shape for composed onboarding.

The transaction must preflight the parent episode ID, all child episode IDs, all fact IDs, all membership IDs, and all relation IDs. If any duplicate is found, nothing should be written.

## ID Invariants

Adapters must enforce uniqueness for:

- `FactId`
- `ProblemEpisodeId`
- `MembershipId`
- `RelationId`

Duplicate rejection must be atomic for multi-record append operations. A failed append must not leave behind a parent episode, partial child slice, partial fact list, partial membership list, or partial relation list.

## Ordering Contract

Replay currently assumes repository reads return facts in append order.

Production database adapters must preserve append order for:

- `all_facts`
- `facts_for_subject`
- any future replay-oriented fact query

Adapters should not use `Fact.occurred_at` as the primary replay ordering key. Domain time and commit order are different:

- domain time is when the fact says the event happened
- commit order is when FEN accepted the fact into append-only history

Facts can arrive late, be imported out of order, correct older history, or represent periods rather than points. Commit order is the safer spine for replaying the accepted graph.

Recommended storage approach:

- store an explicit append sequence or transaction sequence for each appended record
- order replay queries by that sequence
- keep the sequence in persistence-level storage metadata rather than adding it to domain structs

The current in-memory repository preserves append order through vector insertion order. A database adapter should make this guarantee explicit with an `ORDER BY append_sequence` or equivalent.

## Storage Metadata

Real adapters will likely need persistence envelopes such as:

```text
StoredFact { append_sequence, transaction_id, committed_at, fact }
StoredEpisode { append_sequence, transaction_id, committed_at, episode }
StoredMembership { append_sequence, transaction_id, committed_at, membership }
StoredEpisodeRelation { append_sequence, transaction_id, committed_at, relation }
```

These envelopes should remain persistence concerns. Do not add database sequence fields to `Fact`, `ProblemEpisode`, `EpisodeMembership`, or `EpisodeRelation` unless the domain model itself needs them later.

For production fact storage, `StoredFact` should usually be an encrypted envelope rather than a plaintext `Fact` wrapper. A representative shape is:

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
  encryption_metadata,
  ciphertext
}
```

The decrypted payload must round-trip into the typed Rust domain value. Plaintext columns are operational indexes and governance handles, not the source of identity truth.

## Projection Contract

`MaterializedIdentityState` is derived from facts only.

Episodes, memberships, and relations can explain why facts were produced and how workflows are organized, but they must not change replayed identity state. In particular, adding onboarding `PartOf` relations must not change:

- assurance level
- active devices
- active clinical links
- active payer links
- active authorities
- unresolved disputes
- latest continuity or access decision views

Cached projections are allowed, but they are disposable. The adapter must retain enough append-only history to rebuild projections.

## Suggested Tables and Indexes

Adapters may choose JSON, normalized columns, encrypted binary payloads, normalized metadata columns, or a hybrid representation. Whatever shape is chosen, adapters must round-trip typed domain values without relying on rendered fixture strings.

Suggested logical tables:

- `identity_facts`
- `identity_episodes`
- `identity_episode_memberships`
- `identity_episode_relations`

For encrypted fact storage, `identity_facts` should include ciphertext and encryption metadata columns, while keeping queryable columns for IDs, append sequence, subject, payload type, status, and materialization policy refs. PostgreSQL's `bytea` is the natural storage type for ciphertext in a PostgreSQL adapter.

Suggested indexes:

- facts by `fact_id`
- facts by `subject_id`, ordered by append sequence
- episodes by `episode_id`
- episodes by `subject_id`, ordered by append sequence
- memberships by `membership_id`
- memberships by `episode_id`
- memberships by `fact_id`
- relations by `relation_id`
- relations by `source_episode_id`
- relations by `target_episode_id`

For composed onboarding review surfaces, `target_episode_id` lookup is important because parent-to-child display uses child relations where the parent is the relation target.

## Transaction Notes

Adapters should treat each append operation as a single database transaction.

Recommended preflight:

1. Check existing IDs for duplicates.
2. Check duplicate IDs inside the append payload itself.
3. Assign append sequence values.
4. Insert all records.
5. Commit.

If the database can enforce uniqueness constraints directly, the adapter should still surface failures as `RepositoryError` values or adapter-specific equivalents that preserve the same meaning.

## Non-Goals

The persistence layer should not:

- parse fixture or narrative strings back into domain behavior
- store raw biometric templates, captures, embeddings, or liveness frames in ordinary FEN facts
- store plaintext semantic fact payloads as the default production representation
- materialize encrypted payloads without Rust policy and key-access checks
- treat provider IDs, payer IDs, or account IDs as subject identity truth
- mutate old facts to represent corrections
- let episode relations affect materialized identity state
- require database dependencies in the core crate

## Future Adapter Work

When real database-backed persistence lands, prefer adding adapter-level record envelopes and migration notes before changing the core domain structs.

The likely next evolution is:

- persistence envelopes with append sequence and committed-at metadata
- encrypted fact payload envelopes following `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md`
- database adapter notes for transaction isolation and uniqueness constraints
- replay tests that prove database queries preserve append order
- materialization tests that prove encrypted fact payloads can be policy-authorized, decrypted, authenticated, and replayed
- migration notes for policy artifact storage and review workflows
