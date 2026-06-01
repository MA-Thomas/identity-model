# Policy Artifact Contract

## Purpose

This document describes how policy artifacts should be stored, reviewed, versioned, activated, retired, and cited by identity workflows.

The core crate models policy artifacts in memory through `PolicyArtifact`, `PolicyArtifactDefinition`, lifecycle status, effective windows, review metadata, and action-policy evaluation. Database-backed policy storage and review workflows should preserve those semantics without making the core identity model depend on a database.

## Core Principle

Access decisions should cite reviewed, stable policy references.

The policy boundary should preserve this shape:

```text
reviewed policy artifact -> policy evaluation -> access decision cites policy ref
```

Policy artifacts are governance inputs. They should not be hidden helper defaults, mutable application settings, or strings parsed from rendered output.

## Artifact Identity and Versioning

A policy artifact has:

- a stable policy ID
- a version string
- a versioned policy ref
- lifecycle status
- optional effective period
- optional review metadata
- structured definition
- derived action-policy evaluation shape

The versioned policy ref is the value access decisions should cite. The current helper shape is:

```text
policy-id@version
```

For example:

```text
complete-record-export-policy@v2
```

Storage should enforce uniqueness for the pair:

```text
(policy_id, version)
```

Policy IDs may have many versions. A given version should be reviewable and historically stable once it has been used to make decisions.

## Lifecycle Status

The current lifecycle states are:

- `Draft`
- `Active`
- `Retired`

### Draft

Draft artifacts are editable review candidates. They should not authorize production decisions.

If a draft artifact is evaluated, the current model gates it into a manual-review result with `PolicyEvaluationReason::PolicyArtifactNotActive`.

### Active

Active artifacts are eligible for policy evaluation, subject to effective-window checks.

Operational storage should make activation an intentional review workflow step. Activation should record who reviewed or approved the artifact, when it was reviewed, and any notes needed for audit.

### Retired

Retired artifacts remain part of history. They should not be deleted if past access decisions cite them.

If a retired artifact is evaluated, the current model gates it into a manual-review result with `PolicyEvaluationReason::PolicyArtifactNotActive`.

## Effective Windows

Policy artifacts may carry an effective period.

When an evaluated timestamp is available:

- if evaluation time is before the start, evaluation includes `PolicyEvaluationReason::PolicyNotYetEffective`
- if evaluation time is after the end, evaluation includes `PolicyEvaluationReason::PolicyExpired`
- either case forces `AccessDecisionResult::ManualReviewRequired`

Adapters should store effective windows as typed timestamps, not rendered labels.

If a policy has no effective period, it is lifecycle-gated by status only.

## Review Metadata

Review metadata currently includes:

- reviewed-by author
- reviewed-at timestamp
- optional notes

Production review workflows may store richer operational state outside the core artifact, such as approver lists, review tickets, signoff evidence, change rationale, or deployment metadata.

Those details should remain adapter or application concerns unless the domain model needs them later.

At minimum, an activated artifact should be able to answer:

- who reviewed it
- when it was reviewed
- what version was approved
- what definition was approved
- why it changed from the prior version, if applicable

## Structured Definitions

Policy artifacts should store structured definitions, not only rendered policy text.

Current definition shapes include:

- sensitive action policies
- emergency access policies
- delegation constraints
- recovery-method change policies
- break-glass policies

These definitions compile into an `ActionPolicy` shape used by evaluation. Storage should preserve enough typed structure to reconstruct the same artifact and derived action policy.

Storing both the structured definition and a materialized action-policy view is acceptable, but the structured definition should remain the reviewable source.

## Access Decision Citation

Access decision facts should cite the versioned policy refs used for evaluation.

This means a later audit can answer:

- which policy version was evaluated
- which facts were relied on
- what decision was produced
- which typed reasons explain step-up, denial, or manual review

When a policy changes, new decisions should cite the new versioned ref. Existing decisions should continue to cite the policy version used at decision time.

## Relationship to Materialization Policies

Fact payload encryption introduces a related governance question: when may an encrypted semantic fact be materialized into plaintext?

Materialization policies may eventually be stored as `PolicyArtifact` values, consent artifacts, or a closely related governance artifact family. Whichever representation is chosen, it should preserve the same core properties:

- stable policy identity
- reviewed versions
- lifecycle status
- effective windows
- typed structured definitions
- audit-friendly policy refs

Materialization policy refs may be stored in encrypted fact persistence envelopes so the adapter can route a materialization request to Rust policy evaluation before key access and decryption. The database should not evaluate these policies itself, and it should not treat policy refs as permission to expose plaintext.

See `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md` for the encrypted payload and materialization boundary.

## Migration and Version Changes

Policy changes should create a new version rather than silently mutating an already-used artifact.

Recommended migration flow:

1. Create a new draft artifact version.
2. Preserve structured definition changes from the prior version.
3. Review and approve the draft.
4. Activate the new version.
5. Retire the replaced version when appropriate.
6. Keep old versions available for audit.

Avoid changing the semantics of an active, already-cited version in place. If emergency correction is necessary, preserve a clear audit trail and prefer creating a corrected version.

## Storage Guidance

Suggested logical tables:

- `policy_artifacts`
- `policy_reviews`
- `policy_artifact_events`

Suggested fields for `policy_artifacts`:

- `policy_id`
- `version`
- `versioned_policy_ref`
- `title`
- `description`
- `status`
- `effective_start`
- `effective_end`
- `definition_type`
- `definition_payload`
- `created_at`
- `updated_at`

Suggested fields for `policy_reviews`:

- `policy_id`
- `version`
- `reviewed_by`
- `reviewed_at`
- `notes`
- optional external review reference

Suggested fields for `policy_artifact_events`:

- `policy_id`
- `version`
- `event_type`
- `event_at`
- `actor`
- `notes`

Adapters may choose JSON, normalized columns, or a hybrid representation. Whatever storage shape is chosen, adapters must reconstruct typed `PolicyArtifact` values without parsing human-facing rendered output.

## Operational Queries

Application and adapter layers will likely need queries for:

- active artifact by action at evaluation time
- artifact by exact versioned policy ref
- all versions for a policy ID
- draft artifacts awaiting review
- retired artifacts cited by historical decisions
- artifacts effective during a given timestamp

When evaluating an access decision, prefer loading the exact active policy artifact intended for that action and time. Do not infer policy identity from display titles.

## Relationship to Persistence Contract

Policy artifact storage is adjacent to, but separate from, the identity fact graph.

Identity facts should cite policy refs. They should not embed the full policy artifact. Policy storage should retain the artifact versions needed to explain those refs later.

This keeps access decisions small and auditable:

```text
AccessDecision {
  relied_on_facts,
  policy_refs
}
```

The referenced artifact can then be loaded from policy storage during audit or review.

## Non-Goals

Policy artifact storage should not:

- parse narrative or fixture strings into policy behavior
- treat display titles as stable policy identity
- mutate an already-cited policy version without audit history
- hide lifecycle gates behind application defaults
- embed database metadata into core policy structs unless the domain model needs it later
- make the core crate depend on database libraries

## Future Work

Likely future work includes:

- policy repository traits once storage requirements are concrete
- materialization policy artifact shapes, if they belong in this artifact family rather than a separate consent/governance contract
- migration notes for the first production policy store
- tests proving access decisions cite exact versioned refs
- tests proving encrypted fact materialization cites exact policy refs and audits materialization outcomes
- review workflow examples for draft activation and retirement
- adapter-level envelopes for policy storage metadata
- richer policy lifecycle states if operational review needs more than `Draft`, `Active`, and `Retired`
