# Residual Refactor Debt and Next Steps

## Audit conclusion

The initial extraction phase is successful, but the broader Phoros Account
refactor has not yet begun. The repository is now a credible multi-domain FEN
workspace; it is not yet an account platform.

This assessment was produced from a read-only audit of the repository on
2026-08-14. The audit itself did not alter files or run builds or tests, because
those commands can update generated artifacts.

## Audit summary

| Area | State | Assessment |
| --- | --- | --- |
| Shared FEN core | Complete | Clean, dependency-free shared identifiers and values |
| Storage contract | Complete | Database-independent encrypted storage boundary |
| PostgreSQL adapter | Complete | Correctly isolated in its own workspace member |
| Identity bounded context | Partial | Dependency direction is improved, but identity remains a large combined domain/runtime/adapter crate |
| Health-economic domain | Substantially complete | Now a proper sibling rather than an identity dependency |
| Phoros Account domain | Not implemented | No account aggregate, `AccountId`, lifecycle, endpoint ownership, or one-person invariant |
| Cross-account authority | Prototype only | Some useful concepts exist, but granting and enforcement are not production-safe |
| PHI identifier separation | Partial foundation | Encryption, policy gating, and auditing exist; the employee disclosure boundary does not |
| Cloud communications endpoint | Not implemented | Current server is only an identity/mobile-onboarding runtime |
| Ingestion and immutable originals | Not implemented | No transport-neutral ingestion pipeline or original-object store |
| Desktop synchronization | Not implemented | No desktop workspace or synchronization protocol |

## What the refactor accomplished well

The workspace now has the dependency shape established in the initial refactor
plan:

- `fen-core` contains shared semantic primitives and no storage, transport,
  database, or runtime concerns.
- `fen-store` defines a payload-family-neutral encrypted envelope and
  authorization contract.
- `fen-store-postgres` owns the SQL implementation.
- `fen-health-econ` depends on the shared crates, not on identity in its
  production dependency graph.
- Identity onboarding, OIDC, liveness, recovery, Apple App Attest, mobile HTTP,
  and the iOS proof application remain present.

That directly satisfies the first structural goal: identity is no longer the
accidental owner of every FEN domain's storage infrastructure.

## Principal gaps

### 1. "Account" currently means identity session, not Phoros Account

There is no `AccountId`, account aggregate, communications endpoint ownership,
or account lifecycle. `AccountSessionBootstrapRequest` in
`identity-model/src/flows/account.rs` is actually an identity-provider login
workflow keyed directly by `SubjectId`.

`AccountId` and `SubjectId` should remain distinct types with an enforced
one-to-one binding. They represent different things:

- `AccountId` is the durable product and service resource.
- `SubjectId` is the person-shaped semantic identity used across FEN facts.

That distinction is especially important because the identity model permits
organizations, devices, and system agents as subjects, not only people.

### 2. Existing delegation is not safe account-management authority

The vocabulary is promising: authority types, scopes, permitted actions,
validity periods, policy references, and evidence references exist in
`identity-model/src/identity.rs`.

The behavior is still a demonstration workflow:

- A delegation request has only one optional, string-like `evidence_ref`; it
  has no constraint set or witness-satisfaction result.
- It creates actor and target subjects with placeholder names.
- It hardcodes `CaregiverDelegation`.
- It emits an unconditional `Allowed` decision.
- It immediately emits a revocation in the same operation.

This behavior is implemented in `identity-model/src/flows/delegation.rs`.
Consequently, `IdentityWorkflowService::delegate_authority` does not actually
leave a managing relationship active.

Additionally, `DelegationConstraintsPolicyDefinition` records authority type,
permitted actions, and maximum duration, but conversion to the evaluated
action policy ignores those fields. It only evaluates authentication,
continuity, freshness, and risk. This behavior is in
`identity-model/src/policy.rs`.

Authority expiration is also unsafe through the convenience projection:
materialization without an explicit `as_of` treats a validity period as active
regardless of its end date. This behavior is in
`identity-model/src/materialized.rs`.

This code should be treated as prototype and audit-narrative code, not as the
eventual account-management authorization engine.

### 3. PHI controls have good mechanics but lack the required disclosure boundary

The strong pieces are already present:

- Identity payloads and identifiers are inside authenticated ciphertext.
- `SubjectId`, payload class, policy references, and operational envelope
  metadata remain queryable.
- Decryption requires an authorization artifact.
- Materialization records caller, purpose, requested time, outcome, and policy
  references.

These mechanics are primarily defined by `fen-store`.

They do not yet implement the employee access model discussed for the product:

- Identity mappings are not separated into a dedicated identifier/disclosure
  boundary.
- A repository is configured with one common set of materialization policy
  references, rather than distinguishing ordinary SubjectId-based work from
  identifier disclosure.
- Public materialization APIs allow an empty audit context.
- The onboarding server constructs an `Allowed` policy evaluation directly
  from configuration rather than obtaining an independently evaluated
  consent/step-up decision.
- There is no employee principal type, consent grant, disclosure session, or
  mandatory step-up artifact.

The cryptographic mechanism is useful, but the application-level security
boundary remains to be designed.

### 4. The product architecture remains mostly ahead of the code

`Phoros_Product_Architecture_Memo.md` requires a cloud endpoint,
transport-neutral ingestion, immutable originals, FEN conversion, workflows,
and synchronized application surfaces.

Presently:

- The only running server is mobile identity onboarding.
- There is no SMTP, Direct Secure Messaging, secure-upload, or provider-API
  transport.
- There is no immutable original communication or blob repository.
- There is no ingestion event model.
- There is no desktop/Tauri application or synchronization protocol.
- Health-economic facts and reconciliation are real and useful, but FHIR and
  claims-ingestion features are currently manifest declarations without
  corresponding ingestion modules.

## Residual structural debt

Identity is structurally a sibling domain now, but internally it still combines
domain logic, HTTP representation, runtime server, PostgreSQL workflows,
identity providers, cryptography, and Apple-specific implementation behind
feature flags. Its crate root also publicly re-exports nearly everything.

There is transitional database ownership debt:

- The generic adapter retains `identity_facts` and
  `identity_fact_materialization_audit` names for compatibility.
- Identity's migration registry still runs the health-economic rule migration.

These are reasonable compatibility compromises for this tranche, but they
should not become the final ownership model.

## Recommended next tranche

Before communications or UI work, finish the identity boundary and migration
ownership cleanup, then introduce the account and authority domains. This
prevents the new account layer from depending on the current combined identity
crate and making that coupling harder to remove later.

### 1. Finish the identity boundary

Separate pure identity domain logic from infrastructure and delivery concerns:

- Keep identity facts, identity proofing, assurance, policy concepts, and pure
  workflow behavior in a dependency-light identity domain member.
- Move HTTP request and response representations into an HTTP-facing member or
  application edge.
- Move the runtime server into a cloud application member.
- Move PostgreSQL identity workflow persistence, live-presence challenges, and
  App Attest state into an identity PostgreSQL adapter.
- Keep OIDC, identity-provider, cryptographic-provider, continuity-provider,
  and Apple App Attest implementations behind explicit adapter interfaces.
- Preserve all existing onboarding and Apple functionality while moving its
  implementation out of the domain boundary.
- Replace crate-wide wildcard re-exports with a deliberate, stable public API.
- Ensure future account and authority members consume only that identity
  domain API, never the HTTP, runtime, or database implementations.

The precise number of crates should be driven by dependency boundaries rather
than by creating one crate for every module. The essential rule is that the
identity domain must compile without HTTP, runtime, database, Apple, OIDC, or
production cryptography dependencies.

### 2. Resolve migration ownership

Give each domain and adapter sole ownership of its schema changes:

- `fen-store-postgres` owns shared encrypted-fact storage and materialization
  audit migrations.
- Identity owns only identity workflow, live-presence, App Attest, and other
  identity-specific migrations.
- `fen-health-econ` owns its reconciliation-rule migrations.
- A cloud application migrator composes these independently owned migration
  sets in a controlled order.
- New code should not add further cross-domain migrations to the identity
  registry.

The deployed `identity_facts` and `identity_fact_materialization_audit` names
may remain temporarily for compatibility. Renaming them should be handled by
an explicit deployment migration, potentially with compatibility views, after
the cloud deployment and rollback strategy is defined. Correcting ownership
should happen now; renaming deployed tables does not have to happen in the
same tranche.

### 3. Add `phoros-account-core`

This member should own:

- `AccountId`.
- The one-account/one-human-subject binding.
- Account lifecycle state.
- Communications endpoint identity and ownership.
- Account-level invariants.

### 4. Add `phoros-authority`

This member should own:

- Grants between accounts.
- Resource and action scope.
- Validity and revocation.
- Constraints.
- Witness references and witness-satisfaction evidence.
- Grant evaluation.

The exact closed witness taxonomy can remain undecided. The model can support
typed witness references and satisfaction evidence without declaring the
final allowed witness combinations.

### 5. Establish the PHI disclosure boundary

Immediately after the account and authority domains, define the PHI disclosure
boundary:

- Employee principals.
- Consent and step-up evidence.
- Identifier-mapping access.
- Mandatory audit context.
- A service that is the only path from `SubjectId` to direct identifiers.

### 6. Build communications, ingestion, cloud services, and synchronization

Only after the preceding boundaries exist should the product infrastructure
expand to include:

- The permanent cloud-hosted communications endpoint.
- Transport-neutral SMTP, Direct Secure Messaging, FHIR, secure-upload, and
  provider-API ingestion edges.
- Immutable original communication and document storage.
- Typed ingestion events and FEN conversion.
- Cloud workflow orchestration.
- Desktop, mobile, and browser synchronization contracts.
- The desktop records, billing, communications, and consent workspace.

Starting this infrastructure earlier would encode the current conflation of
subject, account, authority, and disclosure into long-lived service APIs.

## Operational repository state at the time of audit

The extraction refactor was still uncommitted on `main`. `HEAD` and
`origin/main` both pointed to commit `ab6c93b`, while the working tree contained
the shared-core, shared-storage, PostgreSQL-adapter, identity, and
health-economic refactor changes.
