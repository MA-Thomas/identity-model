# FEN Identity Build Plan

## Purpose

This plan describes how to build the FEN identity layer in a way that supports the long-term Phase 3 architecture while implementing Phase 1 first.

The central strategy is:

1. Design the stable FEN-facing contracts as if the continuity substrate will eventually be owned, enclave-backed, and provider-swappable.
2. Keep vendors, platform biometrics, and liveness providers outside the identity ontology.
3. Implement Phase 1 as the first adapter behind those contracts.

This avoids building a Phase 1-shaped system that later has to be unwound.

## Architectural North Star

FEN owns the identity graph. Vendors and biometric systems produce evidence.

Identity is not stored as a mutable account profile. It is represented as a graph of time-indexed, provenance-bearing facts:

- credential assertions
- identity witnesses
- device bindings
- biometric enrollment references
- continuity checks
- provider and payer links
- authority relationships
- recovery events
- risk evaluations
- access decisions

`SubjectId` anchors the biologically continuous subject, but it does not prove identity by itself. Identity, continuity, institutional linkage, authority, and access are derived from the fact graph, episode memberships, policies, and narratives.

The continuity substrate has a stable boundary:

```text
FEN issues nonce
client captures and attests
continuity substrate evaluates liveness and 1:1 match
continuity substrate signs assertion
FEN verifies signature and nonce freshness
FEN writes BiometricContinuityCheck fact
policy engine maps assurance to access decision
```

Phase 1 uses a vendor behind this boundary. Phase 2 moves more capture, orchestration, and storage into Reservatory infrastructure. Phase 3 moves toward enclave matching, template protection, multimodal support, formal PAD evaluation, and owned threshold governance. The FEN identity layer should not change when that substrate changes.

## Milestone Template

Each milestone should be small enough to complete during one daily working session.

Every milestone should include:

- **Purpose:** what this chunk accomplishes.
- **Minimal FEN Context:** only the concepts needed for that day.
- **Build Target:** what artifact, code, or test should exist afterward.
- **Acceptance Criteria:** concrete checks for done.
- **Notes for Later Phases:** only when the milestone affects Phase 2 or Phase 3.

## Milestone 1: Architecture Charter

### Purpose

Establish the non-negotiable boundaries before implementation begins.

### Minimal FEN Context

FEN organizes data as `Fact`, `ProblemEpisode`, `EpisodeMembership`, and `Narrative`. The identity supplement extends this model rather than creating a separate identity subsystem.

The answer to the identity problem is never a primitive field. Identity-relevant inputs are evidence.

### Build Target

Create an architecture charter that states:

- FEN owns the identity graph.
- Vendors produce evidence, not identity truth.
- The continuity substrate is replaceable.
- Raw biometric material never enters ordinary FEN facts.
- Access decisions must record relied-on facts and policy references.

### Acceptance Criteria

- The charter clearly distinguishes account authentication, biological continuity, institutional linkage, and authority.
- The Phase 1 vendor path is described as an adapter, not a core model dependency.
- The Phase 3-shaped continuity boundary is named explicitly.

### Notes for Later Phases

This milestone prevents Phase 1 from leaking vendor-specific assumptions into the domain model.

## Milestone 2: Core Identity Types

### Purpose

Define the stable identity primitives used by later milestones.

### Minimal FEN Context

`SubjectId` is the durable internal anchor for a biologically continuous person or other identity-bearing subject. Provider MRNs, payer member IDs, portal links, caregiver relationships, and biometric templates do not belong on the subject object.

### Build Target

Define the first identity-domain types:

- `Subject`
- `SubjectKind`
- `SubjectStatus`
- `StableIdentityProfile`
- `IdentityAttribute`
- `IdentityAttributeValue`
- `AssuranceLevel`
- `MatchConfidence`
- `IdentityWitnessType`
- `AuthenticatorType`

### Acceptance Criteria

- `SubjectKind` describes intrinsic entity kind only.
- Context-specific capacities such as patient, caregiver, clinician, attorney, and witness are not encoded as subject kinds.
- External IDs and authority relationships remain outside the subject object.

### Notes for Later Phases

Keeping `Subject` sparse makes later biometric and institutional-link migration possible without changing the core subject model.

## Milestone 3: Identity Fact Payloads

### Purpose

Represent identity, continuity, linkage, authority, recovery, and access as FEN facts.

### Minimal FEN Context

`Fact` is the atomic, provenance-bearing unit. A fact either happened or it did not. Corrections use status, supersession, or replacement facts rather than mutation.

### Build Target

Extend the closed `FactPayload` set with identity variants:

- `SubjectCreated`
- `IdentityAttributeAsserted`
- `IdentityWitnessRecorded`
- `BiometricEnrollmentReferenceAdded`
- `BiometricContinuityCheck`
- `DeviceBindingEstablished`
- `DeviceBindingRevoked`
- `CredentialAssertion`
- `ClinicalIdentityLinkEstablished`
- `ClinicalIdentityLinkContested`
- `PayerIdentityLinkEstablished`
- `PayerIdentityLinkContested`
- `AuthorityRelationshipEstablished`
- `AuthorityRelationshipRevoked`
- `AccountRecoveryEvent`
- `RiskEvaluationEvent`
- `AccessDecision`

### Acceptance Criteria

- Each variant represents an event, assertion, or decision.
- No variant stores raw biometric material.
- Provider and payer links are defeasible facts, not permanent subject fields.
- Revocation and contestation preserve audit history.

### Notes for Later Phases

Phase 2 and Phase 3 should produce the same canonical FEN facts even if the underlying biometric subsystem changes.

## Milestone 4: Identity Workflow Types

### Purpose

Add workflow scaffolding for onboarding, recovery, delegation, access, and disputes.

### Minimal FEN Context

`ProblemEpisode` is a persistent, fallible, corrigible problem or workflow. `EpisodeMembership` is the authored claim that a fact is relevant to an episode. Membership is separate because relevance needs provenance and contestability.

### Build Target

Add:

- `EpisodeKind`
- identity-specific `FactRole` values
- workflow conventions for onboarding, access authorization, recovery, delegation, data sharing, and dispute resolution

### Acceptance Criteria

- Identity workflows use `ProblemEpisode`; they do not introduce a parallel workflow system.
- Evidence relevance is represented through `EpisodeMembership`.
- The same fact can play different roles in different workflows.

### Notes for Later Phases

This lets new substrate evidence be attached to existing workflows without changing workflow structure.

## Milestone 5: Continuity Assertion Contract

### Purpose

Define the stable trust interface between FEN and any biological-continuity substrate.

### Minimal FEN Context

The substrate verifies continuity, not identity. It performs a 1:1 check against this subject's enrollment reference. FEN stores enrollment references and signed continuity results, not templates or captures.

### Build Target

Define:

- `ContinuityAssertion`
- signed assertion envelope
- nonce challenge type
- verification result type
- signature verification boundary
- freshness and replay rules
- assurance mapping hook

The assertion should include at least:

- enrollment reference
- challenge nonce
- timestamp
- result
- derived assurance
- modality
- model or provider version
- PAD or liveness result

### Acceptance Criteria

- FEN can issue a nonce.
- A valid signed assertion can be verified.
- A missing, stale, or reused nonce is rejected.
- A verified assertion can become a `BiometricContinuityCheck` fact.
- The contract does not expose raw biometric material.

### Notes for Later Phases

FEN should control the FEN-native continuity assertion profile: required fields, nonce binding, canonical bytes, accepted signature profile, key identity, provider authorization, and rejection semantics.

That does not require every Phase 1 provider to emit that profile natively. A vendor may emit its own signed payload, webhook, SDK result, JWS, RSA/ECDSA signature, or other evidence envelope. In that case, the provider adapter verifies the vendor-native envelope at the edge and only then translates or re-signs normalized evidence into the FEN-facing assertion contract.

The preferred first FEN-native production verifier is strict Ed25519 over canonical FEN assertion bytes, behind the `ContinuitySignatureVerifier` seam. The current feature-gated hosted adapter proves provider-issued Ed25519 signatures, active/retired key publication, and service-level nonce rejection semantics. Broader crypto backends belong in provider adapters or production trust-boundary crates when vendor or compliance requirements demand them.

This is the main portability boundary. Everything left of signed assertion verification can move from vendor to hosted SDK to enclave service without changing FEN.

## Milestone 6: Continuity Vault Provider Interface

### Purpose

Create the replaceable provider abstraction behind the continuity contract.

### Minimal FEN Context

FEN should consume trusted continuity assertions. It should not depend on vendor user IDs, vendor account models, or vendor-specific risk semantics as identity truth.

### Build Target

Define a provider interface for:

- enrollment initiation
- enrollment reference creation
- challenge preparation
- assertion receipt
- provider capability metadata
- provider-specific error mapping

### Acceptance Criteria

- A provider can be swapped without changing identity facts.
- Provider errors map into FEN-level outcomes.
- Vendor identifiers are captured as external references or provenance, not primary identity keys.

### Notes for Later Phases

Phase 1 implements this interface with a vendor. Phase 2 and Phase 3 implement the same interface with more Reservatory-owned infrastructure.

## Milestone 7: FEN Translation Layer

### Purpose

Convert trusted external events into canonical FEN facts.

### Minimal FEN Context

Vendor, platform, and vault outputs are evidence. FEN decides how that evidence affects identity, authority, and access.

### Build Target

Create translation functions for:

- provider identity proofing results
- device binding events
- passkey or credential assertions
- biometric enrollment references
- continuity assertions
- risk evaluations
- access decisions

### Acceptance Criteria

- Every translated fact has provenance.
- External transaction IDs and provider references are preserved as external references.
- Translation is separate from provider-specific API code.
- Failed and inconclusive events are representable facts.

### Notes for Later Phases

This layer is where provider-specific vocabulary is normalized. It should be thin, explicit, and well tested.

## Milestone 8: Policy and Sensitive Actions

### Purpose

Encode the difference between ordinary login and sensitive action authorization.

### Minimal FEN Context

Ordinary login is evidence of account or device continuity. It is not a fresh proof of legal identity or authority. Sensitive actions may require step-up evidence.

### Build Target

Define:

- `SensitiveAction`
- `AuthorizedAction`
- `AuthorityScope`
- `RiskEvaluationResult`
- `AccessDecisionResult`
- assurance requirements by action
- policy references on access decisions

### Acceptance Criteria

- Viewing ordinary dashboard content can have different requirements from exporting a complete record.
- Delegating authority, changing recovery methods, linking providers, and authorizing data transactions can require stronger evidence.
- `AccessDecision` records the action, result, relied-on facts, and policy references.

### Notes for Later Phases

Thresholds and assurance mappings should be policy-governed, not hard-coded constants.

## Milestone 9: Materialized Identity State

### Purpose

Build a fast derived view over the identity graph.

### Minimal FEN Context

The current identity state is not the source of truth. It is a projection over active, non-retracted, non-superseded facts and memberships.

### Build Target

Define and compute `MaterializedIdentityState` with:

- subject ID
- current assurance level
- active devices
- active clinical links
- active payer links
- active authority relationships
- unresolved disputes
- latest continuity check

### Acceptance Criteria

- Revoked devices are excluded.
- Contested links are excluded from high-risk reliance.
- Superseded or entered-in-error facts do not contribute to current state.
- The view points back to source fact IDs.

### Notes for Later Phases

This is the object most product surfaces will read, but it must remain rebuildable from facts.

## Milestone 10: Onboarding Flow

### Purpose

Implement initial patient identity binding as a FEN workflow.

### Minimal FEN Context

Onboarding is an identity verification workflow. It creates facts, links them with memberships, and summarizes state in a narrative or materialized view.

The onboarding liveness ceremony should be motivated explicitly because it is easy to mislabel it as "face authentication." A YouTube-style guided video-selfie ceremony is useful because it creates live-presence evidence: a physically present human completed a fresh challenge at onboarding time, under liveness/PAD and capture-path controls. It can also produce or support the biometric enrollment capture used later by the continuity substrate.

That ceremony is not identity by itself. It should be represented as a `SelfieLivenessCheck` identity witness, usually alongside government ID, clinical registration, payer, or provider evidence. The later biological-continuity claim is narrower and stronger in a different way: a signed, nonce-bound 1:1 check against this subject's enrollment reference, translated into a `BiometricContinuityCheck` fact.

The motivated accounting for onboarding evidence is:

- account/session evidence proves control of an account session
- app or hardware attestation helps bind the capture path to a genuine app/device context
- guided video-selfie liveness proves fresh physical presence and presentation-attack resistance
- government ID, clinic, provider, or payer evidence supports civil or institutional identity
- biometric enrollment stores an opaque reference for later 1:1 continuity checks
- signed continuity assertions are used for later step-up, recovery, delegation, and high-risk access decisions

Product language should reflect this distinction. Prefer "live presence check," "video-selfie check," or "confirm you are physically present." Avoid "face authentication" or "prove identity with your face."

### Build Target

Create an onboarding flow that records:

- subject creation
- account bootstrap
- device binding
- identity witnesses
- guided live-presence or video-selfie liveness witness
- biometric enrollment reference
- provider or payer links when available
- episode memberships
- onboarding narrative

### Acceptance Criteria

- Sign in with Apple, Google, or another account mechanism is treated as bootstrap evidence only.
- Government ID and liveness checks are represented as distinct witnesses.
- The live-presence ceremony records `IdentityWitnessRecorded` with `IdentityWitnessType::SelfieLivenessCheck`; it does not collapse into `SubjectCreated`, `DeviceBindingEstablished`, or a mutable profile field.
- A later signed 1:1 match against the enrollment reference records `BiometricContinuityCheck`; onboarding liveness and post-enrollment biological continuity remain separate evidence types.
- Biometric enrollment stores only a reference.
- Raw frames, captures, templates, embeddings, and liveness artifacts stay outside ordinary FEN facts; FEN stores provider references, assurance, result, provenance, challenge binding, and retention/consent policy references where needed.
- Failed or inconclusive liveness is represented as evidence that can drive retry, manual review, lockout, or recovery episodes rather than a silent onboarding denial.
- The onboarding narrative summarizes evidence without becoming the source of truth.

### Notes for Later Phases

The enrollment reference namespace may begin as vendor-owned and later become Reservatory-owned.

## Milestone 11: Ordinary Login Flow

### Purpose

Model routine login as fresh credential evidence.

### Minimal FEN Context

After onboarding, ordinary login does not re-establish identity from scratch. It produces fresh credential or device evidence.

### Build Target

Implement login fact creation:

- `CredentialAssertion`
- optional device reference
- authenticator type
- result
- assurance level

### Acceptance Criteria

- Successful and failed credential assertions can both be facts.
- Login does not mutate the subject object.
- Login evidence can later be used by policy evaluation.

### Notes for Later Phases

Platform biometrics are credential witnesses, not the biological-continuity substrate.

## Milestone 12: Step-Up Access Flow

### Purpose

Implement a sensitive action requiring fresh evidence.

### Minimal FEN Context

For actions such as complete record export, ordinary login may be insufficient. The system may require a recent credential assertion, fresh continuity check, risk evaluation, and policy decision.

### Build Target

Implement the complete-record export example:

- credential assertion
- continuity check
- risk evaluation
- policy evaluation
- access decision

### Acceptance Criteria

- The access decision records all relied-on facts.
- A stale continuity check can force step-up.
- A failed or inconclusive continuity check can produce denial or manual review.
- The action is auditable after the fact.

### Notes for Later Phases

This flow should be insensitive to which continuity provider produced the signed assertion.

## Milestone 13: Authority and Delegation

### Purpose

Represent one subject's authority to act for another.

### Minimal FEN Context

Authority is not a role label. It is a policy-constrained permission to act, supported by evidence-bearing facts.

### Build Target

Implement:

- `AuthorityRelationshipEstablished`
- `AuthorityRelationshipRevoked`
- actor subject
- target subject
- authority type
- permitted actions
- policy constraints
- validity period
- evidence reference

### Acceptance Criteria

- Caregivers authenticate as themselves.
- Delegated access relies on both the caregiver's own evidence and the delegation fact.
- Revocation preserves the original delegation fact for audit.
- Materialized authority state excludes revoked or expired delegations.

### Notes for Later Phases

Delegation should compose with future stronger continuity evidence without changing authority facts.

## Milestone 14: Recovery Flow

### Purpose

Represent account recovery as a FEN workflow.

### Minimal FEN Context

Recovery is not an out-of-band account reset. It is an evidence-bearing workflow that may include identity witnesses, continuity checks, manual review, and access decisions.

### Build Target

Implement:

- `AccountRecoveryEvent`
- recovery episode kind
- recovery evidence memberships
- recovery result
- assurance level
- manual review path

### Acceptance Criteria

- Recovery attempts are auditable.
- Approved, denied, and pending manual review outcomes are represented.
- Recovery can rely on multiple evidence facts.
- Recovery does not erase prior credential or device history.

### Notes for Later Phases

Recovery must work even when a device-bound biometric or platform credential is lost.

## Milestone 15: Contestation, Merge, and Split

### Purpose

Represent identity failures without invisible database edits.

### Minimal FEN Context

Wrong portal links, duplicate subjects, mistaken merges, stale witnesses, and changed authority are ordinary identity-system failures. FEN represents them through facts, statuses, episode relations, and dispute workflows.

### Build Target

Implement support for:

- contested clinical links
- contested payer links
- device revocation
- witness supersession
- duplicate-subject merge representation
- incorrectly merged subject split representation

### Acceptance Criteria

- Contested links remain in audit history but are excluded from high-risk reliance.
- Merges and splits are represented as authored changes.
- Prior facts remain auditable.
- Materialized state reflects contestation and supersession.

### Notes for Later Phases

More accurate continuity checks may later trigger merge, split, or dispute workflows.

## Milestone 16: Phase 1 Vendor Adapter

### Purpose

Implement the first concrete continuity provider behind the stable interface.

### Minimal FEN Context

The vendor is a source of identity-relevant events. It is not the owner of the identity graph.

### Build Target

Create a Phase 1 adapter that maps vendor responses into:

- provider enrollment reference
- signed or validated continuity assertion
- liveness/PAD outcome
- match result
- provider version metadata
- external references

### Acceptance Criteria

- Vendor code is isolated at the edge.
- FEN translation consumes canonical provider outputs.
- Vendor-native signatures are verified before provider outputs are trusted as FEN evidence.
- Vendor-specific IDs do not become primary FEN identity keys.
- Mocked vendor responses can drive onboarding and step-up flows.

### Notes for Later Phases

This adapter should be deletable or replaceable without changing core identity facts, policy, or materialized state.

If the vendor cannot emit FEN-native signed assertions, the adapter may either translate verified vendor evidence directly into FEN fact drafts or hand normalized evidence to a trusted gateway that re-signs the FEN-native continuity assertion profile.

## Milestone 17: Provider Swap Test

### Purpose

Prove the architecture is genuinely provider-portable.

### Minimal FEN Context

The same continuity event should produce the same canonical FEN fact shape even if the provider changes.

### Build Target

Add a second fake provider implementation with different response vocabulary but the same FEN-facing contract.

### Acceptance Criteria

- Two provider-shaped responses produce equivalent `BiometricContinuityCheck` facts.
- Policy evaluation does not know which provider was used except through provenance or external references.
- Existing onboarding and step-up tests pass with either provider.

### Notes for Later Phases

This is the rehearsal for moving from Phase 1 to Phase 2 and eventually Phase 3.

## Milestone 18: Security and Audit Pass

### Purpose

Check the implementation against the security model.

### Minimal FEN Context

Facts are the cryptographic unit. Operational representations support indexing and policy evaluation but do not contain full plaintext payloads. Derived objects inherit constraints from constituent facts.

For production persistence, this means fact payloads can be separately encrypted while append sequence, IDs, payload type, status, and materialization policy refs remain available as operational metadata. Rust remains responsible for policy-gated semantic materialization.

### Build Target

Review and test:

- raw biometric exclusion from FEN
- provenance on all identity facts
- relied-on facts in access decisions
- policy references in access decisions
- revocation behavior
- contested-link behavior
- operational/materialized view boundaries
- encrypted fact-payload envelopes and materialization policy refs
- associated-data binding so ciphertext cannot be moved across facts, subjects, policies, or append positions without detection

### Acceptance Criteria

- No raw biometric capture, template, or embedding is stored in ordinary FEN facts.
- Production storage can keep `FactPayload` values encrypted until Rust policy and key access permit materialization.
- Access decisions are explainable after the fact.
- Revocation prevents future reliance without deleting history.
- Materialized state can be rebuilt from source facts.
- Cached projections and derived views do not become plaintext bypasses around encrypted source facts.

### Notes for Later Phases

This is where Phase 3 requirements such as template isolation, enclave matching, and threshold governance remain clearly outside FEN but connected through policy and assertions.

See `FACT_ENCRYPTION_AND_MATERIALIZATION_CONTRACT.md` for the encrypted fact-payload storage and policy-gated materialization contract.

## Milestone 19: Phase 2 and Phase 3 Transition Notes

### Purpose

Document exactly what changes after Phase 1.

### Minimal FEN Context

FEN consumes signed continuity assertions. It does not own the capture implementation, template store, liveness engine, or matcher internals.

### Build Target

Create transition notes for:

- hosted vendor SDK
- Reservatory-owned enrollment reference namespace
- internal template storage
- confidential-computing matching
- template-protection schemes
- multimodal continuity
- PAD evaluation
- FAR/FRR monitoring
- threshold governance
- encrypted fact-payload persistence and policy-gated materialization

### Acceptance Criteria

- Each later-phase change is assigned to the continuity substrate, policy layer, or FEN graph.
- The notes identify what should not change in FEN.
- The notes identify new risks introduced by owning more of the substrate.
- The notes distinguish database storage access from semantic plaintext materialization.

### Notes for Later Phases

This milestone becomes the bridge from Phase 1 implementation to Phase 2 and Phase 3 planning.

## Product-State Addendum: Onboarding and Recovery Architecture

### Purpose

`Phoros Onboarding and Recovery Architecture.pdf` sharpens the product-facing stages around the same FEN commitments. It does not replace the original identity graph plan. It adds a practical product-state layer that should be derived from the fact graph:

```text
contact identity -> legal identity -> authenticator identity -> biological continuity
  -> recovery and authority policy -> clinical identity binding -> records import authority
```

The key rule is:

```text
account access is not the same as authority over health data
```

The implementation should therefore distinguish:

- contact-channel control
- legal identity proofing
- cryptographic account control
- biological-continuity enrollment and checks
- clinical record binding
- recovery policy
- authority state

Each stage should emit or rely on append-only facts, policy artifacts, provider references, and materialized projections. No stage should become a mutable `users.verified = true` shortcut.

## Milestone 20: Contact Channel Evidence

### Purpose

Represent claimed and verified communication channels as low-risk evidence without treating them as legal identity or account authority.

### Minimal FEN Context

Email and phone verification prove that the claimant controlled a declared channel at a time. They do not prove legal identity, biological continuity, clinical identity, or full account authority.

### Build Target

Add explicit contact-channel evidence support. The likely shape is either a dedicated fact payload such as:

```text
ContactChannelVerified {
  channel_type,
  channel_ref,
  verification_method,
  result,
  expires_at,
}
```

or a structured `IdentityWitnessRecorded` subtype with equivalent context.

The flow should support:

- claimed name, email, and phone as onboarding input
- email verification
- phone verification
- OTP or provider event refs
- expiration or reverification policy refs
- low-risk account status progression to `ContactVerified`

### Acceptance Criteria

- Verified email and phone are represented as evidence, not mutable subject fields.
- Contact evidence can support notifications and low-risk onboarding progression.
- Contact evidence cannot by itself restore full account authority.
- Failed or expired contact verification is representable and auditable.
- The materialized account-status view can distinguish `Pending` from `ContactVerified`.

### Notes for Later Phases

Contact channels may later become recovery inputs, but they should remain weak evidence unless combined with stronger witnesses and policy.

## Milestone 21: Legal Identity Proofing Provider Abstraction

### Purpose

Create a provider-neutral boundary for legal identity assertions. Persona is the default Phase 1 identity-proofing provider. The boundary should still support replacing Persona with ID.me, Socure, Jumio, Entrust/Onfido, Veriff, LexisNexis, government assertions, or provider-mediated legal identity assertions without changing FEN fact semantics.

### Minimal FEN Context

Legal identity proofing vendors provide evidence. They do not own `SubjectId`, account authority, biological continuity, clinical binding, or recovery decisions.

### Build Target

Define an internal legal identity proofing boundary and implement the first adapter as a Persona-shaped provider integration. The domain-facing boundary should look like:

```text
IdentityProofingProvider
  -> provider_name
  -> workflow_id
  -> asserted_attributes
  -> evidence_types
  -> verification_result
  -> assurance_level
  -> risk_signals
  -> timestamp
  -> expiration_policy
  -> audit_reference
```

Translate verified provider results into FEN facts:

- `IdentityWitnessRecorded` for government ID or legal identity verification
- `IdentityAttributeAsserted` for provider-asserted name, date of birth, address, or other attributes
- optional `RiskEvaluationEvent` for fraud or risk signals when the signal affects policy
- external refs for provider transaction, workflow, and audit identifiers

### Acceptance Criteria

- Persona is the default configured identity-proofing provider for Phase 1 onboarding.
- The Persona adapter verifies and normalizes Persona workflow results before FEN facts are created.
- Persona or another vendor can be replaced without changing FEN fact semantics.
- Vendor-native payloads, hosted-flow states, and account IDs stay at the adapter edge.
- Assertions include provenance, assurance, result, expiration or reverification policy, and audit refs.
- Failed, inconclusive, and expired identity proofing outcomes can drive retry or manual review without silent denial.
- Identity proofing remains separate from passkey enrollment and biological-continuity enrollment.

### Notes for Later Phases

Reusable identity-wallet providers such as ID.me may have different account ownership semantics than embedded verification providers. FEN should normalize the result as evidence either way.

## Milestone 22: Account and Authority Status Projections

### Purpose

Add product-facing derived statuses without turning those statuses into the source of truth.

### Minimal FEN Context

The current fact graph can already answer many identity questions, but product surfaces need concise states. Those states should be projections over facts, policies, and access decisions.

### Build Target

Define derived projections such as:

```text
AccountStatus:
  Pending
  ContactVerified
  LegalIdentityVerified
  Active
  Suspended
  Closed

AuthorityStatus:
  None
  Restricted
  Full
  Delegated
  Transferred
  Suspended
  Disputed
```

Derive them from:

- contact-channel evidence
- legal identity proofing evidence
- credential and device-binding facts
- recovery events
- continuity facts
- authority relationships
- access decisions
- disputes, revocations, suspensions, and policy constraints

### Acceptance Criteria

- Product status values are rebuildable from the fact graph.
- Restoring login does not automatically restore full authority.
- A user can have an active Phoros account before any clinical identity is linked.
- Suspended, disputed, or restricted authority can block high-risk actions while allowing limited recovery progress.
- Status projections point back to source facts or policy refs where possible.

### Notes for Later Phases

These statuses are product and policy conveniences. They should not replace `MaterializedIdentityState` or become mutable account rows.

## Milestone 23: Recovery Policy Configuration

### Purpose

Represent recovery policy setup during onboarding as durable, auditable governance rather than an afterthought.

### Minimal FEN Context

Recovery is not only credential replacement. It governs how account access and health-data authority are restored or transferred under uncertainty.

### Build Target

Add a recovery-policy artifact or fact family, likely one of:

```text
RecoveryPolicyConfigured
RecoveryPolicyUpdated
RecoveryDelegateAdded
RecoveryDelegateRevoked
```

The model should capture policy-governed references for:

- backup passkeys
- recovery codes or recovery-code sets, without storing raw codes in facts
- trusted recovery contacts
- provider-mediated recovery options
- caregiver or legal representative preferences
- escalation rules if biological continuity fails
- notification preferences for sensitive recovery events
- policy refs and effective windows

### Acceptance Criteria

- Recovery policy creation and updates are append-only or otherwise fully auditable.
- Raw recovery secrets are not stored in ordinary facts.
- Recovery policy changes can require step-up evidence and cite access-decision policy refs.
- The current recovery policy is derived from active policy facts or policy artifacts.
- Revoked recovery delegates and retired recovery methods remain in audit history.

### Notes for Later Phases

Some recovery policy definitions may fit better as `PolicyArtifact` values than `FactPayload` values. Choose the representation that preserves review, versioning, lifecycle, and citation semantics.

## Milestone 24: Restricted Authority During Recovery

### Purpose

Make the PDF's recovery distinction explicit: credential recovery, continuity recovery, and authority recovery are separate.

### Minimal FEN Context

A claimant may regain a login mechanism while biological continuity remains uncertain or authority is not yet fully restored. The system should represent this middle state instead of choosing between immediate denial and immediate full control.

### Build Target

Add recovery and authority events or policy outcomes that can represent:

- credential recovery requested
- contact channels reverified
- legal identity reverified
- biological continuity confirmed, uncertain, or conflicted
- new passkey bound
- authority restricted
- authority restored
- authority transferred
- manual or provider adjudication required

The event vocabulary may include:

```text
AuthorityRestricted
AuthorityRestored
AuthorityTransferred
BiologicalContinuityConfirmed
BiologicalContinuityUncertain
```

or equivalent fact/policy/access-decision shapes that preserve the same semantics.

### Acceptance Criteria

- Lost-device recovery can bind a new passkey without immediately permitting high-risk actions.
- Restricted authority blocks complete export, data transactions, caregiver changes, recovery delegate changes, clinical binding changes, biometric-reference deletion, and similar sensitive operations.
- Manual review and provider adjudication are auditable recovery episodes.
- Restored, limited, transferred, and denied authority outcomes are represented distinctly.
- Recovery access decisions cite relied-on facts and policy refs.

### Notes for Later Phases

This milestone is the main place where product safety and user experience meet. It should avoid trapping legitimate users while still preventing email, phone, or device control from becoming full health-data authority.

## Milestone 25: Durable Live-Presence Challenge Lifecycle

### Purpose

Move the current liveness ceremony boundary behind a durable server-issued challenge lifecycle.

### Minimal FEN Context

A live-presence ceremony is meaningful only when it is fresh, bound to a server challenge, bound to the expected device/app context, and one-time-use.

### Build Target

Add a durable `LivePresenceChallenge` or equivalent store with:

- challenge nonce
- intended workflow
- expected subject or account context when known
- expected device/app context
- issued-at and expires-at timestamps
- use state such as issued, used, expired, failed, or manual-review
- retry and manual-review policy refs
- retention policy refs
- provider callback or ceremony refs where appropriate

### Acceptance Criteria

- A liveness ceremony cannot be accepted without a matching live challenge.
- Expired, unknown, reused, wrong-device, and wrong-app challenges are rejected or translated into auditable rejection evidence.
- Failed or inconclusive ceremonies can open retry or manual-review paths.
- The challenge store does not contain raw video, biometric templates, embeddings, or vendor-native capture artifacts.
- The liveness provider remains replaceable.

### Notes for Later Phases

The same challenge discipline should later apply to recovery liveness and high-risk continuity checks.

## Milestone 26: Product-Facing Composed Onboarding HTTP Contract

### Purpose

Expose the composed onboarding path through a narrow production-facing contract.

### Minimal FEN Context

The current implementation has a smaller account/device HTTP surface and a richer in-memory composed identity onboarding command. Product onboarding needs the richer command behind HTTP and durable encrypted persistence.

### Build Target

Add an HTTP DTO and handler for the composed onboarding path carrying:

- contact-channel verification refs or already-verified contact evidence
- OIDC or IAM session evidence
- App Attest or device evidence
- legal identity proofing assertion
- live-presence ceremony result
- recovery policy setup input
- optional clinical or payer binding input
- client context

The handler should:

- parse and validate transport DTOs
- call verifier/provider boundaries
- call the shared composed onboarding command
- append through encrypted PostgreSQL workflow persistence
- replay through policy-gated materialization
- return a safe summary with account status, authority status, decision, active devices, and key fact IDs

### Acceptance Criteria

- HTTP and CLI remain thin adapters over shared commands.
- Public DTOs do not expose internal `FactPayload`, encrypted envelopes, provider-native payloads, or policy artifact internals.
- The response distinguishes active account state from full health-data authority.
- Failed or inconclusive liveness returns manual-review or restricted states rather than silently denying onboarding.
- The endpoint is covered by feature-gated HTTP and encrypted-persistence tests.

### Notes for Later Phases

After this endpoint is stable, the smallest iOS proof app can exercise real Keycloak, App Attest, identity proofing, and liveness evidence against the same contract.

## Milestone 27: Clinical Binding and Records Import Authorization States

### Purpose

Keep clinical identity binding separate from account activation and legal identity verification.

### Minimal FEN Context

A Phoros account can be active before a provider record is connected. Clinical binding answers whether the Phoros subject corresponds to a patient identity at a provider, payer, lab, imaging center, pharmacy, or other health-data source.

### Build Target

Expand product-state support for:

- `ClinicalIdentityLinked`
- `RecordsImportAuthorized`
- provider-mediated attestation
- patient portal connection
- EHR export authorization
- medical record number linkage
- payer identity matching
- lab, imaging, pharmacy, or other source binding
- signed clinical organization assertions

Use existing or extended fact shapes such as:

- `ClinicalIdentityLinkEstablished`
- `PayerIdentityLinkEstablished`
- access or consent decisions for records import
- dispute, revocation, supersession, and correction facts

### Acceptance Criteria

- Account activation does not require clinical binding.
- Clinical binding records institution, linked identifiers, consent or authorization refs, provenance, and active/disputed/revoked state.
- Provider, payer, portal, and MRN identifiers do not become subject identity truth.
- Records import authorization is policy-governed and auditable.
- Contested or rejected clinical bindings are excluded from high-risk reliance.

### Notes for Later Phases

This milestone prepares the bridge from identity proofing into patient-mediated record access without making any provider record the root of Phoros identity.

## Suggested Daily Working Rhythm

For each daily conversation:

1. Pick one milestone.
2. Restate only the FEN context needed for that milestone.
3. Create or modify the smallest coherent artifact.
4. Add acceptance checks or tests.
5. Record any Phase 2 or Phase 3 implications discovered during the work.

The goal is not to reproduce the FEN documents in every step. The goal is to keep the relevant part of the model present at the moment it matters.
