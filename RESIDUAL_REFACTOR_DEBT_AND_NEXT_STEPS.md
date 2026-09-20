# Remaining domain work — 2026-09-20

The previous August audit described a combined identity/runtime crate and a
synthetic delegation flow. Those interfaces have been replaced. The current
implementation separates `identity-model`, `identity-adapters`,
`identity-application`, `identity-storage-postgres` and `identity-server`. The
application owns enrollment/change policy, signing and audited disclosure;
`identity-enrollment` owns HTTP transport and executable composition. PostgreSQL
implements the application's atomic persistence ports.

Implemented boundaries include proposal-bound delegation, explicit evaluation time,
separate history and authorization snapshots, purpose/consent-bound identifier
read permits, durable plaintext encoding, explicit account-change ceremonies,
ordered security events and signing-key identifiers. SQL migrations have one owner.
Onboarding no longer decrypts existing history to construct its response.

Remaining work is concentrated in product and deployment integration:

- A Phoros account/employee/communications product, ingestion of immutable originals,
  and desktop synchronization have not been implemented by this cs-mail update.
- Hosts must authenticate principals, load current consent/policy/witness state,
  collect real bank/Apple/liveness evidence, and schedule notification reconciliation.
  The mobile demonstration host still composes explicit development providers.
- Recovery currently requires access to the existing OIDC login and fresh bank
  ownership. Recovery after losing both requires a separately governed review
  ceremony; this implementation does not silently bypass either witness.
- Login linking covers two fresh tokens in the configured issuer realm. Arbitrary
  cross-issuer federation and subject merge/split are not implemented.
- Account-change operations and security versions are product-scoped. A global
  subject-security broadcast across future products requires a separate subscription
  policy and audience-specific notifications.
- Existing generic workflow constructors still have long argument lists. The
  established strict Clippy gate covers identity-application, identity-contract and identity-enrollment;
  workspace-wide `-D warnings` also surfaces older constructor/lint debt.
- No new test cases were added in this update. Existing suites and PostgreSQL checks
  validate regressions, but do not replace dedicated coverage of the newly added
  account-change and disclosure APIs.

The current schema and wire changes require fresh databases and a coordinated
release with cs-mail. There is no compatibility path for the superseded schema,
feature flags, synthetic delegation APIs or billing-owned account closure.

The PostgreSQL encryption-aware façade and its permissive replay methods were
removed in the application cutover. `EncryptedWorkflowService` requires an opaque
disclosure permit and rechecks it after audit waits before key access/decryption.
The earlier source interfaces are not retained as aliases. Existing tests were
adapted, with no additional test cases. Database uniqueness, ownership/version
locks, atomic writes and durable audit remain required adapter guarantees.
