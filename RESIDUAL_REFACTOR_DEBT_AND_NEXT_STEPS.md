# Remaining domain work — 2026-09-20

The [ten Rust-domain design principles](../cs-mail/docs/rust-domain-principles.md)
are the shared architectural reference for identity-model and cs-mail. The link
assumes sibling repository checkouts.

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
- Device-key recovery requires the existing product OIDC login and fresh bank
  ownership. The configured provider owns authentication-method management and
  recovery to the same external subject; deployments must supply that process.
  Additional recovery review remains separate work.
- Product login bindings now enforce one durable login per product and subject.
  Second-login linking has been removed. Phoros must eventually resolve an existing
  cs-mail subject through its own ceremony plus proof of cs-mail account control;
  it must not infer that association from an OIDC match or caller-supplied subject ID.
  See the [product identity model](../cs-mail/docs/product-identity-model.md).
  Subject merge/split remains unimplemented.
- Account-change operations and security versions are product-scoped. A global
  subject-security broadcast across future products requires a separate subscription
  policy and audience-specific notifications.
- Existing generic workflow constructors still have long argument lists. The
  established strict Clippy gate covers identity-application, identity-contract and identity-enrollment;
  workspace-wide `-D warnings` also surfaces older constructor/lint debt.
- No new test cases were added in this update. Existing suites and PostgreSQL checks
  validate regressions, but do not replace dedicated coverage of the newly added
  account-change and disclosure APIs.

Shared-enrollment schema version 2 rejects the old login-alias schema.
The current schema and wire changes require fresh databases and a coordinated
release with cs-mail. There is no compatibility path for the superseded schema,
feature flags, synthetic delegation APIs or billing-owned account closure.

The PostgreSQL encryption-aware façade and its permissive replay methods were
removed in the application cutover. `EncryptedWorkflowService` requires an opaque
disclosure permit and rechecks it after audit waits before key access/decryption.
The earlier source interfaces are not retained as aliases. Existing tests were
adapted, with no additional test cases. Database uniqueness, ownership/version
locks, atomic writes and durable audit remain required adapter guarantees.
