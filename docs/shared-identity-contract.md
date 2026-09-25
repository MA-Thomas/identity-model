# Shared identity and product enrollment, version 1

Status: bank-backed cs-mail enrollment and account changes. The September addendum
below defines device-key recovery, bank rebinding and security events. Phoros
policy, subject merge/split and arbitrary cross-issuer federation remain separate.

See the canonical [product identity model](../../cs-mail/docs/product-identity-model.md)
for one durable login per product and the future ceremony-bound reuse of a subject.

## Ownership

The identity service owns SubjectId, durable product-login bindings, product-scoped
opaque subject references, evidence policy, and durable binding reservations. cs-mail
owns AccountId, PrincipalRef, persona ownership, account authority, and billing/member
associations. Billing continues to own funding records and financial obligations.
The public contract contains no global SubjectId, medical data, bank credentials, or
mutable identity profile. Email is never a subject key.

## Trust boundaries

Only a configured OIDC verifier establishes an external (issuer, subject). The service
resolves that pair within the configured product to its persisted SubjectId; an
enrollment request cannot select one. Matching a login in another product does not
authorize subject adoption. Each product has one durable login per subject, with
multiple authentication methods managed by the configured provider. Method changes
and provider recovery retain its issuer/subject pair and the product binding.
OIDC audience, authorized party, timestamps, and challenge nonce must all match.
A configured bank attestation authority asserts ownership for that login and operation,
including the digest of the exact financial evidence accepted by cs-mail. An attestation
is not proof of universal person uniqueness. A configured product key authenticates
service requests; the proposed device proves possession of its private key.

The service signs a versioned decision over issuer, product/environment audience,
operation, account, challenge, device key, complete local enrollment digest, financial
evidence digest, scoped subject reference, binding version, policy, evidence reference,
issue time and expiry. The consumer pins issuer/key/audience/policy and validates every
binding before constructing a private verified-decision capability. Times are Unix
seconds; domain timestamps in cs-mail are converted explicitly where necessary.

## State and concurrency

cs-mail first reserves local persona, initial key, billing/member and funding-token ownership, and persists independent account/principal IDs with an authentication challenge. The stable enrollment and its expiring attempts are separate concepts. Each authenticated attempt has a durable eligible, denied or review-required outcome. Exact retries return the recorded outcome.

After the challenge expires, an uncommitted local enrollment can renew its challenge and timestamps while retaining every ownership ID and input. Fresh OIDC, bank and device evidence is required. The service permits renewed eligibility only for the same stable enrollment and reserved product subject. A review or denial cannot be overridden by the product: the bank authority must issue new evidence. This deliberately prevents overlapping attempts and can require waiting for the current challenge lifetime (at most 15 minutes).

The service atomically resolves/creates a subject and reserves a unique product binding independently of those attempts. Competing account/subject bindings fail. Reservations are never reassigned on timeout. Confirmed bindings accept exact replay and confirmation, but no new enrollment attempt.

cs-mail commits product account, principal, identity binding, persona, initial authority, billing association and confirmation outbox together through its independent account repository. The memory and PostgreSQL adapters share activation validation against pinned trust and the backend activation timestamp. They accept signed decisions, not cached verified capabilities.

Confirmation is idempotent and runs outside the local transaction. Batches continue after individual delivery failures, schedule transient retries and retain permanent rejection codes for intervention. Administrative retry preserves the original signed decision. Lost acknowledgements cannot create a second account; exact committed decisions remain replayable after expiry. Reconciliation returns the stored eligible, review, denied or missing outcome explicitly.

The shared service makes cs-mail real-person uniqueness a best-effort policy. Exact
product-login ownership and product binding uniqueness are transactional constraints. Phoros
strict person resolution is not inferred from bank evidence and cannot enroll under
this policy.

## Account ownership and authorization

The development schema is initialized fresh. There is no preservation or conversion
path for earlier development accounts. Every cs-mail account requires its own principal
and product-scoped shared identity binding; incomplete enrollment remains a separate
operation. Persona ownership has one source of truth. User keys resolve exclusively
from account authority. Missing ownership or keys reject authorization. Provider and
scheduler keys remain relationship-owned. Accepted commands retain receipt-time
authority for audit and replay.

Fixture constructors, rendering and synthetic onboarding/recovery workflows live in the development-only `identity-test-support` crate. The production facade that fabricated a government-ID witness has been removed. Public session entry points verify tokens before
calling internal workflow composition. Mobile workflow inputs do not resolve
product subject ownership or implement Phoros enrollment.

## Verification gates

1. Contract: cross-product, wrong operation/device/bank digest, invalid/future/expired
   proof and unknown protocol version are rejected.
2. Service: subject resolution is durable; duplicate/concurrent reservations converge;
   evidence and session policy fail closed; no fixture recovery path is reachable.
3. Accounts: independent IDs, immutable binding, unique persona ownership, account-wide
   revocation, required identity fields, and immutable receipt-time authority.
4. Bridge: atomic rollback, restart, duplicate delivery, lost acknowledgement and
   conflicting retry tests against PostgreSQL, plus existing workspace regression tests.

## Deployment boundary

This change supplies an authenticated service application API and a transport adapter.
Production hosts must configure real OIDC and bank attestation authorities, TLS,
secrets, request limits and database roles. There is deliberately no built-in bank
provider or default trusted signing key. A bank provider adapter must authenticate its
upstream evidence before signing this contract. Local sibling path dependencies are
for joint development; release builds must pin the reviewed contract package/revision.

## Runtime ownership

`identity-application` owns policy and orchestration; `identity-storage-postgres` implements atomic persistence ports; `identity-enrollment` owns HTTP and host composition. PostgreSQL is asynchronous; the executable owns and supervises the connection task. Synchronous OIDC verification runs on the blocking pool without database locks. HTTP request capacity remains owned until processing finishes even if the caller disconnects. Freshness is checked after verification and again after database waits. Internal errors preserve their sources; HTTP replies expose protocol error codes only.

One database connection per service instance intentionally serializes short local transactions. Multiple instances coordinate through database locks and constraints. A connection pool is a future capacity choice, not a prerequisite for correctness. The executable remains a loopback development host; no deployment or real identity-provider configuration is implied.


## Account changes and security events (September update)

`SignedRequest` also carries `ChangeIdentity` and `SecurityEvents`.
`ChangeIntent` binds a product/account/subject, expected security version, fresh
challenge, replacement key or bank digest, and a typed change kind. Recovery needs
the existing authenticated login, fresh bank ownership and replacement-key
possession. Bank rebinding requires the current key. Both operations require the
existing login belonging to that product and preserve the subject and login binding.
There is no second-login linking operation. Provider login recovery and product
operational-key recovery are different processes.

Changes return a signed security event. Events carry a key identifier and a
contiguous product security version. A product verifies issuer, audience, subject,
account, version and trust window before applying the event. Product use is
suspended, and recovery revokes old keys. Closed product accounts stay closed.
Financial obligations remain intact. An authenticated financial bank record must
match a bank-rebinding event before the product advances that event's cursor.

Signing uses `identity/enrollment-decision/v2` for key-identified decisions and
`identity/security-event/v1` for notifications. The previous decision signing
format is not accepted. Trusted decision keys have explicit validity windows;
rotation is an operator configuration operation with an expected revision.

Shared-enrollment schema version 2 is a fresh baseline; version 1 is rejected
without conversion. Product logins are unique by both product/subject and
product/external-login pair. Enrollment foreign keys bind the login and scoped
reference to the same subject. Tokens are verified in memory and are not
stored in event records. Login identifiers are omitted from product notifications.
Real provider verification and product-specific consent/role policies remain host
integration responsibilities.
