# Shared identity enrollment service

This crate hosts HTTP transport for bank-backed cs-mail enrollment and explicit
account changes. `identity-application` owns the application services and policy;
`identity-storage-postgres` implements their persistence ports. The existing identity-model workflow/mobile examples
are not its account-enrollment or recovery APIs. It uses the existing OIDC verifier
and SubjectId type, with a durable subject/login index and product binding repository.

The [version 1 contract](../docs/shared-identity-contract.md) defines ownership,
proof context, concurrency and failure rules. The cs-mail sibling integration suite
exercises two independent databases, restart/retry behavior and this HTTP router.

## Run the loopback host

Configure these environment variables, then run `cargo run -p identity-enrollment`:

| Variable | Value |
| --- | --- |
| IDENTITY_DATABASE_URL | Local PostgreSQL URL or Unix socket configuration |
| IDENTITY_ISSUER | Stable identity-service issuer identifier |
| IDENTITY_PRODUCT | Exact `cs-mail/<environment>` audience |
| OIDC_ISSUER | Trusted HTTPS OIDC issuer |
| OIDC_CLIENT_ID | Client audience for enrollment ID tokens |
| PRODUCT_KEY_FILE | Path to the cs-mail backend Ed25519 public key |
| BANK_KEY_FILE | Path to the bank-ownership adapter Ed25519 public key |
| DECISION_SECRET_FILE | Path to the identity decision Ed25519 secret seed |
| IDENTITY_PORT | Loopback listening port |

Key files contain JSON arrays of exactly 32 bytes. Supply secrets through protected
files; there are no defaults or built-in trusted keys. The ownership-attestation key
and cs-mail financial-verification key are separately configured authorities. A live
bank adapter must validate provider ownership evidence before issuing attestations;
this repository does not assume any particular bank vendor or fabricate that evidence.

The executable listens only on 127.0.0.1 and accepts a local database connection.
A production host terminates HTTPS at its proxy and configures request/rate limits.
Embedding hosts construct `PostgresEnrollmentStore` with a TLS-configured Client,
then assemble `identity_application::enrollment::EnrollmentService` with that store,
configuration, verifier, clock and `DecisionSigner`. Only the HTTP router remains
in this crate.
Requests are limited to 64 KiB and 32 concurrent operations. OIDC network calls are
time-bounded and do not follow redirects. PostgreSQL uses its asynchronous client, and the host supervises its connection task. No bearer token is stored or debug-derived
in the shared request DTOs.

POST `/v1/enrollment` accepts SignedRequest and returns Response. Its operations
are Enroll, Lookup, Confirm, ChangeIdentity and SecurityEvents. Each request must be signed by the configured
product backend. Enrollment additionally requires challenge-bound OIDC authentication,
a device-possession signature, and bank-ownership evidence. JSON responses carry a
signed eligible decision or an explicit non-eligible/error result; consumers must
verify the decision, not infer eligibility from HTTP status.

Migrations run transactionally under a migration lock and record schema version 1.
Each operation is idempotent by product and operation ID. Login resolution uses a
separate lock on the verified issuer/subject pair; database constraints prevent
concurrent duplicate product bindings. Reservations survive expiry and lost ACKs.
Confirmed decisions remain replayable, but expired uncommitted enrollment requires
explicit review; no automatic reservation release or subject merge is implemented.

Recovery, bank rebinding and same-realm login linking use separate `ChangeIntent`
variants. Ordered signed security events let the product invalidate authority and
reconcile changes. Signing-key IDs and product trust windows support deliberate
rotation. Recovery requires the existing login and fresh bank ownership; losing
both requires a separate reviewed process. Phoros policy, arbitrary cross-issuer
linking, subject merge/split and global cross-product broadcasts remain separate
work. This service does not authorize healthcare access.

The cs-mail development schema uses fresh databases. Unbound account provisioning
and account compatibility modes have been removed. Identity-model recovery simulations
and fixture renderers are test/example support only; they are not production APIs.
