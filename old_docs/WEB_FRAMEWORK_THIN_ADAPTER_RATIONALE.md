# Web Framework Thin Adapter Rationale

## Core Argument

The production web framework should be chosen for how well it lets the HTTP layer stay thin, boring, and replaceable.

For Phoros/Reservatory, the important question is not which Rust framework is fastest, most expressive, or most feature-rich in isolation. The important question is:

```text
Which framework lets us keep the web layer from becoming the identity model?
```

FEN owns the typed fact graph, evidence translation, append-only workflow semantics, policy citation, encrypted materialization, replay, and explanation. The web framework should own transport mechanics: routing, request parsing, body limits, timeouts, tracing, response shaping, health checks, and operational middleware.

That boundary is central to the FEN philosophy:

```text
provider/substrate produces evidence
  -> FEN verifies/translates evidence
  -> FEN appends facts with provenance
  -> FEN replays/materializes state through policy
  -> FEN explains decisions from relied-on facts
```

The HTTP runtime should help deliver that flow without turning it into ordinary account/profile CRUD.

## The FEN-Specific Risk

Most web frameworks make it natural to model an application as mutable resources:

```text
POST   /users
PATCH  /users/{id}
PUT    /devices/{id}
DELETE /relationships/{id}
```

That shape is familiar, productive, and often correct for ordinary applications. It is dangerous for FEN because it encourages the current projection to become the conceptual source of truth.

In FEN, a device is not simply deleted. A revocation fact is appended, provenance is preserved, and active state is rebuilt by replay. A verified email is not simply patched onto a user record. Credential/session evidence is verified, translated into facts, and later cited or ignored according to policy. A relationship is not merely updated. Authority, delegation, revocation, and disputes are represented through auditable facts and episode membership.

The risk is not that a framework will force CRUD. The risk is that framework ergonomics will make CRUD feel like the obvious local move when the FEN-correct move is evidence submission plus append and replay.

## What The Web Layer Should Own

The web layer should own:

- HTTP method and path routing
- request body size limits
- request ID creation and propagation
- structured transport logging
- response status and JSON shaping
- coarse transport-level authentication plumbing
- CORS and compression when needed
- timeout and rate-limit middleware
- readiness and health endpoints
- dependency injection for repositories, verifiers, key resolvers, and policy selectors

These concerns are important, but they are not identity semantics.

## What The Web Layer Should Not Own

The web layer should not own:

- constructing FEN facts directly
- deciding that an OIDC claim is identity truth
- deciding that an App Attest assertion proves subject continuity
- applying FEN policy as ordinary HTTP authorization middleware
- choosing relied-on facts for access decisions
- bypassing encrypted materialization gates
- mutating projections as if they were source records
- exposing internal `FactPayload`, encrypted envelope, or policy artifact shapes as public API contracts

Route handlers should call FEN commands and workflow services. They should not become miniature workflow engines.

## Endpoint Vocabulary

FEN-friendly endpoint names should describe evidence submission, workflow initiation, decision requests, and safe read projections:

```text
POST /mobile/onboarding
POST /continuity/challenges
POST /continuity/assertions
POST /identity/evidence
POST /access/decisions
GET  /subjects/{id}/summary
GET  /subjects/{id}/explanations/{decision_id}
```

These names keep attention on the actual semantics:

- evidence is submitted
- facts are appended
- policy decides whether facts may be relied on
- materialized state is rebuilt
- explanations cite provenance

CRUD-like endpoints are not forbidden, but they should be treated as public conveniences over append-only facts, not as direct mutation semantics:

```text
DELETE /devices/{id}
```

If such a route exists, its implementation should still append a device-revocation fact and replay state. It should not delete the historical evidence of the device binding.

## Axum

Axum is the preferred first production runtime because it is a good shell around a framework-neutral FEN core.

Its strengths for this project are:

- route handlers can remain small adapter functions
- request parsing can stay explicit through extractors
- application state can hold assembled dependencies without becoming the domain model
- Tower middleware provides transport concerns such as tracing, timeouts, limits, and request IDs
- the same Tower ecosystem can later compose with lower-level Hyper or internal Tonic/gRPC services

The main Axum risk is that its ergonomics can make handlers feel like a natural place for business logic. That should be resisted with a strict rule:

```text
Axum handlers adapt HTTP to FEN commands.
FEN commands own facts, workflow semantics, policy, replay, and materialization.
```

Axum is the best fit if the project wants a boring HTTP boundary with strong middleware composition and minimal framework ideology.

## Actix Web

Actix Web is a credible second choice. It is mature, pragmatic, high-performance, and full-featured.

Its strengths for this project are:

- strong production web-service ergonomics
- mature routing and middleware
- practical deployment history
- good support for common server concerns

Its risk is framework gravity. Actix can make the web application feel like the application, with FEN demoted into a data/model layer underneath. Sessions, app data, scopes, guards, and middleware are all useful, but they can quietly encourage meanings like:

```text
logged-in web session == FEN subject truth
device resource exists == active device binding
relationship row deleted == authority revoked
```

Those meanings are wrong for FEN unless they are backed by fact history, policy, and replay.

Actix Web is a good choice if the team already prefers it, but it needs an especially firm adapter boundary.

## Poem

Poem is attractive if OpenAPI and client contract generation become the dominant near-term concern.

Its strengths for this project are:

- first-class API documentation path through `poem-openapi`
- clear request/response schema modeling
- useful ergonomics for client/server contract alignment

Its risk is schema leakage. The public API schema must not accidentally become the FEN ontology. Internal facts, encrypted envelopes, materialization policy refs, and projection internals should not be published as client-facing types simply because they are easy to derive or document.

Poem is a good fit only if public API DTOs are curated carefully:

```text
external API schema != internal FEN schema
```

The external contract should expose mobile onboarding requests, challenge issuance, attestation submissions, access-decision requests, and safe summaries. It should not expose the internal fact graph as a convenient remote object model.

## Guardrails For Any Framework

The framework choice should be paired with architectural guardrails:

- keep the existing framework-neutral command and handler shape
- use explicit edge DTOs for public APIs
- keep FEN types out of generated public OpenAPI unless intentionally exposed
- keep authorization middleware transport-oriented
- make FEN access decisions inside the domain/service layer
- require fact append for revocation, correction, delegation, recovery, and dispute flows
- make materialized reads trace back to source fact IDs where appropriate
- keep encrypted fact materialization behind policy and key-access checks
- make route tests assert behavior through commands, not internal route convenience

These guardrails matter more than the exact framework.

## Recommendation

Use Axum for the first production runtime.

The reason is not that Axum has the most features. The reason is that Axum is well suited to being a thin, explicit HTTP shell around an application core that already has its own semantics.

The desired shape is:

```text
Axum route
  -> parse HTTP request into edge DTO
  -> select runtime dependencies
  -> call FEN command/workflow service
  -> map result into safe HTTP response
```

The undesired shape is:

```text
Axum route
  -> inspect claims/session/device rows
  -> construct facts inline
  -> mutate current projection
  -> return state as if it were truth
```

The first shape preserves FEN. The second shape slowly turns FEN into a conventional account/profile service.

The framework should stay boring so the identity model can stay honest.
