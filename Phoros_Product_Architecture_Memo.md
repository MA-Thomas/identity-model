# Phoros Product Architecture

## Patient-Controlled Healthcare Communications and Workspace

## Executive Summary

Phoros is a patient-controlled healthcare communications platform built
around a simple idea: every individual should possess a persistent,
programmable healthcare endpoint that remains with them throughout life.

The endpoint is not an email account. It is a communications identity
through which providers, insurers, ROI vendors, employers, and future
healthcare systems communicate with the patient. Email is the initial
compatibility layer because it is universally supported today. Over
time, additional transports such as Direct Secure Messaging, FHIR, and
provider APIs terminate at the same endpoint.

Internally, all communications are transformed into typed FEN facts that
power workflows, AI, search, and patient applications.

The primary user experience is a native desktop application built with a
shared Rust domain model.

------------------------------------------------------------------------

# Vision

Healthcare communication is fragmented across portals, paper mail,
email, SMS, phone calls, and proprietary APIs. Patients have no
persistent communications identity independent of employers, insurers,
or providers.

Phoros provides a permanent endpoint that patients control. Healthcare
organizations communicate with this endpoint regardless of transport.
Phoros converts those communications into structured semantic state
while preserving complete provenance.

------------------------------------------------------------------------

# Design Principles

-   Patient-controlled and portable.
-   Communications transport is independent of internal representation.
-   Email is transport, not the product.
-   Original communications are provenance, not application state.
-   FEN facts are the canonical semantic representation.
-   All transports produce the same typed event model.
-   Shared Rust domain logic across cloud and clients.

------------------------------------------------------------------------

# Transport Layer

Supported transports ultimately include:

-   SMTP
-   Direct Secure Messaging
-   FHIR
-   Secure uploads
-   Provider-specific APIs
-   Future healthcare protocols

Every transport terminates at the same logical endpoint.

------------------------------------------------------------------------

# Ingestion Layer

Responsibilities:

-   Receive communications.
-   Verify sender where applicable.
-   Persist immutable originals.
-   Parse documents and metadata.
-   Retrieve secure ROI download links when authorized.
-   Produce immutable ingestion events.

Typical inputs include:

-   Bills
-   Explanation of Benefits
-   Medical records
-   Appointment notifications
-   Prior authorization correspondence
-   ROI download links

------------------------------------------------------------------------

# Semantic Core

Every ingestion event becomes typed FEN facts.

The original communication remains permanently available as provenance
while applications operate on structured healthcare objects.

------------------------------------------------------------------------

# Workflow Engine

The workflow engine consumes FEN events to:

-   classify documents
-   reconcile bills and EOBs
-   detect duplicates
-   track deadlines
-   request records
-   orchestrate AI assistance
-   manage consent and sharing

------------------------------------------------------------------------

# Application Architecture

    Transport Layer
            │
    Ingestion Layer
            │
    FEN Semantic Core
            │
    Workflow Engine
            │
    Application Surfaces
            ├── Desktop
            ├── Mobile
            └── Browser

## Desktop (Primary)

The desktop application is the patient's healthcare workspace.

Primary activities:

-   reviewing medical records
-   managing bills
-   comparing EOBs
-   interacting with AI
-   approving requests
-   longitudinal search
-   consent management

The desktop experience is optimized for document-heavy workflows.

## Mobile (Companion)

The mobile application complements the desktop.

Primary responsibilities:

-   notifications
-   biometric authentication
-   camera capture
-   approvals
-   quick document review
-   identity verification
-   concise AI interactions

## Browser

A browser experience may be provided for convenience, onboarding, and
occasional access but is not the flagship product.

------------------------------------------------------------------------

# Technology Stack

Core language:

-   Rust

Desktop:

-   Tauri
-   React or Svelte frontend

Cloud:

-   Rust
-   Tokio
-   Axum

Shared domain:

-   FEN crates
-   Typed Rust models
-   Shared validation and workflow logic

The goal is to maximize reuse of domain logic across cloud services,
desktop, and mobile.

------------------------------------------------------------------------

# Communications Model

SMTP is the initial compatibility layer.

Direct Secure Messaging provides secure healthcare messaging where
available.

FHIR provides structured HTTPS-based integration.

Each transport feeds the identical ingestion pipeline. The remainder of
the system is transport-agnostic.

------------------------------------------------------------------------

# User Experience

Users do not manage an inbox.

They manage healthcare objects:

-   Bills
-   Records
-   EOBs
-   Tasks
-   Requests
-   Appointments

Incoming communications simply update the workspace.

------------------------------------------------------------------------

# Long-Term Direction

Phoros is not an email client.

It is a patient-controlled healthcare communications endpoint coupled to
a semantic health workspace.

The endpoint accepts communications through multiple transports. The
semantic core provides a unified representation. The desktop application
becomes the primary environment in which patients understand, manage,
and act on their healthcare.
