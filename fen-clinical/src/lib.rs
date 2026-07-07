//! Clinical fact family for the FEN graph.
//!
//! The identity crate owns subjects, accounts, devices, and the encrypted
//! envelope machinery. This crate owns the clinical fact family for the
//! claims-spine MVP: claims-derived fact payloads, clinical episodes, the
//! `clinical.*` payload labels, ingestion from payer claims feeds, the
//! claims timeline read model, and the completeness (missing-record)
//! engine. Clinical facts reference the same `SubjectId` the identity crate
//! owns: the account layer and the state layer are one graph.

pub mod schema;
