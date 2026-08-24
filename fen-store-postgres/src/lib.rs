//! PostgreSQL persistence for the payload-neutral FEN encrypted store.
//!
//! `fen-store` remains dependency-light and contains no database runtime.
//! This crate owns the durable row mapping, family-scoped envelope queries,
//! append conflict translation, and materialization-audit writes. The frozen
//! `identity_facts` table name is retained for compatibility with deployed
//! migrations; its contents are not identity-family-specific.

mod repository;
mod rows;

pub use repository::*;
pub use rows::*;

pub const FEN_ENCRYPTED_FACTS_MIGRATION_SQL: &str =
    include_str!("../migrations/0001_fen_encrypted_facts.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresMigration {
    pub name: &'static str,
    pub sql: &'static str,
}

pub const FEN_STORE_POSTGRES_MIGRATIONS: [PostgresMigration; 1] = [PostgresMigration {
    name: "0001_fen_encrypted_facts",
    sql: FEN_ENCRYPTED_FACTS_MIGRATION_SQL,
}];
