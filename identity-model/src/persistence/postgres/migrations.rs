pub const IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0001_identity_encrypted_facts.sql");
pub const IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0002_identity_workflow_transactions.sql");
pub const IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0003_identity_app_attest_key_state.sql");
pub const IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0004_identity_live_presence_challenges.sql");
pub const IDENTITY_APP_ATTEST_KEY_REGISTRATION_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0005_identity_app_attest_key_registration.sql");
pub const HEALTH_ECON_RECONCILIATION_RULE_ARTIFACTS_MIGRATION_SQL: &str =
    include_str!("../../../migrations/0006_health_econ_reconciliation_rule_artifacts.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresMigration {
    pub name: &'static str,
    pub sql: &'static str,
}

pub const IDENTITY_POSTGRES_MIGRATIONS: [PostgresMigration; 6] = [
    PostgresMigration {
        name: "0001_identity_encrypted_facts",
        sql: IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0002_identity_workflow_transactions",
        sql: IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0003_identity_app_attest_key_state",
        sql: IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0004_identity_live_presence_challenges",
        sql: IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0005_identity_app_attest_key_registration",
        sql: IDENTITY_APP_ATTEST_KEY_REGISTRATION_MIGRATION_SQL,
    },
    PostgresMigration {
        name: "0006_health_econ_reconciliation_rule_artifacts",
        sql: HEALTH_ECON_RECONCILIATION_RULE_ARTIFACTS_MIGRATION_SQL,
    },
];

pub const IDENTITY_POSTGRES_MIGRATIONS_SQL: [&str; 6] = [
    IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL,
    IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL,
    IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL,
    IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL,
    IDENTITY_APP_ATTEST_KEY_REGISTRATION_MIGRATION_SQL,
    HEALTH_ECON_RECONCILIATION_RULE_ARTIFACTS_MIGRATION_SQL,
];
