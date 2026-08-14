use identity_model::*;

mod common;
use common::*;

const KEY_ID: &str = "fact-key-postgres";
#[cfg(feature = "postgres-adapter")]
const POSTGRES_URL_ENV: &str = "IDENTITY_MODEL_POSTGRES_URL";
#[cfg(feature = "postgres-adapter")]
static LIVE_POSTGRES_MIGRATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn postgres_migration_pins_encrypted_fact_and_audit_table_shape() {
    let sql = IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL;

    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_facts"));
    assert!(sql.contains("append_sequence BIGINT NOT NULL UNIQUE"));
    assert!(sql.contains("committed_at TEXT NOT NULL"));
    assert!(sql.contains("fact_id TEXT PRIMARY KEY"));
    assert!(sql.contains("occurred_start TEXT NOT NULL"));
    assert!(sql.contains("payload_type TEXT NOT NULL"));
    assert!(sql.contains("materialization_policy_refs TEXT[] NOT NULL"));
    assert!(sql.contains("nonce BYTEA NOT NULL"));
    assert!(sql.contains("ciphertext BYTEA NOT NULL"));
    assert!(sql.contains("identity_facts_subject_append_idx"));
    assert!(sql.contains("identity_facts_policy_refs_idx"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_fact_materialization_audit"));
    assert!(sql.contains("fact_ids TEXT[] NOT NULL"));
    assert!(sql.contains("outcome TEXT NOT NULL"));
    assert!(!sql.contains("fact_payload"));
}

/// Pins the identity family's closed label set: `FactPayloadType::ALL` covers
/// every variant exactly once and every label round-trips. Sibling families
/// scope shared-envelope-table queries by exactly this list, so a variant
/// missing from `ALL` would silently drop out of identity replay.
#[test]
fn payload_type_labels_are_closed_and_stable() {
    assert_eq!(FactPayloadType::ALL.len(), 30);

    let mut labels: Vec<&str> = Vec::new();
    for payload_type in FactPayloadType::ALL {
        let label = payload_type.as_str();
        assert_eq!(
            FactPayloadType::from_str_label(label),
            Some(*payload_type),
            "every label must parse back to its variant"
        );
        assert!(
            !label.contains('.'),
            "identity labels are unnamespaced; dotted namespaces belong to sibling families"
        );
        labels.push(label);
    }
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), FactPayloadType::ALL.len(), "labels must be unique");
}

/// The envelope table is shared across payload families, so a row carrying a
/// sibling family's label (e.g. `health_econ.*`) must be a hard error for
/// identity-typed row parsing — family scoping belongs in the query, and rows
/// outside every family's label set must never be silently skipped.
#[test]
fn identity_row_parsing_rejects_sibling_family_labels() {
    let envelope = StoredEncryptedFact {
        append_sequence: 0,
        transaction_id: PersistenceTransactionId("tx-cross-family".to_string()),
        committed_at: Timestamp("2026-07-08T00:00:00Z".to_string()),
        fact_id: FactId::new("fact-cross-family"),
        subject_id: SubjectId::new("subject-cross-family"),
        occurred_at: TemporalAnchor::Point(Timestamp("2026-07-08T00:00:00Z".to_string())),
        payload_type: FactPayloadType::SubjectCreated,
        status: FactStatus::Active,
        materialization_policy_refs: vec![PolicyRef::new("identity-materialization-policy@v1")],
        encryption: FactEncryptionMetadata::deterministic_test(KEY_ID, b"nonce-1".to_vec()),
        ciphertext: vec![1, 2, 3],
    };

    let mut row = PostgresEncryptedFactRow::try_from_envelope(&envelope)
        .expect("identity envelope should map onto the shared row shape");
    assert_eq!(row.payload_type, "subject_created");
    assert_eq!(
        row.clone().try_into_envelope(),
        Ok(envelope),
        "identity labels stay parseable through the shared row"
    );

    row.payload_type = "health_econ.claim".to_string();
    assert_eq!(
        row.try_into_envelope(),
        Err(PostgresAdapterError::UnknownPayloadType(
            "health_econ.claim".to_string()
        ))
    );
}

#[test]
fn postgres_migration_pins_workflow_transaction_table_shape() {
    let sql = IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL;

    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_workflow_transactions"));
    assert!(sql.contains("transaction_kind IN ('workflow_slice', 'episode_composition')"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_episodes"));
    assert!(sql.contains("episode_id TEXT PRIMARY KEY"));
    assert!(sql.contains("subject_id TEXT NOT NULL"));
    assert!(sql.contains("status_payload JSONB NOT NULL"));
    assert!(sql.contains("authored_by JSONB NOT NULL"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_episode_memberships"));
    assert!(sql.contains("membership_id TEXT PRIMARY KEY"));
    assert!(sql.contains("fact_id TEXT NOT NULL REFERENCES identity_facts(fact_id)"));
    assert!(sql.contains("episode_id TEXT NOT NULL REFERENCES identity_episodes(episode_id)"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_episode_relations"));
    assert!(sql.contains("relation_id TEXT PRIMARY KEY"));
    assert!(
        sql.contains("target_episode_id TEXT NOT NULL REFERENCES identity_episodes(episode_id)")
    );
    assert!(sql.contains("identity_episode_relations_target_idx"));
    assert!(!sql.contains("fact_payload"));
}

#[test]
fn postgres_migration_pins_app_attest_key_state_table_shape() {
    let sql = IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL;

    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_app_attest_keys"));
    assert!(sql.contains("key_id TEXT PRIMARY KEY"));
    assert!(sql.contains("environment TEXT NOT NULL CHECK"));
    assert!(sql.contains("status TEXT NOT NULL CHECK"));
    assert!(sql.contains("last_sign_count BIGINT NOT NULL CHECK"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_app_attest_challenge_nonces"));
    assert!(sql.contains("PRIMARY KEY (key_id, challenge_nonce)"));
    assert!(sql.contains("REFERENCES identity_app_attest_keys(key_id) ON DELETE CASCADE"));
    assert!(sql.contains("identity_app_attest_keys_device_idx"));
    assert!(sql.contains("identity_app_attest_challenge_nonces_seen_idx"));
}

#[test]
fn postgres_migration_pins_app_attest_key_registration_table_shape() {
    let sql = IDENTITY_APP_ATTEST_KEY_REGISTRATION_MIGRATION_SQL;

    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_app_attest_key_registrations"));
    assert!(sql.contains("key_id TEXT PRIMARY KEY"));
    assert!(sql.contains("public_key_bytes BYTEA NOT NULL"));
    assert!(sql.contains("attestation_challenge_nonce TEXT NOT NULL"));
    assert!(sql.contains("attestation_format TEXT NOT NULL CHECK"));
    assert!(sql.contains("'apple-app-attest'"));
    assert!(sql.contains("identity_app_attest_key_registrations_device_idx"));
    assert!(sql.contains("identity_app_attest_key_registrations_registered_idx"));
}

#[test]
fn postgres_migration_pins_live_presence_challenge_table_shape() {
    let sql = IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL;

    assert!(sql.contains("CREATE TABLE IF NOT EXISTS identity_live_presence_challenges"));
    assert!(sql.contains("challenge_id TEXT PRIMARY KEY"));
    assert!(sql.contains("challenge_nonce TEXT NOT NULL UNIQUE"));
    assert!(sql.contains("intended_workflow TEXT NOT NULL CHECK"));
    assert!(sql.contains("'mobile_identity_onboarding'"));
    assert!(sql.contains("'account_recovery'"));
    assert!(sql.contains("'sensitive_action_step_up'"));
    assert!(sql.contains("expected_subject_id TEXT"));
    assert!(sql.contains("expected_device_ref TEXT"));
    assert!(sql.contains("expected_team_id TEXT"));
    assert!(sql.contains("expected_bundle_id TEXT"));
    assert!(sql.contains("expected_app_id TEXT"));
    assert!(sql.contains("expected_environment TEXT CHECK"));
    assert!(sql.contains("issued_at TEXT NOT NULL"));
    assert!(sql.contains("expires_at TEXT NOT NULL"));
    assert!(sql.contains("status_kind IN ('issued', 'used', 'expired', 'failed', 'manual_review')"));
    assert!(sql.contains("status_payload JSONB NOT NULL DEFAULT '{}'::jsonb"));
    assert!(sql.contains("retry_policy_refs TEXT[] NOT NULL"));
    assert!(sql.contains("manual_review_policy_refs TEXT[] NOT NULL"));
    assert!(sql.contains("retention_policy_refs TEXT[] NOT NULL"));
    assert!(sql.contains("identity_live_presence_challenges_subject_idx"));
    assert!(sql.contains("identity_live_presence_challenges_device_idx"));
    assert!(sql.contains("identity_live_presence_challenges_status_idx"));
    assert!(sql.contains("identity_live_presence_challenges_expires_idx"));
}

#[test]
fn postgres_migration_registry_pins_ordered_versions() {
    assert_eq!(
        IDENTITY_POSTGRES_MIGRATIONS
            .iter()
            .map(|migration| migration.name)
            .collect::<Vec<_>>(),
        vec![
            "0001_identity_encrypted_facts",
            "0002_identity_workflow_transactions",
            "0003_identity_app_attest_key_state",
            "0004_identity_live_presence_challenges",
            "0005_identity_app_attest_key_registration",
            "0006_health_econ_reconciliation_rule_artifacts"
        ]
    );
    assert_eq!(
        IDENTITY_POSTGRES_MIGRATIONS_SQL,
        [
            IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL,
            IDENTITY_WORKFLOW_TRANSACTIONS_MIGRATION_SQL,
            IDENTITY_APP_ATTEST_KEY_STATE_MIGRATION_SQL,
            IDENTITY_LIVE_PRESENCE_CHALLENGES_MIGRATION_SQL,
            IDENTITY_APP_ATTEST_KEY_REGISTRATION_MIGRATION_SQL,
            HEALTH_ECON_RECONCILIATION_RULE_ARTIFACTS_MIGRATION_SQL,
        ]
    );
}

#[test]
fn postgres_app_attest_key_state_row_round_trips_labels() {
    let state = AppAttestKeyState {
        key_id: "app-attest-key-postgres".to_string(),
        team_id: "TEAMID1234".to_string(),
        bundle_id: "com.fen.identity".to_string(),
        app_id: "TEAMID1234.com.fen.identity".to_string(),
        environment: AppAttestEnvironment::Production,
        device_ref: "iphone-postgres-device".to_string(),
        status: AppAttestKeyStateStatus::Revoked,
        registered_at: ts("2026-05-29T00:05:00Z"),
        last_asserted_at: ts("2026-05-29T00:06:00Z"),
        last_sign_count: 42,
        last_challenge_nonce: Some("nonce-postgres-state".to_string()),
    };

    let row = PostgresAppAttestKeyStateRow::try_from_key_state(&state)
        .expect("key state should map to postgres row");
    assert_eq!(row.environment, "production");
    assert_eq!(row.status, "revoked");
    assert_eq!(row.last_sign_count, 42);

    assert_eq!(
        row.try_into_key_state()
            .expect("postgres row should restore key state"),
        state
    );
}

#[test]
fn postgres_app_attest_key_registration_row_round_trips_labels_and_key_bytes() {
    let registration = AppAttestKeyRegistration {
        key_id: "app-attest-key-registration-postgres".to_string(),
        team_id: "TEAMID1234".to_string(),
        bundle_id: "com.fen.identity".to_string(),
        app_id: "TEAMID1234.com.fen.identity".to_string(),
        environment: AppAttestEnvironment::Production,
        device_ref: "iphone-registration-postgres".to_string(),
        public_key_bytes: vec![4, 1, 2, 3],
        registered_at: ts("2026-05-29T00:05:00Z"),
        attestation_challenge_nonce: "registration-nonce-postgres".to_string(),
        attestation_format: "apple-app-attest".to_string(),
    };

    let row = PostgresAppAttestKeyRegistrationRow::try_from_registration(&registration)
        .expect("registration should map to postgres row");
    assert_eq!(row.environment, "production");
    assert_eq!(row.public_key_bytes, vec![4, 1, 2, 3]);
    assert_eq!(row.attestation_format, "apple-app-attest");

    assert_eq!(
        row.try_into_registration()
            .expect("postgres row should restore registration"),
        registration
    );
}

#[test]
fn postgres_live_presence_challenge_row_round_trips_status_context_and_labels() {
    let config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Production,
    );
    let mut challenge = LivePresenceChallenge::onboarding(
        id("live-presence-challenge-postgres"),
        "live-presence-nonce-postgres",
        Some(id("subject-live-presence-postgres")),
        Some("iphone-live-presence-postgres".to_string()),
        Some(LivePresenceExpectedAppContext::from_app_attest_config(
            &config,
        )),
        ts("2026-05-29T00:05:00Z"),
        ts("2026-05-29T00:06:00Z"),
    );
    challenge.status = LivePresenceChallengeStatus::ManualReview {
        referred_at: ts("2026-05-29T00:05:30Z"),
        reason: LivePresenceChallengeManualReviewReason::PresentationAttackInconclusive,
        provider_event_id: Some("liveness-event-postgres".to_string()),
    };
    challenge.retry_policy_refs = vec![id("live-presence-retry@v1")];
    challenge.manual_review_policy_refs = vec![id("live-presence-review@v1")];
    challenge.retention_policy_refs = vec![id("live-presence-retention@v1")];

    let row = PostgresLivePresenceChallengeRow::try_from_challenge(&challenge)
        .expect("challenge should map to postgres row");
    assert_eq!(row.challenge_id, "live-presence-challenge-postgres");
    assert_eq!(row.challenge_nonce, "live-presence-nonce-postgres");
    assert_eq!(row.intended_workflow, "mobile_identity_onboarding");
    assert_eq!(
        row.expected_subject_id,
        Some("subject-live-presence-postgres".to_string())
    );
    assert_eq!(
        row.expected_device_ref,
        Some("iphone-live-presence-postgres".to_string())
    );
    assert_eq!(row.expected_team_id, Some("TEAMID1234".to_string()));
    assert_eq!(row.expected_bundle_id, Some("com.fen.identity".to_string()));
    assert_eq!(
        row.expected_app_id,
        Some("TEAMID1234.com.fen.identity".to_string())
    );
    assert_eq!(row.expected_environment, Some("production".to_string()));
    assert_eq!(row.status_kind, "manual_review");
    assert_eq!(
        row.status_payload,
        PostgresLivePresenceChallengeStatusPayload::ManualReview {
            referred_at: "2026-05-29T00:05:30Z".to_string(),
            reason: "presentation_attack_inconclusive".to_string(),
            provider_event_id: Some("liveness-event-postgres".to_string())
        }
    );

    assert_eq!(
        row.clone()
            .try_into_challenge()
            .expect("postgres row should restore challenge"),
        challenge
    );

    let mut invalid_status_payload = row.clone();
    invalid_status_payload.status_kind = "used".to_string();
    invalid_status_payload.status_payload = PostgresLivePresenceChallengeStatusPayload::Issued;
    assert_eq!(
        invalid_status_payload.try_into_challenge(),
        Err(PostgresAdapterError::InvalidLivePresenceChallengeStatusPayload)
    );

    let mut unknown_workflow = row;
    unknown_workflow.intended_workflow = "future_workflow".to_string();
    assert_eq!(
        unknown_workflow.try_into_challenge(),
        Err(PostgresAdapterError::UnknownLivePresenceChallengeWorkflow(
            "future_workflow".to_string()
        ))
    );
}

#[test]
fn postgres_encrypted_fact_row_round_trips_without_changing_aad_or_materialization() {
    let key = active_key();
    let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact(
        "fact-postgres-round-trip",
        id("subject-postgres-round-trip"),
    );
    let envelope = encrypted_envelope(&fact, 42, materialization_policy_refs(), &key, &encryptor);
    let original_aad = canonical_encrypted_fact_associated_data(&envelope);

    let row = PostgresEncryptedFactRow::try_from_envelope(&envelope)
        .expect("envelope should map to postgres row");
    assert_eq!(row.append_sequence, 42);
    assert_eq!(row.fact_id, "fact-postgres-round-trip");
    assert_eq!(row.subject_id, "subject-postgres-round-trip");
    assert_eq!(row.occurred_kind, "point");
    assert_eq!(row.payload_type, "clinical_identity_link_established");
    assert_eq!(row.status_kind, "active");
    assert_eq!(row.encryption_algorithm, "deterministic_test");
    assert_eq!(row.aad_version, "v1");
    assert_eq!(row.ciphertext, envelope.ciphertext);

    let restored = row
        .try_into_envelope()
        .expect("postgres row should reconstruct envelope");
    assert_eq!(restored, envelope);
    assert_eq!(
        canonical_encrypted_fact_associated_data(&restored),
        original_aad
    );
    assert_eq!(
        materialize_encrypted_fact(
            &restored,
            &allowed_policy(materialization_policy_refs()),
            &resolver,
            &encryptor,
        )
        .expect("restored row should materialize"),
        fact
    );
}

#[test]
fn postgres_row_round_trips_period_time_and_superseded_status_payload() {
    let key = active_key();
    let encryptor = DeterministicTestFactEncryptor::new();
    let mut fact = sensitive_fact(
        "fact-postgres-superseded",
        id("subject-postgres-superseded"),
    );
    fact.occurred_at = TemporalAnchor::Period(TimeInterval {
        start: ts("2026-05-29T00:00:00Z"),
        end: ts("2026-05-29T00:10:00Z"),
    });
    fact.status = FactStatus::Superseded {
        superseded_by: system_author(),
        superseded_at: TemporalAnchor::Point(ts("2026-05-29T00:11:00Z")),
        replaced_by: Some(id("fact-postgres-replacement")),
        reason: SupersessionReason::AdministrativeCorrection,
    };
    let envelope = encrypted_envelope(&fact, 5, materialization_policy_refs(), &key, &encryptor);

    let row =
        PostgresEncryptedFactRow::try_from_envelope(&envelope).expect("envelope should map to row");
    assert_eq!(row.occurred_kind, "period");
    assert_eq!(row.occurred_end, Some("2026-05-29T00:10:00Z".to_string()));
    assert_eq!(row.status_kind, "superseded");
    assert!(matches!(
        row.status_payload,
        PostgresFactStatusPayload::Superseded { ref reason, .. }
            if reason == "administrative_correction"
    ));

    let restored = row
        .try_into_envelope()
        .expect("row should restore exact envelope status");
    assert_eq!(restored, envelope);
}

#[test]
fn postgres_rows_sort_by_append_sequence_for_replay() {
    let key = active_key();
    let encryptor = DeterministicTestFactEncryptor::new();
    let subject_id: SubjectId = id("subject-postgres-replay");
    let first = fact(
        "fact-postgres-first",
        subject_id.clone(),
        FactPayload::IdentityWitnessRecorded {
            witness_type: IdentityWitnessType::GovernmentIdVerification,
            target_subject_id: subject_id.clone(),
            assurance_level: AssuranceLevel::High,
            evidence_ref: None,
            expires_at: None,
            context: IdentityWitnessContext::default(),
        },
    );
    let second = fact(
        "fact-postgres-second",
        subject_id,
        FactPayload::DeviceBindingEstablished {
            device_ref: "device-postgres".to_string(),
            authenticator_type: AuthenticatorType::Passkey,
            assurance_level: AssuranceLevel::Medium,
        },
    );
    let mut rows = vec![
        PostgresEncryptedFactRow::try_from_envelope(&encrypted_envelope(
            &second,
            2,
            materialization_policy_refs(),
            &key,
            &encryptor,
        ))
        .expect("second row should build"),
        PostgresEncryptedFactRow::try_from_envelope(&encrypted_envelope(
            &first,
            1,
            materialization_policy_refs(),
            &key,
            &encryptor,
        ))
        .expect("first row should build"),
    ];

    PostgresEncryptedFactRow::sort_for_replay(&mut rows);

    assert_eq!(
        rows.iter()
            .map(|row| row.fact_id.as_str())
            .collect::<Vec<_>>(),
        vec!["fact-postgres-first", "fact-postgres-second"]
    );
    assert_eq!(
        rows.into_iter()
            .map(|row| row.try_into_envelope().expect("row should restore").fact_id)
            .collect::<Vec<_>>(),
        vec![id("fact-postgres-first"), id("fact-postgres-second")]
    );
}

#[test]
fn postgres_workflow_rows_round_trip_typed_episode_membership_and_relation_values() {
    let author = system_author();
    let transaction_id: PersistenceTransactionId = id("tx-postgres-workflow");
    let committed_at = ts("2026-05-29T00:03:00Z");
    let episode = StoredProblemEpisode {
        append_sequence: 10,
        transaction_id: transaction_id.clone(),
        committed_at: committed_at.clone(),
        episode: ProblemEpisode {
            id: id("episode-postgres-workflow"),
            subject_id: id("subject-postgres-workflow"),
            episode_kind: EpisodeKind::AccessAuthorizationWorkflow,
            label: "Export authorization".to_string(),
            problem_code: Some(CodedValue {
                system: CodingSystem::Local,
                code: "identity-access".to_string(),
                display: "Identity access workflow".to_string(),
            }),
            status: EpisodeStatus::Resolved(ResolutionInfo {
                at: Some(ApproximateDate {
                    date: Date("2026-05-29".to_string()),
                    precision: DatePrecision::Day,
                }),
            }),
            onset: Some(ApproximateDate {
                date: Date("2026-05-29".to_string()),
                precision: DatePrecision::Day,
            }),
            authored_by: author.clone(),
            authored_at: ts("2026-05-29T00:00:00Z"),
            notes: Some("policy-approved export".to_string()),
        },
    };
    let membership = StoredEpisodeMembership {
        append_sequence: 11,
        transaction_id: transaction_id.clone(),
        committed_at: committed_at.clone(),
        membership: EpisodeMembership {
            id: id("membership-postgres-workflow"),
            fact_id: id("fact-postgres-workflow"),
            episode_id: episode.episode.id.clone(),
            role: FactRole::ContinuityWitness,
            asserted_by: author.clone(),
            asserted_at: TemporalAnchor::Period(TimeInterval {
                start: ts("2026-05-29T00:01:00Z"),
                end: ts("2026-05-29T00:02:00Z"),
            }),
            status: MembershipStatus::Retracted {
                retracted_by: author.clone(),
                retracted_at: TemporalAnchor::Point(ts("2026-05-29T00:03:00Z")),
            },
        },
    };
    let relation = StoredEpisodeRelation {
        append_sequence: 12,
        transaction_id: transaction_id.clone(),
        committed_at,
        relation: EpisodeRelation {
            id: id("relation-postgres-workflow"),
            source_episode_id: episode.episode.id.clone(),
            target_episode_id: id("episode-postgres-parent"),
            relation_type: EpisodeRelationType::PartOf,
            asserted_by: author.clone(),
            asserted_at: TemporalAnchor::Point(ts("2026-05-29T00:04:00Z")),
            status: EpisodeRelationStatus::Retracted {
                retracted_by: author,
                retracted_at: TemporalAnchor::Point(ts("2026-05-29T00:05:00Z")),
            },
        },
    };

    let episode_row =
        PostgresProblemEpisodeRow::try_from_stored(&episode).expect("episode row should build");
    assert_eq!(episode_row.append_sequence, 10);
    assert_eq!(episode_row.episode_kind, "access_authorization_workflow");
    assert_eq!(episode_row.status_kind, "resolved");
    assert!(matches!(
        episode_row.status_payload,
        PostgresEpisodeStatusPayload::Resolved { at: Some(_) }
    ));
    assert_eq!(
        episode_row
            .try_into_stored()
            .expect("episode row should restore"),
        episode
    );

    let membership_row = PostgresEpisodeMembershipRow::try_from_stored(&membership)
        .expect("membership row should build");
    assert_eq!(membership_row.role, "continuity_witness");
    assert_eq!(membership_row.asserted_kind, "period");
    assert_eq!(membership_row.status_kind, "retracted");
    assert_eq!(
        membership_row
            .try_into_stored()
            .expect("membership row should restore"),
        membership
    );

    let relation_row =
        PostgresEpisodeRelationRow::try_from_stored(&relation).expect("relation row should build");
    assert_eq!(relation_row.relation_type, "part_of");
    assert_eq!(relation_row.status_kind, "retracted");
    assert_eq!(
        relation_row
            .try_into_stored()
            .expect("relation row should restore"),
        relation
    );
}

#[test]
fn postgres_workflow_rows_sort_by_append_sequence_for_replay() {
    let first = PostgresProblemEpisodeRow::try_from_stored(&stored_episode(
        "episode-postgres-sort-first",
        1,
    ))
    .expect("first episode row should build");
    let second = PostgresProblemEpisodeRow::try_from_stored(&stored_episode(
        "episode-postgres-sort-second",
        2,
    ))
    .expect("second episode row should build");
    let mut rows = vec![second, first];

    PostgresProblemEpisodeRow::sort_for_replay(&mut rows);

    assert_eq!(
        rows.into_iter()
            .map(|row| row.episode_id)
            .collect::<Vec<_>>(),
        vec![
            "episode-postgres-sort-first".to_string(),
            "episode-postgres-sort-second".to_string()
        ]
    );
}

#[test]
fn postgres_workflow_rows_reject_invalid_storage_labels_and_negative_sequence() {
    let stored_episode = stored_episode("episode-postgres-invalid", 1);
    let episode_row =
        PostgresProblemEpisodeRow::try_from_stored(&stored_episode).expect("row should build");

    let mut negative_episode_sequence = episode_row.clone();
    negative_episode_sequence.append_sequence = -1;
    assert_eq!(
        negative_episode_sequence.try_into_stored(),
        Err(PostgresAdapterError::NegativeAppendSequence)
    );

    let mut unknown_episode_kind = episode_row.clone();
    unknown_episode_kind.episode_kind = "future_episode_kind".to_string();
    assert_eq!(
        unknown_episode_kind.try_into_stored(),
        Err(PostgresAdapterError::UnknownEpisodeKind(
            "future_episode_kind".to_string()
        ))
    );

    let mut invalid_episode_status = episode_row;
    invalid_episode_status.status_kind = "active".to_string();
    invalid_episode_status.status_payload = PostgresEpisodeStatusPayload::Resolved { at: None };
    assert_eq!(
        invalid_episode_status.try_into_stored(),
        Err(PostgresAdapterError::InvalidEpisodeStatusPayload)
    );

    let membership = StoredEpisodeMembership {
        append_sequence: 2,
        transaction_id: id("tx-postgres-workflow-invalid"),
        committed_at: ts("2026-05-29T00:03:00Z"),
        membership: episode_membership(
            id("membership-postgres-invalid"),
            id("fact-postgres-invalid"),
            id("episode-postgres-invalid"),
            FactRole::IdentityWitness,
            system_author(),
            ts("2026-05-29T00:01:00Z"),
        ),
    };
    let mut unknown_role =
        PostgresEpisodeMembershipRow::try_from_stored(&membership).expect("row should build");
    unknown_role.role = "future_role".to_string();
    assert_eq!(
        unknown_role.try_into_stored(),
        Err(PostgresAdapterError::UnknownFactRole(
            "future_role".to_string()
        ))
    );

    let relation = StoredEpisodeRelation {
        append_sequence: 3,
        transaction_id: id("tx-postgres-workflow-invalid"),
        committed_at: ts("2026-05-29T00:03:00Z"),
        relation: episode_relation(
            id("relation-postgres-invalid"),
            id("episode-postgres-invalid"),
            id("episode-postgres-parent-invalid"),
            EpisodeRelationType::PartOf,
            system_author(),
            ts("2026-05-29T00:01:00Z"),
        ),
    };
    let mut unknown_relation_type =
        PostgresEpisodeRelationRow::try_from_stored(&relation).expect("row should build");
    unknown_relation_type.relation_type = "future_relation".to_string();
    assert_eq!(
        unknown_relation_type.try_into_stored(),
        Err(PostgresAdapterError::UnknownEpisodeRelationType(
            "future_relation".to_string()
        ))
    );
}

#[test]
fn postgres_audit_row_round_trips_without_payload_or_ciphertext_fields() {
    let event = FactMaterializationAuditEvent {
        subject_id: id("subject-postgres-audit"),
        fact_ids: vec![id("fact-postgres-audit")],
        materialization_policy_refs: materialization_policy_refs(),
        evaluated_policy_refs: materialization_policy_refs(),
        caller: Some("support-agent-1".to_string()),
        purpose: Some("identity-support-review".to_string()),
        requested_at: Some(ts("2026-05-29T00:05:00Z")),
        outcome: FactMaterializationAuditOutcome::DecryptionFailed,
        error: Some(FactMaterializationError::AuthenticationFailed),
    };

    let row = PostgresMaterializationAuditRow::from_event(&event);
    assert_eq!(row.subject_id, "subject-postgres-audit");
    assert_eq!(row.fact_ids, vec!["fact-postgres-audit".to_string()]);
    assert_eq!(row.outcome, "decryption_failed");
    assert_eq!(row.error, Some("authentication_failed".to_string()));

    let restored = row
        .try_into_event()
        .expect("audit row should restore event");
    assert_eq!(restored, event);
}

#[test]
fn postgres_row_rejects_invalid_storage_labels_and_negative_sequence() {
    let key = active_key();
    let encryptor = DeterministicTestFactEncryptor::new();
    let fact = sensitive_fact("fact-postgres-invalid", id("subject-postgres-invalid"));
    let envelope = encrypted_envelope(&fact, 1, materialization_policy_refs(), &key, &encryptor);
    let row = PostgresEncryptedFactRow::try_from_envelope(&envelope).expect("row should build");

    let mut negative_sequence = row.clone();
    negative_sequence.append_sequence = -1;
    assert_eq!(
        negative_sequence.try_into_envelope(),
        Err(PostgresAdapterError::NegativeAppendSequence)
    );

    let mut unknown_payload = row.clone();
    unknown_payload.payload_type = "future_payload".to_string();
    assert_eq!(
        unknown_payload.try_into_envelope(),
        Err(PostgresAdapterError::UnknownPayloadType(
            "future_payload".to_string()
        ))
    );

    let mut invalid_time = row;
    invalid_time.occurred_end = Some("2026-05-29T00:01:00Z".to_string());
    assert_eq!(
        invalid_time.try_into_envelope(),
        Err(PostgresAdapterError::InvalidTemporalAnchor)
    );
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_app_attest_key_state_store_rejects_replay_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL App Attest state test; set {POSTGRES_URL_ENV} to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;
        let suffix = live_test_suffix();
        let key_id = format!("app-attest-key-live-postgres-{suffix}");
        cleanup_live_app_attest_key_state(repository.pool(), &key_id).await;
        let store = PostgresAppAttestKeyStateStore::from_pool(repository.pool().clone());
        let config = AppAttestClientConfig::ios_app(
            "TEAMID1234",
            "com.fen.identity",
            AppAttestEnvironment::Development,
        );

        let first = postgres_app_attest_assertion(
            &config,
            &key_id,
            "iphone-live-postgres-app-attest",
            "nonce-live-postgres-1",
            7,
        );
        let first_state = store
            .record_verified_app_attest_assertion_async(&first)
            .await
            .expect("first App Attest state should persist");
        assert_eq!(first_state.last_sign_count, 7);
        assert!(store
            .app_attest_challenge_nonce_seen_async(&key_id, "nonce-live-postgres-1")
            .await
            .expect("nonce lookup should succeed"));
        assert_eq!(
            store
                .record_verified_app_attest_assertion_async(&first)
                .await,
            Err(AppAttestAssertionVerificationError::ChallengeReplay)
        );

        let stale_sign_count = postgres_app_attest_assertion(
            &config,
            &key_id,
            "iphone-live-postgres-app-attest",
            "nonce-live-postgres-2",
            7,
        );
        assert_eq!(
            store
                .record_verified_app_attest_assertion_async(&stale_sign_count)
                .await,
            Err(AppAttestAssertionVerificationError::SignCountNotAdvanced)
        );

        let second = postgres_app_attest_assertion(
            &config,
            &key_id,
            "iphone-live-postgres-app-attest",
            "nonce-live-postgres-3",
            8,
        );
        let second_state = store
            .record_verified_app_attest_assertion_async(&second)
            .await
            .expect("advanced sign count should update durable state");
        assert_eq!(second_state.last_sign_count, 8);
        assert_eq!(
            second_state.last_challenge_nonce,
            Some("nonce-live-postgres-3".to_string())
        );

        store
            .revoke_app_attest_key_async(&key_id)
            .await
            .expect("registered key should be revocable");
        let after_revoke = postgres_app_attest_assertion(
            &config,
            &key_id,
            "iphone-live-postgres-app-attest",
            "nonce-live-postgres-4",
            9,
        );
        assert_eq!(
            store
                .record_verified_app_attest_assertion_async(&after_revoke)
                .await,
            Err(AppAttestAssertionVerificationError::KeyRevoked)
        );

        cleanup_live_app_attest_key_state(repository.pool(), &key_id).await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_app_attest_key_registration_store_round_trips_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL App Attest registration test; set {POSTGRES_URL_ENV} to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;
        let suffix = live_test_suffix();
        let key_id = format!("app-attest-registration-live-postgres-{suffix}");
        cleanup_live_app_attest_key_state(repository.pool(), &key_id).await;
        let store = PostgresAppAttestKeyStateStore::from_pool(repository.pool().clone());
        let registration = AppAttestKeyRegistration {
            key_id: key_id.clone(),
            team_id: "TEAMID1234".to_string(),
            bundle_id: "com.fen.identity".to_string(),
            app_id: "TEAMID1234.com.fen.identity".to_string(),
            environment: AppAttestEnvironment::Development,
            device_ref: "iphone-live-postgres-registration".to_string(),
            public_key_bytes: vec![4, 7, 8, 9],
            registered_at: ts("2026-05-29T00:05:00Z"),
            attestation_challenge_nonce: "registration-nonce-live-postgres".to_string(),
            attestation_format: "apple-app-attest".to_string(),
        };

        let stored = store
            .record_app_attest_key_registration_async(&registration)
            .await
            .expect("registration should persist");
        assert_eq!(stored, registration);
        assert_eq!(
            store
                .app_attest_key_registration_async(&key_id)
                .await
                .expect("lookup should succeed"),
            Some(registration.clone())
        );
        assert_eq!(
            store
                .record_app_attest_key_registration_async(&AppAttestKeyRegistration {
                    device_ref: "different-device".to_string(),
                    ..registration.clone()
                })
                .await,
            Err(AppAttestAssertionVerificationError::KeyContextMismatch)
        );

        cleanup_live_app_attest_key_state(repository.pool(), &key_id).await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_repository_exercises_append_query_duplicates_and_audit_when_url_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!("skipping live PostgreSQL adapter test; set {POSTGRES_URL_ENV} to run it");
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;

        let suffix = live_test_suffix();
        let subject_id: SubjectId = id(&format!("subject-live-postgres-{suffix}"));
        let first_fact_id = format!("fact-live-postgres-{suffix}-first");
        let second_fact_id = format!("fact-live-postgres-{suffix}-second");
        let duplicate_sequence_fact_id = format!("fact-live-postgres-{suffix}-duplicate-sequence");
        let workflow_fact_id = format!("fact-live-postgres-{suffix}-workflow");
        let workflow_episode_id = format!("episode-live-postgres-{suffix}-workflow");
        let workflow_membership_id = format!("membership-live-postgres-{suffix}-workflow");
        let workflow_transaction_id = format!("tx-live-postgres-{suffix}-workflow");

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &first_fact_id,
                &second_fact_id,
                &duplicate_sequence_fact_id,
                &workflow_fact_id,
            ],
            &[&workflow_episode_id],
            &[&workflow_membership_id],
            &[&workflow_transaction_id],
        )
        .await;

        let first_sequence = next_live_postgres_append_sequence(repository.pool()).await;
        let second_sequence = first_sequence + 1;
        let duplicate_fact_sequence = first_sequence + 2;
        let workflow_fact_sequence = first_sequence + 3;
        let workflow_episode_sequence =
            next_live_postgres_episode_append_sequence(repository.pool()).await;
        let workflow_membership_sequence =
            next_live_postgres_membership_append_sequence(repository.pool()).await;

        let key = active_key();
        let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
        let encryptor = DeterministicTestFactEncryptor::new();
        let first_fact = sensitive_fact(&first_fact_id, subject_id.clone());
        let second_fact = fact(
            &second_fact_id,
            subject_id.clone(),
            FactPayload::IdentityWitnessRecorded {
                witness_type: IdentityWitnessType::GovernmentIdVerification,
                target_subject_id: subject_id.clone(),
                assurance_level: AssuranceLevel::High,
                evidence_ref: None,
                expires_at: None,
                context: IdentityWitnessContext::default(),
            },
        );

        let first_envelope = encrypted_envelope(
            &first_fact,
            first_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        let second_envelope = encrypted_envelope(
            &second_fact,
            second_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );

        repository
            .append_encrypted_fact(&first_envelope)
            .await
            .expect("first encrypted fact should append");

        let duplicate_fact_envelope = encrypted_envelope(
            &first_fact,
            duplicate_fact_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        assert_eq!(
            repository
                .append_encrypted_fact(&duplicate_fact_envelope)
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateFactId
            ))
        );

        let duplicate_sequence_fact =
            sensitive_fact(&duplicate_sequence_fact_id, subject_id.clone());
        let duplicate_sequence_envelope = encrypted_envelope(
            &duplicate_sequence_fact,
            first_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        assert_eq!(
            repository
                .append_encrypted_fact(&duplicate_sequence_envelope)
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateAppendSequence
            ))
        );

        repository
            .append_encrypted_fact(&second_envelope)
            .await
            .expect("second encrypted fact should append");

        let subject_envelopes = repository
            .encrypted_facts_for_subject(&subject_id)
            .await
            .expect("subject query should return encrypted facts");
        assert_eq!(
            subject_envelopes,
            vec![first_envelope.clone(), second_envelope.clone()]
        );

        let live_fact_ids: Vec<FactId> = repository
            .all_encrypted_facts()
            .await
            .expect("all-facts replay query should succeed")
            .into_iter()
            .filter(|envelope| envelope.subject_id == subject_id)
            .map(|envelope| envelope.fact_id)
            .collect();
        assert_eq!(live_fact_ids, vec![id(&first_fact_id), id(&second_fact_id)]);

        let materialized = materialize_encrypted_facts(
            &subject_envelopes,
            &allowed_policy(materialization_policy_refs()),
            &resolver,
            &encryptor,
        )
        .expect("live rows should materialize after policy approval");
        assert_eq!(materialized, vec![first_fact, second_fact]);

        repository
            .record_materialization_audit_event(&FactMaterializationAuditEvent {
                subject_id: subject_id.clone(),
                fact_ids: vec![id(&first_fact_id), id(&second_fact_id)],
                materialization_policy_refs: materialization_policy_refs(),
                evaluated_policy_refs: materialization_policy_refs(),
                caller: Some("live-postgres-test".to_string()),
                purpose: Some("adapter-verification".to_string()),
                requested_at: Some(ts("2026-05-29T00:06:00Z")),
                outcome: FactMaterializationAuditOutcome::Succeeded,
                error: None,
            })
            .await
            .expect("audit insert should succeed");

        let audit_rows: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM identity_fact_materialization_audit
            WHERE subject_id = $1
              AND outcome = 'succeeded'
              AND caller = 'live-postgres-test'
            "#,
        )
        .bind(&subject_id.0)
        .fetch_one(repository.pool())
        .await
        .expect("audit verification query should succeed");
        assert_eq!(audit_rows, 1);

        let workflow_fact = fact(
            &workflow_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let workflow_envelope = encrypted_envelope(
            &workflow_fact,
            workflow_fact_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        let workflow_episode = StoredProblemEpisode {
            append_sequence: workflow_episode_sequence,
            transaction_id: id(&workflow_transaction_id),
            committed_at: ts("2026-05-29T00:07:00Z"),
            episode: access_authorization_episode(
                id(&workflow_episode_id),
                subject_id.clone(),
                SensitiveAction::ViewRecord,
                system_author(),
                ts("2026-05-29T00:07:00Z"),
            ),
        };
        let workflow_membership = StoredEpisodeMembership {
            append_sequence: workflow_membership_sequence,
            transaction_id: id(&workflow_transaction_id),
            committed_at: ts("2026-05-29T00:07:00Z"),
            membership: episode_membership(
                id(&workflow_membership_id),
                workflow_fact.id.clone(),
                workflow_episode.episode.id.clone(),
                FactRole::IdentityWitness,
                system_author(),
                ts("2026-05-29T00:07:00Z"),
            ),
        };
        repository
            .append_stored_workflow_slice(&StoredIdentityWorkflowSlice {
                transaction_id: id(&workflow_transaction_id),
                committed_at: ts("2026-05-29T00:07:00Z"),
                episode: workflow_episode.clone(),
                encrypted_facts: vec![workflow_envelope.clone()],
                memberships: vec![workflow_membership.clone()],
            })
            .await
            .expect("workflow slice transaction should append atomically");

        assert_eq!(
            repository
                .stored_episodes_for_subject(&subject_id)
                .await
                .expect("stored episodes query should succeed")
                .into_iter()
                .filter(|episode| episode.episode.id == workflow_episode.episode.id)
                .collect::<Vec<_>>(),
            vec![workflow_episode]
        );
        assert_eq!(
            repository
                .stored_memberships_for_fact(&workflow_fact.id)
                .await
                .expect("stored memberships query should succeed"),
            vec![workflow_membership]
        );
        assert!(repository
            .encrypted_facts_for_subject(&subject_id)
            .await
            .expect("workflow fact query should succeed")
            .contains(&workflow_envelope));

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &first_fact_id,
                &second_fact_id,
                &duplicate_sequence_fact_id,
                &workflow_fact_id,
            ],
            &[&workflow_episode_id],
            &[&workflow_membership_id],
            &[&workflow_transaction_id],
        )
        .await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_encrypted_replay_reconstructs_materialized_state_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL replay-equivalence test; set {POSTGRES_URL_ENV} to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;

        let suffix = live_test_suffix();
        let subject_id: SubjectId = id(&format!("subject-live-postgres-replay-{suffix}"));
        let device_fact_id = format!("fact-live-postgres-replay-{suffix}-device");
        let continuity_fact_id = format!("fact-live-postgres-replay-{suffix}-continuity");
        let link_fact_id = format!("fact-live-postgres-replay-{suffix}-link");
        let contested_fact_id = format!("fact-live-postgres-replay-{suffix}-contested");

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &device_fact_id,
                &continuity_fact_id,
                &link_fact_id,
                &contested_fact_id,
            ],
            &[],
            &[],
            &[],
        )
        .await;

        let first_sequence = next_live_postgres_append_sequence(repository.pool()).await;
        let key = active_key();
        let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
        let encryptor = DeterministicTestFactEncryptor::new();
        let device_fact = fact(
            &device_fact_id,
            subject_id.clone(),
            FactPayload::DeviceBindingEstablished {
                device_ref: "device-live-postgres-replay".to_string(),
                authenticator_type: AuthenticatorType::Passkey,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let continuity_fact = fact(
            &continuity_fact_id,
            subject_id.clone(),
            FactPayload::BiometricContinuityCheck {
                biometric_system: "LivePostgresVault".to_string(),
                enrollment_ref: "live-postgres-enrollment".to_string(),
                result: ContinuityCheckResult::Passed,
                assurance_level: AssuranceLevel::High,
            },
        );
        let link_fact = sensitive_fact(&link_fact_id, subject_id.clone());
        let contested_fact = fact(
            &contested_fact_id,
            subject_id.clone(),
            FactPayload::ClinicalIdentityLinkContested {
                link_fact_id: id(&link_fact_id),
                reason: Some("live replay test dispute".to_string()),
            },
        );

        let expected_facts = vec![
            device_fact.clone(),
            continuity_fact.clone(),
            link_fact.clone(),
            contested_fact.clone(),
        ];
        let envelopes = vec![
            encrypted_envelope(
                &continuity_fact,
                first_sequence + 1,
                materialization_policy_refs(),
                &key,
                &encryptor,
            ),
            encrypted_envelope(
                &contested_fact,
                first_sequence + 3,
                materialization_policy_refs(),
                &key,
                &encryptor,
            ),
            encrypted_envelope(
                &device_fact,
                first_sequence,
                materialization_policy_refs(),
                &key,
                &encryptor,
            ),
            encrypted_envelope(
                &link_fact,
                first_sequence + 2,
                materialization_policy_refs(),
                &key,
                &encryptor,
            ),
        ];

        for envelope in &envelopes {
            repository
                .append_encrypted_fact(envelope)
                .await
                .expect("encrypted replay fact should append");
        }

        let stored = repository
            .encrypted_facts_for_subject(&subject_id)
            .await
            .expect("subject query should return encrypted facts in append order");
        assert_eq!(
            stored
                .iter()
                .map(|envelope| envelope.fact_id.clone())
                .collect::<Vec<_>>(),
            vec![
                id(&device_fact_id),
                id(&continuity_fact_id),
                id(&link_fact_id),
                id(&contested_fact_id),
            ]
        );

        let materialized = materialize_encrypted_facts(
            &stored,
            &allowed_policy(materialization_policy_refs()),
            &resolver,
            &encryptor,
        )
        .expect("stored encrypted facts should materialize");
        assert_eq!(materialized, expected_facts);
        assert_eq!(
            replay_identity_state(subject_id.clone(), &materialized),
            replay_identity_state(subject_id.clone(), &expected_facts)
        );

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &device_fact_id,
                &continuity_fact_id,
                &link_fact_id,
                &contested_fact_id,
            ],
            &[],
            &[],
            &[],
        )
        .await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_encryption_aware_workflow_repository_appends_and_replays_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL encrypted workflow facade test; set {POSTGRES_URL_ENV} to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let storage = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&storage).await;

        let suffix = live_test_suffix();
        let subject_id: SubjectId = id(&format!("subject-live-postgres-facade-{suffix}"));
        let fact_id = format!("fact-live-postgres-facade-{suffix}");
        let episode_id = format!("episode-live-postgres-facade-{suffix}");
        let membership_id = format!("membership-live-postgres-facade-{suffix}");
        let transaction_id = format!("tx-live-postgres-facade-{suffix}");

        cleanup_live_postgres_rows(
            storage.pool(),
            &subject_id,
            &[&fact_id],
            &[&episode_id],
            &[&membership_id],
            &[&transaction_id],
        )
        .await;

        let key = active_key();
        let resolver = StaticFactKeyResolver::from_keys([key.clone()]);
        let mut repository = SqlxPostgresEncryptionAwareWorkflowRepository::new(
            storage,
            DeterministicTestFactEncryptionMetadataPlanner::new(KEY_ID, "nonce-postgres-facade"),
            DeterministicTestFactEncryptor::new(),
            key,
            materialization_policy_refs(),
        );
        let fact = sensitive_fact(&fact_id, subject_id.clone());
        let episode = access_authorization_episode(
            id(&episode_id),
            subject_id.clone(),
            SensitiveAction::ViewRecord,
            system_author(),
            ts("2026-05-29T00:03:00Z"),
        );
        let membership = episode_membership(
            id(&membership_id),
            fact.id.clone(),
            episode.id.clone(),
            FactRole::IdentityWitness,
            system_author(),
            ts("2026-05-29T00:04:00Z"),
        );

        let stored = repository
            .append_workflow_slice(
                IdentityWorkflowSlice {
                    episode,
                    facts: vec![fact.clone()],
                    memberships: vec![membership],
                },
                id(&transaction_id),
                ts("2026-05-29T00:05:00Z"),
            )
            .await
            .expect("encrypted workflow facade should append atomically");

        assert_eq!(stored.encrypted_facts.len(), 1);
        assert_eq!(stored.encrypted_facts[0].fact_id, fact.id);
        assert_eq!(stored.memberships.len(), 1);
        let projection = repository
            .replay_identity_state(
                subject_id.clone(),
                &allowed_policy(materialization_policy_refs()),
                &FactMaterializationAuditContext::default(),
                &resolver,
            )
            .await
            .expect("encrypted workflow facade should replay subject state");
        assert_eq!(projection.active_clinical_links.len(), 1);
        assert_eq!(projection.active_clinical_links[0].source_fact_id, fact.id);

        cleanup_live_postgres_rows(
            repository.storage().pool(),
            &subject_id,
            &[&fact_id],
            &[&episode_id],
            &[&membership_id],
            &[&transaction_id],
        )
        .await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_workflow_slice_rolls_back_partial_writes_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!("skipping live PostgreSQL rollback test; set {POSTGRES_URL_ENV} to run it");
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;

        let suffix = live_test_suffix();
        let subject_id: SubjectId = id(&format!("subject-live-postgres-rollback-{suffix}"));
        let seed_fact_id = format!("fact-live-postgres-rollback-{suffix}-seed");
        let seed_episode_id = format!("episode-live-postgres-rollback-{suffix}-seed");
        let seed_membership_id = format!("membership-live-postgres-rollback-{suffix}-seed");
        let seed_transaction_id = format!("tx-live-postgres-rollback-{suffix}-seed");
        let duplicate_episode_transaction_id =
            format!("tx-live-postgres-rollback-{suffix}-duplicate-episode");
        let duplicate_fact_transaction_id =
            format!("tx-live-postgres-rollback-{suffix}-duplicate-fact");
        let duplicate_membership_transaction_id =
            format!("tx-live-postgres-rollback-{suffix}-duplicate-membership");
        let duplicate_sequence_transaction_id =
            format!("tx-live-postgres-rollback-{suffix}-duplicate-sequence");
        let duplicate_fact_episode_id =
            format!("episode-live-postgres-rollback-{suffix}-duplicate-fact");
        let duplicate_membership_episode_id =
            format!("episode-live-postgres-rollback-{suffix}-duplicate-membership");
        let duplicate_sequence_episode_id =
            format!("episode-live-postgres-rollback-{suffix}-duplicate-sequence");
        let duplicate_fact_new_fact_id =
            format!("fact-live-postgres-rollback-{suffix}-duplicate-fact-new");
        let duplicate_membership_fact_id =
            format!("fact-live-postgres-rollback-{suffix}-duplicate-membership");
        let duplicate_sequence_fact_id =
            format!("fact-live-postgres-rollback-{suffix}-duplicate-sequence");
        let duplicate_fact_membership_id =
            format!("membership-live-postgres-rollback-{suffix}-duplicate-fact");
        let duplicate_sequence_membership_id =
            format!("membership-live-postgres-rollback-{suffix}-duplicate-sequence");

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &seed_fact_id,
                &duplicate_fact_new_fact_id,
                &duplicate_membership_fact_id,
                &duplicate_sequence_fact_id,
            ],
            &[
                &seed_episode_id,
                &duplicate_fact_episode_id,
                &duplicate_membership_episode_id,
                &duplicate_sequence_episode_id,
            ],
            &[
                &seed_membership_id,
                &duplicate_fact_membership_id,
                &duplicate_sequence_membership_id,
            ],
            &[
                &seed_transaction_id,
                &duplicate_episode_transaction_id,
                &duplicate_fact_transaction_id,
                &duplicate_membership_transaction_id,
                &duplicate_sequence_transaction_id,
            ],
        )
        .await;

        let fact_sequence = next_live_postgres_append_sequence(repository.pool()).await;
        let episode_sequence = next_live_postgres_episode_append_sequence(repository.pool()).await;
        let membership_sequence =
            next_live_postgres_membership_append_sequence(repository.pool()).await;
        let key = active_key();
        let encryptor = DeterministicTestFactEncryptor::new();
        let seed_fact = fact(
            &seed_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres-rollback-seed".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let seed_envelope = encrypted_envelope(
            &seed_fact,
            fact_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        let seed_episode = stored_problem_episode_for(
            &seed_episode_id,
            subject_id.clone(),
            episode_sequence,
            &seed_transaction_id,
        );
        let seed_membership = stored_membership_for(
            &seed_membership_id,
            seed_fact.id.clone(),
            seed_episode.episode.id.clone(),
            membership_sequence,
            &seed_transaction_id,
        );

        repository
            .append_stored_workflow_slice(&StoredIdentityWorkflowSlice {
                transaction_id: id(&seed_transaction_id),
                committed_at: ts("2026-05-29T00:20:00Z"),
                episode: seed_episode,
                encrypted_facts: vec![seed_envelope.clone()],
                memberships: vec![seed_membership],
            })
            .await
            .expect("seed workflow should append");

        let duplicate_episode = StoredIdentityWorkflowSlice {
            transaction_id: id(&duplicate_episode_transaction_id),
            committed_at: ts("2026-05-29T00:21:00Z"),
            episode: stored_problem_episode_for(
                &seed_episode_id,
                subject_id.clone(),
                episode_sequence + 1,
                &duplicate_episode_transaction_id,
            ),
            encrypted_facts: Vec::new(),
            memberships: Vec::new(),
        };
        assert_eq!(
            repository
                .append_stored_workflow_slice(&duplicate_episode)
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateEpisodeId
            ))
        );
        assert_live_postgres_absent(
            repository.pool(),
            &[&duplicate_episode_transaction_id],
            &[],
            &[],
            &[],
            &[],
        )
        .await;

        let duplicate_fact_fact = fact(
            &seed_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres-rollback-duplicate-fact".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let duplicate_fact_envelope = encrypted_envelope(
            &duplicate_fact_fact,
            fact_sequence + 1,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        assert_eq!(
            repository
                .append_stored_workflow_slice(&StoredIdentityWorkflowSlice {
                    transaction_id: id(&duplicate_fact_transaction_id),
                    committed_at: ts("2026-05-29T00:22:00Z"),
                    episode: stored_problem_episode_for(
                        &duplicate_fact_episode_id,
                        subject_id.clone(),
                        episode_sequence + 2,
                        &duplicate_fact_transaction_id,
                    ),
                    encrypted_facts: vec![duplicate_fact_envelope],
                    memberships: Vec::new(),
                })
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateFactId
            ))
        );
        assert_live_postgres_absent(
            repository.pool(),
            &[&duplicate_fact_transaction_id],
            &[&duplicate_fact_episode_id],
            &[],
            &[],
            &[],
        )
        .await;

        let duplicate_membership_fact = fact(
            &duplicate_membership_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres-rollback-duplicate-membership".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let duplicate_membership_envelope = encrypted_envelope(
            &duplicate_membership_fact,
            fact_sequence + 2,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        let duplicate_membership_episode = stored_problem_episode_for(
            &duplicate_membership_episode_id,
            subject_id.clone(),
            episode_sequence + 3,
            &duplicate_membership_transaction_id,
        );
        let duplicate_membership = stored_membership_for(
            &seed_membership_id,
            duplicate_membership_fact.id.clone(),
            duplicate_membership_episode.episode.id.clone(),
            membership_sequence + 1,
            &duplicate_membership_transaction_id,
        );
        assert_eq!(
            repository
                .append_stored_workflow_slice(&StoredIdentityWorkflowSlice {
                    transaction_id: id(&duplicate_membership_transaction_id),
                    committed_at: ts("2026-05-29T00:23:00Z"),
                    episode: duplicate_membership_episode,
                    encrypted_facts: vec![duplicate_membership_envelope],
                    memberships: vec![duplicate_membership],
                })
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateMembershipId
            ))
        );
        assert_live_postgres_absent(
            repository.pool(),
            &[&duplicate_membership_transaction_id],
            &[&duplicate_membership_episode_id],
            &[&duplicate_membership_fact_id],
            &[],
            &[],
        )
        .await;

        let duplicate_sequence_fact = fact(
            &duplicate_sequence_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres-rollback-duplicate-sequence".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let duplicate_sequence_envelope = encrypted_envelope(
            &duplicate_sequence_fact,
            fact_sequence,
            materialization_policy_refs(),
            &key,
            &encryptor,
        );
        assert_eq!(
            repository
                .append_stored_workflow_slice(&StoredIdentityWorkflowSlice {
                    transaction_id: id(&duplicate_sequence_transaction_id),
                    committed_at: ts("2026-05-29T00:24:00Z"),
                    episode: stored_problem_episode_for(
                        &duplicate_sequence_episode_id,
                        subject_id.clone(),
                        episode_sequence + 4,
                        &duplicate_sequence_transaction_id,
                    ),
                    encrypted_facts: vec![duplicate_sequence_envelope],
                    memberships: vec![stored_membership_for(
                        &duplicate_sequence_membership_id,
                        id(&duplicate_sequence_fact_id),
                        id(&duplicate_sequence_episode_id),
                        membership_sequence + 2,
                        &duplicate_sequence_transaction_id,
                    )],
                })
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateAppendSequence
            ))
        );
        assert_live_postgres_absent(
            repository.pool(),
            &[&duplicate_sequence_transaction_id],
            &[&duplicate_sequence_episode_id],
            &[&duplicate_sequence_fact_id],
            &[],
            &[&duplicate_sequence_membership_id],
        )
        .await;

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[
                &seed_fact_id,
                &duplicate_fact_new_fact_id,
                &duplicate_membership_fact_id,
                &duplicate_sequence_fact_id,
            ],
            &[
                &seed_episode_id,
                &duplicate_fact_episode_id,
                &duplicate_membership_episode_id,
                &duplicate_sequence_episode_id,
            ],
            &[
                &seed_membership_id,
                &duplicate_fact_membership_id,
                &duplicate_sequence_membership_id,
            ],
            &[
                &seed_transaction_id,
                &duplicate_episode_transaction_id,
                &duplicate_fact_transaction_id,
                &duplicate_membership_transaction_id,
                &duplicate_sequence_transaction_id,
            ],
        )
        .await;
    });
}

#[cfg(feature = "postgres-adapter")]
#[test]
fn live_postgres_episode_composition_rolls_back_partial_writes_when_env_is_set() {
    let Ok(database_url) = std::env::var(POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL composition rollback test; set {POSTGRES_URL_ENV} to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        let repository = SqlxPostgresEncryptedFactRepository::connect(&database_url)
            .await
            .expect("live PostgreSQL repository should connect");
        run_live_postgres_migration(&repository).await;

        let suffix = live_test_suffix();
        let subject_id: SubjectId = id(&format!(
            "subject-live-postgres-composition-rollback-{suffix}"
        ));
        let seed_parent_episode_id =
            format!("episode-live-postgres-composition-rollback-{suffix}-seed-parent");
        let seed_child_episode_id =
            format!("episode-live-postgres-composition-rollback-{suffix}-seed-child");
        let seed_relation_id = format!("relation-live-postgres-composition-rollback-{suffix}-seed");
        let seed_transaction_id = format!("tx-live-postgres-composition-rollback-{suffix}-seed");
        let failed_parent_episode_id =
            format!("episode-live-postgres-composition-rollback-{suffix}-failed-parent");
        let failed_child_episode_id =
            format!("episode-live-postgres-composition-rollback-{suffix}-failed-child");
        let failed_fact_id = format!("fact-live-postgres-composition-rollback-{suffix}-failed");
        let failed_membership_id =
            format!("membership-live-postgres-composition-rollback-{suffix}-failed");
        let failed_transaction_id =
            format!("tx-live-postgres-composition-rollback-{suffix}-failed");

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[&failed_fact_id],
            &[
                &seed_parent_episode_id,
                &seed_child_episode_id,
                &failed_parent_episode_id,
                &failed_child_episode_id,
            ],
            &[&failed_membership_id],
            &[&seed_transaction_id, &failed_transaction_id],
        )
        .await;

        let episode_sequence = next_live_postgres_episode_append_sequence(repository.pool()).await;
        let relation_sequence =
            next_live_postgres_relation_append_sequence(repository.pool()).await;
        repository
            .append_stored_episode_composition(&StoredEpisodeComposition {
                transaction_id: id(&seed_transaction_id),
                committed_at: ts("2026-05-29T00:30:00Z"),
                parent_episode: stored_problem_episode_for(
                    &seed_parent_episode_id,
                    subject_id.clone(),
                    episode_sequence,
                    &seed_transaction_id,
                ),
                child_slices: vec![StoredIdentityWorkflowSlice {
                    transaction_id: id(&seed_transaction_id),
                    committed_at: ts("2026-05-29T00:30:00Z"),
                    episode: stored_problem_episode_for(
                        &seed_child_episode_id,
                        subject_id.clone(),
                        episode_sequence + 1,
                        &seed_transaction_id,
                    ),
                    encrypted_facts: Vec::new(),
                    memberships: Vec::new(),
                }],
                episode_relations: vec![stored_episode_relation_for(
                    &seed_relation_id,
                    &seed_child_episode_id,
                    &seed_parent_episode_id,
                    relation_sequence,
                    &seed_transaction_id,
                )],
            })
            .await
            .expect("seed composition should append");

        let key = active_key();
        let encryptor = DeterministicTestFactEncryptor::new();
        let failed_fact = fact(
            &failed_fact_id,
            subject_id.clone(),
            FactPayload::CredentialAssertion {
                authenticator_type: AuthenticatorType::Passkey,
                device_ref: Some("device-live-postgres-composition-rollback".to_string()),
                result: CredentialAssertionResult::Succeeded,
                assurance_level: AssuranceLevel::Medium,
            },
        );
        let failed_fact_sequence = next_live_postgres_append_sequence(repository.pool()).await;
        let failed_membership_sequence =
            next_live_postgres_membership_append_sequence(repository.pool()).await;
        let failed_child_episode = stored_problem_episode_for(
            &failed_child_episode_id,
            subject_id.clone(),
            episode_sequence + 3,
            &failed_transaction_id,
        );
        let failed_membership = stored_membership_for(
            &failed_membership_id,
            failed_fact.id.clone(),
            failed_child_episode.episode.id.clone(),
            failed_membership_sequence,
            &failed_transaction_id,
        );

        assert_eq!(
            repository
                .append_stored_episode_composition(&StoredEpisodeComposition {
                    transaction_id: id(&failed_transaction_id),
                    committed_at: ts("2026-05-29T00:31:00Z"),
                    parent_episode: stored_problem_episode_for(
                        &failed_parent_episode_id,
                        subject_id.clone(),
                        episode_sequence + 2,
                        &failed_transaction_id,
                    ),
                    child_slices: vec![StoredIdentityWorkflowSlice {
                        transaction_id: id(&failed_transaction_id),
                        committed_at: ts("2026-05-29T00:31:00Z"),
                        episode: failed_child_episode,
                        encrypted_facts: vec![encrypted_envelope(
                            &failed_fact,
                            failed_fact_sequence,
                            materialization_policy_refs(),
                            &key,
                            &encryptor,
                        )],
                        memberships: vec![failed_membership],
                    }],
                    episode_relations: vec![stored_episode_relation_for(
                        &seed_relation_id,
                        &failed_child_episode_id,
                        &failed_parent_episode_id,
                        relation_sequence + 1,
                        &failed_transaction_id,
                    )],
                })
                .await,
            Err(PostgresAdapterError::Repository(
                RepositoryError::DuplicateRelationId
            ))
        );

        assert_live_postgres_absent(
            repository.pool(),
            &[&failed_transaction_id],
            &[&failed_parent_episode_id, &failed_child_episode_id],
            &[&failed_fact_id],
            &[],
            &[&failed_membership_id],
        )
        .await;

        cleanup_live_postgres_rows(
            repository.pool(),
            &subject_id,
            &[&failed_fact_id],
            &[
                &seed_parent_episode_id,
                &seed_child_episode_id,
                &failed_parent_episode_id,
                &failed_child_episode_id,
            ],
            &[&failed_membership_id],
            &[&seed_transaction_id, &failed_transaction_id],
        )
        .await;
    });
}

#[cfg(feature = "postgres-adapter")]
async fn next_live_postgres_append_sequence(pool: &sqlx::PgPool) -> AppendSequence {
    let next_sequence: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_facts")
            .fetch_one(pool)
            .await
            .expect("next append sequence query should succeed");
    next_sequence as AppendSequence
}

#[cfg(feature = "postgres-adapter")]
async fn next_live_postgres_episode_append_sequence(pool: &sqlx::PgPool) -> AppendSequence {
    let next_sequence: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episodes")
            .fetch_one(pool)
            .await
            .expect("next episode append sequence query should succeed");
    next_sequence as AppendSequence
}

#[cfg(feature = "postgres-adapter")]
async fn next_live_postgres_membership_append_sequence(pool: &sqlx::PgPool) -> AppendSequence {
    let next_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_memberships",
    )
    .fetch_one(pool)
    .await
    .expect("next membership append sequence query should succeed");
    next_sequence as AppendSequence
}

#[cfg(feature = "postgres-adapter")]
async fn run_live_postgres_migration(repository: &SqlxPostgresEncryptedFactRepository) {
    let _guard = LIVE_POSTGRES_MIGRATION_LOCK
        .lock()
        .expect("live PostgreSQL migration lock should not be poisoned");
    repository
        .run_migration()
        .await
        .expect("migration should run against live PostgreSQL");
}

#[cfg(feature = "postgres-adapter")]
async fn next_live_postgres_relation_append_sequence(pool: &sqlx::PgPool) -> AppendSequence {
    let next_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(append_sequence), -1) + 1 FROM identity_episode_relations",
    )
    .fetch_one(pool)
    .await
    .expect("next relation append sequence query should succeed");
    next_sequence as AppendSequence
}

#[cfg(feature = "postgres-adapter")]
async fn assert_live_postgres_absent(
    pool: &sqlx::PgPool,
    transaction_ids: &[&str],
    episode_ids: &[&str],
    fact_ids: &[&str],
    relation_ids: &[&str],
    membership_ids: &[&str],
) {
    let transaction_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_workflow_transactions WHERE transaction_id = ANY($1)",
    )
    .bind(transaction_ids)
    .fetch_one(pool)
    .await
    .expect("transaction absence query should succeed");
    let episode_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_episodes WHERE episode_id = ANY($1)")
            .bind(episode_ids)
            .fetch_one(pool)
            .await
            .expect("episode absence query should succeed");
    let fact_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_facts WHERE fact_id = ANY($1)")
            .bind(fact_ids)
            .fetch_one(pool)
            .await
            .expect("fact absence query should succeed");
    let relation_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_episode_relations WHERE relation_id = ANY($1)",
    )
    .bind(relation_ids)
    .fetch_one(pool)
    .await
    .expect("relation absence query should succeed");
    let membership_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_episode_memberships WHERE membership_id = ANY($1)",
    )
    .bind(membership_ids)
    .fetch_one(pool)
    .await
    .expect("membership absence query should succeed");

    assert_eq!(transaction_count, 0);
    assert_eq!(episode_count, 0);
    assert_eq!(fact_count, 0);
    assert_eq!(relation_count, 0);
    assert_eq!(membership_count, 0);
}

#[cfg(feature = "postgres-adapter")]
async fn cleanup_live_postgres_rows(
    pool: &sqlx::PgPool,
    subject_id: &SubjectId,
    fact_ids: &[&str],
    episode_ids: &[&str],
    membership_ids: &[&str],
    transaction_ids: &[&str],
) {
    sqlx::query(
        r#"
        DELETE FROM identity_episode_relations
        WHERE source_episode_id = ANY($1)
           OR target_episode_id = ANY($1)
        "#,
    )
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live relation cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episode_memberships
        WHERE membership_id = ANY($1)
           OR fact_id = ANY($2)
           OR episode_id = ANY($3)
        "#,
    )
    .bind(membership_ids)
    .bind(fact_ids)
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live membership cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episodes
        WHERE episode_id = ANY($1)
        "#,
    )
    .bind(episode_ids)
    .execute(pool)
    .await
    .expect("live episode cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_workflow_transactions
        WHERE transaction_id = ANY($1)
        "#,
    )
    .bind(transaction_ids)
    .execute(pool)
    .await
    .expect("live transaction cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_fact_materialization_audit
        WHERE subject_id = $1
        "#,
    )
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("live audit cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_facts
        WHERE fact_id = ANY($1)
        "#,
    )
    .bind(fact_ids)
    .execute(pool)
    .await
    .expect("live fact cleanup should succeed");
}

#[cfg(feature = "postgres-adapter")]
async fn cleanup_live_app_attest_key_state(pool: &sqlx::PgPool, key_id: &str) {
    sqlx::query(
        r#"
        DELETE FROM identity_app_attest_challenge_nonces
        WHERE key_id = $1
        "#,
    )
    .bind(key_id)
    .execute(pool)
    .await
    .expect("live App Attest nonce cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_app_attest_keys
        WHERE key_id = $1
        "#,
    )
    .bind(key_id)
    .execute(pool)
    .await
    .expect("live App Attest key cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_app_attest_key_registrations
        WHERE key_id = $1
        "#,
    )
    .bind(key_id)
    .execute(pool)
    .await
    .expect("live App Attest registration cleanup should succeed");
}

#[cfg(feature = "postgres-adapter")]
fn live_test_suffix() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos()
        .to_string()
}

#[cfg(feature = "postgres-adapter")]
fn postgres_app_attest_assertion(
    config: &AppAttestClientConfig,
    key_id: &str,
    device_ref: &str,
    challenge_nonce: &str,
    sign_count: u64,
) -> VerifiedAppAttestAssertion {
    VerifiedAppAttestAssertion {
        team_id: config.team_id.clone(),
        bundle_id: config.bundle_id.clone(),
        app_id: config.app_id.clone(),
        environment: config.environment,
        device_ref: device_ref.to_string(),
        key_id: key_id.to_string(),
        challenge_nonce: challenge_nonce.to_string(),
        sign_count,
        asserted_at: ts("2026-05-29T00:05:00Z"),
        expires_at: ts("2026-05-29T00:06:00Z"),
        assurance_level: AssuranceLevel::Medium,
    }
}

fn stored_episode(id_value: &str, append_sequence: AppendSequence) -> StoredProblemEpisode {
    StoredProblemEpisode {
        append_sequence,
        transaction_id: id("tx-postgres-workflow"),
        committed_at: ts("2026-05-29T00:03:00Z"),
        episode: ProblemEpisode {
            id: id(id_value),
            subject_id: id("subject-postgres-workflow"),
            episode_kind: EpisodeKind::IdentityVerificationWorkflow,
            label: "Identity verification".to_string(),
            problem_code: None,
            status: EpisodeStatus::Active,
            onset: None,
            authored_by: system_author(),
            authored_at: ts("2026-05-29T00:00:00Z"),
            notes: None,
        },
    }
}

#[cfg(feature = "postgres-adapter")]
fn stored_problem_episode_for(
    episode_id: &str,
    subject_id: SubjectId,
    append_sequence: AppendSequence,
    transaction_id: &str,
) -> StoredProblemEpisode {
    StoredProblemEpisode {
        append_sequence,
        transaction_id: id(transaction_id),
        committed_at: ts("2026-05-29T00:03:00Z"),
        episode: access_authorization_episode(
            id(episode_id),
            subject_id,
            SensitiveAction::ViewRecord,
            system_author(),
            ts("2026-05-29T00:03:00Z"),
        ),
    }
}

#[cfg(feature = "postgres-adapter")]
fn stored_membership_for(
    membership_id: &str,
    fact_id: FactId,
    episode_id: ProblemEpisodeId,
    append_sequence: AppendSequence,
    transaction_id: &str,
) -> StoredEpisodeMembership {
    StoredEpisodeMembership {
        append_sequence,
        transaction_id: id(transaction_id),
        committed_at: ts("2026-05-29T00:04:00Z"),
        membership: episode_membership(
            id(membership_id),
            fact_id,
            episode_id,
            FactRole::IdentityWitness,
            system_author(),
            ts("2026-05-29T00:04:00Z"),
        ),
    }
}

#[cfg(feature = "postgres-adapter")]
fn stored_episode_relation_for(
    relation_id: &str,
    source_episode_id: &str,
    target_episode_id: &str,
    append_sequence: AppendSequence,
    transaction_id: &str,
) -> StoredEpisodeRelation {
    StoredEpisodeRelation {
        append_sequence,
        transaction_id: id(transaction_id),
        committed_at: ts("2026-05-29T00:05:00Z"),
        relation: episode_relation(
            id(relation_id),
            id(source_episode_id),
            id(target_episode_id),
            EpisodeRelationType::PartOf,
            system_author(),
            ts("2026-05-29T00:05:00Z"),
        ),
    }
}

fn sensitive_fact(id_value: &str, subject_id: SubjectId) -> Fact {
    let mut fact = fact(
        id_value,
        subject_id,
        FactPayload::ClinicalIdentityLinkEstablished {
            provider_org: "Example Health".to_string(),
            external_patient_ref: ExternalRef {
                system: ExternalSystem::Fhir,
                resource_type: Some("Patient".to_string()),
                resource_id: "patient-sensitive".to_string(),
                uri: Some("https://example.invalid/fhir/Patient/patient-sensitive".to_string()),
            },
            match_confidence: MatchConfidence::High,
        },
    );
    fact.code = Some(CodedValue {
        system: CodingSystem::Local,
        code: "identity-link".to_string(),
        display: "Identity link".to_string(),
    });
    fact.external_refs = vec![ExternalRef {
        system: ExternalSystem::IdentityProvider,
        resource_type: Some("identity-proofing-event".to_string()),
        resource_id: "proofing-event-sensitive".to_string(),
        uri: None,
    }];
    fact
}

fn encrypted_envelope(
    fact: &Fact,
    append_sequence: AppendSequence,
    policy_refs: Vec<PolicyRef>,
    key: &FactDataEncryptionKey,
    encryptor: &DeterministicTestFactEncryptor,
) -> StoredEncryptedFact {
    encrypt_fact_envelope(
        fact,
        append_sequence,
        id("tx-postgres-encrypted-facts"),
        ts("2026-05-29T00:00:01Z"),
        policy_refs,
        FactEncryptionMetadata::deterministic_test(KEY_ID, b"nonce-postgres-fact".to_vec()),
        key,
        encryptor,
    )
    .expect("fact should encrypt")
}

fn active_key() -> FactDataEncryptionKey {
    FactDataEncryptionKey::active(KEY_ID, b"postgres-test-key-material".to_vec())
}

fn materialization_policy_refs() -> Vec<PolicyRef> {
    vec![id("identity-materialization-policy@v1")]
}

fn allowed_policy(policy_refs: Vec<PolicyRef>) -> PolicyEvaluation {
    PolicyEvaluation {
        action: SensitiveAction::ViewRecord,
        decision: AccessDecisionResult::Allowed,
        reasons: Vec::new(),
        relied_on_facts: Vec::new(),
        policy_refs,
    }
}
