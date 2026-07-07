#![cfg(feature = "runtime-server")]

use identity_model::*;
use serde_json::json;
use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn live_runtime_server_identity_onboarding_e2e_when_env_is_set() {
    let Some(env) = RuntimeServerE2eEnv::from_env() else {
        eprintln!(
            "skipping live runtime-server identity onboarding E2E; set \
             IDENTITY_MODEL_POSTGRES_URL, IDENTITY_MODEL_KEYCLOAK_ISSUER, \
             IDENTITY_MODEL_KEYCLOAK_CLIENT_ID, and IDENTITY_MODEL_KEYCLOAK_TOKEN to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        run_live_runtime_server_identity_onboarding_e2e(env).await;
    });
}

async fn run_live_runtime_server_identity_onboarding_e2e(env: RuntimeServerE2eEnv) {
    let suffix = runtime_e2e_suffix();
    let id_namespace = format!("runtime-server-e2e-{suffix}");
    let subject_id = SubjectId(format!("subject-{id_namespace}"));
    let device_ref = format!("iphone-{id_namespace}");
    let challenge_nonce = format!("app-attest-nonce-{id_namespace}");
    let app_attest_key_id = format!("app-attest-key-{id_namespace}");
    let app_attest_assertion = format!("valid-app-attest-{id_namespace}");
    let liveness_assertion = format!("valid-live-presence-{id_namespace}");
    let transaction_id_prefix = format!("tx-{id_namespace}");
    let app_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let now = unix_now_seconds();
    let observed_at = unix_seconds_to_timestamp(now);
    let expires_at = unix_seconds_to_timestamp(now + 300);

    let storage = SqlxPostgresEncryptedFactRepository::connect(&env.database_url)
        .await
        .expect("runtime E2E PostgreSQL repository should connect");
    storage
        .run_migration()
        .await
        .expect("runtime E2E migrations should run");
    cleanup_runtime_e2e_rows(
        storage.pool(),
        &subject_id,
        &transaction_id_prefix,
        &challenge_nonce,
        &app_attest_key_id,
    )
    .await;

    let bind_addr = free_local_addr();
    let mut server = RuntimeServerChild::spawn(RuntimeServerSpawnConfig {
        binary_path: env!("CARGO_BIN_EXE_mobile_onboarding_server").to_string(),
        bind_addr,
        database_url: env.database_url.clone(),
        oidc_issuer: env.oidc_issuer.clone(),
        oidc_client_id: env.oidc_client_id.clone(),
        app_attest_assertion: app_attest_assertion.clone(),
        app_attest_challenge_nonce: challenge_nonce.clone(),
        app_attest_device_ref: device_ref.clone(),
        app_attest_key_id: app_attest_key_id.clone(),
        app_attest_asserted_at: observed_at.0.clone(),
        app_attest_expires_at: expires_at.0.clone(),
        liveness_assertion: liveness_assertion.clone(),
        liveness_provider_event_id: format!("liveness-event-{id_namespace}"),
        transaction_id_prefix: transaction_id_prefix.clone(),
    });
    wait_for_ready(bind_addr, &mut server);
    let issued_challenge_nonce = issue_runtime_e2e_live_presence_challenge_over_http(
        bind_addr,
        &id_namespace,
        &subject_id,
        &device_ref,
        &app_config,
    );
    assert!(!issued_challenge_nonce.is_empty());
    assert_ne!(issued_challenge_nonce, challenge_nonce);
    let second_issued_challenge_nonce = issue_runtime_e2e_live_presence_challenge_over_http(
        bind_addr,
        &format!("{id_namespace}-second"),
        &subject_id,
        &device_ref,
        &app_config,
    );
    assert_ne!(second_issued_challenge_nonce, issued_challenge_nonce);
    let liveness_input = verify_runtime_e2e_live_presence_callback_over_http(
        bind_addr,
        &id_namespace,
        &device_ref,
        &issued_challenge_nonce,
        &liveness_assertion,
        &observed_at,
        &expires_at,
    );

    let request_body = json!({
        "subject_id": subject_id.0.clone(),
        "observed_at": observed_at.0.clone(),
        "id_namespace": id_namespace.clone(),
        "expected_device_ref": device_ref.clone(),
        "oidc": {
            "access_token": env.oidc_token,
            "issuer": env.oidc_issuer,
            "client_id": env.oidc_client_id,
            "provider_name": "Keycloak"
        },
        "app_attest": {
            "assertion": app_attest_assertion,
            "challenge_nonce": issued_challenge_nonce.clone(),
            "team_id": app_config.team_id,
            "bundle_id": app_config.bundle_id,
            "environment": "development"
        },
        "liveness": liveness_input,
        "identity_proofing": {
            "provider_name": "Persona",
            "workflow_id": format!("persona-workflow-{id_namespace}"),
            "provider_event_id": format!("persona-inquiry-{id_namespace}"),
            "evidence_ref": format!("identity-proofing-{id_namespace}"),
            "evidence_types": ["government_id_document"],
            "verification_result": "passed",
            "assurance_level": "high",
            "asserted_attributes": [
                {
                    "attribute": "legal_name",
                    "value": "Runtime Server Patient",
                    "confidence": "high"
                },
                {
                    "attribute": "date_of_birth",
                    "value": "1990-01-01",
                    "confidence": "high"
                }
            ],
            "verified_at": observed_at.0.clone(),
            "audit_ref": format!("persona-audit-{id_namespace}"),
            "retention_policy_refs": ["identity-proof-retention@v1"]
        },
        "client_context": {
            "platform": "iphone",
            "request_id": format!("request-{id_namespace}"),
            "app_version": "runtime-e2e",
            "user_agent": "FENRuntimeE2E/1.0"
        },
        "subject_kind": "human_person",
        "stable_profile": {
            "legal_name": "Runtime Server Patient",
            "date_of_birth": "1990-01-01"
        },
        "continuity_modality": "face"
    });

    let response = send_http_request(
        bind_addr,
        "POST",
        MOBILE_IDENTITY_ONBOARDING_HTTP_PATH,
        Some(&request_body.to_string()),
    )
    .unwrap_or_else(|error| {
        panic!(
            "runtime server should answer composed identity onboarding request: {error}; {}",
            runtime_server_child_state(&mut server)
        )
    });
    assert_eq!(response.status_code, 200, "{}", response.body);
    let body: MobileIdentityOnboardingHttpResponseBody =
        serde_json::from_str(&response.body).expect("accepted response should be JSON");
    let summary = match body {
        MobileIdentityOnboardingHttpResponseBody::Accepted {
            summary,
            request_id,
        } => {
            assert_eq!(request_id, Some(format!("request-{id_namespace}")));
            summary
        }
        MobileIdentityOnboardingHttpResponseBody::Error { error } => {
            panic!("runtime E2E returned error: {error:?}");
        }
    };
    assert_eq!(summary.subject_id, subject_id.0);
    assert_eq!(summary.decision, "accepted");
    assert_eq!(summary.assurance_level, "high");
    assert_eq!(summary.active_devices, vec![device_ref.clone()]);
    assert!(summary.committed_fact_count >= 9);

    assert_runtime_e2e_postgres_side_effects(
        storage.pool(),
        &subject_id,
        &device_ref,
        &issued_challenge_nonce,
        &app_attest_key_id,
        summary.committed_fact_count,
    )
    .await;
    cleanup_runtime_e2e_rows(
        storage.pool(),
        &subject_id,
        &transaction_id_prefix,
        &issued_challenge_nonce,
        &app_attest_key_id,
    )
    .await;
}

// Regression: the App Attest registration and live-presence-challenge endpoints
// write to PostgreSQL through a store bridge. An earlier version ran that write
// on a freshly-spawned Tokio runtime while the connection pool was owned by the
// server's main runtime, so the acquire hung until the pool timeout (~seconds)
// and returned HTTP 500 with no SQL ever sent. The live-presence-challenge write
// needs no attestation crypto, so it isolates the runtime wiring: assert it
// returns a fresh nonce promptly instead of stalling.
#[test]
fn live_runtime_server_store_write_runs_on_pool_runtime_when_env_is_set() {
    let Some(env) = RuntimeServerE2eEnv::from_env() else {
        eprintln!(
            "skipping live runtime-server store-runtime regression; set \
             IDENTITY_MODEL_POSTGRES_URL, IDENTITY_MODEL_KEYCLOAK_ISSUER, \
             IDENTITY_MODEL_KEYCLOAK_CLIENT_ID, and IDENTITY_MODEL_KEYCLOAK_TOKEN to run it"
        );
        return;
    };

    sqlx::test_block_on(async {
        run_live_runtime_server_store_runtime_regression(env).await;
    });
}

async fn run_live_runtime_server_store_runtime_regression(env: RuntimeServerE2eEnv) {
    let suffix = runtime_e2e_suffix();
    let id_namespace = format!("runtime-server-store-regression-{suffix}");
    let subject_id = SubjectId(format!("subject-{id_namespace}"));
    let device_ref = format!("iphone-{id_namespace}");
    let challenge_nonce = format!("app-attest-nonce-{id_namespace}");
    let app_attest_key_id = format!("app-attest-key-{id_namespace}");
    let app_attest_assertion = format!("valid-app-attest-{id_namespace}");
    let liveness_assertion = format!("valid-live-presence-{id_namespace}");
    let transaction_id_prefix = format!("tx-{id_namespace}");
    let app_config = AppAttestClientConfig::ios_app(
        "TEAMID1234",
        "com.fen.identity",
        AppAttestEnvironment::Development,
    );
    let now = unix_now_seconds();
    let observed_at = unix_seconds_to_timestamp(now);
    let expires_at = unix_seconds_to_timestamp(now + 300);

    let storage = SqlxPostgresEncryptedFactRepository::connect(&env.database_url)
        .await
        .expect("store regression PostgreSQL repository should connect");
    storage
        .run_migration()
        .await
        .expect("store regression migrations should run");
    cleanup_runtime_e2e_rows(
        storage.pool(),
        &subject_id,
        &transaction_id_prefix,
        &challenge_nonce,
        &app_attest_key_id,
    )
    .await;

    let bind_addr = free_local_addr();
    let mut server = RuntimeServerChild::spawn(RuntimeServerSpawnConfig {
        binary_path: env!("CARGO_BIN_EXE_mobile_onboarding_server").to_string(),
        bind_addr,
        database_url: env.database_url.clone(),
        oidc_issuer: env.oidc_issuer.clone(),
        oidc_client_id: env.oidc_client_id.clone(),
        app_attest_assertion,
        app_attest_challenge_nonce: challenge_nonce.clone(),
        app_attest_device_ref: device_ref.clone(),
        app_attest_key_id: app_attest_key_id.clone(),
        app_attest_asserted_at: observed_at.0.clone(),
        app_attest_expires_at: expires_at.0.clone(),
        liveness_assertion,
        liveness_provider_event_id: format!("liveness-event-{id_namespace}"),
        transaction_id_prefix: transaction_id_prefix.clone(),
    });
    wait_for_ready(bind_addr, &mut server);

    let started = std::time::Instant::now();
    let issued_challenge_nonce = issue_runtime_e2e_live_presence_challenge_over_http(
        bind_addr,
        &id_namespace,
        &subject_id,
        &device_ref,
        &app_config,
    );
    let elapsed = started.elapsed();
    assert!(
        !issued_challenge_nonce.is_empty(),
        "live-presence store write must succeed instead of timing out on a foreign runtime; {}",
        runtime_server_child_state(&mut server)
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "store write must run on the pool's runtime and return promptly, took {elapsed:?}"
    );

    cleanup_runtime_e2e_rows(
        storage.pool(),
        &subject_id,
        &transaction_id_prefix,
        &issued_challenge_nonce,
        &app_attest_key_id,
    )
    .await;
}

#[derive(Debug, Clone)]
struct RuntimeServerE2eEnv {
    database_url: String,
    oidc_issuer: String,
    oidc_client_id: String,
    oidc_token: String,
}

impl RuntimeServerE2eEnv {
    fn from_env() -> Option<Self> {
        Some(Self {
            database_url: env::var("IDENTITY_MODEL_POSTGRES_URL").ok()?,
            oidc_issuer: env::var("IDENTITY_MODEL_KEYCLOAK_ISSUER").ok()?,
            oidc_client_id: env::var("IDENTITY_MODEL_KEYCLOAK_CLIENT_ID").ok()?,
            oidc_token: env::var("IDENTITY_MODEL_KEYCLOAK_TOKEN").ok()?,
        })
    }
}

struct RuntimeServerSpawnConfig {
    binary_path: String,
    bind_addr: SocketAddr,
    database_url: String,
    oidc_issuer: String,
    oidc_client_id: String,
    app_attest_assertion: String,
    app_attest_challenge_nonce: String,
    app_attest_device_ref: String,
    app_attest_key_id: String,
    app_attest_asserted_at: String,
    app_attest_expires_at: String,
    liveness_assertion: String,
    liveness_provider_event_id: String,
    transaction_id_prefix: String,
}

struct RuntimeServerChild {
    child: Child,
    stderr_path: PathBuf,
}

impl RuntimeServerChild {
    fn spawn(config: RuntimeServerSpawnConfig) -> Self {
        let stderr_path = env::temp_dir().join(format!(
            "identity-model-runtime-server-e2e-{}-{}.stderr",
            config.bind_addr.port(),
            runtime_e2e_suffix()
        ));
        let stderr = std::fs::File::create(&stderr_path)
            .expect("runtime server stderr capture file should be created");
        let child = Command::new(config.binary_path)
            .env(
                "IDENTITY_MODEL_RUNTIME_BIND_ADDR",
                config.bind_addr.to_string(),
            )
            .env("IDENTITY_MODEL_POSTGRES_URL", config.database_url)
            .env("IDENTITY_MODEL_RUNTIME_RUN_MIGRATIONS", "false")
            .env("IDENTITY_MODEL_RUNTIME_READ_TIMEOUT_SECONDS", "10")
            .env("IDENTITY_MODEL_FACT_KEY_ID", "runtime-e2e-key")
            .env(
                "IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            )
            .env("IDENTITY_MODEL_FACT_NONCE_DOMAIN_HEX", "46454e32")
            .env(
                "IDENTITY_MODEL_MATERIALIZATION_POLICY_REFS",
                "runtime-e2e-materialization@v1",
            )
            .env(
                "IDENTITY_MODEL_MATERIALIZATION_AUDIT_CALLER",
                "runtime-server-e2e",
            )
            .env(
                "IDENTITY_MODEL_MATERIALIZATION_AUDIT_PURPOSE",
                "mobile-identity-onboarding-e2e",
            )
            .env(
                "IDENTITY_MODEL_TRANSACTION_ID_PREFIX",
                config.transaction_id_prefix,
            )
            .env("IDENTITY_MODEL_APP_ATTEST_TEAM_ID", "TEAMID1234")
            .env("IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID", "com.fen.identity")
            .env("IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT", "development")
            .env(
                "IDENTITY_MODEL_APP_ATTEST_EXPECTED_ASSERTION",
                config.app_attest_assertion,
            )
            .env(
                "IDENTITY_MODEL_APP_ATTEST_CHALLENGE_NONCE",
                config.app_attest_challenge_nonce,
            )
            .env(
                "IDENTITY_MODEL_APP_ATTEST_DEVICE_REF",
                config.app_attest_device_ref,
            )
            .env("IDENTITY_MODEL_APP_ATTEST_KEY_ID", config.app_attest_key_id)
            .env("IDENTITY_MODEL_APP_ATTEST_SIGN_COUNT", "1")
            .env(
                "IDENTITY_MODEL_APP_ATTEST_ASSERTED_AT",
                config.app_attest_asserted_at,
            )
            .env(
                "IDENTITY_MODEL_APP_ATTEST_EXPIRES_AT",
                config.app_attest_expires_at,
            )
            .env("IDENTITY_MODEL_APP_ATTEST_ASSURANCE_LEVEL", "medium")
            .env(
                "IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION",
                config.liveness_assertion,
            )
            .env(
                "IDENTITY_MODEL_LIVENESS_PROVIDER_NAME",
                "StaticLivePresenceProvider",
            )
            .env(
                "IDENTITY_MODEL_LIVENESS_PROVIDER_EVENT_ID",
                config.liveness_provider_event_id,
            )
            .env("IDENTITY_MODEL_LIVENESS_RESULT", "passed")
            .env("IDENTITY_MODEL_LIVENESS_ASSURANCE_LEVEL", "high")
            .env("IDENTITY_MODEL_LIVENESS_PAD_RESULT", "passed")
            .env("IDENTITY_MODEL_KEYCLOAK_ISSUER", config.oidc_issuer)
            .env("IDENTITY_MODEL_KEYCLOAK_CLIENT_ID", config.oidc_client_id)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("runtime server binary should spawn");
        Self { child, stderr_path }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for RuntimeServerChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.stderr_path);
    }
}

fn issue_runtime_e2e_live_presence_challenge_over_http(
    bind_addr: SocketAddr,
    id_namespace: &str,
    subject_id: &SubjectId,
    device_ref: &str,
    app_config: &AppAttestClientConfig,
) -> String {
    let request_body = json!({
        "subject_id": subject_id.0.clone(),
        "expected_device_ref": device_ref,
        "expected_app": {
            "team_id": app_config.team_id.clone(),
            "bundle_id": app_config.bundle_id.clone(),
            "environment": "development"
        },
        "client_context": {
            "platform": "iphone",
            "request_id": format!("challenge-request-{id_namespace}")
        }
    });
    let response = send_http_request(
        bind_addr,
        "POST",
        MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CHALLENGE_HTTP_PATH,
        Some(&request_body.to_string()),
    )
    .expect("runtime server should issue live-presence challenge");
    assert_eq!(response.status_code, 200, "{}", response.body);
    let body: MobileLivePresenceChallengeIssueHttpResponseBody =
        serde_json::from_str(&response.body).expect("challenge issue response should be JSON");
    match body {
        MobileLivePresenceChallengeIssueHttpResponseBody::Issued {
            challenge,
            request_id,
        } => {
            assert_eq!(
                request_id,
                Some(format!("challenge-request-{id_namespace}"))
            );
            assert_eq!(challenge.expected_subject_id, Some(subject_id.0.clone()));
            assert_eq!(challenge.expected_device_ref, Some(device_ref.to_string()));
            assert_eq!(challenge.expected_app.app_id, app_config.app_id.clone());
            challenge.challenge_nonce
        }
        MobileLivePresenceChallengeIssueHttpResponseBody::Error { error } => {
            panic!("runtime E2E challenge issuance returned error: {error:?}");
        }
    }
}

fn verify_runtime_e2e_live_presence_callback_over_http(
    bind_addr: SocketAddr,
    id_namespace: &str,
    device_ref: &str,
    challenge_nonce: &str,
    liveness_assertion: &str,
    observed_at: &Timestamp,
    expires_at: &Timestamp,
) -> serde_json::Value {
    let request_body = json!({
        "provider_name": "StaticLivePresenceProvider",
        "provider_event_id": format!("liveness-callback-event-{id_namespace}"),
        "provider_subject_ref": format!("liveness-callback-subject-{id_namespace}"),
        "sdk_or_api_version": "runtime-e2e-static/1.0",
        "assertion": liveness_assertion,
        "challenge_nonce": challenge_nonce,
        "device_ref": device_ref,
        "observed_at": observed_at.0.clone(),
        "expires_at": expires_at.0.clone(),
        "result": "passed",
        "pad_result": "passed",
        "assurance_level": "high",
        "retention_policy_refs": ["live-presence-retention@v1"],
        "client_context": {
            "platform": "iphone",
            "request_id": format!("callback-request-{id_namespace}")
        }
    });
    let response = send_http_request(
        bind_addr,
        "POST",
        MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CALLBACK_HTTP_PATH,
        Some(&request_body.to_string()),
    )
    .expect("runtime server should verify live-presence callback");
    assert_eq!(response.status_code, 200, "{}", response.body);
    let body: MobileLivePresenceCallbackHttpResponseBody =
        serde_json::from_str(&response.body).expect("callback response should be JSON");
    match body {
        MobileLivePresenceCallbackHttpResponseBody::Verified {
            liveness,
            ceremony,
            request_id,
        } => {
            assert_eq!(request_id, Some(format!("callback-request-{id_namespace}")));
            assert_eq!(ceremony.provider_name, "StaticLivePresenceProvider");
            assert_eq!(
                ceremony.provider_event_id,
                Some(format!("liveness-callback-event-{id_namespace}"))
            );
            assert_eq!(ceremony.challenge_nonce, challenge_nonce);
            json!({
                "assertion": liveness.assertion,
                "challenge_nonce": liveness.challenge_nonce,
                "expected_device_ref": liveness.expected_device_ref
            })
        }
        MobileLivePresenceCallbackHttpResponseBody::Error { error } => {
            panic!("runtime E2E live-presence callback returned error: {error:?}");
        }
    }
}

async fn assert_runtime_e2e_postgres_side_effects(
    pool: &sqlx::PgPool,
    subject_id: &SubjectId,
    device_ref: &str,
    challenge_nonce: &str,
    app_attest_key_id: &str,
    committed_fact_count: usize,
) {
    let encrypted_fact_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM identity_facts
        WHERE subject_id = $1
          AND octet_length(ciphertext) > 0
        "#,
    )
    .bind(&subject_id.0)
    .fetch_one(pool)
    .await
    .expect("runtime E2E encrypted fact count should query");
    assert_eq!(encrypted_fact_count as usize, committed_fact_count);

    let challenge_status: String = sqlx::query_scalar(
        r#"
        SELECT status_kind
        FROM identity_live_presence_challenges
        WHERE challenge_nonce = $1
        "#,
    )
    .bind(challenge_nonce)
    .fetch_one(pool)
    .await
    .expect("runtime E2E challenge status should query");
    assert_eq!(challenge_status, "used");

    let app_attest_key_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM identity_app_attest_keys
        WHERE key_id = $1
          AND device_ref = $2
        "#,
    )
    .bind(app_attest_key_id)
    .bind(device_ref)
    .fetch_one(pool)
    .await
    .expect("runtime E2E App Attest key state should query");
    assert_eq!(app_attest_key_count, 1);

    let used_nonce_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM identity_app_attest_challenge_nonces
        WHERE key_id = $1
          AND challenge_nonce = $2
        "#,
    )
    .bind(app_attest_key_id)
    .bind(challenge_nonce)
    .fetch_one(pool)
    .await
    .expect("runtime E2E App Attest nonce state should query");
    assert_eq!(used_nonce_count, 1);

    let audit_event_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM identity_fact_materialization_audit
        WHERE subject_id = $1
          AND caller = $2
          AND purpose = $3
        "#,
    )
    .bind(&subject_id.0)
    .bind("runtime-server-e2e")
    .bind("mobile-identity-onboarding-e2e")
    .fetch_one(pool)
    .await
    .expect("runtime E2E materialization audit count should query");
    assert!(audit_event_count >= committed_fact_count as i64);
}

async fn cleanup_runtime_e2e_rows(
    pool: &sqlx::PgPool,
    subject_id: &SubjectId,
    transaction_id_prefix: &str,
    challenge_nonce: &str,
    app_attest_key_id: &str,
) {
    let tx_like = format!("{transaction_id_prefix}-%");
    sqlx::query(
        r#"
        DELETE FROM identity_episode_relations
        WHERE transaction_id LIKE $1
        "#,
    )
    .bind(&tx_like)
    .execute(pool)
    .await
    .expect("runtime E2E relation cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episode_memberships
        WHERE transaction_id LIKE $1
        "#,
    )
    .bind(&tx_like)
    .execute(pool)
    .await
    .expect("runtime E2E membership cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_episodes
        WHERE transaction_id LIKE $1
           OR subject_id = $2
        "#,
    )
    .bind(&tx_like)
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("runtime E2E episode cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_workflow_transactions
        WHERE transaction_id LIKE $1
        "#,
    )
    .bind(&tx_like)
    .execute(pool)
    .await
    .expect("runtime E2E transaction cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_fact_materialization_audit
        WHERE subject_id = $1
        "#,
    )
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("runtime E2E audit cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_facts
        WHERE subject_id = $1
        "#,
    )
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("runtime E2E fact cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_live_presence_challenges
        WHERE challenge_nonce = $1
           OR expected_subject_id = $2
        "#,
    )
    .bind(challenge_nonce)
    .bind(&subject_id.0)
    .execute(pool)
    .await
    .expect("runtime E2E challenge cleanup should succeed");

    sqlx::query(
        r#"
        DELETE FROM identity_app_attest_keys
        WHERE key_id = $1
        "#,
    )
    .bind(app_attest_key_id)
    .execute(pool)
    .await
    .expect("runtime E2E App Attest cleanup should succeed");
}

fn wait_for_ready(addr: SocketAddr, server: &mut RuntimeServerChild) {
    let deadline = unix_now_seconds() + 15;
    loop {
        if let Some(status) = server
            .child
            .try_wait()
            .expect("runtime server status should be readable")
        {
            panic!(
                "runtime server exited before ready: {status}; stderr: {}",
                server.stderr()
            );
        }

        if let Ok(response) = send_http_request(addr, "GET", "/ready", None) {
            if response.status_code == 200 {
                return;
            }
        }

        if unix_now_seconds() >= deadline {
            panic!("runtime server did not become ready");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn send_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|error| format!("could not connect to runtime server at {addr}: {error}"))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|error| format!("could not write HTTP request: {error}"))?;
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|error| format!("could not read HTTP response: {error}"))?;
    parse_http_response(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    status_code: u16,
    body: String,
}

fn parse_http_response(raw: &str) -> Result<HttpResponse, String> {
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("HTTP response missing header separator: {raw}"))?;
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| "HTTP response missing status line".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("HTTP response malformed status line: {status_line}"))?
        .parse::<u16>()
        .map_err(|_| format!("HTTP response malformed status code: {status_line}"))?;
    Ok(HttpResponse {
        status_code,
        body: body.to_string(),
    })
}

fn free_local_addr() -> SocketAddr {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("runtime E2E should reserve a local port");
    listener
        .local_addr()
        .expect("runtime E2E should read local port")
}

fn runtime_e2e_suffix() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos()
        .to_string()
}

fn unix_now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_secs() as i64
}

fn runtime_server_child_state(server: &mut RuntimeServerChild) -> String {
    match server
        .child
        .try_wait()
        .expect("runtime server status should be readable")
    {
        Some(status) => format!(
            "runtime server exited: {status}; stderr: {}",
            server.stderr()
        ),
        None => format!(
            "runtime server is still running; stderr: {}",
            server.stderr()
        ),
    }
}
