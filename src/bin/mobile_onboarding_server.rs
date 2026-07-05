#[cfg(not(feature = "runtime-server"))]
fn main() {
    eprintln!("mobile_onboarding_server requires --features runtime-server");
    std::process::exit(1);
}

#[cfg(feature = "runtime-server")]
fn main() {
    if let Err(error) = server::run() {
        eprintln!("mobile onboarding server failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(feature = "runtime-server")]
mod server {
    use identity_model::*;
    use ring::rand::SecureRandom;
    use std::env;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    type AppAttestVerifier = StatefulAppAttestAssertionVerifier<
        RuntimeAppAttestAssertionVerifier,
        PostgresAppAttestKeyStateStore,
    >;

    type AccountRuntime = PostgresEncryptedMobileOnboardingRuntime<
        Aes256GcmFactEncryptionMetadataPlanner,
        RingAes256GcmFactEncryptor,
        OidcJwksSessionVerifier,
        AppAttestVerifier,
        DeterministicIdGenerator,
        StaticFactKeyResolver,
    >;

    type IdentityRuntime = PostgresEncryptedMobileIdentityOnboardingRuntime<
        Aes256GcmFactEncryptionMetadataPlanner,
        RingAes256GcmFactEncryptor,
        OidcJwksSessionVerifier,
        AppAttestVerifier,
        PersonaIdentityProofingProvider,
        StaticLivenessCeremonyVerifier,
        PostgresLivePresenceChallengeStore,
        MockPhase1ContinuityProvider,
        DeterministicIdGenerator,
        StaticFactKeyResolver,
    >;

    struct Runtime {
        account: AccountRuntime,
        identity: IdentityRuntime,
    }

    impl Runtime {
        async fn run_migrations(&self) -> Result<(), PostgresAdapterError> {
            self.account.run_migrations().await
        }
    }

    #[derive(Debug, Clone)]
    enum RuntimeAppAttestAssertionVerifier {
        Static(StaticAppAttestAssertionVerifier),
        AppleAssertion(AppleAppAttestAssertionVerifier<PostgresAppAttestKeyStateStore>),
    }

    #[derive(Debug, Clone)]
    enum RuntimeAppAttestVerifierConfig {
        Static(StaticAppAttestAssertionVerifier),
        AppleAssertion {
            expected_config: AppAttestClientConfig,
        },
    }

    impl RuntimeAppAttestVerifierConfig {
        fn static_verified_assertion(&self) -> Option<&VerifiedAppAttestAssertion> {
            match self {
                Self::Static(verifier) => Some(&verifier.verified_assertion),
                Self::AppleAssertion { .. } => None,
            }
        }

        fn build_verifier(
            &self,
            key_state_store: PostgresAppAttestKeyStateStore,
        ) -> RuntimeAppAttestAssertionVerifier {
            match self {
                Self::Static(verifier) => {
                    RuntimeAppAttestAssertionVerifier::Static(verifier.clone())
                }
                Self::AppleAssertion { expected_config } => {
                    RuntimeAppAttestAssertionVerifier::AppleAssertion(
                        AppleAppAttestAssertionVerifier::new(
                            expected_config.clone(),
                            key_state_store,
                        ),
                    )
                }
            }
        }

        fn expected_config(&self) -> AppAttestClientConfig {
            match self {
                Self::Static(verifier) => AppAttestClientConfig {
                    team_id: verifier.verified_assertion.team_id.clone(),
                    bundle_id: verifier.verified_assertion.bundle_id.clone(),
                    app_id: verifier.verified_assertion.app_id.clone(),
                    environment: verifier.verified_assertion.environment,
                },
                Self::AppleAssertion { expected_config } => expected_config.clone(),
            }
        }
    }

    impl AppAttestAssertionVerifier for RuntimeAppAttestAssertionVerifier {
        fn verify_app_attest_assertion(
            &self,
            request: &AppAttestAssertionVerificationRequest,
            observed_at: &Timestamp,
        ) -> Result<VerifiedAppAttestAssertion, AppAttestAssertionVerificationError> {
            match self {
                Self::Static(verifier) => {
                    verifier.verify_app_attest_assertion(request, observed_at)
                }
                Self::AppleAssertion(verifier) => {
                    verifier.verify_app_attest_assertion(request, observed_at)
                }
            }
        }
    }

    pub fn run() -> Result<(), String> {
        let config = ServerConfig::from_env()?;
        let tokio_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start async runtime: {error}"))?;
        let storage = tokio_runtime.block_on(connect_storage(&config))?;
        let readiness_pool = storage.pool().clone();
        let challenge_store = PostgresLivePresenceChallengeStore::from_pool(readiness_pool.clone());
        let app_attest_registration_store =
            PostgresAppAttestKeyStateStore::from_pool(readiness_pool.clone());
        let runtime = build_runtime(&config, storage);
        if config.run_migrations {
            tokio_runtime
                .block_on(runtime.run_migrations())
                .map_err(|error| format!("could not run migrations: {error:?}"))?;
        }

        serve(
            config,
            runtime,
            tokio_runtime,
            readiness_pool,
            challenge_store,
            app_attest_registration_store,
        )
    }

    /// State shared by every worker thread.
    ///
    /// The two onboarding runtimes require `&mut self` (the deterministic ID
    /// generator and the encryption-aware repository are process-global
    /// mutable state), so handler execution is serialized behind one mutex.
    /// Socket reads and writes happen *outside* the lock, which removes the
    /// head-of-line blocking that mattered: a slow or trickling client no
    /// longer stalls other connections. Running the database-bound handler
    /// bodies in parallel is deliberately deferred until the runtimes are
    /// async-native and the ID source is concurrency-safe; duplicating the
    /// deterministic generator across workers would let two workers mint
    /// identical fact IDs.
    struct Shared {
        runtime: Mutex<Runtime>,
        tokio: tokio::runtime::Runtime,
        config: ServerConfig,
        readiness_pool: sqlx::PgPool,
        challenge_store: PostgresLivePresenceChallengeStore,
        app_attest_registration_store: PostgresAppAttestKeyStateStore,
    }

    async fn connect_storage(
        config: &ServerConfig,
    ) -> Result<SqlxPostgresEncryptedFactRepository, String> {
        SqlxPostgresEncryptedFactRepository::connect(&config.database_url)
            .await
            .map_err(|error| format!("could not connect to PostgreSQL: {error:?}"))
    }

    fn build_runtime(
        config: &ServerConfig,
        storage: SqlxPostgresEncryptedFactRepository,
    ) -> Runtime {
        let pool = storage.pool().clone();
        let app_attest_key_state_store = PostgresAppAttestKeyStateStore::from_pool(pool.clone());
        let live_presence_challenge_store = PostgresLivePresenceChallengeStore::from_pool(pool);
        let key = FactDataEncryptionKey::active(
            config.fact_key_id.clone(),
            config.fact_key_material.clone(),
        );
        let account_repository = SqlxPostgresEncryptionAwareWorkflowRepository::new(
            storage.clone(),
            Aes256GcmFactEncryptionMetadataPlanner::new(
                config.fact_key_id.clone(),
                config.fact_nonce_domain,
                config.wrapped_dek_ref.clone(),
            ),
            RingAes256GcmFactEncryptor::new(),
            key.clone(),
            config.materialization_policy_refs.clone(),
        );
        let identity_repository = SqlxPostgresEncryptionAwareWorkflowRepository::new(
            storage,
            Aes256GcmFactEncryptionMetadataPlanner::new(
                config.fact_key_id.clone(),
                config.fact_nonce_domain,
                config.wrapped_dek_ref.clone(),
            ),
            RingAes256GcmFactEncryptor::new(),
            key.clone(),
            config.materialization_policy_refs.clone(),
        );
        let service = IdentityWorkflowService::new(FenTranslator {
            system_author: config.authored_by.clone(),
        });
        let account = PostgresEncryptedMobileOnboardingRuntime::new(
            service.clone(),
            config.authored_by.clone(),
            OidcJwksSessionVerifier::new(),
            StatefulAppAttestAssertionVerifier::new(
                config
                    .app_attest_verifier_config
                    .build_verifier(app_attest_key_state_store.clone()),
                app_attest_key_state_store.clone(),
            ),
            DeterministicIdGenerator::new(),
            account_repository,
            StaticFactKeyResolver::from_keys([key.clone()]),
        );
        let identity = PostgresEncryptedMobileIdentityOnboardingRuntime::new(
            service,
            config.authored_by.clone(),
            OidcJwksSessionVerifier::new(),
            StatefulAppAttestAssertionVerifier::new(
                config
                    .app_attest_verifier_config
                    .build_verifier(app_attest_key_state_store.clone()),
                app_attest_key_state_store,
            ),
            PersonaIdentityProofingProvider::new(),
            config.liveness_verifier.clone(),
            live_presence_challenge_store,
            config.continuity_provider.clone(),
            DeterministicIdGenerator::new(),
            identity_repository,
            StaticFactKeyResolver::from_keys([key]),
        );
        let runtime = Runtime { account, identity };
        runtime
    }

    fn serve(
        config: ServerConfig,
        runtime: Runtime,
        tokio_runtime: tokio::runtime::Runtime,
        readiness_pool: sqlx::PgPool,
        challenge_store: PostgresLivePresenceChallengeStore,
        app_attest_registration_store: PostgresAppAttestKeyStateStore,
    ) -> Result<(), String> {
        let shutdown = Arc::new(AtomicBool::new(false));
        install_shutdown_signal_handler(Arc::clone(&shutdown))?;

        let listener = TcpListener::bind(&config.bind_addr)
            .map_err(|error| format!("could not bind {}: {error}", config.bind_addr))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure listener: {error}"))?;
        println!("mobile onboarding server listening on {}", config.bind_addr);

        let worker_threads = config.worker_threads;
        let queue_depth = config.queue_depth;
        let shutdown_grace = config.shutdown_grace;
        let shared = Arc::new(Shared {
            runtime: Mutex::new(runtime),
            tokio: tokio_runtime,
            config,
            readiness_pool,
            challenge_store,
            app_attest_registration_store,
        });

        // Bounded hand-off: when every worker is busy and the queue is full,
        // new connections get an immediate 503 instead of queueing without
        // bound behind slow requests.
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(queue_depth);
        let receiver = Arc::new(Mutex::new(receiver));
        let workers: Vec<std::thread::JoinHandle<()>> = (0..worker_threads)
            .map(|index| {
                let shared = Arc::clone(&shared);
                let receiver = Arc::clone(&receiver);
                std::thread::Builder::new()
                    .name(format!("http-worker-{index}"))
                    .spawn(move || worker_loop(shared, receiver))
                    .expect("could not spawn http worker thread")
            })
            .collect();

        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => match sender.try_send(stream) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(mut stream)) => {
                        reject_overloaded(&mut stream, &shared.config);
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    // Transient accept failures (e.g. fd exhaustion) must not
                    // take the server down; log, back off, keep serving.
                    eprintln!("could not accept connection: {error}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        // Graceful drain: stop accepting, let workers finish queued and
        // in-flight requests. Total drain time is bounded by the queue depth
        // and the per-request deadline; the grace period is a backstop that
        // lets operators bound it explicitly.
        println!("mobile onboarding server draining (grace {shutdown_grace:?})");
        drop(sender);
        let drain_deadline = Instant::now() + shutdown_grace;
        for worker in workers {
            if Instant::now() >= drain_deadline {
                eprintln!("shutdown grace period elapsed; exiting with workers still busy");
                break;
            }
            let _ = worker.join();
        }
        println!("mobile onboarding server stopped");

        Ok(())
    }

    fn worker_loop(shared: Arc<Shared>, receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>) {
        loop {
            let stream = {
                let receiver = match receiver.lock() {
                    Ok(receiver) => receiver,
                    Err(_) => return,
                };
                match receiver.recv() {
                    Ok(stream) => stream,
                    Err(_) => return,
                }
            };
            let mut stream = stream;
            if let Err(error) = handle_connection(&mut stream, &shared) {
                eprintln!("request failed: {error}");
            }
        }
    }

    fn reject_overloaded(stream: &mut TcpStream, config: &ServerConfig) {
        let _ = stream.set_write_timeout(Some(config.read_timeout));
        let _ = write_http_response(
            stream,
            wire_json_response(
                503,
                r#"{"status":"error","error":{"code":"overloaded","message":"server is at capacity; retry shortly"}}"#,
            ),
        );
    }

    #[cfg(unix)]
    fn install_shutdown_signal_handler(shutdown: Arc<AtomicBool>) -> Result<(), String> {
        let signal_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|error| format!("could not start signal listener runtime: {error}"))?;
        std::thread::Builder::new()
            .name("signal-listener".to_string())
            .spawn(move || {
                signal_runtime.block_on(async {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut terminate = match signal(SignalKind::terminate()) {
                        Ok(signal) => signal,
                        Err(error) => {
                            eprintln!("could not listen for SIGTERM: {error}");
                            return;
                        }
                    };
                    let mut interrupt = match signal(SignalKind::interrupt()) {
                        Ok(signal) => signal,
                        Err(error) => {
                            eprintln!("could not listen for SIGINT: {error}");
                            return;
                        }
                    };
                    std::future::poll_fn(|context| {
                        if terminate.poll_recv(context).is_ready()
                            || interrupt.poll_recv(context).is_ready()
                        {
                            std::task::Poll::Ready(())
                        } else {
                            std::task::Poll::Pending
                        }
                    })
                    .await;
                });
                println!("shutdown signal received; draining in-flight requests");
                shutdown.store(true, Ordering::SeqCst);
            })
            .map_err(|error| format!("could not spawn signal listener thread: {error}"))?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn install_shutdown_signal_handler(_shutdown: Arc<AtomicBool>) -> Result<(), String> {
        Ok(())
    }

    fn handle_connection(stream: &mut TcpStream, shared: &Shared) -> Result<(), String> {
        let config = &shared.config;
        let _ = stream.set_read_timeout(Some(config.read_timeout));
        let _ = stream.set_write_timeout(Some(config.read_timeout));
        // Wall-clock deadline for the whole request. Socket timeouts only
        // bound each individual read; a client trickling one byte per second
        // would otherwise hold a worker indefinitely.
        let deadline = Instant::now() + config.request_deadline;
        let response = match read_http_request(stream, config.max_body_bytes, deadline) {
            Ok(request) => handle_request(request, shared),
            Err(ReadHttpRequestError::PayloadTooLarge) => wire_json_response(
                413,
                r#"{"status":"error","error":{"code":"payload_too_large","message":"request body exceeds configured limit"}}"#,
            ),
            Err(ReadHttpRequestError::BadRequest) => wire_json_response(
                400,
                r#"{"status":"error","error":{"code":"bad_request","message":"request must be a valid HTTP request"}}"#,
            ),
            Err(ReadHttpRequestError::DeadlineExceeded) => wire_json_response(
                408,
                r#"{"status":"error","error":{"code":"request_timeout","message":"request was not received within the configured deadline"}}"#,
            ),
            Err(ReadHttpRequestError::Io(error)) => return Err(format!("read failed: {error}")),
        };
        write_http_response(stream, response).map_err(|error| format!("write failed: {error}"))
    }

    fn handle_request(request: ParsedHttpRequest, shared: &Shared) -> WireResponse {
        let config = &shared.config;
        let route_path = request
            .path
            .split('?')
            .next()
            .unwrap_or(request.path.as_str());
        match (request.method.as_str(), route_path) {
            // Liveness and readiness must answer even while a long-running
            // onboarding request holds the runtime lock, so neither takes it:
            // readiness probes the pool directly.
            ("GET", "/health") => wire_json_response(200, r#"{"status":"ok"}"#),
            ("GET", "/ready") => {
                let probe = shared.tokio.block_on(async {
                    sqlx::query_scalar::<_, i32>("SELECT 1")
                        .fetch_one(&shared.readiness_pool)
                        .await
                });
                match probe {
                    Ok(1) => wire_json_response(200, r#"{"status":"ready"}"#),
                    Ok(_) | Err(_) => wire_json_response(503, r#"{"status":"not_ready"}"#),
                }
            }
            (method, MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CHALLENGE_HTTP_PATH) => {
                handle_live_presence_challenge_issue_http_request(
                    &shared.challenge_store,
                    method,
                    route_path,
                    request.body,
                    config,
                    &shared.tokio,
                )
            }
            (method, MOBILE_APP_ATTEST_KEY_REGISTRATION_CHALLENGE_HTTP_PATH) => {
                handle_app_attest_key_registration_challenge_http_request(
                    method,
                    route_path,
                    request.body,
                    config,
                )
            }
            (method, MOBILE_APP_ATTEST_KEY_REGISTRATION_HTTP_PATH) => {
                handle_app_attest_key_registration_http_request(
                    &shared.app_attest_registration_store,
                    method,
                    route_path,
                    request.body,
                    config,
                    &shared.tokio,
                )
            }
            (method, MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CALLBACK_HTTP_PATH) => {
                handle_live_presence_callback_http_request(method, route_path, request.body, config)
            }
            (method, MOBILE_IDENTITY_ONBOARDING_HTTP_PATH) => {
                let mut runtime = match shared.runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(poisoned) => return runtime_lock_poisoned_response(poisoned),
                };
                handle_identity_runtime_http_request(
                    &mut runtime.identity,
                    method,
                    route_path,
                    request.body,
                    config,
                    &shared.tokio,
                )
            }
            _ => {
                let mut runtime = match shared.runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(poisoned) => return runtime_lock_poisoned_response(poisoned),
                };
                handle_account_runtime_http_request(
                    &mut runtime.account,
                    &request.method,
                    route_path,
                    request.body,
                    config,
                    &shared.tokio,
                )
            }
        }
    }

    fn runtime_lock_poisoned_response(
        _poisoned: std::sync::PoisonError<std::sync::MutexGuard<'_, Runtime>>,
    ) -> WireResponse {
        // A worker panicked while holding the runtime lock. Refuse further
        // stateful work rather than running on possibly inconsistent
        // in-memory state; /health and /ready stay up for diagnosis.
        wire_json_response(
            500,
            r#"{"status":"error","error":{"code":"runtime_unavailable","message":"runtime state is unavailable after an internal error"}}"#,
        )
    }

    fn handle_account_runtime_http_request(
        runtime: &mut AccountRuntime,
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> WireResponse {
        let context = match config.persistence_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let response = tokio_runtime.block_on(runtime.handle_http_request(
            MobileOnboardingHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                body,
            },
            context,
        ));
        wire_response_from_mobile_response(response)
    }

    fn handle_live_presence_challenge_issue_http_request(
        store: &PostgresLivePresenceChallengeStore,
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> WireResponse {
        let issue_context = match config.live_presence_challenge_issue_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let (challenge, request_id) =
            match prepare_mobile_identity_onboarding_live_presence_challenge(
                MobileOnboardingHttpRequest {
                    method: method.to_string(),
                    path: path.to_string(),
                    body,
                },
                &issue_context,
            ) {
                Ok(prepared) => prepared,
                Err(response) => return wire_response_from_mobile_response(response),
            };
        // Run the store write on the runtime that owns the PostgreSQL pool.
        let stored = tokio_runtime.block_on(store.issue_live_presence_challenge_async(&challenge));
        wire_response_from_mobile_response(live_presence_challenge_issue_response(
            stored,
            &issue_context,
            request_id,
        ))
    }

    fn handle_live_presence_callback_http_request(
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
    ) -> WireResponse {
        let context = match config.live_presence_callback_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let response = handle_mobile_identity_onboarding_live_presence_callback_http_request(
            MobileOnboardingHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                body,
            },
            &config.liveness_callback_verifier(),
            context,
        );
        wire_response_from_mobile_response(response)
    }

    fn handle_app_attest_key_registration_challenge_http_request(
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
    ) -> WireResponse {
        let context = match config.app_attest_key_registration_challenge_issue_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let response = handle_mobile_app_attest_key_registration_challenge_http_request(
            MobileOnboardingHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                body,
            },
            context,
        );
        wire_response_from_mobile_response(response)
    }

    fn handle_app_attest_key_registration_http_request(
        store: &PostgresAppAttestKeyStateStore,
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> WireResponse {
        let context = match config.app_attest_key_registration_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let verifier = AppleAppAttestKeyRegistrationVerifier::new(context.expected_config.clone());
        let (registration, request_id) =
            match verify_mobile_app_attest_key_registration_http_request(
                MobileOnboardingHttpRequest {
                    method: method.to_string(),
                    path: path.to_string(),
                    body,
                },
                &verifier,
                &context,
            ) {
                Ok(verified) => verified,
                Err(response) => return wire_response_from_mobile_response(response),
            };
        // Run the store write on the runtime that owns the PostgreSQL pool,
        // matching the onboarding endpoints. Using a foreign runtime here made
        // the shared pool's connection acquire hang until timeout.
        let stored =
            tokio_runtime.block_on(store.record_app_attest_key_registration_async(&registration));
        wire_response_from_mobile_response(app_attest_key_registration_response(stored, request_id))
    }

    fn handle_identity_runtime_http_request(
        runtime: &mut IdentityRuntime,
        method: &str,
        path: &str,
        body: String,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> WireResponse {
        let context = match config.persistence_context() {
            Ok(context) => context,
            Err(error) => return runtime_context_error_response(error),
        };
        let response = tokio_runtime.block_on(runtime.handle_http_request(
            MobileOnboardingHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                body,
            },
            context,
        ));
        wire_response_from_mobile_response(response)
    }

    fn runtime_context_error_response(error: String) -> WireResponse {
        let body = serde_json::json!({
            "status": "error",
            "error": {
                "code": "runtime_context_failed",
                "message": error,
            },
        })
        .to_string();
        wire_json_response(500, &body)
    }

    fn wire_response_from_mobile_response(response: MobileOnboardingHttpResponse) -> WireResponse {
        WireResponse {
            status_code: response.status_code,
            content_type: response.content_type,
            body: response.body,
        }
    }

    #[derive(Debug, Clone)]
    struct ServerConfig {
        bind_addr: String,
        database_url: String,
        run_migrations: bool,
        max_body_bytes: usize,
        read_timeout: Duration,
        request_deadline: Duration,
        worker_threads: usize,
        queue_depth: usize,
        shutdown_grace: Duration,
        authored_by: Author,
        fact_key_id: String,
        fact_key_material: Vec<u8>,
        fact_nonce_domain: [u8; 4],
        wrapped_dek_ref: Option<String>,
        materialization_policy_refs: Vec<PolicyRef>,
        materialization_caller: Option<String>,
        materialization_purpose: Option<String>,
        transaction_id_prefix: String,
        app_attest_verifier_config: RuntimeAppAttestVerifierConfig,
        liveness_verifier: StaticLivenessCeremonyVerifier,
        continuity_provider: MockPhase1ContinuityProvider,
        app_attest_key_registration_challenge_ttl_seconds: u64,
        live_presence_challenge_ttl_seconds: u64,
        live_presence_provider_name: String,
        live_presence_handoff_uri: Option<String>,
        live_presence_callback_path: String,
        live_presence_retry_policy_refs: Vec<PolicyRef>,
        live_presence_manual_review_policy_refs: Vec<PolicyRef>,
        live_presence_retention_policy_refs: Vec<PolicyRef>,
    }

    impl ServerConfig {
        fn from_env() -> Result<Self, String> {
            let bind_addr = optional_env("IDENTITY_MODEL_RUNTIME_BIND_ADDR")
                .unwrap_or_else(|| "127.0.0.1:3000".to_string());
            let database_url = required_env("IDENTITY_MODEL_POSTGRES_URL")?;
            let run_migrations = bool_env("IDENTITY_MODEL_RUNTIME_RUN_MIGRATIONS", true)?;
            let max_body_bytes = usize_env("IDENTITY_MODEL_RUNTIME_MAX_BODY_BYTES", 65_536)?;
            let read_timeout =
                Duration::from_secs(u64_env("IDENTITY_MODEL_RUNTIME_READ_TIMEOUT_SECONDS", 5)?);
            let request_deadline = Duration::from_secs(u64_env(
                "IDENTITY_MODEL_RUNTIME_REQUEST_DEADLINE_SECONDS",
                15,
            )?);
            let worker_threads = usize_env("IDENTITY_MODEL_RUNTIME_WORKER_THREADS", 8)?.max(1);
            let queue_depth = usize_env("IDENTITY_MODEL_RUNTIME_QUEUE_DEPTH", 32)?.max(1);
            let shutdown_grace = Duration::from_secs(u64_env(
                "IDENTITY_MODEL_RUNTIME_SHUTDOWN_GRACE_SECONDS",
                20,
            )?);
            let authored_by = Author {
                author_type: AuthorType::System,
                author_id: Some(AuthorId(
                    optional_env("IDENTITY_MODEL_RUNTIME_AUTHOR_ID")
                        .unwrap_or_else(|| "author-mobile-runtime".to_string()),
                )),
                display_name: Some(
                    optional_env("IDENTITY_MODEL_RUNTIME_AUTHOR_DISPLAY")
                        .unwrap_or_else(|| "FEN mobile runtime".to_string()),
                ),
            };
            let fact_key_id = required_env("IDENTITY_MODEL_FACT_KEY_ID")?;
            let fact_key_material = fact_key_material_env()?;
            let fact_nonce_domain = nonce_domain_env("IDENTITY_MODEL_FACT_NONCE_DOMAIN_HEX")?;
            let wrapped_dek_ref = optional_env("IDENTITY_MODEL_WRAPPED_DEK_REF");
            let materialization_policy_refs =
                policy_refs_env("IDENTITY_MODEL_MATERIALIZATION_POLICY_REFS")?;
            let materialization_caller =
                optional_env("IDENTITY_MODEL_MATERIALIZATION_AUDIT_CALLER")
                    .or_else(|| Some("mobile-onboarding-server".to_string()));
            let materialization_purpose =
                optional_env("IDENTITY_MODEL_MATERIALIZATION_AUDIT_PURPOSE")
                    .or_else(|| Some("mobile-onboarding-summary".to_string()));
            let transaction_id_prefix = optional_env("IDENTITY_MODEL_TRANSACTION_ID_PREFIX")
                .unwrap_or_else(|| "tx-mobile-onboarding".to_string());
            let app_attest_verifier_config = app_attest_verifier_config_from_env()?;
            let liveness_verifier = liveness_verifier_from_env(&app_attest_verifier_config)?;
            let continuity_provider = MockPhase1ContinuityProvider::successful();
            let app_attest_key_registration_challenge_ttl_seconds = u64_env(
                "IDENTITY_MODEL_APP_ATTEST_KEY_REGISTRATION_CHALLENGE_TTL_SECONDS",
                300,
            )?;
            let live_presence_challenge_ttl_seconds =
                u64_env("IDENTITY_MODEL_LIVE_PRESENCE_CHALLENGE_TTL_SECONDS", 300)?;
            let live_presence_provider_name = liveness_verifier
                .verified_ceremony
                .provider_metadata
                .provider_name
                .clone();
            let live_presence_handoff_uri =
                optional_env("IDENTITY_MODEL_LIVE_PRESENCE_HANDOFF_URI");
            let live_presence_callback_path =
                optional_env("IDENTITY_MODEL_LIVE_PRESENCE_CALLBACK_PATH").unwrap_or_else(|| {
                    MOBILE_IDENTITY_ONBOARDING_LIVE_PRESENCE_CALLBACK_HTTP_PATH.to_string()
                });
            let live_presence_retry_policy_refs =
                optional_policy_refs_env("IDENTITY_MODEL_LIVE_PRESENCE_RETRY_POLICY_REFS")?
                    .unwrap_or_else(|| vec![PolicyRef("live-presence-retry@v1".to_string())]);
            let live_presence_manual_review_policy_refs =
                optional_policy_refs_env("IDENTITY_MODEL_LIVE_PRESENCE_MANUAL_REVIEW_POLICY_REFS")?
                    .unwrap_or_else(|| {
                        vec![PolicyRef("live-presence-manual-review@v1".to_string())]
                    });
            let live_presence_retention_policy_refs =
                optional_policy_refs_env("IDENTITY_MODEL_LIVE_PRESENCE_RETENTION_POLICY_REFS")?
                    .unwrap_or_else(|| vec![PolicyRef("live-presence-retention@v1".to_string())]);

            Ok(Self {
                bind_addr,
                database_url,
                run_migrations,
                max_body_bytes,
                read_timeout,
                request_deadline,
                worker_threads,
                queue_depth,
                shutdown_grace,
                authored_by,
                fact_key_id,
                fact_key_material,
                fact_nonce_domain,
                wrapped_dek_ref,
                materialization_policy_refs,
                materialization_caller,
                materialization_purpose,
                transaction_id_prefix,
                app_attest_verifier_config,
                liveness_verifier,
                continuity_provider,
                app_attest_key_registration_challenge_ttl_seconds,
                live_presence_challenge_ttl_seconds,
                live_presence_provider_name,
                live_presence_handoff_uri,
                live_presence_callback_path,
                live_presence_retry_policy_refs,
                live_presence_manual_review_policy_refs,
                live_presence_retention_policy_refs,
            })
        }

        fn persistence_context(
            &self,
        ) -> Result<MobileOnboardingEncryptedPersistenceContext, String> {
            let (now, nanos) = now_timestamp_and_nanos()?;
            Ok(MobileOnboardingEncryptedPersistenceContext {
                transaction_id: PersistenceTransactionId(format!(
                    "{}-{nanos}",
                    self.transaction_id_prefix
                )),
                committed_at: now.clone(),
                materialization_policy: PolicyEvaluation {
                    action: SensitiveAction::ViewRecord,
                    decision: AccessDecisionResult::Allowed,
                    reasons: Vec::new(),
                    relied_on_facts: Vec::new(),
                    policy_refs: self.materialization_policy_refs.clone(),
                },
                materialization_audit_context: FactMaterializationAuditContext::new(
                    self.materialization_caller.clone(),
                    self.materialization_purpose.clone(),
                    Some(now),
                ),
            })
        }

        fn live_presence_challenge_issue_context(
            &self,
        ) -> Result<MobileLivePresenceChallengeIssueContext, String> {
            let (issued_at, nanos) = now_timestamp_and_nanos()?;
            let issued_at_seconds = timestamp_to_unix_seconds(&issued_at)
                .map_err(|_| "could not parse generated live-presence issued_at".to_string())?;
            let expires_at = unix_seconds_to_timestamp(
                issued_at_seconds + self.live_presence_challenge_ttl_seconds as i64,
            );
            Ok(MobileLivePresenceChallengeIssueContext {
                challenge_id: LivePresenceChallengeId(format!("live-presence-{nanos}")),
                challenge_nonce: generate_challenge_nonce("live-presence")?,
                issued_at,
                expires_at,
                provider_name: self.live_presence_provider_name.clone(),
                handoff_uri: self.live_presence_handoff_uri.clone(),
                callback_path: self.live_presence_callback_path.clone(),
                retry_policy_refs: self.live_presence_retry_policy_refs.clone(),
                manual_review_policy_refs: self.live_presence_manual_review_policy_refs.clone(),
                retention_policy_refs: self.live_presence_retention_policy_refs.clone(),
            })
        }

        fn app_attest_key_registration_challenge_issue_context(
            &self,
        ) -> Result<MobileAppAttestKeyRegistrationChallengeIssueContext, String> {
            let (issued_at, _) = now_timestamp_and_nanos()?;
            let issued_at_seconds = timestamp_to_unix_seconds(&issued_at).map_err(|_| {
                "could not parse generated App Attest registration challenge issued_at".to_string()
            })?;
            let expires_at = unix_seconds_to_timestamp(
                issued_at_seconds + self.app_attest_key_registration_challenge_ttl_seconds as i64,
            );
            Ok(MobileAppAttestKeyRegistrationChallengeIssueContext {
                challenge_nonce: generate_challenge_nonce("App Attest key-registration")?,
                issued_at,
                expires_at,
                expected_config: self.app_attest_verifier_config.expected_config(),
            })
        }

        fn app_attest_key_registration_context(
            &self,
        ) -> Result<MobileAppAttestKeyRegistrationContext, String> {
            let (observed_at, _) = now_timestamp_and_nanos()?;
            Ok(MobileAppAttestKeyRegistrationContext {
                observed_at,
                expected_config: self.app_attest_verifier_config.expected_config(),
            })
        }

        fn live_presence_callback_context(
            &self,
        ) -> Result<MobileLivePresenceCallbackContext, String> {
            let (observed_at, _) = now_timestamp_and_nanos()?;
            Ok(MobileLivePresenceCallbackContext { observed_at })
        }

        fn liveness_callback_verifier(&self) -> StaticLivenessProviderCallbackVerifier {
            StaticLivenessProviderCallbackVerifier::new(
                self.live_presence_provider_name.clone(),
                self.liveness_verifier.expected_assertion.clone(),
            )
        }
    }

    fn app_attest_verifier_config_from_env() -> Result<RuntimeAppAttestVerifierConfig, String> {
        match optional_env("IDENTITY_MODEL_APP_ATTEST_VERIFIER")
            .unwrap_or_else(|| "static".to_string())
            .as_str()
        {
            "static" => Ok(RuntimeAppAttestVerifierConfig::Static(
                static_app_attest_verifier_from_env()?,
            )),
            "apple_assertion" | "apple" => Ok(RuntimeAppAttestVerifierConfig::AppleAssertion {
                expected_config: app_attest_config_from_env()?,
            }),
            other => Err(format!(
                "IDENTITY_MODEL_APP_ATTEST_VERIFIER must be static or apple_assertion; got {other}"
            )),
        }
    }

    fn app_attest_config_from_env() -> Result<AppAttestClientConfig, String> {
        Ok(AppAttestClientConfig::ios_app(
            required_env("IDENTITY_MODEL_APP_ATTEST_TEAM_ID")?,
            required_env("IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID")?,
            app_attest_environment_env("IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT")?,
        ))
    }

    fn static_app_attest_verifier_from_env() -> Result<StaticAppAttestAssertionVerifier, String> {
        let config = app_attest_config_from_env()?;
        let expected_assertion = required_env("IDENTITY_MODEL_APP_ATTEST_EXPECTED_ASSERTION")?;
        let challenge_nonce = optional_env("IDENTITY_MODEL_APP_ATTEST_CHALLENGE_NONCE")
            .unwrap_or_else(|| "static-app-attest-template-nonce".to_string());
        Ok(StaticAppAttestAssertionVerifier::new(
            expected_assertion,
            VerifiedAppAttestAssertion {
                team_id: config.team_id.clone(),
                bundle_id: config.bundle_id.clone(),
                app_id: config.app_id.clone(),
                environment: config.environment,
                device_ref: required_env("IDENTITY_MODEL_APP_ATTEST_DEVICE_REF")?,
                key_id: required_env("IDENTITY_MODEL_APP_ATTEST_KEY_ID")?,
                challenge_nonce,
                sign_count: u64_env("IDENTITY_MODEL_APP_ATTEST_SIGN_COUNT", 1)?,
                asserted_at: Timestamp(required_env("IDENTITY_MODEL_APP_ATTEST_ASSERTED_AT")?),
                expires_at: Timestamp(required_env("IDENTITY_MODEL_APP_ATTEST_EXPIRES_AT")?),
                assurance_level: assurance_level_env(
                    "IDENTITY_MODEL_APP_ATTEST_ASSURANCE_LEVEL",
                    AssuranceLevel::Medium,
                )?,
            },
        )
        .with_request_challenge_nonce())
    }

    fn liveness_verifier_from_env(
        app_attest_verifier: &RuntimeAppAttestVerifierConfig,
    ) -> Result<StaticLivenessCeremonyVerifier, String> {
        let app_attest = app_attest_verifier.static_verified_assertion();
        let expected_assertion = optional_env("IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION")
            .unwrap_or_else(|| "valid-live-presence-assertion".to_string());
        let provider_name = optional_env("IDENTITY_MODEL_LIVENESS_PROVIDER_NAME")
            .unwrap_or_else(|| "StaticLivePresenceProvider".to_string());
        let provider_event_id = optional_env("IDENTITY_MODEL_LIVENESS_PROVIDER_EVENT_ID");
        let provider_subject_ref = optional_env("IDENTITY_MODEL_LIVENESS_PROVIDER_SUBJECT_REF");
        let sdk_or_api_version = optional_env("IDENTITY_MODEL_LIVENESS_SDK_OR_API_VERSION");
        let challenge_nonce = optional_env("IDENTITY_MODEL_LIVENESS_CHALLENGE_NONCE")
            .or_else(|| app_attest.map(|assertion| assertion.challenge_nonce.clone()))
            .ok_or_else(|| {
                "IDENTITY_MODEL_LIVENESS_CHALLENGE_NONCE is required for apple_assertion App Attest mode"
                    .to_string()
            })?;
        let device_ref = optional_env("IDENTITY_MODEL_LIVENESS_DEVICE_REF")
            .or_else(|| app_attest.map(|assertion| assertion.device_ref.clone()))
            .ok_or_else(|| {
                "IDENTITY_MODEL_LIVENESS_DEVICE_REF is required for apple_assertion App Attest mode"
                    .to_string()
            })?;
        let observed_at = optional_env("IDENTITY_MODEL_LIVENESS_OBSERVED_AT")
            .map(Timestamp)
            .or_else(|| app_attest.map(|assertion| assertion.asserted_at.clone()))
            .ok_or_else(|| {
                "IDENTITY_MODEL_LIVENESS_OBSERVED_AT is required for apple_assertion App Attest mode"
                    .to_string()
            })?;
        let expires_at = optional_env("IDENTITY_MODEL_LIVENESS_EXPIRES_AT")
            .map(Timestamp)
            .or_else(|| app_attest.map(|assertion| assertion.expires_at.clone()))
            .ok_or_else(|| {
                "IDENTITY_MODEL_LIVENESS_EXPIRES_AT is required for apple_assertion App Attest mode"
                    .to_string()
            })?;
        let retention_policy_refs =
            optional_policy_refs_env("IDENTITY_MODEL_LIVENESS_RETENTION_POLICY_REFS")?
                .unwrap_or_else(|| vec![PolicyRef("live-presence-retention@v1".to_string())]);

        Ok(StaticLivenessCeremonyVerifier::new(
            expected_assertion,
            VerifiedLivenessCeremony {
                provider_metadata: ContinuityProviderMetadata {
                    provider_name,
                    provider_event_id,
                    provider_subject_ref,
                    sdk_or_api_version,
                },
                challenge_nonce,
                device_ref,
                observed_at,
                expires_at,
                result: identity_witness_result_env(
                    "IDENTITY_MODEL_LIVENESS_RESULT",
                    IdentityWitnessResult::Passed,
                )?,
                assurance_level: assurance_level_env(
                    "IDENTITY_MODEL_LIVENESS_ASSURANCE_LEVEL",
                    AssuranceLevel::High,
                )?,
                pad_result: pad_result_env(
                    "IDENTITY_MODEL_LIVENESS_PAD_RESULT",
                    PresentationAttackDetectionResult::Passed,
                )?,
                retention_policy_refs,
            },
        )
        .with_request_challenge_nonce()
        .with_request_device_ref())
    }

    #[derive(Debug, Clone)]
    struct ParsedHttpRequest {
        method: String,
        path: String,
        body: String,
    }

    #[derive(Debug)]
    enum ReadHttpRequestError {
        BadRequest,
        PayloadTooLarge,
        DeadlineExceeded,
        Io(std::io::Error),
    }

    fn read_http_request(
        stream: &mut TcpStream,
        max_body_bytes: usize,
        deadline: Instant,
    ) -> Result<ParsedHttpRequest, ReadHttpRequestError> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            if Instant::now() >= deadline {
                return Err(ReadHttpRequestError::DeadlineExceeded);
            }
            let read = stream.read(&mut chunk).map_err(read_error)?;
            if read == 0 {
                return Err(ReadHttpRequestError::BadRequest);
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(index) = find_header_end(&buffer) {
                break index;
            }
            if buffer.len() > 16 * 1024 {
                return Err(ReadHttpRequestError::BadRequest);
            }
        };

        let headers = std::str::from_utf8(&buffer[..header_end])
            .map_err(|_| ReadHttpRequestError::BadRequest)?;
        let mut lines = headers.split("\r\n");
        let request_line = lines.next().ok_or(ReadHttpRequestError::BadRequest)?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .ok_or(ReadHttpRequestError::BadRequest)?
            .to_string();
        let path = request_parts
            .next()
            .ok_or(ReadHttpRequestError::BadRequest)?
            .to_string();
        let content_length = content_length(headers)?;
        if content_length > max_body_bytes {
            return Err(ReadHttpRequestError::PayloadTooLarge);
        }

        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            if Instant::now() >= deadline {
                return Err(ReadHttpRequestError::DeadlineExceeded);
            }
            let read = stream.read(&mut chunk).map_err(read_error)?;
            if read == 0 {
                return Err(ReadHttpRequestError::BadRequest);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body = String::from_utf8(buffer[body_start..body_start + content_length].to_vec())
            .map_err(|_| ReadHttpRequestError::BadRequest)?;

        Ok(ParsedHttpRequest { method, path, body })
    }

    fn read_error(error: std::io::Error) -> ReadHttpRequestError {
        // A per-read socket timeout surfaces as WouldBlock/TimedOut; report
        // it as a request timeout rather than an opaque I/O failure so the
        // client gets a 408 instead of a dropped connection.
        match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                ReadHttpRequestError::DeadlineExceeded
            }
            _ => ReadHttpRequestError::Io(error),
        }
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &str) -> Result<usize, ReadHttpRequestError> {
        for line in headers.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse()
                    .map_err(|_| ReadHttpRequestError::BadRequest);
            }
        }
        Ok(0)
    }

    struct WireResponse {
        status_code: u16,
        content_type: &'static str,
        body: String,
    }

    fn wire_json_response(status_code: u16, body: &str) -> WireResponse {
        WireResponse {
            status_code,
            content_type: APPLICATION_JSON,
            body: body.to_string(),
        }
    }

    fn write_http_response(stream: &mut TcpStream, response: WireResponse) -> std::io::Result<()> {
        let status = reason_phrase(response.status_code);
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status_code,
            status,
            response.content_type,
            response.body.len(),
            response.body
        )
    }

    fn reason_phrase(status_code: u16) -> &'static str {
        match status_code {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            408 => "Request Timeout",
            405 => "Method Not Allowed",
            409 => "Conflict",
            413 => "Payload Too Large",
            422 => "Unprocessable Entity",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "OK",
        }
    }

    fn required_env(name: &'static str) -> Result<String, String> {
        env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing required environment variable {name}"))
    }

    fn optional_env(name: &str) -> Option<String> {
        env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn bool_env(name: &'static str, default: bool) -> Result<bool, String> {
        match optional_env(name).as_deref() {
            Some("true" | "1" | "yes") => Ok(true),
            Some("false" | "0" | "no") => Ok(false),
            Some(other) => Err(format!(
                "{name} must be true/false, 1/0, or yes/no; got {other}"
            )),
            None => Ok(default),
        }
    }

    fn usize_env(name: &'static str, default: usize) -> Result<usize, String> {
        optional_env(name)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("{name} must be a positive integer; got {value}"))
            })
            .unwrap_or(Ok(default))
    }

    fn u64_env(name: &'static str, default: u64) -> Result<u64, String> {
        optional_env(name)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("{name} must be a positive integer; got {value}"))
            })
            .unwrap_or(Ok(default))
    }

    fn policy_refs_env(name: &'static str) -> Result<Vec<PolicyRef>, String> {
        let refs = required_env(name)?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| PolicyRef(value.to_string()))
            .collect::<Vec<_>>();
        if refs.is_empty() {
            return Err(format!("{name} must contain at least one policy ref"));
        }
        Ok(refs)
    }

    fn optional_policy_refs_env(name: &'static str) -> Result<Option<Vec<PolicyRef>>, String> {
        optional_env(name)
            .map(|value| {
                let refs = value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| PolicyRef(value.to_string()))
                    .collect::<Vec<_>>();
                if refs.is_empty() {
                    return Err(format!("{name} must contain at least one policy ref"));
                }
                Ok(refs)
            })
            .transpose()
    }

    fn fact_key_material_env() -> Result<Vec<u8>, String> {
        if let Some(value) = optional_env("IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX") {
            let bytes = decode_hex(&value)?;
            if bytes.len() != 32 {
                return Err(
                    "IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX must decode to exactly 32 bytes"
                        .to_string(),
                );
            }
            return Ok(bytes);
        }

        let bytes = required_env("IDENTITY_MODEL_FACT_KEY_MATERIAL")?.into_bytes();
        if bytes.len() != 32 {
            return Err(
                "IDENTITY_MODEL_FACT_KEY_MATERIAL must be exactly 32 bytes, or provide IDENTITY_MODEL_FACT_KEY_MATERIAL_HEX"
                    .to_string(),
            );
        }
        Ok(bytes)
    }

    fn nonce_domain_env(name: &'static str) -> Result<[u8; 4], String> {
        let value = optional_env(name).unwrap_or_else(|| "46454e31".to_string());
        let bytes = decode_hex(&value)?;
        bytes
            .try_into()
            .map_err(|_| format!("{name} must decode to exactly 4 bytes"))
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
        let value = value.trim();
        if value.len() % 2 != 0 {
            return Err("hex value must have an even number of characters".to_string());
        }

        let mut bytes = Vec::with_capacity(value.len() / 2);
        let mut chars = value.as_bytes().chunks_exact(2);
        for pair in &mut chars {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            bytes.push((high << 4) | low);
        }
        Ok(bytes)
    }

    fn generate_challenge_nonce(label: &str) -> Result<String, String> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0_u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| format!("could not generate {label} challenge nonce"))?;
        Ok(encode_hex(&bytes))
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn hex_nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("hex value contains a non-hex character".to_string()),
        }
    }

    fn app_attest_environment_env(name: &'static str) -> Result<AppAttestEnvironment, String> {
        match required_env(name)?.as_str() {
            "development" => Ok(AppAttestEnvironment::Development),
            "production" => Ok(AppAttestEnvironment::Production),
            other => Err(format!(
                "{name} must be development or production; got {other}"
            )),
        }
    }

    fn assurance_level_env(
        name: &'static str,
        default: AssuranceLevel,
    ) -> Result<AssuranceLevel, String> {
        match optional_env(name).as_deref() {
            Some("low") => Ok(AssuranceLevel::Low),
            Some("medium") => Ok(AssuranceLevel::Medium),
            Some("high") => Ok(AssuranceLevel::High),
            Some("very_high") => Ok(AssuranceLevel::VeryHigh),
            Some(other) => Err(format!(
                "{name} must be low, medium, high, or very_high; got {other}"
            )),
            None => Ok(default),
        }
    }

    fn identity_witness_result_env(
        name: &'static str,
        default: IdentityWitnessResult,
    ) -> Result<IdentityWitnessResult, String> {
        match optional_env(name).as_deref() {
            Some("passed") => Ok(IdentityWitnessResult::Passed),
            Some("failed") => Ok(IdentityWitnessResult::Failed),
            Some("inconclusive") => Ok(IdentityWitnessResult::Inconclusive),
            Some(other) => Err(format!(
                "{name} must be passed, failed, or inconclusive; got {other}"
            )),
            None => Ok(default),
        }
    }

    fn pad_result_env(
        name: &'static str,
        default: PresentationAttackDetectionResult,
    ) -> Result<PresentationAttackDetectionResult, String> {
        match optional_env(name).as_deref() {
            Some("passed") => Ok(PresentationAttackDetectionResult::Passed),
            Some("failed") => Ok(PresentationAttackDetectionResult::Failed),
            Some("inconclusive") => Ok(PresentationAttackDetectionResult::Inconclusive),
            Some("not_performed") => Ok(PresentationAttackDetectionResult::NotPerformed),
            Some(other) => Err(format!(
                "{name} must be passed, failed, inconclusive, or not_performed; got {other}"
            )),
            None => Ok(default),
        }
    }

    fn now_timestamp_and_nanos() -> Result<(Timestamp, u128), String> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system time is before the Unix epoch".to_string())?;
        Ok((
            unix_seconds_to_timestamp(duration.as_secs() as i64),
            duration.as_nanos(),
        ))
    }
}
