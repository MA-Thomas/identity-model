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
    use std::env;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    type Runtime = PostgresEncryptedMobileOnboardingRuntime<
        Aes256GcmFactEncryptionMetadataPlanner,
        RingAes256GcmFactEncryptor,
        OidcJwksSessionVerifier,
        StatefulAppAttestAssertionVerifier<
            StaticAppAttestAssertionVerifier,
            PostgresAppAttestKeyStateStore,
        >,
        DeterministicIdGenerator,
        StaticFactKeyResolver,
    >;

    pub fn run() -> Result<(), String> {
        let config = ServerConfig::from_env()?;
        let tokio_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start async runtime: {error}"))?;
        let runtime = tokio_runtime.block_on(build_runtime(&config))?;

        serve(config, runtime, &tokio_runtime)
    }

    async fn build_runtime(config: &ServerConfig) -> Result<Runtime, String> {
        let storage = SqlxPostgresEncryptedFactRepository::connect(&config.database_url)
            .await
            .map_err(|error| format!("could not connect to PostgreSQL: {error:?}"))?;
        let app_attest_key_state_store =
            PostgresAppAttestKeyStateStore::from_pool(storage.pool().clone());
        let key = FactDataEncryptionKey::active(
            config.fact_key_id.clone(),
            config.fact_key_material.clone(),
        );
        let repository = SqlxPostgresEncryptionAwareWorkflowRepository::new(
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
        let runtime = PostgresEncryptedMobileOnboardingRuntime::new(
            service,
            config.authored_by.clone(),
            OidcJwksSessionVerifier::new(),
            StatefulAppAttestAssertionVerifier::new(
                config.app_attest_verifier.clone(),
                app_attest_key_state_store,
            ),
            DeterministicIdGenerator::new(),
            repository,
            StaticFactKeyResolver::from_keys([key]),
        );

        if config.run_migrations {
            runtime
                .run_migrations()
                .await
                .map_err(|error| format!("could not run migrations: {error:?}"))?;
        }

        Ok(runtime)
    }

    fn serve(
        config: ServerConfig,
        mut runtime: Runtime,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        let listener = TcpListener::bind(&config.bind_addr)
            .map_err(|error| format!("could not bind {}: {error}", config.bind_addr))?;
        println!("mobile onboarding server listening on {}", config.bind_addr);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(config.read_timeout));
                    let _ = stream.set_write_timeout(Some(config.read_timeout));
                    if let Err(error) =
                        handle_connection(&mut stream, &mut runtime, &config, tokio_runtime)
                    {
                        eprintln!("request failed: {error}");
                    }
                }
                Err(error) => return Err(format!("could not accept connection: {error}")),
            }
        }

        Ok(())
    }

    fn handle_connection(
        stream: &mut TcpStream,
        runtime: &mut Runtime,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        let response = match read_http_request(stream, config.max_body_bytes) {
            Ok(request) => handle_request(request, runtime, config, tokio_runtime),
            Err(ReadHttpRequestError::PayloadTooLarge) => wire_json_response(
                413,
                r#"{"status":"error","error":{"code":"payload_too_large","message":"request body exceeds configured limit"}}"#,
            ),
            Err(ReadHttpRequestError::BadRequest) => wire_json_response(
                400,
                r#"{"status":"error","error":{"code":"bad_request","message":"request must be a valid HTTP request"}}"#,
            ),
            Err(ReadHttpRequestError::Io(error)) => return Err(format!("read failed: {error}")),
        };
        write_http_response(stream, response).map_err(|error| format!("write failed: {error}"))
    }

    fn handle_request(
        request: ParsedHttpRequest,
        runtime: &mut Runtime,
        config: &ServerConfig,
        tokio_runtime: &tokio::runtime::Runtime,
    ) -> WireResponse {
        let route_path = request
            .path
            .split('?')
            .next()
            .unwrap_or(request.path.as_str());
        match (request.method.as_str(), route_path) {
            ("GET", "/health") => wire_json_response(200, r#"{"status":"ok"}"#),
            ("GET", "/ready") => match tokio_runtime.block_on(runtime.readiness_check()) {
                Ok(readiness) if readiness.database_reachable => {
                    wire_json_response(200, r#"{"status":"ready"}"#)
                }
                Ok(_) => wire_json_response(503, r#"{"status":"not_ready"}"#),
                Err(_) => wire_json_response(503, r#"{"status":"not_ready"}"#),
            },
            _ => {
                let context = match config.persistence_context() {
                    Ok(context) => context,
                    Err(error) => {
                        return wire_json_response(
                            500,
                            &format!(
                                r#"{{"status":"error","error":{{"code":"runtime_context_failed","message":"{error}"}}}}"#
                            ),
                        );
                    }
                };
                let response = tokio_runtime.block_on(runtime.handle_http_request(
                    MobileOnboardingHttpRequest {
                        method: request.method,
                        path: route_path.to_string(),
                        body: request.body,
                    },
                    context,
                ));
                WireResponse {
                    status_code: response.status_code,
                    content_type: response.content_type,
                    body: response.body,
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ServerConfig {
        bind_addr: String,
        database_url: String,
        run_migrations: bool,
        max_body_bytes: usize,
        read_timeout: Duration,
        authored_by: Author,
        fact_key_id: String,
        fact_key_material: Vec<u8>,
        fact_nonce_domain: [u8; 4],
        wrapped_dek_ref: Option<String>,
        materialization_policy_refs: Vec<PolicyRef>,
        materialization_caller: Option<String>,
        materialization_purpose: Option<String>,
        transaction_id_prefix: String,
        app_attest_verifier: StaticAppAttestAssertionVerifier,
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
            let authored_by = Author {
                author_type: AuthorType::System,
                author_id: Some(Id(optional_env("IDENTITY_MODEL_RUNTIME_AUTHOR_ID")
                    .unwrap_or_else(|| "author-mobile-runtime".to_string()))),
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
            let app_attest_verifier = app_attest_verifier_from_env()?;

            Ok(Self {
                bind_addr,
                database_url,
                run_migrations,
                max_body_bytes,
                read_timeout,
                authored_by,
                fact_key_id,
                fact_key_material,
                fact_nonce_domain,
                wrapped_dek_ref,
                materialization_policy_refs,
                materialization_caller,
                materialization_purpose,
                transaction_id_prefix,
                app_attest_verifier,
            })
        }

        fn persistence_context(
            &self,
        ) -> Result<MobileOnboardingEncryptedPersistenceContext, String> {
            let (now, nanos) = now_timestamp_and_nanos()?;
            Ok(MobileOnboardingEncryptedPersistenceContext {
                transaction_id: Id(format!("{}-{nanos}", self.transaction_id_prefix)),
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
    }

    fn app_attest_verifier_from_env() -> Result<StaticAppAttestAssertionVerifier, String> {
        let config = AppAttestClientConfig::ios_app(
            required_env("IDENTITY_MODEL_APP_ATTEST_TEAM_ID")?,
            required_env("IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID")?,
            app_attest_environment_env("IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT")?,
        );
        let expected_assertion = required_env("IDENTITY_MODEL_APP_ATTEST_EXPECTED_ASSERTION")?;
        let challenge_nonce = required_env("IDENTITY_MODEL_APP_ATTEST_CHALLENGE_NONCE")?;
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
        ))
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
        Io(std::io::Error),
    }

    fn read_http_request(
        stream: &mut TcpStream,
        max_body_bytes: usize,
    ) -> Result<ParsedHttpRequest, ReadHttpRequestError> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).map_err(ReadHttpRequestError::Io)?;
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
            let read = stream.read(&mut chunk).map_err(ReadHttpRequestError::Io)?;
            if read == 0 {
                return Err(ReadHttpRequestError::BadRequest);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body = String::from_utf8(buffer[body_start..body_start + content_length].to_vec())
            .map_err(|_| ReadHttpRequestError::BadRequest)?;

        Ok(ParsedHttpRequest { method, path, body })
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
            .map(|value| Id(value.to_string()))
            .collect::<Vec<_>>();
        if refs.is_empty() {
            return Err(format!("{name} must contain at least one policy ref"));
        }
        Ok(refs)
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
