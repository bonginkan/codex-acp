use acp::schema::{
    AgentAuthCapabilities, AgentCapabilities, AuthEnvVar, AuthMethod, AuthMethodAgent,
    AuthMethodEnvVar, AuthMethodId, AuthenticateRequest, AuthenticateResponse, CancelNotification,
    ClientCapabilities, CloseSessionRequest, CloseSessionResponse, ContentBlock, Implementation,
    InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
    LoadSessionRequest, LoadSessionResponse, LogoutCapabilities, LogoutRequest, LogoutResponse,
    McpCapabilities, McpServer, McpServerHttp, McpServerStdio, NewSessionRequest,
    NewSessionResponse, PromptCapabilities, PromptRequest, PromptResponse, ProtocolVersion,
    SessionCapabilities, SessionCloseCapabilities, SessionId, SessionInfo, SessionListCapabilities,
    SetSessionConfigOptionRequest, SetSessionConfigOptionResponse, SetSessionModeRequest,
    SetSessionModeResponse, SetSessionModelRequest, SetSessionModelResponse,
};
use acp::{Agent, Client, ConnectTo, ConnectionTo, Error};
use agent_client_protocol as acp;
use codex_config::{McpServerConfig, McpServerTransportConfig};
use codex_core::{
    CodexAppsToolsCache, NewThread, RolloutRecorder, SortDirection, StartThreadOptions,
    StateDbHandle, ThreadManager, ThreadSortKey, build_models_manager, config::Config,
    find_thread_path_by_id_str, init_state_db, parse_cursor, resolve_installation_id,
    thread_store_from_config,
};
use codex_exec_server::{EnvironmentManager, ExecServerRuntimePaths};
use codex_extension_api::empty_extension_registry;
use codex_home::CodexHomeUserInstructionsProvider;
use codex_login::{
    CODEX_API_KEY_ENV_VAR, OPENAI_API_KEY_ENV_VAR,
    auth::{AuthManager, CodexAuth, read_codex_api_key_from_env, read_openai_api_key_from_env},
};
use codex_protocol::{
    ThreadId,
    mcp::ClientMcpExtensions,
    protocol::{SessionConfiguredEvent, SessionSource},
};
use codex_rollout::InitialHistory;
use codex_utils_path_uri::LegacyAppPathString;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tracing::{debug, info};
use unicode_segmentation::UnicodeSegmentation;

use crate::restricted::{
    RestrictedRuntime, reject_validation_metadata_when_feature_disabled, request_hash, sha256_hex,
};
use crate::thread::Thread;

/// The Codex implementation of the ACP Agent.
///
/// This bridges the ACP protocol with the existing codex-rs infrastructure,
/// allowing codex to be used as an ACP agent.
pub struct CodexAgent {
    /// Handle to the current authentication
    auth_manager: Arc<AuthManager>,
    /// Capabilities of the connected client
    client_capabilities: Arc<Mutex<ClientCapabilities>>,
    /// The underlying codex configuration
    config: Config,
    /// Thread manager for handling sessions
    thread_manager: ThreadManager,
    /// SQLite-backed Codex state index, when initialization succeeds
    state_db: Option<StateDbHandle>,
    /// Active sessions mapped by `SessionId`
    sessions: Arc<Mutex<HashMap<SessionId, Arc<Thread>>>>,
    /// Session working directories for filesystem sandboxing
    session_roots: Arc<Mutex<HashMap<SessionId, PathBuf>>>,
    /// Fail-closed NINNA inquiry runtime, when explicitly enabled at process start.
    restricted: Option<Arc<RestrictedRuntime>>,
}

const SESSION_LIST_PAGE_SIZE: usize = 25;
const SESSION_TITLE_MAX_GRAPHEMES: usize = 120;
const SESSION_RUNTIME_EVIDENCE_SCHEMA_VERSION: u32 = 1;

fn session_runtime_evidence_value(
    session_id: &str,
    process_id: u32,
    model: &str,
    model_provider: &str,
    reasoning_effort: Option<String>,
    service_tier: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": SESSION_RUNTIME_EVIDENCE_SCHEMA_VERSION,
        "processId": process_id,
        "sessionIdHash": sha256_hex(session_id.as_bytes()),
        "sourceCommit": option_env!("NINNA_SOURCE_COMMIT").unwrap_or("unknown"),
        "effectiveModel": model,
        "effectiveModelProvider": model_provider,
        "effectiveReasoningEffort": reasoning_effort,
        "effectiveServiceTier": service_tier,
    })
}

fn normal_session_runtime_meta(
    session_id: &SessionId,
    session_configured: &SessionConfiguredEvent,
) -> acp::schema::Meta {
    acp::schema::Meta::from_iter([(
        "ninnaSessionRuntimeEvidence".to_string(),
        session_runtime_evidence_value(
            session_id.0.as_ref(),
            std::process::id(),
            &session_configured.model,
            &session_configured.model_provider_id,
            session_configured
                .reasoning_effort
                .as_ref()
                .map(ToString::to_string),
            session_configured.service_tier.clone(),
        ),
    )])
}

impl CodexAgent {
    /// Create a new `CodexAgent` with the given configuration
    pub async fn new(
        config: Config,
        codex_linux_sandbox_exe: Option<PathBuf>,
        restricted: Option<Arc<RestrictedRuntime>>,
    ) -> std::io::Result<Self> {
        let auth_manager = AuthManager::shared_from_config(&config, false)
            .await
            .map_err(std::io::Error::other)?;

        let client_capabilities: Arc<Mutex<ClientCapabilities>> = Arc::default();
        let session_roots: Arc<Mutex<HashMap<SessionId, PathBuf>>> = Arc::default();
        let state_db = init_state_db(&config).await;
        let local_runtime_paths =
            ExecServerRuntimePaths::new(std::env::current_exe()?, codex_linux_sandbox_exe)?;
        // rust-v0.146.0 で from_codex_home は HttpClientFactory を受け取る。
        let environment_manager = Arc::new(
            EnvironmentManager::from_codex_home(
                config.codex_home.clone(),
                Some(local_runtime_paths),
                config.http_client_factory(),
            )
            .await
            .map_err(std::io::Error::other)?,
        );
        let thread_store = thread_store_from_config(&config, state_db.clone());
        let agent_graph_store =
            codex_core::local_agent_graph_store_from_state_db(state_db.as_ref());
        let installation_id = resolve_installation_id(&config.codex_home).await?;
        let thread_manager = ThreadManager::new(
            &config,
            auth_manager.clone(),
            // rust-v0.146.0 で models_manager / codex_apps_tools_cache が必須になった。
            // models_manager がモデルメタデータ(gpt-5.6-sol 等)の解決を担う。
            build_models_manager(&config, auth_manager.clone()),
            CodexAppsToolsCache::default(),
            SessionSource::Unknown,
            environment_manager,
            empty_extension_registry(),
            Arc::new(CodexHomeUserInstructionsProvider::new(
                config.codex_home.clone(),
            )),
            None,
            thread_store,
            agent_graph_store,
            installation_id,
            None,
            None,
        );
        Ok(Self {
            auth_manager,
            client_capabilities,
            config,
            thread_manager,
            state_db,
            sessions: Arc::default(),
            session_roots,
            restricted,
        })
    }

    /// Build and run the ACP agent, serving requests over the given transport.
    pub async fn serve(
        self: Arc<Self>,
        transport: impl ConnectTo<Agent> + 'static,
    ) -> acp::Result<()> {
        let agent = self;
        Agent
            .builder()
            .name("codex-acp")
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: InitializeRequest, responder, _cx| {
                        responder.respond_with_result(agent.initialize(request).await)
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: AuthenticateRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.authenticate(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: LogoutRequest, responder, cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.logout(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: NewSessionRequest, responder, cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        let session_cx = cx.clone();
                        cx.spawn(async move {
                            responder
                                .respond_with_result(agent.new_session(request, session_cx).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: LoadSessionRequest, responder, cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        let session_cx = cx.clone();
                        cx.spawn(async move {
                            responder
                                .respond_with_result(agent.load_session(request, session_cx).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: ListSessionsRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.list_sessions(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: CloseSessionRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.close_session(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: PromptRequest, responder, cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.prompt(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_notification(
                {
                    let agent = agent.clone();
                    async move |notification: CancelNotification, cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            if let Err(e) = agent.cancel(notification).await {
                                tracing::error!("Error handling cancel: {:?}", e);
                            }
                            Ok(())
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_notification!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: SetSessionModeRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.set_session_mode(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: SetSessionModelRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder.respond_with_result(agent.set_session_model(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .on_receive_request(
                {
                    let agent = agent.clone();
                    async move |request: SetSessionConfigOptionRequest,
                                responder,
                                cx: ConnectionTo<Client>| {
                        let agent = agent.clone();
                        cx.spawn(async move {
                            responder
                                .respond_with_result(agent.set_session_config_option(request).await)
                        })?;
                        Ok(())
                    }
                },
                acp::on_receive_request!(),
            )
            .connect_to(transport)
            .await
    }

    fn session_id_from_thread_id(thread_id: ThreadId) -> SessionId {
        SessionId::new(thread_id.to_string())
    }

    fn get_thread(&self, session_id: &SessionId) -> Result<Arc<Thread>, Error> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .get(session_id)
            .ok_or_else(|| Error::resource_not_found(None))?
            .clone())
    }

    async fn check_auth(&self) -> Result<(), Error> {
        if self.config.model_provider_id == "openai"
            && self.auth_manager.auth().await.is_none()
            // Check if anything changed on disk since the last reload
            && !self.auth_manager.reload().await
        {
            return Err(Error::auth_required());
        }
        Ok(())
    }

    /// Build a session config from base config, working directory, and MCP servers.
    /// This is shared between `new_session` and `load_session`.
    fn build_session_config(
        &self,
        cwd: &Path,
        mcp_servers: Vec<McpServer>,
    ) -> Result<Config, Error> {
        if let Some(restricted) = &self.restricted {
            restricted
                .validate_session_request(cwd, mcp_servers.len())
                .map_err(|error| Error::invalid_params().data(error))?;
            return Ok(self.config.clone());
        }
        let mut config = self.config.clone();
        config.cwd = cwd.try_into().map_err(Error::into_internal_error)?;
        let cwd = config.cwd.clone();

        // Propagate any client-provided MCP servers that codex-rs supports.
        let mut new_mcp_servers = config.mcp_servers.get().clone();
        for mcp_server in mcp_servers {
            match mcp_server {
                // Not supported in codex
                McpServer::Sse(..) => {}
                McpServer::Http(McpServerHttp {
                    name, url, headers, ..
                }) => {
                    // Codex does not allow whitespace in MCP server names; replace with underscores.
                    let name = name.replace(|c: char| c.is_whitespace(), "_");
                    new_mcp_servers.insert(
                        name,
                        McpServerConfig {
                            transport: McpServerTransportConfig::StreamableHttp {
                                url,
                                bearer_token_env_var: None,
                                http_headers: if headers.is_empty() {
                                    None
                                } else {
                                    Some(headers.into_iter().map(|h| (h.name, h.value)).collect())
                                },
                                env_http_headers: None,
                                http_headers_helper: None,
                            },
                            auth: Default::default(),
                            environment_id: codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID
                                .to_string(),
                            required: false,
                            enabled: true,
                            startup_timeout_sec: None,
                            tool_timeout_sec: None,
                            disabled_tools: None,
                            enabled_tools: None,
                            disabled_reason: None,
                            scopes: None,
                            oauth: None,
                            oauth_resource: None,
                            tools: Default::default(),
                            supports_parallel_tool_calls: false,
                            default_tools_approval_mode: None,
                            omit_tools_from: None,
                        },
                    );
                }
                McpServer::Stdio(McpServerStdio {
                    name,
                    command,
                    args,
                    env,
                    ..
                }) => {
                    // Codex does not allow whitespace in MCP server names; replace with underscores.
                    let name = name.replace(|c: char| c.is_whitespace(), "_");
                    new_mcp_servers.insert(
                        name,
                        McpServerConfig {
                            transport: McpServerTransportConfig::Stdio {
                                command: command.display().to_string(),
                                args,
                                env: if env.is_empty() {
                                    None
                                } else {
                                    Some(env.into_iter().map(|env| (env.name, env.value)).collect())
                                },
                                env_vars: vec![],
                                cwd: Some(LegacyAppPathString::from_abs_path(&cwd)),
                            },
                            auth: Default::default(),
                            environment_id: codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID
                                .to_string(),
                            required: false,
                            enabled: true,
                            startup_timeout_sec: None,
                            tool_timeout_sec: None,
                            disabled_tools: None,
                            enabled_tools: None,
                            disabled_reason: None,
                            scopes: None,
                            oauth: None,
                            oauth_resource: None,
                            tools: Default::default(),
                            supports_parallel_tool_calls: false,
                            default_tools_approval_mode: None,
                            omit_tools_from: None,
                        },
                    );
                }
                _ => {}
            }
        }

        config
            .mcp_servers
            .set(new_mcp_servers)
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(config)
    }
}

impl CodexAgent {
    async fn initialize(&self, request: InitializeRequest) -> Result<InitializeResponse, Error> {
        let restricted_meta = self
            .restricted
            .as_ref()
            .map(|runtime| runtime.initialize(request.meta.as_ref()))
            .transpose()
            .map_err(|error| Error::invalid_params().data(error))?;
        let InitializeRequest {
            protocol_version,
            client_capabilities,
            ..
        } = request;
        debug!("Received initialize request with protocol version {protocol_version:?}",);
        let protocol_version = ProtocolVersion::V1;

        *self.client_capabilities.lock().unwrap() = client_capabilities;

        let mut agent_capabilities = if self.restricted.is_some() {
            AgentCapabilities::new().prompt_capabilities(PromptCapabilities::new())
        } else {
            AgentCapabilities::new()
                .prompt_capabilities(PromptCapabilities::new().embedded_context(true).image(true))
                .mcp_capabilities(McpCapabilities::new().http(true))
                .load_session(true)
                .auth(AgentAuthCapabilities::new().logout(LogoutCapabilities::new()))
                // Non-standard hint that this agent supports TRUE mid-turn steering:
                // a `session/prompt` sent while a turn is in flight is injected into
                // the running turn (dissolved) rather than queued as a new turn.
                .meta(acp::schema::Meta::from_iter([(
                    "midTurnSteering".to_string(),
                    serde_json::Value::Bool(true),
                )]))
        };

        agent_capabilities.session_capabilities = if self.restricted.is_some() {
            SessionCapabilities::new().close(SessionCloseCapabilities::new())
        } else {
            SessionCapabilities::new()
                .close(SessionCloseCapabilities::new())
                .list(SessionListCapabilities::new())
        };

        let mut auth_methods = if self.restricted.is_some() {
            vec![CodexAuthMethod::ChatGpt.into()]
        } else {
            vec![
                CodexAuthMethod::ChatGpt.into(),
                CodexAuthMethod::CodexApiKey.into(),
                CodexAuthMethod::OpenAiApiKey.into(),
            ]
        };
        // Until codex device code auth works, we can't use this in remote ssh projects.
        if self.restricted.is_none() && std::env::var("NO_BROWSER").is_ok() {
            auth_methods.remove(0);
        }

        let response = InitializeResponse::new(protocol_version)
            .agent_capabilities(agent_capabilities)
            .agent_info(Implementation::new("codex-acp", env!("CARGO_PKG_VERSION")).title("Codex"))
            .auth_methods(auth_methods);
        Ok(if let Some(meta) = restricted_meta {
            response.meta(meta)
        } else {
            response
        })
    }

    async fn authenticate(
        &self,
        request: AuthenticateRequest,
    ) -> Result<AuthenticateResponse, Error> {
        let auth_method = CodexAuthMethod::try_from(request.method_id)?;

        if self.restricted.is_some() {
            if auth_method != CodexAuthMethod::ChatGpt {
                return Err(Error::invalid_params()
                    .data("restricted mode permits only ChatGPT-managed authentication"));
            }
            return match self.auth_manager.auth().await {
                Some(auth) if auth.auth_mode() == codex_protocol::auth::AuthMode::Chatgpt => {
                    Ok(AuthenticateResponse::new())
                }
                _ => Err(Error::auth_required()),
            };
        }

        // Check before starting login flow if already authenticated with the same method
        if let Some(auth) = self.auth_manager.auth().await {
            match (auth, auth_method) {
                (
                    CodexAuth::ApiKey(..),
                    CodexAuthMethod::CodexApiKey | CodexAuthMethod::OpenAiApiKey,
                )
                | (CodexAuth::Chatgpt(..), CodexAuthMethod::ChatGpt) => {
                    return Ok(AuthenticateResponse::new());
                }
                _ => {}
            }
        }

        match auth_method {
            CodexAuthMethod::ChatGpt => {
                // Perform browser/device login via codex-rs, then report success/failure to the client.
                let opts = codex_login::ServerOptions::new(
                    self.config.codex_home.to_path_buf(),
                    codex_login::auth::CLIENT_ID.to_string(),
                    None,
                    self.config.cli_auth_credentials_store_mode,
                    self.config.auth_keyring_backend_kind(),
                    self.config.auth_route_config(),
                );

                let server =
                    codex_login::run_login_server(opts).map_err(Error::into_internal_error)?;

                server
                    .block_until_done()
                    .await
                    .map_err(Error::into_internal_error)?;
            }
            CodexAuthMethod::CodexApiKey => {
                let api_key = read_codex_api_key_from_env().ok_or_else(|| {
                    Error::internal_error().data(format!("{CODEX_API_KEY_ENV_VAR} is not set"))
                })?;
                codex_login::login_with_api_key(
                    &self.config.codex_home,
                    &api_key,
                    self.config.cli_auth_credentials_store_mode,
                    self.config.auth_keyring_backend_kind(),
                )
                .map_err(Error::into_internal_error)?;
            }
            CodexAuthMethod::OpenAiApiKey => {
                let api_key = read_openai_api_key_from_env().ok_or_else(|| {
                    Error::internal_error().data(format!("{OPENAI_API_KEY_ENV_VAR} is not set"))
                })?;
                codex_login::login_with_api_key(
                    &self.config.codex_home,
                    &api_key,
                    self.config.cli_auth_credentials_store_mode,
                    self.config.auth_keyring_backend_kind(),
                )
                .map_err(Error::into_internal_error)?;
            }
        }

        self.auth_manager.reload().await;

        Ok(AuthenticateResponse::new())
    }

    async fn logout(&self, _request: LogoutRequest) -> Result<LogoutResponse, Error> {
        if self.restricted.is_some() {
            return Err(Error::invalid_params().data("logout is disabled in restricted mode"));
        }
        self.auth_manager
            .logout()
            .await
            .map_err(Error::into_internal_error)?;
        Ok(LogoutResponse::new())
    }

    async fn new_session(
        &self,
        request: NewSessionRequest,
        cx: ConnectionTo<Client>,
    ) -> Result<NewSessionResponse, Error> {
        // Check before sending if authentication was successful or not
        self.check_auth().await?;

        #[cfg(feature = "ninna-validation-attestation")]
        let validation_binding = if let Some(restricted) = &self.restricted {
            restricted
                .validation_session_binding(request.meta.as_ref())
                .map_err(|error| Error::invalid_params().data(error))?
        } else {
            reject_validation_metadata_when_feature_disabled(request.meta.as_ref())
                .map_err(|error| Error::invalid_params().data(error))?;
            None
        };
        #[cfg(not(feature = "ninna-validation-attestation"))]
        reject_validation_metadata_when_feature_disabled(request.meta.as_ref())
            .map_err(|error| Error::invalid_params().data(error))?;

        let request_hash = self
            .restricted
            .as_ref()
            .map(|_| request_hash(&request))
            .transpose()
            .map_err(|error| Error::invalid_params().data(error))?;
        let NewSessionRequest {
            cwd, mcp_servers, ..
        } = request;
        info!("Creating new session with cwd: {}", cwd.display());

        let config = self.build_session_config(&cwd, mcp_servers)?;
        let num_mcp_servers = config.mcp_servers.len();

        let NewThread {
            thread_id,
            thread,
            session_configured,
        } = Box::pin(
            self.thread_manager
                .start_thread(StartThreadOptions::new(config.clone())),
        )
        .await
        .map_err(|_e| Error::internal_error())?;

        let session_id = Self::session_id_from_thread_id(thread_id);
        // Validate the effective SessionConfigured values before registering
        // any ACP-visible session. A model/provider/reasoning mismatch must not
        // leave a session that a later request could reuse.
        let response_meta = if let (Some(restricted), Some(request_hash)) =
            (&self.restricted, request_hash.as_ref())
        {
            let auth_mode = self
                .auth_manager
                .auth()
                .await
                .ok_or_else(Error::auth_required)?
                .auth_mode();
            Some(
                restricted
                    .session_attestation(
                        &config,
                        request_hash.clone(),
                        session_id.0.as_ref(),
                        auth_mode,
                        &session_configured,
                        #[cfg(feature = "ninna-validation-attestation")]
                        validation_binding,
                    )
                    .map_err(|error| Error::invalid_params().data(error))?,
            )
        } else {
            // Bind the normal-mode evidence to the exact Core
            // SessionConfigured event returned by this start_thread call.
            // The client receives it on the same response and stdio process as
            // the ACP session id, rather than re-reading launch configuration.
            Some(normal_session_runtime_meta(
                &session_id,
                &session_configured,
            ))
        };
        // Record the session root for filesystem sandboxing.
        self.session_roots
            .lock()
            .unwrap()
            .insert(session_id.clone(), config.cwd.to_path_buf());
        let thread = Arc::new(Thread::new(
            session_id.clone(),
            thread,
            self.auth_manager.clone(),
            Arc::new(self.thread_manager.get_models_manager()),
            self.client_capabilities.clone(),
            config.clone(),
            cx,
            self.restricted.is_some(),
        ));
        let load = thread.load().await?;

        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), thread);

        debug!("Created new session with {} MCP servers", num_mcp_servers);

        let response = if self.restricted.is_some() {
            // Do not advertise any post-attestation configuration surface.
            // The load is still awaited above so the exact MCP startup and
            // thread initialization complete before the session is registered.
            NewSessionResponse::new(session_id.clone())
        } else {
            NewSessionResponse::new(session_id.clone())
                .modes(load.modes)
                .models(load.models)
                .config_options(load.config_options)
        };
        if let Some(meta) = response_meta {
            Ok(response.meta(meta))
        } else {
            Ok(response)
        }
    }

    async fn load_session(
        &self,
        request: LoadSessionRequest,
        cx: ConnectionTo<Client>,
    ) -> Result<LoadSessionResponse, Error> {
        if self.restricted.is_some() {
            return Err(
                Error::invalid_params().data("session loading is disabled in restricted mode")
            );
        }
        info!("Loading session: {}", request.session_id);
        // Check before sending if authentication was successful or not
        self.check_auth().await?;

        let LoadSessionRequest {
            session_id,
            cwd,
            mcp_servers,
            ..
        } = request;

        let rollout_path = find_thread_path_by_id_str(
            &self.config.codex_home,
            session_id.0.as_ref(),
            self.state_db.as_deref(),
        )
        .await
        .map_err(|e| Error::internal_error().data(e.to_string()))?
        .ok_or_else(|| Error::resource_not_found(None))?;

        let history = RolloutRecorder::get_rollout_history(&rollout_path)
            .await
            .map_err(|e| Error::internal_error().data(e.to_string()))?;

        let rollout_items = match &history {
            InitialHistory::Resumed(resumed) => resumed.history.as_ref().clone(),
            InitialHistory::Forked(items) => items.clone(),
            InitialHistory::Cleared | InitialHistory::New => Vec::new(),
        };

        let config = self.build_session_config(&cwd, mcp_servers)?;

        let NewThread {
            thread_id: _,
            thread,
            session_configured: _,
        } = Box::pin(self.thread_manager.resume_thread_from_rollout(
            config.clone(),
            rollout_path,
            self.auth_manager.clone(),
            None,
            ClientMcpExtensions::default(),
        ))
        .await
        .map_err(|e| Error::internal_error().data(e.to_string()))?;

        let thread = Arc::new(Thread::new(
            session_id.clone(),
            thread,
            self.auth_manager.clone(),
            Arc::new(self.thread_manager.get_models_manager()),
            self.client_capabilities.clone(),
            config.clone(),
            cx,
            false,
        ));

        thread.replay_history(rollout_items).await?;

        let load = thread.load().await?;

        self.session_roots
            .lock()
            .unwrap()
            .insert(session_id.clone(), config.cwd.to_path_buf());
        self.sessions.lock().unwrap().insert(session_id, thread);

        Ok(LoadSessionResponse::new()
            .modes(load.modes)
            .models(load.models)
            .config_options(load.config_options))
    }

    async fn list_sessions(
        &self,
        request: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, Error> {
        if self.restricted.is_some() {
            return Err(
                Error::invalid_params().data("session listing is disabled in restricted mode")
            );
        }
        self.check_auth().await?;

        let ListSessionsRequest { cwd, cursor, .. } = request;
        let cursor_obj = cursor.as_deref().and_then(parse_cursor);

        let page = RolloutRecorder::list_threads(
            self.state_db.clone(),
            &self.config,
            SESSION_LIST_PAGE_SIZE,
            cursor_obj.as_ref(),
            ThreadSortKey::UpdatedAt,
            SortDirection::Desc,
            &[
                SessionSource::Cli,
                SessionSource::VSCode,
                SessionSource::Unknown,
            ],
            None,
            None,
            self.config.model_provider_id.as_str(),
            None,
        )
        .await
        .map_err(|err| Error::internal_error().data(format!("failed to list sessions: {err}")))?;

        let sessions = page
            .items
            .into_iter()
            .filter_map(|item| {
                let thread_id = item.thread_id?;
                let item_cwd = item.cwd?;

                if let Some(filter_cwd) = cwd.as_ref()
                    && item_cwd != *filter_cwd
                {
                    return None;
                }

                let title = item
                    .first_user_message
                    .as_deref()
                    .and_then(format_session_title);
                let updated_at = item.updated_at.or(item.created_at);

                Some(
                    SessionInfo::new(SessionId::new(thread_id.to_string()), item_cwd)
                        .title(title)
                        .updated_at(updated_at),
                )
            })
            .collect::<Vec<_>>();

        let next_cursor = page
            .next_cursor
            .as_ref()
            .and_then(|next_cursor| serde_json::to_value(next_cursor).ok())
            .and_then(|value| value.as_str().map(str::to_owned));

        Ok(ListSessionsResponse::new(sessions).next_cursor(next_cursor))
    }

    async fn close_session(
        &self,
        request: CloseSessionRequest,
    ) -> Result<CloseSessionResponse, Error> {
        self.get_thread(&request.session_id)?.shutdown().await?;
        self.thread_manager
            .remove_thread(
                &ThreadId::from_string(&request.session_id.0)
                    .map_err(Error::into_internal_error)?,
            )
            .await;
        self.sessions.lock().unwrap().remove(&request.session_id);
        self.session_roots
            .lock()
            .unwrap()
            .remove(&request.session_id);
        Ok(CloseSessionResponse::new())
    }

    async fn prompt(&self, request: PromptRequest) -> Result<PromptResponse, Error> {
        info!("Processing prompt for session: {}", request.session_id);
        if self.restricted.is_some()
            && (request.meta.is_some()
                || request.prompt.is_empty()
                || request.prompt.len() > 8
                || request
                    .prompt
                    .iter()
                    .any(|block| !matches!(block, ContentBlock::Text(_)))
                || request
                    .prompt
                    .iter()
                    .filter_map(|block| match block {
                        ContentBlock::Text(text) => Some(text.text.len()),
                        _ => None,
                    })
                    .sum::<usize>()
                    > 32_000)
        {
            return Err(
                Error::invalid_params().data("restricted prompts permit only bounded text blocks")
            );
        }
        // Check before sending if authentication was successful or not
        self.check_auth().await?;

        // Get the session state
        let thread = self.get_thread(&request.session_id)?;
        let stop_reason = thread.prompt(request).await?;

        Ok(PromptResponse::new(stop_reason))
    }

    async fn cancel(&self, args: CancelNotification) -> Result<(), Error> {
        info!("Cancelling operations for session: {}", args.session_id);
        self.get_thread(&args.session_id)?.cancel().await?;
        Ok(())
    }

    async fn set_session_mode(
        &self,
        args: SetSessionModeRequest,
    ) -> Result<SetSessionModeResponse, Error> {
        if self.restricted.is_some() {
            return Err(Error::invalid_params()
                .data("session mode changes are disabled in restricted mode"));
        }
        info!("Setting session mode for session: {}", args.session_id);
        self.get_thread(&args.session_id)?
            .set_mode(args.mode_id)
            .await?;
        Ok(SetSessionModeResponse::default())
    }

    async fn set_session_model(
        &self,
        args: SetSessionModelRequest,
    ) -> Result<SetSessionModelResponse, Error> {
        if self.restricted.is_some() {
            return Err(Error::invalid_params()
                .data("session model changes are disabled in restricted mode"));
        }
        info!("Setting session model for session: {}", args.session_id);

        self.get_thread(&args.session_id)?
            .set_model(args.model_id)
            .await?;

        Ok(SetSessionModelResponse::default())
    }

    async fn set_session_config_option(
        &self,
        args: SetSessionConfigOptionRequest,
    ) -> Result<SetSessionConfigOptionResponse, Error> {
        if self.restricted.is_some() {
            return Err(Error::invalid_params()
                .data("session config changes are disabled in restricted mode"));
        }
        info!(
            "Setting session config option for session: {} (config_id: {}, value: {:?})",
            args.session_id, args.config_id.0, args.value
        );

        let thread = self.get_thread(&args.session_id)?;

        thread.set_config_option(args.config_id, args.value).await?;

        let config_options = thread.config_options().await?;

        Ok(SetSessionConfigOptionResponse::new(config_options))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexAuthMethod {
    ChatGpt,
    CodexApiKey,
    OpenAiApiKey,
}

impl From<CodexAuthMethod> for AuthMethodId {
    fn from(method: CodexAuthMethod) -> Self {
        Self::new(match method {
            CodexAuthMethod::ChatGpt => "chatgpt",
            CodexAuthMethod::CodexApiKey => "codex-api-key",
            CodexAuthMethod::OpenAiApiKey => "openai-api-key",
        })
    }
}

impl From<CodexAuthMethod> for AuthMethod {
    fn from(method: CodexAuthMethod) -> Self {
        match method {
            CodexAuthMethod::ChatGpt => Self::Agent(
                AuthMethodAgent::new(method, "Login with ChatGPT").description(
                    "Use your ChatGPT login with Codex CLI (requires a paid ChatGPT subscription)",
                ),
            ),
            CodexAuthMethod::CodexApiKey => Self::EnvVar(
                AuthMethodEnvVar::new(
                    method,
                    format!("Use {CODEX_API_KEY_ENV_VAR}"),
                    vec![AuthEnvVar::new(CODEX_API_KEY_ENV_VAR)],
                )
                .description(format!(
                    "Requires setting the `{CODEX_API_KEY_ENV_VAR}` environment variable."
                )),
            ),
            CodexAuthMethod::OpenAiApiKey => Self::EnvVar(
                AuthMethodEnvVar::new(
                    method,
                    format!("Use {OPENAI_API_KEY_ENV_VAR}"),
                    vec![AuthEnvVar::new(OPENAI_API_KEY_ENV_VAR)],
                )
                .description(format!(
                    "Requires setting the `{OPENAI_API_KEY_ENV_VAR}` environment variable."
                )),
            ),
        }
    }
}

impl TryFrom<AuthMethodId> for CodexAuthMethod {
    type Error = Error;

    fn try_from(value: AuthMethodId) -> Result<Self, Self::Error> {
        match value.0.as_ref() {
            "chatgpt" => Ok(CodexAuthMethod::ChatGpt),
            "codex-api-key" => Ok(CodexAuthMethod::CodexApiKey),
            "openai-api-key" => Ok(CodexAuthMethod::OpenAiApiKey),
            _ => Err(Error::invalid_params().data("unsupported authentication method")),
        }
    }
}

fn truncate_graphemes(text: &str, max_graphemes: usize) -> String {
    let mut graphemes = text.grapheme_indices(true);

    if let Some((byte_index, _)) = graphemes.nth(max_graphemes) {
        if max_graphemes >= 3 {
            let mut truncate_graphemes = text.grapheme_indices(true);
            if let Some((truncate_byte_index, _)) = truncate_graphemes.nth(max_graphemes - 3) {
                let truncated = &text[..truncate_byte_index];
                format!("{truncated}...")
            } else {
                text.to_string()
            }
        } else {
            let truncated = &text[..byte_index];
            truncated.to_string()
        }
    } else {
        text.to_string()
    }
}

fn format_session_title(message: &str) -> Option<String> {
    let normalized = message.replace(['\r', '\n'], " ");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(truncate_graphemes(trimmed, SESSION_TITLE_MAX_GRAPHEMES))
    }
}

#[cfg(test)]
mod tests {
    use super::session_runtime_evidence_value;

    #[test]
    fn normal_session_runtime_evidence_includes_effective_priority() {
        let value = session_runtime_evidence_value(
            "session-1",
            42,
            "gpt-6-astra",
            "openai",
            Some("xhigh".to_string()),
            Some("priority".to_string()),
        );

        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["processId"], 42);
        assert_eq!(value["effectiveModel"], "gpt-6-astra");
        assert_eq!(value["effectiveModelProvider"], "openai");
        assert_eq!(value["effectiveReasoningEffort"], "xhigh");
        assert_eq!(value["effectiveServiceTier"], "priority");
        assert_ne!(value["sessionIdHash"], "session-1");
    }

    #[test]
    fn normal_session_runtime_evidence_does_not_invent_missing_values() {
        let value =
            session_runtime_evidence_value("session-2", 43, "gpt-6-astra", "openai", None, None);

        assert!(value["effectiveReasoningEffort"].is_null());
        assert!(value["effectiveServiceTier"].is_null());
    }
}
