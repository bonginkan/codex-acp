//! Restricted NINNA inquiry-mode attestation.
//!
//! This module intentionally exposes only hashes and normalized policy state.
//! Tokens, header values, environment values, prompts, and tool payloads never
//! enter the attestation envelope.

use agent_client_protocol::schema::Meta;
use codex_config::{
    ConfigRequirementsToml, McpServerTransportConfig, config_error_from_ignored_toml_fields,
    config_toml::ConfigToml,
};
use codex_core::config::Config;
use codex_protocol::auth::AuthMode;
use codex_protocol::models::{ManagedFileSystemPermissions, PermissionProfile};
use codex_protocol::permissions::{
    FileSystemAccessMode, FileSystemPath, FileSystemSpecialPath, NetworkSandboxPolicy,
};
use codex_protocol::protocol::{AskForApproval, SessionConfiguredEvent};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const RESTRICTED_SCHEMA_VERSION: u32 = 1;
pub const RESTRICTED_PROFILE_ID: &str = "ninna_inquiry_noio";
pub const RESTRICTED_MCP_NAME: &str = "ninna_inquiry";
pub const RESTRICTED_MCP_COMMAND: &str = "/usr/local/libexec/ninna-mcp-launch";
pub const RESTRICTED_MCP_ARGS: [&str; 2] = ["serve", "--socket=/run/ninna/query.sock"];
pub const REQUIREMENTS_PATH: &str = "/etc/codex/requirements.toml";
pub const EMBEDDED_CODEX_TAG: &str = "rust-v0.153.4";
pub const EMBEDDED_CODEX_COMMIT: &str = "3d2ee51ca2d5db578f328aa75e20aa22c0197c9a";
pub const RESTRICTED_MODEL: &str = "gpt-6-astra";
pub const RESTRICTED_MODEL_PROVIDER: &str = "openai";
pub const RESTRICTED_REASONING_EFFORT: &str = "xhigh";
pub const RESTRICTED_SERVICE_TIER: &str = "priority";

fn validate_effective_session_identity(
    model: &str,
    provider: &str,
    reasoning_effort: Option<&str>,
    service_tier: Option<&str>,
) -> Result<(), String> {
    if model != RESTRICTED_MODEL
        || provider != RESTRICTED_MODEL_PROVIDER
        || reasoning_effort != Some(RESTRICTED_REASONING_EFFORT)
        || service_tier != Some(RESTRICTED_SERVICE_TIER)
    {
        return Err(
            "effective restricted session model/provider/reasoning/tier does not match the trusted configuration"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BuildManifest {
    schema_version: u32,
    crate_name: &'static str,
    crate_version: &'static str,
    source_commit: &'static str,
    source_dirty: bool,
    cargo_lock_sha256: &'static str,
    embedded_codex_tag: &'static str,
    embedded_codex_commit: &'static str,
    target: &'static str,
}

impl BuildManifest {
    pub fn current() -> Self {
        Self {
            schema_version: RESTRICTED_SCHEMA_VERSION,
            crate_name: env!("CARGO_PKG_NAME"),
            crate_version: env!("CARGO_PKG_VERSION"),
            source_commit: env!("NINNA_SOURCE_COMMIT"),
            source_dirty: env!("NINNA_SOURCE_DIRTY") == "true",
            cargo_lock_sha256: env!("NINNA_CARGO_LOCK_SHA256"),
            embedded_codex_tag: EMBEDDED_CODEX_TAG,
            embedded_codex_commit: EMBEDDED_CODEX_COMMIT,
            target: env!("NINNA_BUILD_TARGET"),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct McpSnapshot {
    name: String,
    transport: &'static str,
    command: Option<String>,
    args: Vec<String>,
    env_names: Vec<String>,
    header_names: Vec<String>,
    bearer_token_env_var: Option<String>,
    cwd: Option<String>,
    auth: Value,
    environment_id: String,
    enabled: bool,
    required: bool,
    supports_parallel_tool_calls: bool,
    startup_timeout_secs: Option<u64>,
    tool_timeout_secs: Option<u64>,
    default_tools_approval_mode: Value,
    enabled_tools: Vec<String>,
    disabled_tools: Vec<String>,
    scopes: Vec<String>,
    oauth_configured: bool,
    oauth_resource_configured: bool,
    tool_approval_overrides: Value,
    disabled_reason_present: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ShellEnvironmentSnapshot {
    inherit: Value,
    ignore_default_excludes: bool,
    exclude: Vec<String>,
    set_names: Vec<String>,
    include_only: Vec<String>,
    use_profile: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSnapshot {
    model: Option<String>,
    model_provider_id: String,
    reasoning_effort: Option<String>,
    service_tier: Option<String>,
    approval_policy: String,
    active_permission_profile: Option<String>,
    permission_profile: Value,
    permission_profile_envelope_valid: bool,
    command_network_enabled: bool,
    allow_login_shell: bool,
    shell_environment_policy: ShellEnvironmentSnapshot,
    web_search_mode: String,
    enabled_features: Vec<String>,
    agents_enabled: bool,
    include_permissions_instructions: bool,
    include_apps_instructions: bool,
    include_collaboration_mode_instructions: bool,
    include_skill_instructions: bool,
    include_environment_context: bool,
    orchestrator_skills_enabled: bool,
    orchestrator_mcp_enabled: bool,
    notify_configured: bool,
    instruction_override_configured: bool,
    ephemeral: bool,
    check_for_update_on_startup: bool,
    respect_system_proxy: bool,
    request_user_input_enabled: bool,
    update_plan_enabled: bool,
    non_prefixed_mcp_tool_servers: Vec<String>,
    config_lock_export_configured: bool,
    bypass_hook_trust: bool,
    forced_login_method: Value,
    mcp_oauth_callback_configured: bool,
    apps_mcp_product_sku_configured: bool,
    experimental_remote_configured: bool,
    cwd: String,
    workspace_roots: Vec<String>,
    mcp_servers: Vec<McpSnapshot>,
    startup_warning_count: usize,
}

impl ConfigSnapshot {
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let mut enabled_features = codex_features::FEATURES
            .iter()
            .filter(|spec| config.features.enabled(spec.id))
            .map(|spec| spec.key.to_string())
            .collect::<Vec<_>>();
        enabled_features.sort();

        let mut mcp_servers = config
            .mcp_servers
            .get()
            .iter()
            .map(|(name, server)| {
                let (transport, command, args, env_names, header_names, bearer_token_env_var, cwd) =
                    match &server.transport {
                        McpServerTransportConfig::Stdio {
                            command,
                            args,
                            env,
                            env_vars,
                            cwd,
                        } => {
                            let mut env_names = env
                                .as_ref()
                                .map(|items| items.keys().cloned().collect::<Vec<_>>())
                                .unwrap_or_default();
                            env_names.extend(env_vars.iter().map(|item| item.name().to_string()));
                            env_names.sort();
                            env_names.dedup();
                            (
                                "stdio",
                                Some(command.clone()),
                                args.clone(),
                                env_names,
                                Vec::new(),
                                None,
                                cwd.as_ref().map(ToString::to_string),
                            )
                        }
                        McpServerTransportConfig::StreamableHttp {
                            bearer_token_env_var,
                            http_headers,
                            env_http_headers,
                            ..
                        } => {
                            let mut header_names = http_headers
                                .as_ref()
                                .map(|items| items.keys().cloned().collect::<Vec<_>>())
                                .unwrap_or_default();
                            header_names.extend(
                                env_http_headers
                                    .as_ref()
                                    .into_iter()
                                    .flat_map(|items| items.keys().cloned()),
                            );
                            header_names.sort();
                            header_names.dedup();
                            (
                                "http",
                                None,
                                Vec::new(),
                                Vec::new(),
                                header_names,
                                bearer_token_env_var.clone(),
                                None,
                            )
                        }
                    };
                let mut enabled_tools = server.enabled_tools.clone().unwrap_or_default();
                enabled_tools.sort();
                let mut disabled_tools = server.disabled_tools.clone().unwrap_or_default();
                disabled_tools.sort();
                let mut scopes = server.scopes.clone().unwrap_or_default();
                scopes.sort();
                McpSnapshot {
                    name: name.clone(),
                    transport,
                    command,
                    args,
                    env_names,
                    header_names,
                    bearer_token_env_var,
                    cwd,
                    auth: serde_json::to_value(server.auth.clone())
                        .expect("serialize MCP authentication mode"),
                    environment_id: server.environment_id.clone(),
                    enabled: server.enabled,
                    required: server.required,
                    supports_parallel_tool_calls: server.supports_parallel_tool_calls,
                    startup_timeout_secs: server.startup_timeout_sec.map(|value| value.as_secs()),
                    tool_timeout_secs: server.tool_timeout_sec.map(|value| value.as_secs()),
                    default_tools_approval_mode: serde_json::to_value(
                        server.default_tools_approval_mode,
                    )
                    .expect("serialize MCP approval mode"),
                    enabled_tools,
                    disabled_tools,
                    scopes,
                    oauth_configured: server.oauth.is_some(),
                    oauth_resource_configured: server.oauth_resource.is_some(),
                    tool_approval_overrides: serde_json::to_value(&server.tools)
                        .expect("serialize MCP tool overrides"),
                    disabled_reason_present: server.disabled_reason.is_some(),
                }
            })
            .collect::<Vec<_>>();
        mcp_servers.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(Self {
            model: config.model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            reasoning_effort: config
                .model_reasoning_effort
                .as_ref()
                .map(ToString::to_string),
            service_tier: config.service_tier.clone(),
            approval_policy: config.permissions.approval_policy.get().to_string(),
            active_permission_profile: config
                .permissions
                .active_permission_profile()
                .map(|profile| profile.id),
            permission_profile: serde_json::to_value(config.permissions.permission_profile())
                .map_err(|error| error.to_string())?,
            permission_profile_envelope_valid: restricted_permission_profile_is_exact(config),
            command_network_enabled: config.permissions.network_sandbox_policy().is_enabled(),
            allow_login_shell: config.permissions.allow_login_shell,
            shell_environment_policy: {
                let policy = &config.permissions.shell_environment_policy;
                let mut set_names = policy.r#set.keys().cloned().collect::<Vec<_>>();
                set_names.sort();
                ShellEnvironmentSnapshot {
                    inherit: serde_json::to_value(&policy.inherit)
                        .map_err(|error| error.to_string())?,
                    ignore_default_excludes: policy.ignore_default_excludes,
                    exclude: policy.exclude.iter().map(ToString::to_string).collect(),
                    set_names,
                    include_only: policy
                        .include_only
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    use_profile: policy.use_profile,
                }
            },
            web_search_mode: config.web_search_mode.get().to_string(),
            enabled_features,
            agents_enabled: config.agents_enabled,
            include_permissions_instructions: config.include_permissions_instructions,
            include_apps_instructions: config.include_apps_instructions,
            include_collaboration_mode_instructions: config.include_collaboration_mode_instructions,
            include_skill_instructions: config.include_skill_instructions,
            include_environment_context: config.include_environment_context,
            orchestrator_skills_enabled: config.orchestrator_skills_enabled,
            orchestrator_mcp_enabled: config.orchestrator_mcp_enabled,
            notify_configured: config.notify.is_some(),
            instruction_override_configured: config.base_instructions.is_some()
                || config.developer_instructions.is_some()
                || config.guardian_policy_config.is_some()
                || config.compact_prompt.is_some(),
            ephemeral: config.ephemeral,
            check_for_update_on_startup: config.check_for_update_on_startup,
            respect_system_proxy: config.respect_system_proxy,
            request_user_input_enabled: config.experimental_request_user_input_enabled,
            update_plan_enabled: config.update_plan_enabled,
            non_prefixed_mcp_tool_servers: config
                .non_prefixed_mcp_tool_servers
                .clone()
                .unwrap_or_default(),
            // These legacy remote/export endpoints are absent from Codex 0.153.4.
            config_lock_export_configured: false,
            bypass_hook_trust: config.bypass_hook_trust,
            forced_login_method: serde_json::to_value(config.forced_login_method)
                .map_err(|error| error.to_string())?,
            mcp_oauth_callback_configured: config.mcp_oauth_callback_port.is_some()
                || config.mcp_oauth_callback_url.is_some(),
            apps_mcp_product_sku_configured: config.apps_mcp_product_sku.is_some(),
            experimental_remote_configured: config.experimental_realtime_ws_base_url.is_some()
                || config.experimental_realtime_webrtc_call_base_url.is_some()
                || config.experimental_realtime_ws_model.is_some()
                || config.experimental_realtime_ws_backend_prompt.is_some()
                || config.experimental_realtime_ws_startup_context.is_some()
                || config.experimental_realtime_start_instructions.is_some(),
            cwd: config.cwd.as_path().display().to_string(),
            workspace_roots: config
                .workspace_roots
                .iter()
                .map(|root| root.as_path().display().to_string())
                .collect(),
            mcp_servers,
            startup_warning_count: config.startup_warnings.len(),
        })
    }

    fn fingerprint(&self) -> Result<String, String> {
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        Ok(sha256_hex(canonical_json(&value).as_bytes()))
    }

    pub fn validate_restricted(&self) -> Result<(), String> {
        if self.model.as_deref() != Some(RESTRICTED_MODEL)
            || self.model_provider_id != RESTRICTED_MODEL_PROVIDER
            || self.reasoning_effort.as_deref() != Some(RESTRICTED_REASONING_EFFORT)
            || self.service_tier.as_deref() != Some(RESTRICTED_SERVICE_TIER)
        {
            return Err(
                "restricted model, provider, reasoning, or service tier is not pinned".into(),
            );
        }
        if self.approval_policy != AskForApproval::Never.to_string() {
            return Err("approval policy is not never".into());
        }
        if self.active_permission_profile.as_deref() != Some(RESTRICTED_PROFILE_ID) {
            return Err("unexpected permission profile".into());
        }
        if !self.permission_profile_envelope_valid
            || self.command_network_enabled
            || self.allow_login_shell
        {
            return Err("command network or login shell is enabled".into());
        }
        if !self.shell_environment_policy.set_names.is_empty() {
            return Err("shell environment injects explicit values".into());
        }
        if self.shell_environment_policy.inherit != Value::String("none".to_string())
            || self.shell_environment_policy.ignore_default_excludes
            || !self.shell_environment_policy.include_only.is_empty()
            || self.shell_environment_policy.use_profile
        {
            return Err("shell environment policy is not the reviewed empty policy".into());
        }
        if self.web_search_mode != "disabled" {
            return Err("web search is enabled".into());
        }
        if self.agents_enabled
            || self.include_permissions_instructions
            || self.include_apps_instructions
            || self.include_collaboration_mode_instructions
            || self.include_skill_instructions
            || self.include_environment_context
            || self.orchestrator_skills_enabled
            || self.orchestrator_mcp_enabled
            || self.notify_configured
            || self.instruction_override_configured
            || !self.ephemeral
            || self.check_for_update_on_startup
            || self.respect_system_proxy
            || self.request_user_input_enabled
            || self.update_plan_enabled
            || !self.non_prefixed_mcp_tool_servers.is_empty()
            || self.config_lock_export_configured
            || self.bypass_hook_trust
            || self.forced_login_method != Value::String("chatgpt".to_string())
            || self.mcp_oauth_callback_configured
            || self.apps_mcp_product_sku_configured
            || self.experimental_remote_configured
            || self.startup_warning_count != 0
        {
            return Err("forbidden runtime surface is enabled".into());
        }
        // The pinned Codex release defaults many tool and plugin surfaces on.
        // An allowlist would have to predict the security meaning of every
        // future feature. Restricted mode therefore accepts no enabled feature
        // flags; model transport and the exact MCP server do not require one.
        if !self.enabled_features.is_empty() {
            return Err("restricted mode requires every Codex feature flag disabled".into());
        }
        if self.mcp_servers.len() != 1 {
            return Err("restricted mode requires exactly one MCP server".into());
        }
        let server = &self.mcp_servers[0];
        if server.name != RESTRICTED_MCP_NAME
            || server.transport != "stdio"
            || server.command.as_deref() != Some(RESTRICTED_MCP_COMMAND)
            || server.args
                != RESTRICTED_MCP_ARGS
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            || !server.env_names.is_empty()
            || !server.header_names.is_empty()
            || server.bearer_token_env_var.is_some()
            || server.cwd.is_some()
            || server.auth != Value::String("oauth".to_string())
            || server.environment_id != codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID
            || !server.enabled
            || !server.required
            || server.supports_parallel_tool_calls
            || server.startup_timeout_secs.is_some()
            || server.tool_timeout_secs.is_some()
            || !server.default_tools_approval_mode.is_null()
            || server.enabled_tools != ["knowledge_query".to_string()]
            || !server.disabled_tools.is_empty()
            || !server.scopes.is_empty()
            || server.oauth_configured
            || server.oauth_resource_configured
            || server.tool_approval_overrides != json!({})
            || server.disabled_reason_present
        {
            return Err("restricted MCP identity does not match allowlist".into());
        }
        Ok(())
    }
}

fn restricted_permission_profile_is_exact(config: &Config) -> bool {
    let PermissionProfile::Managed {
        file_system:
            ManagedFileSystemPermissions::Restricted {
                entries,
                glob_scan_max_depth: _,
            },
        network: NetworkSandboxPolicy::Restricted,
    } = config.permissions.permission_profile()
    else {
        return false;
    };
    if entries.iter().any(|entry| {
        entry.access == FileSystemAccessMode::Write
            || (entry.access == FileSystemAccessMode::Read
                && !matches!(
                    &entry.path,
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Minimal
                    }
                ))
    }) {
        return false;
    }
    let has_minimal_read = entries.iter().any(|entry| {
        entry.access == FileSystemAccessMode::Read
            && matches!(
                &entry.path,
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Minimal
                }
            )
    });
    let denied_path = |required: &Path| {
        entries.iter().any(|entry| {
            entry.access == FileSystemAccessMode::Deny
                && matches!(&entry.path, FileSystemPath::Path { path } if path.to_abs_path().is_ok_and(|path| path.as_path() == required))
        })
    };
    has_minimal_read
        && denied_path(Path::new("/home"))
        && denied_path(Path::new("/run/ninna"))
        && denied_path(config.codex_home.as_path())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootAttestation {
    schema_version: u32,
    challenge_hash: String,
    binary_sha256: String,
    process_id: u32,
    process_start_ticks: Option<u64>,
    build_manifest: BuildManifest,
    config_sha256: String,
    requirements_sha256: String,
    base_config_fingerprint: String,
    base_config: ConfigSnapshot,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionAttestation {
    schema_version: u32,
    challenge_hash: String,
    binary_sha256: String,
    process_id: u32,
    process_start_ticks: Option<u64>,
    request_hash: String,
    session_id_hash: String,
    base_config_fingerprint: String,
    session_config_fingerprint: String,
    auth_kind: &'static str,
    effective_model: String,
    effective_model_provider: String,
    effective_reasoning_effort: String,
    effective_service_tier: String,
    session_config: ConfigSnapshot,
}

#[derive(Clone, Debug)]
struct FileEvidence {
    config_sha256: String,
    requirements_sha256: String,
}

#[derive(Clone, Debug)]
struct BootBinding {
    challenge_hash: String,
    binary_sha256: String,
    process_start_ticks: Option<u64>,
}

pub struct RestrictedRuntime {
    base_snapshot: ConfigSnapshot,
    base_fingerprint: String,
    file_evidence: FileEvidence,
    binding: Mutex<Option<BootBinding>>,
}

impl RestrictedRuntime {
    pub fn new(config: &Config) -> Result<Self, String> {
        if std::env::var_os("OPENAI_API_KEY").is_some()
            || std::env::var_os("CODEX_API_KEY").is_some()
        {
            return Err("API-key environment is forbidden in restricted mode".into());
        }
        let codex_home = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "CODEX_HOME is required in restricted mode".to_string())?;
        if !codex_home.is_absolute() {
            return Err("CODEX_HOME must be absolute in restricted mode".into());
        }
        if config.cwd.as_path() != Path::new("/var/empty/ninna-inquiry")
            || config
                .workspace_roots
                .iter()
                .any(|root| root.as_path() != Path::new("/var/empty/ninna-inquiry"))
        {
            return Err("restricted workspace is not the reviewed empty directory".into());
        }
        let file_evidence = strict_file_evidence(
            &codex_home.join("config.toml"),
            Path::new(REQUIREMENTS_PATH),
        )?;
        let base_snapshot = ConfigSnapshot::from_config(config)?;
        base_snapshot.validate_restricted()?;
        let base_fingerprint = base_snapshot.fingerprint()?;
        Ok(Self {
            base_snapshot,
            base_fingerprint,
            file_evidence,
            binding: Mutex::new(None),
        })
    }

    pub fn initialize(&self, meta: Option<&Meta>) -> Result<Meta, String> {
        let challenge = extract_boot_challenge(meta)?;
        let challenge_hash = sha256_hex(challenge.as_bytes());
        let binary_sha256 = current_binary_sha256()?;
        let process_start_ticks = process_start_ticks();
        let mut binding = self
            .binding
            .lock()
            .map_err(|_| "attestation lock poisoned")?;
        if binding.is_some() {
            return Err("restricted connection already initialized".into());
        }
        *binding = Some(BootBinding {
            challenge_hash: challenge_hash.clone(),
            binary_sha256: binary_sha256.clone(),
            process_start_ticks,
        });
        let attestation = BootAttestation {
            schema_version: RESTRICTED_SCHEMA_VERSION,
            challenge_hash,
            binary_sha256,
            process_id: std::process::id(),
            process_start_ticks,
            build_manifest: BuildManifest::current(),
            config_sha256: self.file_evidence.config_sha256.clone(),
            requirements_sha256: self.file_evidence.requirements_sha256.clone(),
            base_config_fingerprint: self.base_fingerprint.clone(),
            base_config: self.base_snapshot.clone(),
        };
        Ok(Meta::from_iter([(
            "ninnaRestrictedAttestation".to_string(),
            serde_json::to_value(attestation).map_err(|error| error.to_string())?,
        )]))
    }

    pub fn validate_session_request(
        &self,
        cwd: &Path,
        client_mcp_count: usize,
    ) -> Result<(), String> {
        if client_mcp_count != 0 {
            return Err("client-supplied MCP is forbidden in restricted mode".into());
        }
        if cwd != Path::new(&self.base_snapshot.cwd) {
            return Err("restricted session cwd must equal attested base cwd".into());
        }
        Ok(())
    }

    pub fn session_attestation(
        &self,
        session_config: &Config,
        request_hash: String,
        session_id: &str,
        auth_mode: AuthMode,
        session_configured: &SessionConfiguredEvent,
    ) -> Result<Meta, String> {
        if auth_mode != AuthMode::Chatgpt {
            return Err("restricted mode requires ChatGPT-managed authentication".into());
        }
        let snapshot = ConfigSnapshot::from_config(session_config)?;
        snapshot.validate_restricted()?;
        let session_fingerprint = snapshot.fingerprint()?;
        if session_fingerprint != self.base_fingerprint {
            return Err("session Config differs from attested base Config".into());
        }
        let effective_reasoning_effort = session_configured
            .reasoning_effort
            .as_ref()
            .map(ToString::to_string)
            .ok_or_else(|| "effective reasoning effort is unavailable".to_string())?;
        let effective_service_tier = session_configured
            .service_tier
            .clone()
            .ok_or_else(|| "effective service tier is unavailable".to_string())?;
        validate_effective_session_identity(
            &session_configured.model,
            &session_configured.model_provider_id,
            Some(effective_reasoning_effort.as_str()),
            Some(effective_service_tier.as_str()),
        )?;
        let binding = self
            .binding
            .lock()
            .map_err(|_| "attestation lock poisoned")?
            .clone()
            .ok_or_else(|| "restricted connection was not attested".to_string())?;
        let attestation = SessionAttestation {
            schema_version: RESTRICTED_SCHEMA_VERSION,
            challenge_hash: binding.challenge_hash,
            binary_sha256: binding.binary_sha256,
            process_id: std::process::id(),
            process_start_ticks: binding.process_start_ticks,
            request_hash,
            session_id_hash: sha256_hex(session_id.as_bytes()),
            base_config_fingerprint: self.base_fingerprint.clone(),
            session_config_fingerprint: session_fingerprint,
            auth_kind: "chatgpt",
            effective_model: session_configured.model.clone(),
            effective_model_provider: session_configured.model_provider_id.clone(),
            effective_reasoning_effort,
            effective_service_tier,
            session_config: snapshot,
        };
        Ok(Meta::from_iter([(
            "ninnaRestrictedAttestation".to_string(),
            serde_json::to_value(attestation).map_err(|error| error.to_string())?,
        )]))
    }
}

pub fn request_hash<T: Serialize>(request: &T) -> Result<String, String> {
    let value = serde_json::to_value(request).map_err(|error| error.to_string())?;
    Ok(sha256_hex(canonical_json(&value).as_bytes()))
}

fn extract_boot_challenge(meta: Option<&Meta>) -> Result<String, String> {
    let value = meta
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(Value::Null);
    let challenge = value
        .pointer("/ninnaRestricted/bootChallenge")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing restricted boot challenge".to_string())?;
    if challenge.len() != 64 || !challenge.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("restricted boot challenge must be 256-bit hex".into());
    }
    Ok(challenge.to_ascii_lowercase())
}

fn strict_file_evidence(
    config_path: &Path,
    requirements_path: &Path,
) -> Result<FileEvidence, String> {
    let config = fs::read_to_string(config_path)
        .map_err(|error| format!("cannot read restricted config: {error}"))?;
    let requirements = fs::read_to_string(requirements_path)
        .map_err(|error| format!("cannot read restricted requirements: {error}"))?;
    if let Some(error) = config_error_from_ignored_toml_fields::<ConfigToml>(config_path, &config) {
        return Err(format!("restricted config is not strict: {error:?}"));
    }
    if let Some(error) = config_error_from_ignored_toml_fields::<ConfigRequirementsToml>(
        requirements_path,
        &requirements,
    ) {
        return Err(format!("restricted requirements are not strict: {error:?}"));
    }
    Ok(FileEvidence {
        config_sha256: sha256_hex(config.as_bytes()),
        requirements_sha256: sha256_hex(requirements.as_bytes()),
    })
}

fn current_binary_sha256() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|error| error.to_string())?;
    let body = fs::read(path).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&body))
}

fn process_start_ticks() -> Option<u64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let close = stat.rfind(')')?;
    stat.get(close + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("serialize string"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let ordered = values.iter().collect::<BTreeMap<_, _>>();
            let fields = ordered
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("serialize key"),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
    }
}

pub fn build_manifest_json() -> Value {
    json!(BuildManifest::current())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_requires_exact_256_bit_hex() {
        let good = Meta::from_iter([(
            "ninnaRestricted".to_string(),
            json!({"bootChallenge": "ab".repeat(32)}),
        )]);
        assert_eq!(
            extract_boot_challenge(Some(&good)).unwrap(),
            "ab".repeat(32)
        );

        let short = Meta::from_iter([(
            "ninnaRestricted".to_string(),
            json!({"bootChallenge": "ab"}),
        )]);
        assert!(extract_boot_challenge(Some(&short)).is_err());
        assert!(extract_boot_challenge(None).is_err());
    }

    #[test]
    fn canonical_json_orders_object_keys() {
        let left = json!({"z": 1, "a": {"d": 2, "b": 3}});
        let right = json!({"a": {"b": 3, "d": 2}, "z": 1});
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(
            sha256_hex(canonical_json(&left).as_bytes()),
            sha256_hex(canonical_json(&right).as_bytes())
        );
    }

    #[test]
    fn build_manifest_pins_embedded_codex() {
        let manifest = build_manifest_json();
        assert_eq!(manifest["embeddedCodexTag"], EMBEDDED_CODEX_TAG);
        assert_eq!(manifest["embeddedCodexCommit"], EMBEDDED_CODEX_COMMIT);
        assert_eq!(manifest["cargoLockSha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn effective_astra_identity_rejects_fallbacks() {
        validate_effective_session_identity(
            RESTRICTED_MODEL,
            RESTRICTED_MODEL_PROVIDER,
            Some(RESTRICTED_REASONING_EFFORT),
            Some(RESTRICTED_SERVICE_TIER),
        )
        .unwrap();
        assert!(
            validate_effective_session_identity(
                "gpt-5-fallback",
                RESTRICTED_MODEL_PROVIDER,
                Some(RESTRICTED_REASONING_EFFORT),
                Some(RESTRICTED_SERVICE_TIER),
            )
            .is_err()
        );
    }
}
