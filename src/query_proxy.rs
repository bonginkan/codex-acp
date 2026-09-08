//! Model-invisible query transport for the restricted NINNA worker.
//!
//! The same review-pinned binary supplies both the MCP stdio bridge inside the
//! ACP sandbox and a separate-UID Unix proxy outside it. The proxy opens the
//! broker connection immediately when accepting the frontend connection, so
//! the broker can bind that connection to the then-current turn before any
//! model-controlled query bytes are read.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const FIXED_MCP_SOCKET: &str = "/run/ninna/query.sock";
const FIXED_BACKEND_SOCKET: &str = "/run/ninna-broker/query.sock";
const MAX_FRAME: usize = 64 * 1024;

pub async fn run_requested_mode() -> Result<bool> {
    let args = std::env::args().collect::<Vec<_>>();
    let arg0 = Path::new(args.first().map(String::as_str).unwrap_or_default())
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if arg0 == "ninna-mcp-launch" {
        if args.as_slice()
            != [
                args[0].clone(),
                "serve".into(),
                format!("--socket={FIXED_MCP_SOCKET}"),
            ]
        {
            bail!("invalid ninna-mcp-launch invocation");
        }
        run_mcp_bridge(Path::new(FIXED_MCP_SOCKET)).await?;
        return Ok(true);
    }
    if args.get(1).map(String::as_str) != Some("--ninna-query-proxy") {
        return Ok(false);
    }
    let frontend = exact_option(&args[2..], "frontend-socket")?;
    let backend = exact_option(&args[2..], "backend-socket")?;
    let worker_instance = exact_option(&args[2..], "worker-instance")?;
    let expected_client_uid = exact_option(&args[2..], "expected-client-uid")?
        .parse::<u32>()
        .context("invalid expected client uid")?;
    if args.len() != 6
        || !frontend.starts_with("/run/ninna-proxy/")
        || backend != FIXED_BACKEND_SOCKET
        || !is_sha256(&worker_instance)
        || expected_client_uid == 0
    {
        bail!("invalid restricted query proxy invocation");
    }
    run_query_proxy(
        Path::new(&frontend),
        Path::new(&backend),
        &worker_instance,
        expected_client_uid,
    )
    .await?;
    Ok(true)
}

fn exact_option(args: &[String], name: &str) -> Result<String> {
    let prefix = format!("--{name}=");
    let values = args
        .iter()
        .filter_map(|arg| arg.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        bail!("missing or duplicate query proxy option");
    }
    Ok(values[0].to_string())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn run_query_proxy(
    frontend: &Path,
    backend: &Path,
    worker_instance: &str,
    expected_client_uid: u32,
) -> Result<()> {
    if let Some(parent) = frontend.parent() {
        let metadata = std::fs::symlink_metadata(parent).context("stat query proxy directory")?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            bail!("query proxy directory is unsafe");
        }
    }
    if frontend.exists() {
        bail!("query proxy frontend already exists");
    }
    let listener = UnixListener::bind(frontend).context("bind query proxy frontend")?;
    std::fs::set_permissions(frontend, std::fs::Permissions::from_mode(0o660))?;
    loop {
        let (client, _) = listener.accept().await?;
        let backend = backend.to_path_buf();
        let worker_instance = worker_instance.to_string();
        tokio::spawn(async move {
            drop(proxy_one(client, backend, worker_instance, expected_client_uid).await);
        });
    }
}

async fn proxy_one(
    mut client: UnixStream,
    backend_path: PathBuf,
    worker_instance: String,
    expected_client_uid: u32,
) -> Result<()> {
    let credentials = client
        .peer_cred()
        .context("read query frontend peer credentials")?;
    if credentials.uid() != expected_client_uid {
        bail!("query frontend peer uid mismatch");
    }
    // Connect and bind at accept time, before reading any untrusted bytes.
    let mut backend = UnixStream::connect(&backend_path)
        .await
        .context("connect knowledge broker query socket")?;
    backend
        .write_all(format!("{}\n", json!({"workerInstance": worker_instance})).as_bytes())
        .await?;
    let mut acknowledgement = String::new();
    {
        let mut reader = BufReader::new(&mut backend);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut acknowledgement),
        )
        .await
        .context("knowledge broker query binding timeout")??;
    }
    if acknowledgement.len() > 128
        || serde_json::from_str::<Value>(acknowledgement.trim())?
            != json!({"ok": true, "bound": true})
    {
        bail!("knowledge broker did not confirm the query binding");
    }
    // Only after the broker acknowledges the immutable turn binding may any
    // bytes controlled by the MCP child cross into the trusted backend.
    tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
    Ok(())
}

async fn run_mcp_bridge(socket_path: &Path) -> Result<()> {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        if line.len() > MAX_FRAME {
            bail!("MCP request exceeds the fixed envelope");
        }
        let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => Ok(json!({
                "protocolVersion": message.pointer("/params/protocolVersion")
                    .cloned().unwrap_or_else(|| json!("2024-11-05")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ninna-query-mcp", "version": "1.0.0"}
            })),
            Some("tools/list") => Ok(json!({"tools": [knowledge_tool()]})),
            Some("tools/call")
                if message.pointer("/params/name").and_then(Value::as_str)
                    == Some("knowledge_query") =>
            {
                broker_query(
                    socket_path,
                    message
                        .pointer("/params/arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                )
                .await
                .map(|value| json!({"content": [{"type": "text", "text": value.to_string()}]}))
            }
            Some("ping") => Ok(json!({})),
            _ => Err(anyhow!("method not found")),
        };
        let response = match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(_) => json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32001, "message": "knowledge query denied"}}),
        };
        stdout.write_all(format!("{response}\n").as_bytes()).await?;
        stdout.flush().await?;
    }
}

async fn broker_query(socket_path: &Path, args: Value) -> Result<Value> {
    let mut socket = UnixStream::connect(socket_path).await?;
    socket
        .write_all(format!("{}\n", json!({"args": args})).as_bytes())
        .await?;
    socket.shutdown().await?;
    let mut body = Vec::new();
    socket
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut body)
        .await?;
    if body.len() > MAX_FRAME {
        bail!("knowledge broker response exceeds the fixed envelope");
    }
    let envelope: Value = serde_json::from_slice(&body)?;
    if envelope.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("knowledge broker denied query");
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("missing result"))
}

fn knowledge_tool() -> Value {
    json!({
        "name": "knowledge_query",
        "description": "NINNOに関する問い合わせに必要な、閲覧可能範囲の承認済み情報を検索する。",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "properties": {
                "query": {"type": "string", "minLength": 2, "maxLength": 240},
                "top": {"type": "integer", "minimum": 1, "maximum": 5},
                "mode": {"type": "string", "enum": ["hybrid", "bm25"]},
                "source": {"type": "string", "enum": ["slack", "drive", "vault"]},
                "kind": {"type": "string", "enum": ["message", "attachment", "document", "link"]},
                "channel": {"type": "string", "minLength": 1, "maxLength": 120}
            },
            "required": ["query"]
        }
    })
}
