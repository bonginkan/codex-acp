//! Model-invisible query transport for the restricted NINNA worker.
//!
//! The same review-pinned binary supplies both the MCP stdio bridge inside the
//! ACP sandbox and a separate-UID Unix proxy outside it. The proxy opens the
//! broker connection immediately when accepting the frontend connection, so
//! the broker can bind that connection to the then-current turn before any
//! model-controlled query bytes are read.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

const FIXED_MCP_SOCKET: &str = "/run/ninna/query.sock";
const FIXED_BACKEND_SOCKET: &str = "/run/ninna-broker/query.sock";
const MAX_FRAME: usize = 64 * 1024;
const QUERY_AUTHORIZATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

struct QueryAuthorizationClient {
    stream: Mutex<UnixStream>,
    raw_fd: i32,
    poisoned: AtomicBool,
}

struct QueryAuthorizationAttempt<'a> {
    client: &'a QueryAuthorizationClient,
    completed: bool,
}

impl QueryAuthorizationAttempt<'_> {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for QueryAuthorizationAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.client.poison_now();
        }
    }
}

impl QueryAuthorizationClient {
    fn new(stream: UnixStream) -> Self {
        Self {
            raw_fd: stream.as_raw_fd(),
            stream: Mutex::new(stream),
            poisoned: AtomicBool::new(false),
        }
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison_now(&self) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            unsafe {
                libc::shutdown(self.raw_fd, libc::SHUT_RDWR);
            }
        }
    }

    async fn authorize(&self, worker_instance: &str, turn_binding: &str) -> Result<()> {
        self.authorize_with_timeout(worker_instance, turn_binding, QUERY_AUTHORIZATION_TIMEOUT)
            .await
    }

    async fn authorize_with_timeout(
        &self,
        worker_instance: &str,
        turn_binding: &str,
        timeout: std::time::Duration,
    ) -> Result<()> {
        if self.is_poisoned() {
            bail!("query authorization channel is poisoned");
        }
        let query_nonce = Uuid::new_v4().simple().to_string();
        let expires_at_epoch_millis = epoch_millis()?
            .checked_add(
                u64::try_from(timeout.as_millis()).context("authorization timeout overflow")?,
            )
            .ok_or_else(|| anyhow!("authorization deadline overflow"))?;
        let request = json!({
            "workerInstance": worker_instance,
            "turnBinding": turn_binding,
            "queryNonce": query_nonce,
            "expiresAtEpochMillis": expires_at_epoch_millis,
        });
        let expected_acknowledgement = json!({
            "ok": true,
            "authorized": true,
            "workerInstance": worker_instance,
            "turnBinding": turn_binding,
            "queryNonce": query_nonce,
            "expiresAtEpochMillis": expires_at_epoch_millis,
        });
        let attempt = QueryAuthorizationAttempt {
            client: self,
            completed: false,
        };
        let exchange = async {
            let mut authorization = self.stream.lock().await;
            if self.is_poisoned() {
                bail!("query authorization channel is poisoned");
            }
            authorization
                .write_all(format!("{request}\n").as_bytes())
                .await?;
            authorization.flush().await?;
            let mut response = String::new();
            let read = BufReader::new(&mut *authorization)
                .read_line(&mut response)
                .await?;
            if read == 0 || response.len() > 512 {
                bail!("live query authorization response is unavailable or oversized");
            }
            if epoch_millis()? >= expires_at_epoch_millis
                || serde_json::from_str::<Value>(response.trim())? != expected_acknowledgement
            {
                bail!("live query authorization was denied or mismatched");
            }
            Ok(())
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(Ok(())) => {
                attempt.complete();
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(_) => bail!("live query authorization timeout"),
        }
    }
}

fn epoch_millis() -> Result<u64> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("epoch millisecond value overflow")
}

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
    let authorization_fd = exact_option(&args[2..], "authorization-fd")?
        .parse::<i32>()
        .context("invalid authorization fd")?;
    if args.len() != 7
        || !frontend.starts_with("/run/ninna-proxy/")
        || backend != FIXED_BACKEND_SOCKET
        || !is_sha256(&worker_instance)
        || expected_client_uid == 0
        || authorization_fd != 4
    {
        bail!("invalid restricted query proxy invocation");
    }
    // SAFETY: OpenAB creates a private socketpair, duplicates the child end to
    // the exact inherited FD 4, and transfers ownership to this process.
    let authorization = unsafe { StdUnixStream::from_raw_fd(authorization_fd) };
    authorization
        .set_nonblocking(true)
        .context("configure query authorization channel")?;
    let authorization = Arc::new(QueryAuthorizationClient::new(
        UnixStream::from_std(authorization).context("adopt query authorization channel")?,
    ));
    run_query_proxy(
        Path::new(&frontend),
        Path::new(&backend),
        &worker_instance,
        expected_client_uid,
        authorization,
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
    authorization: Arc<QueryAuthorizationClient>,
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
    let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
    loop {
        tokio::select! {
            failure = failure_rx.recv() => {
                let error = failure.ok_or_else(|| anyhow!("query proxy failure channel closed"))?;
                authorization.poison_now();
                return Err(error).context("restricted query failed; retiring proxy");
            }
            accepted = listener.accept() => {
                let (client, _) = accepted?;
                let backend = backend.to_path_buf();
                let worker_instance = worker_instance.to_string();
                let authorization = Arc::clone(&authorization);
                let failure_tx = failure_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = proxy_one(
                        client,
                        backend,
                        worker_instance,
                        expected_client_uid,
                        Arc::clone(&authorization),
                    )
                    .await
                    {
                        authorization.poison_now();
                        drop(failure_tx.send(error));
                    }
                });
            }
        }
    }
}

async fn proxy_one(
    mut client: UnixStream,
    backend_path: PathBuf,
    worker_instance: String,
    expected_client_uid: u32,
    authorization: Arc<QueryAuthorizationClient>,
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
    if acknowledgement.len() > 256 {
        bail!("knowledge broker did not confirm the query binding");
    }
    let acknowledgement: Value = serde_json::from_str(acknowledgement.trim())?;
    let authorization_binding = acknowledgement
        .get("authorizationBinding")
        .and_then(Value::as_str)
        .filter(|value| is_sha256(value))
        .ok_or_else(|| anyhow!("knowledge broker omitted the authorization binding"))?;
    if acknowledgement.get("ok").and_then(Value::as_bool) != Some(true)
        || acknowledgement.get("bound").and_then(Value::as_bool) != Some(true)
        || acknowledgement
            .as_object()
            .is_none_or(|value| value.len() != 3)
    {
        bail!("knowledge broker did not confirm the query binding");
    }
    // Ask OpenAB to perform a fresh Slack API visibility check for this exact
    // Knowledge turn. This private channel is outside the ACP namespace. The
    // frontend remains unread until the exact positive ACK arrives.
    authorization
        .authorize(&worker_instance, authorization_binding)
        .await?;
    // Only after the broker acknowledges the immutable turn binding may any
    // bytes controlled by the MCP child cross into the trusted backend, and
    // only after OpenAB has refreshed current Slack visibility for that turn.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_authorization_denial_forwards_no_query_bytes() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let backend_path = std::env::temp_dir().join(format!(
            "codex-acp-query-auth-{}-{nonce}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&backend_path).unwrap();
        let binding = "b".repeat(64);
        let backend_binding = binding.clone();
        let backend = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut handshake = String::new();
            reader.read_line(&mut handshake).await.unwrap();
            reader
                .get_mut()
                .write_all(
                    format!(
                        "{}\n",
                        json!({
                            "ok": true,
                            "bound": true,
                            "authorizationBinding": backend_binding,
                        })
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut leaked = Vec::new();
            reader.read_to_end(&mut leaked).await.unwrap();
            leaked
        });

        let (proxy_authorization, mut trusted_authorizer) = UnixStream::pair().unwrap();
        let worker = "a".repeat(64);
        let expected_worker = worker.clone();
        let authorization = tokio::spawn(async move {
            let mut request = String::new();
            BufReader::new(&mut trusted_authorizer)
                .read_line(&mut request)
                .await
                .unwrap();
            let request = serde_json::from_str::<Value>(request.trim()).unwrap();
            assert_eq!(request["workerInstance"], expected_worker);
            assert_eq!(request["turnBinding"], binding);
            assert_eq!(request["queryNonce"].as_str().unwrap().len(), 32);
            assert!(request["expiresAtEpochMillis"].as_u64().unwrap() > epoch_millis().unwrap());
            trusted_authorizer
                .write_all(b"{\"ok\":false}\n")
                .await
                .unwrap();
        });

        let (proxy_client, mut model_client) = UnixStream::pair().unwrap();
        model_client
            .write_all(b"{\"args\":{\"query\":\"must-not-cross\"}}\n")
            .await
            .unwrap();
        model_client.shutdown().await.unwrap();

        let result = proxy_one(
            proxy_client,
            backend_path.clone(),
            worker,
            unsafe { libc::geteuid() },
            Arc::new(QueryAuthorizationClient::new(proxy_authorization)),
        )
        .await;
        assert!(result.is_err());
        authorization.await.unwrap();
        assert!(backend.await.unwrap().is_empty());
        drop(std::fs::remove_file(backend_path));
    }

    #[tokio::test]
    async fn timed_out_ack_cannot_authorize_a_later_query() {
        let (client_stream, mut authorizer) = UnixStream::pair().unwrap();
        let client = Arc::new(QueryAuthorizationClient::new(client_stream));
        let server = tokio::spawn(async move {
            let mut request = String::new();
            BufReader::new(&mut authorizer)
                .read_line(&mut request)
                .await
                .unwrap();
            let request = serde_json::from_str::<Value>(request.trim()).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            let late_ack = json!({
                "ok": true,
                "authorized": true,
                "workerInstance": request["workerInstance"],
                "turnBinding": request["turnBinding"],
                "queryNonce": request["queryNonce"],
                "expiresAtEpochMillis": request["expiresAtEpochMillis"],
            });
            drop(
                authorizer
                    .write_all(format!("{late_ack}\n").as_bytes())
                    .await,
            );
            let mut unexpected_second_request = Vec::new();
            drop(authorizer.read_to_end(&mut unexpected_second_request).await);
            unexpected_second_request
        });

        assert!(
            client
                .authorize_with_timeout(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    std::time::Duration::from_millis(10),
                )
                .await
                .is_err()
        );
        assert!(client.is_poisoned());
        assert!(
            client
                .authorize_with_timeout(
                    &"a".repeat(64),
                    &"c".repeat(64),
                    std::time::Duration::from_millis(10),
                )
                .await
                .is_err()
        );
        assert!(server.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn partial_ack_timeout_poisons_the_shared_channel() {
        let (client_stream, mut authorizer) = UnixStream::pair().unwrap();
        let client = Arc::new(QueryAuthorizationClient::new(client_stream));
        let server = tokio::spawn(async move {
            let mut request = String::new();
            BufReader::new(&mut authorizer)
                .read_line(&mut request)
                .await
                .unwrap();
            authorizer.write_all(b"{\"ok\":true").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        });

        assert!(
            client
                .authorize_with_timeout(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    std::time::Duration::from_millis(10),
                )
                .await
                .is_err()
        );
        assert!(client.is_poisoned());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn acknowledgement_for_a_different_query_nonce_is_rejected() {
        let (client_stream, mut authorizer) = UnixStream::pair().unwrap();
        let client = Arc::new(QueryAuthorizationClient::new(client_stream));
        let server = tokio::spawn(async move {
            let mut request = String::new();
            BufReader::new(&mut authorizer)
                .read_line(&mut request)
                .await
                .unwrap();
            let request = serde_json::from_str::<Value>(request.trim()).unwrap();
            let wrong_ack = json!({
                "ok": true,
                "authorized": true,
                "workerInstance": request["workerInstance"],
                "turnBinding": request["turnBinding"],
                "queryNonce": "f".repeat(32),
                "expiresAtEpochMillis": request["expiresAtEpochMillis"],
            });
            authorizer
                .write_all(format!("{wrong_ack}\n").as_bytes())
                .await
                .unwrap();
        });

        assert!(
            client
                .authorize_with_timeout(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    std::time::Duration::from_secs(1),
                )
                .await
                .is_err()
        );
        assert!(client.is_poisoned());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_authorization_attempt_poisons_the_shared_channel() {
        let (client_stream, mut authorizer) = UnixStream::pair().unwrap();
        let client = Arc::new(QueryAuthorizationClient::new(client_stream));
        let (request_seen_tx, request_seen_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut request = String::new();
            BufReader::new(&mut authorizer)
                .read_line(&mut request)
                .await
                .unwrap();
            request_seen_tx.send(()).unwrap();
            let mut remainder = Vec::new();
            authorizer.read_to_end(&mut remainder).await.unwrap();
        });
        let task_client = Arc::clone(&client);
        let task = tokio::spawn(async move {
            task_client
                .authorize(&"a".repeat(64), &"b".repeat(64))
                .await
        });
        request_seen_rx.await.unwrap();
        task.abort();
        drop(task.await);
        assert!(client.is_poisoned());
        assert!(
            client
                .authorize_with_timeout(
                    &"a".repeat(64),
                    &"c".repeat(64),
                    std::time::Duration::from_millis(10),
                )
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}
