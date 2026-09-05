//! Agent 模式
//!
//! 接入 PK 主控，接受任务派发并回报结果。
//! 生命周期：启动自检 → 主控发现 → 节点注册 → WebSocket 连接 → 心跳循环 → 任务执行/回报 → 断线重连

use crate::bootstrap::{hostname, platform_info, Bootstrap};
use PeerDiscoveryCenter::config::PdcConfig;
use crate::history::HistoryWriter;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Agent 运行时状态
pub struct AgentRuntime {
    /// 启动引导信息
    pub bootstrap: Bootstrap,
    /// 配置
    pub config: RwLock<PdcConfig>,
    /// 历史记录写入器
    pub history: HistoryWriter,
    /// 主控地址
    pub master_url: RwLock<Option<String>>,
    /// 认证 Token
    pub token: RwLock<Option<String>>,
    /// WebSocket 连接状态
    pub connected: RwLock<bool>,
}

impl AgentRuntime {
    /// 创建新的 Agent 运行时
    pub fn new(bootstrap: Bootstrap, history: HistoryWriter) -> Self {
        let master_url = bootstrap.config.controller.master.clone();
        let token = bootstrap.config.controller.token.clone();
        Self {
            config: RwLock::new(bootstrap.config.clone()),
            bootstrap,
            history,
            master_url: RwLock::new(master_url),
            token: RwLock::new(token),
            connected: RwLock::new(false),
        }
    }

    /// 获取节点 ID
    pub fn node_id(&self) -> Uuid {
        self.bootstrap.identity.node_id
    }

    /// 获取节点名称
    pub fn node_name(&self) -> String {
        self.bootstrap
            .config
            .agent
            .name
            .clone()
            .unwrap_or_else(hostname)
    }
}

/// 注册请求
#[derive(Debug, Serialize)]
struct RegisterRequest {
    node_id: Uuid,
    hostname: String,
    platform: String,
    arch: String,
    version: String,
    agent_type: String,
    serve_host: String,
    serve_port: u16,
    region: Option<String>,
    capability_tags: Vec<String>,
}

/// 注册响应
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    node_id: Uuid,
    poll_interval_secs: u64,
    master_listen: String,
}

/// 心跳请求
#[derive(Debug, Serialize)]
struct HeartbeatRequest {
    node_id: Uuid,
    active_tasks: u32,
    bytes_downloaded: u64,
    busy: bool,
}

/// WebSocket 消息信封
#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(flatten)]
    payload: serde_json::Value,
}

/// 启动 Agent 模式
pub async fn run_agent(
    bootstrap: Bootstrap,
    history: HistoryWriter,
    master_override: Option<String>,
    token_override: Option<String>,
    name_override: Option<String>,
) -> Result<()> {
    let mut config = bootstrap.config.clone();

    // 应用命令行覆盖
    if let Some(master) = master_override {
        config.controller.master = Some(master);
    }
    if let Some(token) = token_override {
        config.controller.token = Some(token);
    }
    if let Some(name) = name_override {
        config.agent.name = Some(name);
    }

    let runtime = Arc::new(AgentRuntime::new(bootstrap, history));

    // 如果没有指定主控，尝试局域网自动发现
    if runtime.master_url.read().await.is_none() && config.controller.auto_discover_master {
        tracing::info!("未指定主控地址，尝试局域网自动发现...");
        if let Some(found) = discover_master_on_lan(&config).await {
            tracing::info!("局域网发现主控: {}", found);
            *runtime.master_url.write().await = Some(found);
        }
    }

    let master_url = runtime.master_url.read().await.clone();
    let master_url = match master_url {
        Some(url) => url,
        None => {
            return Err(anyhow::anyhow!(
                "未找到主控地址。请使用 --master 指定，或启用局域网自动发现"
            ));
        }
    };

    tracing::info!("PDC Agent 模式启动，节点 ID: {}", runtime.node_id());
    tracing::info!("主控地址: {}", master_url);
    tracing::info!("节点名称: {}", runtime.node_name());

    // 1. 注册节点
    let register_result = register_node(&runtime, &master_url).await;
    match register_result {
        Ok(resp) => {
            tracing::info!("节点注册成功，心跳间隔: {}s", resp.poll_interval_secs);
        }
        Err(e) => {
            tracing::warn!("HTTP 注册失败，将通过 WebSocket 注册: {}", e);
        }
    }

    // 2. 建立 WebSocket 连接
    let ws_url = format!(
        "{}/ws",
        master_url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    );
    tracing::info!("连接 WebSocket: {}", ws_url);

    let reconnect_interval = config.agent.reconnect_interval_secs;
    let heartbeat_interval = config.agent.heartbeat_interval_secs;

    loop {
        match connect_and_run(&runtime, &ws_url, heartbeat_interval).await {
            Ok(()) => {
                tracing::info!("WebSocket 连接正常结束");
                break;
            }
            Err(e) => {
                tracing::warn!("WebSocket 连接断开: {}，{}s 后重连", e, reconnect_interval);
                *runtime.connected.write().await = false;
                tokio::time::sleep(Duration::from_secs(reconnect_interval)).await;
            }
        }
    }

    Ok(())
}

/// 注册节点（HTTP）
async fn register_node(runtime: &Arc<AgentRuntime>, master_url: &str) -> Result<RegisterResponse> {
    let (platform, arch) = platform_info();
    let config = runtime.config.read().await;

    let req = RegisterRequest {
        node_id: runtime.node_id(),
        hostname: runtime.node_name(),
        platform,
        arch,
        version: crate::VERSION.to_string(),
        agent_type: "pdc".to_string(),
        serve_host: config.server.listen.clone(),
        serve_port: config.server.port,
        region: config.agent.region.clone(),
        capability_tags: config.capability_tags(),
    };

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/agent/register", master_url);
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .with_context(|| "注册请求失败")?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("注册失败，状态码: {}", resp.status()));
    }

    let body: RegisterResponse = resp.json().await?;
    Ok(body)
}

/// 建立 WebSocket 连接并运行
async fn connect_and_run(
    runtime: &Arc<AgentRuntime>,
    ws_url: &str,
    heartbeat_interval: u64,
) -> Result<()> {
    let (ws_stream, _) = connect_async(ws_url).await?;
    let (mut write, mut read) = ws_stream.split();
    *runtime.connected.write().await = true;

    tracing::info!("WebSocket 连接成功");

    // 发送注册消息
    let (platform, arch) = platform_info();
    let config = runtime.config.read().await;
    let register_msg = serde_json::json!({
        "type": "register",
        "node_id": runtime.node_id().to_string(),
        "hostname": runtime.node_name(),
        "platform": platform,
        "arch": arch,
        "version": crate::VERSION,
        "agent_type": "pdc",
        "serve_host": config.server.listen,
        "serve_port": config.server.port,
        "region": config.agent.region,
        "capability_tags": config.capability_tags(),
    });
    drop(config);
    write.send(Message::Text(register_msg.to_string())).await?;

    // 心跳任务
    let runtime_clone = runtime.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(heartbeat_interval)).await;
            if !*runtime_clone.connected.read().await {
                break;
            }
            // 心跳通过 WebSocket 发送
            // 实际实现中需要通过 channel 发送给 write 任务
            tracing::debug!("发送心跳");
        }
    });

    // 读取消息
    while let Some(msg) = read.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                if let Err(e) = handle_ws_message(runtime, &text).await {
                    tracing::warn!("处理 WebSocket 消息失败: {}", e);
                }
            }
            Message::Close(_) => {
                tracing::info!("收到关闭帧");
                break;
            }
            _ => {}
        }
    }

    heartbeat_handle.abort();
    *runtime.connected.write().await = false;

    Ok(())
}

/// 处理 WebSocket 消息
async fn handle_ws_message(_runtime: &Arc<AgentRuntime>, text: &str) -> Result<()> {
    let msg: WsMessage = serde_json::from_str(text)?;
    match msg.msg_type.as_str() {
        "ping" => {
            tracing::debug!("收到 ping");
        }
        "config_changed" => {
            tracing::info!("收到配置变更通知，重新拉取配置");
            // TODO: 重新拉取配置
        }
        "new_task" => {
            tracing::info!("收到新任务通知");
            // TODO: 拉取并执行任务
        }
        "discover" => {
            tracing::info!("收到发现任务");
            // TODO: 执行发现任务并回报结果
        }
        "service_changed" => {
            tracing::debug!("收到服务变更通知");
            // TODO: 更新本地服务缓存
        }
        other => {
            tracing::debug!("收到未知消息类型: {}", other);
        }
    }
    Ok(())
}

/// 局域网自动发现主控
async fn discover_master_on_lan(config: &PdcConfig) -> Option<String> {
    let scan_ports = &config.agent.scan_ports;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    // 扫描本地网络的常见地址
    // 简化实现：只扫描 127.0.0.1 和 192.168.1.1
    let hosts = vec!["127.0.0.1".to_string(), "192.168.1.1".to_string()];

    for host in hosts {
        for port in scan_ports {
            let url = format!("http://{}:{}/api/v1/overview", host, port);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    return Some(format!("http://{}:{}", host, port));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_message_parse() {
        let json = r#"{"type":"ping","data":"test"}"#;
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.msg_type, "ping");
    }

    #[test]
    fn register_request_serialize() {
        let req = RegisterRequest {
            node_id: Uuid::new_v4(),
            hostname: "test".to_string(),
            platform: "linux".to_string(),
            arch: "x86_64".to_string(),
            version: "0.1.0".to_string(),
            agent_type: "pdc".to_string(),
            serve_host: "127.0.0.1".to_string(),
            serve_port: 6881,
            region: None,
            capability_tags: vec!["tracker".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"agent_type\":\"pdc\""));
        assert!(json.contains("\"serve_port\":6881"));
    }
}
