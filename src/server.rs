//! serve 模式 HTTP API 服务
//!
//! 基于 axum 实现，提供 7 个端点：
//! - POST /api/v1/discover - 发现 peer
//! - GET  /api/v1/peers    - 查看缓存 peer
//! - GET  /api/v1/stats    - 统计信息
//! - GET  /api/v1/health   - 健康检查
//! - GET  /api/v1/config   - 查看配置
//! - POST /api/v1/announce - 宣告做种
//! - GET  /api/v1/capability - 能力清单（供其他 Agent 能力协商）

use crate::config::PdcConfig;
use crate::history::{DiscoveryHistoryRecord, HistoryWriter};
use crate::protocol::*;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// 共享状态
pub struct ServerState {
    /// 配置
    pub config: RwLock<PdcConfig>,
    /// 启动时间
    pub started_at: Instant,
    /// 历史记录写入器
    pub history: HistoryWriter,
    /// 统计：总请求数
    pub total_requests: AtomicU64,
    /// 统计：成功请求数
    pub success_requests: AtomicU64,
    /// 统计：失败请求数
    pub failed_requests: AtomicU64,
    /// 统计：总发现 peer 数
    pub total_peers_discovered: AtomicU64,
    /// 统计：总响应时间（毫秒）
    pub total_response_ms: AtomicU64,
    /// 缓存的 peer（infohash -> peer 列表）
    pub cached_peers: DashMap<String, Vec<PeerResponse>>,
}

impl ServerState {
    /// 创建新的共享状态
    pub fn new(config: PdcConfig, history: HistoryWriter) -> Self {
        Self {
            config: RwLock::new(config),
            started_at: Instant::now(),
            history,
            total_requests: AtomicU64::new(0),
            success_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            total_peers_discovered: AtomicU64::new(0),
            total_response_ms: AtomicU64::new(0),
            cached_peers: DashMap::new(),
        }
    }

    /// 记录一次请求
    pub fn record_request(&self, success: bool, peers_count: usize, duration_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        self.total_peers_discovered
            .fetch_add(peers_count as u64, Ordering::Relaxed);
        self.total_response_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
    }

    /// 获取成功率
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.success_requests.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// 获取平均响应时间
    pub fn avg_response_ms(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.total_response_ms.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// 获取缓存 peer 总数
    pub fn cached_peers_count(&self) -> usize {
        self.cached_peers.iter().map(|r| r.value().len()).sum()
    }
}

/// 统一响应类型
pub type ApiResult<T> = Result<Json<T>, AppError>;

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

// ─── API 端点 ───

/// 发现 peer
async fn discover(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<DiscoverResponse> {
    let start = Instant::now();
    tracing::info!("发现请求: infohash={}, limit={}", req.infohash, req.limit);

    // 解析 infohash
    let infohash_bytes = match hex::decode(&req.infohash) {
        Ok(bytes) if bytes.len() == 20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return Err(AppError(anyhow::anyhow!(
                "无效的 infohash：必须是 40 字符的 hex 编码"
            )));
        }
    };

    // 模拟发现结果（实际应调用 PeerDiscoveryAggregator）
    // TODO: 集成真实的 PeerDiscoveryAggregator
    let peers: Vec<PeerResponse> = Vec::new();
    let mut source_stats = std::collections::HashMap::new();
    source_stats.insert("tracker".to_string(), 0);
    source_stats.insert("dht".to_string(), 0);
    source_stats.insert("cache".to_string(), 0);

    let duration_ms = start.elapsed().as_millis() as u64;
    let success = true;
    let peers_count = peers.len();

    // 记录统计
    state.record_request(success, peers_count, duration_ms);

    // 写入历史
    let record = DiscoveryHistoryRecord::new(
        req.infohash.clone(),
        peers_count,
        source_stats.clone(),
        duration_ms,
        success,
        None,
    );
    if let Err(e) = state.history.append(&record) {
        tracing::warn!("写入历史记录失败: {}", e);
    }

    Ok(Json(DiscoverResponse {
        peers_count,
        peers,
        duration_ms,
        source_stats,
    }))
}

/// 查看缓存 peer
async fn list_peers(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<PeersQuery>,
) -> ApiResult<CachedPeersResponse> {
    let limit = params.limit.unwrap_or(50);
    let mut all_peers: Vec<PeerResponse> = Vec::new();

    if let Some(infohash) = &params.infohash {
        if let Some(peers) = state.cached_peers.get(infohash) {
            all_peers.extend(peers.iter().take(limit).cloned());
        }
    } else {
        for entry in state.cached_peers.iter() {
            all_peers.extend(entry.value().iter().cloned());
            if all_peers.len() >= limit {
                break;
            }
        }
        all_peers.truncate(limit);
    }

    Ok(Json(CachedPeersResponse {
        count: all_peers.len(),
        peers: all_peers,
    }))
}

#[derive(Debug, serde::Deserialize)]
struct PeersQuery {
    infohash: Option<String>,
    limit: Option<usize>,
}

/// 统计信息
async fn stats(State(state): State<Arc<ServerState>>) -> ApiResult<StatsResponse> {
    let mut discoverer_stats = std::collections::HashMap::new();
    // TODO: 集成真实的发现器统计
    discoverer_stats.insert(
        "tracker".to_string(),
        DiscovererStat {
            total_requests: 0,
            success_requests: 0,
            failed_requests: 0,
            success_rate: 0.0,
            total_peers_discovered: 0,
            avg_response_ms: 0.0,
        },
    );

    Ok(Json(StatsResponse {
        total_requests: state.total_requests.load(Ordering::Relaxed),
        success_requests: state.success_requests.load(Ordering::Relaxed),
        failed_requests: state.failed_requests.load(Ordering::Relaxed),
        success_rate: state.success_rate(),
        total_peers_discovered: state.total_peers_discovered.load(Ordering::Relaxed),
        avg_response_ms: state.avg_response_ms(),
        cached_peers: state.cached_peers_count(),
        discoverer_stats,
    }))
}

/// 健康检查
async fn health(State(state): State<Arc<ServerState>>) -> ApiResult<HealthResponse> {
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        discoverers: 3, // tracker + dht + pex
        cached_peers: state.cached_peers_count(),
        uptime_secs: state.started_at.elapsed().as_secs(),
    }))
}

/// 查看配置
async fn get_config(State(state): State<Arc<ServerState>>) -> ApiResult<ConfigResponse> {
    let config = state.config.read().await;
    let yaml = config.to_yaml()?;
    Ok(Json(ConfigResponse { config_yaml: yaml }))
}

/// 宣告做种
async fn announce(
    State(_state): State<Arc<ServerState>>,
    Json(_req): Json<AnnounceRequest>,
) -> ApiResult<serde_json::Value> {
    // TODO: 集成真实的 announce 逻辑
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "announce received"
    })))
}

/// 能力清单（供其他 Agent 能力协商使用）
async fn capability(State(state): State<Arc<ServerState>>) -> ApiResult<CapabilityResponse> {
    let config = state.config.read().await;
    Ok(Json(CapabilityResponse {
        name: "pdc".to_string(),
        version: crate::VERSION.to_string(),
        capabilities: config.capability_tags(),
        max_concurrent_discoverers: config.discovery.max_concurrent_discoverers,
        cached_peers: state.cached_peers_count(),
    }))
}

/// 构建 HTTP 路由
pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/api/v1/discover", post(discover))
        .route("/api/v1/peers", get(list_peers))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/health", get(health))
        .route("/api/v1/config", get(get_config))
        .route("/api/v1/announce", post(announce))
        .route("/api/v1/capability", get(capability))
        .with_state(state)
}

/// 启动 serve 模式 HTTP 服务
pub async fn run_server(config: PdcConfig, history: HistoryWriter) -> anyhow::Result<()> {
    let state = Arc::new(ServerState::new(config.clone(), history));
    let app = build_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let socket_addr: SocketAddr = addr.parse()?;

    tracing::info!("PDC serve 模式启动，监听 http://{}", socket_addr);
    tracing::info!("API 端点:");
    tracing::info!("  POST /api/v1/discover    - 发现 peer");
    tracing::info!("  GET  /api/v1/peers       - 查看缓存 peer");
    tracing::info!("  GET  /api/v1/stats       - 统计信息");
    tracing::info!("  GET  /api/v1/health      - 健康检查");
    tracing::info!("  GET  /api/v1/config      - 查看配置");
    tracing::info!("  POST /api/v1/announce    - 宣告做种");
    tracing::info!("  GET  /api/v1/capability  - 能力清单");

    let listener = tokio::net::TcpListener::bind(socket_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_state_stats() {
        let dir = std::env::temp_dir().join(format!("pdc-server-test-{}", uuid::Uuid::new_v4()));
        let history = HistoryWriter::open(&dir.join("test.jsonl")).unwrap();
        let state = ServerState::new(PdcConfig::default_config(), history);

        assert_eq!(state.total_requests.load(Ordering::Relaxed), 0);
        state.record_request(true, 10, 100);
        assert_eq!(state.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.success_rate(), 1.0);
        assert_eq!(state.avg_response_ms(), 100.0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
