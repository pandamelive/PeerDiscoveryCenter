//! PDC 通信协议数据结构
//!
//! 包含 PDC 特有的 API 请求/响应类型，复用 pandanetos 标准库的通用类型。

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// 发现请求
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverRequest {
    /// 目标 info_hash（hex 编码，40 字符）
    pub infohash: String,
    /// 期望返回的 peer 数量上限
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    200
}

/// 发现响应中的单个 peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerResponse {
    /// 节点地址（ip:port）
    pub addr: String,
    /// 来源（tracker / dht / pex / cache）
    pub source: String,
    /// 优先级分数（越高越优先）
    pub priority_score: u32,
    /// 是否为 IPv6
    pub is_ipv6: bool,
}

/// 发现响应
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResponse {
    /// 发现的 peer 数量
    pub peers_count: usize,
    /// 发现的 peer 列表
    pub peers: Vec<PeerResponse>,
    /// 耗时（毫秒）
    pub duration_ms: u64,
    /// 各来源统计（source → count）
    pub source_stats: HashMap<String, usize>,
}

/// 缓存查询响应
#[derive(Debug, Clone, Serialize)]
pub struct CachedPeersResponse {
    /// 缓存的 peer 数量
    pub count: usize,
    /// 缓存的 peer 列表
    pub peers: Vec<PeerResponse>,
}

/// 统计响应
#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    /// 总请求数
    pub total_requests: u64,
    /// 成功请求数
    pub success_requests: u64,
    /// 失败请求数
    pub failed_requests: u64,
    /// 成功率
    pub success_rate: f64,
    /// 总发现 peer 数
    pub total_peers_discovered: u64,
    /// 平均响应时间（毫秒）
    pub avg_response_ms: f64,
    /// 当前缓存 peer 数
    pub cached_peers: usize,
    /// 各发现器统计
    pub discoverer_stats: HashMap<String, DiscovererStat>,
}

/// 单个发现器统计
#[derive(Debug, Clone, Serialize)]
pub struct DiscovererStat {
    pub total_requests: u64,
    pub success_requests: u64,
    pub failed_requests: u64,
    pub success_rate: f64,
    pub total_peers_discovered: u64,
    pub avg_response_ms: f64,
}

/// 健康检查响应
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// 状态（ok / degraded / down）
    pub status: String,
    /// 活跃发现器数量
    pub discoverers: usize,
    /// 缓存 peer 数量
    pub cached_peers: usize,
    /// 运行时间（秒）
    pub uptime_secs: u64,
}

/// 能力清单响应（供其他 Agent 能力协商使用）
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityResponse {
    /// 服务名称
    pub name: String,
    /// 版本号
    pub version: String,
    /// 能力标识列表
    pub capabilities: Vec<String>,
    /// 最大并发发现器数
    pub max_concurrent_discoverers: usize,
    /// 当前缓存 peer 数
    pub cached_peers: usize,
}

/// Announce 请求
#[derive(Debug, Clone, Deserialize)]
pub struct AnnounceRequest {
    /// 本地监听端口
    pub port: u16,
    /// 事件（started / stopped / completed / none）
    #[serde(default = "default_event")]
    pub event: String,
}

fn default_event() -> String {
    "none".to_string()
}

/// 配置查询响应
#[derive(Debug, Clone, Serialize)]
pub struct ConfigResponse {
    /// 当前配置（YAML 字符串）
    pub config_yaml: String,
}

/// Agent 模式下的任务 ID 生成
pub fn new_task_id() -> Uuid {
    Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_request_defaults() {
        let req: DiscoverRequest = serde_json::from_str(r#"{"infohash":"abc"}"#).unwrap();
        assert_eq!(req.infohash, "abc");
        assert_eq!(req.limit, 200);
    }

    #[test]
    fn peer_response_round_trip() {
        let peer = PeerResponse {
            addr: "1.2.3.4:6881".to_string(),
            source: "tracker".to_string(),
            priority_score: 150,
            is_ipv6: false,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let back: PeerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.addr, "1.2.3.4:6881");
        assert_eq!(back.priority_score, 150);
    }

    #[test]
    fn capability_response_serialization() {
        let resp = CapabilityResponse {
            name: "pdc".to_string(),
            version: "0.1.0".to_string(),
            capabilities: vec![
                "tracker".to_string(),
                "dht".to_string(),
                "cache".to_string(),
            ],
            max_concurrent_discoverers: 3,
            cached_peers: 100,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"tracker\""));
    }
}
