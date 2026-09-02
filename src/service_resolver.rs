//! Agent 间服务发现客户端
//!
//! 通过 PK 主控的服务注册中心发现其他 Agent，支持本地缓存、负载均衡、故障转移。
//!
//! 使用场景：
//! - SPDE 发现 PDC 服务，将 peer 发现任务委托给 PDC
//! - PDC 发现其他 Agent，建立点对点连接

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// 服务信息（从 PK 查询返回）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub agent_id: Uuid,
    pub name: String,
    pub agent_type: String,
    pub host: String,
    pub port: u16,
    pub capabilities: Vec<String>,
    pub health: String,
    pub load: f32,
    #[serde(default)]
    pub region: Option<String>,
    pub version: String,
}

impl ServiceInfo {
    /// 构造基础 URL
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// 是否健康
    pub fn is_healthy(&self) -> bool {
        self.health == "healthy"
    }

    /// 是否具备指定能力
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
}

/// 缓存条目
struct CacheEntry {
    services: Vec<ServiceInfo>,
    cached_at: Instant,
}

/// 失败记录
struct FailureRecord {
    failed_at: Instant,
    consecutive_failures: u32,
}

/// 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// 轮询
    RoundRobin,
    /// 随机
    Random,
    /// 最低负载优先
    LeastLoad,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::LeastLoad
    }
}

/// 服务解析器配置
#[derive(Debug, Clone)]
pub struct ServiceResolverConfig {
    /// PK 主控地址
    pub master_url: String,
    /// 认证 Token
    pub token: Option<String>,
    /// 缓存 TTL（秒）
    pub cache_ttl_secs: u64,
    /// 失败冷却时间（秒）
    pub failure_cooldown_secs: u64,
    /// 最大连续失败次数（超过后暂时移除）
    pub max_consecutive_failures: u32,
    /// 负载均衡策略
    pub strategy: LoadBalanceStrategy,
}

impl Default for ServiceResolverConfig {
    fn default() -> Self {
        Self {
            master_url: "http://127.0.0.1:5566".to_string(),
            token: None,
            cache_ttl_secs: 60,
            failure_cooldown_secs: 30,
            max_consecutive_failures: 3,
            strategy: LoadBalanceStrategy::default(),
        }
    }
}

/// 服务解析器
pub struct ServiceResolver {
    config: ServiceResolverConfig,
    /// 缓存（查询键 -> 缓存条目）
    cache: DashMap<String, CacheEntry>,
    /// 失败记录（agent_id -> 失败记录）
    failures: DashMap<Uuid, FailureRecord>,
    /// 轮询计数器
    round_robin_counter: DashMap<String, std::sync::atomic::AtomicUsize>,
    /// HTTP 客户端
    client: reqwest::Client,
}

impl ServiceResolver {
    /// 创建新的服务解析器
    pub fn new(config: ServiceResolverConfig) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build http client");
        Arc::new(Self {
            config,
            cache: DashMap::new(),
            failures: DashMap::new(),
            round_robin_counter: DashMap::new(),
            client,
        })
    }

    /// 查询指定类型和能力的服务列表
    pub async fn resolve(
        &self,
        agent_type: &str,
        capability: Option<&str>,
    ) -> Result<Vec<ServiceInfo>> {
        let cache_key = format!("{}:{}", agent_type, capability.unwrap_or("any"));

        // 检查缓存
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.cached_at.elapsed() < Duration::from_secs(self.config.cache_ttl_secs) {
                return Ok(self.filter_healthy(&entry.services));
            }
        }

        // 从 PK 查询
        let services = self.query_from_master(agent_type, capability).await?;

        // 更新缓存
        self.cache.insert(
            cache_key,
            CacheEntry {
                services: services.clone(),
                cached_at: Instant::now(),
            },
        );

        Ok(self.filter_healthy(&services))
    }

    /// 选择一个服务实例（负载均衡）
    pub async fn select_one(
        &self,
        agent_type: &str,
        capability: Option<&str>,
    ) -> Result<Option<ServiceInfo>> {
        let services = self.resolve(agent_type, capability).await?;
        if services.is_empty() {
            return Ok(None);
        }

        let key = format!("{}:{}", agent_type, capability.unwrap_or("any"));
        let selected = match self.config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let counter = self
                    .round_robin_counter
                    .entry(key.clone())
                    .or_insert_with(|| std::sync::atomic::AtomicUsize::new(0));
                let idx =
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % services.len();
                services[idx].clone()
            }
            LoadBalanceStrategy::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..services.len());
                services[idx].clone()
            }
            LoadBalanceStrategy::LeastLoad => services
                .iter()
                .min_by(|a, b| {
                    a.load
                        .partial_cmp(&b.load)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned()
                .unwrap_or_else(|| services[0].clone()),
        };

        Ok(Some(selected))
    }

    /// 记录服务调用成功
    pub fn record_success(&self, agent_id: Uuid) {
        self.failures.remove(&agent_id);
    }

    /// 记录服务调用失败
    pub fn record_failure(&self, agent_id: Uuid) {
        let mut entry = self
            .failures
            .entry(agent_id)
            .or_insert_with(|| FailureRecord {
                failed_at: Instant::now(),
                consecutive_failures: 0,
            });
        entry.failed_at = Instant::now();
        entry.consecutive_failures += 1;
    }

    /// 从 PK 主控查询服务
    async fn query_from_master(
        &self,
        agent_type: &str,
        capability: Option<&str>,
    ) -> Result<Vec<ServiceInfo>> {
        let mut url = format!(
            "{}/api/v1/agents?agent_type={}",
            self.config.master_url, agent_type
        );
        if let Some(cap) = capability {
            url.push_str(&format!("&capability={}", cap));
        }

        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let resp = request
            .send()
            .await
            .with_context(|| "查询服务注册中心失败")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "查询服务注册中心失败，状态码: {}",
                resp.status()
            ));
        }

        #[derive(Deserialize)]
        struct QueryResponse {
            success: bool,
            data: Option<QueryData>,
        }
        #[derive(Deserialize)]
        struct QueryData {
            agents: Vec<ServiceInfo>,
            total: usize,
        }

        let body: QueryResponse = resp.json().await?;
        let agents = body.data.map(|d| d.agents).unwrap_or_default();
        Ok(agents)
    }

    /// 过滤掉不健康和冷却中的服务
    fn filter_healthy(&self, services: &[ServiceInfo]) -> Vec<ServiceInfo> {
        services
            .iter()
            .filter(|s| s.is_healthy())
            .filter(|s| {
                if let Some(failure) = self.failures.get(&s.agent_id) {
                    // 超过最大失败次数且在冷却期内，跳过
                    if failure.consecutive_failures >= self.config.max_consecutive_failures
                        && failure.failed_at.elapsed()
                            < Duration::from_secs(self.config.failure_cooldown_secs)
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// 清空缓存
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// 获取缓存的服务数量
    pub fn cached_count(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_info_base_url() {
        let info = ServiceInfo {
            agent_id: Uuid::new_v4(),
            name: "pdc-1".to_string(),
            agent_type: "pdc".to_string(),
            host: "10.0.0.5".to_string(),
            port: 6881,
            capabilities: vec!["tracker".to_string()],
            health: "healthy".to_string(),
            load: 0.3,
            region: None,
            version: "0.1.0".to_string(),
        };
        assert_eq!(info.base_url(), "http://10.0.0.5:6881");
        assert!(info.is_healthy());
        assert!(info.has_capability("tracker"));
        assert!(!info.has_capability("dht"));
    }

    #[test]
    fn resolver_config_defaults() {
        let config = ServiceResolverConfig::default();
        assert_eq!(config.cache_ttl_secs, 60);
        assert_eq!(config.failure_cooldown_secs, 30);
        assert_eq!(config.max_consecutive_failures, 3);
        assert_eq!(config.strategy, LoadBalanceStrategy::LeastLoad);
    }

    #[test]
    fn failure_record_tracking() {
        let resolver = ServiceResolver::new(ServiceResolverConfig::default());
        let id = Uuid::new_v4();

        resolver.record_failure(id);
        resolver.record_failure(id);
        resolver.record_failure(id);

        // 超过最大失败次数，应该被过滤
        let info = ServiceInfo {
            agent_id: id,
            name: "test".to_string(),
            agent_type: "pdc".to_string(),
            host: "127.0.0.1".to_string(),
            port: 6881,
            capabilities: vec![],
            health: "healthy".to_string(),
            load: 0.0,
            region: None,
            version: "0.1.0".to_string(),
        };
        let filtered = resolver.filter_healthy(&[info]);
        assert!(filtered.is_empty());

        // 记录成功后应该恢复
        resolver.record_success(id);
        let info2 = ServiceInfo {
            agent_id: id,
            name: "test".to_string(),
            agent_type: "pdc".to_string(),
            host: "127.0.0.1".to_string(),
            port: 6881,
            capabilities: vec![],
            health: "healthy".to_string(),
            load: 0.0,
            region: None,
            version: "0.1.0".to_string(),
        };
        let filtered2 = resolver.filter_healthy(&[info2]);
        assert_eq!(filtered2.len(), 1);
    }
}
