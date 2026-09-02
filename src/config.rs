//! PDC 配置管理
//!
//! YAML 分段配置，与 SPDE 配置风格保持一致。
//! 配置文件位于工作目录 `pdc-node/config/config.yaml`。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 完整配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdcConfig {
    /// Agent 模式配置
    #[serde(default)]
    pub agent: AgentConfig,
    /// 全局配置
    #[serde(default)]
    pub global: GlobalConfig,
    /// serve 模式 HTTP 服务配置
    #[serde(default)]
    pub server: ServerConfig,
    /// 发现机制配置
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    /// 主控连接配置
    #[serde(default)]
    pub controller: ControllerConfig,
}

/// Agent 模式配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// 是否启用 Agent 模式
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// 节点名称（默认使用 hostname）
    #[serde(default)]
    pub name: Option<String>,
    /// 区域/机房标识
    #[serde(default)]
    pub region: Option<String>,
    /// 心跳间隔（秒）
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// WebSocket 断线重连间隔（秒）
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,
    /// 局域网自动发现扫描端口列表
    #[serde(default = "default_scan_ports")]
    pub scan_ports: Vec<u16>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: None,
            region: None,
            heartbeat_interval_secs: 5,
            reconnect_interval_secs: 3,
            scan_ports: vec![5566, 8080, 80, 8000, 3000],
        }
    }
}

/// 全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// 日志级别（debug / info / warn / error）
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 工作目录（默认使用二进制同级目录）
    #[serde(default)]
    pub work_dir: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            work_dir: None,
        }
    }
}

/// serve 模式 HTTP 服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址
    #[serde(default = "default_host")]
    pub host: String,
    /// 监听端口
    #[serde(default = "default_port")]
    pub port: u16,
    /// 是否启用 serve 模式
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6881,
            enabled: true,
        }
    }
}

/// 发现机制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// 是否启用 Tracker 发现
    #[serde(default = "default_true")]
    pub enable_tracker: bool,
    /// 是否启用 DHT 发现
    #[serde(default = "default_true")]
    pub enable_dht: bool,
    /// 是否启用 PEX 发现
    #[serde(default = "default_false")]
    pub enable_pex: bool,
    /// 发现超时（秒）
    #[serde(default = "default_discover_timeout")]
    pub timeout_secs: u64,
    /// 最大并发发现器数
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_discoverers: usize,
    /// 缓存最大 peer 数
    #[serde(default = "default_max_cached")]
    pub max_cached_peers: usize,
    /// 缓存过期时间（秒）
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_tracker: true,
            enable_dht: true,
            enable_pex: false,
            timeout_secs: 10,
            max_concurrent_discoverers: 3,
            max_cached_peers: 10000,
            cache_ttl_secs: 86400,
        }
    }
}

/// 主控连接配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// 主控地址（如 http://127.0.0.1:5566）
    #[serde(default)]
    pub master: Option<String>,
    /// 认证 Token
    #[serde(default)]
    pub token: Option<String>,
    /// 是否自动发现局域网内的主控
    #[serde(default = "default_true")]
    pub auto_discover_master: bool,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            master: None,
            token: None,
            auto_discover_master: true,
        }
    }
}

// ─── 默认值函数 ───

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_heartbeat_interval() -> u64 {
    5
}
fn default_reconnect_interval() -> u64 {
    3
}
fn default_scan_ports() -> Vec<u16> {
    vec![5566, 8080, 80, 8000, 3000]
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    6881
}
fn default_discover_timeout() -> u64 {
    10
}
fn default_max_concurrent() -> usize {
    3
}
fn default_max_cached() -> usize {
    10000
}
fn default_cache_ttl() -> u64 {
    86400
}

impl PdcConfig {
    /// 生成默认配置
    pub fn default_config() -> Self {
        Self {
            agent: AgentConfig::default(),
            global: GlobalConfig::default(),
            server: ServerConfig::default(),
            discovery: DiscoveryConfig::default(),
            controller: ControllerConfig::default(),
        }
    }

    /// 从 YAML 文件加载配置
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let config: PdcConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        Ok(config)
    }

    /// 保存配置到 YAML 文件
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    /// 序列化为 YAML 字符串
    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// 获取能力标识列表
    pub fn capability_tags(&self) -> Vec<String> {
        let mut caps = Vec::new();
        if self.discovery.enable_tracker {
            caps.push("tracker".to_string());
        }
        if self.discovery.enable_dht {
            caps.push("dht".to_string());
        }
        if self.discovery.enable_pex {
            caps.push("pex".to_string());
        }
        caps.push("cache".to_string());
        caps.push("announce".to_string());
        caps.push("priority_sorting".to_string());
        caps.push("dedup".to_string());
        caps.push("health_check".to_string());
        caps
    }
}

/// 解析工作目录
pub fn resolve_work_dir(explicit: Option<&str>) -> PathBuf {
    if let Some(dir) = explicit {
        return PathBuf::from(dir);
    }
    // 默认使用二进制同级目录下的 pdc-node/
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.join("pdc-node");
        }
    }
    PathBuf::from("pdc-node")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes() {
        let config = PdcConfig::default_config();
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("agent:"));
        assert!(yaml.contains("server:"));
        assert!(yaml.contains("discovery:"));
    }

    #[test]
    fn capability_tags_includes_enabled() {
        let config = PdcConfig::default_config();
        let caps = config.capability_tags();
        assert!(caps.contains(&"tracker".to_string()));
        assert!(caps.contains(&"dht".to_string()));
        assert!(caps.contains(&"cache".to_string()));
        // PEX 默认关闭
        assert!(!caps.contains(&"pex".to_string()));
    }

    #[test]
    fn config_round_trip() {
        let config = PdcConfig::default_config();
        let yaml = config.to_yaml().unwrap();
        let back: PdcConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.server.port, 6881);
        assert_eq!(back.discovery.max_cached_peers, 10000);
    }
}
