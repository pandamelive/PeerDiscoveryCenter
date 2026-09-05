//! DHT 状态持久化
//!
//! 将路由表节点和 peer 存储持久化到磁盘，重启后快速恢复，
//! 避免冷启动时重新引导 DHT 网络。
//!
//! 持久化格式：JSON（简单可读，便于调试）
//! 持久化时机：定期（默认 5 分钟）+ 优雅关闭时

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::discoverers::dht::routing_table::{CompactAddr, RoutingTable};
use crate::discoverers::dht::store::DhtStore;

/// 持久化配置
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// 持久化文件路径
    pub path: PathBuf,
    /// 持久化间隔（秒）
    pub interval: u64,
    /// 是否启用
    pub enabled: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        PersistenceConfig {
            path: PathBuf::from("data/dht_state.json"),
            interval: 300, // 5 分钟
            enabled: true,
        }
    }
}

/// 持久化的 DHT 状态
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhtState {
    /// 路由表节点（node_id hex -> compact addr）
    pub routing_nodes: HashMap<String, String>,
    /// 已知的 peer（infohash hex -> peer 列表）
    pub peers: HashMap<String, Vec<String>>,
    /// 保存时间（Unix 时间戳）
    pub saved_at: u64,
}

/// DHT 持久化管理器
pub struct DhtPersistence {
    config: PersistenceConfig,
    last_save: Mutex<Option<Instant>>,
}

impl DhtPersistence {
    /// 创建新的持久化管理器
    pub fn new(config: PersistenceConfig) -> Self {
        DhtPersistence {
            config,
            last_save: Mutex::new(None),
        }
    }

    /// 检查是否需要保存（基于间隔）
    pub fn should_save(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let last = self.last_save.lock().unwrap();
        match *last {
            Some(t) => t.elapsed() >= Duration::from_secs(self.config.interval),
            None => true,
        }
    }

    /// 保存 DHT 状态到磁盘
    pub fn save(&self, routing_table: &RoutingTable, peer_store: &DhtStore) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut state = DhtState {
            saved_at: current_timestamp(),
            ..Default::default()
        };

        // 导出路由表节点
        for node in routing_table.all_nodes() {
            let id_hex = hex::encode(node.id);
            let addr_str = match node.addr {
                CompactAddr::V4(buf) => format!("v4:{}", hex::encode(buf)),
                CompactAddr::V6(buf) => format!("v6:{}", hex::encode(buf)),
            };
            state.routing_nodes.insert(id_hex, addr_str);
        }

        // 导出 peer 存储
        for infohash in peer_store.all_infohashes() {
            let peers = peer_store.get_peers(&infohash, 256);
            let ih_hex = hex::encode(infohash);
            let peer_strs: Vec<String> = peers
                .iter()
                .map(|p| {
                    let addr = p.to_socket();
                    format!("{}:{}", addr.ip(), addr.port())
                })
                .collect();
            state.peers.insert(ih_hex, peer_strs);
        }

        // 确保目录存在
        if let Some(parent) = self.config.path.parent() {
            std::fs::create_dir_all(parent).context("创建持久化目录失败")?;
        }

        // 写入文件（原子写入：先写临时文件再 rename）
        let tmp_path = self.config.path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&state).context("序列化 DHT 状态失败")?;
        std::fs::write(&tmp_path, json).context("写入临时文件失败")?;
        std::fs::rename(&tmp_path, &self.config.path).context("重命名持久化文件失败")?;

        *self.last_save.lock().unwrap() = Some(Instant::now());
        info!(
            "[persistence] 已保存 DHT 状态: {} 节点, {} infohash",
            state.routing_nodes.len(),
            state.peers.len()
        );
        Ok(())
    }

    /// 从磁盘加载 DHT 状态
    pub fn load(&self) -> Result<DhtState> {
        if !self.config.enabled {
            return Ok(DhtState::default());
        }

        if !self.config.path.exists() {
            debug!("[persistence] 无持久化文件，冷启动");
            return Ok(DhtState::default());
        }

        let json = std::fs::read_to_string(&self.config.path).context("读取持久化文件失败")?;
        let state: DhtState = serde_json::from_str(&json).context("解析持久化文件失败")?;

        info!(
            "[persistence] 已加载 DHT 状态: {} 节点, {} infohash (保存于 {})",
            state.routing_nodes.len(),
            state.peers.len(),
            state.saved_at
        );
        Ok(state)
    }

    /// 恢复状态到路由表和 peer 存储
    pub fn restore(
        &self,
        state: &DhtState,
        routing_table: &mut RoutingTable,
        peer_store: &mut DhtStore,
    ) -> Result<usize> {
        let mut restored = 0;

        // 恢复路由表节点
        for (id_hex, addr_str) in &state.routing_nodes {
            if let Ok(id_bytes) = hex::decode(id_hex) {
                if id_bytes.len() == 20 {
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&id_bytes);

                    let addr = if let Some(hex_str) = addr_str.strip_prefix("v4:") {
                        if let Ok(buf) = hex::decode(hex_str) {
                            if buf.len() == 6 {
                                let mut arr = [0u8; 6];
                                arr.copy_from_slice(&buf);
                                Some(CompactAddr::V4(arr))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else if let Some(hex_str) = addr_str.strip_prefix("v6:") {
                        if let Ok(buf) = hex::decode(hex_str) {
                            if buf.len() == 18 {
                                let mut arr = [0u8; 18];
                                arr.copy_from_slice(&buf);
                                Some(CompactAddr::V6(arr))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(addr) = addr {
                        let socket_addr = addr.to_socket();
                        routing_table.insert(id, CompactAddr::from(socket_addr));
                        restored += 1;
                    }
                }
            }
        }

        // 恢复 peer 存储
        for (ih_hex, peer_strs) in &state.peers {
            if let Ok(ih_bytes) = hex::decode(ih_hex) {
                if ih_bytes.len() == 20 {
                    let mut infohash = [0u8; 20];
                    infohash.copy_from_slice(&ih_bytes);

                    for peer_str in peer_strs {
                        if let Ok(addr) = peer_str.parse::<std::net::SocketAddr>() {
                            peer_store.announce(infohash, CompactAddr::from(addr));
                        }
                    }
                }
            }
        }

        debug!("[persistence] 恢复了 {} 个路由表节点", restored);
        Ok(restored)
    }

    /// 获取持久化文件路径
    pub fn path(&self) -> &Path {
        &self.config.path
    }
}

/// 当前 Unix 时间戳
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PersistenceConfig {
        PersistenceConfig {
            path: PathBuf::from("/tmp/test_dht_state.json"),
            interval: 1,
            enabled: true,
        }
    }

    #[test]
    fn test_config_default() {
        let config = PersistenceConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, 300);
    }

    #[test]
    fn test_state_serialize() {
        let mut state = DhtState::default();
        state.routing_nodes.insert(
            "0123456789abcdef0123456789abcdef01234567".to_string(),
            "v4:010203041ae0".to_string(),
        );
        state.peers.insert(
            "fedcba9876543210fedcba9876543210fedcba98".to_string(),
            vec!["1.2.3.4:6881".to_string()],
        );
        state.saved_at = 1700000000;

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("0123456789abcdef"));
        assert!(json.contains("1.2.3.4:6881"));

        let parsed: DhtState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.routing_nodes.len(), 1);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.saved_at, 1700000000);
    }

    #[test]
    fn test_should_save() {
        let persistence = DhtPersistence::new(test_config());
        assert!(persistence.should_save()); // 首次应该保存

        // 模拟已保存
        *persistence.last_save.lock().unwrap() = Some(Instant::now());
        assert!(!persistence.should_save()); // 刚保存过，不应该立即保存
    }

    #[test]
    fn test_disabled() {
        let config = PersistenceConfig {
            enabled: false,
            ..test_config()
        };
        let persistence = DhtPersistence::new(config);
        assert!(!persistence.should_save());
    }
}
