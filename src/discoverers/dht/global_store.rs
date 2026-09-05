//! 全局节点池（多虚拟节点共享）
//!
//! 所有虚拟节点共享一个全局节点存储，避免重复存储同一节点。
//! 节点按距离组织，支持按任意目标 ID 查询最近节点。
//!
//! 设计：
//! - 全局节点池存储所有发现的 DHT 节点（去重，按地址）
//! - 支持按任意目标 ID 查询最近 N 个节点（不依赖特定路由表的 own_id）
//! - 支持节点健康状态管理、过期清理
//! - 内存优化：CompactAddr + u32 时间戳 + u8 失败计数

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use rand::Rng;

use super::routing_table::{CompactAddr, distance_less, xor_distance};

/// 全局节点池中的节点条目
#[derive(Debug, Clone)]
pub struct GlobalNodeEntry {
    /// 节点 ID
    pub id: [u8; 20],
    /// 节点地址
    pub addr: CompactAddr,
    /// 最后活跃时间（秒级时间戳）
    pub last_seen: u32,
    /// 连续失败次数
    pub failures: u8,
    /// 首次发现时间（秒级时间戳）
    pub first_seen: u32,
}

impl GlobalNodeEntry {
    /// 是否健康
    pub fn is_healthy(&self) -> bool {
        self.failures < 3
    }

    /// 是否过期（超过 TTL）
    pub fn is_expired(&self, now: u32, ttl_secs: u32) -> bool {
        now.saturating_sub(self.last_seen) > ttl_secs
    }
}

/// 全局节点池
///
/// 所有虚拟节点共享，存储全网发现的 DHT 节点。
pub struct GlobalNodeStore {
    /// 地址 -> 节点条目
    nodes: HashMap<CompactAddr, GlobalNodeEntry>,
    /// 启动时间
    started_at: Instant,
    /// 节点 TTL（秒）
    node_ttl_secs: u32,
}

impl GlobalNodeStore {
    /// 创建新的全局节点池
    pub fn new(node_ttl_secs: u32) -> Self {
        GlobalNodeStore {
            nodes: HashMap::new(),
            started_at: Instant::now(),
            node_ttl_secs,
        }
    }

    /// 当前时间戳
    fn now_secs(&self) -> u32 {
        self.started_at.elapsed().as_secs() as u32
    }

    /// 总节点数
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// 插入或更新节点
    pub fn insert(&mut self, id: [u8; 20], addr: CompactAddr) {
        let now = self.now_secs();
        if let Some(existing) = self.nodes.get_mut(&addr) {
            existing.id = id;
            existing.last_seen = now;
            existing.failures = 0;
        } else {
            self.nodes.insert(
                addr,
                GlobalNodeEntry {
                    id,
                    addr,
                    last_seen: now,
                    failures: 0,
                    first_seen: now,
                },
            );
        }
    }

    /// 标记节点成功（更新最后活跃时间）
    pub fn mark_success(&mut self, addr: &CompactAddr) {
        let now = self.now_secs();
        if let Some(node) = self.nodes.get_mut(addr) {
            node.last_seen = now;
            node.failures = 0;
        }
    }

    /// 标记节点失败
    pub fn mark_failure(&mut self, addr: &CompactAddr) {
        if let Some(node) = self.nodes.get_mut(addr) {
            node.failures = node.failures.saturating_add(1);
        }
    }

    /// 移除节点
    pub fn remove(&mut self, addr: &CompactAddr) -> bool {
        self.nodes.remove(addr).is_some()
    }

    /// 查找距离目标最近的 N 个健康节点
    pub fn find_closest(&self, target: &[u8; 20], count: usize) -> Vec<GlobalNodeEntry> {
        let mut all: Vec<&GlobalNodeEntry> = self
            .nodes
            .values()
            .filter(|n| n.is_healthy())
            .collect();

        all.sort_by(|a, b| {
            let da = xor_distance(&a.id, target);
            let db = xor_distance(&b.id, target);
            if distance_less(&da, &db) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        all.into_iter().take(count).cloned().collect()
    }

    /// 获取所有健康节点
    pub fn healthy_nodes(&self) -> Vec<GlobalNodeEntry> {
        self.nodes.values().filter(|n| n.is_healthy()).cloned().collect()
    }

    /// 获取所有节点
    pub fn all_nodes(&self) -> Vec<GlobalNodeEntry> {
        self.nodes.values().cloned().collect()
    }

    /// 清理过期和不健康节点，返回清理数量
    pub fn evict_expired(&mut self) -> usize {
        let now = self.now_secs();
        let before = self.nodes.len();
        self.nodes
            .retain(|_, n| n.is_healthy() && !n.is_expired(now, self.node_ttl_secs));
        before - self.nodes.len()
    }

    /// 内存估算（字节）
    pub fn estimated_memory(&self) -> usize {
        // HashMap 开销 ~48B/entry + GlobalNodeEntry ~40B
        self.nodes.len() * 88
    }
}

impl Default for GlobalNodeStore {
    fn default() -> Self {
        Self::new(3600)
    }
}

// ---------------------------------------------------------------------------
// 多虚拟节点管理器
// ---------------------------------------------------------------------------

/// 多虚拟节点管理器
///
/// 管理 N 个逻辑 DHT 节点，每个有独立的 node_id，共享全局节点池和 UDP socket。
/// 收到消息时选择最近的虚拟节点响应，发送时选择最近的虚拟节点作为发送方。
pub struct MultiNodeManager {
    /// 虚拟节点 ID 列表
    node_ids: Vec<[u8; 20]>,
    /// 全局节点池（共享）
    global_store: Arc<RwLock<GlobalNodeStore>>,
}

impl MultiNodeManager {
    /// 创建多虚拟节点管理器
    ///
    /// # 参数
    /// - `virtual_node_count`: 虚拟节点数量（建议 512）
    /// - `node_ttl_secs`: 节点 TTL（秒）
    pub fn new(virtual_node_count: usize, node_ttl_secs: u32) -> Self {
        let mut node_ids = Vec::with_capacity(virtual_node_count);
        for _ in 0..virtual_node_count {
            let mut id = [0u8; 20];
            rand::thread_rng().fill(&mut id);
            node_ids.push(id);
        }

        MultiNodeManager {
            node_ids,
            global_store: Arc::new(RwLock::new(GlobalNodeStore::new(node_ttl_secs))),
        }
    }

    /// 虚拟节点数量
    pub fn node_count(&self) -> usize {
        self.node_ids.len()
    }

    /// 获取所有虚拟节点 ID
    pub fn node_ids(&self) -> &[[u8; 20]] {
        &self.node_ids
    }

    /// 获取主节点 ID（第一个）
    pub fn primary_id(&self) -> &[u8; 20] {
        &self.node_ids[0]
    }

    /// 选择距离目标最近的虚拟节点 ID
    pub fn select_closest_node(&self, target: &[u8; 20]) -> &[u8; 20] {
        let mut best = &self.node_ids[0];
        let mut best_dist = xor_distance(best, target);

        for id in &self.node_ids[1..] {
            let dist = xor_distance(id, target);
            if distance_less(&dist, &best_dist) {
                best = id;
                best_dist = dist;
            }
        }
        best
    }

    /// 获取全局节点池引用
    pub fn global_store(&self) -> Arc<RwLock<GlobalNodeStore>> {
        self.global_store.clone()
    }

    /// 将节点加入全局池
    pub fn add_node(&self, id: [u8; 20], addr: CompactAddr) {
        self.global_store.write().insert(id, addr);
    }

    /// 从全局池查找最近节点
    pub fn find_closest(&self, target: &[u8; 20], count: usize) -> Vec<GlobalNodeEntry> {
        self.global_store.read().find_closest(target, count)
    }

    /// 全局池节点数
    pub fn global_node_count(&self) -> usize {
        self.global_store.read().len()
    }

    /// 维护（清理过期节点）
    pub fn maintenance(&self) -> usize {
        self.global_store.write().evict_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(i: u8) -> CompactAddr {
        CompactAddr::V4([127, 0, 0, i, 0x1A, 0xE1])
    }

    fn make_id(prefix: u8) -> [u8; 20] {
        let mut id = [0u8; 20];
        id[0] = prefix;
        id
    }

    #[test]
    fn test_global_store_insert_and_find() {
        let mut store = GlobalNodeStore::new(3600);

        for i in 1..=10u8 {
            store.insert(make_id(i), make_addr(i));
        }
        assert_eq!(store.len(), 10);

        let closest = store.find_closest(&make_id(5), 3);
        assert_eq!(closest.len(), 3);
        assert_eq!(closest[0].id[0], 5);
    }

    #[test]
    fn test_global_store_insert_update() {
        let mut store = GlobalNodeStore::new(3600);
        let addr = make_addr(1);

        store.insert(make_id(1), addr);
        store.insert(make_id(2), addr); // 同地址，更新 ID

        assert_eq!(store.len(), 1);
        let nodes = store.all_nodes();
        assert_eq!(nodes[0].id[0], 2);
    }

    #[test]
    fn test_global_store_mark_failure() {
        let mut store = GlobalNodeStore::new(3600);
        let addr = make_addr(1);
        store.insert(make_id(1), addr);

        for _ in 0..3 {
            store.mark_failure(&addr);
        }

        let healthy = store.healthy_nodes();
        assert!(healthy.is_empty());
    }

    #[test]
    fn test_global_store_evict() {
        let mut store = GlobalNodeStore::new(3600);
        for i in 1..=5u8 {
            store.insert(make_id(i), make_addr(i));
        }
        // 标记 3 个为不健康
        for i in 1..=3u8 {
            for _ in 0..3 {
                store.mark_failure(&make_addr(i));
            }
        }

        let evicted = store.evict_expired();
        assert_eq!(evicted, 3);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_multi_node_manager() {
        let manager = MultiNodeManager::new(512, 3600);
        assert_eq!(manager.node_count(), 512);

        // 所有节点 ID 应该唯一
        let mut ids = manager.node_ids().to_vec();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 512);
    }

    #[test]
    fn test_multi_node_select_closest() {
        let manager = MultiNodeManager::new(512, 3600);
        let target = [0xFFu8; 20];
        let selected = manager.select_closest_node(&target);

        // 选中的节点应该比主节点更接近目标
        let primary_dist = xor_distance(manager.primary_id(), &target);
        let selected_dist = xor_distance(selected, &target);
        assert!(!distance_less(&primary_dist, &selected_dist));
    }

    #[test]
    fn test_multi_node_global_store() {
        let manager = MultiNodeManager::new(16, 3600);

        for i in 1..=10u8 {
            manager.add_node(make_id(i), make_addr(i));
        }

        assert_eq!(manager.global_node_count(), 10);

        let closest = manager.find_closest(&make_id(5), 3);
        assert_eq!(closest.len(), 3);
        assert_eq!(closest[0].id[0], 5);
    }

    #[test]
    fn test_global_node_entry_health() {
        let entry = GlobalNodeEntry {
            id: [0u8; 20],
            addr: make_addr(1),
            last_seen: 100,
            failures: 0,
            first_seen: 0,
        };
        assert!(entry.is_healthy());
        assert!(!entry.is_expired(200, 3600));
        assert!(entry.is_expired(100 + 3601, 3600));
    }

    #[test]
    fn test_global_store_estimated_memory() {
        let mut store = GlobalNodeStore::new(3600);
        for i in 0..100u8 {
            store.insert(make_id(i), make_addr(i));
        }
        let mem = store.estimated_memory();
        assert!(mem > 0);
        assert!(mem < 100000); // 100 节点应该 < 100KB
    }
}
