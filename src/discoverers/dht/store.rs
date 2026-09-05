//! DHT Peer 存储层（BEP 5）
//!
//! 存储其他节点通过 announce_peer 上报的 peer 信息：
//! - infohash -> Vec<(CompactAddr, last_seen)>
//! - TTL 30 分钟（DHT announce 标准有效期）
//! - 支持插入、查询、过期清理
//! - 内存优化：CompactAddr（6B/18B）+ u32 时间戳

use super::routing_table::CompactAddr;
use crate::types::Infohash;
use std::collections::HashMap;
use std::time::Instant;

/// Peer 条目 TTL（秒）— DHT announce 标准有效期 30 分钟
pub const PEER_TTL_SECS: u32 = 1800;

/// 单个 infohash 最多存储的 peer 数
pub const MAX_PEERS_PER_INFOHASH: usize = 256;

/// 单个 peer 条目（压缩表示）
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// peer 地址
    pub addr: CompactAddr,
    /// 最后 announce 时间（秒级时间戳）
    pub last_seen: u32,
}

impl PeerEntry {
    /// 是否过期
    pub fn is_expired(&self, now: u32) -> bool {
        now.saturating_sub(self.last_seen) > PEER_TTL_SECS
    }
}

/// DHT Peer 存储层
///
/// 存储 announce_peer 上报的 peer，供 get_peers 查询返回。
pub struct DhtStore {
    /// infohash -> peer 列表
    peers: HashMap<Infohash, Vec<PeerEntry>>,
    /// 启动时间（用于 u32 时间戳转换）
    started_at: Instant,
    /// 总 peer 数（缓存）
    total_peers: usize,
    /// 总 infohash 数（缓存）
    total_infohashes: usize,
}

impl DhtStore {
    /// 创建新存储
    pub fn new() -> Self {
        DhtStore {
            peers: HashMap::new(),
            started_at: Instant::now(),
            total_peers: 0,
            total_infohashes: 0,
        }
    }

    /// 当前时间戳（秒级）
    fn now_secs(&self) -> u32 {
        self.started_at.elapsed().as_secs() as u32
    }

    /// 总 peer 数
    pub fn total_peers(&self) -> usize {
        self.total_peers
    }

    /// 总 infohash 数
    pub fn total_infohashes(&self) -> usize {
        self.total_infohashes
    }

    /// 插入/更新一个 peer（announce_peer 时调用）
    ///
    /// 如果 peer 已存在，更新 last_seen；否则插入。
    /// 超过 MAX_PEERS_PER_INFOHASH 时，淘汰最久未活跃的 peer。
    pub fn announce(&mut self, infohash: Infohash, addr: CompactAddr) {
        let now = self.now_secs();
        let entry = PeerEntry {
            addr,
            last_seen: now,
        };

        let list = self.peers.entry(infohash).or_default();

        // 已存在则更新
        if let Some(existing) = list.iter_mut().find(|e| e.addr == addr) {
            existing.last_seen = now;
            return;
        }

        // 新 peer
        if list.len() >= MAX_PEERS_PER_INFOHASH {
            // 淘汰最久未活跃的
            list.sort_by_key(|e| e.last_seen);
            list.remove(0);
            self.total_peers = self.total_peers.saturating_sub(1);
        }
        list.push(entry);
        self.total_peers += 1;
        if list.len() == 1 {
            self.total_infohashes += 1;
        }
    }

    /// 查询某个 infohash 的 peer（get_peers 时调用）
    ///
    /// 返回最多 `limit` 个未过期的 peer。
    pub fn get_peers(&self, infohash: &Infohash, limit: usize) -> Vec<CompactAddr> {
        let now = self.now_secs();
        self.peers
            .get(infohash)
            .map(|list| {
                list.iter()
                    .filter(|e| !e.is_expired(now))
                    .take(limit)
                    .map(|e| e.addr)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 查询某个 infohash 的 peer 数量（DHT scrape 时调用）
    pub fn peer_count(&self, infohash: &Infohash) -> usize {
        let now = self.now_secs();
        self.peers
            .get(infohash)
            .map(|list| list.iter().filter(|e| !e.is_expired(now)).count())
            .unwrap_or(0)
    }

    /// 清理过期 peer，返回清理数量
    pub fn evict_expired(&mut self) -> usize {
        let now = self.now_secs();
        let mut evicted = 0;
        let mut empty_infohashes = Vec::new();

        for (infohash, list) in self.peers.iter_mut() {
            let before = list.len();
            list.retain(|e| !e.is_expired(now));
            evicted += before - list.len();
            if list.is_empty() {
                empty_infohashes.push(*infohash);
            }
        }

        for ih in empty_infohashes {
            self.peers.remove(&ih);
            self.total_infohashes = self.total_infohashes.saturating_sub(1);
        }

        self.total_peers = self.total_peers.saturating_sub(evicted);
        evicted
    }

    /// 获取所有 infohash（用于爬虫索引/统计）
    pub fn all_infohashes(&self) -> Vec<Infohash> {
        self.peers.keys().copied().collect()
    }

    /// BEP 51: 随机采样 infohash（用于 sample_infohashes 响应）
    ///
    /// 返回最多 `max_samples` 个随机 infohash，以及总 infohash 数。
    pub fn sample_infohashes(&self, max_samples: usize) -> (Vec<Infohash>, usize) {
        use rand::seq::SliceRandom;
        let all: Vec<Infohash> = self.peers.keys().copied().collect();
        let total = all.len();
        if all.len() <= max_samples {
            return (all, total);
        }
        let mut rng = rand::thread_rng();
        let sample: Vec<Infohash> = all
            .choose_multiple(&mut rng, max_samples)
            .copied()
            .collect();
        (sample, total)
    }

    /// 内存估算（字节）
    pub fn estimated_memory(&self) -> usize {
        // HashMap 开销约 48B/entry + key 20B + Vec overhead 24B
        // 每个 PeerEntry 约 20B（CompactAddr 18B + u32 4B + padding）
        let hashmap_overhead = self.total_infohashes * (48 + 20 + 24);
        let peer_entries = self.total_peers * 20;
        hashmap_overhead + peer_entries
    }
}

impl Default for DhtStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(i: u8) -> CompactAddr {
        CompactAddr::V4([127, 0, 0, i, 0x1A, 0xE1])
    }

    #[test]
    fn test_store_announce_and_get() {
        let mut store = DhtStore::new();
        let ih = [1u8; 20];

        store.announce(ih, make_addr(1));
        store.announce(ih, make_addr(2));
        store.announce(ih, make_addr(3));

        assert_eq!(store.total_peers(), 3);
        assert_eq!(store.total_infohashes(), 1);

        let peers = store.get_peers(&ih, 10);
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn test_store_announce_update() {
        let mut store = DhtStore::new();
        let ih = [1u8; 20];

        store.announce(ih, make_addr(1));
        store.announce(ih, make_addr(1)); // 重复 announce，应更新而非新增

        assert_eq!(store.total_peers(), 1);
    }

    #[test]
    fn test_store_peer_count() {
        let mut store = DhtStore::new();
        let ih = [1u8; 20];

        store.announce(ih, make_addr(1));
        store.announce(ih, make_addr(2));

        assert_eq!(store.peer_count(&ih), 2);
        assert_eq!(store.peer_count(&[2u8; 20]), 0);
    }

    #[test]
    fn test_store_max_peers_per_infohash() {
        let mut store = DhtStore::new();
        let ih = [1u8; 20];

        for i in 0..(MAX_PEERS_PER_INFOHASH + 10) as u8 {
            store.announce(ih, make_addr(i));
        }

        // 应该被限制在 MAX_PEERS_PER_INFOHASH
        assert!(store.peer_count(&ih) <= MAX_PEERS_PER_INFOHASH);
    }

    #[test]
    fn test_store_get_peers_limit() {
        let mut store = DhtStore::new();
        let ih = [1u8; 20];

        for i in 1..=10u8 {
            store.announce(ih, make_addr(i));
        }

        let peers = store.get_peers(&ih, 3);
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn test_store_all_infohashes() {
        let mut store = DhtStore::new();
        store.announce([1u8; 20], make_addr(1));
        store.announce([2u8; 20], make_addr(2));
        store.announce([3u8; 20], make_addr(3));

        assert_eq!(store.all_infohashes().len(), 3);
    }

    #[test]
    fn test_store_estimated_memory() {
        let mut store = DhtStore::new();
        for i in 0..100u8 {
            store.announce([i; 20], make_addr(i));
        }
        let mem = store.estimated_memory();
        assert!(mem > 0);
        // 100 infohash * ~92B + 100 peer * 20B ≈ 11200B
        assert!(mem < 50000);
    }

    #[test]
    fn test_peer_entry_expired() {
        let entry = PeerEntry {
            addr: make_addr(1),
            last_seen: 100,
        };
        assert!(!entry.is_expired(200)); // 100秒前，未过期
        assert!(entry.is_expired(100 + PEER_TTL_SECS + 1)); // 超过TTL
    }
}
