//! Kademlia k-bucket 路由表（BEP 5 + BEP 42）
//!
//! 实现：
//! - 160 桶 k-bucket（k=20），支持桶分裂
//! - LRU 淘汰（最久未活跃的节点优先淘汰）
//! - 数据结构压缩（CompactAddr 6B/18B、u32 时间戳、u8 失败计数）
//! - BEP 42 DHT 安全（node ID IP 约束，防 sybil 攻击）
//!
//! # BEP 42 算法
//! 对 IPv4 地址，计算 `r = crc32(ip & 0x030f3fff)`，
//! node ID 的前 21 位必须等于 r 的前 21 位，第 22-23 位为 class（可随机），
//! 其余位随机。验证时检查前 21 位是否匹配。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rand::Rng;

/// k-bucket 大小（每个桶最多节点数）
pub const K: usize = 20;

/// 桶数量上限（160 位 node ID）
pub const MAX_BUCKETS: usize = 160;

/// 节点过期时间（秒）
pub const NODE_TTL_SECS: u32 = 3600;

/// 连续失败次数上限（超过则标记为不健康）
pub const MAX_FAILURES: u8 = 3;

// ---------------------------------------------------------------------------
// 压缩地址
// ---------------------------------------------------------------------------

/// 压缩地址（IPv4 6B，IPv6 18B）
///
/// 比 `SocketAddr`（~28B 含 enum tag + padding）节省约 60% 内存。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompactAddr {
    /// IPv4: 4B IP + 2B port（大端）
    V4([u8; 6]),
    /// IPv6: 16B IP + 2B port（大端）
    V6([u8; 18]),
}

impl CompactAddr {
    /// 从 SocketAddr 创建
    pub fn from_socket(addr: &SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(ip) => {
                let mut buf = [0u8; 6];
                buf[0..4].copy_from_slice(&ip.octets());
                buf[4..6].copy_from_slice(&addr.port().to_be_bytes());
                CompactAddr::V4(buf)
            }
            IpAddr::V6(ip) => {
                let mut buf = [0u8; 18];
                buf[0..16].copy_from_slice(&ip.octets());
                buf[16..18].copy_from_slice(&addr.port().to_be_bytes());
                CompactAddr::V6(buf)
            }
        }
    }

    /// 转换为 SocketAddr
    pub fn to_socket(&self) -> SocketAddr {
        match self {
            CompactAddr::V4(buf) => {
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            CompactAddr::V6(buf) => {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[0..16]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
        }
    }

    /// 获取 IP 地址
    pub fn ip(&self) -> IpAddr {
        match self {
            CompactAddr::V4(buf) => IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
            CompactAddr::V6(buf) => {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[0..16]);
                IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes))
            }
        }
    }

    /// 获取端口
    pub fn port(&self) -> u16 {
        match self {
            CompactAddr::V4(buf) => u16::from_be_bytes([buf[4], buf[5]]),
            CompactAddr::V6(buf) => u16::from_be_bytes([buf[16], buf[17]]),
        }
    }

    /// 是否为 IPv4
    pub fn is_ipv4(&self) -> bool {
        matches!(self, CompactAddr::V4(_))
    }
}

impl From<SocketAddr> for CompactAddr {
    fn from(addr: SocketAddr) -> Self {
        CompactAddr::from_socket(&addr)
    }
}

impl From<&SocketAddr> for CompactAddr {
    fn from(addr: &SocketAddr) -> Self {
        CompactAddr::from_socket(addr)
    }
}

// ---------------------------------------------------------------------------
// 路由表节点
// ---------------------------------------------------------------------------

/// 路由表中的节点（压缩表示）
///
/// 比原 `RoutingNode`（~60B：id 20B + SocketAddr 28B + Instant 16B + u32 + bool + padding）
/// 节省约 50% 内存。
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// 节点 ID（20 字节，完整保留，路由表需要计算距离）
    pub id: [u8; 20],
    /// 节点地址（压缩表示）
    pub addr: CompactAddr,
    /// 最后活跃时间（秒级时间戳，从路由表启动时计算）
    pub last_seen: u32,
    /// 连续失败次数
    pub failures: u8,
}

impl RoutingEntry {
    /// 是否健康（连续失败次数 < 上限）
    pub fn is_healthy(&self) -> bool {
        self.failures < MAX_FAILURES
    }

    /// 是否过期（超过 TTL 未活跃）
    pub fn is_expired(&self, now: u32) -> bool {
        now.saturating_sub(self.last_seen) > NODE_TTL_SECS
    }
}

// ---------------------------------------------------------------------------
// BEP 42: node ID IP 约束
// ---------------------------------------------------------------------------

/// BEP 42: 为 IPv4 地址生成符合约束的 node ID
///
/// 前 21 位 = crc32(ip & 0x030f3fff) 的前 21 位，
/// 第 22-23 位为 class（随机），其余位随机。
pub fn generate_node_id_v4(ip: Ipv4Addr) -> [u8; 20] {
    let octets = ip.octets();
    // IPv4 mask: 0x030f3fff（大端）
    let masked = [
        octets[0] & 0x03,
        octets[1] & 0x0f,
        octets[2] & 0x3f,
        octets[3],
    ];
    let r = crc32(&masked);
    let mut id = [0u8; 20];
    rand::thread_rng().fill(&mut id);
    // 前 8 位
    id[0] = (r >> 24) as u8;
    // 第 9-16 位
    id[1] = (r >> 16) as u8;
    // 第 17-21 位（高 5 位）匹配，低 3 位（class + 随机）保留
    id[2] = (id[2] & 0x07) | (((r >> 11) as u8) & 0xf8);
    id
}

/// BEP 42: 验证 node ID 是否与 IPv4 地址匹配
///
/// 检查前 21 位是否等于 crc32(ip & mask) 的前 21 位。
pub fn verify_node_id_v4(id: &[u8; 20], ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let masked = [
        octets[0] & 0x03,
        octets[1] & 0x0f,
        octets[2] & 0x3f,
        octets[3],
    ];
    let r = crc32(&masked);
    id[0] == (r >> 24) as u8
        && id[1] == (r >> 16) as u8
        && (id[2] & 0xf8) == ((r >> 11) as u8 & 0xf8)
}

/// BEP 42: 为任意 IP 地址生成符合约束的 node ID
///
/// IPv6 使用 mask 0x0103070f1f3f7fff（前 8 字节），
/// 但当前主要支持 IPv4，IPv6 退化为随机 ID。
pub fn generate_node_id(ip: IpAddr) -> [u8; 20] {
    match ip {
        IpAddr::V4(v4) => generate_node_id_v4(v4),
        IpAddr::V6(_) => {
            // IPv6 BEP 42 暂未实现，使用随机 ID
            let mut id = [0u8; 20];
            rand::thread_rng().fill(&mut id);
            id
        }
    }
}

/// BEP 42: 验证 node ID 是否与任意 IP 地址匹配
pub fn verify_node_id(id: &[u8; 20], addr: &CompactAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => verify_node_id_v4(id, v4),
        IpAddr::V6(_) => true, // IPv6 暂不验证
    }
}

/// 标准 CRC32（IEEE 802.3）实现
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// XOR 距离工具
// ---------------------------------------------------------------------------

/// 计算两个 20 字节 ID 的 XOR 距离
#[inline]
pub fn xor_distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut result = [0u8; 20];
    for i in 0..20 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// 比较两个距离，返回 true 如果 a < b（字典序）
#[inline]
pub fn distance_less(a: &[u8; 20], b: &[u8; 20]) -> bool {
    for i in 0..20 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// 计算两个 ID 共同前缀长度（0-160）
#[inline]
pub fn common_prefix_len(a: &[u8; 20], b: &[u8; 20]) -> usize {
    let dist = xor_distance(a, b);
    let mut len = 0;
    for byte in &dist {
        if *byte == 0 {
            len += 8;
        } else {
            len += byte.leading_zeros() as usize;
            break;
        }
    }
    len
}

// ---------------------------------------------------------------------------
// k-bucket
// ---------------------------------------------------------------------------

/// 单个 k-bucket
struct KBucket {
    /// 桶覆盖的共同前缀长度（0 = 覆盖全部 ID 空间）
    prefix_len: usize,
    /// 桶内节点（按 last_seen 升序，最久未活跃的在前面）
    entries: Vec<RoutingEntry>,
}

impl KBucket {
    /// 创建新桶
    fn new(prefix_len: usize) -> Self {
        KBucket {
            prefix_len,
            entries: Vec::with_capacity(K),
        }
    }

    /// 桶是否已满
    fn is_full(&self) -> bool {
        self.entries.len() >= K
    }

    /// 查找节点（按地址）
    fn find(&self, addr: &CompactAddr) -> Option<usize> {
        self.entries.iter().position(|e| e.addr == *addr)
    }

    /// 插入节点（保持按 last_seen 升序）
    ///
    /// 返回：Ok(()) 插入成功，Err(()) 桶已满且无法替换
    fn insert(&mut self, entry: RoutingEntry) -> Result<(), ()> {
        // 如果已存在，更新
        if let Some(idx) = self.find(&entry.addr) {
            self.entries[idx] = entry;
            self.entries.sort_by_key(|e| e.last_seen);
            return Ok(());
        }
        // 桶未满，直接插入
        if !self.is_full() {
            self.entries.push(entry);
            self.entries.sort_by_key(|e| e.last_seen);
            return Ok(());
        }
        // 桶已满：尝试替换最久未活跃的不健康/过期节点
        if let Some(idx) = self
            .entries
            .iter()
            .position(|e| !e.is_healthy() || e.is_expired(entry.last_seen))
        {
            self.entries[idx] = entry;
            self.entries.sort_by_key(|e| e.last_seen);
            return Ok(());
        }
        Err(())
    }

    /// 移除节点
    fn remove(&mut self, addr: &CompactAddr) -> Option<RoutingEntry> {
        if let Some(idx) = self.find(addr) {
            Some(self.entries.remove(idx))
        } else {
            None
        }
    }

    /// 更新节点最后活跃时间
    fn touch(&mut self, addr: &CompactAddr, now: u32) -> bool {
        if let Some(idx) = self.find(addr) {
            self.entries[idx].last_seen = now;
            self.entries[idx].failures = 0;
            self.entries.sort_by_key(|e| e.last_seen);
            true
        } else {
            false
        }
    }

    /// 标记节点失败
    fn mark_failed(&mut self, addr: &CompactAddr) -> bool {
        if let Some(idx) = self.find(addr) {
            self.entries[idx].failures = self.entries[idx].failures.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// 清理过期和不健康节点
    fn evict(&mut self, now: u32) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.is_healthy() && !e.is_expired(now));
        before - self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// 路由表
// ---------------------------------------------------------------------------

/// Kademlia k-bucket 路由表
///
/// 维护 160 位 ID 空间的桶划分，支持动态分裂。
/// 自己的 node ID 所在路径上的桶可以无限分裂，
/// 其他桶保持不分裂（标准 Kademlia 行为）。
pub struct RoutingTable {
    /// 自己的 node ID
    own_id: [u8; 20],
    /// 桶列表（按 prefix_len 排序，前缀越长覆盖范围越小）
    buckets: Vec<KBucket>,
    /// 启动时间（用于 u32 时间戳转换）
    started_at: Instant,
    /// 总节点数（缓存，避免每次遍历）
    total_nodes: usize,
}

impl RoutingTable {
    /// 创建新路由表
    pub fn new(own_id: [u8; 20]) -> Self {
        let mut buckets = Vec::with_capacity(16);
        buckets.push(KBucket::new(0)); // 初始一个覆盖全部的桶
        RoutingTable {
            own_id,
            buckets,
            started_at: Instant::now(),
            total_nodes: 0,
        }
    }

    /// 获取自己的 node ID
    pub fn own_id(&self) -> &[u8; 20] {
        &self.own_id
    }

    /// 当前时间戳（秒级，从启动时计算）
    fn now_secs(&self) -> u32 {
        self.started_at.elapsed().as_secs() as u32
    }

    /// 将时间戳转换为 Instant
    pub fn timestamp_to_instant(&self, ts: u32) -> Instant {
        self.started_at + Duration::from_secs(ts as u64)
    }

    /// 总节点数
    pub fn len(&self) -> usize {
        self.total_nodes
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.total_nodes == 0
    }

    /// 桶数量
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// 找到目标 ID 所属的桶索引
    fn find_bucket(&self, target: &[u8; 20]) -> usize {
        // 找到 prefix_len 最大且包含目标的桶
        let target_prefix = common_prefix_len(&self.own_id, target);
        for (i, bucket) in self.buckets.iter().enumerate() {
            if bucket.prefix_len <= target_prefix {
                // 检查目标是否真的在这个桶的范围内
                // 桶的范围由 own_id 和 prefix_len 决定
                if self.bucket_contains(i, target) {
                    return i;
                }
            }
        }
        // 兜底：返回第一个桶
        0
    }

    /// 检查桶是否包含目标 ID
    fn bucket_contains(&self, bucket_idx: usize, target: &[u8; 20]) -> bool {
        let bucket = &self.buckets[bucket_idx];
        if bucket.prefix_len == 0 {
            return true; // 根桶包含全部
        }
        // 检查目标与 own_id 的共同前缀是否 >= bucket.prefix_len
        common_prefix_len(&self.own_id, target) >= bucket.prefix_len
    }

    /// 分裂指定桶（只能分裂包含 own_id 的桶）
    fn split_bucket(&mut self, bucket_idx: usize) {
        let prefix_len = self.buckets[bucket_idx].prefix_len;
        // 只能分裂包含 own_id 的桶
        if !self.bucket_contains(bucket_idx, &self.own_id) {
            return;
        }
        if prefix_len >= MAX_BUCKETS - 1 {
            return; // 已达最大深度
        }

        let old_entries = std::mem::take(&mut self.buckets[bucket_idx].entries);
        let new_prefix = prefix_len + 1;

        // 新桶：与 own_id 前 new_prefix 位相同的节点
        let mut new_bucket = KBucket::new(new_prefix);
        // 旧桶保留：与 own_id 前 new_prefix 位不同的节点
        self.buckets[bucket_idx].prefix_len = new_prefix; // 旧桶也更新前缀（表示"另一半"）

        for entry in old_entries {
            if common_prefix_len(&self.own_id, &entry.id) >= new_prefix {
                new_bucket.entries.push(entry);
            } else {
                self.buckets[bucket_idx].entries.push(entry);
            }
        }

        // 插入新桶（保持按 prefix_len 排序）
        let insert_pos = self
            .buckets
            .iter()
            .position(|b| b.prefix_len > new_prefix)
            .unwrap_or(self.buckets.len());
        self.buckets.insert(insert_pos, new_bucket);
    }

    /// 插入节点
    ///
    /// 如果目标桶已满且包含 own_id，则分裂桶后重试；
    /// 否则尝试替换最久未活跃的不健康/过期节点。
    pub fn insert(&mut self, id: [u8; 20], addr: CompactAddr) -> bool {
        let now = self.now_secs();
        let entry = RoutingEntry {
            id,
            addr,
            last_seen: now,
            failures: 0,
        };
        self.insert_entry(entry)
    }

    /// 内部：插入 RoutingEntry
    fn insert_entry(&mut self, entry: RoutingEntry) -> bool {
        let bucket_idx = self.find_bucket(&entry.id);

        // 先尝试直接插入
        match self.buckets[bucket_idx].insert(entry.clone()) {
            Ok(()) => {
                self.total_nodes += 1;
                return true;
            }
            Err(()) => {
                // 桶已满，尝试分裂（如果包含 own_id）
                if self.bucket_contains(bucket_idx, &self.own_id) {
                    self.split_bucket(bucket_idx);
                    // 分裂后重新查找桶并插入
                    let new_idx = self.find_bucket(&entry.id);
                    if self.buckets[new_idx].insert(entry).is_ok() {
                        self.total_nodes += 1;
                        return true;
                    }
                }
            }
        }
        false
    }

    /// 移除节点
    pub fn remove(&mut self, addr: &CompactAddr) -> bool {
        for bucket in &mut self.buckets {
            if bucket.remove(addr).is_some() {
                self.total_nodes = self.total_nodes.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// 更新节点最后活跃时间（节点成功响应时调用）
    pub fn touch(&mut self, addr: &CompactAddr) -> bool {
        let now = self.now_secs();
        for bucket in &mut self.buckets {
            if bucket.touch(addr, now) {
                return true;
            }
        }
        false
    }

    /// 标记节点失败
    pub fn mark_failed(&mut self, addr: &CompactAddr) -> bool {
        for bucket in &mut self.buckets {
            if bucket.mark_failed(addr) {
                return true;
            }
        }
        false
    }

    /// 查找距离目标最近的 N 个健康节点
    pub fn find_closest(&self, target: &[u8; 20], count: usize) -> Vec<RoutingEntry> {
        // 收集所有健康节点
        let mut all: Vec<RoutingEntry> = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| e.is_healthy())
            .cloned()
            .collect();

        // 按 XOR 距离排序
        all.sort_by(|a, b| {
            let da = xor_distance(&a.id, target);
            let db = xor_distance(&b.id, target);
            if distance_less(&da, &db) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        all.truncate(count);
        all
    }

    /// 获取所有健康节点
    pub fn healthy_nodes(&self) -> Vec<RoutingEntry> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| e.is_healthy())
            .cloned()
            .collect()
    }

    /// 获取所有节点（包括不健康的）
    pub fn all_nodes(&self) -> Vec<RoutingEntry> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .cloned()
            .collect()
    }

    /// 清理过期和不健康节点，返回清理数量
    pub fn evict_expired(&mut self) -> usize {
        let now = self.now_secs();
        let mut evicted = 0;
        for bucket in &mut self.buckets {
            evicted += bucket.evict(now);
        }
        self.total_nodes = self.total_nodes.saturating_sub(evicted);
        evicted
    }

    /// 刷新路由表（对每个桶中最久未联系的节点发送 ping）
    ///
    /// 返回需要刷新的节点地址列表（调用方负责发送 ping）
    pub fn refresh_candidates(&self) -> Vec<CompactAddr> {
        let now = self.now_secs();
        let mut candidates = Vec::new();
        for bucket in &self.buckets {
            // 每个桶取最久未活跃的健康节点
            if let Some(oldest) = bucket
                .entries
                .iter()
                .find(|e| e.is_healthy() && now.saturating_sub(e.last_seen) > 300)
            {
                candidates.push(oldest.addr);
            }
        }
        candidates
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(i: u8) -> CompactAddr {
        CompactAddr::V4([127, 0, 0, i, 0x1A, 0xE1])
    }

    fn make_id(prefix: u8) -> [u8; 20] {
        let mut id = [0u8; 20];
        id[0] = prefix;
        id
    }

    #[test]
    fn test_compact_addr_v4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 6881);
        let compact = CompactAddr::from_socket(&addr);
        assert!(compact.is_ipv4());
        assert_eq!(compact.port(), 6881);
        let back = compact.to_socket();
        assert_eq!(back, addr);
    }

    #[test]
    fn test_compact_addr_v6() {
        let addr = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            6881,
        );
        let compact = CompactAddr::from_socket(&addr);
        assert!(!compact.is_ipv4());
        assert_eq!(compact.port(), 6881);
        let back = compact.to_socket();
        assert_eq!(back, addr);
    }

    #[test]
    fn test_bep42_generate_and_verify() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let id = generate_node_id_v4(ip);
        assert!(verify_node_id_v4(&id, ip));

        // 不同 IP 应该不匹配
        let other_ip = Ipv4Addr::new(10, 0, 0, 1);
        assert!(!verify_node_id_v4(&id, other_ip));
    }

    #[test]
    fn test_bep42_different_ips_give_different_ids() {
        let id1 = generate_node_id_v4(Ipv4Addr::new(192, 168, 1, 1));
        let id2 = generate_node_id_v4(Ipv4Addr::new(192, 168, 1, 2));
        // 前 21 位应该不同（因为 IP 不同）
        assert!(id1[0] != id2[0] || id1[1] != id2[1] || (id1[2] & 0xf8) != (id2[2] & 0xf8));
    }

    #[test]
    fn test_xor_distance() {
        let a = [0u8; 20];
        let b = [0xFFu8; 20];
        assert_eq!(xor_distance(&a, &b), [0xFFu8; 20]);
        assert_eq!(xor_distance(&a, &a), [0u8; 20]);
    }

    #[test]
    fn test_distance_less() {
        let a = [0u8; 20];
        let mut b = [0u8; 20];
        b[19] = 1;
        assert!(distance_less(&a, &b));
        assert!(!distance_less(&b, &a));
    }

    #[test]
    fn test_common_prefix_len() {
        let a = [0u8; 20];
        let mut b = [0u8; 20];
        assert_eq!(common_prefix_len(&a, &b), 160);
        b[0] = 0x80; // 最高位不同
        assert_eq!(common_prefix_len(&a, &b), 0);
        b[0] = 0x01; // 最低位不同
        assert_eq!(common_prefix_len(&a, &b), 7);
    }

    #[test]
    fn test_routing_table_insert_and_find() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        // 插入 10 个节点
        for i in 1..=10u8 {
            let id = make_id(i);
            let addr = make_addr(i);
            assert!(table.insert(id, addr));
        }
        assert_eq!(table.len(), 10);
        assert_eq!(table.bucket_count(), 1); // 还没满，不分裂

        // 查找最近的 3 个节点
        let target = [5u8; 20];
        let closest = table.find_closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // 最近的应该是 id=5
        assert_eq!(closest[0].id[0], 5);
    }

    #[test]
    fn test_routing_table_bucket_split() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        // 插入 K+1 个与 own_id 前缀相同的节点，触发分裂
        for i in 1..=21u8 {
            let mut id = [0u8; 20];
            id[19] = i; // 只有最后一字节不同，前缀完全相同
            let addr = make_addr(i);
            table.insert(id, addr);
        }

        // 应该发生了分裂
        assert!(table.bucket_count() > 1);
        assert_eq!(table.len(), 21);
    }

    #[test]
    fn test_routing_table_touch_and_fail() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        let addr = make_addr(1);
        table.insert(make_id(1), addr);

        // touch 应该成功
        assert!(table.touch(&addr));
        // 不存在的地址 touch 失败
        assert!(!table.touch(&make_addr(99)));

        // mark_failed
        assert!(table.mark_failed(&addr));
        assert!(!table.mark_failed(&make_addr(99)));
    }

    #[test]
    fn test_routing_table_remove() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        let addr = make_addr(1);
        table.insert(make_id(1), addr);
        assert_eq!(table.len(), 1);

        assert!(table.remove(&addr));
        assert_eq!(table.len(), 0);
        assert!(!table.remove(&addr)); // 重复删除失败
    }

    #[test]
    fn test_routing_table_evict() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        // 插入节点
        for i in 1..=5u8 {
            table.insert(make_id(i), make_addr(i));
        }
        assert_eq!(table.len(), 5);

        // 手动把节点标记为失败多次
        for i in 1..=3u8 {
            for _ in 0..MAX_FAILURES {
                table.mark_failed(&make_addr(i));
            }
        }

        // 清理应该移除 3 个不健康节点
        let evicted = table.evict_expired();
        assert_eq!(evicted, 3);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_routing_table_healthy_nodes() {
        let own_id = [0u8; 20];
        let mut table = RoutingTable::new(own_id);

        for i in 1..=5u8 {
            table.insert(make_id(i), make_addr(i));
        }
        // 标记 2 个为不健康
        for _ in 0..MAX_FAILURES {
            table.mark_failed(&make_addr(1));
            table.mark_failed(&make_addr(2));
        }

        let healthy = table.healthy_nodes();
        assert_eq!(healthy.len(), 3);
    }

    #[test]
    fn test_crc32_known_value() {
        // "123456789" 的标准 CRC32 = 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_routing_entry_health() {
        let entry = RoutingEntry {
            id: [0u8; 20],
            addr: make_addr(1),
            last_seen: 100,
            failures: 0,
        };
        assert!(entry.is_healthy());
        assert!(!entry.is_expired(200)); // 100秒前，未过期
        assert!(entry.is_expired(100 + NODE_TTL_SECS + 1)); // 超过TTL
    }
}
