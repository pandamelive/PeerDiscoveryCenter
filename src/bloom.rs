//! Bloom Filter（布隆过滤器）
//!
//! 用于爬虫去重：判断 infohash 是否已见过。
//! 空间效率极高（百万级 infohash 仅需几 MB），但有极小的假阳性率。
//!
//! 实现：
//! - 双重哈希法（用两个 64 位哈希组合生成 k 个哈希值）
//! - 可配置位数组大小和哈希函数数量
//! - 支持合并两个 BloomFilter

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Bloom Filter
pub struct BloomFilter {
    /// 位数组
    bits: Vec<u64>,
    /// 位数组总位数
    num_bits: usize,
    /// 哈希函数数量
    num_hashes: usize,
    /// 插入元素数量（估算）
    count: usize,
}

impl BloomFilter {
    /// 创建新的 BloomFilter
    ///
    /// # 参数
    /// - `expected_items`: 预期插入的元素数量
    /// - `false_positive_rate`: 期望的假阳性率（如 0.01 = 1%）
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        // 计算最优位数组大小：m = -n*ln(p) / (ln(2))^2
        let ln2 = std::f64::consts::LN_2;
        let num_bits = (-(expected_items as f64) * false_positive_rate.ln() / (ln2 * ln2)).ceil() as usize;
        let num_bits = num_bits.max(64); // 至少 64 位

        // 计算最优哈希函数数量：k = (m/n) * ln(2)
        let num_hashes = ((num_bits as f64 / expected_items as f64) * ln2).round() as usize;
        let num_hashes = num_hashes.max(2).min(20); // 2-20 个哈希函数

        let num_words = (num_bits + 63) / 64;
        BloomFilter {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
            count: 0,
        }
    }

    /// 计算两个基础哈希值
    fn hash_pair<T: Hash>(item: &T) -> (u64, u64) {
        let mut hasher1 = DefaultHasher::new();
        item.hash(&mut hasher1);
        let h1 = hasher1.finish();

        // 第二个哈希用不同的种子
        let mut hasher2 = DefaultHasher::new();
        (h1, 0x9E3779B97F4A7C15u64).hash(&mut hasher2);
        item.hash(&mut hasher2);
        let h2 = hasher2.finish();

        (h1, h2)
    }

    /// 插入元素
    pub fn insert<T: Hash>(&mut self, item: &T) {
        let (h1, h2) = Self::hash_pair(item);
        for i in 0..self.num_hashes {
            let hash = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (hash % self.num_bits as u64) as usize;
            let word_idx = bit_idx / 64;
            let bit_offset = bit_idx % 64;
            self.bits[word_idx] |= 1u64 << bit_offset;
        }
        self.count += 1;
    }

    /// 检查元素是否可能存在
    ///
    /// 返回 true 表示可能存在（有假阳性），返回 false 表示一定不存在。
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let (h1, h2) = Self::hash_pair(item);
        for i in 0..self.num_hashes {
            let hash = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (hash % self.num_bits as u64) as usize;
            let word_idx = bit_idx / 64;
            let bit_offset = bit_idx % 64;
            if self.bits[word_idx] & (1u64 << bit_offset) == 0 {
                return false;
            }
        }
        true
    }

    /// 插入并返回是否是新元素（false 表示可能已存在）
    pub fn insert_and_check<T: Hash>(&mut self, item: &T) -> bool {
        if self.contains(item) {
            false
        } else {
            self.insert(item);
            true
        }
    }

    /// 估算的假阳性率
    pub fn estimated_false_positive_rate(&self) -> f64 {
        let k = self.num_hashes as f64;
        let m = self.num_bits as f64;
        let n = self.count as f64;
        if n == 0.0 {
            return 0.0;
        }
        (1.0 - (-(k * n) / m).exp()).powf(k)
    }

    /// 插入元素数量
    pub fn len(&self) -> usize {
        self.count
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 位数组大小（字节）
    pub fn memory_usage(&self) -> usize {
        self.bits.len() * 8
    }

    /// 清空
    pub fn clear(&mut self) {
        for word in &mut self.bits {
            *word = 0;
        }
        self.count = 0;
    }

    /// 合并另一个 BloomFilter（按位或）
    pub fn merge(&mut self, other: &BloomFilter) {
        if self.num_bits != other.num_bits || self.num_hashes != other.num_hashes {
            return; // 参数不匹配，跳过
        }
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
        self.count += other.count;
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        // 默认：100 万元素，1% 假阳性率
        Self::new(1_000_000, 0.01)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_contains() {
        let mut bf = BloomFilter::new(1000, 0.01);
        let item = [1u8; 20];

        assert!(!bf.contains(&item));
        bf.insert(&item);
        assert!(bf.contains(&item));
    }

    #[test]
    fn test_insert_and_check() {
        let mut bf = BloomFilter::new(1000, 0.01);
        let item = [1u8; 20];

        assert!(bf.insert_and_check(&item)); // 新元素
        assert!(!bf.insert_and_check(&item)); // 已存在
    }

    #[test]
    fn test_false_positive_rate() {
        let mut bf = BloomFilter::new(10000, 0.01);

        // 插入 10000 个元素
        for i in 0..10000u32 {
            let mut item = [0u8; 20];
            item[0..4].copy_from_slice(&i.to_be_bytes());
            bf.insert(&item);
        }

        // 测试未插入的元素
        let mut false_positives = 0;
        let total = 1000;
        for i in 10000..11000u32 {
            let mut item = [0u8; 20];
            item[0..4].copy_from_slice(&i.to_be_bytes());
            if bf.contains(&item) {
                false_positives += 1;
            }
        }

        let rate = false_positives as f64 / total as f64;
        // 应该接近 1%，允许一定波动
        assert!(rate < 0.05, "假阳性率过高: {}", rate);
    }

    #[test]
    fn test_memory_usage() {
        let bf = BloomFilter::new(1_000_000, 0.01);
        // 100 万元素 1% 假阳性率约需 1.2MB
        assert!(bf.memory_usage() > 100_000); // > 100KB
        assert!(bf.memory_usage() < 5_000_000); // < 5MB
    }

    #[test]
    fn test_clear() {
        let mut bf = BloomFilter::new(1000, 0.01);
        bf.insert(&[1u8; 20]);
        assert_eq!(bf.len(), 1);

        bf.clear();
        assert_eq!(bf.len(), 0);
        assert!(!bf.contains(&[1u8; 20]));
    }

    #[test]
    fn test_merge() {
        let mut bf1 = BloomFilter::new(1000, 0.01);
        let mut bf2 = BloomFilter::new(1000, 0.01);

        bf1.insert(&[1u8; 20]);
        bf2.insert(&[2u8; 20]);

        bf1.merge(&bf2);

        assert!(bf1.contains(&[1u8; 20]));
        assert!(bf1.contains(&[2u8; 20]));
    }

    #[test]
    fn test_default() {
        let bf = BloomFilter::default();
        assert!(bf.is_empty());
        assert!(bf.memory_usage() > 0);
    }

    #[test]
    fn test_infohash_dedup() {
        let mut bf = BloomFilter::new(100000, 0.001);
        let mut new_count = 0;

        for i in 0..1000u32 {
            let mut ih = [0u8; 20];
            ih[0..4].copy_from_slice(&i.to_be_bytes());
            if bf.insert_and_check(&ih) {
                new_count += 1;
            }
        }

        // 重复插入同样的
        for i in 0..1000u32 {
            let mut ih = [0u8; 20];
            ih[0..4].copy_from_slice(&i.to_be_bytes());
            if bf.insert_and_check(&ih) {
                new_count += 1;
            }
        }

        // 应该只有 1000 个新元素（第二次全部重复）
        assert_eq!(new_count, 1000);
    }
}
