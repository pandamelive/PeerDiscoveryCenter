//! 恶意 Peer 识别与过滤
//!
//! 监控 peer 行为，识别异常模式：
//! - 请求频率过高（DHT 洪水攻击）
//! - 虚假 announce（token 验证失败）
//! - 短时间内大量不同 infohash 查询
//!
//! 超过阈值的 peer 自动降权或临时封禁。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// 单个 peer 的行为记录
#[derive(Debug, Clone)]
struct PeerBehavior {
    /// 请求计数（当前时间窗口）
    request_count: u32,
    /// 窗口开始时间
    window_start: Instant,
    /// token 验证失败次数
    token_failures: u32,
    /// 查询过的不同 infohash 数量
    unique_infohashes: u32,
    /// 最后一次请求时间
    last_request: Instant,
    /// 封禁截止时间（None = 未封禁）
    banned_until: Option<Instant>,
    /// 累计封禁次数
    ban_count: u32,
}

impl PeerBehavior {
    fn new() -> Self {
        let now = Instant::now();
        PeerBehavior {
            request_count: 0,
            window_start: now,
            token_failures: 0,
            unique_infohashes: 0,
            last_request: now,
            banned_until: None,
            ban_count: 0,
        }
    }
}

/// Peer 过滤器配置
#[derive(Debug, Clone)]
pub struct PeerFilterConfig {
    /// 请求频率阈值（每秒请求数）
    pub max_requests_per_second: u32,
    /// 时间窗口大小（秒）
    pub window_secs: u64,
    /// token 失败阈值（超过则封禁）
    pub max_token_failures: u32,
    /// 唯一 infohash 阈值（短时间内查询过多不同资源）
    pub max_unique_infohashes: u32,
    /// 首次封禁时长（秒）
    pub initial_ban_secs: u64,
    /// 最大封禁时长（秒）
    pub max_ban_secs: u64,
    /// 行为记录过期时间（秒）
    pub record_ttl_secs: u64,
}

impl Default for PeerFilterConfig {
    fn default() -> Self {
        PeerFilterConfig {
            max_requests_per_second: 50,
            window_secs: 60,
            max_token_failures: 5,
            max_unique_infohashes: 200,
            initial_ban_secs: 300,
            max_ban_secs: 86400,
            record_ttl_secs: 3600,
        }
    }
}

/// Peer 过滤器
///
/// 线程安全，可共享使用。
pub struct PeerFilter {
    /// IP -> 行为记录
    behaviors: Arc<RwLock<HashMap<IpAddr, PeerBehavior>>>,
    /// 配置
    config: PeerFilterConfig,
}

impl PeerFilter {
    /// 创建新的 Peer 过滤器
    pub fn new(config: PeerFilterConfig) -> Self {
        PeerFilter {
            behaviors: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// 检查 peer 是否被封禁
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let behaviors = self.behaviors.read();
        if let Some(behavior) = behaviors.get(ip) {
            if let Some(until) = behavior.banned_until {
                return until > Instant::now();
            }
        }
        false
    }

    /// 记录一次请求，返回是否应该封禁
    pub fn record_request(&self, ip: &IpAddr) -> bool {
        let mut behaviors = self.behaviors.write();
        let now = Instant::now();
        let behavior = behaviors.entry(*ip).or_insert_with(PeerBehavior::new);

        // 检查是否已封禁
        if let Some(until) = behavior.banned_until {
            if until > now {
                return true; // 仍在封禁中
            } else {
                behavior.banned_until = None; // 封禁到期
            }
        }

        // 重置时间窗口
        if now.duration_since(behavior.window_start) > Duration::from_secs(self.config.window_secs)
        {
            behavior.window_start = now;
            behavior.request_count = 0;
            behavior.unique_infohashes = 0;
        }

        behavior.request_count += 1;
        behavior.last_request = now;

        // 检查频率
        let elapsed = now
            .duration_since(behavior.window_start)
            .as_secs_f64()
            .max(1.0);
        let rate = behavior.request_count as f64 / elapsed;
        if rate > self.config.max_requests_per_second as f64 {
            self.ban(ip, behavior);
            return true;
        }

        false
    }

    /// 记录一次 token 验证失败
    pub fn record_token_failure(&self, ip: &IpAddr) -> bool {
        let mut behaviors = self.behaviors.write();
        let now = Instant::now();
        let behavior = behaviors.entry(*ip).or_insert_with(PeerBehavior::new);

        behavior.token_failures += 1;
        behavior.last_request = now;

        if behavior.token_failures >= self.config.max_token_failures {
            self.ban(ip, behavior);
            return true;
        }
        false
    }

    /// 记录一次 infohash 查询（用于检测短时间内大量不同资源查询）
    pub fn record_infohash_query(&self, ip: &IpAddr) -> bool {
        let mut behaviors = self.behaviors.write();
        let now = Instant::now();
        let behavior = behaviors.entry(*ip).or_insert_with(PeerBehavior::new);

        // 重置窗口
        if now.duration_since(behavior.window_start) > Duration::from_secs(self.config.window_secs)
        {
            behavior.window_start = now;
            behavior.request_count = 0;
            behavior.unique_infohashes = 0;
        }

        behavior.unique_infohashes += 1;

        if behavior.unique_infohashes > self.config.max_unique_infohashes {
            self.ban(ip, behavior);
            return true;
        }
        false
    }

    /// 执行封禁（内部方法，调用方必须持有写锁）
    fn ban(&self, _ip: &IpAddr, behavior: &mut PeerBehavior) {
        let ban_duration = Duration::from_secs(
            (self.config.initial_ban_secs * 2u64.pow(behavior.ban_count.min(5)))
                .min(self.config.max_ban_secs),
        );
        behavior.banned_until = Some(Instant::now() + ban_duration);
        behavior.ban_count += 1;
        behavior.token_failures = 0; // 重置失败计数
    }

    /// 手动解封
    pub fn unban(&self, ip: &IpAddr) {
        let mut behaviors = self.behaviors.write();
        if let Some(behavior) = behaviors.get_mut(ip) {
            behavior.banned_until = None;
        }
    }

    /// 获取封禁列表
    pub fn banned_peers(&self) -> Vec<(IpAddr, Instant)> {
        let now = Instant::now();
        self.behaviors
            .read()
            .iter()
            .filter_map(|(ip, b)| {
                b.banned_until
                    .filter(|until| *until > now)
                    .map(|until| (*ip, until))
            })
            .collect()
    }

    /// 清理过期记录
    pub fn cleanup(&self) -> usize {
        let mut behaviors = self.behaviors.write();
        let now = Instant::now();
        let before = behaviors.len();
        behaviors.retain(|_, b| {
            now.duration_since(b.last_request) < Duration::from_secs(self.config.record_ttl_secs)
        });
        before - behaviors.len()
    }

    /// 总记录数
    pub fn len(&self) -> usize {
        self.behaviors.read().len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.behaviors.read().is_empty()
    }

    /// 获取统计信息
    pub fn stats(&self) -> PeerFilterStats {
        let behaviors = self.behaviors.read();
        let now = Instant::now();
        let banned = behaviors
            .values()
            .filter(|b| b.banned_until.map(|u| u > now).unwrap_or(false))
            .count();
        PeerFilterStats {
            total_tracked: behaviors.len(),
            currently_banned: banned,
            total_bans: behaviors.values().map(|b| b.ban_count).sum::<u32>() as usize,
        }
    }
}

impl Default for PeerFilter {
    fn default() -> Self {
        Self::new(PeerFilterConfig::default())
    }
}

/// Peer 过滤器统计
#[derive(Debug, Clone)]
pub struct PeerFilterStats {
    /// 总跟踪 peer 数
    pub total_tracked: usize,
    /// 当前封禁数
    pub currently_banned: usize,
    /// 累计封禁次数
    pub total_bans: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_ip(i: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, i))
    }

    #[test]
    fn test_not_banned_initially() {
        let filter = PeerFilter::default();
        let ip = make_ip(1);
        assert!(!filter.is_banned(&ip));
    }

    #[test]
    fn test_record_request_not_banned() {
        let filter = PeerFilter::default();
        let ip = make_ip(1);
        assert!(!filter.record_request(&ip));
        assert!(!filter.is_banned(&ip));
    }

    #[test]
    fn test_high_frequency_ban() {
        let config = PeerFilterConfig {
            max_requests_per_second: 5,
            window_secs: 1,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);
        let ip = make_ip(1);

        // 快速发送大量请求
        for _ in 0..100 {
            filter.record_request(&ip);
        }

        assert!(filter.is_banned(&ip));
    }

    #[test]
    fn test_token_failure_ban() {
        let config = PeerFilterConfig {
            max_token_failures: 3,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);
        let ip = make_ip(2);

        for _ in 0..2 {
            assert!(!filter.record_token_failure(&ip));
        }
        // 第 3 次应该触发封禁
        assert!(filter.record_token_failure(&ip));
        assert!(filter.is_banned(&ip));
    }

    #[test]
    fn test_unban() {
        let config = PeerFilterConfig {
            max_token_failures: 1,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);
        let ip = make_ip(3);

        filter.record_token_failure(&ip);
        assert!(filter.is_banned(&ip));

        filter.unban(&ip);
        assert!(!filter.is_banned(&ip));
    }

    #[test]
    fn test_banned_peers_list() {
        let config = PeerFilterConfig {
            max_token_failures: 1,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);

        filter.record_token_failure(&make_ip(1));
        filter.record_token_failure(&make_ip(2));

        let banned = filter.banned_peers();
        assert_eq!(banned.len(), 2);
    }

    #[test]
    fn test_cleanup() {
        let config = PeerFilterConfig {
            record_ttl_secs: 0, // 立即过期
            ..Default::default()
        };
        let filter = PeerFilter::new(config);
        filter.record_request(&make_ip(1));

        // 等一点点时间
        std::thread::sleep(Duration::from_millis(10));

        let cleaned = filter.cleanup();
        assert!(cleaned >= 1);
    }

    #[test]
    fn test_stats() {
        let config = PeerFilterConfig {
            max_token_failures: 1,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);

        filter.record_request(&make_ip(1));
        filter.record_token_failure(&make_ip(2));

        let stats = filter.stats();
        assert_eq!(stats.total_tracked, 2);
        assert_eq!(stats.currently_banned, 1);
        assert_eq!(stats.total_bans, 1);
    }

    #[test]
    fn test_escalating_ban_duration() {
        let config = PeerFilterConfig {
            max_token_failures: 1,
            initial_ban_secs: 60,
            max_ban_secs: 3600,
            ..Default::default()
        };
        let filter = PeerFilter::new(config);
        let ip = make_ip(4);

        // 第一次封禁
        filter.record_token_failure(&ip);
        let first_ban = filter.banned_peers()[0].1;

        // 解封后再次封禁
        filter.unban(&ip);
        filter.record_token_failure(&ip);
        let second_ban = filter.banned_peers()[0].1;

        // 第二次封禁应该更长
        assert!(second_ban > first_ban);
    }
}
