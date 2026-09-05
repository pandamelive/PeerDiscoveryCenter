//! DHT Token 验证机制（BEP 5）
//!
//! Token 用于验证 announce_peer 请求的合法性：
//! 1. 节点先发送 get_peers，收到响应中的 token
//! 2. 节点再发送 announce_peer，携带该 token
//! 3. 接收方验证 token 是否由自己签发
//!
//! 实现：
//! - token = sha1(addr + secret) 的前 8 字节
//! - secret 每 5 分钟轮换，保留当前和上一个 secret（轮换窗口期有效）
//! - 防止恶意节点伪造 announce_peer

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::routing_table::CompactAddr;
use rand::Rng;
use sha1::{Digest, Sha1};

/// Token 长度（字节）
pub const TOKEN_LEN: usize = 8;

/// Secret 轮换间隔（秒）
pub const SECRET_ROTATION_INTERVAL: u64 = 300; // 5 分钟

/// Token 类型
pub type Token = [u8; TOKEN_LEN];

/// Token 管理器
///
/// 维护当前和上一个 secret，支持 token 生成和验证。
pub struct TokenManager {
    /// 当前 secret
    current_secret: [u8; 32],
    /// 上一个 secret（轮换窗口期内仍有效）
    previous_secret: [u8; 32],
    /// 上次轮换时间
    last_rotation: Instant,
}

impl TokenManager {
    /// 创建新的 Token 管理器
    pub fn new() -> Self {
        let current_secret = Self::generate_secret();
        let previous_secret = Self::generate_secret();
        TokenManager {
            current_secret,
            previous_secret,
            last_rotation: Instant::now(),
        }
    }

    /// 生成随机 secret
    fn generate_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        secret
    }

    /// 检查并轮换 secret（应定期调用）
    pub fn maybe_rotate(&mut self) {
        if self.last_rotation.elapsed() >= Duration::from_secs(SECRET_ROTATION_INTERVAL) {
            self.previous_secret = self.current_secret;
            self.current_secret = Self::generate_secret();
            self.last_rotation = Instant::now();
        }
    }

    /// 为地址生成 token
    pub fn generate(&self, addr: &CompactAddr) -> Token {
        self.generate_with_secret(addr, &self.current_secret)
    }

    /// 使用指定 secret 生成 token
    fn generate_with_secret(&self, addr: &CompactAddr, secret: &[u8; 32]) -> Token {
        let mut hasher = Sha1::new();
        match addr {
            CompactAddr::V4(buf) => hasher.update(buf),
            CompactAddr::V6(buf) => hasher.update(buf),
        }
        hasher.update(secret);
        let result = hasher.finalize();
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&result[..TOKEN_LEN]);
        token
    }

    /// 验证 token 是否有效（检查当前和上一个 secret）
    pub fn verify(&self, addr: &CompactAddr, token: &[u8]) -> bool {
        if token.len() != TOKEN_LEN {
            return false;
        }
        let current = self.generate_with_secret(addr, &self.current_secret);
        if token == current {
            return true;
        }
        let previous = self.generate_with_secret(addr, &self.previous_secret);
        token == previous
    }

    /// 为 SocketAddr 生成 token（便捷方法）
    pub fn generate_for_socket(&self, addr: &SocketAddr) -> Token {
        let compact = CompactAddr::from_socket(addr);
        self.generate(&compact)
    }

    /// 验证 SocketAddr 的 token（便捷方法）
    pub fn verify_socket(&self, addr: &SocketAddr, token: &[u8]) -> bool {
        let compact = CompactAddr::from_socket(addr);
        self.verify(&compact, token)
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_token_generate_and_verify() {
        let manager = TokenManager::new();
        let addr = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);

        let token = manager.generate(&addr);
        assert_eq!(token.len(), TOKEN_LEN);
        assert!(manager.verify(&addr, &token));
    }

    #[test]
    fn test_token_wrong_addr() {
        let manager = TokenManager::new();
        let addr1 = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);
        let addr2 = CompactAddr::V4([127, 0, 0, 2, 0x1A, 0xE1]);

        let token = manager.generate(&addr1);
        assert!(!manager.verify(&addr2, &token));
    }

    #[test]
    fn test_token_wrong_length() {
        let manager = TokenManager::new();
        let addr = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);
        assert!(!manager.verify(&addr, &[0u8; 4]));
        assert!(!manager.verify(&addr, &[]));
    }

    #[test]
    fn test_token_socket_addr() {
        let manager = TokenManager::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 6881);

        let token = manager.generate_for_socket(&addr);
        assert!(manager.verify_socket(&addr, &token));
    }

    #[test]
    fn test_token_after_rotation() {
        let mut manager = TokenManager::new();
        let addr = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);

        let token = manager.generate(&addr);

        // 手动触发轮换（通过修改 last_rotation）
        manager.last_rotation = Instant::now() - Duration::from_secs(SECRET_ROTATION_INTERVAL + 1);
        manager.maybe_rotate();

        // 轮换后，旧 token 仍应有效（previous_secret 保留）
        assert!(manager.verify(&addr, &token));

        // 新生成的 token 也应有效
        let new_token = manager.generate(&addr);
        assert!(manager.verify(&addr, &new_token));
    }

    #[test]
    fn test_token_double_rotation_invalidates() {
        let mut manager = TokenManager::new();
        let addr = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);

        let token = manager.generate(&addr);

        // 两次轮换后，旧 token 应失效
        manager.last_rotation = Instant::now() - Duration::from_secs(SECRET_ROTATION_INTERVAL + 1);
        manager.maybe_rotate();
        manager.last_rotation = Instant::now() - Duration::from_secs(SECRET_ROTATION_INTERVAL + 1);
        manager.maybe_rotate();

        assert!(!manager.verify(&addr, &token));
    }

    #[test]
    fn test_token_different_managers() {
        let manager1 = TokenManager::new();
        let manager2 = TokenManager::new();
        let addr = CompactAddr::V4([127, 0, 0, 1, 0x1A, 0xE1]);

        let token1 = manager1.generate(&addr);
        // 不同 manager 的 secret 不同，token 不应互通
        assert!(!manager2.verify(&addr, &token1));
    }
}
