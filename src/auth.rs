//! API 认证与安全中间件
//!
//! - API Key 认证（P39）
//! - 请求限流（P40）
//! - 审计日志（P41）

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use parking_lot::RwLock;
use tracing::{info, warn};

/// API Key 配置
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// 是否启用 API Key 认证
    pub enabled: bool,
    /// 允许的 API Key 列表
    pub api_keys: Vec<String>,
    /// 限流：每秒最大请求数（0 = 不限流）
    pub rate_limit_per_second: u32,
    /// 限流窗口大小（秒）
    pub rate_limit_window_secs: u64,
    /// 是否启用审计日志
    pub audit_log_enabled: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            enabled: false,
            api_keys: vec![],
            rate_limit_per_second: 0,
            rate_limit_window_secs: 60,
            audit_log_enabled: true,
        }
    }
}

/// 限流器状态
#[derive(Debug, Clone)]
struct RateLimitState {
    /// 窗口开始时间
    window_start: Instant,
    /// 当前窗口请求数
    count: u32,
}

/// 认证与限流状态
#[derive(Clone)]
pub struct AuthState {
    config: Arc<RwLock<AuthConfig>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitState>>>,
}

impl AuthState {
    /// 创建新的认证状态
    pub fn new(config: AuthConfig) -> Self {
        AuthState {
            config: Arc::new(RwLock::new(config)),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 更新配置
    pub fn update_config(&self, config: AuthConfig) {
        *self.config.write() = config;
    }

    /// 验证 API Key
    fn validate_api_key(&self, headers: &HeaderMap) -> bool {
        let config = self.config.read();
        if !config.enabled {
            return true; // 未启用认证，放行
        }
        if config.api_keys.is_empty() {
            return true; // 未配置 key，放行
        }

        // 从 X-API-Key 或 Authorization 头获取
        let key = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
            });

        match key {
            Some(k) => config.api_keys.contains(&k.to_string()),
            None => false,
        }
    }

    /// 检查限流
    fn check_rate_limit(&self, client_id: &str) -> bool {
        let config = self.config.read();
        if config.rate_limit_per_second == 0 {
            return true; // 不限流
        }

        let max_requests = config.rate_limit_per_second * config.rate_limit_window_secs as u32;
        let window = Duration::from_secs(config.rate_limit_window_secs);

        let mut limits = self.rate_limits.write();
        let state = limits.entry(client_id.to_string()).or_insert(RateLimitState {
            window_start: Instant::now(),
            count: 0,
        });

        // 重置窗口
        if state.window_start.elapsed() > window {
            state.window_start = Instant::now();
            state.count = 0;
        }

        if state.count >= max_requests {
            return false;
        }

        state.count += 1;
        true
    }
}

/// 认证 + 限流 + 审计日志中间件
pub async fn auth_middleware(
    state: axum::extract::State<AuthState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_id = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let path = request.uri().path().to_string();
    let method = request.method().to_string();

    // 1. API Key 认证
    if !state.validate_api_key(&headers) {
        warn!("[auth] API Key 验证失败: client={}, path={}", client_id, path);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 2. 限流检查
    if !state.check_rate_limit(&client_id) {
        warn!("[auth] 限流触发: client={}, path={}", client_id, path);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 3. 审计日志（请求前）
    let audit_enabled = state.config.read().audit_log_enabled;
    if audit_enabled {
        info!("[audit] 请求: method={}, path={}, client={}", method, path, client_id);
    }

    // 4. 执行请求
    let response = next.run(request).await;

    // 5. 审计日志（响应后）
    if audit_enabled {
        info!(
            "[audit] 响应: method={}, path={}, client={}, status={}",
            method,
            path,
            client_id,
            response.status().as_u16()
        );
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_disabled() {
        let state = AuthState::new(AuthConfig::default());
        let headers = HeaderMap::new();
        assert!(state.validate_api_key(&headers));
    }

    #[test]
    fn test_api_key_enabled_no_keys() {
        let config = AuthConfig {
            enabled: true,
            api_keys: vec![],
            ..Default::default()
        };
        let state = AuthState::new(config);
        let headers = HeaderMap::new();
        assert!(state.validate_api_key(&headers));
    }

    #[test]
    fn test_api_key_valid() {
        let config = AuthConfig {
            enabled: true,
            api_keys: vec!["test-key-123".to_string()],
            ..Default::default()
        };
        let state = AuthState::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "test-key-123".parse().unwrap());
        assert!(state.validate_api_key(&headers));
    }

    #[test]
    fn test_api_key_invalid() {
        let config = AuthConfig {
            enabled: true,
            api_keys: vec!["test-key-123".to_string()],
            ..Default::default()
        };
        let state = AuthState::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "wrong-key".parse().unwrap());
        assert!(!state.validate_api_key(&headers));
    }

    #[test]
    fn test_api_key_bearer_token() {
        let config = AuthConfig {
            enabled: true,
            api_keys: vec!["bearer-key".to_string()],
            ..Default::default()
        };
        let state = AuthState::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer bearer-key".parse().unwrap());
        assert!(state.validate_api_key(&headers));
    }

    #[test]
    fn test_rate_limit_disabled() {
        let state = AuthState::new(AuthConfig::default());
        for _ in 0..1000 {
            assert!(state.check_rate_limit("client1"));
        }
    }

    #[test]
    fn test_rate_limit_enabled() {
        let config = AuthConfig {
            rate_limit_per_second: 10,
            rate_limit_window_secs: 1,
            ..Default::default()
        };
        let state = AuthState::new(config);

        // 前 10 次应该通过
        for i in 0..10 {
            assert!(state.check_rate_limit("client1"), "第 {} 次应该通过", i);
        }
        // 第 11 次应该被拒绝
        assert!(!state.check_rate_limit("client1"));
    }

    #[test]
    fn test_rate_limit_independent_clients() {
        let config = AuthConfig {
            rate_limit_per_second: 5,
            rate_limit_window_secs: 1,
            ..Default::default()
        };
        let state = AuthState::new(config);

        for _ in 0..5 {
            assert!(state.check_rate_limit("client1"));
        }
        // client1 被限流
        assert!(!state.check_rate_limit("client1"));
        // client2 不受影响
        for _ in 0..5 {
            assert!(state.check_rate_limit("client2"));
        }
    }

    #[test]
    fn test_update_config() {
        let state = AuthState::new(AuthConfig::default());
        assert!(state.validate_api_key(&HeaderMap::new()));

        let new_config = AuthConfig {
            enabled: true,
            api_keys: vec!["new-key".to_string()],
            ..Default::default()
        };
        state.update_config(new_config);
        assert!(!state.validate_api_key(&HeaderMap::new()));
    }
}
