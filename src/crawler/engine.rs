//! 爬虫引擎实现
//!
//! 实现 DHT 被动监听爬虫（完整 DHT 节点模式）：
//! 1. 加入 DHT 网络（通过 bootstrap 节点）
//! 2. 监听其他节点发来的 ping/find_node/get_peers/announce_peer 消息
//! 3. 对查询发送真实响应（查路由表 + 查 peer 存储 + token 验证）
//! 4. 从中提取 infohash，去重后发布到事件总线
//! 5. 维护 k-bucket 路由表和 DHT peer 存储

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;
use rand::Rng;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::bloom::BloomFilter;
use crate::config::CrawlerConfig;
use crate::discoverers::dht::message::{
    DhtMessage, DhtNode, QueryMethod,
};
use crate::discoverers::dht::routing_table::{CompactAddr, RoutingTable};
use crate::discoverers::dht::store::DhtStore;
use crate::discoverers::dht::token::TokenManager;
use crate::event_bus::EventBus;
use crate::types::{Event, Infohash};

use super::Crawler;

/// 爬虫运行状态
#[derive(Debug, Clone, Default)]
pub struct CrawlerState {
    /// 是否在运行
    pub running: bool,
    /// 已爬行的节点数
    pub nodes_crawled: u64,
    /// 已收集的 infohash 数
    pub infohashes_collected: u64,
    /// 已收集的 peer 数
    pub peers_collected: u64,
    /// 爬行开始时间
    pub started_at: Option<Instant>,
    /// 最后一次爬行时间
    pub last_crawl_at: Option<Instant>,
    /// 错误数
    pub errors: u64,
    /// 收到的消息总数
    pub messages_received: u64,
    /// 路由表节点数
    pub routing_table_size: usize,
    /// peer 存储中的 peer 数
    pub stored_peers: usize,
    /// peer 存储中的 infohash 数
    pub stored_infohashes: usize,
}

/// 爬虫引擎
///
/// 被动监听 DHT 网络，收集 infohash，同时作为完整 DHT 节点响应查询。
pub struct CrawlerEngine {
    config: CrawlerConfig,
    state: Arc<RwLock<CrawlerState>>,
    event_bus: EventBus,
    shutdown: Arc<tokio::sync::Notify>,
    /// 已收集的 infohash（BloomFilter 去重，空间高效）
    seen_infohashes: Arc<RwLock<BloomFilter>>,
    /// 我们的节点 ID
    node_id: [u8; 20],
    /// 共享路由表（与 DhtDiscoverer 共享）
    routing_table: Arc<RwLock<RoutingTable>>,
    /// 共享 peer 存储
    peer_store: Arc<RwLock<DhtStore>>,
    /// 共享 token 管理器
    token_manager: Arc<RwLock<TokenManager>>,
}

impl CrawlerEngine {
    /// 创建新的爬虫引擎（独立状态，不与 DhtDiscoverer 共享）
    pub fn new(config: CrawlerConfig, event_bus: EventBus) -> Self {
        let node_id = Self::generate_node_id();
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let peer_store = Arc::new(RwLock::new(DhtStore::new()));
        let token_manager = Arc::new(RwLock::new(TokenManager::new()));

        Self {
            config,
            state: Arc::new(RwLock::new(CrawlerState::default())),
            event_bus,
            shutdown: Arc::new(tokio::sync::Notify::new()),
            seen_infohashes: Arc::new(RwLock::new(BloomFilter::default())),
            node_id,
            routing_table,
            peer_store,
            token_manager,
        }
    }

    /// 创建爬虫引擎，与 DhtDiscoverer 共享路由表/peer存储/token管理器
    pub fn with_shared_state(
        config: CrawlerConfig,
        event_bus: EventBus,
        routing_table: Arc<RwLock<RoutingTable>>,
        peer_store: Arc<RwLock<DhtStore>>,
        token_manager: Arc<RwLock<TokenManager>>,
        node_id: [u8; 20],
    ) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CrawlerState::default())),
            event_bus,
            shutdown: Arc::new(tokio::sync::Notify::new()),
            seen_infohashes: Arc::new(RwLock::new(BloomFilter::default())),
            node_id,
            routing_table,
            peer_store,
            token_manager,
        }
    }

    /// 生成节点 ID（BEP 42，如果可用）
    fn generate_node_id() -> [u8; 20] {
        // 爬虫无法知道自己的外网 IP，先用随机 ID
        // 实际部署时可以通过 STUN 或配置获取外网 IP 后用 generate_node_id()
        let mut id = [0u8; 20];
        rand::thread_rng().fill(&mut id);
        id
    }

    /// 获取状态快照
    pub fn state(&self) -> CrawlerState {
        let mut state = self.state.read().clone();
        state.routing_table_size = self.routing_table.read().len();
        let store = self.peer_store.read();
        state.stored_peers = store.total_peers();
        state.stored_infohashes = store.total_infohashes();
        state
    }

    /// 加入 DHT 网络：向 bootstrap 节点发送 ping
    async fn bootstrap(&self, socket: &UdpSocket) -> usize {
        let mut success = 0;
        for (host, port) in &self.config.bootstrap_nodes {
            let addr_str = format!("{}:{}", host, port);
            if let Ok(addrs) = tokio::net::lookup_host(addr_str.clone()).await {
                for addr in addrs {
                    let tid = rand::thread_rng().gen::<[u8; 2]>();
                    let ping = DhtMessage::build_ping(&tid, &self.node_id);
                    if socket.send_to(&ping, addr).await.is_ok() {
                        success += 1;
                        // 将 bootstrap 节点加入路由表（ID 未知，用随机 ID）
                        let mut bootstrap_id = [0u8; 20];
                        rand::thread_rng().fill(&mut bootstrap_id);
                        self.routing_table
                            .write()
                            .insert(bootstrap_id, CompactAddr::from_socket(&addr));
                        debug!("[crawler] 向 bootstrap {} 发送 ping", addr);
                    }
                }
            }
        }
        success
    }

    /// 处理收到的 DHT 消息（完整 DHT 节点模式）
    ///
    /// 返回新发现的 infohash（如果有）
    async fn handle_message(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        from: SocketAddr,
    ) -> Option<Infohash> {
        // 更新消息计数
        {
            let mut state = self.state.write();
            state.messages_received += 1;
        }

        // 将请求方加入路由表（先尝试解析其 ID）
        let from_compact = CompactAddr::from_socket(&from);

        // 解析查询消息
        let (tid, method, infohash) = DhtMessage::parse_query(data)?;

        match method {
            QueryMethod::Ping => {
                // 响应 ping
                let resp = DhtMessage::build_ping_response(&tid, &self.node_id);
                let _ = socket.send_to(&resp, from).await;
                debug!("[crawler] 响应 {} 的 ping", from);
            }
            QueryMethod::FindNode => {
                // 从路由表找最近的节点
                let target = infohash.unwrap_or([0u8; 20]);
                let closest = self.routing_table.read().find_closest(&target, 8);
                let nodes: Vec<DhtNode> = closest
                    .into_iter()
                    .map(|e| DhtNode {
                        id: e.id,
                        addr: e.addr.to_socket(),
                    })
                    .collect();

                let resp = if nodes.is_empty() {
                    DhtMessage::build_find_node_response(&tid, &self.node_id)
                } else {
                    DhtMessage::build_find_node_response_with_nodes(&tid, &self.node_id, &nodes)
                };
                let _ = socket.send_to(&resp, from).await;
                debug!("[crawler] 响应 {} 的 find_node（返回 {} 节点）", from, nodes.len());
            }
            QueryMethod::GetPeers => {
                let ih = infohash?;

                // 生成 token
                let token = self.token_manager.read().generate(&from_compact);

                // 先查 peer 存储
                let stored_peers = self.peer_store.read().get_peers(&ih, 50);
                let peers: Vec<SocketAddr> = stored_peers.iter().map(|a| a.to_socket()).collect();

                let resp = if !peers.is_empty() {
                    // 有存储的 peer，直接返回
                    DhtMessage::build_get_peers_response_full(
                        &tid, &self.node_id, &token, &peers, &[],
                    )
                } else {
                    // 没有存储的 peer，返回最近的节点
                    let closest = self.routing_table.read().find_closest(&ih, 8);
                    let nodes: Vec<DhtNode> = closest
                        .into_iter()
                        .map(|e| DhtNode {
                            id: e.id,
                            addr: e.addr.to_socket(),
                        })
                        .collect();
                    DhtMessage::build_get_peers_response_full(
                        &tid, &self.node_id, &token, &[], &nodes,
                    )
                };
                let _ = socket.send_to(&resp, from).await;
                debug!(
                    "[crawler] 响应 {} 的 get_peers（{} peers）",
                    from,
                    peers.len()
                );

                return Some(ih);
            }
            QueryMethod::AnnouncePeer => {
                // 解析 announce_peer 参数
                if let Some((tid, params)) = DhtMessage::parse_announce_peer(data) {
                    // 验证 token
                    let token_valid = self.token_manager.read().verify(&from_compact, &params.token);

                    if !token_valid {
                        debug!(
                            "[crawler] {} 的 announce_peer token 验证失败，忽略",
                            from
                        );
                        // 仍然响应（但不存储）
                        let resp = DhtMessage::build_announce_peer_response(&tid, &self.node_id);
                        let _ = socket.send_to(&resp, from).await;
                        return Some(params.info_hash);
                    }

                    // 确定 peer 地址（implied_port 用请求源端口）
                    let peer_port = if params.implied_port {
                        from.port()
                    } else {
                        params.port
                    };
                    let peer_addr = SocketAddr::new(from.ip(), peer_port);
                    let peer_compact = CompactAddr::from_socket(&peer_addr);

                    // 存入 peer 存储
                    self.peer_store
                        .write()
                        .announce(params.info_hash, peer_compact);

                    // 将请求方加入路由表
                    self.routing_table
                        .write()
                        .insert(params.id, from_compact);

                    // 更新统计
                    {
                        let mut state = self.state.write();
                        state.peers_collected += 1;
                    }

                    // 响应
                    let resp = DhtMessage::build_announce_peer_response(&tid, &self.node_id);
                    let _ = socket.send_to(&resp, from).await;

                    debug!(
                        "[crawler] {} announce_peer 成功（ih={}, port={}）",
                        from,
                        hex::encode(params.info_hash),
                        peer_port
                    );

                    return Some(params.info_hash);
                }
            }
            QueryMethod::SampleInfohashes => {
                let (samples, total) = self.peer_store.read().sample_infohashes(64);
                let mut samples_bytes = Vec::with_capacity(samples.len() * 20);
                for ih in &samples {
                    samples_bytes.extend_from_slice(ih);
                }
                let resp = DhtMessage::build_sample_infohashes_response(
                    &tid,
                    &self.node_id,
                    30,
                    total as i64,
                    &samples_bytes,
                );
                let _ = socket.send_to(&resp, from).await;
                debug!(
                    "[crawler] 响应 {} 的 sample_infohashes（{} samples / {} total）",
                    from,
                    samples.len(),
                    total
                );
            }
        }
        None
    }

    /// 爬行循环：被动监听 DHT 消息
    async fn crawl_loop(&self) {
        info!(
            "[crawler] DHT 爬虫启动，监听端口 {}",
            self.config.listen_port
        );

        // 创建 UDP socket
        let socket = match crate::discoverers::dht::bind_udp_socket(&format!("0.0.0.0:{}", self.config.listen_port)).await {
            Ok(s) => s,
            Err(e) => {
                warn!("[crawler] 绑定端口 {} 失败: {}", self.config.listen_port, e);
                let mut state = self.state.write();
                state.running = false;
                state.errors += 1;
                return;
            }
        };

        // 加入 DHT 网络
        let bootstrap_count = self.bootstrap(&socket).await;
        info!(
            "[crawler] 向 {} 个 bootstrap 地址发送了 ping",
            bootstrap_count
        );

        let mut buf = vec![0u8; 4096];
        let mut last_bootstrap = Instant::now();
        let mut last_maintenance = Instant::now();
        let bootstrap_interval = Duration::from_secs(300); // 每 5 分钟重新 bootstrap
        let maintenance_interval = Duration::from_secs(60); // 每分钟维护

        loop {
            tokio::select! {
                _ = self.shutdown.notified() => {
                    info!("[crawler] 爬虫引擎收到停止信号");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            let data = &buf[..n];
                            if let Some(infohash) = self.handle_message(&socket, data, from).await {
                                // 检查是否是新 infohash
                                let is_new = {
                                    let mut seen = self.seen_infohashes.write();
                                    seen.insert_and_check(&infohash)
                                };
                                if is_new {
                                    let hex_ih = hex::encode(infohash);
                                    debug!("[crawler] 发现新 infohash: {} (来自 {})", hex_ih, from);
                                    // 更新状态
                                    {
                                        let mut state = self.state.write();
                                        state.infohashes_collected += 1;
                                        state.last_crawl_at = Some(Instant::now());
                                    }
                                    // 发布事件
                                    self.event_bus.publish(Event::InfohashSeen {
                                        infohash,
                                        source: "dht-crawler".to_string(),
                                        seen_at: std::time::SystemTime::now(),
                                    });
                                    // 定期发布爬行进度
                                    let state = self.state();
                                    if state.infohashes_collected.is_multiple_of(100) {
                                        self.event_bus.publish(Event::CrawlProgress {
                                            nodes_crawled: state.messages_received,
                                            infohashes_collected: state.infohashes_collected,
                                            peers_collected: state.peers_collected,
                                            message: format!(
                                                "已收集 {} infohash, {} peers, 路由表 {} 节点",
                                                state.infohashes_collected,
                                                state.peers_collected,
                                                state.routing_table_size
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("[crawler] 接收消息失败: {}", e);
                            let mut state = self.state.write();
                            state.errors += 1;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // 定期重新 bootstrap，保持在 DHT 网络中
                    if last_bootstrap.elapsed() >= bootstrap_interval {
                        let count = self.bootstrap(&socket).await;
                        debug!("[crawler] 定期 bootstrap，向 {} 个地址发送 ping", count);
                        last_bootstrap = Instant::now();
                    }
                    // 定期维护（清理过期节点/peer、轮换 token）
                    if last_maintenance.elapsed() >= maintenance_interval {
                        self.routing_table.write().evict_expired();
                        self.peer_store.write().evict_expired();
                        self.token_manager.write().maybe_rotate();
                        last_maintenance = Instant::now();
                    }
                }
            }
        }
        info!("[crawler] 爬虫引擎已停止");
    }
}

#[async_trait]
impl Crawler for CrawlerEngine {
    fn name(&self) -> &str {
        "dht-crawler"
    }

    async fn start(&self) -> anyhow::Result<()> {
        if !self.config.enabled {
            warn!("[crawler] 爬虫未启用（config.crawler.enabled = false）");
            return Ok(());
        }
        {
            let mut state = self.state.write();
            if state.running {
                warn!("[crawler] 爬虫已在运行");
                return Ok(());
            }
            state.running = true;
            state.started_at = Some(Instant::now());
        }

        let engine = self.clone_for_async();
        tokio::spawn(async move {
            engine.crawl_loop().await;
        });
        info!("[crawler] 爬虫引擎已启动");
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        {
            let mut state = self.state.write();
            if !state.running {
                return Ok(());
            }
            state.running = false;
        }
        self.shutdown.notify_waiters();
        info!("[crawler] 爬虫引擎停止信号已发送");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.state.read().running
    }

    fn state(&self) -> CrawlerState {
        self.state()
    }
}

impl CrawlerEngine {
    /// 克隆一个可用于 async 任务的引用
    fn clone_for_async(&self) -> CrawlerEngine {
        CrawlerEngine {
            config: self.config.clone(),
            state: self.state.clone(),
            event_bus: self.event_bus.clone(),
            shutdown: self.shutdown.clone(),
            seen_infohashes: self.seen_infohashes.clone(),
            node_id: self.node_id,
            routing_table: self.routing_table.clone(),
            peer_store: self.peer_store.clone(),
            token_manager: self.token_manager.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_state_default() {
        let state = CrawlerState::default();
        assert!(!state.running);
        assert_eq!(state.nodes_crawled, 0);
        assert_eq!(state.infohashes_collected, 0);
    }

    #[test]
    fn test_crawler_engine_creation() {
        let config = CrawlerConfig::default();
        let bus = EventBus::default();
        let engine = CrawlerEngine::new(config, bus);
        assert_eq!(engine.name(), "dht-crawler");
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn test_crawler_start_disabled() {
        let config = CrawlerConfig {
            enabled: false,
            ..Default::default()
        };
        let bus = EventBus::default();
        let engine = CrawlerEngine::new(config, bus);
        let result = engine.start().await;
        assert!(result.is_ok());
        assert!(!engine.is_running());
    }

    #[test]
    fn test_parse_query_ping() {
        let tid = [0x01, 0x02];
        let node_id = [0u8; 20];
        let msg = DhtMessage::build_ping(&tid, &node_id);
        let (parsed_tid, method, ih) = DhtMessage::parse_query(&msg).unwrap();
        assert_eq!(method, QueryMethod::Ping);
        assert_eq!(parsed_tid, vec![0x01, 0x02]);
        assert!(ih.is_none());
    }

    #[test]
    fn test_parse_query_get_peers() {
        let tid = [0x01, 0x02];
        let node_id = [0u8; 20];
        let infohash = [1u8; 20];
        let msg = DhtMessage::build_get_peers(&tid, &node_id, &infohash);
        let (_, method, ih) = DhtMessage::parse_query(&msg).unwrap();
        assert_eq!(method, QueryMethod::GetPeers);
        assert_eq!(ih, Some(infohash));
    }

    #[test]
    fn test_parse_announce_peer() {
        let tid = [0x01, 0x02];
        let node_id = [0u8; 20];
        let infohash = [1u8; 20];
        let token = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let msg = DhtMessage::build_announce_peer(&tid, &node_id, &infohash, 6881, &token);
        let (parsed_tid, params) = DhtMessage::parse_announce_peer(&msg).unwrap();
        assert_eq!(parsed_tid, vec![0x01, 0x02]);
        assert_eq!(params.info_hash, infohash);
        assert_eq!(params.port, 6881);
        assert_eq!(params.token, token);
        assert!(!params.implied_port);
    }

    #[test]
    fn test_build_ping_response() {
        let tid = vec![0x01, 0x02];
        let node_id = [0u8; 20];
        let resp = DhtMessage::build_ping_response(&tid, &node_id);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("1:y1:r"));
    }

    #[test]
    fn test_build_find_node_response_with_nodes() {
        let tid = vec![0x01, 0x02];
        let node_id = [0u8; 20];
        let nodes = vec![DhtNode {
            id: [1u8; 20],
            addr: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                6881,
            ),
        }];
        let resp = DhtMessage::build_find_node_response_with_nodes(&tid, &node_id, &nodes);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("5:nodes"));
        assert!(s.contains("1:y1:r"));
    }

    #[test]
    fn test_build_get_peers_response_full_with_peers() {
        let tid = vec![0x01, 0x02];
        let node_id = [0u8; 20];
        let token = vec![0xAA, 0xBB];
        let peers = vec![SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            6881,
        )];
        let resp = DhtMessage::build_get_peers_response_full(&tid, &node_id, &token, &peers, &[]);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("6:values"));
        assert!(s.contains("5:token"));
    }

    #[test]
    fn test_build_announce_peer_response() {
        let tid = vec![0x01, 0x02];
        let node_id = [0u8; 20];
        let resp = DhtMessage::build_announce_peer_response(&tid, &node_id);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("1:y1:r"));
    }

    #[test]
    fn test_build_error_response() {
        let tid = vec![0x01, 0x02];
        let resp = DhtMessage::build_error_response(&tid, 203, "Server error");
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("1:y1:e"));
        assert!(s.contains("Server error"));
    }

    #[test]
    fn test_crawler_with_shared_state() {
        let config = CrawlerConfig::default();
        let bus = EventBus::default();
        let node_id = [0u8; 20];
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let peer_store = Arc::new(RwLock::new(DhtStore::new()));
        let token_manager = Arc::new(RwLock::new(TokenManager::new()));

        let engine = CrawlerEngine::with_shared_state(
            config,
            bus,
            routing_table.clone(),
            peer_store.clone(),
            token_manager.clone(),
            node_id,
        );
        assert_eq!(engine.name(), "dht-crawler");
        assert_eq!(engine.routing_table.read().len(), 0);
    }
}
