//! PeerDiscoveryCenter 二进制入口
//!
//! 双模式架构：
//! - `pdc serve` - 本地独立运行，提供 HTTP API + 超级 Tracker
//! - `pdc agent` - 接入 PK 主控，接受任务派发
//!
//! 其他子命令：discover / peers / stats / health / config

mod agent;
mod bootstrap;
mod cli;
mod history;
mod protocol;
mod service_resolver;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use parking_lot::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use PeerDiscoveryCenter::aggregator::{PeerDiscoveryAggregator, PeerDiscoveryConfig};
use PeerDiscoveryCenter::cache::PeerCache;
use PeerDiscoveryCenter::config::{resolve_work_dir, PdcConfig};
use PeerDiscoveryCenter::control_plane::ControlPlane;
use PeerDiscoveryCenter::crawler::{Crawler, CrawlerEngine};
use PeerDiscoveryCenter::data_plane::http_tracker::SuperTrackerState;
use PeerDiscoveryCenter::data_plane::{AppState, DataPlane};
use PeerDiscoveryCenter::discoverers::DiscovererRegistry;
use PeerDiscoveryCenter::event_bus::EventBus;
use PeerDiscoveryCenter::health_check::{HealthCheckConfig, HealthCheckTask};
use PeerDiscoveryCenter::nat::NatManager;
use PeerDiscoveryCenter::types::Infohash;

use cli::{Cli, Commands};

/// 程序版本（从 Cargo.toml 读取）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 初始化日志
    let log_level = cli.log_level.as_deref().unwrap_or("info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("PeerDiscoveryCenter v{}", VERSION);

    // 解析工作目录
    let work_dir = match &cli.work_dir {
        Some(dir) => dir.clone(),
        None => resolve_work_dir(None),
    };
    info!("工作目录: {}", work_dir.display());

    match &cli.command {
        Commands::Serve { host, port } => {
            run_serve(&work_dir, host.clone(), *port).await?;
        }
        Commands::Agent {
            master,
            token,
            name,
        } => {
            run_agent(&work_dir, master.clone(), token.clone(), name.clone()).await?;
        }
        Commands::Discover {
            infohash,
            limit,
            format,
        } => {
            run_discover(&work_dir, infohash, *limit, format).await?;
        }
        Commands::Peers { infohash, limit } => {
            run_peers(&work_dir, infohash.as_deref(), *limit).await?;
        }
        Commands::Stats => {
            run_stats(&work_dir).await?;
        }
        Commands::Health => {
            run_health(&work_dir).await?;
        }
        Commands::Config { show, reset } => {
            run_config(&work_dir, *show, *reset).await?;
        }
    }

    Ok(())
}

// ─── serve 模式：完整 library 服务 ───────────────────────────────────────

async fn run_serve(
    work_dir: &std::path::Path,
    host_override: Option<String>,
    port_override: Option<u16>,
) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;
    let mut config = boot.config.clone();

    // 应用命令行覆盖
    if let Some(host) = host_override {
        config.server.listen = host;
    }
    if let Some(port) = port_override {
        config.server.port = port;
    }

    info!("========================================");
    info!("PeerDiscoveryCenter v{} 启动 (serve 模式)", VERSION);
    info!("========================================");
    info!(
        "[serve] 配置: 监听 {}:{}, 超级Tracker={}, 爬虫={}",
        config.server.listen,
        config.server.port,
        config.super_tracker.enabled,
        config.crawler.enabled
    );

    // 创建核心组件
    let event_bus = EventBus::new(4096);
    let registry = Arc::new(DiscovererRegistry::new());
    let control_plane = ControlPlane::new(config.clone(), registry.clone(), event_bus.clone());
    control_plane.init_default_discoverers();
    info!("[serve] 已注册 {} 个发现器", control_plane.registry().len());

    let cache = Arc::new(PeerCache::new(
        config.cache.max_cached_peers,
        Duration::from_secs(config.cache.peer_ttl_secs),
    ));

    let super_tracker = Arc::new(SuperTrackerState::new(config.super_tracker.clone()));

    // NAT / UPnP
    let nat = Arc::new(NatManager::new(
        config.nat.enabled,
        config.nat.lease_duration,
    ));
    let udp_port = config.super_tracker.udp_port.unwrap_or(config.server.port);
    let crawler_port = if config.crawler.enabled {
        config.crawler.listen_port
    } else {
        0
    };
    if let Err(e) = nat.init(config.server.port, udp_port, crawler_port).await {
        warn!("[serve] NAT/UPnP 初始化失败: {}", e);
    } else if config.nat.enabled {
        let status = nat.status();
        if let Some(ip) = &status.external_ip {
            info!("[serve] 公网访问地址: http://{}:{}", ip, config.server.port);
        }
    }

    let app_state = AppState {
        control_plane: control_plane.clone(),
        super_tracker: super_tracker.clone(),
        cache: cache.clone(),
        event_bus: event_bus.clone(),
        config: Arc::new(RwLock::new(config.clone())),
        nat: nat.clone(),
    };

    // 健康检查任务
    let hc_config = HealthCheckConfig {
        interval: Duration::from_secs(config.health_check.interval_secs),
        cache_cleanup_interval: Duration::from_secs(
            config.health_check.cache_cleanup_interval_secs,
        ),
        stats_output_interval: Duration::from_secs(config.health_check.stats_output_interval_secs),
    };
    let health_check = Arc::new(HealthCheckTask::new(
        registry.clone(),
        cache.clone(),
        hc_config,
    ));
    tokio::spawn(async move {
        health_check.run().await;
    });
    info!("[serve] 健康检查任务已启动");

    // 爬虫引擎
    if config.crawler.enabled {
        let crawler = CrawlerEngine::new(config.crawler.clone(), event_bus.clone());
        if let Err(e) = crawler.start().await {
            warn!("[serve] 爬虫引擎启动失败: {}", e);
        } else {
            info!("[serve] 爬虫引擎已启动");
        }
    }

    // UDP Tracker
    if config.super_tracker.enabled {
        let udp_state = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = DataPlane::serve_udp(udp_state).await {
                warn!("[serve] UDP Tracker 服务异常: {}", e);
            }
        });
        info!(
            "[serve] UDP Tracker: udp://{}:{}",
            config.server.listen, udp_port
        );
    }

    // HTTP 服务（阻塞）
    info!(
        "[serve] HTTP 服务: http://{}:{}",
        config.server.listen, config.server.port
    );
    DataPlane::serve(app_state).await?;

    Ok(())
}

// ─── agent 模式：接入 PK 主控 ────────────────────────────────────────────

async fn run_agent(
    work_dir: &std::path::Path,
    master: Option<String>,
    token: Option<String>,
    name: Option<String>,
) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&boot.dirs.history_file)?;
    info!("[agent] 启动 agent 模式，node_id={}", boot.identity.node_id);
    agent::run_agent(boot, history, master, token, name).await?;
    Ok(())
}

// ─── discover 子命令：一次性发现 ─────────────────────────────────────────

async fn run_discover(
    work_dir: &std::path::Path,
    infohash_str: &str,
    limit: usize,
    format: &str,
) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&boot.dirs.history_file)?;
    let config = &boot.config;

    // 验证 infohash 格式
    if infohash_str.len() != 40 {
        return Err(anyhow::anyhow!(
            "infohash 必须是 40 字符的 hex 编码，当前长度: {}",
            infohash_str.len()
        ));
    }
    let bytes = hex::decode(infohash_str)?;
    let infohash: Infohash = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("infohash 转换失败"))?;

    info!("[discover] infohash={}, limit={}", infohash_str, limit);

    // 设置最小发现栈
    let event_bus = EventBus::new(4096);
    let registry = Arc::new(DiscovererRegistry::new());
    let control_plane = ControlPlane::new(config.clone(), registry.clone(), event_bus.clone());
    control_plane.init_default_discoverers();

    let agg_config = PeerDiscoveryConfig {
        max_cached_peers: config.cache.max_cached_peers,
        peer_ttl: Duration::from_secs(config.cache.peer_ttl_secs),
        discovery_timeout: Duration::from_secs(config.discoverers.discovery_timeout_secs),
        max_concurrent_discoverers: config.discoverers.max_concurrent,
        max_peers_per_discovery: config.cache.max_peers_per_discovery,
    };
    let aggregator = PeerDiscoveryAggregator::new(agg_config, registry.clone(), event_bus.clone());

    let result = aggregator.discover_peers(&infohash, limit).await?;

    // 写入历史
    let source_stats: std::collections::HashMap<String, usize> = result
        .source_stats
        .iter()
        .map(|(k, v)| (format!("{:?}", k), *v))
        .collect();
    let record = history::DiscoveryHistoryRecord::new(
        infohash_str.to_string(),
        result.peers.len(),
        source_stats.clone(),
        result.total_duration.as_millis() as u64,
        true,
        None,
    );
    history.append(&record)?;

    // 输出
    match format {
        "json" => {
            let peers: Vec<protocol::PeerResponse> = result
                .peers
                .iter()
                .map(|p| protocol::PeerResponse {
                    addr: p.addr.to_string(),
                    source: format!("{:?}", p.source),
                    priority_score: p.priority_score,
                    is_ipv6: p.addr.is_ipv6(),
                })
                .collect();
            let resp = protocol::DiscoverResponse {
                peers_count: peers.len(),
                peers,
                duration_ms: result.total_duration.as_millis() as u64,
                source_stats,
            };
            println!("{}", serde_json::to_string_pretty(&resp)?); // panda-allow: cli-output
        }
        _ => {
            println!("发现完成:"); // panda-allow: cli-output
            println!("  infohash: {}", infohash_str); // panda-allow: cli-output
            println!("  peer 数量: {}", result.peers.len()); // panda-allow: cli-output
            println!("  耗时: {}ms", result.total_duration.as_millis()); // panda-allow: cli-output
            println!("  来源统计: {:?}", source_stats); // panda-allow: cli-output
            for p in &result.peers {
                let line = format!(
                    "    {} (source={:?}, score={})",
                    p.addr, p.source, p.priority_score
                );
                println!("{}", line); // panda-allow: cli-output
            }
        }
    }

    Ok(())
}

// ─── peers 子命令：查看历史记录 ──────────────────────────────────────────

async fn run_peers(
    work_dir: &std::path::Path,
    infohash: Option<&str>,
    limit: usize,
) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&boot.dirs.history_file)?;
    let recent = history.read_recent(limit)?;

    println!("最近的发现记录（最多 {} 条）:", limit); // panda-allow: cli-output
    for record in &recent {
        if let Some(ih) = infohash {
            if record.infohash != ih {
                continue;
            }
        }
        let line = format!(
            "  [{}] infohash={}, peers={}, duration={}ms, success={}",
            record.timestamp,
            record.infohash,
            record.peers_count,
            record.duration_ms,
            record.success
        );
        println!("{}", line); // panda-allow: cli-output
    }

    Ok(())
}

// ─── stats 子命令：统计信息 ──────────────────────────────────────────────

async fn run_stats(work_dir: &std::path::Path) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&boot.dirs.history_file)?;

    let total = history.count()?;
    let recent = history.read_recent(100)?;
    let success_count = recent.iter().filter(|r| r.success).count();
    let avg_duration = if recent.is_empty() {
        0.0
    } else {
        recent.iter().map(|r| r.duration_ms as f64).sum::<f64>() / recent.len() as f64
    };
    let total_peers: u64 = recent.iter().map(|r| r.peers_count as u64).sum();

    println!("PDC 统计信息:"); // panda-allow: cli-output
    println!("  历史记录总数: {}", total); // panda-allow: cli-output
    let success_rate = if recent.is_empty() {
        0.0
    } else {
        success_count as f64 / recent.len() as f64 * 100.0
    };
    println!("  最近 100 次成功率: {:.1}%", success_rate); // panda-allow: cli-output
    println!("  最近 100 次平均耗时: {:.1}ms", avg_duration); // panda-allow: cli-output
    println!("  最近 100 次总发现 peer 数: {}", total_peers); // panda-allow: cli-output

    Ok(())
}

// ─── health 子命令：健康检查 ─────────────────────────────────────────────

async fn run_health(work_dir: &std::path::Path) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;

    println!("PDC 健康检查:"); // panda-allow: cli-output
    println!("  状态: ok"); // panda-allow: cli-output
    println!("  节点 ID: {}", boot.identity.node_id); // panda-allow: cli-output
    println!("  配置文件: {}", boot.dirs.config_file.display()); // panda-allow: cli-output
    println!("  历史文件: {}", boot.dirs.history_file.display()); // panda-allow: cli-output
    let serve_addr = format!("{}:{}", boot.config.server.listen, boot.config.server.port);
    println!("  serve 监听: {}", serve_addr); // panda-allow: cli-output
    let agent_status = if boot.config.agent.enabled {
        "enabled"
    } else {
        "disabled"
    };
    println!("  agent 模式: {}", agent_status); // panda-allow: cli-output

    Ok(())
}

// ─── config 子命令：查看/重置配置 ────────────────────────────────────────

async fn run_config(work_dir: &std::path::Path, show: bool, reset: bool) -> anyhow::Result<()> {
    let boot = bootstrap::Bootstrap::run(work_dir)?;

    if reset {
        let default = PdcConfig::default_config();
        default.save(&boot.dirs.config_file)?;
        println!("配置已重置为默认值: {}", boot.dirs.config_file.display()); // panda-allow: cli-output
        return Ok(());
    }

    if show {
        let yaml = boot.config.to_yaml()?;
        println!("{}", yaml); // panda-allow: cli-output
    } else {
        println!("配置文件路径: {}", boot.dirs.config_file.display()); // panda-allow: cli-output
        println!("使用 --show 查看当前配置，使用 --reset 重置为默认配置"); // panda-allow: cli-output
    }

    Ok(())
}
