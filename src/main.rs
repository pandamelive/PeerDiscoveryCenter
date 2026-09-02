//! PDC 程序入口
//!
//! 支持两种运行模式：
//! - `pdc serve` - 本地独立运行，提供 HTTP API
//! - `pdc agent` - 接入 PK 主控，接受任务派发

mod agent;
mod bootstrap;
mod cli;
mod config;
mod history;
mod protocol;
mod server;
mod service_resolver;

use clap::Parser;
use cli::{Cli, Commands};
use config::resolve_work_dir;
use std::path::PathBuf;

/// 程序版本（从 Cargo.toml 读取）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 初始化日志
    let log_level = cli.log_level.as_deref().unwrap_or("info");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    tracing::info!("PeerDiscoveryCenter v{}", VERSION);

    // 解析工作目录
    let work_dir = match &cli.work_dir {
        Some(dir) => dir.clone(),
        None => resolve_work_dir(None),
    };
    tracing::info!("工作目录: {}", work_dir.display());

    // 执行命令
    match &cli.command {
        Commands::Serve { host, port } => {
            run_serve(&work_dir, host.clone(), *port).await?;
        }
        Commands::Agent {
            master,
            token,
            name,
        } => {
            run_agent_cmd(&work_dir, master.clone(), token.clone(), name.clone()).await?;
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

/// 运行 serve 模式
async fn run_serve(
    work_dir: &PathBuf,
    host_override: Option<String>,
    port_override: Option<u16>,
) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;
    let mut config = bootstrap.config.clone();

    // 应用命令行覆盖
    if let Some(host) = host_override {
        config.server.host = host;
    }
    if let Some(port) = port_override {
        config.server.port = port;
    }

    let history = history::HistoryWriter::open(&bootstrap.dirs.history_file)?;

    tracing::info!("启动 serve 模式...");
    server::run_server(config, history).await?;

    Ok(())
}

/// 运行 agent 模式
async fn run_agent_cmd(
    work_dir: &PathBuf,
    master: Option<String>,
    token: Option<String>,
    name: Option<String>,
) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&bootstrap.dirs.history_file)?;

    agent::run_agent(bootstrap, history, master, token, name).await?;

    Ok(())
}

/// 运行一次性发现命令
async fn run_discover(
    work_dir: &PathBuf,
    infohash: &str,
    limit: usize,
    format: &str,
) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&bootstrap.dirs.history_file)?;

    tracing::info!("发现 peer: infohash={}, limit={}", infohash, limit);

    // 验证 infohash 格式
    if infohash.len() != 40 {
        return Err(anyhow::anyhow!(
            "infohash 必须是 40 字符的 hex 编码，当前长度: {}",
            infohash.len()
        ));
    }

    // TODO: 调用真实的 PeerDiscoveryAggregator
    // 目前输出模拟结果
    let result = protocol::DiscoverResponse {
        peers_count: 0,
        peers: vec![],
        duration_ms: 0,
        source_stats: std::collections::HashMap::new(),
    };

    // 写入历史
    let record = history::DiscoveryHistoryRecord::new(
        infohash.to_string(),
        result.peers_count,
        result.source_stats.clone(),
        result.duration_ms,
        true,
        None,
    );
    history.append(&record)?;

    // 输出结果
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            println!("发现完成:");
            println!("  infohash: {}", infohash);
            println!("  peer 数量: {}", result.peers_count);
            println!("  耗时: {}ms", result.duration_ms);
            println!("  来源统计: {:?}", result.source_stats);
        }
    }

    Ok(())
}

/// 运行查看缓存 peer 命令
async fn run_peers(work_dir: &PathBuf, infohash: Option<&str>, limit: usize) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&bootstrap.dirs.history_file)?;

    let recent = history.read_recent(limit)?;

    println!("最近的发现记录（最多 {} 条）:", limit);
    for record in &recent {
        if let Some(ih) = infohash {
            if record.infohash != ih {
                continue;
            }
        }
        println!(
            "  [{}] infohash={}, peers={}, duration={}ms, success={}",
            record.timestamp,
            record.infohash,
            record.peers_count,
            record.duration_ms,
            record.success
        );
    }

    Ok(())
}

/// 运行统计命令
async fn run_stats(work_dir: &PathBuf) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;
    let history = history::HistoryWriter::open(&bootstrap.dirs.history_file)?;

    let total = history.count()?;
    let recent = history.read_recent(100)?;

    let success_count = recent.iter().filter(|r| r.success).count();
    let avg_duration = if recent.is_empty() {
        0.0
    } else {
        recent.iter().map(|r| r.duration_ms as f64).sum::<f64>() / recent.len() as f64
    };
    let total_peers = recent.iter().map(|r| r.peers_count as u64).sum::<u64>();

    println!("PDC 统计信息:");
    println!("  历史记录总数: {}", total);
    println!(
        "  最近 100 次成功率: {:.1}%",
        success_count as f64 / recent.len() as f64 * 100.0
    );
    println!("  最近 100 次平均耗时: {:.1}ms", avg_duration);
    println!("  最近 100 次总发现 peer 数: {}", total_peers);

    Ok(())
}

/// 运行健康检查命令
async fn run_health(work_dir: &PathBuf) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;

    println!("PDC 健康检查:");
    println!("  状态: ok");
    println!("  节点 ID: {}", bootstrap.identity.node_id);
    println!("  配置文件: {}", bootstrap.dirs.config_file.display());
    println!("  历史文件: {}", bootstrap.dirs.history_file.display());
    println!(
        "  serve 模式: {}:{}",
        bootstrap.config.server.host, bootstrap.config.server.port
    );
    println!(
        "  agent 模式: {}",
        if bootstrap.config.agent.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    Ok(())
}

/// 运行配置命令
async fn run_config(work_dir: &PathBuf, show: bool, reset: bool) -> anyhow::Result<()> {
    let bootstrap = bootstrap::Bootstrap::run(work_dir)?;

    if reset {
        let default = config::PdcConfig::default_config();
        default.save(&bootstrap.dirs.config_file)?;
        println!(
            "配置已重置为默认值: {}",
            bootstrap.dirs.config_file.display()
        );
        return Ok(());
    }

    if show {
        let yaml = bootstrap.config.to_yaml()?;
        println!("{}", yaml);
    } else {
        println!("配置文件路径: {}", bootstrap.dirs.config_file.display());
        println!("使用 --show 查看当前配置，使用 --reset 重置为默认配置");
    }

    Ok(())
}
