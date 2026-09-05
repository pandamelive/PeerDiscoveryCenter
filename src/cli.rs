//! CLI 命令定义
//!
//! 使用 clap derive 宏定义命令行接口。

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// PeerDiscoveryCenter - 统一的 BitTorrent Peer 发现中心
#[derive(Debug, Parser)]
#[command(
    name = "pdc",
    version,
    about = "统一的 BitTorrent Peer 发现中心：Tracker + DHT + PEX 三合一"
)]
pub struct Cli {
    /// 工作目录（默认：二进制同级目录下的 pdc-node/）
    #[arg(short, long, global = true)]
    pub work_dir: Option<PathBuf>,

    /// 日志级别（debug/info/warn/error）
    #[arg(long, global = true)]
    pub log_level: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// 启动 serve 模式（本地独立运行，提供 HTTP API）
    Serve {
        /// 监听地址（覆盖配置文件）
        #[arg(long)]
        host: Option<String>,
        /// 监听端口（覆盖配置文件）
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// 启动 agent 模式（接入 PK 主控）
    Agent {
        /// 主控地址（如 http://127.0.0.1:5566，覆盖配置文件）
        #[arg(short, long)]
        master: Option<String>,
        /// 认证 Token（覆盖配置文件）
        #[arg(short, long)]
        token: Option<String>,
        /// 节点名称（覆盖配置文件）
        #[arg(short, long)]
        name: Option<String>,
    },

    /// 发现指定 infohash 的 peer（一次性命令）
    Discover {
        /// 目标 info_hash（hex 编码，40 字符）
        infohash: String,
        /// 返回 peer 数量上限
        #[arg(short, long, default_value_t = 100)]
        limit: usize,
        /// 输出格式（json/plain）
        #[arg(short, long, default_value = "plain")]
        format: String,
    },

    /// 查看缓存中的 peer
    Peers {
        /// 按 infohash 过滤（可选）
        infohash: Option<String>,
        /// 输出数量上限
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
    },

    /// 查看统计信息
    Stats,

    /// 健康检查
    Health,

    /// 查看或修改配置
    Config {
        /// 输出当前配置
        #[arg(short, long)]
        show: bool,
        /// 重置为默认配置
        #[arg(short, long)]
        reset: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_serve() {
        let cli = Cli::parse_from(["pdc", "serve", "--port", "9090"]);
        match cli.command {
            Commands::Serve { port, .. } => assert_eq!(port, Some(9090)),
            _ => panic!("expected serve command"),
        }
    }

    #[test]
    fn cli_parse_discover() {
        let cli = Cli::parse_from(["pdc", "discover", "abc123", "--limit", "50"]);
        match cli.command {
            Commands::Discover {
                infohash, limit, ..
            } => {
                assert_eq!(infohash, "abc123");
                assert_eq!(limit, 50);
            }
            _ => panic!("expected discover command"),
        }
    }

    #[test]
    fn cli_parse_agent() {
        let cli = Cli::parse_from([
            "pdc",
            "agent",
            "--master",
            "http://127.0.0.1:5566",
            "--token",
            "secret",
        ]);
        match cli.command {
            Commands::Agent { master, token, .. } => {
                assert_eq!(master, Some("http://127.0.0.1:5566".to_string()));
                assert_eq!(token, Some("secret".to_string()));
            }
            _ => panic!("expected agent command"),
        }
    }
}
