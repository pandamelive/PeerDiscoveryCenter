//! DHT 发现机制
//!
//! 通过 BitTorrent DHT（分布式哈希表）发现 peer。
//!
//! 支持：
//! - Kademlia 路由表
//! - Bootstrap 节点启动
//! - 路由表自动刷新
//! - 路由表持久化
//! - 节点健康检查和自动淘汰

pub mod client;
pub mod global_store;
pub mod message;
pub mod routing_table;
pub mod store;
pub mod token;

pub use client::{DhtConfig, DhtDiscoverer};
pub use global_store::{GlobalNodeStore, MultiNodeManager};
pub use routing_table::{CompactAddr, RoutingTable, generate_node_id, verify_node_id};

use std::io;
use tokio::net::UdpSocket;

/// UDP 接收缓冲区大小（16MB）
pub const UDP_RCVBUF_SIZE: usize = 16 * 1024 * 1024;

/// 创建并绑定 UDP socket，设置大接收缓冲区
///
/// 用于 DHT 高并发场景，避免内核缓冲区溢出丢包。
pub async fn bind_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(UDP_RCVBUF_SIZE)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.parse::<std::net::SocketAddr>().unwrap().into())?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// 常用 DHT Bootstrap 节点
pub const DHT_BOOTSTRAP_NODES: &[(&str, u16)] = &[
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.aelitis.com", 6881),     // Vuze
    ("router.bitcomet.com", 6881), // BitComet
    ("dht.libtorrent.org", 25401), // libtorrent
    // 国内可用的节点
    ("dht.cfcdn.club", 6881),
    ("tracker1.itzmx.com", 6881),
];
