//! Prometheus 指标收集
//!
//! 暴露 PDC 运行时指标，供 Prometheus 抓取。

use prometheus::{Encoder, IntCounter, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::OnceLock;

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

fn register_gauge(name: &str, help: &str) -> IntGauge {
    let g = IntGauge::new(name, help).unwrap();
    registry().register(Box::new(g.clone())).unwrap();
    g
}

fn register_counter(name: &str, help: &str) -> IntCounter {
    let c = IntCounter::new(name, help).unwrap();
    registry().register(Box::new(c.clone())).unwrap();
    c
}

// Gauges
static DHT_NODES_G: OnceLock<IntGauge> = OnceLock::new();
pub fn dht_nodes() -> &'static IntGauge {
    DHT_NODES_G.get_or_init(|| register_gauge("pdc_dht_nodes_total", "DHT 路由表节点总数"))
}

static DHT_INFOHASHES_G: OnceLock<IntGauge> = OnceLock::new();
pub fn dht_infohashes() -> &'static IntGauge {
    DHT_INFOHASHES_G
        .get_or_init(|| register_gauge("pdc_dht_infohashes_total", "DHT 存储的 infohash 总数"))
}

static DHT_PEERS_G: OnceLock<IntGauge> = OnceLock::new();
pub fn dht_peers() -> &'static IntGauge {
    DHT_PEERS_G.get_or_init(|| register_gauge("pdc_dht_peers_total", "DHT 存储的 peer 总数"))
}

static TRACKER_PEERS_G: OnceLock<IntGauge> = OnceLock::new();
pub fn tracker_peers() -> &'static IntGauge {
    TRACKER_PEERS_G
        .get_or_init(|| register_gauge("pdc_tracker_peers_total", "超级 Tracker 存储的 peer 总数"))
}

static TRACKER_INFOHASHES_G: OnceLock<IntGauge> = OnceLock::new();
pub fn tracker_infohashes() -> &'static IntGauge {
    TRACKER_INFOHASHES_G.get_or_init(|| {
        register_gauge(
            "pdc_tracker_infohashes_total",
            "超级 Tracker 存储的 infohash 总数",
        )
    })
}

static CACHE_PEERS_G: OnceLock<IntGauge> = OnceLock::new();
pub fn cache_peers() -> &'static IntGauge {
    CACHE_PEERS_G.get_or_init(|| register_gauge("pdc_cache_peers_total", "Peer 缓存总数"))
}

static CACHE_INFOHASHES_G: OnceLock<IntGauge> = OnceLock::new();
pub fn cache_infohashes() -> &'static IntGauge {
    CACHE_INFOHASHES_G
        .get_or_init(|| register_gauge("pdc_cache_infohashes_total", "Peer 缓存 infohash 数"))
}

static BANNED_PEERS_G: OnceLock<IntGauge> = OnceLock::new();
pub fn banned_peers() -> &'static IntGauge {
    BANNED_PEERS_G.get_or_init(|| register_gauge("pdc_banned_peers_total", "当前封禁的 peer 数"))
}

// Counters
static CRAWLER_INFOHASHES_C: OnceLock<IntCounter> = OnceLock::new();
pub fn crawler_infohashes() -> &'static IntCounter {
    CRAWLER_INFOHASHES_C.get_or_init(|| {
        register_counter(
            "pdc_crawler_infohashes_collected_total",
            "爬虫收集的 infohash 累计数",
        )
    })
}

static CRAWLER_PEERS_C: OnceLock<IntCounter> = OnceLock::new();
pub fn crawler_peers() -> &'static IntCounter {
    CRAWLER_PEERS_C.get_or_init(|| {
        register_counter(
            "pdc_crawler_peers_collected_total",
            "爬虫收集的 peer 累计数",
        )
    })
}

// GaugeVec
static HTTP_REQUESTS_GV: OnceLock<IntGaugeVec> = OnceLock::new();
pub fn http_requests() -> &'static IntGaugeVec {
    HTTP_REQUESTS_GV.get_or_init(|| {
        let g = IntGaugeVec::new(
            Opts::new("pdc_http_requests_total", "HTTP 请求总数"),
            &["endpoint", "status"],
        )
        .unwrap();
        registry().register(Box::new(g.clone())).unwrap();
        g
    })
}

/// 收集指标并序列化为 Prometheus 文本格式
pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_gather() {
        dht_nodes().set(100);
        dht_infohashes().set(50);
        dht_peers().set(200);

        let output = gather();
        assert!(output.contains("pdc_dht_nodes_total 100"));
        assert!(output.contains("pdc_dht_infohashes_total 50"));
        assert!(output.contains("pdc_dht_peers_total 200"));
    }

    #[test]
    fn test_counters() {
        let before = crawler_infohashes().get();
        crawler_infohashes().inc();
        crawler_infohashes().inc_by(5);
        assert_eq!(crawler_infohashes().get(), before + 6);
    }

    #[test]
    fn test_http_requests_labels() {
        http_requests()
            .with_label_values(&["/announce", "200"])
            .inc();
        http_requests().with_label_values(&["/scrape", "200"]).inc();

        let output = gather();
        assert!(output.contains("pdc_http_requests_total"));
        assert!(output.contains("/announce"));
        assert!(output.contains("/scrape"));
    }
}
