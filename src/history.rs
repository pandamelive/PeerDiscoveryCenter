//! 发现历史流水记录
//!
//! 以 JSONL 格式记录每次发现任务的结果，用于审计和分析。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

/// 单次发现任务的历史记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryHistoryRecord {
    /// 记录 ID
    pub id: Uuid,
    /// 任务 ID（Agent 模式下由主控分配）
    pub task_id: Option<Uuid>,
    /// 目标 infohash
    pub infohash: String,
    /// 发现的 peer 数量
    pub peers_count: usize,
    /// 各来源统计
    pub source_stats: std::collections::HashMap<String, usize>,
    /// 耗时（毫秒）
    pub duration_ms: u64,
    /// 是否成功
    pub success: bool,
    /// 错误消息（失败时）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_msg: Option<String>,
    /// 时间戳
    pub timestamp: String,
}

impl DiscoveryHistoryRecord {
    /// 创建新记录
    pub fn new(
        infohash: String,
        peers_count: usize,
        source_stats: std::collections::HashMap<String, usize>,
        duration_ms: u64,
        success: bool,
        error_msg: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            task_id: None,
            infohash,
            peers_count,
            source_stats,
            duration_ms,
            success,
            error_msg,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// 历史记录写入器
pub struct HistoryWriter {
    file_path: std::path::PathBuf,
    file: Mutex<std::fs::File>,
}

impl HistoryWriter {
    /// 打开或创建历史记录文件
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("打开历史记录文件失败: {}", path.display()))?;
        Ok(Self {
            file_path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    /// 追加一条记录
    pub fn append(&self, record: &DiscoveryHistoryRecord) -> Result<()> {
        let json = serde_json::to_string(record)?;
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json)?;
        file.flush()?;
        Ok(())
    }

    /// 读取最近 N 条记录
    pub fn read_recent(&self, limit: usize) -> Result<Vec<DiscoveryHistoryRecord>> {
        let content =
            std::fs::read_to_string(&self.file_path).with_context(|| "读取历史记录文件失败")?;
        let mut records: Vec<DiscoveryHistoryRecord> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        // 按时间倒序
        records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        records.truncate(limit);
        Ok(records)
    }

    /// 获取记录总数
    pub fn count(&self) -> Result<usize> {
        let content = std::fs::read_to_string(&self.file_path)?;
        Ok(content.lines().count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn history_record_new() {
        let mut stats = HashMap::new();
        stats.insert("tracker".to_string(), 10);
        let record = DiscoveryHistoryRecord::new("abc".to_string(), 10, stats, 100, true, None);
        assert_eq!(record.infohash, "abc");
        assert_eq!(record.peers_count, 10);
        assert!(record.success);
        assert!(!record.timestamp.is_empty());
    }

    #[test]
    fn history_writer_append_and_read() {
        let dir = std::env::temp_dir().join(format!("pdc-test-{}", Uuid::new_v4()));
        let path = dir.join("test-history.jsonl");

        let writer = HistoryWriter::open(&path).unwrap();
        let record1 =
            DiscoveryHistoryRecord::new("hash1".to_string(), 5, HashMap::new(), 50, true, None);
        let record2 =
            DiscoveryHistoryRecord::new("hash2".to_string(), 10, HashMap::new(), 100, true, None);
        writer.append(&record1).unwrap();
        writer.append(&record2).unwrap();

        assert_eq!(writer.count().unwrap(), 2);

        let recent = writer.read_recent(10).unwrap();
        assert_eq!(recent.len(), 2);

        // 清理
        let _ = std::fs::remove_dir_all(&dir);
    }
}
