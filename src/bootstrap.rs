//! 启动自检与初始化
//!
//! 负责创建工作目录、生成 node-id、初始化配置模板。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// 节点持久化标识
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// 节点唯一 ID
    pub node_id: Uuid,
    /// 创建时间
    pub created_at: String,
}

impl NodeIdentity {
    /// 生成新的节点标识
    pub fn new() -> Self {
        Self {
            node_id: Uuid::new_v4(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for NodeIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// 工作目录结构
pub struct WorkDirs {
    /// 根目录
    pub root: PathBuf,
    /// 配置目录
    pub config: PathBuf,
    /// 数据目录
    pub data: PathBuf,
    /// 配置文件路径
    pub config_file: PathBuf,
    /// node-id 文件路径
    pub node_id_file: PathBuf,
    /// 发现历史流水文件路径
    pub history_file: PathBuf,
}

impl WorkDirs {
    /// 基于根目录构建所有子目录路径
    pub fn new(root: &Path) -> Self {
        let config = root.join("config");
        let data = root.join("data");
        Self {
            root: root.to_path_buf(),
            config: config.clone(),
            data: data.clone(),
            config_file: config.join("config.yaml"),
            node_id_file: data.join("node-id.json"),
            history_file: data.join("discovery-history.jsonl"),
        }
    }

    /// 创建所有目录
    pub fn create_all(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config)
            .with_context(|| format!("创建配置目录失败: {}", self.config.display()))?;
        std::fs::create_dir_all(&self.data)
            .with_context(|| format!("创建数据目录失败: {}", self.data.display()))?;
        Ok(())
    }
}

/// 启动自检结果
pub struct Bootstrap {
    /// 工作目录
    pub dirs: WorkDirs,
    /// 节点标识
    pub identity: NodeIdentity,
    /// 配置（从文件加载或生成默认）
    pub config: crate::config::PdcConfig,
}

impl Bootstrap {
    /// 执行启动自检
    pub fn run(work_dir: &Path) -> Result<Self> {
        let dirs = WorkDirs::new(work_dir);
        dirs.create_all()?;

        // 加载或生成 node-id
        let identity = if dirs.node_id_file.exists() {
            let content = std::fs::read_to_string(&dirs.node_id_file)
                .with_context(|| "读取 node-id 文件失败")?;
            serde_json::from_str(&content).unwrap_or_else(|_| {
                tracing::warn!("node-id 文件解析失败，重新生成");
                let id = NodeIdentity::new();
                let _ = save_identity(&dirs.node_id_file, &id);
                id
            })
        } else {
            let id = NodeIdentity::new();
            save_identity(&dirs.node_id_file, &id)?;
            tracing::info!("生成新的 node-id: {}", id.node_id);
            id
        };

        // 加载或生成默认配置
        let config = if dirs.config_file.exists() {
            crate::config::PdcConfig::load(&dirs.config_file)?
        } else {
            let default = crate::config::PdcConfig::default_config();
            default.save(&dirs.config_file)?;
            tracing::info!("生成默认配置文件: {}", dirs.config_file.display());
            default
        };

        Ok(Self {
            dirs,
            identity,
            config,
        })
    }
}

fn save_identity(path: &Path, identity: &NodeIdentity) -> Result<()> {
    let json = serde_json::to_string_pretty(identity)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// 获取主机名
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "pdc-node".to_string())
}

/// 获取平台信息
pub fn platform_info() -> (String, String) {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    (os.to_string(), arch.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_identity_new() {
        let id = NodeIdentity::new();
        assert!(!id.node_id.to_string().is_empty());
        assert!(!id.created_at.is_empty());
    }

    #[test]
    fn work_dirs_structure() {
        let dirs = WorkDirs::new(Path::new("/tmp/pdc-test"));
        assert_eq!(
            dirs.config_file,
            Path::new("/tmp/pdc-test/config/config.yaml")
        );
        assert_eq!(
            dirs.node_id_file,
            Path::new("/tmp/pdc-test/data/node-id.json")
        );
        assert_eq!(
            dirs.history_file,
            Path::new("/tmp/pdc-test/data/discovery-history.jsonl")
        );
    }
}
