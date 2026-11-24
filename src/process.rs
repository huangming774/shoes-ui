use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;

use crate::db::Database;
use crate::yaml_gen::sync_and_apply_config;

const MAX_LOG_LINES: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    pub time: String,
    pub stream: &'static str,
    pub line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub started_at: Option<i64>,
    pub version: String,
    pub bin_path: String,
    pub bin_exists: bool,
    pub last_error: Option<String>,
}

struct LogBuffer {
    next_seq: u64,
    entries: VecDeque<LogEntry>,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self {
            next_seq: 1,
            entries: VecDeque::with_capacity(MAX_LOG_LINES),
        }
    }
}

pub struct ShoesProcessManager {
    db: Arc<Database>,
    child: AsyncMutex<Option<Child>>,
    started_at: Mutex<Option<i64>>,
    last_error: Mutex<Option<String>>,
    cached_version: Mutex<Option<(String, String)>>, // (bin_path, version_str)
    desired_running: AtomicBool,
    logs: Arc<Mutex<LogBuffer>>,
}

impl ShoesProcessManager {
    pub fn new(db: Arc<Database>) -> Arc<Self> {
        let mgr = Arc::new(Self {
            db,
            child: AsyncMutex::new(None),
            started_at: Mutex::new(None),
            last_error: Mutex::new(None),
            cached_version: Mutex::new(None),
            desired_running: AtomicBool::new(false),
            logs: Arc::new(Mutex::new(LogBuffer::default())),
        });
        Self::spawn_watchdog(mgr.clone());
        mgr
    }

    pub fn push_panel_log(&self, msg: impl Into<String>) {
        Self::push_log(&self.logs, "panel", msg.into());
    }

    fn push_log(logs: &Mutex<LogBuffer>, stream: &'static str, line: String) {
        let mut guard = logs.lock();
        let seq = guard.next_seq;
        guard.next_seq += 1;
        if guard.entries.len() >= MAX_LOG_LINES {
            guard.entries.pop_front();
        }
        guard.entries.push_back(LogEntry {
            seq,
            time: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            stream,
            line,
        });
    }

    pub fn get_logs(&self, since_seq: u64, limit: usize) -> Vec<LogEntry> {
        let guard = self.logs.lock();
        let cap = limit.clamp(1, MAX_LOG_LINES);
        let filtered: Vec<LogEntry> = guard
            .entries
            .iter()
            .filter(|e| e.seq > since_seq)
            .cloned()
            .collect();
        if filtered.len() > cap {
            filtered[filtered.len() - cap..].to_vec()
        } else {
            filtered
        }
    }

    pub fn clear_logs(&self) {
        self.logs.lock().entries.clear();
    }

    pub async fn current_pid(&self) -> Option<u32> {
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(None) => return child.id(),
                Ok(Some(code)) => {
                    Self::push_log(
                        &self.logs,
                        "panel",
                        format!("shoes process exited with status: {code}"),
                    );
                    *guard = None;
                    *self.started_at.lock() = None;
                }
                Err(_) => {
                    *guard = None;
                    *self.started_at.lock() = None;
                }
            }
        }
        None
    }

    pub async fn query_version(&self, bin_path: &str) -> String {
        let trimmed = bin_path.trim();
        if let Some((cached_bin, cached_ver)) = self.cached_version.lock().clone() {
            if cached_bin == trimmed && !cached_ver.is_empty() {
                return cached_ver;
            }
        }
        let p = PathBuf::from(trimmed);
        if !p.exists() {
            return "not found".to_string();
        }
        match Command::new(&p).arg("-V").output().await {
            Ok(out) if out.status.success() => {
                let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let ver = if v.is_empty() {
                    String::from_utf8_lossy(&out.stderr).trim().to_string()
                } else {
                    v
                };
                *self.cached_version.lock() = Some((trimmed.to_string(), ver.clone()));
                ver
            }
            _ => "unknown".to_string(),
        }
    }

    pub async fn status(&self) -> ProcessStatus {
        let settings = self.db.get_settings().ok();
        let bin_path = settings
            .as_ref()
            .map(|s| s.shoes_bin_path.clone())
            .unwrap_or_default();
        let bin_exists = PathBuf::from(bin_path.trim()).exists();
        let pid = self.current_pid().await;
        let version = self.query_version(&bin_path).await;
        let started_at = *self.started_at.lock();
        let last_error = self.last_error.lock().clone();

        ProcessStatus {
            running: pid.is_some(),
            pid,
            started_at,
            version,
            bin_path,
            bin_exists,
            last_error,
        }
    }

    pub async fn start(&self) -> Result<ProcessStatus> {
        self.desired_running.store(true, Ordering::SeqCst);
        if self.current_pid().await.is_some() {
            return Ok(self.status().await);
        }

        let settings = self.db.get_settings()?;
        let bin = PathBuf::from(settings.shoes_bin_path.trim());
        if !bin.exists() {
            let err = format!(
                "shoes binary not found at '{}'. Configure shoes_bin_path in Panel Settings.",
                bin.display()
            );
            *self.last_error.lock() = Some(err.clone());
            Self::push_log(&self.logs, "panel", err.clone());
            return Err(anyhow!(err));
        }

        // Always sync and validate config before starting
        sync_and_apply_config(&self.db, None).await?;

        let cfg_path = PathBuf::from(settings.shoes_config_path.trim());
        let mut cmd = Command::new(&bin);
        cmd.arg(&cfg_path)
            .env("RUST_LOG", std::env::var("SHOES_LOG").unwrap_or_else(|_| "info".to_string()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn shoes binary '{}'", bin.display()))?;

        let pid = child.id().unwrap_or(0);
        Self::push_log(
            &self.logs,
            "panel",
            format!("Started shoes (PID {pid}) with config {}", cfg_path.display()),
        );

        if let Some(stdout) = child.stdout.take() {
            let logs = self.logs.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::push_log(&logs, "stdout", line);
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let logs = self.logs.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::push_log(&logs, "stderr", line);
                }
            });
        }

        *self.started_at.lock() = Some(Utc::now().timestamp_millis());
        *self.last_error.lock() = None;
        *self.child.lock().await = Some(child);

        // Wait briefly to catch immediate bind/startup errors
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if self.current_pid().await.is_none() {
            let msg = "shoes exited immediately after startup; check live logs for details".to_string();
            *self.last_error.lock() = Some(msg.clone());
            return Err(anyhow!(msg));
        }

        Ok(self.status().await)
    }

    pub async fn stop(&self) -> Result<ProcessStatus> {
        self.desired_running.store(false, Ordering::SeqCst);
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            let pid = child.id().unwrap_or(0);
            let _ = child.kill().await;
            let _ = child.wait().await;
            Self::push_log(&self.logs, "panel", format!("Stopped shoes (PID {pid})"));
        }
        *self.started_at.lock() = None;
        drop(guard);
        Ok(self.status().await)
    }

    pub async fn restart(&self) -> Result<ProcessStatus> {
        let _ = self.stop().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.start().await
    }

    pub async fn reload_config(&self) -> Result<String> {
        let pid = self.current_pid().await;
        let yaml = sync_and_apply_config(&self.db, pid).await?;
        Self::push_log(
            &self.logs,
            "panel",
            if pid.is_some() {
                "Validated and applied updated shoes configuration (hot reload triggered)".to_string()
            } else {
                "Validated and saved shoes configuration (shoes is currently stopped)".to_string()
            },
        );
        Ok(yaml)
    }

    fn spawn_watchdog(mgr: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(4));
            loop {
                interval.tick().await;
                if !mgr.desired_running.load(Ordering::SeqCst) {
                    continue;
                }
                if mgr.current_pid().await.is_none() {
                    let settings = match mgr.db.get_settings() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if !PathBuf::from(settings.shoes_bin_path.trim()).exists() {
                        continue;
                    }
                    Self::push_log(
                        &mgr.logs,
                        "panel",
                        "Watchdog detected shoes is not running; attempting automatic restart..."
                            .to_string(),
                    );
                    if let Err(e) = mgr.start().await {
                        *mgr.last_error.lock() = Some(e.to_string());
                    }
                }
            }
        });
    }
}
