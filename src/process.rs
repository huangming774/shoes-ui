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
use crate::models::PanelSettings;
use crate::yaml_gen::{sync_and_apply_config, validated_config};

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
    pub(crate) operation: AsyncMutex<()>,
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
            operation: AsyncMutex::new(()),
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
        let _operation = self.operation.lock().await;
        self.start_locked().await
    }

    async fn start_locked(&self) -> Result<ProcessStatus> {
        self.desired_running.store(true, Ordering::SeqCst);
        if self.current_pid().await.is_some() {
            return Ok(self.status().await);
        }

        let settings = self.db.get_settings()?;
        sync_and_apply_config(&self.db, None).await?;
        self.launch(&settings).await?;
        Ok(self.status().await)
    }

    async fn launch(&self, settings: &PanelSettings) -> Result<()> {
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

        Ok(())
    }

    pub async fn stop(&self) -> Result<ProcessStatus> {
        let _operation = self.operation.lock().await;
        self.desired_running.store(false, Ordering::SeqCst);
        self.stop_child().await?;
        Ok(self.status().await)
    }

    async fn stop_child(&self) -> Result<()> {
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            let pid = child.id().unwrap_or(0);
            if child.try_wait()?.is_none() {
                child.kill().await?;
            }
            *guard = None;
            Self::push_log(&self.logs, "panel", format!("Stopped shoes (PID {pid})"));
        }
        *self.started_at.lock() = None;
        Ok(())
    }

    pub async fn restart(&self) -> Result<ProcessStatus> {
        let _operation = self.operation.lock().await;
        self.stop_child().await?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.start_locked().await
    }

    pub async fn reload_config(&self) -> Result<String> {
        let _operation = self.operation.lock().await;
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

    // Caller holds operation until the new base path has also been published.
    pub(crate) async fn apply_settings(&self, candidate: &PanelSettings) -> Result<()> {
        crate::db::validated_base_path(&candidate.panel_base_path)?;
        candidate.listen_addr()?;
        anyhow::ensure!(candidate.panel_port > 0, "Panel port must be positive");
        anyhow::ensure!(
            candidate.session_ttl_hours > 0,
            "Session duration must be at least one hour"
        );
        let cert = candidate.panel_cert_file.trim();
        let key = candidate.panel_key_file.trim();
        anyhow::ensure!(
            cert.is_empty() == key.is_empty(),
            "Provide both the panel TLS certificate and key, or clear both"
        );

        let old = self.db.get_settings()?;
        if !cert.is_empty() && (cert != old.panel_cert_file || key != old.panel_key_file) {
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("Failed to load panel TLS certificate and key")?;
        }
        let yaml = validated_config(&self.db, candidate).await?;
        let path = std::path::Path::new(candidate.shoes_config_path.trim());
        let previous = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("Cannot read {}", path.display())),
        };
        let changed = previous.as_deref() != Some(yaml.as_bytes());
        // Controller credentials and some extra YAML settings are startup-only in Shoes.
        // A settings save that changes the rendered config must use the new config at launch.
        let restart = self.current_pid().await.is_some()
            && (changed
                || old.shoes_config_path != candidate.shoes_config_path.trim()
                || old.shoes_bin_path != candidate.shoes_bin_path.trim());
        if restart {
            anyhow::ensure!(
                std::path::Path::new(candidate.shoes_bin_path.trim()).is_file(),
                "Shoes executable not found"
            );
            self.stop_child().await?;
        }

        let applied = async {
            if changed {
                std::fs::write(path, &yaml)
                    .with_context(|| format!("Cannot write {}", path.display()))?;
            }
            if restart {
                self.launch(candidate).await?;
            }
            self.db.save_settings(candidate)
        }
        .await;
        if let Err(error) = applied {
            let restored: Result<()> = async {
                if restart {
                    self.stop_child().await?;
                }
                if changed {
                    if let Some(bytes) = previous {
                        if std::fs::read(path).ok().as_ref() != Some(&bytes) {
                            std::fs::write(path, bytes)?;
                        }
                    } else if path.exists() {
                        std::fs::remove_file(path)?;
                    }
                }
                if restart {
                    self.launch(&old).await?;
                }
                Ok(())
            }
            .await;
            if let Err(rollback) = restored {
                anyhow::bail!(
                    "{error:#}; restoring the previous configuration failed: {rollback:#}"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    fn spawn_watchdog(mgr: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(4));
            loop {
                interval.tick().await;
                let _operation = mgr.operation.lock().await;
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
                    if let Err(e) = mgr.start_locked().await {
                        *mgr.last_error.lock() = Some(e.to_string());
                    }
                }
            }
        });
    }
}
