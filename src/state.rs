use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::SessionStore;
use crate::db::{normalize_base_path, Database};
use crate::monitor::RuntimeMonitor;
use crate::process::ShoesProcessManager;

pub struct AppState {
    pub db: Arc<Database>,
    pub proc_mgr: Arc<ShoesProcessManager>,
    pub monitor: Arc<RuntimeMonitor>,
    pub sessions: SessionStore,
    pub base_path: RwLock<String>,
    pub detected_public_ip: RwLock<String>,
}

impl AppState {
    pub fn new(
        db: Arc<Database>,
        proc_mgr: Arc<ShoesProcessManager>,
        monitor: Arc<RuntimeMonitor>,
    ) -> Arc<Self> {
        let bp = db
            .get_settings()
            .map(|s| normalize_base_path(&s.panel_base_path))
            .unwrap_or_else(|_| "/".to_string());
        let st = Arc::new(Self {
            db,
            proc_mgr,
            monitor,
            sessions: SessionStore::default(),
            base_path: RwLock::new(bp),
            detected_public_ip: RwLock::new(String::new()),
        });
        Self::spawn_public_ip_detector(st.clone());
        st
    }

    pub fn get_base_path(&self) -> String {
        self.base_path.read().clone()
    }

    pub fn set_base_path(&self, p: &str) {
        *self.base_path.write() = normalize_base_path(p);
    }

    pub fn get_detected_public_ip(&self) -> String {
        self.detected_public_ip.read().clone()
    }

    fn spawn_public_ip_detector(state: Arc<Self>) {
        tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(4))
                .no_proxy()
                .build()
            {
                Ok(c) => c,
                Err(_) => return,
            };

            let endpoints = [
                "https://4.ipw.cn",
                "https://api4.ipify.org",
                "https://ipv4.icanhazip.com",
                "https://ifconfig.me/ip",
            ];

            for url in endpoints {
                if let Ok(resp) = client.get(url).send().await {
                    if resp.status().is_success() {
                        if let Ok(txt) = resp.text().await {
                            let candidate = txt.trim();
                            if let Ok(ip) = candidate.parse::<IpAddr>() {
                                if !ip.is_loopback() && !ip.is_unspecified() {
                                    let ip_str = ip.to_string();
                                    *state.detected_public_ip.write() = ip_str.clone();
                                    // Auto-populate public_host in DB if empty or mistakenly set to loopback/0.0.0.0
                                    if let Ok(settings) = state.db.get_settings() {
                                        let cur = settings.public_host.trim();
                                        if cur.is_empty() || is_loopback_or_unspecified_host(cur) {
                                            let _ = state.db.set_setting_kv("public_host", &ip_str);
                                            tracing::info!(
                                                "Auto-detected server public IP for share links: {}",
                                                ip_str
                                            );
                                        }
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}

pub fn is_loopback_or_unspecified_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    if h.is_empty() || h == "localhost" || h == "0.0.0.0" || h == "::" || h == "::1" {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }
    false
}
