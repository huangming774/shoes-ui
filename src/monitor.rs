use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, System};

use crate::db::Database;
use crate::process::ShoesProcessManager;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemTelemetry {
    pub cpu_usage: f32,
    pub cpu_cores: usize,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rx_speed: u64,
    pub net_tx_speed: u64,
    pub host_uptime_secs: u64,
    pub panel_uptime_secs: u64,
    pub os_name: String,
    pub kernel_version: String,
    pub arch: String,
    // Proxy / Clash API metrics
    pub clash_online: bool,
    pub shoes_rss_bytes: u64,
    pub active_connections: usize,
    pub proxy_up_speed: u64,
    pub proxy_down_speed: u64,
    pub inbound_active_conns: HashMap<String, usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashConnectionsResp {
    #[serde(default)]
    upload_total: u64,
    #[serde(default)]
    download_total: u64,
    #[serde(default)]
    memory: u64,
    #[serde(default)]
    connections: Vec<ClashConnItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashConnItem {
    id: String,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    #[serde(default)]
    metadata: ClashConnMeta,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashConnMeta {
    #[serde(default)]
    inbound_name: String,
}

pub struct RuntimeMonitor {
    db: Arc<Database>,
    proc_mgr: Arc<ShoesProcessManager>,
    http: Client,
    telemetry: RwLock<SystemTelemetry>,
    panel_start: Instant,
}

impl RuntimeMonitor {
    pub fn new(db: Arc<Database>, proc_mgr: Arc<ShoesProcessManager>) -> Arc<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(6))
            .no_proxy()
            .build()
            .expect("failed to build reqwest client");

        let mon = Arc::new(Self {
            db,
            proc_mgr,
            http,
            telemetry: RwLock::new(SystemTelemetry {
                os_name: System::long_os_version()
                    .or_else(System::name)
                    .unwrap_or_else(|| std::env::consts::OS.to_string()),
                kernel_version: System::kernel_version().unwrap_or_default(),
                arch: std::env::consts::ARCH.to_string(),
                ..Default::default()
            }),
            panel_start: Instant::now(),
        });

        Self::spawn_poller(mon.clone());
        mon
    }

    pub fn snapshot(&self) -> SystemTelemetry {
        self.telemetry.read().clone()
    }

    fn clash_base_and_secret(&self) -> Result<(String, String)> {
        let s = self.db.get_settings()?;
        let addr = s.clash_api_addr.trim();
        if addr.is_empty() {
            return Err(anyhow!("Clash API address is not configured"));
        }
        let base = if addr.starts_with("http://") || addr.starts_with("https://") {
            addr.trim_end_matches('/').to_string()
        } else {
            format!("http://{addr}")
        };
        Ok((base, s.clash_api_secret))
    }

    pub async fn fetch_connections_raw(&self) -> Result<Value> {
        let (base, secret) = self.clash_base_and_secret()?;
        let resp = self
            .http
            .get(format!("{base}/connections"))
            .bearer_auth(secret)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Clash API /connections returned {}", resp.status()));
        }
        Ok(resp.json::<Value>().await?)
    }

    pub async fn close_connection(&self, id: Option<&str>) -> Result<()> {
        let (base, secret) = self.clash_base_and_secret()?;
        let url = match id {
            Some(cid) if !cid.is_empty() => format!("{base}/connections/{cid}"),
            _ => format!("{base}/connections"),
        };
        let resp = self.http.delete(url).bearer_auth(secret).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Clash API DELETE connection returned {}", resp.status()));
        }
        Ok(())
    }

    pub async fn fetch_proxies(&self) -> Result<Value> {
        let (base, secret) = self.clash_base_and_secret()?;
        let resp = self
            .http
            .get(format!("{base}/proxies"))
            .bearer_auth(secret)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Clash API /proxies returned {}", resp.status()));
        }
        Ok(resp.json::<Value>().await?)
    }

    pub async fn select_proxy(&self, group: &str, member: &str) -> Result<()> {
        let (base, secret) = self.clash_base_and_secret()?;
        let encoded = urlencoding_segment(group);
        let resp = self
            .http
            .put(format!("{base}/proxies/{encoded}"))
            .bearer_auth(secret)
            .json(&json!({ "name": member }))
            .send()
            .await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Selector switch failed: {txt}"));
        }
        Ok(())
    }

    pub async fn test_delay(
        &self,
        is_group: bool,
        name: &str,
        url: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> Result<Value> {
        let (base, secret) = self.clash_base_and_secret()?;
        let kind = if is_group { "group" } else { "proxies" };
        let encoded = urlencoding_segment(name);
        let probe_url = url.unwrap_or("https://www.gstatic.com/generate_204");
        let timeout = timeout_ms.unwrap_or(5000);

        let resp = self
            .http
            .get(format!("{base}/{kind}/{encoded}/delay"))
            .bearer_auth(secret)
            .query(&[("url", probe_url), ("timeout", &timeout.to_string())])
            .send()
            .await?;
        let status = resp.status();
        let val: Value = resp.json().await.unwrap_or_else(|_| json!({}));
        if !status.is_success() {
            return Err(anyhow!("Delay probe returned {status}: {val}"));
        }
        Ok(val)
    }

    fn spawn_poller(mon: Arc<Self>) {
        tokio::spawn(async move {
            let mut sys = System::new_all();
            let mut disks = Disks::new_with_refreshed_list();
            let mut networks = Networks::new_with_refreshed_list();

            let mut prev_net_rx: u64 = networks.iter().map(|(_, n)| n.total_received()).sum();
            let mut prev_net_tx: u64 = networks.iter().map(|(_, n)| n.total_transmitted()).sum();

            let mut last_conn_bytes: HashMap<String, (u64, u64)> = HashMap::new();
            let mut prev_proxy_totals: Option<(u64, u64)> = None;
            let mut tick_count: u64 = 0;

            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                tick_count = tick_count.wrapping_add(1);

                // 1. Refresh host system stats
                sys.refresh_cpu_usage();
                sys.refresh_memory();
                if tick_count % 10 == 1 {
                    disks.refresh(true);
                }
                networks.refresh(true);

                let cpu_usage = sys.global_cpu_usage();
                let cpu_cores = sys.cpus().len();
                let mem_used = sys.used_memory();
                let mem_total = sys.total_memory();
                let swap_used = sys.used_swap();
                let swap_total = sys.total_swap();

                let mut disk_total = 0u64;
                let mut disk_avail = 0u64;
                for d in disks.list() {
                    disk_total = disk_total.saturating_add(d.total_space());
                    disk_avail = disk_avail.saturating_add(d.available_space());
                }
                let disk_used = disk_total.saturating_sub(disk_avail);

                let cur_rx: u64 = networks.iter().map(|(_, n)| n.total_received()).sum();
                let cur_tx: u64 = networks.iter().map(|(_, n)| n.total_transmitted()).sum();
                let net_rx_speed = cur_rx.saturating_sub(prev_net_rx);
                let net_tx_speed = cur_tx.saturating_sub(prev_net_tx);
                prev_net_rx = cur_rx;
                prev_net_tx = cur_tx;

                // 2. Poll shoes Clash API /connections for traffic deltas & active connection counts
                let mut clash_online = false;
                let mut shoes_rss_bytes = 0u64;
                let mut active_connections = 0usize;
                let mut proxy_up_speed = 0u64;
                let mut proxy_down_speed = 0u64;
                let mut inbound_active_conns: HashMap<String, usize> = HashMap::new();
                let mut active_ids_by_tag: HashMap<String, Vec<String>> = HashMap::new();

                if let Ok((base, secret)) = mon.clash_base_and_secret() {
                    if let Ok(resp) = mon
                        .http
                        .get(format!("{base}/connections"))
                        .bearer_auth(secret)
                        .timeout(Duration::from_millis(900))
                        .send()
                        .await
                    {
                        if resp.status().is_success() {
                            if let Ok(snap) = resp.json::<ClashConnectionsResp>().await {
                                clash_online = true;
                                shoes_rss_bytes = snap.memory;
                                active_connections = snap.connections.len();

                                if let Some((pu, pd)) = prev_proxy_totals {
                                    if snap.upload_total >= pu && snap.download_total >= pd {
                                        proxy_up_speed = snap.upload_total - pu;
                                        proxy_down_speed = snap.download_total - pd;
                                    }
                                }
                                prev_proxy_totals = Some((snap.upload_total, snap.download_total));

                                let mut next_conn_bytes =
                                    HashMap::with_capacity(snap.connections.len());
                                let mut deltas_by_inbound: HashMap<String, (u64, u64)> =
                                    HashMap::new();

                                for c in snap.connections {
                                    let (prev_u, prev_d) =
                                        last_conn_bytes.get(&c.id).copied().unwrap_or((0, 0));
                                    let du = c.upload.saturating_sub(prev_u);
                                    let dd = c.download.saturating_sub(prev_d);
                                    next_conn_bytes.insert(c.id.clone(), (c.upload, c.download));

                                    let tag = c.metadata.inbound_name;
                                    if !tag.is_empty() {
                                        *inbound_active_conns.entry(tag.clone()).or_insert(0) += 1;
                                        active_ids_by_tag.entry(tag.clone()).or_default().push(c.id);
                                        if du > 0 || dd > 0 {
                                            let entry =
                                                deltas_by_inbound.entry(tag).or_insert((0, 0));
                                            entry.0 = entry.0.saturating_add(du);
                                            entry.1 = entry.1.saturating_add(dd);
                                        }
                                    }
                                }

                                last_conn_bytes = next_conn_bytes;
                                if !deltas_by_inbound.is_empty() {
                                    let _ = mon.db.add_traffic_deltas(&deltas_by_inbound);
                                }
                            }
                        }
                    }
                }
                if !clash_online {
                    last_conn_bytes.clear();
                    prev_proxy_totals = None;
                }

                // 3. Enforce expiry and traffic quotas every 3 seconds
                if tick_count % 3 == 0 {
                    if let Ok(disabled_tags) = mon.db.enforce_quotas_and_expiry() {
                        if !disabled_tags.is_empty() {
                            mon.proc_mgr.push_panel_log(format!(
                                "Auto-disabled expired/over-quota inbounds: {}",
                                disabled_tags.join(", ")
                            ));
                            // Immediately terminate active connections for those disabled inbounds
                            for tag in &disabled_tags {
                                if let Some(conn_ids) = active_ids_by_tag.get(tag) {
                                    for cid in conn_ids {
                                        let _ = mon.close_connection(Some(cid)).await;
                                    }
                                }
                            }
                            let _ = mon.proc_mgr.reload_config().await;
                        }
                    }
                }

                // 4. Publish telemetry snapshot
                {
                    let mut guard = mon.telemetry.write();
                    guard.cpu_usage = cpu_usage;
                    guard.cpu_cores = cpu_cores;
                    guard.mem_used = mem_used;
                    guard.mem_total = mem_total;
                    guard.swap_used = swap_used;
                    guard.swap_total = swap_total;
                    guard.disk_used = disk_used;
                    guard.disk_total = disk_total;
                    guard.net_rx_bytes = cur_rx;
                    guard.net_tx_bytes = cur_tx;
                    guard.net_rx_speed = net_rx_speed;
                    guard.net_tx_speed = net_tx_speed;
                    guard.host_uptime_secs = System::uptime();
                    guard.panel_uptime_secs = mon.panel_start.elapsed().as_secs();
                    guard.clash_online = clash_online;
                    guard.shoes_rss_bytes = shoes_rss_bytes;
                    guard.active_connections = active_connections;
                    guard.proxy_up_speed = proxy_up_speed;
                    guard.proxy_down_speed = proxy_down_speed;
                    guard.inbound_active_conns = inbound_active_conns;
                }
            }
        });
    }
}

fn urlencoding_segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}
