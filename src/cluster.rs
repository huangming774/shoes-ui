use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::db::{normalize_cluster_api_url, Database};
use crate::models::{ClusterNodeRecord, Inbound, InboundTotals};
use crate::monitor::SystemTelemetry;
use crate::process::ProcessStatus;

const CLUSTER_POLL_INTERVAL_SECS: u64 = 15;
const REMOTE_FETCH_TIMEOUT_SECS: u64 = 6;
/// Keep recently synced remote nodes usable in subscriptions for brief network blips (5 min).
const STALE_SUB_GRACE_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterShoesSummary {
    #[serde(default)]
    pub running: bool,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub started_at: Option<i64>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub bin_exists: bool,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl From<&ProcessStatus> for ClusterShoesSummary {
    fn from(s: &ProcessStatus) -> Self {
        Self {
            running: s.running,
            pid: s.pid,
            started_at: s.started_at,
            version: s.version.clone(),
            bin_exists: s.bin_exists,
            last_error: s.last_error.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterSystemSummary {
    #[serde(default)]
    pub sampled_at: i64,
    #[serde(default)]
    pub cpu_usage: f32,
    #[serde(default)]
    pub cpu_cores: usize,
    #[serde(default)]
    pub mem_used: u64,
    #[serde(default)]
    pub mem_total: u64,
    #[serde(default)]
    pub net_rx_speed: u64,
    #[serde(default)]
    pub net_tx_speed: u64,
    #[serde(default)]
    pub proxy_up_speed: u64,
    #[serde(default)]
    pub proxy_down_speed: u64,
    #[serde(default)]
    pub active_connections: usize,
    #[serde(default)]
    pub clash_online: bool,
    #[serde(default)]
    pub shoes_rss_bytes: u64,
    #[serde(default)]
    pub host_uptime_secs: u64,
    #[serde(default)]
    pub panel_uptime_secs: u64,
    #[serde(default)]
    pub os_name: String,
    #[serde(default)]
    pub arch: String,
}

impl From<&SystemTelemetry> for ClusterSystemSummary {
    fn from(t: &SystemTelemetry) -> Self {
        Self {
            sampled_at: t.sampled_at,
            cpu_usage: t.cpu_usage,
            cpu_cores: t.cpu_cores,
            mem_used: t.mem_used,
            mem_total: t.mem_total,
            net_rx_speed: t.net_rx_speed,
            net_tx_speed: t.net_tx_speed,
            proxy_up_speed: t.proxy_up_speed,
            proxy_down_speed: t.proxy_down_speed,
            active_connections: t.active_connections,
            clash_online: t.clash_online,
            shoes_rss_bytes: t.shoes_rss_bytes,
            host_uptime_secs: t.host_uptime_secs,
            panel_uptime_secs: t.panel_uptime_secs,
            os_name: t.os_name.clone(),
            arch: t.arch.clone(),
        }
    }
}

/// Read-only payload returned by `GET /api/cluster/export` on every node.
/// Contains live telemetry + enabled proxy inbounds + public cert PEMs (never private keys).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterExportPayload {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub panel_version: String,
    #[serde(default)]
    pub local_name: String,
    #[serde(default)]
    pub local_region: String,
    #[serde(default)]
    pub local_region_flag: String,
    #[serde(default)]
    pub share_host: String,
    #[serde(default)]
    pub shoes: ClusterShoesSummary,
    #[serde(default)]
    pub system: ClusterSystemSummary,
    #[serde(default)]
    pub totals: InboundTotals,
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub cert_pems: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RemoteNodeSnapshot {
    pub node_id: i64,
    pub online: bool,
    pub latency_ms: Option<u64>,
    pub last_synced_at: i64,
    pub last_ok_at: i64,
    pub last_error: Option<String>,
    pub instance_id: String,
    pub panel_version: String,
    pub share_host: String,
    pub shoes: ClusterShoesSummary,
    pub system: ClusterSystemSummary,
    pub totals: InboundTotals,
    #[serde(skip_serializing)]
    pub inbounds: Vec<Inbound>,
    #[serde(skip_serializing)]
    pub cert_pems: HashMap<String, String>,
}

impl RemoteNodeSnapshot {
    pub fn has_usable_inbounds(&self, now_ms: i64) -> bool {
        if self.inbounds.is_empty() {
            return false;
        }
        self.online || (self.last_ok_at > 0 && now_ms.saturating_sub(self.last_ok_at) <= STALE_SUB_GRACE_MS)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterNodeTestResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub instance_id: String,
    pub panel_version: String,
    pub local_name: String,
    pub local_region: String,
    pub local_region_flag: String,
    pub share_host: String,
    pub shoes_running: bool,
    pub shoes_version: String,
    pub inbounds_enabled: i64,
    pub inbounds_total: i64,
    pub clients_total: i64,
}

pub struct ClusterManager {
    db: Arc<Database>,
    http_verified: Client,
    http_insecure: Client,
    snapshots: RwLock<HashMap<i64, Arc<RemoteNodeSnapshot>>>,
}

impl ClusterManager {
    pub fn new(db: Arc<Database>) -> Arc<Self> {
        let http_verified = Client::builder()
            .timeout(Duration::from_secs(REMOTE_FETCH_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(4))
            .no_proxy()
            .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build verified cluster HTTP client");
        let http_insecure = Client::builder()
            .timeout(Duration::from_secs(REMOTE_FETCH_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(4))
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build insecure cluster HTTP client");

        let mgr = Arc::new(Self {
            db,
            http_verified,
            http_insecure,
            snapshots: RwLock::new(HashMap::new()),
        });
        Self::spawn_poller(mgr.clone());
        mgr
    }

    fn client_for(&self, allow_insecure: bool) -> &Client {
        if allow_insecure {
            &self.http_insecure
        } else {
            &self.http_verified
        }
    }

    pub async fn fetch_remote_export(
        &self,
        api_url: &str,
        api_token: &str,
        allow_insecure: bool,
    ) -> Result<(ClusterExportPayload, u64)> {
        let base = normalize_cluster_api_url(api_url)?;
        let token = api_token.trim();
        if token.is_empty() {
            return Err(anyhow!("Remote node API token is empty"));
        }
        let endpoint = format!("{base}/api/cluster/export");
        let t0 = Instant::now();
        let resp = self
            .client_for(allow_insecure)
            .get(&endpoint)
            .bearer_auth(token)
            .header("X-Cluster-Token", token)
            .send()
            .await
            .with_context(|| format!("Failed to reach remote node at {endpoint}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let latency_ms = t0.elapsed().as_millis() as u64;
        if !status.is_success() {
            let err_msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or_else(|| {
                    if text.trim().is_empty() {
                        format!("HTTP {}", status.as_u16())
                    } else {
                        text.chars().take(200).collect()
                    }
                });
            return Err(anyhow!(
                "Remote panel rejected request (HTTP {}): {err_msg}",
                status.as_u16()
            ));
        }

        let mut envelope: Value = serde_json::from_str(&text)
            .context("Remote panel returned invalid JSON (verify panel URL & base path)")?;
        if envelope.get("ok").and_then(Value::as_bool) != Some(true) {
            let msg = envelope["error"].as_str().unwrap_or("unknown error");
            return Err(anyhow!("Remote panel returned error: {msg}"));
        }
        let payload: ClusterExportPayload = serde_json::from_value(envelope["data"].take())
            .context("Remote panel export payload schema mismatch (upgrade child shoes-panel)")?;

        // Prevent accidental self-mount loops
        if let Ok(Some(local_instance_id)) = self.db.get_cluster_instance_id() {
            if !payload.instance_id.is_empty()
                && !local_instance_id.is_empty()
                && payload.instance_id == local_instance_id
            {
                return Err(anyhow!(
                    "Remote URL points to this same shoes-panel instance (self-mount blocked)"
                ));
            }
        }

        Ok((payload, latency_ms))
    }

    pub async fn test_connection(
        &self,
        api_url: &str,
        api_token: &str,
        allow_insecure: bool,
    ) -> Result<ClusterNodeTestResult> {
        let (payload, latency_ms) = self
            .fetch_remote_export(api_url, api_token, allow_insecure)
            .await?;
        Ok(ClusterNodeTestResult {
            ok: true,
            latency_ms,
            instance_id: payload.instance_id,
            panel_version: payload.panel_version,
            local_name: payload.local_name,
            local_region: payload.local_region,
            local_region_flag: payload.local_region_flag,
            share_host: payload.share_host,
            shoes_running: payload.shoes.running,
            shoes_version: payload.shoes.version,
            inbounds_enabled: payload.totals.inbounds_enabled,
            inbounds_total: payload.totals.inbounds_total,
            clients_total: payload.totals.clients_total,
        })
    }

    pub async fn sync_node(&self, node: &ClusterNodeRecord) -> Arc<RemoteNodeSnapshot> {
        let now = Utc::now().timestamp_millis();

        let snap = match self
            .fetch_remote_export(&node.api_url, &node.api_token, node.allow_insecure)
            .await
        {
            Ok((payload, latency_ms)) => {
                let effective_host = resolve_remote_share_host(node, &payload.share_host);
                Arc::new(RemoteNodeSnapshot {
                    node_id: node.id,
                    online: true,
                    latency_ms: Some(latency_ms),
                    last_synced_at: now,
                    last_ok_at: now,
                    last_error: None,
                    instance_id: payload.instance_id,
                    panel_version: payload.panel_version,
                    share_host: effective_host,
                    shoes: payload.shoes,
                    system: payload.system,
                    totals: payload.totals,
                    inbounds: payload.inbounds,
                    cert_pems: payload.cert_pems,
                })
            }
            Err(err) => {
                let prev = self.snapshots.read().get(&node.id).cloned();
                let mut failed = prev
                    .map(|arc| (*arc).clone())
                    .unwrap_or_else(|| RemoteNodeSnapshot {
                        node_id: node.id,
                        ..Default::default()
                    });
                failed.online = false;
                failed.latency_ms = None;
                failed.last_synced_at = now;
                failed.last_error = Some(err.to_string());
                Arc::new(failed)
            }
        };

        self.snapshots.write().insert(node.id, Arc::clone(&snap));
        snap
    }

    pub async fn sync_all_now(self: &Arc<Self>) -> Vec<Arc<RemoteNodeSnapshot>> {
        let Ok(nodes) = self.db.list_cluster_nodes() else {
            return Vec::new();
        };
        let active_ids: std::collections::HashSet<i64> = nodes.iter().map(|n| n.id).collect();
        self.snapshots.write().retain(|id, _| active_ids.contains(id));

        let enabled_nodes: Vec<ClusterNodeRecord> =
            nodes.into_iter().filter(|n| n.enable).collect();
        if enabled_nodes.is_empty() {
            return Vec::new();
        }

        let mut join_set = tokio::task::JoinSet::new();
        for node in enabled_nodes {
            let mgr = self.clone();
            join_set.spawn(async move { mgr.sync_node(&node).await });
        }
        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(snap) = res {
                results.push(snap);
            }
        }
        results
    }

    pub async fn sync_node_by_id(&self, id: i64) -> Result<Arc<RemoteNodeSnapshot>> {
        let node = self
            .db
            .get_cluster_node(id)?
            .ok_or_else(|| anyhow!("Cluster node #{id} not found"))?;
        Ok(self.sync_node(&node).await)
    }

    pub fn remove_snapshot(&self, id: i64) {
        self.snapshots.write().remove(&id);
    }

    pub fn get_snapshots(&self) -> HashMap<i64, Arc<RemoteNodeSnapshot>> {
        self.snapshots.read().clone()
    }

    /// Ensures any enabled `include_in_sub` node that hasn't been synced recently gets a fast bounded refresh
    /// before building an aggregated subscription (never blocks longer than 3.5s).
    pub async fn ensure_fresh_for_subscription(self: &Arc<Self>, max_age_ms: i64) {
        let Ok(nodes) = self.db.list_cluster_nodes() else {
            return;
        };
        let now = Utc::now().timestamp_millis();
        let stale: Vec<ClusterNodeRecord> = {
            let current = self.snapshots.read();
            nodes
                .into_iter()
                .filter(|n| {
                    if !n.enable || !n.include_in_sub {
                        return false;
                    }
                    match current.get(&n.id) {
                        None => true,
                        Some(s) => now.saturating_sub(s.last_synced_at) > max_age_ms,
                    }
                })
                .collect()
        };
        if stale.is_empty() {
            return;
        }
        let mut join_set = tokio::task::JoinSet::new();
        for node in stale {
            let mgr = self.clone();
            join_set.spawn(async move {
                let _ = mgr.sync_node(&node).await;
            });
        }
        let _ = tokio::time::timeout(Duration::from_millis(3500), async {
            while join_set.join_next().await.is_some() {}
        })
        .await;
    }

    /// Counts matching subscription client nodes currently available across enabled remote cluster nodes.
    pub fn count_remote_sub_nodes(&self, sub_id_filter: &str) -> i64 {
        let Ok(nodes) = self.db.list_cluster_nodes() else {
            return 0;
        };
        let snaps = self.snapshots.read();
        let now = Utc::now().timestamp_millis();
        let match_all = sub_id_filter.eq_ignore_ascii_case("all") || sub_id_filter == "*";
        let mut total = 0i64;
        for n in nodes.iter().filter(|n| n.enable && n.include_in_sub) {
            let Some(snap) = snaps.get(&n.id) else {
                continue;
            };
            if !snap.has_usable_inbounds(now) {
                continue;
            }
            for ib in snap
                .inbounds
                .iter()
                .filter(|i| i.enable && i.protocol != "portforward")
            {
                for c in ib.clients.iter().filter(|c| c.enable) {
                    if match_all || c.sub_id.trim() == sub_id_filter.trim() {
                        total += 1;
                    }
                }
            }
        }
        total
    }

    fn spawn_poller(mgr: Arc<Self>) {
        tokio::spawn(async move {
            // Brief startup delay so local server finishes binding cleanly
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut interval =
                tokio::time::interval(Duration::from_secs(CLUSTER_POLL_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let has_enabled = mgr
                    .db
                    .list_cluster_nodes()
                    .map(|list| list.iter().any(|n| n.enable))
                    .unwrap_or(false);
                if has_enabled {
                    let _ = mgr.sync_all_now().await;
                }
            }
        });
    }
}

pub fn resolve_remote_share_host(node: &ClusterNodeRecord, reported_host: &str) -> String {
    if !node.share_host_override.trim().is_empty() {
        return node.share_host_override.trim().to_string();
    }
    let rep = reported_host.trim();
    if !rep.is_empty() && !crate::state::is_loopback_or_unspecified_host(rep) {
        return rep.to_string();
    }
    if let Ok(parsed) = url::Url::parse(node.api_url.trim()) {
        if let Some(h) = parsed.host_str() {
            return h.trim_matches(['[', ']']).to_string();
        }
    }
    rep.to_string()
}

pub fn effective_node_prefix(node: &ClusterNodeRecord) -> String {
    if !node.node_prefix.trim().is_empty() {
        return node.node_prefix.trim().to_string();
    }
    let flag = node.region_flag.trim();
    if !flag.is_empty() {
        format!("{flag} {}", node.name.trim())
    } else {
        node.name.trim().to_string()
    }
}
