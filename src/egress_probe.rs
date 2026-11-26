use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use reqwest::{redirect::Policy, Client, Proxy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

use crate::crypto_util::generate_random_alnum;
use crate::db::Database;
use crate::yaml_gen::build_egress_probe_yaml;

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

const OPENAI_UNSUPPORTED_REGIONS: &[&str] = &[
    "CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU", "AF", "VE",
];

const CLAUDE_UNSUPPORTED_REGIONS: &[&str] = &[
    "CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU",
];

fn default_target_kind() -> String {
    "direct".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct EgressProbeTargetReq {
    /// "direct" | "outbound_group"
    #[serde(default = "default_target_kind")]
    pub kind: String,
    /// Required when kind == "outbound_group"
    #[serde(default)]
    pub group_name: String,
    /// Optional member name inside outbound_group
    #[serde(default)]
    pub member_name: String,
    /// "auto" | "ipv4" | "ipv6"
    #[serde(default)]
    pub ip_version: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EgressIpSummary {
    pub ipv4: String,
    pub ipv4_latency_ms: Option<u64>,
    pub ipv6: String,
    pub ipv6_latency_ms: Option<u64>,
    pub primary_ip: String,
    pub country_code: String,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub org: String,
    pub isp: String,
    pub cf_colo: String,
    pub cf_loc: String,
    /// "on" | "plus" | "off" | ""
    pub warp_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceUnlockResult {
    /// "chatgpt" | "claude" | "gemini" | "netflix" | "disney" | "youtube"
    pub service: String,
    pub name: String,
    /// "unlocked" | "partial" | "blocked" | "error"
    pub status: String,
    pub region: String,
    pub detail: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EgressTargetReport {
    pub target_id: String,
    pub kind: String,
    pub label: String,
    pub group_name: String,
    pub member_name: String,
    pub ip_version: String,
    pub ok: bool,
    pub error: Option<String>,
    pub elapsed_ms: u64,
    pub ip_info: EgressIpSummary,
    pub services: Vec<ServiceUnlockResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutingRecommendation {
    pub service: String,
    pub service_name: String,
    pub direct_status: String,
    pub best_group: String,
    pub best_status: String,
    pub best_region: String,
    pub suggested_rule_source: String,
    pub suggested_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EgressProbeResponse {
    pub checked_at: i64,
    pub reports: Vec<EgressTargetReport>,
    pub recommendations: Vec<RoutingRecommendation>,
}

struct ProbeClients {
    follow: Client,
    no_redirect: Client,
}

fn build_probe_clients(
    proxy_url: Option<&str>,
    local_ip: Option<IpAddr>,
    timeout: Duration,
) -> Result<ProbeClients> {
    let make = |policy: Policy| -> Result<Client> {
        let mut b = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(8)))
            .user_agent(BROWSER_UA)
            .redirect(policy);
        if let Some(p) = proxy_url {
            b = b.proxy(Proxy::all(p).context("invalid probe proxy URL")?);
        } else {
            b = b.no_proxy();
            if let Some(ip) = local_ip {
                b = b.local_address(ip);
            }
        }
        b.build().context("failed to build HTTP probe client")
    };
    Ok(ProbeClients {
        follow: make(Policy::limited(6))?,
        no_redirect: make(Policy::none())?,
    })
}

struct ShoesProbeSidecar {
    child: Child,
    proxy_url: String,
    _yaml_file: tempfile::NamedTempFile,
}

impl ShoesProbeSidecar {
    async fn start(
        db: &Database,
        group_name: &str,
        member_name: Option<&str>,
        ip_strategy: Option<&str>,
    ) -> Result<Self> {
        let settings = db.get_settings()?;
        let bin = PathBuf::from(settings.shoes_bin_path.trim());
        if !bin.is_file() {
            return Err(anyhow!(
                "shoes binary not found at '{}'; configure shoes_bin_path in Settings to probe outbound groups",
                bin.display()
            ));
        }
        let dns_groups = db.list_dns_groups()?;
        let outbound_groups = db.list_outbound_groups()?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("failed to reserve local loopback port for egress probe")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let user = format!("probe{}", generate_random_alnum(8));
        let pass = generate_random_alnum(20);

        let yaml = build_egress_probe_yaml(
            port,
            &user,
            &pass,
            group_name,
            member_name,
            ip_strategy,
            &settings,
            &dns_groups,
            &outbound_groups,
        )?;

        let mut yaml_file = tempfile::Builder::new()
            .prefix(".shoes-egress-probe-")
            .suffix(".yaml")
            .tempfile_in(&db.data_dir)
            .context("failed to create temporary probe config file")?;
        yaml_file.write_all(yaml.as_bytes())?;
        yaml_file.flush()?;

        let mut cmd = Command::new(&bin);
        cmd.arg(yaml_file.path())
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to launch shoes probe sidecar '{}'", bin.display()))?;

        // Wait up to 3 seconds for loopback HTTP proxy listener to accept connections
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut ready = false;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                let mut err_buf = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let _ = stderr.read_to_string(&mut err_buf).await;
                }
                let detail = err_buf.trim();
                return Err(anyhow!(
                    "shoes probe sidecar exited ({status}){}",
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                ));
            }
            if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(45)).await;
        }

        if !ready {
            let _ = child.kill().await;
            return Err(anyhow!(
                "shoes probe sidecar did not open loopback port {port} in time"
            ));
        }

        let proxy_url = format!("http://{user}:{pass}@127.0.0.1:{port}");
        Ok(Self {
            child,
            proxy_url,
            _yaml_file: yaml_file,
        })
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

pub fn parse_cloudflare_trace(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    map
}

fn extract_json_string_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let pos = body.find(&needle)?;
    let rest = &body[pos + needle.len()..];
    let end = rest.find('"')?;
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

fn extract_netflix_region(location: &str, body: &str) -> String {
    // Location header like "https://www.netflix.com/jp/title/80018499" or "/hk-en/title/..."
    for source in [location, body] {
        if let Some(idx) = source.find("netflix.com/") {
            let after = &source[idx + "netflix.com/".len()..];
            if let Some((seg, rest)) = after.split_once('/') {
                if rest.starts_with("title/") || rest.starts_with("Title/") {
                    let code = seg.split('-').next().unwrap_or("").trim();
                    if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) {
                        return code.to_ascii_uppercase();
                    }
                }
            }
        }
    }
    if let Some(seg) = location.strip_prefix('/') {
        if let Some((part, rest)) = seg.split_once('/') {
            if rest.starts_with("title/") {
                let code = part.split('-').next().unwrap_or("").trim();
                if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) {
                    return code.to_ascii_uppercase();
                }
            }
        }
    }
    if let Some(cc) = extract_json_string_field(body, "countryCode") {
        if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
            return cc.to_ascii_uppercase();
        }
    }
    if location.contains("netflix.com/title/") || body.contains("\"netflix.com/title/") {
        return "US".to_string();
    }
    String::new()
}

fn extract_disney_region(location: &str, body: &str) -> String {
    // e.g. https://www.disneyplus.com/en-jp or /zh-hk or /en-gb
    for candidate in [location, body] {
        if let Some(idx) = candidate.find("disneyplus.com/") {
            let after = &candidate[idx + "disneyplus.com/".len()..];
            let seg = after.split(['/', '?', '"', '\'', '<']).next().unwrap_or("");
            if let Some((_, cc)) = seg.split_once('-') {
                if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
                    return cc.to_ascii_uppercase();
                }
            }
        }
    }
    if let Some(cc) = extract_json_string_field(body, "countryCode") {
        if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
            return cc.to_ascii_uppercase();
        }
    }
    String::new()
}

pub fn classify_chatgpt(
    web_status: Option<u16>,
    web_body: &str,
    api_status: Option<u16>,
    api_body: &str,
    trace_loc: &str,
) -> (&'static str, String, String) {
    let region = trace_loc.trim().to_ascii_uppercase();
    let region_unsupported = !region.is_empty()
        && OPENAI_UNSUPPORTED_REGIONS
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&region));

    let api_lower = api_body.to_ascii_lowercase();
    let web_lower = web_body.to_ascii_lowercase();

    let api_region_blocked = api_lower.contains("unsupported_country_region_territory")
        || api_lower.contains("country, region, or territory not supported");
    let api_cf_blocked = api_status == Some(403)
        && (api_lower.contains("just a moment")
            || api_lower.contains("access denied")
            || api_lower.contains("attention required")
            || api_lower.contains("cloudflare"));
    let api_ok = !api_region_blocked
        && !api_cf_blocked
        && matches!(api_status, Some(200 | 401 | 400 | 429))
        && (api_status != Some(401)
            || api_lower.contains("invalid_api_key")
            || api_lower.contains("missing")
            || api_lower.contains("bearer")
            || api_lower.contains("error"));

    let web_blocked = web_lower.contains("unsupported_country")
        || web_lower.contains("not available in your country")
        || web_lower.contains("unable to load site")
        || web_lower.contains("access denied")
        || web_lower.contains("just a moment")
        || web_lower.contains("attention required")
        || matches!(web_status, Some(403 | 451));
    let web_ok = !web_blocked && matches!(web_status, Some(200..=399));

    if region_unsupported || api_region_blocked {
        let code = if region.is_empty() {
            "N/A".to_string()
        } else {
            region.clone()
        };
        return (
            "blocked",
            region,
            format!("Unsupported region ({code})"),
        );
    }

    match (web_ok, api_ok) {
        (true, true) => ("unlocked", region, "Web + API".to_string()),
        (true, false) => (
            "unlocked",
            region,
            if api_status.is_none() {
                "Web OK".to_string()
            } else {
                format!("Web OK (API HTTP {})", api_status.unwrap_or(0))
            },
        ),
        (false, true) => (
            "partial",
            region,
            format!(
                "API Only (Web HTTP {})",
                web_status.map(|s| s.to_string()).unwrap_or_else(|| "err".into())
            ),
        ),
        (false, false) => {
            if web_status.is_none() && api_status.is_none() {
                ("error", region, "Timeout / unreachable".to_string())
            } else {
                (
                    "blocked",
                    region,
                    format!(
                        "Blocked / Challenged (Web {}, API {})",
                        web_status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                        api_status.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
                    ),
                )
            }
        }
    }
}

pub fn classify_claude(
    status: Option<u16>,
    final_url: &str,
    body: &str,
    trace_loc: &str,
) -> (&'static str, String, String) {
    let region = trace_loc.trim().to_ascii_uppercase();
    if !region.is_empty()
        && CLAUDE_UNSUPPORTED_REGIONS
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&region))
    {
        return ("blocked", region.clone(), format!("Unsupported region ({region})"));
    }
    let lower = body.to_ascii_lowercase();
    let url_lower = final_url.to_ascii_lowercase();
    if url_lower.contains("unavailable")
        || lower.contains("app unavailable")
        || lower.contains("not available in your region")
        || lower.contains("not available in your country")
    {
        return ("blocked", region, "Unavailable in region".to_string());
    }
    match status {
        None => ("error", region, "Timeout / unreachable".to_string()),
        Some(403 | 451) => {
            if lower.contains("just a moment") || lower.contains("cf-chl") {
                ("blocked", region, "Cloudflare challenge (HTTP 403)".to_string())
            } else {
                ("blocked", region, "Blocked (HTTP 403)".to_string())
            }
        }
        Some(200..=399) => ("unlocked", region, "Available".to_string()),
        Some(code) => ("error", region, format!("HTTP {code}")),
    }
}

pub fn classify_gemini(
    status: Option<u16>,
    final_url: &str,
    body: &str,
) -> (&'static str, String, String) {
    let url_lower = final_url.to_ascii_lowercase();
    let lower = body.to_ascii_lowercase();
    let region = extract_json_string_field(body, "COUNTRY_CODE")
        .or_else(|| {
            // Google embeds 2-letter GL in WIZ_global_data as ,"XX", near "gemini"
            let needle = "\"2,1,200,\"";
            if let Some(i) = body.find(needle) {
                let s = &body[i + needle.len()..];
                s.get(..2)
                    .filter(|c| c.chars().all(|ch| ch.is_ascii_uppercase()))
                    .map(str::to_string)
            } else {
                None
            }
        })
        .unwrap_or_default();

    if url_lower.contains("/sorry") || lower.contains("unusual traffic") {
        return ("blocked", region, "Google risk check (/sorry)".to_string());
    }
    if url_lower.contains("/faq")
        || lower.contains("not available in your country")
        || lower.contains("isn't supported in your country")
        || body.contains("45631641,null,false")
    {
        return ("blocked", region, "Unsupported region".to_string());
    }
    match status {
        None => ("error", region, "Timeout / unreachable".to_string()),
        Some(403 | 451) => ("blocked", region, "Blocked (HTTP 403)".to_string()),
        Some(200..=399) => {
            if body.contains("45631641,null,true")
                || lower.contains("gemini")
                || url_lower.contains("gemini.google.com")
            {
                ("unlocked", region, "Available".to_string())
            } else {
                ("partial", region, "Reachable (unconfirmed)".to_string())
            }
        }
        Some(code) => ("error", region, format!("HTTP {code}")),
    }
}

pub fn classify_netflix(
    orig_status: Option<u16>,
    orig_loc: &str,
    orig_body: &str,
    lic_status: Option<u16>,
    lic_loc: &str,
    lic_body: &str,
) -> (&'static str, String, String) {
    let region = {
        let r1 = extract_netflix_region(lic_loc, lic_body);
        if !r1.is_empty() {
            r1
        } else {
            let r2 = extract_netflix_region(orig_loc, orig_body);
            if !r2.is_empty() {
                r2
            } else if orig_status == Some(200) && orig_loc.is_empty() {
                // Netflix serves /title/<id> directly with HTTP 200 (no /<cc>/ redirect) for US egress.
                "US".to_string()
            } else {
                String::new()
            }
        }
    };

    match orig_status {
        None => return ("error", region, "Timeout / unreachable".to_string()),
        Some(403) => return ("blocked", region, "Blocked / Proxy detected (HTTP 403)".to_string()),
        Some(404) => return ("blocked", region, "Unavailable in region (HTTP 404)".to_string()),
        Some(code) if !(200..=399).contains(&code) => {
            return ("error", region, format!("HTTP {code}"));
        }
        _ => {}
    }

    match lic_status {
        Some(200..=399) => ("unlocked", region, "Full (Originals + Licensed)".to_string()),
        Some(404) => ("partial", region, "Originals Only".to_string()),
        Some(403) => ("partial", region, "Originals Only (Licensed 403)".to_string()),
        None => ("partial", region, "Originals OK (Licensed timeout)".to_string()),
        Some(code) => ("partial", region, format!("Originals OK (Licensed HTTP {code})")),
    }
}

pub fn classify_disney(
    status: Option<u16>,
    location: &str,
    body: &str,
) -> (&'static str, String, String) {
    let loc_lower = location.to_ascii_lowercase();
    let body_lower = body.to_ascii_lowercase();
    let region = extract_disney_region(location, body);

    if loc_lower.contains("unavailable")
        || loc_lower.contains("preview.disneyplus.com")
        || body_lower.contains("not available in your region")
        || body_lower.contains("unavailable in your region")
    {
        return ("blocked", region, "Unavailable in region".to_string());
    }
    match status {
        None => ("error", region, "Timeout / unreachable".to_string()),
        Some(403 | 451) => ("blocked", region, "IP / Geo blocked (HTTP 403)".to_string()),
        Some(200..=399) => ("unlocked", region, "Available".to_string()),
        Some(code) => ("error", region, format!("HTTP {code}")),
    }
}

pub fn classify_youtube(status: Option<u16>, body: &str) -> (&'static str, String, String) {
    let gl = extract_json_string_field(body, "INNERTUBE_CONTEXT_GL")
        .or_else(|| extract_json_string_field(body, "GL"))
        .or_else(|| extract_json_string_field(body, "countryCode"))
        .unwrap_or_default()
        .to_ascii_uppercase();
    let lower = body.to_ascii_lowercase();
    if lower.contains("youtube premium is not available in your country")
        || lower.contains("this offer is not available")
    {
        return ("blocked", gl, "Premium unavailable in region".to_string());
    }
    match status {
        None => ("error", gl, "Timeout / unreachable".to_string()),
        Some(403 | 451) => ("blocked", gl, "Blocked (HTTP 403)".to_string()),
        Some(200..=399) => {
            if gl == "CN" || gl == "RU" {
                ("blocked", gl.clone(), format!("Restricted region ({gl})"))
            } else {
                ("unlocked", gl, "Premium Available".to_string())
            }
        }
        Some(code) => ("error", gl, format!("HTTP {code}")),
    }
}

async fn fetch_cf_trace(client: &Client, url: &str) -> Option<(HashMap<String, String>, u64)> {
    let t0 = Instant::now();
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let ms = t0.elapsed().as_millis() as u64;
    let map = parse_cloudflare_trace(&text);
    if map.is_empty() {
        None
    } else {
        Some((map, ms))
    }
}

async fn probe_ip_summary(
    clients: &ProbeClients,
    is_direct: bool,
    ip_version: &str,
) -> EgressIpSummary {
    let mut info = EgressIpSummary::default();

    // Run Cloudflare trace (default stack), explicit IPv4 & IPv6 probes, and GeoIP/ASN lookup in parallel
    let cf_main_fut = fetch_cf_trace(&clients.follow, "https://www.cloudflare.com/cdn-cgi/trace");

    let v4_fut = async {
        if is_direct && ip_version == "ipv6" {
            return None;
        }
        let t0 = Instant::now();
        if let Ok(resp) = clients.follow.get("https://api4.ipify.org").send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    let ip = txt.trim().to_string();
                    if ip.parse::<Ipv4Addr>().is_ok() {
                        return Some((ip, t0.elapsed().as_millis() as u64));
                    }
                }
            }
        }
        if let Some((cf4, ms)) = fetch_cf_trace(&clients.follow, "https://1.1.1.1/cdn-cgi/trace").await {
            if let Some(ip) = cf4.get("ip").filter(|s| s.parse::<Ipv4Addr>().is_ok()) {
                return Some((ip.clone(), ms));
            }
        }
        None
    };

    let v6_fut = async {
        if is_direct && ip_version == "ipv4" {
            return None;
        }
        let t0 = Instant::now();
        if let Ok(resp) = clients.follow.get("https://api6.ipify.org").send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    let ip = txt.trim().to_string();
                    if ip.parse::<Ipv6Addr>().is_ok() {
                        return Some((ip, t0.elapsed().as_millis() as u64));
                    }
                }
            }
        }
        None
    };

    let geo_fut = async {
        if let Ok(resp) = clients.follow.get("https://ipwho.is/").send().await {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<Value>().await {
                    if v["success"].as_bool() != Some(false) && v["ip"].as_str().is_some() {
                        return Some(v);
                    }
                }
            }
        }
        if let Ok(resp) = clients.follow.get("https://api.ip.sb/geoip").send().await {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<Value>().await {
                    if v["ip"].as_str().is_some() {
                        return Some(v);
                    }
                }
            }
        }
        None
    };

    let (cf_res, v4_res, v6_res, geo_res) = tokio::join!(cf_main_fut, v4_fut, v6_fut, geo_fut);

    if let Some((ip, ms)) = v4_res {
        info.ipv4 = ip;
        info.ipv4_latency_ms = Some(ms);
    }
    if let Some((ip, ms)) = v6_res {
        info.ipv6 = ip;
        info.ipv6_latency_ms = Some(ms);
    }
    if let Some((cf, ms)) = cf_res {
        if let Some(ip) = cf.get("ip") {
            info.primary_ip = ip.clone();
            if ip.parse::<Ipv4Addr>().is_ok() && info.ipv4.is_empty() {
                info.ipv4 = ip.clone();
                info.ipv4_latency_ms = Some(ms);
            } else if ip.parse::<Ipv6Addr>().is_ok() && info.ipv6.is_empty() {
                info.ipv6 = ip.clone();
                info.ipv6_latency_ms = Some(ms);
            }
        }
        info.cf_loc = cf.get("loc").cloned().unwrap_or_default();
        info.cf_colo = cf.get("colo").cloned().unwrap_or_default();
        info.warp_status = cf.get("warp").cloned().unwrap_or_default();
    }

    if let Some(v) = geo_res {
        let geo_ip = v["ip"].as_str().unwrap_or("").trim().to_string();
        if !geo_ip.is_empty() {
            if info.primary_ip.is_empty() {
                info.primary_ip = geo_ip.clone();
            }
            if geo_ip.parse::<Ipv4Addr>().is_ok() && info.ipv4.is_empty() {
                info.ipv4 = geo_ip;
            } else if geo_ip.parse::<Ipv6Addr>().is_ok() && info.ipv6.is_empty() {
                info.ipv6 = geo_ip;
            }
        }
        info.country_code = v["country_code"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        info.country = v["country"].as_str().unwrap_or("").trim().to_string();
        info.city = v["city"].as_str().unwrap_or("").trim().to_string();

        // ipwho.is puts ASN under connection.{asn,org,isp}; api.ip.sb puts top-level {asn,asn_organization,isp}
        if let Some(asn_num) = v["connection"]["asn"]
            .as_u64()
            .or_else(|| v["asn"].as_u64())
        {
            info.asn = format!("AS{asn_num}");
        }
        info.org = v["connection"]["org"]
            .as_str()
            .or_else(|| v["asn_organization"].as_str())
            .or_else(|| v["organization"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        info.isp = v["connection"]["isp"]
            .as_str()
            .or_else(|| v["isp"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
    }

    if info.primary_ip.is_empty() {
        info.primary_ip = if !info.ipv4.is_empty() {
            info.ipv4.clone()
        } else {
            info.ipv6.clone()
        };
    }
    if info.country_code.is_empty() && !info.cf_loc.is_empty() {
        info.country_code = info.cf_loc.clone();
    }

    info
}

/// Streams only the first `max_bytes` of an HTTP body (up to 4s) and stops immediately,
/// preventing multi-megabyte HTML pages (YouTube/Netflix/Gemini) from hitting full-body timeouts
/// while preserving any bytes already received.
async fn read_snippet(mut resp: reqwest::Response, max_bytes: usize) -> String {
    let mut buf = Vec::with_capacity(max_bytes.min(16_384));
    let _ = tokio::time::timeout(Duration::from_secs(4), async {
        while buf.len() < max_bytes {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    let take = (max_bytes - buf.len()).min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
                _ => break,
            }
        }
    })
    .await;
    String::from_utf8_lossy(&buf).to_string()
}

async fn probe_chatgpt(clients: &ProbeClients, fallback_loc: &str) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let trace_fut = fetch_cf_trace(&clients.follow, "https://chatgpt.com/cdn-cgi/trace");
    let web_fut = async {
        match clients
            .no_redirect
            .get("https://chatgpt.com/")
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .await
        {
            Ok(r) => {
                let code = r.status().as_u16();
                let body = read_snippet(r, 8192).await;
                (Some(code), body)
            }
            Err(_) => (None, String::new()),
        }
    };
    let api_fut = async {
        match clients
            .no_redirect
            .get("https://api.openai.com/v1/models")
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(r) => {
                let code = r.status().as_u16();
                let body = read_snippet(r, 4096).await;
                (Some(code), body)
            }
            Err(_) => (None, String::new()),
        }
    };

    let (trace_res, (web_code, web_body), (api_code, api_body)) =
        tokio::join!(trace_fut, web_fut, api_fut);
    let loc = trace_res
        .as_ref()
        .and_then(|(m, _)| m.get("loc").cloned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback_loc.to_string());
    let (status, region, detail) = classify_chatgpt(web_code, &web_body, api_code, &api_body, &loc);
    ServiceUnlockResult {
        service: "chatgpt".to_string(),
        name: "ChatGPT / OpenAI".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn probe_claude(clients: &ProbeClients, fallback_loc: &str) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let trace_fut = fetch_cf_trace(&clients.follow, "https://claude.ai/cdn-cgi/trace");
    let page_fut = async {
        match clients
            .follow
            .get("https://claude.ai/login")
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .await
        {
            Ok(r) => {
                let code = r.status().as_u16();
                let url = r.url().to_string();
                let body = read_snippet(r, 8192).await;
                (Some(code), url, body)
            }
            Err(_) => (None, String::new(), String::new()),
        }
    };
    let (trace_res, (code, url, body)) = tokio::join!(trace_fut, page_fut);
    let loc = trace_res
        .as_ref()
        .and_then(|(m, _)| m.get("loc").cloned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback_loc.to_string());
    let (status, region, detail) = classify_claude(code, &url, &body, &loc);
    ServiceUnlockResult {
        service: "claude".to_string(),
        name: "Claude / Anthropic".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn probe_gemini(clients: &ProbeClients, fallback_loc: &str) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let (code, url, body) = match clients
        .follow
        .get("https://gemini.google.com/")
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(r) => {
            let code = r.status().as_u16();
            let url = r.url().to_string();
            let body = read_snippet(r, 65_536).await;
            (Some(code), url, body)
        }
        Err(_) => (None, String::new(), String::new()),
    };
    let (status, mut region, detail) = classify_gemini(code, &url, &body);
    if region.is_empty() && status == "unlocked" {
        region = fallback_loc.to_string();
    }
    ServiceUnlockResult {
        service: "gemini".to_string(),
        name: "Google Gemini".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn probe_netflix(clients: &ProbeClients) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let fetch_title = |url: &'static str| async move {
        match clients
            .no_redirect
            .get(url)
            .header("Accept", "text/html,application/xhtml+xml")
            .header("Accept-Language", "en-US,en;q=0.9")
            .send()
            .await
        {
            Ok(r) => {
                let code = r.status().as_u16();
                let loc = r
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = read_snippet(r, 32_768).await;
                (Some(code), loc, body)
            }
            Err(_) => (None, String::new(), String::new()),
        }
    };

    // 80018499 = Netflix Original; 70143836 (Breaking Bad) & 81280792 = Licensed non-originals
    let (orig, lic1) = tokio::join!(
        fetch_title("https://www.netflix.com/title/80018499"),
        fetch_title("https://www.netflix.com/title/70143836")
    );
    let lic = if matches!(lic1.0, Some(404)) && matches!(orig.0, Some(200..=399)) {
        // Fallback second licensed title to avoid single-country catalog licensing gaps
        let lic2 = fetch_title("https://www.netflix.com/title/81280792").await;
        if matches!(lic2.0, Some(200..=399)) {
            lic2
        } else {
            lic1
        }
    } else {
        lic1
    };

    let (status, region, detail) =
        classify_netflix(orig.0, &orig.1, &orig.2, lic.0, &lic.1, &lic.2);
    ServiceUnlockResult {
        service: "netflix".to_string(),
        name: "Netflix".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn probe_disney(clients: &ProbeClients, fallback_loc: &str) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let (code, loc, body) = match clients
        .no_redirect
        .get("https://www.disneyplus.com/")
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(r) => {
            let code = r.status().as_u16();
            let loc = r
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = read_snippet(r, 16_384).await;
            (Some(code), loc, body)
        }
        Err(_) => (None, String::new(), String::new()),
    };
    let (status, mut region, detail) = classify_disney(code, &loc, &body);
    if region.is_empty() && status == "unlocked" {
        region = fallback_loc.to_string();
    }
    ServiceUnlockResult {
        service: "disney".to_string(),
        name: "Disney+".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn probe_youtube(clients: &ProbeClients) -> ServiceUnlockResult {
    let t0 = Instant::now();
    let (code, body) = match clients
        .follow
        .get("https://www.youtube.com/premium")
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cookie", "CONSENT=YES+cb.20240101-01-p0.en+FX+999")
        .send()
        .await
    {
        Ok(r) => {
            let code = r.status().as_u16();
            let body = read_snippet(r, 131_072).await;
            (Some(code), body)
        }
        Err(_) => (None, String::new()),
    };
    let (status, region, detail) = classify_youtube(code, &body);
    ServiceUnlockResult {
        service: "youtube".to_string(),
        name: "YouTube Premium".to_string(),
        status: status.to_string(),
        region,
        detail,
        latency_ms: Some(t0.elapsed().as_millis() as u64),
    }
}

async fn run_all_probes_on_clients(
    clients: &ProbeClients,
    is_direct: bool,
    ip_version: &str,
) -> (EgressIpSummary, Vec<ServiceUnlockResult>) {
    let ip_info = probe_ip_summary(clients, is_direct, ip_version).await;
    let fallback_loc = if !ip_info.cf_loc.is_empty() {
        ip_info.cf_loc.clone()
    } else {
        ip_info.country_code.clone()
    };

    let (chatgpt, claude, gemini, netflix, disney, youtube) = tokio::join!(
        probe_chatgpt(clients, &fallback_loc),
        probe_claude(clients, &fallback_loc),
        probe_gemini(clients, &fallback_loc),
        probe_netflix(clients),
        probe_disney(clients, &fallback_loc),
        probe_youtube(clients),
    );
    (
        ip_info,
        vec![chatgpt, claude, gemini, netflix, disney, youtube],
    )
}

fn status_rank(s: &str) -> u8 {
    match s {
        "unlocked" => 3,
        "partial" => 2,
        "blocked" => 1,
        _ => 0,
    }
}

fn service_routing_preset(service: &str) -> (&'static str, &'static str, &'static [&'static str]) {
    match service {
        "chatgpt" => (
            "ChatGPT / OpenAI",
            "geosite-openai",
            &["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
        ),
        "claude" => (
            "Claude / Anthropic",
            "geosite-anthropic",
            &["anthropic.com", "claude.ai"],
        ),
        "gemini" => (
            "Google Gemini",
            "geosite-google-gemini",
            &["gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com"],
        ),
        "netflix" => (
            "Netflix",
            "geosite-netflix",
            &["netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net"],
        ),
        "disney" => (
            "Disney+",
            "geosite-disney",
            &["disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com"],
        ),
        "youtube" => (
            "YouTube Premium",
            "geosite-youtube",
            &["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"],
        ),
        _ => ("Service", "", &[]),
    }
}

pub fn compute_recommendations(reports: &[EgressTargetReport]) -> Vec<RoutingRecommendation> {
    let direct_reports: Vec<&EgressTargetReport> =
        reports.iter().filter(|r| r.kind == "direct" && r.ok).collect();
    let group_reports: Vec<&EgressTargetReport> = reports
        .iter()
        .filter(|r| r.kind == "outbound_group" && r.ok && !r.group_name.is_empty())
        .collect();

    if direct_reports.is_empty() || group_reports.is_empty() {
        return Vec::new();
    }

    let mut recs = Vec::new();
    for service in ["chatgpt", "claude", "gemini", "netflix", "disney", "youtube"] {
        // Best status achieved across direct targets (e.g. IPv4 / IPv6)
        let direct_best = direct_reports
            .iter()
            .filter_map(|r| r.services.iter().find(|s| s.service == service))
            .max_by_key(|s| status_rank(&s.status));
        let Some(direct_svc) = direct_best else {
            continue;
        };
        let direct_score = status_rank(&direct_svc.status);
        if direct_score >= 3 {
            continue;
        }

        let best_group_match = group_reports
            .iter()
            .filter_map(|r| {
                r.services
                    .iter()
                    .find(|s| s.service == service)
                    .map(|s| (r, s))
            })
            .max_by_key(|(_, s)| status_rank(&s.status));

        if let Some((grp_rep, grp_svc)) = best_group_match {
            if status_rank(&grp_svc.status) > direct_score && status_rank(&grp_svc.status) >= 2 {
                let (svc_name, rs_name, domains) = service_routing_preset(service);
                recs.push(RoutingRecommendation {
                    service: service.to_string(),
                    service_name: svc_name.to_string(),
                    direct_status: direct_svc.status.clone(),
                    best_group: grp_rep.group_name.clone(),
                    best_status: grp_svc.status.clone(),
                    best_region: grp_svc.region.clone(),
                    suggested_rule_source: rs_name.to_string(),
                    suggested_domains: domains.iter().map(|s| (*s).to_string()).collect(),
                });
            }
        }
    }
    recs
}

async fn probe_single_target(
    db: &Database,
    target: EgressProbeTargetReq,
    timeout: Duration,
) -> EgressTargetReport {
    let t0 = Instant::now();
    let kind = if target.kind.trim().eq_ignore_ascii_case("outbound_group") {
        "outbound_group".to_string()
    } else {
        "direct".to_string()
    };
    let ip_version = match target.ip_version.trim().to_ascii_lowercase().as_str() {
        "ipv4" | "v4" | "4" => "ipv4".to_string(),
        "ipv6" | "v6" | "6" => "ipv6".to_string(),
        _ => "auto".to_string(),
    };
    let group_name = target.group_name.trim().to_string();
    let member_name = target.member_name.trim().to_string();

    let (target_id, label) = if kind == "direct" {
        let lbl = match ip_version.as_str() {
            "ipv4" => "Direct (IPv4)".to_string(),
            "ipv6" => "Direct (IPv6)".to_string(),
            _ => "Direct".to_string(),
        };
        (format!("direct:{ip_version}"), lbl)
    } else {
        let mut lbl = group_name.clone();
        if !member_name.is_empty() {
            lbl.push_str(&format!(" / {member_name}"));
        }
        if ip_version != "auto" {
            lbl.push_str(&format!(" ({})", ip_version.to_ascii_uppercase()));
        }
        (
            format!("group:{group_name}:{member_name}:{ip_version}"),
            lbl,
        )
    };

    if kind == "direct" {
        let local_ip = match ip_version.as_str() {
            "ipv4" => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            "ipv6" => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            _ => None,
        };
        let clients = match build_probe_clients(None, local_ip, timeout) {
            Ok(c) => c,
            Err(e) => {
                return EgressTargetReport {
                    target_id,
                    kind,
                    label,
                    group_name,
                    member_name,
                    ip_version,
                    ok: false,
                    error: Some(e.to_string()),
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                    ip_info: EgressIpSummary::default(),
                    services: Vec::new(),
                };
            }
        };
        let (ip_info, services) = run_all_probes_on_clients(&clients, true, &ip_version).await;
        let reachable = !ip_info.primary_ip.is_empty()
            || services.iter().any(|s| s.status != "error");
        let error = if !reachable {
            Some(match ip_version.as_str() {
                "ipv6" => "IPv6 egress appears unavailable on this host".to_string(),
                "ipv4" => "IPv4 egress appears unavailable on this host".to_string(),
                _ => "Direct egress unreachable".to_string(),
            })
        } else {
            None
        };
        return EgressTargetReport {
            target_id,
            kind,
            label,
            group_name,
            member_name,
            ip_version,
            ok: reachable,
            error,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            ip_info,
            services,
        };
    }

    // Outbound group probe via isolated ephemeral shoes HTTP sidecar
    let ip_strat = match ip_version.as_str() {
        "ipv4" => Some("ipv4_only"),
        "ipv6" => Some("ipv6_only"),
        _ => None,
    };
    let member_opt = (!member_name.is_empty()).then_some(member_name.as_str());
    let sidecar = match ShoesProbeSidecar::start(db, &group_name, member_opt, ip_strat).await {
        Ok(s) => s,
        Err(e) => {
            return EgressTargetReport {
                target_id,
                kind,
                label,
                group_name,
                member_name,
                ip_version,
                ok: false,
                error: Some(format!("{e:#}")),
                elapsed_ms: t0.elapsed().as_millis() as u64,
                ip_info: EgressIpSummary::default(),
                services: Vec::new(),
            };
        }
    };

    let clients = match build_probe_clients(Some(&sidecar.proxy_url), None, timeout) {
        Ok(c) => c,
        Err(e) => {
            sidecar.shutdown().await;
            return EgressTargetReport {
                target_id,
                kind,
                label,
                group_name,
                member_name,
                ip_version,
                ok: false,
                error: Some(e.to_string()),
                elapsed_ms: t0.elapsed().as_millis() as u64,
                ip_info: EgressIpSummary::default(),
                services: Vec::new(),
            };
        }
    };

    let (ip_info, services) = run_all_probes_on_clients(&clients, false, &ip_version).await;
    sidecar.shutdown().await;

    let reachable =
        !ip_info.primary_ip.is_empty() || services.iter().any(|s| s.status != "error");
    let error = if !reachable {
        Some(format!(
            "Outbound group '{group_name}' could not reach test endpoints (check credentials, endpoint, or firewall)"
        ))
    } else {
        None
    };

    EgressTargetReport {
        target_id,
        kind,
        label,
        group_name,
        member_name,
        ip_version,
        ok: reachable,
        error,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        ip_info,
        services,
    }
}

/// Runs egress quality and streaming/AI unlock diagnostics across up to 6 targets concurrently,
/// preserving caller target ordering.
pub async fn probe_egress_batch(
    db: Arc<Database>,
    targets: Vec<EgressProbeTargetReq>,
    timeout: Duration,
) -> EgressProbeResponse {
    let capped: Vec<EgressProbeTargetReq> = targets.into_iter().take(6).collect();
    let count = capped.len();
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, target) in capped.into_iter().enumerate() {
        let db_clone = db.clone();
        join_set.spawn(async move {
            let report = probe_single_target(&db_clone, target, timeout).await;
            (idx, report)
        });
    }

    let mut ordered: Vec<Option<EgressTargetReport>> = vec![None; count];
    while let Some(res) = join_set.join_next().await {
        if let Ok((idx, report)) = res {
            if idx < ordered.len() {
                ordered[idx] = Some(report);
            }
        }
    }

    let reports: Vec<EgressTargetReport> = ordered.into_iter().flatten().collect();
    let recommendations = compute_recommendations(&reports);
    EgressProbeResponse {
        checked_at: Utc::now().timestamp_millis(),
        reports,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{OutboundGroupRecord, OutboundMember};

    #[test]
    fn cloudflare_trace_and_service_classifiers_handle_all_verdicts() {
        let trace = parse_cloudflare_trace(
            "fl=21f10\nh=www.cloudflare.com\nip=104.28.200.12\nloc=JP\ncolo=NRT\nwarp=on\n",
        );
        assert_eq!(trace.get("ip").map(String::as_str), Some("104.28.200.12"));
        assert_eq!(trace.get("loc").map(String::as_str), Some("JP"));
        assert_eq!(trace.get("colo").map(String::as_str), Some("NRT"));
        assert_eq!(trace.get("warp").map(String::as_str), Some("on"));

        // ChatGPT: Web + API unlocked
        let (st, reg, detail) = classify_chatgpt(
            Some(200),
            "<html>ChatGPT</html>",
            Some(401),
            r#"{"error":{"code":"invalid_api_key"}}"#,
            "US",
        );
        assert_eq!((st, reg.as_str(), detail.as_str()), ("unlocked", "US", "Web + API"));

        // ChatGPT: API only (Web Cloudflare challenged)
        let (st, reg, _) = classify_chatgpt(
            Some(403),
            "<title>Just a moment...</title>",
            Some(401),
            r#"{"error":{"code":"invalid_api_key"}}"#,
            "JP",
        );
        assert_eq!((st, reg.as_str()), ("partial", "JP"));

        // ChatGPT: Unsupported region (HK)
        let (st, reg, _) = classify_chatgpt(
            Some(200),
            "<html>ok</html>",
            Some(403),
            r#"{"error":{"code":"unsupported_country_region_territory"}}"#,
            "HK",
        );
        assert_eq!((st, reg.as_str()), ("blocked", "HK"));

        // Claude
        assert_eq!(
            classify_claude(Some(200), "https://claude.ai/login", "<html>Claude</html>", "US").0,
            "unlocked"
        );
        assert_eq!(
            classify_claude(Some(200), "https://claude.ai/login", "<html>ok</html>", "HK").0,
            "blocked"
        );
        assert_eq!(
            classify_claude(
                Some(403),
                "https://claude.ai/login",
                "<title>Just a moment...</title>",
                "US"
            )
            .0,
            "blocked"
        );

        // Gemini
        assert_eq!(
            classify_gemini(Some(200), "https://gemini.google.com/app", "45631641,null,true").0,
            "unlocked"
        );
        assert_eq!(
            classify_gemini(Some(200), "https://gemini.google.com/faq", "not available in your country").0,
            "blocked"
        );

        // Netflix: Full unlock with JP region
        let (st, reg, _) = classify_netflix(
            Some(302),
            "https://www.netflix.com/jp/title/80018499",
            "",
            Some(302),
            "https://www.netflix.com/jp/title/70143836",
            "",
        );
        assert_eq!((st, reg.as_str()), ("unlocked", "JP"));

        // Netflix: Originals Only (licensed title 404)
        let (st, reg, _) = classify_netflix(
            Some(200),
            "https://www.netflix.com/sg/title/80018499",
            "",
            Some(404),
            "",
            "",
        );
        assert_eq!((st, reg.as_str()), ("partial", "SG"));

        // Netflix: Blocked (403)
        let (st, _, _) = classify_netflix(Some(403), "", "", Some(403), "", "");
        assert_eq!(st, "blocked");

        // Disney+
        let (st, reg, _) = classify_disney(Some(302), "https://www.disneyplus.com/en-jp", "");
        assert_eq!((st, reg.as_str()), ("unlocked", "JP"));
        let (st, _, _) =
            classify_disney(Some(302), "https://preview.disneyplus.com/unavailable", "");
        assert_eq!(st, "blocked");

        // YouTube Premium
        let (st, reg, _) = classify_youtube(Some(200), r#"{"INNERTUBE_CONTEXT_GL":"US"}"#);
        assert_eq!((st, reg.as_str()), ("unlocked", "US"));
        let (st, reg, _) = classify_youtube(
            Some(200),
            r#"{"INNERTUBE_CONTEXT_GL":"HK"} YouTube Premium is not available in your country"#,
        );
        assert_eq!((st, reg.as_str()), ("blocked", "HK"));
    }

    #[test]
    fn recommendations_identify_services_improved_by_outbound_group() {
        let direct = EgressTargetReport {
            target_id: "direct:ipv4".into(),
            kind: "direct".into(),
            label: "Direct (IPv4)".into(),
            group_name: String::new(),
            member_name: String::new(),
            ip_version: "ipv4".into(),
            ok: true,
            error: None,
            elapsed_ms: 420,
            ip_info: EgressIpSummary::default(),
            services: vec![
                ServiceUnlockResult {
                    service: "chatgpt".into(),
                    name: "ChatGPT / OpenAI".into(),
                    status: "blocked".into(),
                    region: "HK".into(),
                    detail: "Unsupported region (HK)".into(),
                    latency_ms: Some(100),
                },
                ServiceUnlockResult {
                    service: "netflix".into(),
                    name: "Netflix".into(),
                    status: "partial".into(),
                    region: "HK".into(),
                    detail: "Originals Only".into(),
                    latency_ms: Some(120),
                },
                ServiceUnlockResult {
                    service: "youtube".into(),
                    name: "YouTube Premium".into(),
                    status: "unlocked".into(),
                    region: "HK".into(),
                    detail: "Premium Available".into(),
                    latency_ms: Some(90),
                },
            ],
        };
        let warp = EgressTargetReport {
            target_id: "group:warp::auto".into(),
            kind: "outbound_group".into(),
            label: "warp".into(),
            group_name: "warp".into(),
            member_name: String::new(),
            ip_version: "auto".into(),
            ok: true,
            error: None,
            elapsed_ms: 510,
            ip_info: EgressIpSummary {
                warp_status: "on".into(),
                ..Default::default()
            },
            services: vec![
                ServiceUnlockResult {
                    service: "chatgpt".into(),
                    name: "ChatGPT / OpenAI".into(),
                    status: "unlocked".into(),
                    region: "JP".into(),
                    detail: "Web + API".into(),
                    latency_ms: Some(140),
                },
                ServiceUnlockResult {
                    service: "netflix".into(),
                    name: "Netflix".into(),
                    status: "unlocked".into(),
                    region: "JP".into(),
                    detail: "Full".into(),
                    latency_ms: Some(180),
                },
                ServiceUnlockResult {
                    service: "youtube".into(),
                    name: "YouTube Premium".into(),
                    status: "unlocked".into(),
                    region: "JP".into(),
                    detail: "Premium Available".into(),
                    latency_ms: Some(110),
                },
            ],
        };

        let recs = compute_recommendations(&[direct, warp]);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].service, "chatgpt");
        assert_eq!(recs[0].best_group, "warp");
        assert_eq!(recs[0].suggested_rule_source, "geosite-openai");
        assert_eq!(recs[1].service, "netflix");
        assert_eq!(recs[1].best_group, "warp");
        assert_eq!(recs[1].suggested_rule_source, "geosite-netflix");
    }

    #[tokio::test]
    async fn egress_probe_sidecar_yaml_passes_real_shoes_check() -> Result<()> {
        let (priv_k, pub_k, _) = crate::crypto_util::generate_wireguard_keypair();
        let warp_group = OutboundGroupRecord {
            id: 1,
            name: "warp".into(),
            enable: false, // Even disabled groups can be pre-flight probed!
            group_type: "selector".into(),
            default_member: "cf-warp".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            interval_secs: 300,
            timeout_ms: 5000,
            tolerance_ms: 50,
            members: vec![OutboundMember {
                name: "cf-warp".into(),
                protocol: "wireguard".into(),
                address: "162.159.192.1:2408".into(),
                wg_private_key: priv_k,
                wg_public_key: pub_k,
                wg_addresses: vec!["172.16.0.2/32".into(), "2606:4700:110::2/128".into()],
                wg_allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                wg_mtu: 1280,
                wg_keepalive: 25,
                ..Default::default()
            }],
            raw_chains_yaml: String::new(),
            remark: String::new(),
        };

        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let settings = db.get_settings()?;
        let yaml = build_egress_probe_yaml(
            18999,
            "probeuser",
            "probepass",
            "warp",
            Some("cf-warp"),
            Some("ipv4_only"),
            &settings,
            &[],
            &[warp_group],
        )?;
        assert!(yaml.contains("client_group: warp"));
        assert!(yaml.contains("127.0.0.1:18999"));
        assert!(yaml.contains("ip_strategy: ipv4_only"));

        // 1. Cross-platform outbound group (direct + socks) must pass real `shoes check` on every OS
        let relay_group = OutboundGroupRecord {
            id: 2,
            name: "relay-test".into(),
            enable: false,
            group_type: "selector".into(),
            default_member: "direct-out".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            interval_secs: 300,
            timeout_ms: 5000,
            tolerance_ms: 50,
            members: vec![
                OutboundMember {
                    name: "direct-out".into(),
                    protocol: "direct".into(),
                    ..Default::default()
                },
                OutboundMember {
                    name: "socks-out".into(),
                    protocol: "socks".into(),
                    address: "127.0.0.1:1080".into(),
                    ..Default::default()
                },
            ],
            raw_chains_yaml: String::new(),
            remark: String::new(),
        };
        let relay_yaml = build_egress_probe_yaml(
            18998,
            "probeuser",
            "probepass",
            "relay-test",
            Some("direct-out"),
            Some("ipv4_only"),
            &settings,
            &[],
            &[relay_group],
        )?;
        assert!(relay_yaml.contains("client_group: relay-test"));
        assert!(relay_yaml.contains("127.0.0.1:18998"));
        assert!(relay_yaml.contains("ip_strategy: ipv4_only"));

        let bin = PathBuf::from(Database::default_shoes_bin_path(std::path::Path::new(
            "./data",
        )));
        if bin.is_file() {
            let mut tmp_relay = tempfile::Builder::new().suffix(".yaml").tempfile()?;
            tmp_relay.write_all(relay_yaml.as_bytes())?;
            let out_relay = tokio::process::Command::new(&bin)
                .arg("check")
                .arg(tmp_relay.path())
                .output()
                .await?;
            assert!(
                out_relay.status.success(),
                "shoes check failed on relay egress probe YAML:\n{}\nYAML:\n{}",
                String::from_utf8_lossy(&out_relay.stderr),
                relay_yaml
            );

            // 2. WireGuard WARP probe YAML: full validation on Unix; on Windows shoes explicitly reports Unix-only
            let mut tmp = tempfile::Builder::new().suffix(".yaml").tempfile()?;
            tmp.write_all(yaml.as_bytes())?;
            let out = tokio::process::Command::new(&bin)
                .arg("check")
                .arg(tmp.path())
                .output()
                .await?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if cfg!(unix) {
                assert!(
                    out.status.success(),
                    "shoes check failed on WARP egress probe YAML:\n{stderr}\nYAML:\n{yaml}"
                );
            } else {
                assert!(
                    out.status.success() || stderr.contains("WireGuard requires Unix"),
                    "unexpected shoes check failure on Windows:\n{stderr}\nYAML:\n{yaml}"
                );
            }
        }
        Ok(())
    }
}

