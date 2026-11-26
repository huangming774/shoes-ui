use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use parking_lot::Mutex;
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::acme_util::set_private_file_permissions;
use crate::db::Database;
use crate::process::ShoesProcessManager;
use crate::state::AppState;

const PANEL_GITHUB_REPO: &str = "huangming774/shoes-ui";
const SHOES_GITHUB_REPO: &str = "cfal/shoes";
const UPDATE_CACHE_TTL: Duration = Duration::from_secs(600);
const AUTO_BACKUP_POLL_SECS: u64 = 900; // Check every 15 minutes

// ==================== Local Backups & Telegram Push ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub filename: String,
    pub size_bytes: u64,
    pub modified_at: i64,
}

pub fn backups_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("backups")
}

pub fn sanitize_backup_filename(raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.len() > 128
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || !name.ends_with(".db")
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(anyhow!("Invalid backup filename '{name}'"));
    }
    Ok(name.to_string())
}

pub fn list_local_backups(data_dir: &Path) -> Result<Vec<BackupEntry>> {
    let dir = backups_dir(data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !fname.ends_with(".db") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified_at = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        entries.push(BackupEntry {
            filename: fname.to_string(),
            size_bytes: meta.len(),
            modified_at,
        });
    }
    entries.sort_by(|a, b| b.modified_at.cmp(&a.modified_at).then_with(|| b.filename.cmp(&a.filename)));
    Ok(entries)
}

pub fn prune_old_backups(data_dir: &Path, retain_count: usize) -> Result<usize> {
    if retain_count == 0 {
        return Ok(0);
    }
    let list = list_local_backups(data_dir)?;
    let auto_list: Vec<BackupEntry> = list
        .into_iter()
        .filter(|b| b.filename.starts_with("auto-") || b.filename.starts_with("manual-"))
        .collect();
    let mut removed = 0usize;
    for old in auto_list.into_iter().skip(retain_count) {
        let p = backups_dir(data_dir).join(&old.filename);
        if std::fs::remove_file(&p).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn create_local_backup(
    db: &Database,
    prefix: &str,
    retain_count: Option<usize>,
) -> Result<(BackupEntry, Vec<u8>)> {
    let dir = backups_dir(&db.data_dir);
    std::fs::create_dir_all(&dir)?;
    let bytes = db.backup_snapshot()?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    let safe_prefix: String = prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let safe_prefix = if safe_prefix.is_empty() {
        "manual".to_string()
    } else {
        safe_prefix
    };
    let filename = format!("{safe_prefix}-shoes-panel-{stamp}.db");
    let final_path = dir.join(&filename);

    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(&bytes)?;
    tmp.flush()?;
    set_private_file_permissions(tmp.path());
    tmp.persist(&final_path)
        .map_err(|e| anyhow!("failed to persist backup {}: {}", final_path.display(), e.error))?;
    set_private_file_permissions(&final_path);

    if let Some(keep) = retain_count {
        let _ = prune_old_backups(&db.data_dir, keep);
    }

    let entry = BackupEntry {
        filename,
        size_bytes: bytes.len() as u64,
        modified_at: Utc::now().timestamp(),
    };
    Ok((entry, bytes))
}

fn build_telegram_document_multipart(
    boundary: &str,
    chat_id: &str,
    caption: &str,
    filename: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 512);
    let _ = write!(
        body,
        "--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n"
    );
    if !caption.is_empty() {
        let _ = write!(
            body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption}\r\n"
        );
    }
    let _ = write!(
        body,
        "--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    body.extend_from_slice(bytes);
    let _ = write!(body, "\r\n--{boundary}--\r\n");
    body
}

pub async fn send_backup_to_telegram(
    api_base_override: Option<&str>,
    bot_token: &str,
    chat_id_csv: &str,
    filename: &str,
    bytes: &[u8],
    caption: &str,
) -> Result<usize> {
    let token = bot_token.trim();
    if token.is_empty() {
        return Err(anyhow!("Telegram Bot Token is empty"));
    }
    let chat_ids: Vec<&str> = chat_id_csv
        .split([',', ' ', '\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if chat_ids.is_empty() {
        return Err(anyhow!("Telegram Chat ID is empty"));
    }

    let base = api_base_override
        .unwrap_or("https://api.telegram.org")
        .trim_end_matches('/');
    let url = format!("{base}/bot{token}/sendDocument");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut sent = 0usize;
    for chat_id in chat_ids {
        let boundary = format!(
            "----ShoesPanelBackup{}",
            crate::crypto_util::generate_random_alnum(16)
        );
        let body = build_telegram_document_multipart(&boundary, chat_id, caption, filename, bytes);
        let resp = client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .with_context(|| format!("Failed to reach Telegram API for chat_id {chat_id}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let desc = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("description").and_then(Value::as_str).map(str::to_string))
                .unwrap_or(text);
            return Err(anyhow!(
                "Telegram sendDocument failed for chat_id '{chat_id}' (HTTP {}): {desc}",
                status.as_u16()
            ));
        }
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.get("ok").and_then(Value::as_bool) == Some(false) {
                let desc = v
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown Telegram error");
                return Err(anyhow!("Telegram rejected backup for '{chat_id}': {desc}"));
            }
        }
        sent += 1;
    }
    Ok(sent)
}

pub fn build_backup_caption(db: &Database, host_hint: &str) -> String {
    let totals = db.inbound_totals().ok();
    let host = if host_hint.trim().is_empty() {
        "shoes-panel"
    } else {
        host_hint.trim()
    };
    let ts = Utc::now().format("%Y-%m-%d %H:%M UTC");
    match totals {
        Some(t) => format!(
            "Shoes Panel Backup\nHost: {host}\nTime: {ts}\nInbounds: {}/{} | Clients: {}",
            t.inbounds_enabled, t.inbounds_total, t.clients_total
        ),
        None => format!("Shoes Panel Backup\nHost: {host}\nTime: {ts}"),
    }
}

pub fn spawn_auto_backup_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(AUTO_BACKUP_POLL_SECS));
        interval.tick().await;
        tokio::time::sleep(Duration::from_secs(90)).await;

        loop {
            if let Ok(settings) = state.db.get_settings() {
                if settings.auto_backup_enabled {
                    let interval_secs = (settings.auto_backup_interval_hours.max(1) as i64) * 3600;
                    let now = Utc::now().timestamp();
                    let latest_auto_ts = list_local_backups(&state.db.data_dir)
                        .ok()
                        .and_then(|list| {
                            list.into_iter()
                                .find(|b| b.filename.starts_with("auto-"))
                                .map(|b| b.modified_at)
                        })
                        .unwrap_or(0);

                    if now - latest_auto_ts >= interval_secs {
                        let retain = settings.auto_backup_retain_count.clamp(1, 100) as usize;
                        match create_local_backup(&state.db, "auto", Some(retain)) {
                            Ok((entry, bytes)) => {
                                tracing::info!(
                                    "Created scheduled backup '{}' ({} bytes)",
                                    entry.filename,
                                    entry.size_bytes
                                );
                                if settings.tg_backup_enabled
                                    && !settings.tg_bot_token.trim().is_empty()
                                    && !settings.tg_chat_id.trim().is_empty()
                                {
                                    let host = if !settings.public_host.trim().is_empty() {
                                        settings.public_host.clone()
                                    } else {
                                        state.get_detected_public_ip()
                                    };
                                    let caption = build_backup_caption(&state.db, &host);
                                    match send_backup_to_telegram(
                                        None,
                                        &settings.tg_bot_token,
                                        &settings.tg_chat_id,
                                        &entry.filename,
                                        &bytes,
                                        &caption,
                                    )
                                    .await
                                    {
                                        Ok(cnt) => tracing::info!(
                                            "Sent scheduled backup '{}' to {cnt} Telegram chat(s)",
                                            entry.filename
                                        ),
                                        Err(e) => tracing::warn!(
                                            "Scheduled Telegram backup delivery failed: {e}"
                                        ),
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Scheduled local backup failed: {e}");
                            }
                        }
                    }
                }
            }
            interval.tick().await;
        }
    });
}

// ==================== Panel Self-Restart ====================

pub fn schedule_panel_restart(state: Arc<AppState>, delay_ms: u64) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        tracing::info!("Initiating graceful shoes-panel restart...");
        let _ = state.proc_mgr.stop().await;

        let under_systemd = std::env::var_os("INVOCATION_ID").is_some();
        let under_docker = Path::new("/.dockerenv").exists();

        if under_systemd || under_docker {
            // Exit non-zero (EX_TEMPFAIL=75) so systemd Restart=on-failure or Docker restart policy relaunches immediately.
            std::process::exit(75);
        }

        // Standalone launch: re-spawn current executable with identical arguments.
        if let Ok(exe) = std::env::current_exe() {
            let args: Vec<String> = std::env::args().skip(1).collect();
            match std::process::Command::new(&exe).args(&args).spawn() {
                Ok(_) => {
                    tracing::info!("Spawned replacement shoes-panel process; exiting old instance.");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!("Failed to re-spawn shoes-panel: {e}");
                    std::process::exit(75);
                }
            }
        }
        std::process::exit(75);
    });
}

// ==================== GitHub Release Check & Online Upgrade ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentUpdateInfo {
    pub current: String,
    pub latest: String,
    pub has_update: bool,
    pub release_url: String,
    pub published_at: String,
    pub notes: String,
    pub target: Option<String>,
    pub download_supported: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub panel: ComponentUpdateInfo,
    pub shoes: ComponentUpdateInfo,
    pub checked_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpgradeResult {
    pub component: &'static str,
    pub previous_version: String,
    pub new_version: String,
    pub restarting: bool,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

pub fn current_release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("linux", "arm") => Some("armv7-unknown-linux-musleabihf"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

pub fn parse_semver_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    // Extract first X.Y.Z occurrence from strings like "v0.1.3", "shoes 0.1.35 (abc)", "0.1.2-rc1"
    for token in raw.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
        let cleaned = token.trim().trim_start_matches(['v', 'V']);
        let core = cleaned.split(['-', '+']).next().unwrap_or("");
        let mut parts = core.split('.');
        let (Some(a), Some(b), Some(c)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let (Ok(maj), Ok(min), Ok(pat)) = (a.parse::<u64>(), b.parse::<u64>(), c.parse::<u64>()) {
            return Some((maj, min, pat));
        }
    }
    None
}

pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver_tuple(current), parse_semver_tuple(latest)) {
        (Some(cur), Some(lat)) => lat > cur,
        _ => {
            let c = current.trim().trim_start_matches(['v', 'V']);
            let l = latest.trim().trim_start_matches(['v', 'V']);
            !l.is_empty() && !c.is_empty() && c != l && c != "not found" && c != "unknown"
        }
    }
}

pub fn verify_sha256_against_sums(sums_text: &str, filename: &str, bytes: &[u8]) -> Result<()> {
    let expected = sums_text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let fname = parts.next()?.trim_start_matches('*');
        if fname == filename || fname.ends_with(&format!("/{filename}")) {
            Some(hash.to_ascii_lowercase())
        } else {
            None
        }
    });
    let Some(expected_hex) = expected else {
        return Ok(());
    };
    let actual_hex = hex::encode(digest::digest(&digest::SHA256, bytes).as_ref());
    if actual_hex != expected_hex {
        return Err(anyhow!(
            "SHA-256 checksum mismatch for {filename}: expected {expected_hex}, got {actual_hex}"
        ));
    }
    Ok(())
}

async fn fetch_latest_release(client: &reqwest::Client, api_url: &str) -> Result<GhRelease> {
    let resp = client
        .get(api_url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("Failed to query GitHub Releases API ({api_url})"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "GitHub API returned HTTP {} for {api_url}",
            resp.status().as_u16()
        ));
    }
    resp.json::<GhRelease>()
        .await
        .context("Invalid GitHub Release JSON")
}

fn update_cache() -> &'static Mutex<Option<(Instant, UpdateCheckResult)>> {
    static CACHE: OnceLock<Mutex<Option<(Instant, UpdateCheckResult)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

pub async fn check_github_updates(
    db: &Database,
    proc_mgr: &ShoesProcessManager,
    force: bool,
) -> UpdateCheckResult {
    if !force {
        if let Some((at, cached)) = update_cache().lock().clone() {
            if at.elapsed() < UPDATE_CACHE_TTL {
                return cached;
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let target = current_release_target().map(str::to_string);
    let panel_cur = env!("CARGO_PKG_VERSION").to_string();
    let shoes_bin = db
        .get_settings()
        .map(|s| s.shoes_bin_path)
        .unwrap_or_default();
    let shoes_cur = proc_mgr.query_version(&shoes_bin).await;

    let panel_api = format!("https://api.github.com/repos/{PANEL_GITHUB_REPO}/releases/latest");
    let shoes_api = format!("https://api.github.com/repos/{SHOES_GITHUB_REPO}/releases/latest");

    let (panel_res, shoes_res) = tokio::join!(
        fetch_latest_release(&client, &panel_api),
        fetch_latest_release(&client, &shoes_api)
    );

    let panel = match panel_res {
        Ok(rel) => {
            let notes = rel.body.chars().take(600).collect();
            let has_asset = target.as_deref().is_some_and(|t| {
                rel.assets
                    .iter()
                    .any(|a| a.name.starts_with(&format!("shoes-panel-{t}")))
            });
            ComponentUpdateInfo {
                has_update: is_newer_version(&panel_cur, &rel.tag_name),
                current: panel_cur,
                latest: rel.tag_name,
                release_url: rel.html_url,
                published_at: rel.published_at,
                notes,
                target: target.clone(),
                download_supported: has_asset,
                error: None,
            }
        }
        Err(e) => ComponentUpdateInfo {
            current: panel_cur,
            latest: String::new(),
            has_update: false,
            release_url: format!("https://github.com/{PANEL_GITHUB_REPO}/releases"),
            published_at: String::new(),
            notes: String::new(),
            target: target.clone(),
            download_supported: false,
            error: Some(e.to_string()),
        },
    };

    let shoes = match shoes_res {
        Ok(rel) => {
            let notes = rel.body.chars().take(600).collect();
            let has_asset = target.as_deref().is_some_and(|t| {
                rel.assets
                    .iter()
                    .any(|a| a.name.starts_with(&format!("shoes-{t}")))
            });
            ComponentUpdateInfo {
                has_update: is_newer_version(&shoes_cur, &rel.tag_name),
                current: shoes_cur,
                latest: rel.tag_name,
                release_url: rel.html_url,
                published_at: rel.published_at,
                notes,
                target,
                download_supported: has_asset,
                error: None,
            }
        }
        Err(e) => ComponentUpdateInfo {
            current: shoes_cur,
            latest: String::new(),
            has_update: false,
            release_url: format!("https://github.com/{SHOES_GITHUB_REPO}/releases"),
            published_at: String::new(),
            notes: String::new(),
            target,
            download_supported: false,
            error: Some(e.to_string()),
        },
    };

    let result = UpdateCheckResult {
        panel,
        shoes,
        checked_at: Utc::now().timestamp(),
    };
    *update_cache().lock() = Some((Instant::now(), result.clone()));
    result
}

async fn extract_archive_and_find_binary(
    archive_path: &Path,
    dest_dir: &Path,
    bin_names: &[&str],
) -> Result<PathBuf> {
    let is_zip = archive_path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"));

    let status = if is_zip {
        #[cfg(windows)]
        {
            tokio::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                        archive_path.display(),
                        dest_dir.display()
                    ),
                ])
                .status()
                .await
                .context("Failed to execute PowerShell Expand-Archive")?
        }
        #[cfg(not(windows))]
        {
            tokio::process::Command::new("unzip")
                .arg("-o")
                .arg(archive_path)
                .arg("-d")
                .arg(dest_dir)
                .status()
                .await
                .context("Failed to execute unzip")?
        }
    } else {
        tokio::process::Command::new("tar")
            .arg("-xzf")
            .arg(archive_path)
            .arg("-C")
            .arg(dest_dir)
            .status()
            .await
            .context("Failed to execute tar -xzf")?
    };

    if !status.success() {
        return Err(anyhow!(
            "Failed to extract release archive {}",
            archive_path.display()
        ));
    }

    // BFS search up to depth 3 inside dest_dir for matching executable filename
    let mut stack = vec![(dest_dir.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 3 {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push((p, depth + 1));
            } else if p.is_file() {
                if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                    if bin_names.iter().any(|b| b.eq_ignore_ascii_case(fname)) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ =
                                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
                        }
                        return Ok(p);
                    }
                }
            }
        }
    }
    Err(anyhow!(
        "Extracted archive did not contain binary ({:?})",
        bin_names
    ))
}

fn replace_executable_atomic(new_bin: &Path, target_exe: &Path) -> Result<()> {
    let parent = target_exe
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let staged = parent.join(format!(
        ".{}.new-{}",
        target_exe
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("bin"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::copy(new_bin, &staged).with_context(|| {
        format!(
            "Failed to stage new executable into {} (check write permission)",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staged, target_exe).with_context(|| {
            let _ = std::fs::remove_file(&staged);
            format!("Failed to replace executable {}", target_exe.display())
        })?;
    }
    #[cfg(windows)]
    {
        let backup_old = target_exe.with_extension("exe.old");
        let _ = std::fs::remove_file(&backup_old);
        if target_exe.exists() {
            std::fs::rename(target_exe, &backup_old).with_context(|| {
                let _ = std::fs::remove_file(&staged);
                format!("Failed to move running executable {}", target_exe.display())
            })?;
        }
        if let Err(e) = std::fs::rename(&staged, target_exe) {
            let _ = std::fs::rename(&backup_old, target_exe);
            let _ = std::fs::remove_file(&staged);
            return Err(e).context("Failed to install new executable");
        }
    }
    Ok(())
}

pub async fn upgrade_panel_binary(state: Arc<AppState>) -> Result<UpgradeResult> {
    let target = current_release_target().ok_or_else(|| {
        anyhow!(
            "Unsupported platform for one-click upgrade ({}/{})",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let api_url = format!("https://api.github.com/repos/{PANEL_GITHUB_REPO}/releases/latest");
    let rel = fetch_latest_release(&client, &api_url).await?;
    let expected_ext = if cfg!(windows) { ".zip" } else { ".tar.gz" };
    let expected_name = format!("shoes-panel-{target}{expected_ext}");
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name == expected_name)
        .ok_or_else(|| {
            anyhow!(
                "Release {} does not contain asset '{expected_name}'",
                rel.tag_name
            )
        })?;

    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("Failed to download {}", asset.browser_download_url))?
        .error_for_status()?
        .bytes()
        .await?;

    // Verify SHA-256 against SHA256SUMS.txt if present in the release
    if let Some(sums_asset) = rel.assets.iter().find(|a| a.name == "SHA256SUMS.txt") {
        if let Ok(resp) = client.get(&sums_asset.browser_download_url).send().await {
            if resp.status().is_success() {
                if let Ok(sums_text) = resp.text().await {
                    verify_sha256_against_sums(&sums_text, &asset.name, &bytes)?;
                }
            }
        }
    }

    let tmp_dir = tempfile::tempdir()?;
    let archive_path = tmp_dir.path().join(&asset.name);
    std::fs::write(&archive_path, &bytes)?;

    let extracted = extract_archive_and_find_binary(
        &archive_path,
        tmp_dir.path(),
        &["shoes-panel", "shoes-panel.exe"],
    )
    .await?;

    // Smoke-test the downloaded binary before replacing current executable
    let ver_out = tokio::process::Command::new(&extracted)
        .arg("version")
        .output()
        .await
        .context("Downloaded shoes-panel binary failed to execute")?;
    if !ver_out.status.success() {
        return Err(anyhow!(
            "Downloaded shoes-panel binary failed health check: {}",
            String::from_utf8_lossy(&ver_out.stderr)
        ));
    }
    let new_ver = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();

    let current_exe = std::env::current_exe().context("Cannot locate current shoes-panel executable")?;
    replace_executable_atomic(&extracted, &current_exe)?;

    // Invalidate update cache and schedule graceful restart
    *update_cache().lock() = None;
    schedule_panel_restart(state, 900);

    Ok(UpgradeResult {
        component: "panel",
        previous_version: env!("CARGO_PKG_VERSION").to_string(),
        new_version: if new_ver.is_empty() { rel.tag_name } else { new_ver },
        restarting: true,
    })
}

pub async fn upgrade_shoes_binary(state: Arc<AppState>) -> Result<UpgradeResult> {
    let target = current_release_target().ok_or_else(|| {
        anyhow!(
            "Unsupported platform for one-click shoes upgrade ({}/{})",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;

    let settings = state.db.get_settings()?;
    let target_bin = PathBuf::from(settings.shoes_bin_path.trim());
    if target_bin.as_os_str().is_empty() {
        return Err(anyhow!("shoes_bin_path is empty in Panel Settings"));
    }
    let previous_version = state.proc_mgr.query_version(settings.shoes_bin_path.trim()).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let api_url = format!("https://api.github.com/repos/{SHOES_GITHUB_REPO}/releases/latest");
    let rel = fetch_latest_release(&client, &api_url).await?;
    let expected_ext = if cfg!(windows) { ".zip" } else { ".tar.gz" };
    let expected_name = format!("shoes-{target}{expected_ext}");
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name == expected_name)
        .or_else(|| {
            rel.assets
                .iter()
                .find(|a| a.name.starts_with(&format!("shoes-{target}")))
        })
        .ok_or_else(|| {
            anyhow!(
                "cfal/shoes release {} does not contain asset for '{target}'",
                rel.tag_name
            )
        })?;

    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("Failed to download {}", asset.browser_download_url))?
        .error_for_status()?
        .bytes()
        .await?;

    let tmp_dir = tempfile::tempdir()?;
    let archive_path = tmp_dir.path().join(&asset.name);
    std::fs::write(&archive_path, &bytes)?;

    let extracted = extract_archive_and_find_binary(
        &archive_path,
        tmp_dir.path(),
        &["shoes", "shoes.exe"],
    )
    .await?;

    // Verify downloaded shoes binary executes cleanly
    let ver_out = tokio::process::Command::new(&extracted)
        .arg("-V")
        .output()
        .await
        .context("Downloaded shoes binary failed to execute")?;
    if !ver_out.status.success() {
        return Err(anyhow!(
            "Downloaded shoes binary failed '-V' check: {}",
            String::from_utf8_lossy(&ver_out.stderr)
        ));
    }
    let new_ver = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();

    // Swap shoes binary under process manager operation lock with automatic rollback on start failure
    let _op = state.proc_mgr.operation.lock().await;
    let was_running = state.proc_mgr.current_pid().await.is_some();
    if was_running {
        state.proc_mgr.stop_child().await?;
    }

    let backup_bin = target_bin.with_extension("bak");
    let had_old = target_bin.exists();
    if had_old {
        let _ = std::fs::copy(&target_bin, &backup_bin);
    }

    if let Err(e) = replace_executable_atomic(&extracted, &target_bin) {
        if had_old && backup_bin.exists() {
            let _ = std::fs::copy(&backup_bin, &target_bin);
        }
        if was_running {
            let _ = state.proc_mgr.start_locked("restart").await;
        }
        return Err(e);
    }

    state.proc_mgr.clear_version_cache();

    if was_running {
        if let Err(start_err) = state.proc_mgr.start_locked("restart").await {
            // Roll back to previous shoes binary so service recovers
            if had_old && backup_bin.exists() {
                let _ = replace_executable_atomic(&backup_bin, &target_bin);
                state.proc_mgr.clear_version_cache();
                let _ = state.proc_mgr.start_locked("restart").await;
            }
            return Err(anyhow!(
                "New shoes binary failed to start (rolled back to previous version): {start_err}"
            ));
        }
    }
    let _ = std::fs::remove_file(&backup_bin);
    *update_cache().lock() = None;

    Ok(UpgradeResult {
        component: "shoes",
        previous_version,
        new_version: if new_ver.is_empty() { rel.tag_name } else { new_ver },
        restarting: false,
    })
}

// ==================== Cloudflare WARP Registration & WireGuard Conf Parser ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpAccountProfile {
    pub address: String,
    pub wg_private_key: String,
    pub wg_public_key: String,
    pub wg_preshared_key: String,
    pub wg_addresses: Vec<String>,
    pub wg_allowed_ips: Vec<String>,
    pub wg_mtu: u16,
    pub wg_keepalive: u16,
    pub account_id: String,
}

fn ensure_cidr(ip: &str, default_v4_prefix: u8, default_v6_prefix: u8) -> String {
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed.contains('/') {
        return trimmed.to_string();
    }
    if trimmed.contains(':') {
        format!("{trimmed}/{default_v6_prefix}")
    } else {
        format!("{trimmed}/{default_v4_prefix}")
    }
}

/// Registers a free Cloudflare WARP WireGuard profile using a locally generated Curve25519 keypair.
pub async fn register_cloudflare_warp() -> Result<WarpAccountProfile> {
    let (private_key, local_public_key, _) = crate::crypto_util::generate_wireguard_keypair();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("okhttp/3.12.1")
        .build()?;

    let payload = serde_json::json!({
        "key": local_public_key,
        "install_id": "",
        "fcm_token": "",
        "tos": Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string(),
        "model": "PC",
        "serial_number": "",
        "locale": "en_US"
    });

    let resp = client
        .post("https://api.cloudflareclient.com/v0a2158/reg")
        .header("CF-Client-Version", "a-6.11-2223")
        .header("Accept", "application/json")
        .json(&payload)
        .send()
        .await
        .context("Failed to connect to Cloudflare WARP registration API")?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("Failed to parse Cloudflare WARP registration response")?;

    if !status.is_success() {
        return Err(anyhow!(
            "Cloudflare WARP API returned HTTP {}: {}",
            status.as_u16(),
            body
        ));
    }

    let account_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let cfg = body
        .get("config")
        .ok_or_else(|| anyhow!("Cloudflare WARP response missing 'config' object"))?;

    let mut addresses = Vec::new();
    if let Some(v4) = cfg.pointer("/interface/addresses/v4").and_then(|v| v.as_str()) {
        if !v4.trim().is_empty() {
            addresses.push(ensure_cidr(v4, 32, 128));
        }
    }
    if let Some(v6) = cfg.pointer("/interface/addresses/v6").and_then(|v| v.as_str()) {
        if !v6.trim().is_empty() {
            addresses.push(ensure_cidr(v6, 32, 128));
        }
    }
    if addresses.is_empty() {
        return Err(anyhow!(
            "Cloudflare WARP response did not include interface tunnel addresses"
        ));
    }

    let peer = cfg
        .pointer("/peers/0")
        .ok_or_else(|| anyhow!("Cloudflare WARP response missing peer entry"))?;
    let peer_public_key = peer
        .get("public_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        .to_string();

    let raw_endpoint = peer
        .pointer("/endpoint/host")
        .and_then(|v| v.as_str())
        .or_else(|| peer.pointer("/endpoint/v4").and_then(|v| v.as_str()))
        .unwrap_or("engage.cloudflareclient.com:2408")
        .trim();
    let endpoint = if let Some(host) = raw_endpoint.strip_suffix(":0") {
        format!("{host}:2408")
    } else if raw_endpoint.is_empty() {
        "engage.cloudflareclient.com:2408".to_string()
    } else {
        raw_endpoint.to_string()
    };

    Ok(WarpAccountProfile {
        address: endpoint,
        wg_private_key: private_key,
        wg_public_key: peer_public_key,
        wg_preshared_key: String::new(),
        wg_addresses: addresses,
        wg_allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        wg_mtu: 1280,
        wg_keepalive: 25,
        account_id,
    })
}

/// Parses a standard WireGuard / `wgcf-profile.conf` INI text into outbound WireGuard fields.
pub fn parse_wireguard_conf(conf_text: &str) -> Result<WarpAccountProfile> {
    let mut section = String::new();
    let mut private_key = String::new();
    let mut public_key = String::new();
    let mut preshared_key = String::new();
    let mut endpoint = String::new();
    let mut addresses = Vec::new();
    let mut allowed_ips = Vec::new();
    let mut mtu: u16 = 1280;
    let mut keepalive: u16 = 25;

    for raw_line in conf_text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => private_key = val.to_string(),
            ("interface", "address") => {
                for part in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    addresses.push(ensure_cidr(part, 32, 128));
                }
            }
            ("interface", "mtu") => {
                if let Ok(parsed) = val.parse::<u16>() {
                    mtu = parsed.clamp(1280, 1420);
                }
            }
            ("peer", "publickey") => public_key = val.to_string(),
            ("peer", "presharedkey") => preshared_key = val.to_string(),
            ("peer", "endpoint") => endpoint = val.to_string(),
            ("peer", "allowedips") => {
                for part in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    allowed_ips.push(part.to_string());
                }
            }
            ("peer", "persistentkeepalive") => {
                if let Ok(parsed) = val.parse::<u16>() {
                    keepalive = parsed;
                }
            }
            _ => {}
        }
    }

    if private_key.is_empty() || public_key.is_empty() || addresses.is_empty() || endpoint.is_empty() {
        return Err(anyhow!(
            "WireGuard config must contain PrivateKey, Address, PublicKey, and Endpoint"
        ));
    }
    if allowed_ips.is_empty() {
        allowed_ips = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    }

    Ok(WarpAccountProfile {
        address: endpoint,
        wg_private_key: private_key,
        wg_public_key: public_key,
        wg_preshared_key: preshared_key,
        wg_addresses: addresses,
        wg_allowed_ips: allowed_ips,
        wg_mtu: mtu,
        wg_keepalive: keepalive,
        account_id: String::new(),
    })
}

// ==================== Rule Source Synchronization (SRS / MRS / GeoData / YAML) ====================

const MAX_RULE_SOURCE_BYTES: usize = 64 * 1024 * 1024;

pub fn parse_rule_interval_secs(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let (num_str, unit) = trimmed.split_at(trimmed.len() - 1);
    let factor: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    let n = num_str.parse::<u64>().ok()?;
    let secs = n.checked_mul(factor)?;
    (1..=365 * 86_400).contains(&secs).then_some(secs)
}

pub fn managed_rule_file_path(
    data_dir: &Path,
    group_name: &str,
    index: usize,
    item: &crate::models::RuleSourceItem,
) -> PathBuf {
    let safe: String = group_name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = if safe.is_empty() {
        "ruleset".to_string()
    } else {
        safe
    };

    let ext = match item.format.trim() {
        "srs" => "srs",
        "mrs" => "mrs",
        "singbox_json" => "json",
        "mihomo_yaml" => "yaml",
        "mihomo_text" => "txt",
        "geosite_dat" | "geoip_dat" => "dat",
        _ => {
            let url_path = item
                .url
                .trim()
                .split(['?', '#'])
                .next()
                .unwrap_or("");
            match Path::new(url_path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_ascii_lowercase())
                .as_deref()
            {
                Some("srs") => "srs",
                Some("mrs") => "mrs",
                Some("json") => "json",
                Some("yaml") | Some("yml") => "yaml",
                Some("txt") => "txt",
                Some("dat") => "dat",
                _ => "srs",
            }
        }
    };
    data_dir.join("rules").join(format!("{safe}_{index}.{ext}"))
}

/// Downloads and atomically caches all `panel`-synced remote items in a rule source group.
/// Returns `Ok(changed)` indicating whether any cached rule file on disk changed.
pub async fn sync_rule_source_group(
    data_dir: &Path,
    group: &mut crate::models::RuleSourceGroupRecord,
) -> Result<bool> {
    let rules_dir = data_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut changed = false;
    let now = Utc::now().timestamp_millis();

    for (idx, item) in group.items.iter_mut().enumerate() {
        if item.source_type == "local" {
            let p = PathBuf::from(item.path.trim());
            if let Ok(meta) = std::fs::metadata(&p) {
                item.file_size = meta.len();
                item.last_updated_at = now;
                item.last_error.clear();
            } else {
                item.last_error = format!("Local file not found: {}", p.display());
                return Err(anyhow!(item.last_error.clone()));
            }
            continue;
        }

        if item.sync_mode == "shoes_native" {
            item.last_error.clear();
            continue;
        }

        let url_str = item.url.trim();
        let parsed = url::Url::parse(url_str)
            .with_context(|| format!("Invalid rule source URL '{url_str}'"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(anyhow!(
                "Rule source URL must use http:// or https:// (got '{}')",
                parsed.scheme()
            ));
        }

        let resp = client
            .get(url_str)
            .send()
            .await
            .with_context(|| format!("Failed to download rule source '{url_str}'"))?;
        if !resp.status().is_success() {
            let err = format!(
                "Failed to download '{}': HTTP {}",
                url_str,
                resp.status().as_u16()
            );
            item.last_error = err.clone();
            return Err(anyhow!(err));
        }
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("Failed to read response body from '{url_str}'"))?;
        if bytes.is_empty() {
            let err = format!("Rule source '{url_str}' returned empty content");
            item.last_error = err.clone();
            return Err(anyhow!(err));
        }
        if bytes.len() > MAX_RULE_SOURCE_BYTES {
            let err = format!("Rule source '{url_str}' exceeds 64 MiB limit");
            item.last_error = err.clone();
            return Err(anyhow!(err));
        }

        let target = managed_rule_file_path(data_dir, &group.name, idx, item);
        let unchanged = std::fs::read(&target)
            .map(|existing| existing.as_slice() == bytes.as_ref())
            .unwrap_or(false);
        if !unchanged {
            let tmp = rules_dir.join(format!(
                ".rule-tmp-{}-{idx}-{}.part",
                now,
                crate::crypto_util::generate_random_alnum(6)
            ));
            std::fs::write(&tmp, &bytes)?;
            if target.exists() {
                let _ = std::fs::remove_file(&target);
            }
            std::fs::rename(&tmp, &target).with_context(|| {
                format!("Failed to save downloaded rule file to {}", target.display())
            })?;
            changed = true;
        }

        let abs_target = std::fs::canonicalize(&target).unwrap_or(target);
        let path_str = abs_target.to_string_lossy().to_string();
        item.path = path_str
            .strip_prefix(r"\\?\")
            .unwrap_or(&path_str)
            .replace('\\', "/");
        item.file_size = bytes.len() as u64;
        item.last_updated_at = now;
        item.last_error.clear();
    }

    Ok(changed)
}

/// Refreshes all due `panel`-synced remote rule sources in the background.
pub async fn sync_due_rule_sources(state: &Arc<AppState>) {
    let groups = match state.db.list_rule_source_groups() {
        Ok(g) => g,
        Err(_) => return,
    };
    let now = Utc::now().timestamp_millis();
    let mut any_changed = false;

    for mut group in groups.into_iter().filter(|g| g.enable) {
        let is_due = group.items.iter().any(|item| {
            if item.source_type != "url" || item.sync_mode == "shoes_native" {
                return false;
            }
            let interval_ms = parse_rule_interval_secs(&item.update_interval)
                .unwrap_or(86_400)
                .saturating_mul(1000) as i64;
            item.last_updated_at <= 0 || (now - item.last_updated_at) >= interval_ms
        });
        if !is_due {
            continue;
        }
        match sync_rule_source_group(&state.db.data_dir, &mut group).await {
            Ok(changed) => {
                let _ = state.db.update_rule_source_items(group.id, &group.items);
                if changed {
                    any_changed = true;
                }
            }
            Err(e) => {
                tracing::warn!("Rule source '{}' auto-refresh failed: {e}", group.name);
                let _ = state.db.update_rule_source_items(group.id, &group.items);
            }
        }
    }

    if any_changed {
        if let Err(e) = state.proc_mgr.reload_config().await {
            tracing::warn!("Failed to reload shoes after rule-set refresh: {e}");
        } else {
            state
                .proc_mgr
                .push_panel_log("Refreshed remote rule sources and hot-reloaded shoes");
        }
    }
}

pub fn spawn_rule_source_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
        // Skip immediate tick so startup stays fast and non-blocking
        interval.tick().await;
        loop {
            interval.tick().await;
            sync_due_rule_sources(&state).await;
        }
    });
}
