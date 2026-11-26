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
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .unwrap_or_default();
        entries.push((modified, BackupEntry {
            filename: fname.to_string(),
            size_bytes: meta.len(),
            modified_at: modified.as_secs() as i64,
        }));
    }
    entries.sort_by(|(at, a), (bt, b)| bt.cmp(at).then_with(|| b.filename.cmp(&a.filename)));
    Ok(entries.into_iter().map(|(_, entry)| entry).collect())
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
    let stamp = Utc::now().format("%Y%m%d-%H%M%S%.9f");
    let safe_prefix: String = prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let safe_prefix = if safe_prefix.is_empty() {
        "manual".to_string()
    } else {
        safe_prefix
    };
    let filename = format!("{safe_prefix}-shoes-panel-{stamp}-{}.db", uuid::Uuid::new_v4());
    let final_path = dir.join(&filename);

    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(&bytes)?;
    tmp.flush()?;
    set_private_file_permissions(tmp.path());
    tmp.persist_noclobber(&final_path)
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

// ==================== Share URI -> OutboundMember Parser ====================

fn decode_b64_flexible(raw: &str) -> Result<Vec<u8>> {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
        Engine as _,
    };
    let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(&clean)
        .or_else(|_| STANDARD_NO_PAD.decode(&clean))
        .or_else(|_| URL_SAFE.decode(&clean))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&clean))
        .map_err(|e| anyhow!("invalid base64 payload: {e}"))
}

fn pct_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

fn format_host_port(host: &str, port: u16) -> String {
    let h = host.trim().trim_matches(['[', ']']);
    if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

fn query_map(parsed: &url::Url) -> std::collections::HashMap<String, String> {
    parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect()
}

fn is_truthy(v: Option<&String>) -> bool {
    v.map(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

pub fn parse_single_share_uri(raw: &str, fallback_idx: usize) -> Result<crate::models::OutboundMember> {
    let line = raw.trim();
    if line.is_empty() {
        return Err(anyhow!("empty share URI"));
    }
    let lower = line.to_ascii_lowercase();
    let default_name = |frag: Option<&str>, proto: &str| -> String {
        let decoded = frag.map(pct_decode).unwrap_or_default();
        let trimmed = decoded.trim();
        if trimmed.is_empty() {
            format!("{proto}-{fallback_idx}")
        } else {
            trimmed.to_string()
        }
    };

    if lower.starts_with("vmess://") {
        let b64 = &line[8..];
        let json_bytes = decode_b64_flexible(b64).context("failed to decode vmess:// base64")?;
        let v: serde_json::Value =
            serde_json::from_slice(&json_bytes).context("invalid vmess:// JSON")?;
        let host = v["add"].as_str().unwrap_or("").trim();
        let port: u16 = v["port"]
            .as_u64()
            .or_else(|| v["port"].as_str().and_then(|s| s.trim().parse().ok()))
            .ok_or_else(|| anyhow!("vmess:// missing port"))? as u16;
        let uuid = v["id"].as_str().unwrap_or("").trim().to_string();
        if host.is_empty() || uuid.is_empty() {
            return Err(anyhow!("vmess:// missing host or id"));
        }
        let name = v["ps"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("vmess-{fallback_idx}"));
        let cipher = v["scy"].as_str().unwrap_or("aes-128-gcm").trim().to_string();
        let net = v["net"].as_str().unwrap_or("tcp").trim().to_ascii_lowercase();
        let tls_on = v["tls"].as_str().unwrap_or("").eq_ignore_ascii_case("tls");
        let sni = v["sni"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| v["host"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let alpn: Vec<String> = v["alpn"]
            .as_str()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let insecure = v["allowInsecure"].as_i64().unwrap_or(0) != 0
            || v["allowInsecure"].as_bool().unwrap_or(false);
        return Ok(crate::models::OutboundMember {
            name,
            protocol: "vmess".to_string(),
            address: format_host_port(host, port),
            uuid,
            cipher: if cipher.is_empty() || cipher == "auto" {
                "aes-128-gcm".to_string()
            } else {
                cipher
            },
            security: if tls_on { "tls" } else { "none" }.to_string(),
            tls: tls_on,
            sni,
            verify: !insecure,
            alpn,
            network: if net == "ws" { "ws" } else { "tcp" }.to_string(),
            ws_path: v["path"].as_str().unwrap_or("").trim().to_string(),
            ws_host: v["host"].as_str().unwrap_or("").trim().to_string(),
            ..Default::default()
        });
    }

    if lower.starts_with("ss://") {
        let rest = &line[5..];
        let (before_frag, frag) = match rest.split_once('#') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };
        let (main_part, query_part) = match before_frag.split_once('?') {
            Some((a, b)) => (a.trim_end_matches('/'), Some(b)),
            None => (before_frag.trim_end_matches('/'), None),
        };
        let (cipher, password, address) = if let Some((userinfo, hostport)) = main_part.split_once('@') {
            let decoded_ui = if userinfo.contains(':') {
                pct_decode(userinfo)
            } else {
                String::from_utf8(decode_b64_flexible(userinfo)?)
                    .unwrap_or_else(|_| pct_decode(userinfo))
            };
            let (c, p) = decoded_ui
                .split_once(':')
                .ok_or_else(|| anyhow!("ss:// invalid userinfo"))?;
            (c.trim().to_string(), p.trim().to_string(), hostport.trim().to_string())
        } else {
            let decoded = String::from_utf8(decode_b64_flexible(main_part)?)
                .context("ss:// invalid legacy base64")?;
            let (ui, hp) = decoded
                .split_once('@')
                .ok_or_else(|| anyhow!("ss:// missing @ in decoded payload"))?;
            let (c, p) = ui
                .split_once(':')
                .ok_or_else(|| anyhow!("ss:// missing cipher:password"))?;
            (c.trim().to_string(), p.trim().to_string(), hp.trim().to_string())
        };
        let mut m = crate::models::OutboundMember {
            name: default_name(frag, "ss"),
            protocol: "shadowsocks".to_string(),
            address,
            cipher,
            password,
            security: "none".to_string(),
            network: "tcp".to_string(),
            ..Default::default()
        };
        if let Some(q) = query_part {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case("plugin") {
                        let plug = pct_decode(v);
                        let parts: Vec<&str> = plug.split(';').collect();
                        let pname = parts.first().copied().unwrap_or("").trim().to_ascii_lowercase();
                        if pname == "shadow-tls" {
                            m.security = "shadowtls".to_string();
                            m.shadowtls = true;
                            for opt in parts.iter().skip(1) {
                                if let Some((ok, ov)) = opt.split_once('=') {
                                    match ok.trim().to_ascii_lowercase().as_str() {
                                        "host" | "sni" => m.sni = ov.trim().to_string(),
                                        "password" => m.shadowtls_password = ov.trim().to_string(),
                                        _ => {}
                                    }
                                }
                            }
                        } else if pname == "v2ray-plugin" {
                            m.network = "ws".to_string();
                            for opt in parts.iter().skip(1) {
                                if opt.trim().eq_ignore_ascii_case("tls") {
                                    m.security = "tls".to_string();
                                    m.tls = true;
                                } else if let Some((ok, ov)) = opt.split_once('=') {
                                    match ok.trim().to_ascii_lowercase().as_str() {
                                        "host" => {
                                            m.ws_host = ov.trim().to_string();
                                            if m.sni.is_empty() {
                                                m.sni = ov.trim().to_string();
                                            }
                                        }
                                        "path" => m.ws_path = ov.trim().to_string(),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return Ok(m);
    }

    // Standard RFC-3986 URI schemes: vless://, trojan://, hysteria2://, hy2://, tuic://, anytls://, socks://, socks5://, http://, https://
    let parsed = url::Url::parse(line).with_context(|| format!("invalid URI '{line}'"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("{scheme}:// missing host"))?;
    let default_port = match scheme.as_str() {
        "http" => 80,
        "socks" | "socks5" => 1080,
        _ => 443,
    };
    let port = parsed.port().unwrap_or(default_port);
    let address = format_host_port(host, port);
    let q = query_map(&parsed);
    let name = default_name(parsed.fragment(), &scheme);
    let sni = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .or_else(|| q.get("servername"))
        .cloned()
        .unwrap_or_default();
    let insecure = is_truthy(q.get("allowinsecure")) || is_truthy(q.get("insecure"));
    let alpn: Vec<String> = q
        .get("alpn")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    match scheme.as_str() {
        "vless" => {
            let uuid = pct_decode(parsed.username());
            if uuid.is_empty() {
                return Err(anyhow!("vless:// missing UUID"));
            }
            let raw_sec = q
                .get("security")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "none".to_string());
            let security = match raw_sec.as_str() {
                "tls" => "tls",
                "reality" => "reality",
                _ => "none",
            };
            let raw_net = q
                .get("type")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "tcp".to_string());
            let network = match raw_net.as_str() {
                "ws" | "websocket" => "ws",
                "xhttp" | "splithttp" => "xhttp",
                _ => "tcp",
            };
            let flow = q.get("flow").cloned().unwrap_or_default();
            let vision = flow.to_ascii_lowercase().contains("vision");
            let enc = q
                .get("encryption")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
                .unwrap_or_default();
            let path = q.get("path").cloned().unwrap_or_default();
            let host_hdr = q.get("host").cloned().unwrap_or_default();
            Ok(crate::models::OutboundMember {
                name,
                protocol: "vless".to_string(),
                address,
                uuid,
                security: security.to_string(),
                tls: security == "tls",
                sni,
                verify: !insecure,
                alpn,
                reality_public_key: q.get("pbk").cloned().unwrap_or_default(),
                reality_short_id: q.get("sid").cloned().unwrap_or_default(),
                reality_mldsa65_verify: q.get("pqv").cloned().unwrap_or_default(),
                vision,
                vless_encryption: enc,
                network: network.to_string(),
                ws_path: if network == "ws" { path.clone() } else { String::new() },
                ws_host: if network == "ws" { host_hdr.clone() } else { String::new() },
                xhttp_path: if network == "xhttp" { path } else { String::new() },
                xhttp_host: if network == "xhttp" { host_hdr } else { String::new() },
                xhttp_mode: q.get("mode").cloned().unwrap_or_default(),
                ..Default::default()
            })
        }
        "trojan" => {
            let password = pct_decode(parsed.username());
            if password.is_empty() {
                return Err(anyhow!("trojan:// missing password"));
            }
            let raw_sec = q
                .get("security")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "tls".to_string());
            let security = match raw_sec.as_str() {
                "none" => "none",
                "reality" => "reality",
                _ => "tls",
            };
            let raw_net = q
                .get("type")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "tcp".to_string());
            let network = if matches!(raw_net.as_str(), "ws" | "websocket") {
                "ws"
            } else {
                "tcp"
            };
            Ok(crate::models::OutboundMember {
                name,
                protocol: "trojan".to_string(),
                address,
                password,
                security: security.to_string(),
                tls: security == "tls",
                sni,
                verify: !insecure,
                alpn,
                reality_public_key: q.get("pbk").cloned().unwrap_or_default(),
                reality_short_id: q.get("sid").cloned().unwrap_or_default(),
                reality_mldsa65_verify: q.get("pqv").cloned().unwrap_or_default(),
                network: network.to_string(),
                ws_path: q.get("path").cloned().unwrap_or_default(),
                ws_host: q.get("host").cloned().unwrap_or_default(),
                ..Default::default()
            })
        }
        "hysteria2" | "hy2" => {
            let password = pct_decode(parsed.username());
            if password.is_empty() {
                return Err(anyhow!("hysteria2:// missing password"));
            }
            let obfs_pw = if q
                .get("obfs")
                .map(|s| s.eq_ignore_ascii_case("salamander"))
                .unwrap_or(false)
            {
                q.get("obfs-password").cloned().unwrap_or_default()
            } else {
                String::new()
            };
            Ok(crate::models::OutboundMember {
                name,
                protocol: "hysteria2".to_string(),
                address,
                password,
                security: "tls".to_string(),
                tls: true,
                sni,
                verify: !insecure,
                alpn,
                hy2_obfs_password: obfs_pw,
                hy2_hopping_ports: q.get("mport").cloned().unwrap_or_default(),
                ..Default::default()
            })
        }
        "tuic" => {
            let uuid = pct_decode(parsed.username());
            let password = parsed.password().map(pct_decode).unwrap_or_default();
            if uuid.is_empty() {
                return Err(anyhow!("tuic:// missing uuid"));
            }
            Ok(crate::models::OutboundMember {
                name,
                protocol: "tuic".to_string(),
                address,
                uuid,
                password,
                security: "tls".to_string(),
                tls: true,
                sni,
                verify: !insecure,
                alpn,
                tuic_udp_mode: q
                    .get("udp_relay_mode")
                    .cloned()
                    .unwrap_or_else(|| "native".to_string()),
                ..Default::default()
            })
        }
        "anytls" => {
            let password = pct_decode(parsed.username());
            if password.is_empty() {
                return Err(anyhow!("anytls:// missing password"));
            }
            let is_reality = q
                .get("security")
                .map(|s| s.eq_ignore_ascii_case("reality"))
                .unwrap_or(false)
                || q.contains_key("pbk");
            let security = if is_reality { "reality" } else { "tls" };
            Ok(crate::models::OutboundMember {
                name,
                protocol: "anytls".to_string(),
                address,
                password,
                security: security.to_string(),
                tls: security == "tls",
                sni,
                verify: !insecure,
                alpn,
                reality_public_key: q.get("pbk").cloned().unwrap_or_default(),
                reality_short_id: q.get("sid").cloned().unwrap_or_default(),
                reality_mldsa65_verify: q.get("pqv").cloned().unwrap_or_default(),
                ..Default::default()
            })
        }
        "socks" | "socks5" => Ok(crate::models::OutboundMember {
            name,
            protocol: "socks".to_string(),
            address,
            username: pct_decode(parsed.username()),
            password: parsed.password().map(pct_decode).unwrap_or_default(),
            security: "none".to_string(),
            ..Default::default()
        }),
        "http" | "https" => Ok(crate::models::OutboundMember {
            name,
            protocol: "http".to_string(),
            address,
            username: pct_decode(parsed.username()),
            password: parsed.password().map(pct_decode).unwrap_or_default(),
            security: if scheme == "https" { "tls" } else { "none" }.to_string(),
            tls: scheme == "https",
            sni,
            verify: !insecure,
            ..Default::default()
        }),
        other => Err(anyhow!("Unsupported share URI scheme '{other}://'")),
    }
}

pub fn parse_outbound_share_uris(input: &str) -> Result<Vec<crate::models::OutboundMember>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Please paste one or more share URIs"));
    }
    // Support pasting a Base64-encoded subscription list directly
    let expanded = if !trimmed.contains("://") {
        if let Ok(bytes) = decode_b64_flexible(trimmed) {
            if let Ok(text) = String::from_utf8(bytes) {
                if text.contains("://") {
                    text
                } else {
                    trimmed.to_string()
                }
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };

    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in expanded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
    {
        match parse_single_share_uri(line, idx + 1) {
            Ok(m) => out.push(m),
            Err(e) => errors.push(format!("Line {}: {e}", idx + 1)),
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "No valid proxy URIs parsed: {}",
            errors.join("; ")
        ));
    }
    Ok(out)
}

// ==================== 3x-ui / Xray / Share-URI Inbound Migration Importer ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPreviewItem {
    pub inbound: crate::models::Inbound,
    pub warnings: Vec<String>,
    pub port_conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPreview {
    /// "3x-ui" | "xray" | "share-uri"
    pub source_format: String,
    pub items: Vec<MigrationPreviewItem>,
    pub skipped: Vec<String>,
}

fn parse_json_or_embedded_str(val: Option<&Value>) -> Value {
    match val {
        Some(Value::String(s)) if !s.trim().is_empty() => {
            serde_json::from_str(s).unwrap_or_else(|_| Value::Object(Default::default()))
        }
        Some(v @ Value::Object(_)) | Some(v @ Value::Array(_)) => v.clone(),
        _ => Value::Object(Default::default()),
    }
}

fn parse_u16_flex(val: Option<&Value>) -> Option<u16> {
    let v = val?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok().filter(|&p| p > 0);
    }
    if let Some(s) = v.as_str() {
        let first = s.split(['-', ',']).next().unwrap_or("").trim();
        return first.parse::<u16>().ok().filter(|&p| p > 0);
    }
    None
}

fn parse_port_from_addr(addr: &str) -> Option<u16> {
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix('[') {
        let (_, after) = rest.split_once(']')?;
        return after.strip_prefix(':')?.parse::<u16>().ok().filter(|&p| p > 0);
    }
    let (_, p) = a.rsplit_once(':')?;
    p.parse::<u16>().ok().filter(|&p| p > 0)
}

fn inbounds_conflict(a: &crate::models::Inbound, b: &crate::models::Inbound) -> bool {
    if a.port != b.port {
        let mut ranges = crate::yaml_gen::parse_port_ranges(a.port, &a.protocol_settings.port_range)
            .unwrap_or_default();
        if ranges.is_empty() { ranges.push((a.port, a.port)); }
        if crate::db::overlapping_port(&ranges, b.port, &b.protocol_settings.port_range).is_none() {
            return false;
        }
    }
    if a.is_udp_transport() != b.is_udp_transport() {
        return false;
    }
    let la = if a.listen.trim().is_empty() {
        "0.0.0.0"
    } else {
        a.listen.trim()
    };
    let lb = if b.listen.trim().is_empty() {
        "0.0.0.0"
    } else {
        b.listen.trim()
    };
    let bind_overlaps = la == lb
        || la == "0.0.0.0"
        || lb == "0.0.0.0"
        || la == "::"
        || lb == "::";
    if !bind_overlaps {
        return false;
    }
    // Same-port TCP TLS/REALITY/ShadowTLS inbounds can share if their SNIs are distinct
    if la == lb && a.can_share_sni_port() && b.can_share_sni_port() {
        return a.sni_mux_key() == b.sni_mux_key();
    }
    true
}

fn convert_3xui_inbound_obj(
    obj: &Value,
    idx: usize,
    skipped: &mut Vec<String>,
) -> Vec<(crate::models::Inbound, Vec<String>)> {
    use crate::crypto_util::{
        derive_reality_public_key, derive_wireguard_public_key, generate_random_alnum,
        generate_reality_keypair, generate_short_id, generate_uuid,
    };
    use crate::models::{
        ClientRecord, Inbound, ProtocolSettings, RealitySettings, StreamSettings, TlsSettings,
        WsSettings, XhttpSettings,
    };

    let raw_proto = obj["protocol"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let remark_base = obj["remark"]
        .as_str()
        .or_else(|| obj["tag"].as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("imported-{}", idx + 1));

    let mapped_proto = match raw_proto.as_str() {
        "vless" => "vless",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "shadowsocks" | "ss" => "shadowsocks",
        "dokodemo-door" => "portforward",
        "socks" => "socks",
        "http" => "http",
        "wireguard" => "wireguard",
        "mixed" => "mixed",
        "anytls" => "anytls",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        "" => {
            skipped.push(format!("Item #{}: missing protocol", idx + 1));
            return Vec::new();
        }
        other => {
            skipped.push(format!(
                "Item #{} ('{remark_base}'): unsupported protocol '{other}'",
                idx + 1
            ));
            return Vec::new();
        }
    };

    let port = parse_u16_flex(obj.get("port")).unwrap_or(20000 + (idx as u16));
    let listen = obj["listen"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("0.0.0.0")
        .to_string();
    let enable = obj["enable"].as_bool().unwrap_or(true);
    let total_quota_bytes = obj["total"].as_i64().unwrap_or(0).max(0);
    let raw_expiry = obj["expiryTime"].as_i64().unwrap_or(0);
    let mut warnings = Vec::new();
    let expiry_time = if raw_expiry < 0 {
        warnings.push(
            "3x-ui relative 'expiry after first use' is not supported; reset expiry to never"
                .to_string(),
        );
        0
    } else {
        raw_expiry
    };

    let settings = parse_json_or_embedded_str(obj.get("settings"));
    let stream = parse_json_or_embedded_str(obj.get("streamSettings"));

    let mut ps = ProtocolSettings::default();
    let mut ss = StreamSettings::default();

    // Parse streamSettings (network + security)
    let raw_net = stream["network"]
        .as_str()
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase();
    ss.network = match raw_net.as_str() {
        "tcp" | "raw" | "" => "tcp".to_string(),
        "ws" | "websocket" => "ws".to_string(),
        "xhttp" | "splithttp" => "xhttp".to_string(),
        "quic" => "quic".to_string(),
        other => {
            warnings.push(format!(
                "Transport '{other}' is not supported by shoes; converted to 'tcp'"
            ));
            "tcp".to_string()
        }
    };

    if ss.network == "ws" {
        let ws_obj = &stream["wsSettings"];
        let mut ws = WsSettings {
            path: ws_obj["path"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("/")
                .to_string(),
            ..Default::default()
        };
        if let Some(h) = ws_obj["host"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
            ws.host = h.to_string();
        }
        if let Some(hdrs) = ws_obj["headers"].as_object() {
            for (k, v) in hdrs {
                if let Some(vs) = v.as_str() {
                    if k.eq_ignore_ascii_case("host") && ws.host.is_empty() {
                        ws.host = vs.trim().to_string();
                    }
                    ws.headers.insert(k.clone(), vs.trim().to_string());
                }
            }
        }
        ss.ws = ws;
    } else if ss.network == "xhttp" {
        let xh_obj = if stream["xhttpSettings"].is_object() {
            &stream["xhttpSettings"]
        } else {
            &stream["splithttpSettings"]
        };
        ss.xhttp = XhttpSettings {
            path: xh_obj["path"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("/")
                .to_string(),
            host: xh_obj["host"].as_str().unwrap_or("").trim().to_string(),
            mode: xh_obj["mode"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("auto")
                .to_string(),
            ..Default::default()
        };
    }

    let raw_sec = stream["security"]
        .as_str()
        .unwrap_or("none")
        .trim()
        .to_ascii_lowercase();
    ss.security = match raw_sec.as_str() {
        "reality" => "reality".to_string(),
        "tls" => "tls".to_string(),
        _ => "none".to_string(),
    };

    if ss.security == "reality" {
        let ro = &stream["realitySettings"];
        let dest = ro["target"]
            .as_str()
            .or_else(|| ro["dest"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("www.microsoft.com:443")
            .to_string();
        let sni = ro["serverNames"]
            .as_array()
            .and_then(|arr| arr.iter().find_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty())))
            .map(str::to_string)
            .unwrap_or_else(|| dest.split(':').next().unwrap_or("www.microsoft.com").to_string());
        let mut priv_key = ro["privateKey"].as_str().unwrap_or("").trim().to_string();
        let mut pub_key = ro["settings"]["publicKey"]
            .as_str()
            .or_else(|| ro["publicKey"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if priv_key.is_empty() {
            let (nk, np) = generate_reality_keypair();
            priv_key = nk;
            pub_key = np;
            warnings.push(
                "3x-ui REALITY config had no privateKey; generated a new REALITY keypair"
                    .to_string(),
            );
        } else if pub_key.is_empty() {
            pub_key = derive_reality_public_key(&priv_key).unwrap_or_default();
        }
        let mut short_ids: Vec<String> = ro["shortIds"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::trim))
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if short_ids.is_empty() {
            short_ids.push(generate_short_id(16));
        }
        let fp = ro["settings"]["fingerprint"]
            .as_str()
            .or_else(|| ro["fingerprint"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("chrome")
            .to_string();
        let mldsa_seed = ro["mldsa65Seed"]
            .as_str()
            .or_else(|| ro["settings"]["mldsa65Seed"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let mldsa_verify = ro["settings"]["mldsa65Verify"]
            .as_str()
            .or_else(|| ro["mldsa65Verify"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        ss.reality = RealitySettings {
            sni,
            dest,
            private_key: priv_key,
            public_key: pub_key,
            short_ids,
            vision: false,
            fingerprint: fp,
            mldsa65_seed: mldsa_seed,
            mldsa65_verify: mldsa_verify,
        };
    } else if ss.security == "tls" {
        let to = &stream["tlsSettings"];
        let sni = to["serverName"]
            .as_str()
            .or_else(|| to["settings"]["serverName"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let alpn: Vec<String> = to["alpn"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::trim))
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let cert_obj = to["certificates"].as_array().and_then(|a| a.first());
        let cert_file = cert_obj
            .and_then(|c| c["certificateFile"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let key_file = cert_obj
            .and_then(|c| c["keyFile"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let mut tls = TlsSettings {
            sni,
            alpn,
            ..Default::default()
        };
        if !cert_file.is_empty() && !key_file.is_empty() {
            tls.cert_mode = "files".to_string();
            tls.cert_file = cert_file;
            tls.key_file = key_file;
            warnings.push(
                "Imported TLS certificate file paths from 3x-ui; verify those files exist on this host or switch to a Certificate Source"
                    .to_string(),
            );
        } else {
            tls.cert_mode = "source".to_string();
            warnings.push(
                "TLS inbound has no certificate attached yet; attach a Certificate Source in Edit before enabling"
                    .to_string(),
            );
        }
        ss.tls = tls;
    }

    // Parse protocol-specific settings and clients
    let mut parsed_clients: Vec<ClientRecord> = Vec::new();
    match mapped_proto {
        "vless" => {
            let dec = settings["decryption"].as_str().unwrap_or("").trim();
            if !dec.is_empty() && !dec.eq_ignore_ascii_case("none") {
                ps.vless_decryption = dec.to_string();
            }
            if let Some(arr) = settings["clients"].as_array() {
                for (ci, c) in arr.iter().enumerate() {
                    let flow = c["flow"].as_str().unwrap_or("").trim().to_string();
                    if flow.to_ascii_lowercase().contains("vision") {
                        if ss.security == "reality" {
                            ss.reality.vision = true;
                        } else if ss.security == "tls" {
                            ss.tls.vision = true;
                        } else if !ps.vless_decryption.is_empty() {
                            ps.vless_native_vision = true;
                        }
                    }
                    let cid = c["id"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(generate_uuid);
                    let cname = c["email"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{remark_base}-{}", ci + 1));
                    let sub_id = c["subId"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("default")
                        .to_string();
                    parsed_clients.push(ClientRecord {
                        name: cname,
                        enable: c["enable"].as_bool().unwrap_or(true),
                        uuid: cid,
                        flow,
                        sub_id,
                        expiry_time: c["expiryTime"].as_i64().unwrap_or(0).max(0),
                        ..Default::default()
                    });
                }
            }
        }
        "vmess" => {
            ps.cipher = "aes-128-gcm".to_string();
            if let Some(arr) = settings["clients"].as_array() {
                for (ci, c) in arr.iter().enumerate() {
                    let cid = c["id"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(generate_uuid);
                    let cname = c["email"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{remark_base}-{}", ci + 1));
                    let sub_id = c["subId"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("default")
                        .to_string();
                    parsed_clients.push(ClientRecord {
                        name: cname,
                        enable: c["enable"].as_bool().unwrap_or(true),
                        uuid: cid,
                        sub_id,
                        expiry_time: c["expiryTime"].as_i64().unwrap_or(0).max(0),
                        ..Default::default()
                    });
                }
            }
        }
        "trojan" => {
            if let Some(arr) = settings["clients"].as_array() {
                for (ci, c) in arr.iter().enumerate() {
                    let pw = c["password"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| generate_random_alnum(20));
                    let cname = c["email"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{remark_base}-{}", ci + 1));
                    let sub_id = c["subId"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("default")
                        .to_string();
                    parsed_clients.push(ClientRecord {
                        name: cname,
                        enable: c["enable"].as_bool().unwrap_or(true),
                        password: pw,
                        sub_id,
                        expiry_time: c["expiryTime"].as_i64().unwrap_or(0).max(0),
                        ..Default::default()
                    });
                }
            }
        }
        "shadowsocks" => {
            ps.cipher = settings["method"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("aes-256-gcm")
                .to_string();
            let top_pw = settings["password"].as_str().unwrap_or("").trim().to_string();
            if let Some(arr) = settings["clients"].as_array().filter(|a| !a.is_empty()) {
                for (ci, c) in arr.iter().enumerate() {
                    let pw = c["password"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            if !top_pw.is_empty() {
                                top_pw.clone()
                            } else {
                                generate_random_alnum(24)
                            }
                        });
                    let cname = c["email"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{remark_base}-{}", ci + 1));
                    let sub_id = c["subId"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("default")
                        .to_string();
                    parsed_clients.push(ClientRecord {
                        name: cname,
                        enable: c["enable"].as_bool().unwrap_or(true),
                        password: pw,
                        sub_id,
                        ..Default::default()
                    });
                }
            } else {
                parsed_clients.push(ClientRecord {
                    name: remark_base.clone(),
                    enable: true,
                    password: if top_pw.is_empty() {
                        generate_random_alnum(24)
                    } else {
                        top_pw
                    },
                    sub_id: "default".to_string(),
                    ..Default::default()
                });
            }
        }
        "portforward" => {
            let addr = settings["address"].as_str().unwrap_or("").trim();
            let target_port = parse_u16_flex(settings.get("port")).unwrap_or(80);
            if !addr.is_empty() {
                ps.forward_targets.push(format_host_port(addr, target_port));
            } else {
                warnings.push(
                    "dokodemo-door had no target address; fill forward_targets before enabling"
                        .to_string(),
                );
            }
        }
        "socks" | "http" | "mixed" => {
            if let Some(arr) = settings["accounts"].as_array() {
                for (ci, acc) in arr.iter().enumerate() {
                    let u = acc["user"].as_str().unwrap_or("").trim().to_string();
                    let p = acc["pass"].as_str().unwrap_or("").trim().to_string();
                    parsed_clients.push(ClientRecord {
                        name: if u.is_empty() {
                            format!("{remark_base}-{}", ci + 1)
                        } else {
                            u.clone()
                        },
                        enable: true,
                        username: u,
                        password: p,
                        sub_id: "default".to_string(),
                        ..Default::default()
                    });
                }
            }
        }
        "wireguard" => {
            ss.network = "udp".to_string();
            ss.security = "none".to_string();
            let sk = settings["secretKey"].as_str().unwrap_or("").trim().to_string();
            if !sk.is_empty() {
                ps.wg_server_private_key = sk.clone();
                ps.wg_server_public_key = derive_wireguard_public_key(&sk).unwrap_or_default();
            }
            if let Some(mtu) = settings["mtu"].as_u64() {
                ps.wg_mtu = mtu.clamp(1280, 1420) as u16;
            }
            if let Some(peers) = settings["peers"].as_array() {
                for (pi, p) in peers.iter().enumerate() {
                    let priv_k = p["privateKey"].as_str().unwrap_or("").trim().to_string();
                    let mut pub_k = p["publicKey"].as_str().unwrap_or("").trim().to_string();
                    if pub_k.is_empty() && !priv_k.is_empty() {
                        pub_k = derive_wireguard_public_key(&priv_k).unwrap_or_default();
                    }
                    let allowed = p["allowedIPs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::trim))
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    parsed_clients.push(ClientRecord {
                        name: format!("peer-{}", pi + 1),
                        enable: true,
                        sub_id: "default".to_string(),
                        wg_private_key: priv_k,
                        wg_public_key: pub_k,
                        wg_preshared_key: p["preSharedKey"].as_str().unwrap_or("").trim().to_string(),
                        wg_allowed_ips: allowed,
                        wg_keepalive: p["keepAlive"].as_u64().unwrap_or(25) as u16,
                        ..Default::default()
                    });
                }
            }
        }
        _ => {}
    }

    let make_base = |remark: String, p: u16, clients: Vec<ClientRecord>| Inbound {
        id: 0,
        tag: String::new(),
        remark,
        enable,
        listen: listen.clone(),
        port: p,
        protocol: mapped_proto.to_string(),
        protocol_settings: ps.clone(),
        stream_settings: ss.clone(),
        up_bytes: 0,
        down_bytes: 0,
        total_quota_bytes,
        expiry_time,
        auto_reset_day: 0,
        last_reset_month: String::new(),
        created_at: 0,
        updated_at: 0,
        clients,
    };

    if mapped_proto == "portforward" {
        return vec![(make_base(remark_base, port, Vec::new()), warnings)];
    }

    if parsed_clients.is_empty() {
        let mut draft = make_base(remark_base, port, Vec::new());
        let def = crate::db::default_client_for_inbound(&draft, 1);
        draft.clients.push(def);
        return vec![(draft, warnings)];
    }

    let sample = make_base(remark_base.clone(), port, Vec::new());
    if sample.supports_multi_user() || parsed_clients.len() == 1 {
        return vec![(make_base(remark_base, port, parsed_clients), warnings)];
    }

    // Single-user protocol in shoes with multiple 3x-ui clients -> split cleanly into consecutive ports
    let total_c = parsed_clients.len();
    let mut split_out = Vec::with_capacity(total_c);
    for (ci, c) in parsed_clients.into_iter().enumerate() {
        let mut w = warnings.clone();
        w.push(format!(
            "3x-ui {mapped_proto} had {total_c} clients; shoes uses 1 user per port for {mapped_proto}, so client '{}' was split onto port {}",
            c.name,
            port.saturating_add(ci as u16)
        ));
        let r = if ci == 0 {
            format!("{}-{}", remark_base, c.name)
        } else {
            format!("{}-{}", remark_base, c.name)
        };
        split_out.push((
            make_base(r, port.saturating_add(ci as u16), vec![c]),
            w,
        ));
    }
    split_out
}

fn convert_share_uri_member_to_inbound(
    m: crate::models::OutboundMember,
    idx: usize,
) -> (crate::models::Inbound, Vec<String>) {
    use crate::crypto_util::{generate_random_alnum, generate_reality_keypair, generate_short_id, generate_uuid};
    use crate::models::{
        ClientRecord, Inbound, ProtocolSettings, RealitySettings, ShadowTlsSettings,
        StreamSettings, TlsSettings, WsSettings, XhttpSettings,
    };

    let mut warnings = Vec::new();
    let port = parse_port_from_addr(&m.address).unwrap_or(20000 + (idx as u16));
    let mut ps = ProtocolSettings::default();
    let mut ss = StreamSettings {
        network: if m.network.trim().is_empty() {
            "tcp".to_string()
        } else {
            m.network.trim().to_string()
        },
        security: m.primary_hop().effective_security().to_string(),
        ..Default::default()
    };

    if matches!(m.protocol.as_str(), "hysteria2" | "tuic") {
        ss.network = "quic".to_string();
        ss.security = "tls".to_string();
        ss.tls = TlsSettings {
            sni: m.sni.clone(),
            cert_mode: "auto".to_string(),
            allow_insecure: true,
            alpn: m.alpn.clone(),
            ..Default::default()
        };
        if m.protocol == "hysteria2" {
            if !m.hy2_obfs_password.trim().is_empty() {
                warnings.push(
                    "Hysteria2 Salamander obfs password is preserved as client hint; check server obfs settings if needed"
                        .to_string(),
                );
            }
            if !m.hy2_hopping_ports.trim().is_empty() {
                ps.port_range = m.hy2_hopping_ports.trim().to_string();
            }
        }
    } else {
        if ss.network == "ws" {
            ss.ws = WsSettings {
                path: if m.ws_path.trim().is_empty() {
                    "/".to_string()
                } else {
                    m.ws_path.trim().to_string()
                },
                host: m.ws_host.trim().to_string(),
                ..Default::default()
            };
        } else if ss.network == "xhttp" {
            ss.xhttp = XhttpSettings {
                path: if m.xhttp_path.trim().is_empty() {
                    "/".to_string()
                } else {
                    m.xhttp_path.trim().to_string()
                },
                host: m.xhttp_host.trim().to_string(),
                mode: if m.xhttp_mode.trim().is_empty() {
                    "auto".to_string()
                } else {
                    m.xhttp_mode.trim().to_string()
                },
                ..Default::default()
            };
        }

        match ss.security.as_str() {
            "reality" => {
                let (priv_k, pub_k) = generate_reality_keypair();
                let sni = if m.sni.trim().is_empty() {
                    "www.microsoft.com".to_string()
                } else {
                    m.sni.trim().to_string()
                };
                let sid = if m.reality_short_id.trim().is_empty() {
                    generate_short_id(16)
                } else {
                    m.reality_short_id.trim().to_string()
                };
                ss.reality = RealitySettings {
                    dest: format!("{sni}:443"),
                    sni,
                    private_key: priv_k,
                    public_key: pub_k,
                    short_ids: vec![sid],
                    vision: m.vision,
                    fingerprint: "chrome".to_string(),
                    ..Default::default()
                };
                warnings.push(
                    "Share URI only contains REALITY public key; generated a fresh server private/public keypair — re-export client links after importing"
                        .to_string(),
                );
            }
            "shadowtls" => {
                let sni = if m.sni.trim().is_empty() {
                    "www.microsoft.com".to_string()
                } else {
                    m.sni.trim().to_string()
                };
                ss.shadowtls = ShadowTlsSettings {
                    handshake_addr: format!("{sni}:443"),
                    sni,
                    password: if m.shadowtls_password.trim().is_empty() {
                        generate_random_alnum(20)
                    } else {
                        m.shadowtls_password.trim().to_string()
                    },
                    handshake_mode: "remote".to_string(),
                    ..Default::default()
                };
            }
            "tls" => {
                ss.tls = TlsSettings {
                    sni: m.sni.clone(),
                    cert_mode: "source".to_string(),
                    alpn: m.alpn.clone(),
                    vision: m.vision,
                    allow_insecure: !m.verify,
                    ..Default::default()
                };
                warnings.push(
                    "TLS inbound imported from share URI needs a Certificate Source attached before enabling"
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    if !m.cipher.trim().is_empty() {
        ps.cipher = m.cipher.trim().to_string();
    }
    if !m.vless_encryption.trim().is_empty() {
        ps.vless_encryption = m.vless_encryption.trim().to_string();
        warnings.push(
            "Share URI only contains client VLESS encryption string; generate a matching server decryption pair in Edit"
                .to_string(),
        );
    }

    let client = ClientRecord {
        name: m.name.clone(),
        enable: true,
        uuid: if matches!(m.protocol.as_str(), "vless" | "vmess" | "tuic") {
            if m.uuid.trim().is_empty() {
                generate_uuid()
            } else {
                m.uuid.trim().to_string()
            }
        } else {
            String::new()
        },
        password: if matches!(
            m.protocol.as_str(),
            "trojan" | "shadowsocks" | "hysteria2" | "tuic" | "anytls" | "socks" | "http"
        ) {
            if m.password.trim().is_empty() && !matches!(m.protocol.as_str(), "socks" | "http") {
                generate_random_alnum(20)
            } else {
                m.password.trim().to_string()
            }
        } else {
            String::new()
        },
        username: m.username.trim().to_string(),
        flow: if m.vision {
            "xtls-rprx-vision".to_string()
        } else {
            String::new()
        },
        sub_id: "default".to_string(),
        ..Default::default()
    };

    let ib = Inbound {
        id: 0,
        tag: String::new(),
        remark: m.name,
        enable: true,
        listen: "0.0.0.0".to_string(),
        port,
        protocol: m.protocol,
        protocol_settings: ps,
        stream_settings: ss,
        up_bytes: 0,
        down_bytes: 0,
        total_quota_bytes: 0,
        expiry_time: 0,
        auto_reset_day: 0,
        last_reset_month: String::new(),
        created_at: 0,
        updated_at: 0,
        clients: vec![client],
    };
    (ib, warnings)
}

/// Parses either 3x-ui JSON / Xray `inbounds` JSON OR external proxy share URIs (plain or Base64)
/// into previewable `Inbound` drafts with port-conflict detection and compatibility warnings.
pub fn parse_migration_inbounds(
    input: &str,
    existing_inbounds: &[crate::models::Inbound],
) -> Result<MigrationPreview> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "Please paste 3x-ui / Xray JSON or proxy share URIs"
        ));
    }

    let mut skipped = Vec::new();
    let (source_format, raw_items): (String, Vec<(crate::models::Inbound, Vec<String>)>) =
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            let parsed: Value = serde_json::from_str(trimmed)
                .context("Input starts with JSON but is not valid JSON")?;
            let (fmt, arr): (&str, Vec<Value>) = if let Some(a) = parsed.as_array() {
                ("3x-ui", a.clone())
            } else if let Some(a) = parsed.get("obj").and_then(|v| v.as_array()) {
                ("3x-ui", a.clone())
            } else if let Some(a) = parsed.get("inbounds").and_then(|v| v.as_array()) {
                ("xray", a.clone())
            } else if parsed.get("protocol").is_some() {
                ("3x-ui", vec![parsed])
            } else {
                return Err(anyhow!(
                    "Unrecognized JSON shape: expected 3x-ui inbound object/array, {{ obj: [...] }}, or Xray {{ inbounds: [...] }}"
                ));
            };
            let mut list = Vec::new();
            for (idx, item) in arr.iter().enumerate() {
                list.extend(convert_3xui_inbound_obj(item, idx, &mut skipped));
            }
            (fmt.to_string(), list)
        } else {
            let members = parse_outbound_share_uris(trimmed)?;
            let list = members
                .into_iter()
                .enumerate()
                .map(|(i, m)| convert_share_uri_member_to_inbound(m, i))
                .collect();
            ("share-uri".to_string(), list)
        };

    if raw_items.is_empty() {
        return Err(anyhow!(
            "No importable inbounds found{}",
            if skipped.is_empty() {
                String::new()
            } else {
                format!(": {}", skipped.join("; "))
            }
        ));
    }

    let mut items = Vec::with_capacity(raw_items.len());
    let mut accumulated: Vec<crate::models::Inbound> = existing_inbounds.to_vec();
    for (ib, warnings) in raw_items {
        let port_conflict = accumulated.iter().any(|other| inbounds_conflict(&ib, other));
        accumulated.push(ib.clone());
        items.push(MigrationPreviewItem {
            inbound: ib,
            warnings,
            port_conflict,
        });
    }

    Ok(MigrationPreview {
        source_format,
        items,
        skipped,
    })
}
