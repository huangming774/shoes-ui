use anyhow::{anyhow, Context, Result};
use chrono::{Datelike, NaiveDate, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::crypto_util::{generate_random_alnum, generate_uuid, hash_password, verify_password};
use crate::models::{
    CertificateRecord, ClientRecord, ClusterLocalConfig, ClusterNodeRecord, CoreGlobalSettings,
    DnsGroupRecord, Inbound, InboundTotals, OutboundGroupRecord, PanelSettings, RoutingRuleRecord,
    RuleSourceGroupRecord, RuleSourceItem, StreamSettings, SubscriptionRecord,
    SubscriptionTemplateConfig,
};

pub struct Database {
    conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

const HAS_PORT_RANGE: &str = "CASE WHEN json_valid(protocol_settings)
    THEN coalesce(json_extract(protocol_settings, '$.port_range'), '') <> '' ELSE 0 END";

#[derive(Clone, Copy)]
pub enum ConfigTable {
    Inbounds,
    OutboundGroups,
    RoutingRules,
    DnsGroups,
    RuleSourceGroups,
}

struct DeletedRows {
    table: &'static str,
    rows: Vec<Vec<rusqlite::types::Value>>,
}

pub struct ConfigDeletion {
    tables: Vec<DeletedRows>,
    pub affected: usize,
}

impl Database {
    pub fn open(db_path: &Path, data_dir: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(data_dir)?;
        std::fs::create_dir_all(data_dir.join("certs"))?;
        std::fs::create_dir_all(data_dir.join("acme"))?;

        let conn = Connection::open(db_path)
            .with_context(|| format!("failed to open sqlite db at {}", db_path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let db = Self {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let mut guard = self.conn.lock();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS core_minutes (time INTEGER PRIMARY KEY, metrics TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS core_events (time INTEGER NOT NULL, kind TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS core_events_time ON core_events(time);
            CREATE TABLE IF NOT EXISTS daily_traffic (
                day TEXT PRIMARY KEY,
                up_bytes INTEGER NOT NULL,
                down_bytes INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT UNIQUE NOT NULL,
                remark TEXT NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                listen TEXT NOT NULL DEFAULT '0.0.0.0',
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                protocol_settings TEXT NOT NULL,
                stream_settings TEXT NOT NULL,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                total_quota_bytes INTEGER NOT NULL DEFAULT 0,
                expiry_time INTEGER NOT NULL DEFAULT 0,
                auto_reset_day INTEGER NOT NULL DEFAULT 0,
                last_reset_month TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_inbounds_port ON inbounds(port);
            CREATE INDEX IF NOT EXISTS idx_inbounds_reset ON inbounds(auto_reset_day)
                WHERE auto_reset_day > 0;
            CREATE INDEX IF NOT EXISTS idx_inbounds_expiry ON inbounds(expiry_time)
                WHERE enable = 1 AND expiry_time > 0;
            CREATE INDEX IF NOT EXISTS idx_inbounds_quota ON inbounds(id)
                WHERE enable = 1 AND total_quota_bytes > 0;

            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                uuid TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                flow TEXT NOT NULL DEFAULT '',
                sub_id TEXT NOT NULL DEFAULT 'default',
                up_bytes INTEGER NOT NULL DEFAULT 0,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                total_quota_bytes INTEGER NOT NULL DEFAULT 0,
                expiry_time INTEGER NOT NULL DEFAULT 0,
                comment TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                wg_private_key TEXT NOT NULL DEFAULT '',
                wg_public_key TEXT NOT NULL DEFAULT '',
                wg_preshared_key TEXT NOT NULL DEFAULT '',
                wg_allowed_ips TEXT NOT NULL DEFAULT '',
                wg_keepalive INTEGER NOT NULL DEFAULT 25
            );
            CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);
            CREATE INDEX IF NOT EXISTS idx_clients_sub ON clients(sub_id);

            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                cert_type TEXT NOT NULL,
                cert_file TEXT NOT NULL DEFAULT '',
                key_file TEXT NOT NULL DEFAULT '',
                domains_json TEXT NOT NULL DEFAULT '[]',
                email TEXT NOT NULL DEFAULT '',
                directory_url TEXT NOT NULL DEFAULT '',
                terms_of_service TEXT NOT NULL DEFAULT '',
                challenge_type TEXT NOT NULL DEFAULT 'http01',
                http01_listen TEXT NOT NULL DEFAULT '0.0.0.0:80',
                remark TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                group_type TEXT NOT NULL DEFAULT 'selector',
                default_member TEXT NOT NULL DEFAULT '',
                test_url TEXT NOT NULL DEFAULT 'https://www.gstatic.com/generate_204',
                interval_secs INTEGER NOT NULL DEFAULT 300,
                timeout_ms INTEGER NOT NULL DEFAULT 5000,
                tolerance_ms INTEGER NOT NULL DEFAULT 50,
                members_json TEXT NOT NULL DEFAULT '[]',
                raw_chains_yaml TEXT NOT NULL DEFAULT '',
                remark TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL DEFAULT 100,
                enable INTEGER NOT NULL DEFAULT 1,
                remark TEXT NOT NULL DEFAULT '',
                match_type TEXT NOT NULL,
                match_value TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT 'allow',
                outbound TEXT NOT NULL DEFAULT 'direct',
                no_resolve INTEGER NOT NULL DEFAULT 0,
                override_address TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS dns_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                servers_json TEXT NOT NULL DEFAULT '[]',
                hosts_json TEXT NOT NULL DEFAULT '{}',
                remark TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rule_source_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                items_json TEXT NOT NULL DEFAULT '[]',
                remark TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_id TEXT UNIQUE NOT NULL,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                template TEXT NOT NULL DEFAULT '',
                include_cluster INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cluster_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                region TEXT NOT NULL DEFAULT '',
                region_flag TEXT NOT NULL DEFAULT '',
                api_url TEXT NOT NULL,
                api_token TEXT NOT NULL DEFAULT '',
                share_host_override TEXT NOT NULL DEFAULT '',
                allow_insecure INTEGER NOT NULL DEFAULT 0,
                enable INTEGER NOT NULL DEFAULT 1,
                include_in_sub INTEGER NOT NULL DEFAULT 1,
                node_prefix TEXT NOT NULL DEFAULT '',
                remark TEXT NOT NULL DEFAULT '',
                sort_order INTEGER NOT NULL DEFAULT 100,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;

        conn.execute(&format!("CREATE INDEX IF NOT EXISTS idx_inbounds_range ON inbounds(id) WHERE {HAS_PORT_RANGE}"), [])?;

        // Lightweight column migrations for older databases
        {
            let mut stmt = conn.prepare("PRAGMA table_info(routing_rules)")?;
            let cols: std::collections::HashSet<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<_>>()?;
            if !cols.contains("no_resolve") {
                conn.execute(
                    "ALTER TABLE routing_rules ADD COLUMN no_resolve INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
            if !cols.contains("override_address") {
                conn.execute(
                    "ALTER TABLE routing_rules ADD COLUMN override_address TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
        }
        {
            let mut stmt = conn.prepare("PRAGMA table_info(clients)")?;
            let cols: std::collections::HashSet<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<_>>()?;
            for (col, ddl) in [
                ("wg_private_key", "ALTER TABLE clients ADD COLUMN wg_private_key TEXT NOT NULL DEFAULT ''"),
                ("wg_public_key", "ALTER TABLE clients ADD COLUMN wg_public_key TEXT NOT NULL DEFAULT ''"),
                ("wg_preshared_key", "ALTER TABLE clients ADD COLUMN wg_preshared_key TEXT NOT NULL DEFAULT ''"),
                ("wg_allowed_ips", "ALTER TABLE clients ADD COLUMN wg_allowed_ips TEXT NOT NULL DEFAULT ''"),
                ("wg_keepalive", "ALTER TABLE clients ADD COLUMN wg_keepalive INTEGER NOT NULL DEFAULT 25"),
            ] {
                if !cols.contains(col) {
                    conn.execute(ddl, [])?;
                }
            }
        }

        {
            let mut stmt = conn.prepare("PRAGMA table_info(subscriptions)")?;
            let cols: std::collections::HashSet<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<_>>()?;
            if !cols.contains("template") {
                conn.execute(
                    "ALTER TABLE subscriptions ADD COLUMN template TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
            if !cols.contains("include_cluster") {
                conn.execute(
                    "ALTER TABLE subscriptions ADD COLUMN include_cluster INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
            }
        }

        // Seed default admin user (`admin` / `admin`) if users table is empty
        let user_count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if user_count == 0 {
            let hash = hash_password("admin")?;
            let now = Utc::now().timestamp_millis();
            conn.execute(
                "INSERT INTO users (username, password_hash, updated_at) VALUES (?1, ?2, ?3)",
                params!["admin", hash, now],
            )?;
        }

        // Seed default subscription (`default`) if subscriptions table is empty
        let sub_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))?;
        if sub_count == 0 {
            let now = Utc::now().timestamp_millis();
            conn.execute(
                "INSERT INTO subscriptions (sub_id, token, name, enable, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                params!["default", generate_random_alnum(22), "默认订阅 / Default", now],
            )?;
        }

        // Seed missing keys on first startup and when opening an older database.
        let port = std::env::var("PANEL_PORT").unwrap_or_else(|_| "54321".into());
        let bin = Self::default_shoes_bin_path(&self.data_dir);
        let config = self.data_dir.join("shoes.config.yaml");
        let secret = generate_random_alnum(32);
        let instance_id = generate_uuid();
        {
            let mut insert =
                conn.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)")?;
            for (key, value) in [
                ("panel_listen", "0.0.0.0"),
                ("panel_port", port.as_str()),
                ("panel_base_path", "/"),
                ("panel_cert_file", ""),
                ("panel_key_file", ""),
                ("public_host", ""),
                ("sub_public_url", ""),
                ("shoes_bin_path", bin.as_str()),
                ("shoes_config_path", config.to_string_lossy().as_ref()),
                ("clash_api_addr", "127.0.0.1:19090"),
                ("clash_api_secret", secret.as_str()),
                ("shoes_auto_start", "true"),
                ("shoes_extra_yaml", ""),
                ("session_ttl_hours", "168"),
                ("auto_backup_enabled", "false"),
                ("auto_backup_interval_hours", "24"),
                ("auto_backup_retain_count", "7"),
                ("tg_bot_token", ""),
                ("tg_chat_id", ""),
                ("tg_backup_enabled", "false"),
                ("core_global_settings", "{}"),
                ("cluster_instance_id", instance_id.as_str()),
                ("cluster_local_name", ""),
                ("cluster_local_region", ""),
                ("cluster_local_region_flag", ""),
                ("cluster_api_token", ""),
            ] {
                insert.execute(params![key, value])?;
            }
        }
        conn.commit()?;
        Ok(())
    }

    pub fn default_shoes_bin_path(data_dir: &Path) -> String {
        let exe_name = if cfg!(windows) { "shoes.exe" } else { "shoes" };
        // Check common relative/system locations
        let candidates = [
            data_dir.join(exe_name),
            PathBuf::from(exe_name),
            PathBuf::from("./shoes/target/release").join(exe_name),
            PathBuf::from("./shoes/target/debug").join(exe_name),
            PathBuf::from("../shoes/target/release").join(exe_name),
            PathBuf::from("../shoes/target/debug").join(exe_name),
            PathBuf::from("/usr/local/bin/shoes"),
            PathBuf::from("/usr/bin/shoes"),
        ];
        for c in &candidates {
            if c.is_file() {
                if let Ok(abs) = std::fs::canonicalize(c) {
                    let s = abs.to_string_lossy().to_string();
                    return s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
                }
                return c.to_string_lossy().to_string();
            }
        }
        if cfg!(windows) {
            "shoes.exe".to_string()
        } else {
            "/usr/local/bin/shoes".to_string()
        }
    }

    // ==================== Auth & Users ====================

    pub fn verify_user(&self, username: &str, password: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let hash: Option<String> = conn
            .query_row(
                "SELECT password_hash FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .optional()?;
        drop(conn);
        Ok(match hash {
            Some(h) => verify_password(password, &h),
            None => false,
        })
    }

    pub fn get_admin_username(&self) -> Result<String> {
        let conn = self.conn.lock();
        let u: String = conn.query_row("SELECT username FROM users ORDER BY id ASC LIMIT 1", [], |r| {
            r.get(0)
        })?;
        Ok(u)
    }

    pub fn is_default_credentials(&self) -> bool {
        let conn = self.conn.lock();
        let res: Option<(String, String)> = conn
            .query_row(
                "SELECT username, password_hash FROM users ORDER BY id ASC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        drop(conn);
        matches!(res, Some((u, h)) if u == "admin" && verify_password("admin", &h))
    }

    pub fn update_credentials(
        &self,
        current_password: Option<&str>,
        new_username: &str,
        new_password: &str,
    ) -> Result<()> {
        let new_username = new_username.trim();
        if new_username.is_empty() {
            return Err(anyhow!("Username must not be empty"));
        }
        let changing_password = !new_password.is_empty();
        if !changing_password && current_password.is_none() {
            return Err(anyhow!("Password must be at least 4 characters"));
        }
        if changing_password && new_password.len() < 4 {
            return Err(anyhow!("Password must be at least 4 characters"));
        }
        let conn = self.conn.lock();
        let (id, existing_user, existing_hash): (i64, String, String) = conn.query_row(
            "SELECT id, username, password_hash FROM users ORDER BY id ASC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if let Some(curr) = current_password {
            if !verify_password(curr, &existing_hash) {
                return Err(anyhow!("Current password is incorrect"));
            }
        }
        if !changing_password && new_username == existing_user {
            return Err(anyhow!("Please enter a new username or a new password"));
        }
        let final_hash = if changing_password {
            hash_password(new_password)?
        } else {
            existing_hash
        };
        let now = Utc::now().timestamp_millis();
        conn.execute(
            "UPDATE users SET username = ?1, password_hash = ?2, updated_at = ?3 WHERE id = ?4",
            params![new_username, final_hash, now, id],
        )?;
        Ok(())
    }

    // ==================== Panel Settings ====================

    pub fn get_settings(&self) -> Result<PanelSettings> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }

        let mut get = |key: &str| {
            map.remove(key)
                .with_context(|| format!("Missing panel setting '{key}'"))
        };
        let settings = PanelSettings {
            panel_listen: get("panel_listen")?,
            panel_port: get("panel_port")?.parse().unwrap_or(54321),
            panel_base_path: normalize_base_path(&get("panel_base_path")?),
            panel_cert_file: get("panel_cert_file")?,
            panel_key_file: get("panel_key_file")?,
            public_host: get("public_host")?,
            sub_public_url: get("sub_public_url")?,
            shoes_bin_path: get("shoes_bin_path")?,
            shoes_config_path: get("shoes_config_path")?,
            clash_api_addr: get("clash_api_addr")?,
            clash_api_secret: get("clash_api_secret")?,
            shoes_auto_start: get("shoes_auto_start")? == "true",
            shoes_extra_yaml: get("shoes_extra_yaml")?,
            session_ttl_hours: get("session_ttl_hours")?.parse().unwrap_or(168),
            auto_backup_enabled: map.remove("auto_backup_enabled").as_deref() == Some("true"),
            auto_backup_interval_hours: map
                .remove("auto_backup_interval_hours")
                .and_then(|v| v.parse().ok())
                .unwrap_or(24)
                .clamp(1, 720),
            auto_backup_retain_count: map
                .remove("auto_backup_retain_count")
                .and_then(|v| v.parse().ok())
                .unwrap_or(7)
                .clamp(1, 100),
            tg_bot_token: map.remove("tg_bot_token").unwrap_or_default(),
            tg_chat_id: map.remove("tg_chat_id").unwrap_or_default(),
            tg_backup_enabled: map.remove("tg_backup_enabled").as_deref() == Some("true"),
            core_global: map
                .remove("core_global_settings")
                .and_then(|raw| serde_json::from_str::<CoreGlobalSettings>(&raw).ok())
                .unwrap_or_default(),
            sub_template: map
                .remove("sub_template_json")
                .and_then(|raw| serde_json::from_str::<SubscriptionTemplateConfig>(&raw).ok())
                .unwrap_or_default(),
        };
        Ok(settings)
    }

    pub fn clash_api_settings(&self) -> Result<(String, String)> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT addr.value, secret.value FROM settings AS addr, settings AS secret
             WHERE addr.key = 'clash_api_addr' AND secret.key = 'clash_api_secret'",
        )?;
        Ok(stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }

    pub fn backup_snapshot(&self) -> Result<Vec<u8>> {
        let conn = self.conn.lock();
        let snapshot = conn.serialize(rusqlite::DatabaseName::Main)?;
        Ok(snapshot.to_vec())
    }

    /// Validates an uploaded SQLite backup image, creates a safety pre-restore snapshot,
    /// restores atomically via SQLite's online Backup API, and re-runs schema seeding.
    pub fn restore_from_bytes(&self, raw_bytes: &[u8]) -> Result<String> {
        use std::io::Write;

        if raw_bytes.len() < 100 || !raw_bytes.starts_with(b"SQLite format 3\0") {
            return Err(anyhow!(
                "Uploaded file is not a valid SQLite 3 database (.db)"
            ));
        }

        // Write candidate database to a temp file and verify integrity + expected panel tables
        let staging = tempfile::tempdir_in(&self.data_dir)?;
        let mut staged_file = tempfile::NamedTempFile::new_in(staging.path())?;
        staged_file.write_all(raw_bytes)?;
        let candidate_path = staged_file.into_temp_path();
        let src_conn = Connection::open(&candidate_path)
            .context("Failed to open uploaded SQLite database")?;
        src_conn.pragma_update(None, "foreign_keys", true)?;

        let integrity: String = src_conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .context("Failed to run SQLite integrity_check")?;
        if !integrity.eq_ignore_ascii_case("ok") {
            return Err(anyhow!("Uploaded SQLite database failed integrity check: {integrity}"));
        }

        for required in ["users", "settings", "inbounds"] {
            let exists: i64 = src_conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![required],
                |r| r.get(0),
            )?;
            if exists == 0 {
                return Err(anyhow!(
                    "Uploaded database is missing required shoes-panel table '{required}'"
                ));
            }
        }
        let user_count: i64 =
            src_conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if user_count == 0 {
            return Err(anyhow!("Uploaded database has no admin user account"));
        }

        // Run migrations and exercise the panel's read paths on the private copy.
        // A structurally valid SQLite file can still have an incompatible panel schema.
        let candidate = Self { conn: Mutex::new(src_conn), data_dir: self.data_dir.clone() };
        candidate.init_schema()?;
        candidate.get_settings()?;
        candidate.list_inbounds()?;
        candidate.list_subscriptions()?;
        candidate.list_certificates()?;
        candidate.list_outbound_groups()?;
        candidate.list_routing_rules()?;
        candidate.list_dns_groups()?;
        candidate.list_rule_source_groups()?;
        candidate.list_cluster_nodes()?;
        candidate.core_history()?;
        candidate.daily_traffic()?;
        let src_conn = candidate.conn.into_inner();
        src_conn.query_row("SELECT id, username, password_hash, updated_at FROM users ORDER BY id LIMIT 1", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))
        })?;
        anyhow::ensure!(
            !src_conn.prepare("PRAGMA foreign_key_check")?.exists([])?,
            "Uploaded database contains broken foreign key references"
        );

        let backup_dir = self.data_dir.join("backups");
        std::fs::create_dir_all(&backup_dir)?;
        let pre_name = format!(
            "pre-restore-{}-{}.db",
            Utc::now().format("%Y%m%d-%H%M%S"), generate_uuid()
        );
        let pre_path = backup_dir.join(&pre_name);
        let mut temp_backup = tempfile::NamedTempFile::new_in(backup_dir)?;
        let mut dst_conn = self.conn.lock();
        {
            let snapshot = dst_conn.serialize(rusqlite::DatabaseName::Main)?;
            temp_backup.write_all(&snapshot)?;
            temp_backup.as_file().sync_all()?;
        }
        temp_backup.persist_noclobber(&pre_path)?;
        let backup = rusqlite::backup::Backup::new(&src_conn, &mut dst_conn)
            .context("Failed to initialize SQLite restore backup handle")?;
        backup.run_to_completion(128, std::time::Duration::from_millis(5), None)
            .context("SQLite restore failed")?;
        Ok(pre_name)
    }

    pub fn save_settings(&self, s: &PanelSettings) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let pairs = [
            ("panel_listen", s.panel_listen.trim().to_string()),
            ("panel_port", s.panel_port.to_string()),
            ("panel_base_path", normalize_base_path(&s.panel_base_path)),
            ("panel_cert_file", s.panel_cert_file.trim().to_string()),
            ("panel_key_file", s.panel_key_file.trim().to_string()),
            ("public_host", s.public_host.trim().to_string()),
            ("sub_public_url", s.sub_public_url.trim().to_string()),
            ("shoes_bin_path", s.shoes_bin_path.trim().to_string()),
            ("shoes_config_path", s.shoes_config_path.trim().to_string()),
            ("clash_api_addr", s.clash_api_addr.trim().to_string()),
            ("clash_api_secret", s.clash_api_secret.trim().to_string()),
            (
                "shoes_auto_start",
                if s.shoes_auto_start { "true" } else { "false" }.to_string(),
            ),
            ("shoes_extra_yaml", s.shoes_extra_yaml.clone()),
            ("session_ttl_hours", s.session_ttl_hours.max(1).to_string()),
            (
                "auto_backup_enabled",
                if s.auto_backup_enabled { "true" } else { "false" }.to_string(),
            ),
            (
                "auto_backup_interval_hours",
                s.auto_backup_interval_hours.clamp(1, 720).to_string(),
            ),
            (
                "auto_backup_retain_count",
                s.auto_backup_retain_count.clamp(1, 100).to_string(),
            ),
            ("tg_bot_token", s.tg_bot_token.trim().to_string()),
            ("tg_chat_id", s.tg_chat_id.trim().to_string()),
            (
                "tg_backup_enabled",
                if s.tg_backup_enabled { "true" } else { "false" }.to_string(),
            ),
            (
                "core_global_settings",
                serde_json::to_string(&s.core_global).unwrap_or_else(|_| "{}".to_string()),
            ),
            (
                "sub_template_json",
                serde_json::to_string(&s.sub_template).unwrap_or_else(|_| "{}".to_string()),
            ),
        ];
        for (k, v) in pairs {
            tx.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![k, v],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_setting_kv(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn save_sub_template(&self, tpl: &SubscriptionTemplateConfig) -> Result<SubscriptionTemplateConfig> {
        let mut norm = tpl.clone();
        norm.preset = match norm.preset.trim().to_ascii_lowercase().as_str() {
            "global_direct" | "bypass_cn" | "streaming" => norm.preset.trim().to_ascii_lowercase(),
            _ => "minimal".to_string(),
        };
        let encoded = serde_json::to_string(&norm)?;
        self.set_setting_kv("sub_template_json", &encoded)?;
        Ok(norm)
    }

    // ==================== Inbounds & Clients (Two-Layer Model) ====================

    pub fn inbound_totals(&self) -> Result<InboundTotals> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT COALESCE(SUM(up_bytes), 0), COALESCE(SUM(down_bytes), 0),
                    COUNT(*), COUNT(CASE WHEN enable <> 0 THEN 1 END),
                    (SELECT COUNT(*) FROM clients)
             FROM inbounds",
        )?;
        Ok(stmt.query_row([], |r| {
            Ok(InboundTotals {
                up_bytes: r.get(0)?,
                down_bytes: r.get(1)?,
                inbounds_total: r.get(2)?,
                inbounds_enabled: r.get(3)?,
                clients_total: r.get(4)?,
            })
        })?)
    }

    pub fn list_inbounds(&self) -> Result<Vec<Inbound>> {
        self.read_inbounds(None)
    }

    pub fn get_inbound(&self, id: i64) -> Result<Option<Inbound>> {
        Ok(self.read_inbounds(Some(id))?.pop())
    }

    fn read_inbounds(&self, id: Option<i64>) -> Result<Vec<Inbound>> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let inbounds = Self::select_inbounds(&tx, id)?;
        tx.commit()?;
        Ok(inbounds)
    }

    fn require_inbound(conn: &Connection, id: i64) -> Result<Inbound> {
        Self::select_inbounds(conn, Some(id))?.pop()
            .ok_or_else(|| anyhow!("Inbound #{id} not found"))
    }

    fn select_inbounds(conn: &Connection, id: Option<i64>) -> Result<Vec<Inbound>> {
        let (inbound_filter, client_filter) = if id.is_some() {
            ("WHERE id = ?1", "WHERE inbound_id = ?1")
        } else {
            ("", "")
        };
        let mut inbounds: Vec<Inbound> = conn
            .prepare_cached(&format!(
                "SELECT id, tag, remark, enable, listen, port, protocol, protocol_settings,
                    stream_settings, up_bytes, down_bytes, total_quota_bytes, expiry_time,
                    auto_reset_day, last_reset_month, created_at, updated_at
             FROM inbounds {inbound_filter} ORDER BY id ASC"
            ))?
            .query_map(rusqlite::params_from_iter(id), |r| {
                let ps_str: String = r.get(7)?;
                let ss_str: String = r.get(8)?;
                Ok(Inbound {
                    id: r.get(0)?,
                    tag: r.get(1)?,
                    remark: r.get(2)?,
                    enable: r.get::<_, i64>(3)? != 0,
                    listen: r.get(4)?,
                    port: r.get::<_, u16>(5)?,
                    protocol: r.get(6)?,
                    protocol_settings: serde_json::from_str(&ps_str).unwrap_or_default(),
                    stream_settings: serde_json::from_str(&ss_str).unwrap_or_default(),
                    up_bytes: r.get(9)?,
                    down_bytes: r.get(10)?,
                    total_quota_bytes: r.get(11)?,
                    expiry_time: r.get(12)?,
                    auto_reset_day: r.get(13)?,
                    last_reset_month: r.get(14)?,
                    created_at: r.get(15)?,
                    updated_at: r.get(16)?,
                    clients: Vec::new(),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let clients: Vec<ClientRecord> = conn
            .prepare_cached(&format!(
                "SELECT id, inbound_id, name, enable, uuid, password, username, flow, sub_id,
                    up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at,
                    wg_private_key, wg_public_key, wg_preshared_key, wg_allowed_ips, wg_keepalive
             FROM clients {client_filter} ORDER BY id ASC"
            ))?
            .query_map(rusqlite::params_from_iter(id), |r| {
                Ok(ClientRecord {
                    id: r.get(0)?,
                    inbound_id: r.get(1)?,
                    name: r.get(2)?,
                    enable: r.get::<_, i64>(3)? != 0,
                    uuid: r.get(4)?,
                    password: r.get(5)?,
                    username: r.get(6)?,
                    flow: r.get(7)?,
                    sub_id: r.get(8)?,
                    up_bytes: r.get(9)?,
                    down_bytes: r.get(10)?,
                    total_quota_bytes: r.get(11)?,
                    expiry_time: r.get(12)?,
                    comment: r.get(13)?,
                    created_at: r.get(14)?,
                    wg_private_key: r.get(15)?,
                    wg_public_key: r.get(16)?,
                    wg_preshared_key: r.get(17)?,
                    wg_allowed_ips: r.get(18)?,
                    wg_keepalive: r.get::<_, u16>(19).unwrap_or(25),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut by_inbound: HashMap<i64, Vec<ClientRecord>> = HashMap::new();
        for c in clients {
            by_inbound.entry(c.inbound_id).or_default().push(c);
        }
        for ib in &mut inbounds {
            let is_single = !ib.supports_multi_user();
            let mut list = by_inbound.remove(&ib.id).unwrap_or_default();
            if is_single {
                // Keep 1-port-1-client layer synced with authoritative inbound stats/quota/expiry
                for c in &mut list {
                    c.up_bytes = ib.up_bytes;
                    c.down_bytes = ib.down_bytes;
                    c.total_quota_bytes = ib.total_quota_bytes;
                    c.expiry_time = ib.expiry_time;
                }
            }
            ib.clients = list;
        }
        Ok(inbounds)
    }

    fn ensure_subscription_for_sub_id(conn: &Connection, sub_id: &str) -> Result<()> {
        let sub_id = sub_id.trim();
        if sub_id.is_empty() {
            return Ok(());
        }
        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM subscriptions WHERE sub_id = ?1",
                params![sub_id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            let now = Utc::now().timestamp_millis();
            conn.execute(
                "INSERT INTO subscriptions (sub_id, token, name, enable, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                params![sub_id, generate_random_alnum(22), sub_id, now],
            )?;
        }
        Ok(())
    }

    fn normalize_wireguard_inbound(ib: &mut Inbound) -> Result<()> {
        if ib.protocol != "wireguard" {
            return Ok(());
        }
        let ps = &mut ib.protocol_settings;
        if ps.wg_server_private_key.trim().is_empty() {
            let (priv_k, pub_k, _) = crate::crypto_util::generate_wireguard_keypair();
            ps.wg_server_private_key = priv_k;
            ps.wg_server_public_key = pub_k;
        } else if ps.wg_server_public_key.trim().is_empty() {
            ps.wg_server_public_key =
                crate::crypto_util::derive_wireguard_public_key(&ps.wg_server_private_key)?;
        }
        if ps.wg_server_addresses.is_empty() {
            ps.wg_server_addresses = vec!["10.77.0.1/32".to_string(), "fd77::1/128".to_string()];
        }
        if ps.wg_mtu == 0 {
            ps.wg_mtu = 1408;
        }
        Ok(())
    }

    fn normalize_wireguard_client(
        ib: &Inbound,
        c: &mut ClientRecord,
        existing_peers: &[ClientRecord],
    ) -> Result<()> {
        if ib.protocol != "wireguard" {
            return Ok(());
        }
        if c.wg_private_key.trim().is_empty() && c.wg_public_key.trim().is_empty() {
            let (priv_k, pub_k, psk) = crate::crypto_util::generate_wireguard_keypair();
            c.wg_private_key = priv_k;
            c.wg_public_key = pub_k;
            if c.wg_preshared_key.trim().is_empty() {
                c.wg_preshared_key = psk;
            }
        } else if !c.wg_private_key.trim().is_empty() && c.wg_public_key.trim().is_empty() {
            c.wg_public_key = crate::crypto_util::derive_wireguard_public_key(&c.wg_private_key)?;
        }
        if c.wg_allowed_ips.trim().is_empty() {
            c.wg_allowed_ips = next_wg_peer_ips(ib, existing_peers)?;
        }
        Ok(())
    }

    fn check_port_conflict(
        conn: &Connection,
        exclude_id: Option<i64>,
        ib: &Inbound,
    ) -> Result<()> {
        let port = ib.port;
        if port == 0 {
            return Err(anyhow!("Port must be between 1 and 65535"));
        }
        let listen = if ib.listen.trim().is_empty() {
            "0.0.0.0"
        } else {
            ib.listen.trim()
        };
        let is_udp = ib.is_udp_transport();
        let can_sni_share = ib.can_share_sni_port();
        let my_sni = ib.sni_mux_key();
        let mut ranges = crate::yaml_gen::parse_port_ranges(port, &ib.protocol_settings.port_range)?;
        if ranges.is_empty() { ranges.push((port, port)); }
        let low = ranges.iter().map(|r| r.0).min().unwrap();
        let high = ranges.iter().map(|r| r.1).max().unwrap();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT id, remark, listen, protocol, protocol_settings, stream_settings, port
             FROM inbounds WHERE port BETWEEN ?1 AND ?2 OR id IN (SELECT id FROM inbounds WHERE {HAS_PORT_RANGE})"
        ))?;
        let rows = stmt.query_map(params![low, high], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, u16>(6)?,
            ))
        })?;
        for row in rows {
            let (other_id, remark, other_listen_raw, other_proto, ps_json, ss_json, other_port) = row?;
            if exclude_id == Some(other_id) {
                continue;
            }
            let other_listen = if other_listen_raw.trim().is_empty() {
                "0.0.0.0"
            } else {
                other_listen_raw.trim()
            };
            let other_ps: crate::models::ProtocolSettings =
                serde_json::from_str(&ps_json).unwrap_or_default();
            let Some(port) = overlapping_port(&ranges, other_port, &other_ps.port_range) else {
                continue;
            };
            let other_ss: StreamSettings = serde_json::from_str(&ss_json).unwrap_or_default();
            let other_ib = Inbound {
                id: other_id,
                tag: String::new(),
                remark: remark.clone(),
                enable: true,
                listen: other_listen.to_string(),
                port: other_port,
                protocol: other_proto,
                protocol_settings: other_ps,
                stream_settings: other_ss,
                up_bytes: 0,
                down_bytes: 0,
                total_quota_bytes: 0,
                expiry_time: 0,
                auto_reset_day: 0,
                last_reset_month: String::new(),
                created_at: 0,
                updated_at: 0,
                clients: Vec::new(),
            };
            let other_is_udp = other_ib.is_udp_transport();
            // TCP and UDP (QUIC / WireGuard) CAN share the same port (e.g., TCP 443 + QUIC 443)!
            if is_udp != other_is_udp {
                continue;
            }
            let listen_overlaps = listen == "0.0.0.0"
                || other_listen == "0.0.0.0"
                || listen == "::"
                || other_listen == "::"
                || listen == other_listen;
            if !listen_overlaps {
                continue;
            }
            // Same TCP (listen, port) with outer TLS / REALITY / ShadowTLS can share via SNI multiplexing!
            if !is_udp && can_sni_share && other_ib.can_share_sni_port() {
                if listen != other_listen {
                    return Err(anyhow!(
                        "To share TCP port {port} via SNI multiplexing, both inbounds must use the same listen address ('{other_listen}' vs '{listen}')"
                    ));
                }
                let other_sni = other_ib.sni_mux_key();
                if my_sni == other_sni {
                    let sni_desc = my_sni.as_deref().unwrap_or("(default / empty SNI)");
                    return Err(anyhow!(
                        "Port {port} SNI '{sni_desc}' is already used by inbound '{remark}' (#{other_id}). Use a distinct SNI to share port {port}."
                    ));
                }
                continue;
            }
            let proto_label = if is_udp { "UDP/QUIC" } else { "TCP" };
            return Err(anyhow!(
                "Port {} ({}) is already used by inbound '{}' (#{})",
                port,
                proto_label,
                remark,
                other_id
            ));
        }
        Ok(())
    }

    pub fn create_inbound(&self, mut ib: Inbound) -> Result<Inbound> {
        let created = Utc::now();
        let now = created.timestamp_millis();
        ib.protocol = ib.protocol.trim().to_lowercase();
        Self::normalize_wireguard_inbound(&mut ib)?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_port_conflict(&tx, None, &ib)?;
        let temp_tag = format!("inbound-tmp-{}", generate_random_alnum(8));
        let ps_json = serde_json::to_string(&ib.protocol_settings)?;
        let ss_json = serde_json::to_string(&ib.stream_settings)?;

        tx.execute(
            "INSERT INTO inbounds (
                tag, remark, enable, listen, port, protocol, protocol_settings, stream_settings,
                up_bytes, down_bytes, total_quota_bytes, expiry_time, auto_reset_day,
                last_reset_month, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, ?12, ?13, ?13)",
            params![
                temp_tag,
                ib.remark.trim(),
                if ib.enable { 1 } else { 0 },
                if ib.listen.trim().is_empty() {
                    "0.0.0.0"
                } else {
                    ib.listen.trim()
                },
                ib.port,
                ib.protocol.as_str(),
                ps_json,
                ss_json,
                ib.total_quota_bytes.max(0),
                ib.expiry_time.max(0),
                ib.auto_reset_day.clamp(0, 31),
                reset_cycle(created.date_naive(), ib.auto_reset_day),
                now
            ],
        )?;
        let inbound_id = tx.last_insert_rowid();
        let final_tag = format!("inbound-{inbound_id}");
        tx.execute(
            "UPDATE inbounds SET tag = ?1 WHERE id = ?2",
            params![final_tag, inbound_id],
        )?;

        // Ensure at least 1 client exists in `clients` table (except portforward); for single-user protocols cap at 1.
        if ib.clients.is_empty() && ib.protocol != "portforward" {
            ib.clients.push(default_client_for_inbound(&ib, 1));
        } else if !ib.supports_multi_user() && ib.clients.len() > 1 {
            ib.clients.truncate(1);
        }

        for c in &mut ib.clients {
            c.id = 0;
        }
        Self::replace_inbound_clients(&tx, inbound_id, &mut ib, false, now)?;
        let created = Self::require_inbound(&tx, inbound_id)?;
        tx.commit()?;
        Ok(created)
    }

    pub fn update_inbound(&self, id: i64, ib: Inbound) -> Result<Inbound> {
        self.update_inbound_record(id, ib, false)
    }

    pub fn restore_inbound(&self, ib: Inbound) -> Result<Inbound> {
        self.update_inbound_record(ib.id, ib, true)
    }

    fn update_inbound_record(&self, id: i64, mut ib: Inbound, restoring: bool) -> Result<Inbound> {
        let updated = Utc::now();
        let now = updated.timestamp_millis();
        ib.protocol = ib.protocol.trim().to_lowercase();
        Self::normalize_wireguard_inbound(&mut ib)?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_port_conflict(&tx, Some(id), &ib)?;
        let tag = if restoring { ib.tag.clone() } else { format!("inbound-{id}") };
        let ps_json = serde_json::to_string(&ib.protocol_settings)?;
        let ss_json = serde_json::to_string(&ib.stream_settings)?;

        let affected = tx.execute(
            "UPDATE inbounds SET
                tag = ?1, remark = ?2, enable = ?3, listen = ?4, port = ?5, protocol = ?6,
                protocol_settings = ?7, stream_settings = ?8, total_quota_bytes = ?9,
                expiry_time = ?10, auto_reset_day = ?11, updated_at = ?12,
                last_reset_month = CASE WHEN ?14 OR auto_reset_day != ?11 THEN ?15 ELSE last_reset_month END
             WHERE id = ?13",
            params![
                tag,
                ib.remark.trim(),
                if ib.enable { 1 } else { 0 },
                if ib.listen.trim().is_empty() {
                    "0.0.0.0"
                } else {
                    ib.listen.trim()
                },
                ib.port,
                ib.protocol.as_str(),
                ps_json,
                ss_json,
                ib.total_quota_bytes.max(0),
                ib.expiry_time.max(0),
                ib.auto_reset_day.clamp(0, 31),
                if restoring { ib.updated_at } else { now },
                id,
                restoring,
                if restoring { ib.last_reset_month.clone() } else { reset_cycle(updated.date_naive(), ib.auto_reset_day) }
            ],
        )?;
        if affected == 0 {
            return Err(anyhow!("Inbound #{id} not found"));
        }

        if restoring || !ib.clients.is_empty() {
            if !ib.supports_multi_user() {
                ib.clients.truncate(1);
            }
            Self::replace_inbound_clients(&tx, id, &mut ib, restoring, now)?;
        }
        let updated = Self::require_inbound(&tx, id)?;
        tx.commit()?;
        Ok(updated)
    }

    fn replace_inbound_clients(conn: &Connection, id: i64, ib: &mut Inbound, restoring: bool, now: i64) -> Result<()> {
        let mut remaining: HashSet<i64> = conn.prepare_cached("SELECT id FROM clients WHERE inbound_id = ?1")?
            .query_map([id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        // Reserve explicit peer addresses before assigning addresses to new peers.
        let clients = std::mem::take(&mut ib.clients);
        let mut peers: Vec<_> = clients.iter().filter(|c| !c.wg_allowed_ips.trim().is_empty()).cloned().collect();
        for mut c in clients {
            if c.id > 0 {
                let owned = remaining.remove(&c.id);
                anyhow::ensure!(owned || restoring, "Client #{} is stale or does not belong to this inbound", c.id);
            }
            let needs_address = ib.protocol == "wireguard" && c.wg_allowed_ips.trim().is_empty();
            Self::normalize_wireguard_client(ib, &mut c, &peers)?;
            if c.name.trim().is_empty() {
                c.name = ib.remark.trim().to_owned();
            }
            if !ib.supports_multi_user() {
                c.total_quota_bytes = ib.total_quota_bytes;
                c.expiry_time = ib.expiry_time;
            }
            if !restoring {
                c.up_bytes = 0;
                c.down_bytes = 0;
            }
            let created_at = if restoring && c.created_at > 0 { c.created_at } else { now };
            Self::write_client(conn, id, &c, created_at)?;
            if needs_address {
                peers.push(c);
            }
        }
        for old_id in remaining {
            conn.execute("DELETE FROM clients WHERE id = ?1", [old_id])?;
        }
        Ok(())
    }

    fn write_client(conn: &Connection, inbound_id: i64, c: &ClientRecord, created_at: i64) -> Result<()> {
        let sub_id = c.sub_id.trim();
        let sub_id = if sub_id.is_empty() { "default" } else { sub_id };
        Self::ensure_subscription_for_sub_id(conn, sub_id)?;
        let affected = conn.prepare_cached(
            "INSERT INTO clients (id, inbound_id, name, enable, uuid, password, username, flow, sub_id,
                 up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at,
                 wg_private_key, wg_public_key, wg_preshared_key, wg_allowed_ips, wg_keepalive)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, enable=excluded.enable,
                 uuid=excluded.uuid, password=excluded.password, username=excluded.username,
                 flow=excluded.flow, sub_id=excluded.sub_id, total_quota_bytes=excluded.total_quota_bytes,
                 expiry_time=excluded.expiry_time, comment=excluded.comment,
                 wg_private_key=excluded.wg_private_key, wg_public_key=excluded.wg_public_key,
                 wg_preshared_key=excluded.wg_preshared_key, wg_allowed_ips=excluded.wg_allowed_ips,
                 wg_keepalive=excluded.wg_keepalive
             WHERE clients.inbound_id = excluded.inbound_id"
        )?.execute(params![
            (c.id > 0).then_some(c.id), inbound_id, c.name.trim(), c.enable, c.uuid.trim(),
            c.password.trim(), c.username.trim(), c.flow.trim(), sub_id, c.up_bytes, c.down_bytes,
            c.total_quota_bytes.max(0), c.expiry_time.max(0), c.comment.trim(), created_at,
            c.wg_private_key.trim(), c.wg_public_key.trim(), c.wg_preshared_key.trim(),
            c.wg_allowed_ips.trim(), c.wg_keepalive,
        ])?;
        anyhow::ensure!(affected == 1, "Client belongs to a different inbound");
        Ok(())
    }

    pub fn set_inbound_enable(&self, id: i64, enable: bool) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().timestamp_millis();
        conn.execute(
            "UPDATE inbounds SET enable = ?1, updated_at = ?2 WHERE id = ?3",
            params![if enable { 1 } else { 0 }, now, id],
        )?;
        Ok(())
    }

    pub fn delete_inbound(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM inbounds WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Keep the exact SQLite rows until Shoes has accepted the deletion.
    pub fn delete_config_rows(&self, table: ConfigTable, ids: &[i64]) -> Result<ConfigDeletion> {
        let tables: &[(&str, &str)] = match table {
            ConfigTable::Inbounds => &[("clients", "inbound_id"), ("inbounds", "id")],
            ConfigTable::OutboundGroups => &[("outbound_groups", "id")],
            ConfigTable::RoutingRules => &[("routing_rules", "id")],
            ConfigTable::DnsGroups => &[("dns_groups", "id")],
            ConfigTable::RuleSourceGroups => &[("rule_source_groups", "id")],
        };
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut deleted = ConfigDeletion { tables: Vec::new(), affected: 0 };
        for &(table, key) in tables {
            let mut stmt = tx.prepare_cached(&format!("DELETE FROM {table} WHERE {key} = ?1 RETURNING *"))?;
            let columns = stmt.column_count();
            let mut rows = Vec::new();
            for id in ids {
                let mut result = stmt.query([id])?;
                while let Some(row) = result.next()? {
                    rows.push((0..columns).map(|col| row.get(col)).collect::<rusqlite::Result<Vec<_>>>()?);
                }
            }
            deleted.affected = rows.len();
            deleted.tables.push(DeletedRows { table, rows });
        }
        tx.commit()?;
        Ok(deleted)
    }

    pub fn undo_config_deletion(&self, deleted: ConfigDeletion) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        // Restore parent rows before rows that reference them.
        for DeletedRows { table, rows } in deleted.tables.into_iter().rev() {
            if let Some(first) = rows.first() {
                let params = vec!["?"; first.len()].join(", ");
                let mut insert = tx.prepare(&format!("INSERT INTO {table} VALUES ({params})"))?;
                for row in rows {
                    insert.execute(rusqlite::params_from_iter(row))?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn batch_set_inbounds_enable(&self, ids: &[i64], enable: bool) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp_millis();
        let mut affected = 0usize;
        for &id in ids {
            affected += tx.execute(
                "UPDATE inbounds SET enable = ?1, updated_at = ?2 WHERE id = ?3",
                params![if enable { 1 } else { 0 }, now, id],
            )?;
        }
        tx.commit()?;
        Ok(affected)
    }

    pub fn batch_extend_inbounds_expiry(
        &self,
        ids: &[i64],
        extend_days: Option<i64>,
        set_expiry_time: Option<i64>,
        apply_to_clients: bool,
        re_enable_expired: bool,
    ) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp_millis();
        let mut affected = 0usize;

        for &id in ids {
            let cur: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT expiry_time, enable FROM inbounds WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((cur_exp, cur_en)) = cur else {
                continue;
            };
            let new_exp = if let Some(exact) = set_expiry_time {
                exact.max(0)
            } else if let Some(days) = extend_days {
                if days <= 0 {
                    return Err(anyhow!("extend_days must be greater than 0"));
                }
                let base = if cur_exp > now { cur_exp } else { now };
                base.saturating_add(days.saturating_mul(86_400_000))
            } else {
                return Err(anyhow!("Either extend_days or set_expiry_time is required"));
            };

            let should_enable = if re_enable_expired
                && cur_en == 0
                && cur_exp > 0
                && cur_exp <= now
                && (new_exp == 0 || new_exp > now)
            {
                1
            } else {
                cur_en
            };

            affected += tx.execute(
                "UPDATE inbounds SET expiry_time = ?1, enable = ?2, updated_at = ?3 WHERE id = ?4",
                params![new_exp, should_enable, now, id],
            )?;

            if apply_to_clients {
                if let Some(exact) = set_expiry_time {
                    tx.execute(
                        "UPDATE clients SET expiry_time = ?1 WHERE inbound_id = ?2",
                        params![exact.max(0), id],
                    )?;
                } else if let Some(days) = extend_days {
                    let delta = days.saturating_mul(86_400_000);
                    tx.execute(
                        "UPDATE clients
                         SET expiry_time = MIN(MAX(expiry_time, ?1), 9223372036854775807 - ?2) + ?2
                         WHERE inbound_id = ?3",
                        params![now, delta, id],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(affected)
    }

    pub fn batch_reset_inbounds_traffic(&self, ids: &[i64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp_millis();
        let mut affected = 0usize;
        for &id in ids {
            affected += tx.execute(
                "UPDATE inbounds SET up_bytes = 0, down_bytes = 0, updated_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
            tx.execute(
                "UPDATE clients SET up_bytes = 0, down_bytes = 0 WHERE inbound_id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(affected)
    }

    pub fn batch_delete_inbounds(&self, ids: &[i64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let mut affected = 0usize;
        for &id in ids {
            affected += tx.execute("DELETE FROM inbounds WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(affected)
    }

    pub fn reset_inbound_traffic(&self, id: i64) -> Result<()> {
        anyhow::ensure!(self.batch_reset_inbounds_traffic(&[id])? == 1, "Inbound #{id} not found");
        Ok(())
    }

    pub fn reset_all_traffic(&self) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("UPDATE inbounds SET up_bytes = 0, down_bytes = 0", [])?;
        tx.execute("UPDATE clients SET up_bytes = 0, down_bytes = 0", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Adds a client to an inbound (for AnyTLS / NaiveProxy / WireGuard multi-user inbounds).
    pub fn add_client(&self, inbound_id: i64, mut c: ClientRecord) -> Result<Inbound> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inbound = Self::require_inbound(&tx, inbound_id)?;
        if !inbound.supports_multi_user() && !inbound.clients.is_empty() {
            return Err(anyhow!(
                "Protocol '{}' only supports 1 credential per port in shoes. Use Clone Inbound to allocate a dedicated port for a new client.",
                inbound.protocol
            ));
        }
        Self::normalize_wireguard_client(&inbound, &mut c, &inbound.clients)?;
        c.id = 0;
        c.up_bytes = 0;
        c.down_bytes = 0;
        Self::write_client(&tx, inbound_id, &c, Utc::now().timestamp_millis())?;
        let updated = Self::require_inbound(&tx, inbound_id)?;
        tx.commit()?;
        Ok(updated)
    }

    fn client_inbound_id(conn: &Connection, client_id: i64) -> Result<i64> {
        conn.query_row("SELECT inbound_id FROM clients WHERE id = ?1", [client_id], |r| r.get(0))
            .optional()?.ok_or_else(|| anyhow!("Client #{client_id} not found"))
    }

    pub fn inbound_for_client(&self, client_id: i64) -> Result<Inbound> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let id = Self::client_inbound_id(&tx, client_id)?;
        let ib = Self::require_inbound(&tx, id)?;
        tx.commit()?;
        Ok(ib)
    }

    pub fn update_client(&self, client_id: i64, mut c: ClientRecord) -> Result<Inbound> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inbound_id = Self::client_inbound_id(&tx, client_id)?;
        let mut inbound = Self::require_inbound(&tx, inbound_id)?;
        let pos = inbound.clients.iter().position(|client| client.id == client_id)
            .context("Client missing from its inbound")?;
        let existing = inbound.clients.remove(pos);
        Self::normalize_wireguard_client(&inbound, &mut c, &inbound.clients)?;
        c.id = client_id;
        c.total_quota_bytes = existing.total_quota_bytes;
        c.expiry_time = existing.expiry_time;
        Self::write_client(&tx, inbound_id, &c, existing.created_at)?;
        let updated = Self::require_inbound(&tx, inbound_id)?;
        tx.commit()?;
        Ok(updated)
    }

    pub fn delete_client(&self, client_id: i64) -> Result<Inbound> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inbound_id = Self::client_inbound_id(&tx, client_id)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM clients WHERE inbound_id = ?1", [inbound_id], |r| r.get(0)
        )?;
        anyhow::ensure!(count > 1,
            "An inbound must retain at least 1 client credential. Delete the inbound instead."
        );
        tx.execute("DELETE FROM clients WHERE id = ?1", [client_id])?;
        let updated = Self::require_inbound(&tx, inbound_id)?;
        tx.commit()?;
        Ok(updated)
    }

    fn reserved_range_ports(conn: &Connection) -> Result<std::collections::BTreeSet<u16>> {
        let mut reserved = std::collections::BTreeSet::new();
        let mut ranges = conn.prepare_cached(&format!(
            "SELECT port, json_extract(protocol_settings, '$.port_range') FROM inbounds WHERE {HAS_PORT_RANGE}"
        ))?;
        for row in ranges.query_map([], |r| Ok((r.get(0)?, r.get::<_, String>(1)?)))? {
            let (port, raw) = row?;
            for (lo, hi) in crate::yaml_gen::parse_port_ranges(port, &raw).unwrap_or_default() {
                reserved.extend(lo..=hi);
            }
        }
        Ok(reserved)
    }

    pub fn next_available_port(&self, start_port: u16) -> Result<u16> {
        let conn = self.conn.lock();
        let reserved = Self::reserved_range_ports(&conn)?;
        let mut candidates = (start_port.max(1024)..=u16::MAX).filter(|p| !reserved.contains(p));
        let exhausted = || anyhow!("No available port at or above {}", start_port.max(1024));
        let mut candidate = candidates.next().ok_or_else(exhausted)?;
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT port FROM inbounds WHERE port >= ?1 ORDER BY port"
        )?;
        for used in stmt.query_map([candidate], |r| r.get::<_, u16>(0))? {
            match used?.cmp(&candidate) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => candidate = candidates.next().ok_or_else(exhausted)?,
                std::cmp::Ordering::Greater => break,
            }
        }
        Ok(candidate)
    }

    /// Move every port in a hopping range by the same offset as its primary port.
    pub fn assign_inbound_port(&self, ib: &mut Inbound, start: u16, exact: bool) -> Result<()> {
        let ranges = crate::yaml_gen::parse_port_ranges(ib.port, &ib.protocol_settings.port_range)?;
        if ranges.is_empty() {
            ib.port = if exact { start } else { self.next_available_port(start)? };
            return Ok(());
        }
        let mut occupied = std::collections::BTreeSet::new();
        if !exact {
            let conn = self.conn.lock();
            occupied = Self::reserved_range_ports(&conn)?;
            let mut stmt = conn.prepare_cached("SELECT DISTINCT port FROM inbounds")?;
            for p in stmt.query_map([], |r| r.get::<_, u16>(0))? {
                occupied.insert(p?);
            }
        }
        let mut candidate = i32::from(if exact { start } else { start.max(1024) });
        loop {
            let shift = candidate - i32::from(ib.port);
            let mut next = candidate;
            let mut parts = Vec::new();
            for &(lo, hi) in &ranges {
                let low = i32::from(lo) + shift;
                let high = i32::from(hi) + shift;
                if low < 1 && !exact {
                    next = next.max(candidate + 1 - low);
                    continue;
                }
                anyhow::ensure!(low >= 1 && high <= i32::from(u16::MAX), "Port range cannot fit at or above the requested port");
                if let Some(&blocked) = occupied.range(low as u16..=high as u16).next_back() {
                    next = next.max(candidate + i32::from(blocked) - low + 1);
                }
                parts.push(if low == high { low.to_string() } else { format!("{low}-{high}") });
            }
            if next == candidate {
                ib.port = candidate as u16;
                ib.protocol_settings.port_range = parts.join(",");
                return Ok(());
            }
            candidate = next;
        }
    }

    /// Missing days remain null so a monitoring gap is distinct from an idle day.
    pub fn save_core_minute(&self, time: i64, metrics: serde_json::Value) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("INSERT OR REPLACE INTO core_minutes VALUES (?1, ?2)", params![time, metrics.to_string()])?;
        let cutoff = time - 86_400_000;
        tx.execute("DELETE FROM core_minutes WHERE time <= ?1", [cutoff])?;
        tx.execute("DELETE FROM core_events WHERE time < ?1", [cutoff])?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_core_event(&self, kind: &str) {
        if let Err(err) = self.conn.lock().execute("INSERT INTO core_events VALUES (?1, ?2)", params![Utc::now().timestamp_millis(), kind]) {
            tracing::warn!("Could not record core event: {err}");
        }
    }

    pub fn core_history(&self) -> Result<serde_json::Value> {
        let end = Utc::now().timestamp_millis() / 60_000 * 60_000;
        let start = end - 1439 * 60_000;
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT metrics FROM core_minutes WHERE time BETWEEN ?1 AND ?2 ORDER BY time")?;
        let mut minutes = Vec::new();
        for row in stmt.query_map([start, end], |r| r.get::<_, String>(0))? {
            minutes.push(serde_json::from_str::<serde_json::Value>(&row?)?);
        }
        let mut stmt = conn.prepare("SELECT time, kind FROM core_events WHERE time >= ?1 ORDER BY time")?;
        let events = stmt.query_map([start], |r| Ok(serde_json::json!({"time": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?})))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(serde_json::json!({"start":start,"minutes":minutes,"events":events}))
    }

    pub fn daily_traffic(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "WITH RECURSIVE days(day) AS (
                SELECT date('now', 'localtime', '-29 days')
                UNION ALL SELECT date(day, '+1 day') FROM days WHERE day < date('now', 'localtime')
             )
             SELECT days.day, up_bytes, down_bytes FROM days
             LEFT JOIN daily_traffic USING(day) ORDER BY days.day",
        )?;
        let rows = stmt.query_map([], |r| Ok(serde_json::json!({
            "day": r.get::<_, String>(0)?,
            "up": r.get::<_, Option<i64>>(1)?,
            "down": r.get::<_, Option<i64>>(2)?,
        })))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Record the controller-wide daily delta alongside any per-inbound accounting.
    pub fn add_traffic_deltas(
        &self,
        deltas: &HashMap<String, (u64, u64)>,
        daily: Option<(&str, u64, u64)>,
    ) -> Result<()> {
        if deltas.is_empty() && daily.is_none() {
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        if let Some((day, up, down)) = daily {
            tx.execute(
                "INSERT INTO daily_traffic VALUES (?1, ?2, ?3)
                 ON CONFLICT(day) DO UPDATE SET up_bytes = up_bytes + excluded.up_bytes,
                                                down_bytes = down_bytes + excluded.down_bytes",
                params![day, up, down],
            )?;
        }
        let mut update = tx.prepare_cached(
            "UPDATE inbounds SET up_bytes = up_bytes + ?1, down_bytes = down_bytes + ?2 WHERE tag = ?3"
        )?;
        for (tag, (up, down)) in deltas {
            if *up == 0 && *down == 0 {
                continue;
            }
            update.execute(params![up, down, tag])?;
        }
        drop(update);
        tx.commit()?;
        Ok(())
    }

    /// Checks monthly traffic reset, expiry timestamps, and traffic quotas.
    /// Returns tags of any inbounds that were newly auto-disabled so caller can trigger hot-reload!
    pub fn enforce_quotas_and_expiry(&self) -> Result<Vec<String>> {
        self.enforce_quotas_at(Utc::now())
    }

    fn enforce_quotas_at(&self, now_dt: chrono::DateTime<Utc>) -> Result<Vec<String>> {
        let now_ms = now_dt.timestamp_millis();
        let current_month = now_dt.format("%Y-%m").to_string();
        let today = now_dt.date_naive();
        let cutoff_day = if today.succ_opt().unwrap().day() == 1 { 31 } else { today.day() };
        let previous_month = today.with_day(1).unwrap().pred_opt().unwrap().format("%Y-%m").to_string();

        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;

        // Catch up after downtime. An empty legacy marker establishes a baseline.
        tx.execute(
            "UPDATE inbounds SET
                 up_bytes = CASE WHEN last_reset_month = '' THEN up_bytes ELSE 0 END,
                 down_bytes = CASE WHEN last_reset_month = '' THEN down_bytes ELSE 0 END,
                 last_reset_month = CASE WHEN auto_reset_day <= ?1 THEN ?2 ELSE ?3 END
             WHERE auto_reset_day > 0
               AND last_reset_month < CASE WHEN auto_reset_day <= ?1 THEN ?2 ELSE ?3 END",
            params![cutoff_day, current_month, previous_month],
        )?;

        let mut stmt = tx.prepare_cached(
            "UPDATE inbounds SET enable = 0, updated_at = ?1 WHERE id IN (
                SELECT id FROM inbounds WHERE enable = 1 AND expiry_time > 0 AND expiry_time <= ?1
                UNION ALL
                SELECT id FROM inbounds WHERE enable = 1 AND total_quota_bytes > 0
                    AND up_bytes + down_bytes >= total_quota_bytes
             ) RETURNING tag"
        )?;
        let result_tags = stmt.query_map([now_ms], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        tx.commit()?;
        Ok(result_tags)
    }

    // ==================== Certificates ====================

    fn query_records<T>(
        &self, select: &str, order: &str, id: Option<i64>,
        decode: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>> {
        let sql = match id {
            Some(_) => format!("{select} WHERE id = ?1"),
            None => format!("{select} ORDER BY {order}"),
        };
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(id), decode)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn list_certificates(&self) -> Result<Vec<CertificateRecord>> {
        self.read_certificates(None)
    }

    pub fn get_certificate(&self, id: i64) -> Result<Option<CertificateRecord>> {
        Ok(self.read_certificates(Some(id))?.pop())
    }

    fn read_certificates(&self, id: Option<i64>) -> Result<Vec<CertificateRecord>> {
        self.query_records(
            "SELECT id, name, cert_type, cert_file, key_file, domains_json, email,
                    directory_url, terms_of_service, challenge_type, http01_listen, remark, created_at
             FROM certificates",
            "id ASC", id, |r| {
                let domains_str: String = r.get(5)?;
                Ok(CertificateRecord {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    cert_type: r.get(2)?,
                    cert_file: r.get(3)?,
                    key_file: r.get(4)?,
                    domains: serde_json::from_str(&domains_str).unwrap_or_default(),
                    email: r.get(6)?,
                    directory_url: r.get(7)?,
                    terms_of_service: r.get(8)?,
                    challenge_type: r.get(9)?,
                    http01_listen: r.get(10)?,
                    remark: r.get(11)?,
                    created_at: r.get(12)?,
                })
            },
        )
    }

    pub fn save_certificate(&self, c: CertificateRecord) -> Result<CertificateRecord> {
        let name = c.name.trim();
        if name.is_empty() {
            return Err(anyhow!("Certificate source name must not be empty"));
        }
        let domains_json = serde_json::to_string(&c.domains)?;
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if c.id > 0 {
            conn.execute(
                "UPDATE certificates SET
                    name = ?1, cert_type = ?2, cert_file = ?3, key_file = ?4, domains_json = ?5,
                    email = ?6, directory_url = ?7, terms_of_service = ?8, challenge_type = ?9,
                    http01_listen = ?10, remark = ?11
                 WHERE id = ?12",
                params![
                    name,
                    c.cert_type.trim(),
                    c.cert_file.trim(),
                    c.key_file.trim(),
                    domains_json,
                    c.email.trim(),
                    c.directory_url.trim(),
                    c.terms_of_service.trim(),
                    c.challenge_type.trim(),
                    c.http01_listen.trim(),
                    c.remark.trim(),
                    c.id
                ],
            )?;
            c.id
        } else {
            conn.execute(
                "INSERT INTO certificates (
                    name, cert_type, cert_file, key_file, domains_json, email,
                    directory_url, terms_of_service, challenge_type, http01_listen, remark, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    name,
                    c.cert_type.trim(),
                    c.cert_file.trim(),
                    c.key_file.trim(),
                    domains_json,
                    c.email.trim(),
                    c.directory_url.trim(),
                    c.terms_of_service.trim(),
                    c.challenge_type.trim(),
                    c.http01_listen.trim(),
                    c.remark.trim(),
                    now
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_certificate(id)?
            .ok_or_else(|| anyhow!("failed to reload certificate"))
    }

    pub fn restore_certificate(&self, c: &CertificateRecord) -> Result<()> {
        let domains_json = serde_json::to_string(&c.domains)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO certificates (
                id, name, cert_type, cert_file, key_file, domains_json, email,
                directory_url, terms_of_service, challenge_type, http01_listen, remark, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                c.id,
                c.name.trim(),
                c.cert_type.trim(),
                c.cert_file.trim(),
                c.key_file.trim(),
                domains_json,
                c.email.trim(),
                c.directory_url.trim(),
                c.terms_of_service.trim(),
                c.challenge_type.trim(),
                c.http01_listen.trim(),
                c.remark.trim(),
                c.created_at
            ],
        )?;
        Ok(())
    }

    pub fn delete_certificate(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM certificates WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Outbound Groups & Routing Rules ====================

    pub fn list_outbound_groups(&self) -> Result<Vec<OutboundGroupRecord>> {
        self.read_outbound_groups(None)
    }

    pub fn get_outbound_group(&self, id: i64) -> Result<Option<OutboundGroupRecord>> {
        Ok(self.read_outbound_groups(Some(id))?.pop())
    }

    fn read_outbound_groups(&self, id: Option<i64>) -> Result<Vec<OutboundGroupRecord>> {
        self.query_records(
            "SELECT id, name, enable, group_type, default_member, test_url, interval_secs,
                    timeout_ms, tolerance_ms, members_json, raw_chains_yaml, remark
             FROM outbound_groups",
            "id ASC", id, |r| {
                let m_str: String = r.get(9)?;
                Ok(OutboundGroupRecord {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    enable: r.get::<_, i64>(2)? != 0,
                    group_type: r.get(3)?,
                    default_member: r.get(4)?,
                    test_url: r.get(5)?,
                    interval_secs: r.get::<_, i64>(6)?.max(1) as u64,
                    timeout_ms: r.get::<_, i64>(7)?.max(100) as u64,
                    tolerance_ms: r.get::<_, i64>(8)?.max(0) as u64,
                    members: serde_json::from_str(&m_str).unwrap_or_default(),
                    raw_chains_yaml: r.get(10)?,
                    remark: r.get(11)?,
                })
            },
        )
    }

    pub fn save_outbound_group(&self, g: OutboundGroupRecord) -> Result<OutboundGroupRecord> {
        let name = g.name.trim();
        if name.is_empty() || matches!(name.to_uppercase().as_str(), "DIRECT" | "REJECT" | "GLOBAL")
        {
            return Err(anyhow!(
                "Outbound group name must be non-empty and cannot be DIRECT, REJECT, or GLOBAL"
            ));
        }
        let m_json = serde_json::to_string(&g.members)?;
        let conn = self.conn.lock();
        let id = if g.id > 0 {
            conn.execute(
                "UPDATE outbound_groups SET
                    name = ?1, enable = ?2, group_type = ?3, default_member = ?4, test_url = ?5,
                    interval_secs = ?6, timeout_ms = ?7, tolerance_ms = ?8, members_json = ?9,
                    raw_chains_yaml = ?10, remark = ?11
                 WHERE id = ?12",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    g.group_type.trim(),
                    g.default_member.trim(),
                    g.test_url.trim(),
                    g.interval_secs as i64,
                    g.timeout_ms as i64,
                    g.tolerance_ms as i64,
                    m_json,
                    g.raw_chains_yaml,
                    g.remark.trim(),
                    g.id
                ],
            )?;
            g.id
        } else {
            conn.execute(
                "INSERT INTO outbound_groups (
                    name, enable, group_type, default_member, test_url, interval_secs,
                    timeout_ms, tolerance_ms, members_json, raw_chains_yaml, remark
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    g.group_type.trim(),
                    g.default_member.trim(),
                    g.test_url.trim(),
                    g.interval_secs as i64,
                    g.timeout_ms as i64,
                    g.tolerance_ms as i64,
                    m_json,
                    g.raw_chains_yaml,
                    g.remark.trim(),
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_outbound_group(id)?
            .ok_or_else(|| anyhow!("failed to reload outbound group"))
    }

    pub fn delete_outbound_group(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM outbound_groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_routing_rules(&self) -> Result<Vec<RoutingRuleRecord>> {
        self.read_routing_rules(None)
    }

    pub fn get_routing_rule(&self, id: i64) -> Result<Option<RoutingRuleRecord>> {
        Ok(self.read_routing_rules(Some(id))?.pop())
    }

    fn read_routing_rules(&self, id: Option<i64>) -> Result<Vec<RoutingRuleRecord>> {
        self.query_records(
            "SELECT id, priority, enable, remark, match_type, match_value, action, outbound,
                    no_resolve, override_address
             FROM routing_rules",
            "priority ASC, id ASC", id, |r| {
                Ok(RoutingRuleRecord {
                    id: r.get(0)?,
                    priority: r.get(1)?,
                    enable: r.get::<_, i64>(2)? != 0,
                    remark: r.get(3)?,
                    match_type: r.get(4)?,
                    match_value: r.get(5)?,
                    action: r.get(6)?,
                    outbound: r.get(7)?,
                    no_resolve: r.get::<_, i64>(8)? != 0,
                    override_address: r.get(9)?,
                })
            },
        )
    }

    pub fn save_routing_rule(&self, r: RoutingRuleRecord) -> Result<RoutingRuleRecord> {
        let conn = self.conn.lock();
        let id = if r.id > 0 {
            conn.execute(
                "UPDATE routing_rules SET
                    priority = ?1, enable = ?2, remark = ?3, match_type = ?4,
                    match_value = ?5, action = ?6, outbound = ?7, no_resolve = ?8,
                    override_address = ?9
                 WHERE id = ?10",
                params![
                    r.priority,
                    if r.enable { 1 } else { 0 },
                    r.remark.trim(),
                    r.match_type.trim(),
                    r.match_value.trim(),
                    r.action.trim(),
                    r.outbound.trim(),
                    if r.no_resolve { 1 } else { 0 },
                    r.override_address.trim(),
                    r.id
                ],
            )?;
            r.id
        } else {
            conn.execute(
                "INSERT INTO routing_rules (
                    priority, enable, remark, match_type, match_value, action, outbound,
                    no_resolve, override_address
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.priority,
                    if r.enable { 1 } else { 0 },
                    r.remark.trim(),
                    r.match_type.trim(),
                    r.match_value.trim(),
                    r.action.trim(),
                    r.outbound.trim(),
                    if r.no_resolve { 1 } else { 0 },
                    r.override_address.trim()
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_routing_rule(id)?
            .ok_or_else(|| anyhow!("failed to reload routing rule"))
    }

    pub fn delete_routing_rule(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM routing_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== DNS Groups ====================

    pub fn list_dns_groups(&self) -> Result<Vec<DnsGroupRecord>> {
        self.read_dns_groups(None)
    }

    pub fn get_dns_group(&self, id: i64) -> Result<Option<DnsGroupRecord>> {
        Ok(self.read_dns_groups(Some(id))?.pop())
    }

    fn read_dns_groups(&self, id: Option<i64>) -> Result<Vec<DnsGroupRecord>> {
        self.query_records(
            "SELECT id, name, enable, servers_json, hosts_json, remark, created_at
             FROM dns_groups",
            "id ASC", id, |r| {
                let s_str: String = r.get(3)?;
                let h_str: String = r.get(4)?;
                Ok(DnsGroupRecord {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    enable: r.get::<_, i64>(2)? != 0,
                    servers: serde_json::from_str(&s_str).unwrap_or_default(),
                    hosts: serde_json::from_str(&h_str).unwrap_or_default(),
                    remark: r.get(5)?,
                    created_at: r.get(6)?,
                })
            },
        )
    }

    pub fn save_dns_group(&self, g: DnsGroupRecord) -> Result<DnsGroupRecord> {
        let name = g.name.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("system") {
            return Err(anyhow!(
                "DNS group name must be non-empty and cannot be reserved name 'system'"
            ));
        }
        let s_json = serde_json::to_string(&g.servers)?;
        let h_json = serde_json::to_string(&g.hosts)?;
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if g.id > 0 {
            conn.execute(
                "UPDATE dns_groups SET name = ?1, enable = ?2, servers_json = ?3, hosts_json = ?4, remark = ?5
                 WHERE id = ?6",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    s_json,
                    h_json,
                    g.remark.trim(),
                    g.id
                ],
            )?;
            g.id
        } else {
            conn.execute(
                "INSERT INTO dns_groups (name, enable, servers_json, hosts_json, remark, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    s_json,
                    h_json,
                    g.remark.trim(),
                    now
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_dns_group(id)?
            .ok_or_else(|| anyhow!("failed to reload DNS group"))
    }

    pub fn delete_dns_group(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM dns_groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Rule Source Groups (GeoIP / GeoSite / SRS / MRS) ====================

    pub fn list_rule_source_groups(&self) -> Result<Vec<RuleSourceGroupRecord>> {
        self.read_rule_source_groups(None)
    }

    pub fn get_rule_source_group(&self, id: i64) -> Result<Option<RuleSourceGroupRecord>> {
        Ok(self.read_rule_source_groups(Some(id))?.pop())
    }

    fn read_rule_source_groups(&self, id: Option<i64>) -> Result<Vec<RuleSourceGroupRecord>> {
        self.query_records(
            "SELECT id, name, enable, items_json, remark, created_at
             FROM rule_source_groups",
            "id ASC", id, |r| {
                let items_str: String = r.get(3)?;
                Ok(RuleSourceGroupRecord {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    enable: r.get::<_, i64>(2)? != 0,
                    items: serde_json::from_str(&items_str).unwrap_or_default(),
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                })
            },
        )
    }

    pub fn save_rule_source_group(
        &self,
        g: RuleSourceGroupRecord,
    ) -> Result<RuleSourceGroupRecord> {
        let name = g.name.trim();
        if name.is_empty() {
            return Err(anyhow!("Rule source group name must not be empty"));
        }
        let items_json = serde_json::to_string(&g.items)?;
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if g.id > 0 {
            conn.execute(
                "UPDATE rule_source_groups SET name = ?1, enable = ?2, items_json = ?3, remark = ?4
                 WHERE id = ?5",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    items_json,
                    g.remark.trim(),
                    g.id
                ],
            )?;
            g.id
        } else {
            conn.execute(
                "INSERT INTO rule_source_groups (name, enable, items_json, remark, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    name,
                    if g.enable { 1 } else { 0 },
                    items_json,
                    g.remark.trim(),
                    now
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_rule_source_group(id)?
            .ok_or_else(|| anyhow!("failed to reload rule source group"))
    }

    pub fn update_rule_source_items(&self, id: i64, items: &[RuleSourceItem]) -> Result<()> {
        let items_json = serde_json::to_string(items)?;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE rule_source_groups SET items_json = ?1 WHERE id = ?2",
            params![items_json, id],
        )?;
        Ok(())
    }

    pub fn delete_rule_source_group(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM rule_source_groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Subscriptions ====================

    fn subscription_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SubscriptionRecord> {
        Ok(SubscriptionRecord {
            id: r.get(0)?,
            sub_id: r.get(1)?,
            token: r.get(2)?,
            name: r.get(3)?,
            enable: r.get::<_, i64>(4)? != 0,
            template: r.get(5)?,
            include_cluster: r.get::<_, i64>(6)? != 0,
            created_at: r.get(7)?,
        })
    }

    pub fn list_subscriptions(&self) -> Result<Vec<SubscriptionRecord>> {
        self.read_subscriptions(None)
    }

    pub fn get_subscription(&self, id: i64) -> Result<Option<SubscriptionRecord>> {
        Ok(self.read_subscriptions(Some(id))?.pop())
    }

    fn read_subscriptions(&self, id: Option<i64>) -> Result<Vec<SubscriptionRecord>> {
        self.query_records(
            "SELECT id, sub_id, token, name, enable, template, include_cluster, created_at FROM subscriptions",
            "id ASC", id, Self::subscription_from_row,
        )
    }

    pub fn find_subscription_by_token(&self, token: &str) -> Result<Option<SubscriptionRecord>> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, sub_id, token, name, enable, template, include_cluster, created_at FROM subscriptions WHERE token = ?1 AND enable = 1",
            params![token],
            Self::subscription_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn subscriptions_with_counts(&self) -> Result<Vec<(SubscriptionRecord, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "WITH counts AS (
                 SELECT c.sub_id, COUNT(*) AS nodes
                 FROM clients c JOIN inbounds i ON i.id = c.inbound_id
                 WHERE c.enable <> 0 AND i.enable <> 0 AND i.protocol <> 'portforward'
                 GROUP BY c.sub_id
             )
             SELECT s.id, s.sub_id, s.token, s.name, s.enable, s.template, s.include_cluster, s.created_at,
                    CASE WHEN s.sub_id = 'all' COLLATE NOCASE OR s.sub_id = '*'
                         THEN (SELECT COALESCE(SUM(nodes), 0) FROM counts)
                         ELSE COALESCE(counts.nodes, 0) END
             FROM subscriptions s LEFT JOIN counts ON counts.sub_id = s.sub_id
             ORDER BY s.id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((Self::subscription_from_row(row)?, row.get(8)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn save_subscription(&self, s: SubscriptionRecord) -> Result<SubscriptionRecord> {
        let sub_id = s.sub_id.trim();
        if sub_id.is_empty() {
            return Err(anyhow!("sub_id must not be empty"));
        }
        let token = if s.token.trim().is_empty() {
            generate_random_alnum(22)
        } else {
            s.token.trim().to_string()
        };
        let name = if s.name.trim().is_empty() {
            sub_id
        } else {
            s.name.trim()
        };
        let template = match s.template.trim().to_ascii_lowercase().as_str() {
            "minimal" | "global_direct" | "bypass_cn" | "streaming" => {
                s.template.trim().to_ascii_lowercase()
            }
            _ => String::new(),
        };
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if s.id > 0 {
            conn.execute(
                "UPDATE subscriptions SET sub_id = ?1, token = ?2, name = ?3, enable = ?4, template = ?5, include_cluster = ?6 WHERE id = ?7",
                params![sub_id, token, name, if s.enable { 1 } else { 0 }, template, if s.include_cluster { 1 } else { 0 }, s.id],
            )?;
            s.id
        } else {
            conn.execute(
                "INSERT INTO subscriptions (sub_id, token, name, enable, template, include_cluster, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![sub_id, token, name, if s.enable { 1 } else { 0 }, template, if s.include_cluster { 1 } else { 0 }, now],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_subscription(id)?
            .ok_or_else(|| anyhow!("failed to reload subscription"))
    }

    pub fn rotate_subscription_token(&self, id: i64) -> Result<SubscriptionRecord> {
        let new_tok = generate_random_alnum(22);
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE subscriptions SET token = ?1 WHERE id = ?2",
            params![new_tok, id],
        )?;
        drop(conn);
        self.get_subscription(id)?
            .ok_or_else(|| anyhow!("subscription not found"))
    }

    pub fn delete_subscription(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Cluster Nodes & Local Federation Identity ====================

    fn cluster_node_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ClusterNodeRecord> {
        Ok(ClusterNodeRecord {
            id: r.get(0)?,
            name: r.get(1)?,
            region: r.get(2)?,
            region_flag: r.get(3)?,
            api_url: r.get(4)?,
            api_token: r.get(5)?,
            share_host_override: r.get(6)?,
            allow_insecure: r.get::<_, i64>(7)? != 0,
            enable: r.get::<_, i64>(8)? != 0,
            include_in_sub: r.get::<_, i64>(9)? != 0,
            node_prefix: r.get(10)?,
            remark: r.get(11)?,
            sort_order: r.get(12)?,
            created_at: r.get(13)?,
            updated_at: r.get(14)?,
        })
    }

    pub fn list_cluster_nodes(&self) -> Result<Vec<ClusterNodeRecord>> {
        self.read_cluster_nodes(None)
    }

    pub fn get_cluster_node(&self, id: i64) -> Result<Option<ClusterNodeRecord>> {
        Ok(self.read_cluster_nodes(Some(id))?.pop())
    }

    fn read_cluster_nodes(&self, id: Option<i64>) -> Result<Vec<ClusterNodeRecord>> {
        self.query_records(
            "SELECT id, name, region, region_flag, api_url, api_token, share_host_override,
                    allow_insecure, enable, include_in_sub, node_prefix, remark, sort_order,
                    created_at, updated_at
             FROM cluster_nodes",
            "sort_order ASC, id ASC",
            id,
            Self::cluster_node_from_row,
        )
    }

    pub fn save_cluster_node(&self, mut n: ClusterNodeRecord) -> Result<ClusterNodeRecord> {
        n.name = n.name.trim().to_string();
        if n.name.is_empty() {
            return Err(anyhow!("Cluster node name must not be empty"));
        }
        let normalized_url = normalize_cluster_api_url(&n.api_url)?;
        n.api_url = normalized_url;
        n.region = n.region.trim().to_string();
        n.region_flag = n.region_flag.trim().to_string();
        n.api_token = n.api_token.trim().to_string();
        n.share_host_override = n.share_host_override.trim().to_string();
        n.node_prefix = n.node_prefix.trim().to_string();
        n.remark = n.remark.trim().to_string();

        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if n.id > 0 {
            let existing_token: Option<String> = conn
                .query_row(
                    "SELECT api_token FROM cluster_nodes WHERE id = ?1",
                    params![n.id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(prev_tok) = existing_token else {
                return Err(anyhow!("Cluster node #{} not found", n.id));
            };
            let final_token = if n.api_token.is_empty() {
                prev_tok
            } else {
                n.api_token.clone()
            };
            if final_token.is_empty() {
                return Err(anyhow!("Remote node API token must not be empty"));
            }
            conn.execute(
                "UPDATE cluster_nodes SET
                    name = ?1, region = ?2, region_flag = ?3, api_url = ?4, api_token = ?5,
                    share_host_override = ?6, allow_insecure = ?7, enable = ?8,
                    include_in_sub = ?9, node_prefix = ?10, remark = ?11, sort_order = ?12,
                    updated_at = ?13
                 WHERE id = ?14",
                params![
                    n.name,
                    n.region,
                    n.region_flag,
                    n.api_url,
                    final_token,
                    n.share_host_override,
                    if n.allow_insecure { 1 } else { 0 },
                    if n.enable { 1 } else { 0 },
                    if n.include_in_sub { 1 } else { 0 },
                    n.node_prefix,
                    n.remark,
                    n.sort_order,
                    now,
                    n.id
                ],
            )?;
            n.id
        } else {
            if n.api_token.is_empty() {
                return Err(anyhow!("Remote node API token must not be empty"));
            }
            conn.execute(
                "INSERT INTO cluster_nodes (
                    name, region, region_flag, api_url, api_token, share_host_override,
                    allow_insecure, enable, include_in_sub, node_prefix, remark, sort_order,
                    created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
                params![
                    n.name,
                    n.region,
                    n.region_flag,
                    n.api_url,
                    n.api_token,
                    n.share_host_override,
                    if n.allow_insecure { 1 } else { 0 },
                    if n.enable { 1 } else { 0 },
                    if n.include_in_sub { 1 } else { 0 },
                    n.node_prefix,
                    n.remark,
                    n.sort_order,
                    now
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.get_cluster_node(id)?
            .ok_or_else(|| anyhow!("failed to reload cluster node"))
    }

    pub fn delete_cluster_node(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM cluster_nodes WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_cluster_local_config(&self) -> Result<ClusterLocalConfig> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT key, value FROM settings WHERE key IN (
                'cluster_instance_id',
                'cluster_local_name',
                'cluster_local_region',
                'cluster_local_region_flag',
                'cluster_api_token'
            )",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut cfg = ClusterLocalConfig::default();
        for row in rows {
            let (k, v) = row?;
            match k.as_str() {
                "cluster_instance_id" => cfg.instance_id = v,
                "cluster_local_name" => cfg.local_name = v,
                "cluster_local_region" => cfg.local_region = v,
                "cluster_local_region_flag" => cfg.local_region_flag = v,
                "cluster_api_token" => cfg.api_token = v,
                _ => {}
            }
        }
        drop(stmt);

        if cfg.instance_id.trim().is_empty() {
            cfg.instance_id = generate_uuid();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('cluster_instance_id', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![&cfg.instance_id],
            )?;
        }
        Ok(cfg)
    }

    pub fn get_cluster_api_token(&self) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let val = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'cluster_api_token'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(val)
    }

    pub fn save_cluster_local_identity(
        &self,
        local_name: &str,
        local_region: &str,
        local_region_flag: &str,
    ) -> Result<ClusterLocalConfig> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for (k, v) in [
            ("cluster_local_name", local_name.trim()),
            ("cluster_local_region", local_region.trim()),
            ("cluster_local_region_flag", local_region_flag.trim()),
        ] {
            tx.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![k, v],
            )?;
        }
        tx.commit()?;
        drop(conn);
        self.get_cluster_local_config()
    }

    pub fn rotate_cluster_api_token(&self) -> Result<String> {
        let token = format!("sp_{}", generate_random_alnum(40));
        self.set_setting_kv("cluster_api_token", &token)?;
        Ok(token)
    }

    pub fn revoke_cluster_api_token(&self) -> Result<()> {
        self.set_setting_kv("cluster_api_token", "")
    }

    pub fn get_cluster_instance_id(&self) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let val = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'cluster_instance_id'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(val)
    }

    pub fn verify_cluster_api_token(&self, candidate: &str) -> bool {
        let cand = candidate.trim();
        if cand.is_empty() {
            return false;
        }
        let stored_opt = match self.get_cluster_api_token() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to read cluster_api_token from SQLite: {e:#}");
                return false;
            }
        };
        let Some(raw) = stored_opt else {
            return false;
        };
        let stored = raw.trim();
        if stored.is_empty() {
            return false;
        }
        let d_stored = ring::digest::digest(&ring::digest::SHA256, stored.as_bytes());
        let d_cand = ring::digest::digest(&ring::digest::SHA256, cand.as_bytes());
        let diff = d_stored
            .as_ref()
            .iter()
            .zip(d_cand.as_ref().iter())
            .fold(0u8, |acc, (&a, &b)| acc | (a ^ b));
        diff == 0 && stored.len() == cand.len()
    }
}

pub fn normalize_cluster_api_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(anyhow!("Remote panel API URL must not be empty"));
    }
    let mut parsed = url::Url::parse(trimmed)
        .with_context(|| format!("Invalid remote panel URL '{trimmed}'"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("Remote panel URL must use http:// or https://"));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!("Remote panel URL must include a host"));
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let mut s = parsed.to_string().trim_end_matches('/').to_string();
    for suffix in ["/api/cluster/export", "/api/status", "/api"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim_end_matches('/').to_string();
            break;
        }
    }
    Ok(s)
}

pub fn normalize_base_path(p: &str) -> String {
    let trimmed = p.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub(crate) fn overlapping_port(ranges: &[(u16, u16)], other: u16, spec: &str) -> Option<u16> {
    if ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&other)) {
        return Some(other);
    }
    let others = crate::yaml_gen::parse_port_ranges(other, spec).ok()?;
    ranges.iter().find_map(|&(lo, hi)| others.iter().find_map(|&(a, b)| {
        (lo <= b && a <= hi).then(|| lo.max(a))
    }))
}

// Month containing the most recent scheduled reset, using UTC as the accounting clock.
fn reset_cycle(date: NaiveDate, reset_day: i64) -> String {
    if reset_day <= 0 {
        return String::new();
    }
    let month = if i64::from(date.day()) >= reset_day || date.succ_opt().unwrap().day() == 1 {
        date
    } else {
        date.with_day(1).unwrap().pred_opt().unwrap()
    };
    month.format("%Y-%m").to_string()
}

pub fn validated_base_path(path: &str) -> Result<String> {
    let path = normalize_base_path(path);
    if path == "/sub" || path.starts_with("/sub/") {
        anyhow::bail!("The /sub path is reserved for public subscriptions");
    }
    let url = url::Url::parse(&format!("http://localhost{path}"))?;
    if url.path() != path || url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("Panel base path must be a URL path without dot segments, query or fragment");
    }
    Ok(path)
}

fn next_wg_peer_ips(ib: &Inbound, existing: &[ClientRecord]) -> Result<String> {
    let mut v4_prefix: Option<[u8; 3]> = None;
    let mut v6_prefix = None;
    let mut used_host: std::collections::HashSet<u8> = std::collections::HashSet::new();
    used_host.insert(0);

    let addrs = if ib.protocol_settings.wg_server_addresses.is_empty() {
        vec!["10.77.0.1/32".to_string(), "fd77::1/128".to_string()]
    } else {
        ib.protocol_settings.wg_server_addresses.clone()
    };
    for a in &addrs {
        let ip_part = a.split('/').next().unwrap_or("").trim();
        if let Ok(std::net::IpAddr::V4(v4)) = ip_part.parse::<std::net::IpAddr>() {
            let o = v4.octets();
            v4_prefix = Some([o[0], o[1], o[2]]);
            used_host.insert(o[3]);
        } else if let Ok(std::net::IpAddr::V6(v6)) = ip_part.parse::<std::net::IpAddr>() {
            let segs = v6.segments();
            v6_prefix = Some(segs);
            if segs[7] <= 254 {
                used_host.insert(segs[7] as u8);
            }
        }
    }
    for peer in existing {
        for tok in peer.wg_allowed_ips.split([',', ';', ' ', '\n']) {
            let ip_part = tok.split('/').next().unwrap_or("").trim();
            if let Ok(std::net::IpAddr::V4(v4)) = ip_part.parse::<std::net::IpAddr>() {
                used_host.insert(v4.octets()[3]);
            } else if let Ok(std::net::IpAddr::V6(v6)) = ip_part.parse::<std::net::IpAddr>() {
                let last = v6.segments()[7];
                if last <= 254 {
                    used_host.insert(last as u8);
                }
            }
        }
    }
    let host_id = (2u8..=254u8)
        .find(|n| !used_host.contains(n))
        .context("No free WireGuard peer address in the automatic allocation range")?;
    let mut out = Vec::new();
    if let Some([a, b, c]) = v4_prefix {
        out.push(format!("{a}.{b}.{c}.{host_id}/32"));
    }
    if let Some(mut segments) = v6_prefix {
        segments[7] = u16::from(host_id);
        out.push(format!("{}/128", std::net::Ipv6Addr::from(segments)));
    }
    if out.is_empty() {
        out.push(format!("10.77.0.{host_id}/32"));
    }
    Ok(out.join(", "))
}

pub fn default_client_for_inbound(ib: &Inbound, idx: usize) -> ClientRecord {
    let vision = (ib.stream_settings.security == "reality" && ib.stream_settings.reality.vision)
        || (ib.stream_settings.security == "tls" && ib.stream_settings.tls.vision);
    let cipher = if ib.protocol_settings.cipher.is_empty() {
        "2022-blake3-aes-256-gcm"
    } else {
        ib.protocol_settings.cipher.as_str()
    };
    let password = if ib.protocol == "shadowsocks" && cipher.starts_with("2022-blake3-") {
        crate::crypto_util::generate_ss2022_password(cipher)
            .unwrap_or_else(|_| generate_random_alnum(24))
    } else {
        generate_random_alnum(20)
    };
    let (wg_private_key, wg_public_key, wg_preshared_key, wg_allowed_ips) =
        if ib.protocol == "wireguard" {
            let (priv_k, pub_k, psk) = crate::crypto_util::generate_wireguard_keypair();
            // Allocate the address under the same transaction that inserts the peer.
            (priv_k, pub_k, psk, String::new())
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };
    ClientRecord {
        id: 0,
        inbound_id: ib.id,
        name: if ib.remark.trim().is_empty() {
            format!("client-{idx}")
        } else {
            ib.remark.trim().to_string()
        },
        enable: true,
        uuid: generate_uuid(),
        password,
        username: format!("user{idx}"),
        flow: if ib.protocol == "vless" && vision {
            "xtls-rprx-vision".to_string()
        } else {
            String::new()
        },
        sub_id: "default".to_string(),
        up_bytes: 0,
        down_bytes: 0,
        total_quota_bytes: ib.total_quota_bytes,
        expiry_time: ib.expiry_time,
        comment: String::new(),
        created_at: Utc::now().timestamp_millis(),
        wg_private_key,
        wg_public_key,
        wg_preshared_key,
        wg_allowed_ips,
        wg_keepalive: 25,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    #[test]
    fn inbound_edits_keep_client_ids_accounting_and_rollback_rows() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let mut ib = db.create_inbound(serde_json::from_value(json!({
            "protocol":"anytls", "remark":"test", "port":23456,
            "clients":[{"name":"one","total_quota_bytes":999},{"name":"two","expiry_time":123}]
        }))?)?;
        let first_id = ib.clients[0].id;
        db.conn.lock().execute("UPDATE clients SET up_bytes=70,down_bytes=40 WHERE id=?1", [first_id])?;
        ib.remark = "renamed".into();
        let saved = db.update_inbound(ib.id, ib)?;
        let c = &saved.clients[0];
        assert_eq!((c.id, c.up_bytes, c.down_bytes, c.total_quota_bytes), (first_id, 70, 40, 999));
        assert_eq!(saved.clients[1].expiry_time, 123);
        let mut changed = saved.clone();
        changed.clients.remove(0);
        db.update_inbound(saved.id, changed)?;
        let restored = db.restore_inbound(saved.clone())?;
        assert_eq!(to_value(&restored.clients)?, to_value(&saved.clients)?);
        let deleted = db.delete_config_rows(ConfigTable::Inbounds, &[saved.id, saved.id])?;
        assert_eq!(deleted.affected, 1);
        assert!(db.get_inbound(saved.id)?.is_none());
        db.undo_config_deletion(deleted)?;
        assert_eq!(to_value(db.get_inbound(saved.id)?)?, to_value(restored)?);
        Ok(())
    }

    #[test]
    fn port_search_uses_the_full_range_and_detects_exhaustion() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        for port in [65529, 65530, 65532, 65533, 65534] {
            db.create_inbound(serde_json::from_value(json!({"protocol":"socks","remark":"p","port":port}))?)?;
        }
        assert_eq!(db.next_available_port(65529)?, 65531);
        assert_eq!(db.next_available_port(65532)?, 65535);
        db.create_inbound(serde_json::from_value(json!({"protocol":"socks","remark":"last","port":65535}))?)?;
        assert!(db.next_available_port(65532).is_err());
        Ok(())
    }

    #[test]
    fn ranged_inbounds_reserve_secondary_ports_and_reassign_the_whole_range() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let mut ib = db.create_inbound(serde_json::from_value(json!({
            "protocol":"hysteria2","remark":"hop","port":22000,
            "protocol_settings":{"port_range":"22000-22004,22010"}
        }))?)?;
        assert_eq!(db.next_available_port(22002)?, 22005);
        let conflict: Inbound = serde_json::from_value(json!({
            "protocol":"hysteria2","remark":"overlap","port":21999,
            "protocol_settings":{"port_range":"21999,22003"}
        }))?;
        assert!(db.create_inbound(conflict).is_err());
        db.assign_inbound_port(&mut ib, 22001, false)?;
        assert_eq!(ib.port, 22005);
        assert_eq!(ib.protocol_settings.port_range, "22005-22009,22015");
        db.create_inbound(ib)?;
        assert_eq!(db.next_available_port(22002)?, 22011);
        Ok(())
    }

    #[test]
    fn incompatible_restore_preserves_live_data_and_older_backup_migrates() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("live.db"), dir.path())?;
        db.set_setting_kv("public_host", "live.example")?;
        let other = Database::open(&dir.path().join("old.db"), dir.path())?;
        other.set_setting_kv("public_host", "old.example")?;
        other.conn.lock().execute_batch("ALTER TABLE subscriptions DROP COLUMN template")?;
        let old = other.backup_snapshot()?;
        other.conn.lock().execute_batch("ALTER TABLE clients RENAME COLUMN name TO legacy_name")?;
        assert!(db.restore_from_bytes(&other.backup_snapshot()?).is_err());
        assert_eq!(db.get_settings()?.public_host, "live.example");
        let before = db.restore_from_bytes(&old)?;
        assert_eq!(db.get_settings()?.public_host, "old.example");
        assert_eq!(db.list_subscriptions()?[0].template, "");
        let safety = std::fs::read(dir.path().join("backups").join(before))?;
        db.restore_from_bytes(&safety)?;
        assert_eq!(db.get_settings()?.public_host, "live.example");
        Ok(())
    }

    #[test]
    fn failed_client_reset_rolls_back_inbound_totals() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let ib = db.create_inbound(serde_json::from_value(json!({"protocol":"anytls","remark":"q","port":23456}))?)?;
        db.add_traffic_deltas(&HashMap::from([(ib.tag, (13, 21))]), None)?;
        db.conn.lock().execute_batch(
            "CREATE TRIGGER reject_reset BEFORE UPDATE OF up_bytes ON clients
             BEGIN SELECT RAISE(ABORT, 'reset failure'); END;"
        )?;
        assert!(db.reset_inbound_traffic(ib.id).is_err());
        assert!(db.reset_all_traffic().is_err());
        let totals = db.inbound_totals()?;
        assert_eq!((totals.up_bytes, totals.down_bytes), (13, 21));
        Ok(())
    }

    #[test]
    fn monthly_reset_on_31st_runs_once_in_short_months_and_catches_up() -> Result<()> {
        use chrono::TimeZone;
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let ib = db.create_inbound(serde_json::from_value(json!({
            "protocol":"socks","remark":"quota","port":24000,"auto_reset_day":31
        }))?)?;
        db.conn.lock().execute("UPDATE inbounds SET last_reset_month='2024-01', up_bytes=5", [])?;
        let run = |month, day| db.enforce_quotas_at(Utc.with_ymd_and_hms(2024, month, day, 12, 0, 0).unwrap());
        run(2, 28)?;
        assert_eq!(db.inbound_totals()?.up_bytes, 5);
        run(2, 29)?;
        assert_eq!(db.inbound_totals()?.up_bytes, 0);
        db.add_traffic_deltas(&HashMap::from([(ib.tag, (7, 0))]), None)?;
        run(2, 29)?;
        run(3, 1)?;
        assert_eq!(db.inbound_totals()?.up_bytes, 7);
        run(4, 2)?;
        assert_eq!(db.inbound_totals()?.up_bytes, 0);
        assert_eq!(db.get_inbound(ib.id)?.unwrap().last_reset_month, "2024-03");
        Ok(())
    }

    #[test]
    fn wireguard_ipv6_only_auto_allocation_has_no_duplicates() -> Result<()> {
        let mut ib: Inbound = serde_json::from_value(json!({"protocol":"wireguard","port":51820,"remark":"v6"}))?;
        ib.protocol_settings.wg_server_addresses = vec!["fd77:1::beef:1/128".into()];
        let mut peers = Vec::new();
        for host in 2..=254 {
            let ips = next_wg_peer_ips(&ib, &peers)?;
            assert_eq!(ips, format!("fd77:1::beef:{host:x}/128"));
            peers.push(ClientRecord { wg_allowed_ips: ips, ..Default::default() });
        }
        assert!(next_wg_peer_ips(&ib, &peers).is_err());
        Ok(())
    }

    #[test]
    fn core_history_keeps_recent_minutes_and_events() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let now = Utc::now().timestamp_millis() / 60_000 * 60_000;
        let old = now - 86_400_000;
        db.save_core_minute(old, json!({"time":old}))?;
        db.save_core_minute(now, json!({"time":now,"cpu":15}))?;
        db.record_core_event("restart");
        let history = db.core_history()?;
        assert_eq!(history["minutes"], json!([{"time":now,"cpu":15}]));
        assert_eq!(history["events"][0]["kind"], "restart");
        Ok(())
    }

    #[test]
    fn daily_proxy_history_survives_counter_resets_and_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("panel.db");
        let db = Database::open(&file, dir.path())?;
        let rows = db.daily_traffic()?;
        assert_eq!(rows.len(), 30);
        assert!(rows.iter().all(|r| r["up"].is_null()));
        let yesterday = rows[28]["day"].as_str().unwrap();
        let today = rows[29]["day"].as_str().unwrap();
        let empty = HashMap::new();
        db.add_traffic_deltas(&empty, Some((yesterday, 0, 0)))?;
        db.add_traffic_deltas(&empty, Some((today, 19, 27)))?;
        db.add_traffic_deltas(&empty, Some((today, 3, 4)))?;
        db.reset_all_traffic()?;
        drop(db);
        let rows = Database::open(&file, dir.path())?.daily_traffic()?;
        assert_eq!(rows[28], json!({"day": yesterday, "up": 0, "down": 0}));
        assert_eq!(rows[29], json!({"day": today, "up": 22, "down": 31}));
        Ok(())
    }

    #[test]
    fn subscription_counts_include_only_enabled_nodes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        db.conn.lock().execute_batch(
            "INSERT INTO subscriptions(sub_id, token, name, enable, created_at)
             VALUES ('aLl','all-token','',1,0), ('*','star-token','',1,0),
                    ('team','team-token','',0,0), ('TEAM','upper-token','',1,0);
             INSERT INTO inbounds
               (id,tag,remark,port,enable,protocol,protocol_settings,stream_settings,created_at,updated_at)
             VALUES (1,'a','',1001,1,'anytls','{}','{}',0,0),
                    (2,'b','',1002,0,'anytls','{}','{}',0,0);
             INSERT INTO clients(inbound_id,name,sub_id,enable,created_at)
             VALUES (1,'one','team',1,0), (1,'two','team',1,0), (1,'three','other',1,0),
                    (1,'disabled','team',0,0), (2,'disabled inbound','team',1,0);",
        )?;
        let counts: Vec<_> = db
            .subscriptions_with_counts()?
            .into_iter()
            .map(|(_, n)| n)
            .collect();
        assert_eq!(counts, [0, 3, 3, 2, 0]);
        db.conn.lock().execute("DELETE FROM clients", [])?;
        assert!(db.subscriptions_with_counts()?.iter().all(|(_, n)| *n == 0));
        Ok(())
    }

    #[test]
    fn clash_settings_are_live_and_missing_defaults_are_seeded_on_open() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("panel.db");
        let db = Database::open(&file, dir.path())?;
        let (addr, secret) = db.clash_api_settings()?;
        assert_eq!(addr, "127.0.0.1:19090");
        assert!(!secret.is_empty());
        db.set_setting_kv("clash_api_secret", "changed")?;
        db.set_setting_kv("clash_api_addr", "")?;
        assert_eq!(db.clash_api_settings()?, (String::new(), "changed".into()));
        db.conn
            .lock()
            .execute("DELETE FROM settings WHERE key='clash_api_addr'", [])?;
        drop(db);
        let reopened = Database::open(&file, dir.path())?;
        assert_eq!(reopened.clash_api_settings()?, (addr, "changed".into()));
        assert_eq!(reopened.get_settings()?.clash_api_secret, "changed");
        Ok(())
    }

    #[test]
    fn status_totals_and_single_inbound_match_list_semantics() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        assert_eq!(
            to_value(db.inbound_totals()?)?,
            json!({
                "up_bytes": 0, "down_bytes": 0, "inbounds_total": 0,
                "inbounds_enabled": 0, "clients_total": 0
            })
        );
        db.conn.lock().execute_batch(
            "INSERT INTO inbounds
               (id, tag, remark, port, enable, protocol, protocol_settings, stream_settings,
                up_bytes, down_bytes, total_quota_bytes, expiry_time, created_at, updated_at)
             VALUES (1,'a','',1001,0,'vless','{}','{}',12,8,1000,900,0,0),
                    (2,'b','',1002,1,'anytls','{}','{}',20,30,2000,800,0,0);
             INSERT INTO clients (id,inbound_id,name,enable,up_bytes,created_at)
             VALUES (10,2,'first',0,7,0), (11,1,'single',1,3,0), (12,2,'last',1,9,0);",
        )?;
        assert_eq!(
            to_value(db.inbound_totals()?)?,
            json!({
                "up_bytes": 32, "down_bytes": 38, "inbounds_total": 2,
                "inbounds_enabled": 1, "clients_total": 3
            })
        );
        let list = db.list_inbounds()?;
        for inbound in &list {
            assert_eq!(to_value(db.get_inbound(inbound.id)?)?, to_value(inbound)?);
        }
        assert!(db.get_inbound(999)?.is_none());
        let single = &list[0].clients[0];
        assert_eq!(
            (
                single.up_bytes,
                single.down_bytes,
                single.total_quota_bytes,
                single.expiry_time
            ),
            (12, 8, 1000, 900)
        );
        let multi: Vec<_> = list[1].clients.iter().map(|c| (c.id, c.up_bytes)).collect();
        assert_eq!(multi, [(10, 7), (12, 9)]);
        Ok(())
    }

    #[test]
    fn cluster_token_single_lookup_and_error_propagation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;

        // Initially disabled; missing or empty key both reject tokens cleanly
        assert!(!db.verify_cluster_api_token("sp_anything"));
        let cfg0 = db.get_cluster_local_config()?;
        assert!(!cfg0.instance_id.is_empty());
        assert_eq!(
            db.get_cluster_instance_id()?.as_deref(),
            Some(cfg0.instance_id.as_str())
        );

        let saved = db.save_cluster_local_identity("HK-01", "HK", "🇭🇰")?;
        assert_eq!(saved.instance_id, cfg0.instance_id);
        assert_eq!(saved.local_name, "HK-01");
        assert_eq!(saved.local_region, "HK");
        assert_eq!(saved.local_region_flag, "🇭🇰");

        let tok = db.rotate_cluster_api_token()?;
        assert!(db.verify_cluster_api_token(&tok));
        assert!(!db.verify_cluster_api_token(&format!("{tok}x")));
        assert!(!db.verify_cluster_api_token(""));

        // Deleting the token row distinguishes missing key (Ok(None)) from SQLite error
        db.conn
            .lock()
            .execute("DELETE FROM settings WHERE key = 'cluster_api_token'", [])?;
        assert_eq!(db.get_cluster_api_token()?, None);
        assert!(!db.verify_cluster_api_token(&tok));

        // Real SQLite error must propagate as Err instead of being swallowed into empty defaults
        db.conn.lock().execute_batch("DROP TABLE settings;")?;
        assert!(db.get_cluster_api_token().is_err());
        assert!(db.get_cluster_local_config().is_err());
        assert!(!db.verify_cluster_api_token(&tok));
        Ok(())
    }
}
