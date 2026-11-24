use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crypto_util::{generate_random_alnum, generate_uuid, hash_password, verify_password};
use crate::models::{
    CertificateRecord, ClientRecord, Inbound, OutboundGroupRecord, PanelSettings,
    RoutingRuleRecord, StreamSettings, SubscriptionRecord,
};

pub struct Database {
    conn: Mutex<Connection>,
    pub data_dir: PathBuf,
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
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL
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
                created_at INTEGER NOT NULL
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
                outbound TEXT NOT NULL DEFAULT 'direct'
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_id TEXT UNIQUE NOT NULL,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );",
        )?;

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

        drop(conn);
        // Ensure default settings exist
        let _ = self.get_settings()?;
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
            if c.exists() {
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
        if new_password.len() < 4 {
            return Err(anyhow!("Password must be at least 4 characters"));
        }
        let conn = self.conn.lock();
        let (id, existing_hash): (i64, String) = conn.query_row(
            "SELECT id, password_hash FROM users ORDER BY id ASC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(curr) = current_password {
            if !verify_password(curr, &existing_hash) {
                return Err(anyhow!("Current password is incorrect"));
            }
        }
        let hash = hash_password(new_password)?;
        let now = Utc::now().timestamp_millis();
        conn.execute(
            "UPDATE users SET username = ?1, password_hash = ?2, updated_at = ?3 WHERE id = ?4",
            params![new_username, hash, now, id],
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

        let default_cfg_path = self
            .data_dir
            .join("shoes.config.yaml")
            .to_string_lossy()
            .to_string();
        let default_secret = generate_random_alnum(32);
        let default_bin = Self::default_shoes_bin_path(&self.data_dir);

        let get_or_init = |k: &str, def: &str| -> Result<String> {
            if let Some(v) = map.get(k) {
                Ok(v.clone())
            } else {
                conn.execute(
                    "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
                    params![k, def],
                )?;
                Ok(def.to_string())
            }
        };

        let env_port = std::env::var("PANEL_PORT").unwrap_or_else(|_| "54321".to_string());
        let settings = PanelSettings {
            panel_listen: get_or_init("panel_listen", "0.0.0.0")?,
            panel_port: get_or_init("panel_port", &env_port)?
                .parse()
                .unwrap_or(54321),
            panel_base_path: normalize_base_path(&get_or_init("panel_base_path", "/")?),
            panel_cert_file: get_or_init("panel_cert_file", "")?,
            panel_key_file: get_or_init("panel_key_file", "")?,
            public_host: get_or_init("public_host", "")?,
            sub_public_url: get_or_init("sub_public_url", "")?,
            shoes_bin_path: get_or_init("shoes_bin_path", &default_bin)?,
            shoes_config_path: get_or_init("shoes_config_path", &default_cfg_path)?,
            clash_api_addr: get_or_init("clash_api_addr", "127.0.0.1:19090")?,
            clash_api_secret: get_or_init("clash_api_secret", &default_secret)?,
            shoes_auto_start: get_or_init("shoes_auto_start", "true")? == "true",
            shoes_extra_yaml: get_or_init("shoes_extra_yaml", "")?,
            session_ttl_hours: get_or_init("session_ttl_hours", "168")?
                .parse()
                .unwrap_or(168),
        };
        Ok(settings)
    }

    pub fn save_settings(&self, s: &PanelSettings) -> Result<()> {
        let conn = self.conn.lock();
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
        ];
        for (k, v) in pairs {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![k, v],
            )?;
        }
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

    // ==================== Inbounds & Clients (Two-Layer Model) ====================

    pub fn list_inbounds(&self) -> Result<Vec<Inbound>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, tag, remark, enable, listen, port, protocol, protocol_settings,
                    stream_settings, up_bytes, down_bytes, total_quota_bytes, expiry_time,
                    auto_reset_day, last_reset_month, created_at, updated_at
             FROM inbounds ORDER BY id ASC",
        )?;
        let mut inbounds: Vec<Inbound> = stmt
            .query_map([], |r| {
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

        let mut cstmt = conn.prepare(
            "SELECT id, inbound_id, name, enable, uuid, password, username, flow, sub_id,
                    up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at
             FROM clients ORDER BY id ASC",
        )?;
        let clients: Vec<ClientRecord> = cstmt
            .query_map([], |r| {
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

    pub fn get_inbound(&self, id: i64) -> Result<Option<Inbound>> {
        Ok(self.list_inbounds()?.into_iter().find(|i| i.id == id))
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

    fn check_port_conflict(
        conn: &Connection,
        exclude_id: Option<i64>,
        listen: &str,
        port: u16,
        is_quic: bool,
    ) -> Result<()> {
        if port == 0 {
            return Err(anyhow!("Port must be between 1 and 65535"));
        }
        let mut stmt = conn.prepare(
            "SELECT id, remark, listen, protocol, stream_settings FROM inbounds WHERE port = ?1",
        )?;
        let rows = stmt.query_map(params![port], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (other_id, remark, other_listen, other_proto, ss_json) = row?;
            if exclude_id == Some(other_id) {
                continue;
            }
            let ss: StreamSettings = serde_json::from_str(&ss_json).unwrap_or_default();
            let other_is_quic =
                matches!(other_proto.as_str(), "hysteria2" | "tuic") || ss.network == "quic";
            // TCP and QUIC/UDP CAN share the same port (e.g., VLESS-TLS on TCP 443 + Hysteria2 on QUIC 443)!
            if is_quic == other_is_quic
                && (listen == "0.0.0.0"
                    || other_listen == "0.0.0.0"
                    || listen == "::"
                    || other_listen == "::"
                    || listen == other_listen)
            {
                let proto_label = if is_quic { "UDP/QUIC" } else { "TCP" };
                return Err(anyhow!(
                    "Port {} ({}) is already used by inbound '{}' (#{})",
                    port,
                    proto_label,
                    remark,
                    other_id
                ));
            }
        }
        Ok(())
    }

    pub fn create_inbound(&self, mut ib: Inbound) -> Result<Inbound> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock();
        Self::check_port_conflict(&conn, None, &ib.listen, ib.port, ib.is_quic())?;

        let tx = conn.transaction()?;
        let temp_tag = format!("inbound-tmp-{}", generate_random_alnum(8));
        let ps_json = serde_json::to_string(&ib.protocol_settings)?;
        let ss_json = serde_json::to_string(&ib.stream_settings)?;

        tx.execute(
            "INSERT INTO inbounds (
                tag, remark, enable, listen, port, protocol, protocol_settings, stream_settings,
                up_bytes, down_bytes, total_quota_bytes, expiry_time, auto_reset_day,
                last_reset_month, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, '', ?12, ?13)",
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
                ib.protocol.trim().to_lowercase(),
                ps_json,
                ss_json,
                ib.total_quota_bytes.max(0),
                ib.expiry_time.max(0),
                ib.auto_reset_day.clamp(0, 31),
                now,
                now
            ],
        )?;
        let inbound_id = tx.last_insert_rowid();
        let final_tag = format!("inbound-{inbound_id}");
        tx.execute(
            "UPDATE inbounds SET tag = ?1 WHERE id = ?2",
            params![final_tag, inbound_id],
        )?;

        // Ensure at least 1 client exists in `clients` table; for single-user protocols cap at 1.
        if ib.clients.is_empty() {
            ib.clients.push(default_client_for_inbound(&ib, 1));
        } else if !ib.supports_multi_user() && ib.clients.len() > 1 {
            ib.clients.truncate(1);
        }

        for c in &ib.clients {
            let sub_id = if c.sub_id.trim().is_empty() {
                "default"
            } else {
                c.sub_id.trim()
            };
            Self::ensure_subscription_for_sub_id(&tx, sub_id)?;
            tx.execute(
                "INSERT INTO clients (
                    inbound_id, name, enable, uuid, password, username, flow, sub_id,
                    up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, ?12)",
                params![
                    inbound_id,
                    if c.name.trim().is_empty() {
                        ib.remark.trim()
                    } else {
                        c.name.trim()
                    },
                    if c.enable { 1 } else { 0 },
                    c.uuid.trim(),
                    c.password.trim(),
                    c.username.trim(),
                    c.flow.trim(),
                    sub_id,
                    ib.total_quota_bytes.max(0),
                    ib.expiry_time.max(0),
                    c.comment.trim(),
                    now
                ],
            )?;
        }

        tx.commit()?;
        drop(conn);
        self.get_inbound(inbound_id)?
            .ok_or_else(|| anyhow!("failed to reload created inbound"))
    }

    pub fn update_inbound(&self, id: i64, mut ib: Inbound) -> Result<Inbound> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock();
        Self::check_port_conflict(&conn, Some(id), &ib.listen, ib.port, ib.is_quic())?;

        let tx = conn.transaction()?;
        let tag = format!("inbound-{id}");
        let ps_json = serde_json::to_string(&ib.protocol_settings)?;
        let ss_json = serde_json::to_string(&ib.stream_settings)?;

        let affected = tx.execute(
            "UPDATE inbounds SET
                tag = ?1, remark = ?2, enable = ?3, listen = ?4, port = ?5, protocol = ?6,
                protocol_settings = ?7, stream_settings = ?8, total_quota_bytes = ?9,
                expiry_time = ?10, auto_reset_day = ?11, updated_at = ?12
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
                ib.protocol.trim().to_lowercase(),
                ps_json,
                ss_json,
                ib.total_quota_bytes.max(0),
                ib.expiry_time.max(0),
                ib.auto_reset_day.clamp(0, 31),
                now,
                id
            ],
        )?;
        if affected == 0 {
            return Err(anyhow!("Inbound #{id} not found"));
        }

        if !ib.clients.is_empty() {
            if !ib.supports_multi_user() && ib.clients.len() > 1 {
                ib.clients.truncate(1);
            }
            tx.execute("DELETE FROM clients WHERE inbound_id = ?1", params![id])?;
            for c in &ib.clients {
                let sub_id = if c.sub_id.trim().is_empty() {
                    "default"
                } else {
                    c.sub_id.trim()
                };
                Self::ensure_subscription_for_sub_id(&tx, sub_id)?;
                tx.execute(
                    "INSERT INTO clients (
                        inbound_id, name, enable, uuid, password, username, flow, sub_id,
                        up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, ?12)",
                    params![
                        id,
                        if c.name.trim().is_empty() {
                            ib.remark.trim()
                        } else {
                            c.name.trim()
                        },
                        if c.enable { 1 } else { 0 },
                        c.uuid.trim(),
                        c.password.trim(),
                        c.username.trim(),
                        c.flow.trim(),
                        sub_id,
                        ib.total_quota_bytes.max(0),
                        ib.expiry_time.max(0),
                        c.comment.trim(),
                        if c.created_at > 0 { c.created_at } else { now }
                    ],
                )?;
            }
        }

        tx.commit()?;
        drop(conn);
        self.get_inbound(id)?
            .ok_or_else(|| anyhow!("failed to reload updated inbound"))
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

    pub fn reset_inbound_traffic(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE inbounds SET up_bytes = 0, down_bytes = 0 WHERE id = ?1",
            params![id],
        )?;
        conn.execute(
            "UPDATE clients SET up_bytes = 0, down_bytes = 0 WHERE inbound_id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn reset_all_traffic(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("UPDATE inbounds SET up_bytes = 0, down_bytes = 0", [])?;
        conn.execute("UPDATE clients SET up_bytes = 0, down_bytes = 0", [])?;
        Ok(())
    }

    /// Adds a client to an inbound (for AnyTLS / NaiveProxy multi-user inbounds).
    pub fn add_client(&self, inbound_id: i64, c: ClientRecord) -> Result<Inbound> {
        let inbound = self
            .get_inbound(inbound_id)?
            .ok_or_else(|| anyhow!("Inbound #{inbound_id} not found"))?;
        if !inbound.supports_multi_user() && !inbound.clients.is_empty() {
            return Err(anyhow!(
                "Protocol '{}' only supports 1 credential per port in shoes. Use Clone Inbound to allocate a dedicated port for a new client.",
                inbound.protocol
            ));
        }
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let sub_id = if c.sub_id.trim().is_empty() {
            "default"
        } else {
            c.sub_id.trim()
        };
        Self::ensure_subscription_for_sub_id(&conn, sub_id)?;
        conn.execute(
            "INSERT INTO clients (
                inbound_id, name, enable, uuid, password, username, flow, sub_id,
                up_bytes, down_bytes, total_quota_bytes, expiry_time, comment, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, ?12)",
            params![
                inbound_id,
                c.name.trim(),
                if c.enable { 1 } else { 0 },
                c.uuid.trim(),
                c.password.trim(),
                c.username.trim(),
                c.flow.trim(),
                sub_id,
                c.total_quota_bytes.max(0),
                c.expiry_time.max(0),
                c.comment.trim(),
                now
            ],
        )?;
        drop(conn);
        self.get_inbound(inbound_id)?
            .ok_or_else(|| anyhow!("Inbound not found"))
    }

    pub fn update_client(&self, client_id: i64, c: ClientRecord) -> Result<Inbound> {
        let conn = self.conn.lock();
        let inbound_id: i64 = conn.query_row(
            "SELECT inbound_id FROM clients WHERE id = ?1",
            params![client_id],
            |r| r.get(0),
        )?;
        let sub_id = if c.sub_id.trim().is_empty() {
            "default"
        } else {
            c.sub_id.trim()
        };
        Self::ensure_subscription_for_sub_id(&conn, sub_id)?;
        conn.execute(
            "UPDATE clients SET
                name = ?1, enable = ?2, uuid = ?3, password = ?4, username = ?5,
                flow = ?6, sub_id = ?7, comment = ?8
             WHERE id = ?9",
            params![
                c.name.trim(),
                if c.enable { 1 } else { 0 },
                c.uuid.trim(),
                c.password.trim(),
                c.username.trim(),
                c.flow.trim(),
                sub_id,
                c.comment.trim(),
                client_id
            ],
        )?;
        drop(conn);
        self.get_inbound(inbound_id)?
            .ok_or_else(|| anyhow!("Inbound not found"))
    }

    pub fn delete_client(&self, client_id: i64) -> Result<Inbound> {
        let conn = self.conn.lock();
        let inbound_id: i64 = conn.query_row(
            "SELECT inbound_id FROM clients WHERE id = ?1",
            params![client_id],
            |r| r.get(0),
        )?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM clients WHERE inbound_id = ?1",
            params![inbound_id],
            |r| r.get(0),
        )?;
        if count <= 1 {
            return Err(anyhow!(
                "An inbound must retain at least 1 client credential. Delete the inbound instead."
            ));
        }
        conn.execute("DELETE FROM clients WHERE id = ?1", params![client_id])?;
        drop(conn);
        self.get_inbound(inbound_id)?
            .ok_or_else(|| anyhow!("Inbound not found"))
    }

    pub fn next_available_port(&self, start_port: u16) -> Result<u16> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT port FROM inbounds")?;
        let used: std::collections::HashSet<u16> = stmt
            .query_map([], |r| r.get::<_, u16>(0))?
            .filter_map(|r| r.ok())
            .collect();
        let mut candidate = start_port.max(1024);
        while used.contains(&candidate) && candidate < 65530 {
            candidate += 1;
        }
        Ok(candidate)
    }

    /// Accumulates per-inbound byte deltas (`tag -> (up_delta, down_delta)`) into SQLite.
    pub fn add_traffic_deltas(&self, deltas: &HashMap<String, (u64, u64)>) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for (tag, (up, down)) in deltas {
            if *up == 0 && *down == 0 {
                continue;
            }
            tx.execute(
                "UPDATE inbounds SET up_bytes = up_bytes + ?1, down_bytes = down_bytes + ?2 WHERE tag = ?3",
                params![*up as i64, *down as i64, tag],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Checks monthly traffic reset, expiry timestamps, and traffic quotas.
    /// Returns tags of any inbounds that were newly auto-disabled so caller can trigger hot-reload!
    pub fn enforce_quotas_and_expiry(&self) -> Result<Vec<String>> {
        let now_dt = Utc::now();
        let now_ms = now_dt.timestamp_millis();
        let current_month = now_dt.format("%Y-%m").to_string();
        let today_day = chrono::Datelike::day(&now_dt) as i64;

        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;

        // 1. Monthly auto-reset if configured
        tx.execute(
            "UPDATE inbounds
             SET up_bytes = 0, down_bytes = 0, last_reset_month = ?1
             WHERE auto_reset_day > 0
               AND auto_reset_day <= ?2
               AND last_reset_month != ?1
               AND last_reset_month != ''",
            params![current_month, today_day],
        )?;
        // Initialize empty last_reset_month so newly created inbounds don't immediately reset
        tx.execute(
            "UPDATE inbounds SET last_reset_month = ?1 WHERE auto_reset_day > 0 AND last_reset_month = ''",
            params![current_month],
        )?;

        // 2. Find enabled inbounds that exceeded expiry_time or total_quota_bytes
        let mut disabled_tags = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, tag FROM inbounds
                 WHERE enable = 1
                   AND (
                       (expiry_time > 0 AND expiry_time <= ?1)
                       OR (total_quota_bytes > 0 AND (up_bytes + down_bytes) >= total_quota_bytes)
                   )",
            )?;
            let rows = stmt.query_map(params![now_ms], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (id, tag) = row?;
                disabled_tags.push((id, tag));
            }
        }

        let mut result_tags = Vec::new();
        for (id, tag) in disabled_tags {
            tx.execute(
                "UPDATE inbounds SET enable = 0, updated_at = ?1 WHERE id = ?2",
                params![now_ms, id],
            )?;
            result_tags.push(tag);
        }

        tx.commit()?;
        Ok(result_tags)
    }

    // ==================== Certificates ====================

    pub fn list_certificates(&self) -> Result<Vec<CertificateRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, cert_type, cert_file, key_file, domains_json, email,
                    directory_url, terms_of_service, challenge_type, http01_listen, remark, created_at
             FROM certificates ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
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
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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
        self.list_certificates()?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("failed to reload certificate"))
    }

    pub fn delete_certificate(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM certificates WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Outbound Groups & Routing Rules ====================

    pub fn list_outbound_groups(&self) -> Result<Vec<OutboundGroupRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, enable, group_type, default_member, test_url, interval_secs,
                    timeout_ms, tolerance_ms, members_json, raw_chains_yaml, remark
             FROM outbound_groups ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
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
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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
        self.list_outbound_groups()?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("failed to reload outbound group"))
    }

    pub fn delete_outbound_group(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM outbound_groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_routing_rules(&self) -> Result<Vec<RoutingRuleRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, priority, enable, remark, match_type, match_value, action, outbound
             FROM routing_rules ORDER BY priority ASC, id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RoutingRuleRecord {
                id: r.get(0)?,
                priority: r.get(1)?,
                enable: r.get::<_, i64>(2)? != 0,
                remark: r.get(3)?,
                match_type: r.get(4)?,
                match_value: r.get(5)?,
                action: r.get(6)?,
                outbound: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn save_routing_rule(&self, r: RoutingRuleRecord) -> Result<RoutingRuleRecord> {
        let conn = self.conn.lock();
        let id = if r.id > 0 {
            conn.execute(
                "UPDATE routing_rules SET
                    priority = ?1, enable = ?2, remark = ?3, match_type = ?4,
                    match_value = ?5, action = ?6, outbound = ?7
                 WHERE id = ?8",
                params![
                    r.priority,
                    if r.enable { 1 } else { 0 },
                    r.remark.trim(),
                    r.match_type.trim(),
                    r.match_value.trim(),
                    r.action.trim(),
                    r.outbound.trim(),
                    r.id
                ],
            )?;
            r.id
        } else {
            conn.execute(
                "INSERT INTO routing_rules (
                    priority, enable, remark, match_type, match_value, action, outbound
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    r.priority,
                    if r.enable { 1 } else { 0 },
                    r.remark.trim(),
                    r.match_type.trim(),
                    r.match_value.trim(),
                    r.action.trim(),
                    r.outbound.trim()
                ],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.list_routing_rules()?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("failed to reload routing rule"))
    }

    pub fn delete_routing_rule(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM routing_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==================== Subscriptions ====================

    pub fn list_subscriptions(&self) -> Result<Vec<SubscriptionRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, sub_id, token, name, enable, created_at FROM subscriptions ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SubscriptionRecord {
                id: r.get(0)?,
                sub_id: r.get(1)?,
                token: r.get(2)?,
                name: r.get(3)?,
                enable: r.get::<_, i64>(4)? != 0,
                created_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn find_subscription_by_token(&self, token: &str) -> Result<Option<SubscriptionRecord>> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, sub_id, token, name, enable, created_at FROM subscriptions WHERE token = ?1 AND enable = 1",
            params![token],
            |r| {
                Ok(SubscriptionRecord {
                    id: r.get(0)?,
                    sub_id: r.get(1)?,
                    token: r.get(2)?,
                    name: r.get(3)?,
                    enable: r.get::<_, i64>(4)? != 0,
                    created_at: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
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
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock();
        let id = if s.id > 0 {
            conn.execute(
                "UPDATE subscriptions SET sub_id = ?1, token = ?2, name = ?3, enable = ?4 WHERE id = ?5",
                params![sub_id, token, name, if s.enable { 1 } else { 0 }, s.id],
            )?;
            s.id
        } else {
            conn.execute(
                "INSERT INTO subscriptions (sub_id, token, name, enable, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sub_id, token, name, if s.enable { 1 } else { 0 }, now],
            )?;
            conn.last_insert_rowid()
        };
        drop(conn);
        self.list_subscriptions()?
            .into_iter()
            .find(|item| item.id == id)
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
        self.list_subscriptions()?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription not found"))
    }

    pub fn delete_subscription(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        Ok(())
    }
}

pub fn normalize_base_path(p: &str) -> String {
    let trimmed = p.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
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
    }
}
