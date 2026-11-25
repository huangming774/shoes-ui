mod api;
mod auth;
mod crypto_util;
mod db;
mod models;
mod monitor;
mod process;
mod state;
mod sub_gen;
mod yaml_gen;

use anyhow::{Context, Result};
use axum::{
    extract::Request,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer};

use crate::api::build_inner_router;
use crate::db::{validated_base_path, Database};
use crate::monitor::RuntimeMonitor;
use crate::process::ShoesProcessManager;
use crate::state::AppState;

fn resolve_data_dir(custom: Option<String>) -> PathBuf {
    if let Some(c) = custom {
        return PathBuf::from(c);
    }
    if let Ok(env_dir) = std::env::var("SHOES_PANEL_DATA") {
        if !env_dir.trim().is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    if cfg!(unix) && PathBuf::from("/etc/shoes-panel").exists() {
        return PathBuf::from("/etc/shoes-panel");
    }
    PathBuf::from("./data")
}

fn print_help() {
    println!(
        "shoes-panel v{} — 3x-ui style web panel for cfal/shoes

USAGE:
  shoes-panel [serve] [--data-dir <DIR>] [--port <PORT>]
  shoes-panel reset [--username <USER>] [--password <PASS>] [--data-dir <DIR>]
  shoes-panel setting [--port <PORT>] [--base-path <PATH>] [--shoes-bin <PATH>] [--data-dir <DIR>]
  shoes-panel info [--data-dir <DIR>]
  shoes-panel version",
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls ring provider before any TLS listener/client initialization
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shoes_panel=info,tower_http=warn".into()),
        )
        .init();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let subcmd = if args.first().is_some_and(|a| !a.starts_with('-')) {
        args.remove(0)
    } else {
        "serve".to_string()
    };

    if matches!(subcmd.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    if matches!(subcmd.as_str(), "version" | "--version" | "-V") {
        println!("shoes-panel {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let mut data_dir_arg: Option<String> = None;
    let mut username_arg: Option<String> = None;
    let mut password_arg: Option<String> = None;
    let mut port_arg: Option<u16> = None;
    let mut base_path_arg: Option<String> = None;
    let mut shoes_bin_arg: Option<String> = None;
    let mut public_host_arg: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" | "-d" if i + 1 < args.len() => {
                data_dir_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--username" | "-u" if i + 1 < args.len() => {
                username_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--password" | "-p" if i + 1 < args.len() => {
                password_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port_arg = args[i + 1].parse().ok();
                i += 2;
            }
            "--base-path" if i + 1 < args.len() => {
                base_path_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--shoes-bin" if i + 1 < args.len() => {
                shoes_bin_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--public-host" if i + 1 < args.len() => {
                public_host_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {
                i += 1;
            }
        }
    }

    let data_dir = resolve_data_dir(data_dir_arg);
    let db_path = data_dir.join("panel.db");
    let db = Arc::new(Database::open(&db_path, &data_dir)?);

    match subcmd.as_str() {
        "reset" => {
            let user = username_arg.unwrap_or_else(|| "admin".to_string());
            let pass = password_arg.unwrap_or_else(|| "admin".to_string());
            db.update_credentials(None, &user, &pass)?;
            println!("==========================================");
            println!("Credentials reset successfully!");
            println!("  Username : {user}");
            println!("  Password : {pass}");
            println!("==========================================");
            return Ok(());
        }
        "setting" => {
            let base_path = base_path_arg
                .as_deref()
                .map(validated_base_path)
                .transpose()?;
            if let Some(p) = port_arg {
                db.set_setting_kv("panel_port", &p.to_string())?;
                println!("Updated panel_port = {p}");
            }
            if let Some(norm) = base_path {
                db.set_setting_kv("panel_base_path", &norm)?;
                println!("Updated panel_base_path = {norm}");
            }
            if let Some(bin) = shoes_bin_arg {
                db.set_setting_kv("shoes_bin_path", &bin)?;
                println!("Updated shoes_bin_path = {bin}");
            }
            if let Some(ph) = public_host_arg {
                db.set_setting_kv("public_host", ph.trim())?;
                println!("Updated public_host = {}", ph.trim());
            }
            return Ok(());
        }
        "info" => {
            let s = db.get_settings()?;
            let u = db.get_admin_username()?;
            let scheme = s.scheme();
            let disp_host = if s.public_host.trim().is_empty() {
                "<auto>"
            } else {
                s.public_host.trim()
            };
            println!("==========================================");
            println!("shoes-panel current configuration:");
            println!("  Admin user   : {u}");
            println!("  Listen       : {}:{}", s.panel_listen, s.panel_port);
            println!("  Base path    : {}", s.panel_base_path);
            println!("  Public host  : {disp_host}");
            println!(
                "  URL          : {scheme}://{}:{}{}",
                if s.public_host.trim().is_empty() {
                    "127.0.0.1"
                } else {
                    s.public_host.trim()
                },
                s.panel_port,
                s.panel_base_path
            );
            println!("  shoes binary : {}", s.shoes_bin_path);
            println!("  shoes config : {}", s.shoes_config_path);
            println!("==========================================");
            return Ok(());
        }
        "serve" => {}
        other => {
            eprintln!("Unknown command: {other}");
            print_help();
            std::process::exit(1);
        }
    }

    if let Some(p) = port_arg {
        db.set_setting_kv("panel_port", &p.to_string())?;
    }
    if let Some(bin) = shoes_bin_arg {
        db.set_setting_kv("shoes_bin_path", &bin)?;
    }
    if let Some(ph) = public_host_arg {
        db.set_setting_kv("public_host", ph.trim())?;
    }

    let settings = db.get_settings()?;
    let addr = settings.listen_addr()?;
    let scheme = settings.scheme();
    let proc_mgr = ShoesProcessManager::new(db.clone());
    let monitor = RuntimeMonitor::new(db.clone(), proc_mgr.clone());
    let state = AppState::new(db.clone(), proc_mgr.clone(), monitor, &settings);

    // Ensure initial shoes.config.yaml is generated and optionally auto-start shoes
    if let Err(e) = proc_mgr.reload_config().await {
        tracing::warn!("Initial shoes config sync note: {e}");
    }
    if settings.shoes_auto_start && PathBuf::from(settings.shoes_bin_path.trim()).exists() {
        if let Err(e) = proc_mgr.start().await {
            tracing::warn!("shoes auto-start skipped/failed: {e}");
        }
    }

    let inner = build_inner_router(state.clone())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(16 * 1024 * 1024));

    // Dynamic base_path rewriting wrapper so changing panel_base_path works immediately!
    let dispatch_state = state.clone();
    let app = tower::service_fn(move |mut req: Request| {
        let inner = inner.clone();
        let st = dispatch_state.clone();
        async move {
            let path = req.uri().path().to_string();
            // Always allow public /sub/{token} at root regardless of panel_base_path
            if path
                .strip_prefix("/sub/")
                .is_some_and(|token| !token.is_empty() && !token.contains('/'))
            {
                return inner.oneshot(req).await;
            }
            let bp = st.get_base_path();
            if bp == "/" {
                return inner.oneshot(req).await;
            }
            if path == bp {
                let loc = match req.uri().query() {
                    Some(q) => format!("{bp}/?{q}"),
                    None => format!("{bp}/"),
                };
                return Ok::<Response, std::convert::Infallible>(
                    (StatusCode::FOUND, [(header::LOCATION, loc)]).into_response(),
                );
            }
            let prefix = format!("{bp}/");
            if let Some(stripped) = path.strip_prefix(&prefix) {
                let new_pq = match req.uri().query() {
                    Some(q) => format!("/{stripped}?{q}"),
                    None => format!("/{stripped}"),
                };
                if let Ok(new_uri) = new_pq.parse::<Uri>() {
                    *req.uri_mut() = new_uri;
                    return inner.oneshot(req).await;
                }
            }
            Ok((StatusCode::NOT_FOUND, "404 Not Found").into_response())
        }
    });

    tracing::info!(
        "shoes-panel listening on {}://{}{}",
        scheme,
        addr,
        state.get_base_path()
    );

    let make_svc = axum::routing::any_service(app);

    if scheme == "https" {
        let tls_cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            settings.panel_cert_file.trim(),
            settings.panel_key_file.trim(),
        )
        .await
        .context("failed to load panel TLS cert/key")?;

        axum_server::bind_rustls(addr, tls_cfg)
            .serve(make_svc.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, make_svc).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::default_client_for_inbound;
    use crate::models::*;

    #[tokio::test]
    async fn native_quic_generates_and_reuses_a_certificate() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        for (protocol, port) in [("tuic", 21000), ("hysteria2", 21001)] {
            let ib = db.create_inbound(serde_json::from_value(serde_json::json!({
                "protocol": protocol, "remark": protocol, "port": port
            }))?)?;
            assert!(ib.uses_auto_quic_cert());
        }
        let settings = db.get_settings()?;
        let yaml = yaml_gen::validated_config(&db, &settings).await?;
        let docs: Vec<serde_yaml::Value> = serde_yaml::from_str(&yaml)?;
        let cert = dir.path().join("certs/auto-quic/cert.pem");
        let pem = std::fs::read(&cert)?;
        let servers: Vec<_> = docs.iter().filter(|v| v["transport"] == "quic").collect();
        assert_eq!(servers.len(), 2);
        for server in servers {
            assert_eq!(PathBuf::from(server["quic_settings"]["cert"].as_str().unwrap()), cert);
            assert!(PathBuf::from(server["quic_settings"]["key"].as_str().unwrap()).is_file());
        }
        yaml_gen::validated_config(&db, &settings).await?;
        assert_eq!(std::fs::read(cert)?, pem);
        Ok(())
    }

    #[test]
    fn vmess_ws_without_tls_keeps_host_in_client_exports() -> anyhow::Result<()> {
        let ib: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "vmess", "remark": "ws", "port": 20000,
            "stream_settings": {"network": "ws", "security": "none",
                "ws": {"path": "/chat", "host": "ws.example.test"}},
            "clients": [{"name": "test", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?;
        let share = sub_gen::build_client_share_info(&ib, &ib.clients[0], "127.0.0.1");
        let doc: serde_yaml::Value = serde_yaml::from_str(&share.shoes_client_yaml)?;
        let protocol = &doc[0]["rules"][0]["client_chain"]["protocol"];
        assert_eq!(protocol["type"], "websocket");
        assert_eq!(protocol["matching_headers"]["Host"], "ws.example.test");
        assert_eq!(protocol["matching_path"], "/chat");
        let sub = sub_gen::generate_subscription(&[ib], "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson);
        let doc: serde_json::Value = serde_json::from_str(&sub.body)?;
        let node = doc["outbounds"].as_array().unwrap().iter().find(|v| v["type"] == "vmess").unwrap();
        assert_eq!(node["transport"]["headers"]["Host"], "ws.example.test");
        assert!(node.get("tls").is_none());
        Ok(())
    }

    #[test]
    fn xhttp_exports_preserve_handshake_fields() -> anyhow::Result<()> {
        let mut ib: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "vless", "remark": "node", "port": 21000,
            "stream_settings": {"network": "xhttp", "security": "tls",
                "xhttp": {"host": "edge.test", "path": "/data", "mode": "packet-up",
                    "headers": {"X-Route": "edge"}},
                "tls": {"alpn": ["h2"]}},
            "clients": [{"name": "user", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?;
        let share = sub_gen::build_client_share_info(&ib, &ib.clients[0], "localhost");
        let doc: serde_yaml::Value = serde_yaml::from_str(&share.shoes_client_yaml)?;
        let tls = &doc[0]["rules"][0]["client_chain"]["protocol"];
        assert_eq!(tls["alpn_protocols"][0], "h2");
        let xhttp = &tls["protocol"];
        assert_eq!(xhttp["host"], "edge.test");
        assert_eq!(xhttp["headers"]["X-Route"], "edge");
        assert_eq!(xhttp["path"], "/data");
        assert_eq!(xhttp["mode"], "packet-up");
        assert!(share.uri.contains("extra="));
        let clash = sub_gen::generate_subscription(std::slice::from_ref(&ib), "*", "localhost", sub_gen::SubFormat::ClashYaml);
        let doc: serde_yaml::Value = serde_yaml::from_str(&clash.body)?;
        assert_eq!(doc["proxies"][0]["xhttp-opts"]["headers"]["X-Route"], "edge");

        ib.protocol = "shadowsocks".into();
        assert!(sub_gen::build_uri(&ib, &ib.clients[0], "localhost", "node").is_empty());
        let clash = sub_gen::generate_subscription(&[ib], "*", "localhost", sub_gen::SubFormat::ClashYaml);
        let doc: serde_yaml::Value = serde_yaml::from_str(&clash.body)?;
        assert!(doc["proxies"].as_sequence().unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn invalid_reality_dest_is_rejected_before_start() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("test.db"), dir.path())?;
        let mut ib: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "vless", "remark": "node", "port": 21000,
            "stream_settings": {"network": "tcp", "security": "reality",
                "reality": {"sni": "localhost", "private_key": "test"}},
            "clients": [{"name": "user"}]
        }))?;
        for dest in ["127.0.0.1:443", "[::1]:443"] {
            ib.stream_settings.reality.dest = dest.into();
            let result = yaml_gen::build_shoes_yaml(dir.path(), &db.get_settings()?, &[], &[], &[], std::slice::from_ref(&ib));
            assert!(format!("{:#}", result.unwrap_err()).contains("DNS hostname"));
        }
        Ok(())
    }

    #[test]
    fn backup_contains_committed_wal_pages() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(&tmp.path().join("live.db"), tmp.path()).unwrap();
        db.set_setting_kv("public_host", "updated.example").unwrap();

        let backup = tmp.path().join("download.db");
        std::fs::write(&backup, db.backup_snapshot().unwrap()).unwrap();
        let copy = rusqlite::Connection::open(&backup).unwrap();
        let integrity: String = copy
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let host: String = copy
            .query_row(
                "SELECT value FROM settings WHERE key = 'public_host'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(host, "updated.example");
    }

    #[test]
    fn reserved_paths_and_ipv6_listener() {
        for path in ["/sub", "sub/", "/sub/team"] {
            assert!(validated_base_path(path).is_err());
        }
        assert_eq!(
            validated_base_path("sub-panel/team/").unwrap(),
            "/sub-panel/team"
        );
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(&tmp.path().join("test.db"), tmp.path()).unwrap();
        let mut s = db.get_settings().unwrap();
        s.panel_port = 54321;
        for host in ["::1", "[::1]"] {
            s.panel_listen = host.into();
            assert_eq!(s.listen_addr().unwrap().to_string(), "[::1]:54321");
        }
        s.panel_cert_file = "cert.pem".into();
        assert_eq!(s.scheme(), "http");
        s.panel_key_file = "key.pem".into();
        assert_eq!(s.scheme(), "https");
    }

    #[tokio::test]
    async fn failed_settings_save_preserves_database_and_config() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("panel.db");
        let db = Arc::new(Database::open(&file, tmp.path()).unwrap());
        db.set_setting_kv(
            "shoes_bin_path",
            tmp.path().join("absent").to_str().unwrap(),
        )
        .unwrap();
        let manager = ShoesProcessManager::new(db.clone());
        let initial = db.get_settings().unwrap();
        manager.apply_settings(&initial).await.unwrap();
        let old_yaml = std::fs::read(&initial.shoes_config_path).unwrap();

        let mut candidate = initial.clone();
        candidate.panel_base_path = "/new".into();
        candidate.shoes_extra_yaml = "- [".into();
        assert!(manager.apply_settings(&candidate).await.is_err());
        assert_eq!(std::fs::read(&initial.shoes_config_path).unwrap(), old_yaml);
        assert_eq!(
            db.get_settings().unwrap().panel_base_path,
            initial.panel_base_path
        );

        // A late database error must also roll back the previously written YAML.
        rusqlite::Connection::open(file)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_save BEFORE UPDATE ON settings WHEN NEW.key='public_host'
             BEGIN SELECT RAISE(ABORT, 'simulated save failure'); END;",
            )
            .unwrap();
        candidate.shoes_extra_yaml = "- global_settings: {}".into();
        assert!(manager.apply_settings(&candidate).await.is_err());
        assert_eq!(std::fs::read(&initial.shoes_config_path).unwrap(), old_yaml);
        assert_eq!(
            db.get_settings().unwrap().panel_base_path,
            initial.panel_base_path
        );
    }

    #[test]
    fn test_yaml_and_subscription_generation_all_protocols() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(&tmp.path().join("test.db"), tmp.path()).unwrap();

        // Create self-signed cert source for TLS/QUIC protocols
        let (cert_pem, key_pem) =
            crypto_util::generate_self_signed_cert(&["example.com".to_string()]).unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        db.save_certificate(CertificateRecord {
            id: 0,
            name: "main-cert".to_string(),
            cert_type: "files".to_string(),
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            domains: vec!["example.com".to_string()],
            email: String::new(),
            directory_url: String::new(),
            terms_of_service: String::new(),
            challenge_type: "http01".to_string(),
            http01_listen: String::new(),
            remark: "test".to_string(),
            created_at: 0,
        })
        .unwrap();

        let (priv_k, pub_k) = crypto_util::generate_reality_keypair();

        // 1. VLESS + Reality + Vision
        let mut vless_ib = Inbound {
            id: 0,
            tag: String::new(),
            remark: "VLESS-Reality".to_string(),
            enable: true,
            listen: "0.0.0.0".to_string(),
            port: 20443,
            protocol: "vless".to_string(),
            protocol_settings: ProtocolSettings::default(),
            stream_settings: StreamSettings {
                network: "tcp".to_string(),
                security: "reality".to_string(),
                reality: RealitySettings {
                    sni: "www.microsoft.com".to_string(),
                    dest: "www.microsoft.com:443".to_string(),
                    private_key: priv_k,
                    public_key: pub_k,
                    short_ids: vec!["0123456789abcdef".to_string()],
                    vision: true,
                    fingerprint: "chrome".to_string(),
                    mldsa65_seed: String::new(),
                    mldsa65_verify: String::new(),
                },
                ..Default::default()
            },
            up_bytes: 0,
            down_bytes: 0,
            total_quota_bytes: 10 * 1024 * 1024 * 1024,
            expiry_time: 0,
            auto_reset_day: 0,
            last_reset_month: String::new(),
            created_at: 0,
            updated_at: 0,
            clients: Vec::new(),
        };
        vless_ib = db.create_inbound(vless_ib).unwrap();
        assert_eq!(vless_ib.clients.len(), 1);

        // 2. Hysteria2 QUIC
        let mut hy2_ib = vless_ib.clone();
        hy2_ib.id = 0;
        hy2_ib.remark = "Hy2-Node".to_string();
        hy2_ib.port = 20843;
        hy2_ib.protocol = "hysteria2".to_string();
        hy2_ib.stream_settings = StreamSettings {
            network: "quic".to_string(),
            security: "tls".to_string(),
            tls: TlsSettings {
                sni: "example.com".to_string(),
                cert_mode: "source".to_string(),
                certificate_source: "main-cert".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        hy2_ib.clients.clear();
        db.create_inbound(hy2_ib).unwrap();

        // 3. AnyTLS Multi-User
        let mut anytls_ib = vless_ib.clone();
        anytls_ib.id = 0;
        anytls_ib.remark = "AnyTLS-Multi".to_string();
        anytls_ib.port = 20943;
        anytls_ib.protocol = "anytls".to_string();
        anytls_ib.stream_settings = StreamSettings {
            network: "tcp".to_string(),
            security: "tls".to_string(),
            tls: TlsSettings {
                sni: "example.com".to_string(),
                cert_mode: "source".to_string(),
                certificate_source: "main-cert".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        anytls_ib.clients.clear();
        let anytls_created = db.create_inbound(anytls_ib).unwrap();
        let mut second_user = default_client_for_inbound(&anytls_created, 2);
        second_user.name = "bob".to_string();
        let anytls_multi = db.add_client(anytls_created.id, second_user).unwrap();
        assert_eq!(anytls_multi.clients.len(), 2);

        let settings = db.get_settings().unwrap();
        let certs = db.list_certificates().unwrap();
        let groups = db.list_outbound_groups().unwrap();
        let rules = db.list_routing_rules().unwrap();
        let inbounds = db.list_inbounds().unwrap();

        let yaml =
            yaml_gen::build_shoes_yaml(tmp.path(), &settings, &certs, &groups, &rules, &inbounds)
                .unwrap();
        assert!(yaml.contains("reality_targets"));
        assert!(yaml.contains("hysteria2"));
        assert!(yaml.contains("anytls"));

        let clash_sub = sub_gen::generate_subscription(
            &inbounds,
            "default",
            "203.0.113.88",
            sub_gen::SubFormat::ClashYaml,
        );
        assert!(clash_sub.body.contains("VLESS-Reality"));
        assert!(clash_sub.body.contains("Hy2-Node"));
        assert!(clash_sub.body.contains("server: 203.0.113.88"));
        assert!(!clash_sub.body.contains("GEOIP,LAN"));
        assert!(clash_sub.body.contains("short-id: '0123456789abcdef'"));

        // Verify Shadowrocket / standard URI never percent-encodes '-', '_', '.' in UUID, pbk, or sni
        let raw_sub = sub_gen::generate_subscription(
            &inbounds,
            "default",
            "203.0.113.88",
            sub_gen::SubFormat::RawUris,
        );
        let vless_uri = raw_sub
            .body
            .lines()
            .find(|l| l.starts_with("vless://"))
            .expect("vless URI missing");
        let user_part = vless_uri
            .strip_prefix("vless://")
            .unwrap()
            .split('@')
            .next()
            .unwrap();
        assert_eq!(
            user_part.len(),
            36,
            "VLESS UUID must be raw 36-char UUID, got: {vless_uri}"
        );
        assert!(
            !user_part.contains('%'),
            "VLESS UUID must not contain percent-encoding: {vless_uri}"
        );
        assert!(
            vless_uri.contains("sni=www.microsoft.com"),
            "SNI dots must not be percent-encoded: {vless_uri}"
        );
        assert!(
            !vless_uri.contains("%5F") && !vless_uri.contains("%2D"),
            "pbk/UUID must not encode '-' or '_': {vless_uri}"
        );

        let sb_sub = sub_gen::generate_subscription(
            &inbounds,
            "default",
            "proxy.example.com",
            sub_gen::SubFormat::SingBoxJson,
        );
        assert!(sb_sub.body.contains("\"type\": \"vless\""));

        // 4. Validate comprehensive multi-protocol YAML with real `shoes check` if shoes binary exists
        let shoes_bin = [
            PathBuf::from("./shoes/target/debug/shoes.exe"),
            PathBuf::from("./shoes/target/release/shoes.exe"),
            PathBuf::from("../shoes/target/debug/shoes.exe"),
        ]
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("./shoes/target/debug/shoes.exe"));
        if shoes_bin.exists() {
            for (port, proto, net, sec, cipher) in [
                (21001u16, "vmess", "ws", "tls", "aes-128-gcm"),
                (21002u16, "trojan", "tcp", "tls", ""),
                (21003u16, "shadowsocks", "tcp", "none", "2022-blake3-aes-256-gcm"),
                (21004u16, "tuic", "quic", "tls", ""),
                (21005u16, "naiveproxy", "tcp", "tls", ""),
                (21006u16, "snell", "tcp", "none", "chacha20-ietf-poly1305"),
                (21007u16, "socks", "tcp", "none", ""),
                (21008u16, "http", "tcp", "none", ""),
                (21009u16, "mixed", "tcp", "none", ""),
                (21010u16, "vless", "xhttp", "tls", ""),
            ] {
                let mut ib = vless_ib.clone();
                ib.id = 0;
                ib.remark = format!("test-{proto}");
                ib.port = port;
                ib.protocol = proto.to_string();
                ib.protocol_settings.cipher = cipher.to_string();
                ib.stream_settings = StreamSettings {
                    network: net.to_string(),
                    security: sec.to_string(),
                    tls: TlsSettings {
                        sni: "example.com".to_string(),
                        allow_any_sni: true,
                        cert_mode: "source".to_string(),
                        certificate_source: "main-cert".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                ib.clients.clear();
                db.create_inbound(ib).unwrap();
            }

            db.save_outbound_group(OutboundGroupRecord {
                id: 0,
                name: "upstream-sel".to_string(),
                enable: true,
                group_type: "selector".to_string(),
                default_member: "edge-1".to_string(),
                test_url: "https://www.gstatic.com/generate_204".to_string(),
                interval_secs: 300,
                timeout_ms: 5000,
                tolerance_ms: 50,
                members: vec![OutboundMember {
                    name: "edge-1".to_string(),
                    protocol: "socks".to_string(),
                    address: "198.51.100.10:1080".to_string(),
                    uuid: String::new(),
                    username: String::new(),
                    password: String::new(),
                    cipher: String::new(),
                    tls: false,
                    sni: String::new(),
                    verify: true,
                }],
                raw_chains_yaml: String::new(),
                remark: String::new(),
            })
            .unwrap();

            db.save_routing_rule(RoutingRuleRecord {
                id: 0,
                priority: 10,
                enable: true,
                remark: "block-lan".to_string(),
                match_type: "masks".to_string(),
                match_value: "10.0.0.0/8, 192.168.0.0/16".to_string(),
                action: "block".to_string(),
                outbound: "direct".to_string(),
            })
            .unwrap();

            let full_yaml = yaml_gen::build_shoes_yaml(
                tmp.path(),
                &db.get_settings().unwrap(),
                &db.list_certificates().unwrap(),
                &db.list_outbound_groups().unwrap(),
                &db.list_routing_rules().unwrap(),
                &db.list_inbounds().unwrap(),
            )
            .unwrap();
            let yaml_path = tmp.path().join("all_protocols.yaml");
            std::fs::write(&yaml_path, &full_yaml).unwrap();

            let out = std::process::Command::new(&shoes_bin)
                .arg("check")
                .arg(&yaml_path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "shoes check failed!\nstdout: {}\nstderr: {}\nYAML:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                full_yaml
            );
        }
    }

    #[test]
    fn subscription_client_compatibility_matrix_rules() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (cert_pem, key_pem) = crypto_util::generate_self_signed_cert(&["localhost".to_string()])?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, &key_pem)?;
        let certs = vec![CertificateRecord {
            id: 1,
            name: "self".into(),
            cert_type: "files".into(),
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            domains: vec!["localhost".into()],
            email: String::new(),
            directory_url: String::new(),
            terms_of_service: String::new(),
            challenge_type: "http01".into(),
            http01_listen: String::new(),
            remark: String::new(),
            created_at: 0,
        }];
        let (priv_k, pub_k) = crypto_util::generate_reality_keypair();
        let make_ib = |v: serde_json::Value| -> Inbound { serde_json::from_value(v).unwrap() };

        // 1. Mihomo omits WS+Reality & AnyTLS+Reality, while sing-box exports them
        for (proto, net) in [("vless", "ws"), ("vmess", "ws"), ("trojan", "ws"), ("anytls", "tcp")] {
            let ib = make_ib(serde_json::json!({
                "protocol": proto, "remark": format!("{proto}-{net}-r"), "port": 22000,
                "stream_settings": {
                    "network": net, "security": "reality",
                    "reality": {"sni": "localhost", "dest": "localhost:443", "private_key": priv_k, "public_key": pub_k, "short_ids": ["01234567"]}
                },
                "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d", "password": "pw"}]
            }));
            let clash = sub_gen::generate_subscription_with_certs(std::slice::from_ref(&ib), &certs, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml);
            let clash_doc: serde_yaml::Value = serde_yaml::from_str(&clash.body)?;
            assert!(clash_doc["proxies"].as_sequence().unwrap().is_empty(), "Mihomo should omit {proto}+{net}+reality");

            let sb = sub_gen::generate_subscription_with_certs(&[ib], &certs, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson);
            let sb_doc: serde_json::Value = serde_json::from_str(&sb.body)?;
            assert!(sb_doc["outbounds"].as_array().unwrap().iter().any(|o| o["type"] == proto), "sing-box should export {proto}+{net}+reality");
        }

        // 2. Snell ciphers: default/aes-128-gcm -> Mihomo v3, chacha20-ietf-poly1305 -> Mihomo v1, aes-256-gcm -> omitted
        for (cipher, expected_ver) in [("", Some(3)), ("aes-128-gcm", Some(3)), ("chacha20-ietf-poly1305", Some(1)), ("aes-256-gcm", None)] {
            let ib = make_ib(serde_json::json!({
                "protocol": "snell", "remark": "sn", "port": 22001,
                "protocol_settings": {"cipher": cipher},
                "clients": [{"name": "u", "password": "pw"}]
            }));
            let clash = sub_gen::generate_subscription_with_certs(&[ib], &certs, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml);
            let clash_doc: serde_yaml::Value = serde_yaml::from_str(&clash.body)?;
            let proxies = clash_doc["proxies"].as_sequence().unwrap();
            match expected_ver {
                Some(v) => assert_eq!(proxies[0]["version"].as_u64(), Some(v), "snell cipher={cipher}"),
                None => assert!(proxies.is_empty(), "snell aes-256-gcm must be omitted from Mihomo"),
            }
        }

        // 3. VMess cipher=none omitted from both Mihomo & sing-box (sing-vmess incompatibility with shoes)
        let vmess_none = make_ib(serde_json::json!({
            "protocol": "vmess", "remark": "vm-none", "port": 22002,
            "protocol_settings": {"cipher": "none"},
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }));
        let c_vm = sub_gen::generate_subscription_with_certs(std::slice::from_ref(&vmess_none), &certs, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml);
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&c_vm.body)?["proxies"].as_sequence().unwrap().is_empty());
        let s_vm = sub_gen::generate_subscription_with_certs(&[vmess_none], &certs, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson);
        assert!(!serde_json::from_str::<serde_json::Value>(&s_vm.body)?["outbounds"].as_array().unwrap().iter().any(|o| o["type"] == "vmess"));

        // 4. Newly exported: SS+WS (Mihomo none/tls + sing-box none), VLESS+QUIC (sing-box), NaiveProxy+TLS (sing-box with cert)
        let ss_ws_none = make_ib(serde_json::json!({
            "protocol": "shadowsocks", "remark": "ss-ws", "port": 22003,
            "protocol_settings": {"cipher": "aes-256-gcm"},
            "stream_settings": {"network": "ws", "security": "none", "ws": {"path": "/ws", "host": "ws.test"}},
            "clients": [{"name": "u", "password": "pw"}]
        }));
        let c_ss = serde_yaml::from_str::<serde_yaml::Value>(&sub_gen::generate_subscription_with_certs(std::slice::from_ref(&ss_ws_none), &certs, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml).body)?;
        assert_eq!(c_ss["proxies"][0]["plugin"], "v2ray-plugin");
        assert_eq!(c_ss["proxies"][0]["plugin-opts"]["mux"], false);
        let s_ss = serde_json::from_str::<serde_json::Value>(&sub_gen::generate_subscription_with_certs(&[ss_ws_none], &certs, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson).body)?;
        let s_ss_node = s_ss["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "shadowsocks").unwrap();
        assert_eq!(s_ss_node["plugin"], "v2ray-plugin");
        assert!(s_ss_node["plugin_opts"].as_str().unwrap().contains("mux=0"));

        let vless_quic = make_ib(serde_json::json!({
            "protocol": "vless", "remark": "vl-quic", "port": 22004,
            "stream_settings": {"network": "quic", "security": "tls", "tls": {"sni": "localhost", "allow_insecure": true}},
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }));
        let s_vq = serde_json::from_str::<serde_json::Value>(&sub_gen::generate_subscription_with_certs(&[vless_quic], &certs, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson).body)?;
        let s_vq_node = s_vq["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "vless").unwrap();
        assert_eq!(s_vq_node["transport"]["type"], "quic");

        let naive_tls = make_ib(serde_json::json!({
            "protocol": "naiveproxy", "remark": "nv-tls", "port": 22005,
            "stream_settings": {"network": "tcp", "security": "tls", "tls": {"cert_mode": "source", "certificate_source": "self", "sni": "localhost", "allow_insecure": true}},
            "clients": [{"name": "u", "username": "u", "password": "pw"}]
        }));
        let s_nv = serde_json::from_str::<serde_json::Value>(&sub_gen::generate_subscription_with_certs(&[naive_tls], &certs, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson).body)?;
        let s_nv_node = s_nv["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "naive").unwrap();
        assert!(s_nv_node["tls"]["certificate"][0].as_str().unwrap().contains("BEGIN CERTIFICATE"));
        assert!(s_nv_node["tls"].get("insecure").is_none());

        Ok(())
    }
}
