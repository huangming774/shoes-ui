mod acme_util;
mod api;
mod auth;
mod crypto_util;
mod db;
mod models;
mod monitor;
mod ops_util;
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
  shoes-panel reset [--username <USER>] [--password <PASS>] [--random] [--data-dir <DIR>]
  shoes-panel setting [--port <PORT>] [--base-path <PATH>] [--shoes-bin <PATH>] [--public-host <HOST>] [--data-dir <DIR>]
  shoes-panel cert ip [--ip <IP>] [--email <EMAIL>] [--listen <ADDR>] [--staging] [--panel-https] [--data-dir <DIR>]
  shoes-panel cert self-signed [--ip <IP>] [--panel-https] [--data-dir <DIR>]
  shoes-panel cert clear [--data-dir <DIR>]
  shoes-panel backup [--data-dir <DIR>]
  shoes-panel restore <BACKUP_DB_FILE> [--data-dir <DIR>]
  shoes-panel info [--data-dir <DIR>]
  shoes-panel version",
        env!("CARGO_PKG_VERSION")
    );
}

async fn detect_public_ip_cli() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .no_proxy()
        .build()
        .ok()?;
    for url in [
        "https://4.ipw.cn",
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://6.ipw.cn",
    ] {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    let cand = txt.trim();
                    if let Ok(ip) = cand.parse::<std::net::IpAddr>() {
                        if acme_util::is_globally_routable_ip(ip) {
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

async fn run_cert_cli(db: &Database, args: &[String]) -> Result<()> {
    let action = args
        .first()
        .map(String::as_str)
        .unwrap_or("help");
    if matches!(action, "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }

    let mut ips: Vec<String> = Vec::new();
    let mut email = String::new();
    let mut listen = "0.0.0.0:80".to_string();
    let mut directory_url = crate::models::DEFAULT_LETSENCRYPT_DIR.to_string();
    let mut name_arg: Option<String> = None;
    let mut panel_https = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ip" if i + 1 < args.len() => {
                for part in args[i + 1].split([',', ' ']) {
                    let t = part.trim();
                    if !t.is_empty() {
                        ips.push(t.to_string());
                    }
                }
                i += 2;
            }
            "--email" if i + 1 < args.len() => {
                email = args[i + 1].trim().to_string();
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen = args[i + 1].trim().to_string();
                i += 2;
            }
            "--directory" if i + 1 < args.len() => {
                directory_url = args[i + 1].trim().to_string();
                i += 2;
            }
            "--staging" => {
                directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
                i += 1;
            }
            "--name" if i + 1 < args.len() => {
                name_arg = Some(args[i + 1].trim().to_string());
                i += 2;
            }
            "--panel-https" => {
                panel_https = true;
                i += 1;
            }
            "--data-dir" | "-d" if i + 1 < args.len() => {
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    match action {
        "ip" => {
            if ips.is_empty() {
                if let Ok(s) = db.get_settings() {
                    let ph = s.public_host.trim().trim_matches(['[', ']']);
                    if ph.parse::<std::net::IpAddr>().is_ok() {
                        ips.push(ph.to_string());
                    }
                }
            }
            if ips.is_empty() {
                if let Some(detected) = detect_public_ip_cli().await {
                    ips.push(detected);
                }
            }
            if ips.is_empty() {
                anyhow::bail!("Could not determine server public IP; pass --ip <PUBLIC_IP>");
            }

            let safe_name = acme_util::sanitize_cert_filename(
                name_arg.as_deref().unwrap_or("panel-ip-ssl"),
            );
            let issued = acme_util::issue_shortlived_ip_cert(
                &db.data_dir,
                &safe_name,
                &ips,
                &email,
                &directory_url,
                &listen,
            )
            .await?;

            let cert_dir = db.data_dir.join("certs");
            let cert_path = cert_dir.join(format!("{safe_name}.crt"));
            let key_path = cert_dir.join(format!("{safe_name}.key"));
            acme_util::write_cert_and_key_atomic(
                &cert_path,
                &key_path,
                &issued.cert_pem,
                &issued.key_pem,
            )?;

            let cert_str = cert_path.to_string_lossy().replace('\\', "/");
            let key_str = key_path.to_string_lossy().replace('\\', "/");
            let existing_id = db
                .list_certificates()?
                .into_iter()
                .find(|c| c.name == safe_name)
                .map(|c| c.id)
                .unwrap_or(0);

            db.save_certificate(crate::models::CertificateRecord {
                id: existing_id,
                name: safe_name.clone(),
                cert_type: "acme_ip".to_string(),
                cert_file: cert_str.clone(),
                key_file: key_str.clone(),
                domains: if issued.info.sans.is_empty() {
                    ips.clone()
                } else {
                    issued.info.sans.clone()
                },
                email,
                directory_url,
                terms_of_service: issued.terms_of_service,
                challenge_type: "http01".to_string(),
                http01_listen: listen,
                remark: "Let's Encrypt IP SSL (shortlived 6d auto-renew)".to_string(),
                created_at: 0,
            })?;

            if panel_https {
                db.set_setting_kv("panel_cert_file", &cert_str)?;
                db.set_setting_kv("panel_key_file", &key_str)?;
            }

            println!("==========================================");
            println!("Free Let's Encrypt IP SSL issued successfully!");
            println!("  Source Name : {safe_name}");
            println!("  IP SANs     : {}", issued.info.sans.join(", "));
            println!("  Cert File   : {cert_str}");
            println!("  Key File    : {key_str}");
            println!("  Panel HTTPS : {}", if panel_https { "ENABLED" } else { "unchanged" });
            println!("==========================================");
            Ok(())
        }
        "self-signed" => {
            if ips.is_empty() {
                if let Ok(s) = db.get_settings() {
                    let ph = s.public_host.trim();
                    if !ph.is_empty() && !crate::state::is_loopback_or_unspecified_host(ph) {
                        ips.push(ph.to_string());
                    }
                }
            }
            if !ips.iter().any(|s| s == "localhost") {
                ips.push("localhost".to_string());
            }
            if !ips.iter().any(|s| s == "127.0.0.1") {
                ips.push("127.0.0.1".to_string());
            }

            let safe_name = acme_util::sanitize_cert_filename(
                name_arg.as_deref().unwrap_or("panel-self-ssl"),
            );
            let (cert_pem, key_pem) = crate::crypto_util::generate_self_signed_cert(&ips)?;
            let cert_dir = db.data_dir.join("certs");
            let cert_path = cert_dir.join(format!("{safe_name}.crt"));
            let key_path = cert_dir.join(format!("{safe_name}.key"));
            acme_util::write_cert_and_key_atomic(&cert_path, &key_path, &cert_pem, &key_pem)?;

            let cert_str = cert_path.to_string_lossy().replace('\\', "/");
            let key_str = key_path.to_string_lossy().replace('\\', "/");
            let existing_id = db
                .list_certificates()?
                .into_iter()
                .find(|c| c.name == safe_name)
                .map(|c| c.id)
                .unwrap_or(0);

            db.save_certificate(crate::models::CertificateRecord {
                id: existing_id,
                name: safe_name.clone(),
                cert_type: "files".to_string(),
                cert_file: cert_str.clone(),
                key_file: key_str.clone(),
                domains: ips.clone(),
                email: String::new(),
                directory_url: String::new(),
                terms_of_service: String::new(),
                challenge_type: "http01".to_string(),
                http01_listen: String::new(),
                remark: "Self-Signed IP SSL (180d)".to_string(),
                created_at: 0,
            })?;

            if panel_https {
                db.set_setting_kv("panel_cert_file", &cert_str)?;
                db.set_setting_kv("panel_key_file", &key_str)?;
            }

            println!("==========================================");
            println!("Self-signed IP SSL certificate generated!");
            println!("  Source Name : {safe_name}");
            println!("  SANs        : {}", ips.join(", "));
            println!("  Cert File   : {cert_str}");
            println!("  Key File    : {key_str}");
            println!("  Panel HTTPS : {}", if panel_https { "ENABLED" } else { "unchanged" });
            println!("==========================================");
            Ok(())
        }
        "clear" => {
            db.set_setting_kv("panel_cert_file", "")?;
            db.set_setting_kv("panel_key_file", "")?;
            println!("Cleared Panel HTTPS certificate settings (panel will serve HTTP after restart).");
            Ok(())
        }
        other => anyhow::bail!("Unknown cert subcommand '{other}' (expected: ip, self-signed, clear)"),
    }
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
    let mut random_creds = false;
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
            "--random" => {
                random_creds = true;
                i += 1;
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
        "cert" => {
            run_cert_cli(&db, &args).await?;
            return Ok(());
        }
        "backup" => {
            let (entry, _) = ops_util::create_local_backup(&db, "cli", None)?;
            let full_path = ops_util::backups_dir(&db.data_dir).join(&entry.filename);
            println!("Backup saved: {} ({} bytes)", full_path.display(), entry.size_bytes);
            return Ok(());
        }
        "restore" => {
            let file_arg = args
                .iter()
                .find(|a| !a.starts_with('-'))
                .ok_or_else(|| anyhow::anyhow!("Usage: shoes-panel restore <BACKUP_DB_FILE> [--data-dir <DIR>]"))?;
            let bytes = std::fs::read(file_arg)
                .with_context(|| format!("Cannot read backup file '{file_arg}'"))?;
            let pre_backup = db.restore_from_bytes(&bytes)?;
            println!("Database restored successfully from {file_arg}!");
            println!("Safety pre-restore snapshot saved as backups/{pre_backup}");
            return Ok(());
        }
        "reset" => {
            let user = username_arg.unwrap_or_else(|| {
                if random_creds {
                    crypto_util::generate_random_alnum(8).to_lowercase()
                } else {
                    "admin".to_string()
                }
            });
            let pass = password_arg.unwrap_or_else(|| {
                if random_creds {
                    crypto_util::generate_random_alnum(12)
                } else {
                    "admin".to_string()
                }
            });
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
            let url_host_raw = if s.public_host.trim().is_empty() {
                "127.0.0.1"
            } else {
                s.public_host.trim()
            };
            let url_host = if url_host_raw.contains(':') && !url_host_raw.starts_with('[') {
                format!("[{url_host_raw}]")
            } else {
                url_host_raw.to_string()
            };
            println!("==========================================");
            println!("shoes-panel current configuration:");
            println!("  Admin user   : {u}");
            println!("  Scheme       : {scheme}");
            println!("  Listen       : {}:{}", s.panel_listen, s.panel_port);
            println!("  Base path    : {}", s.panel_base_path);
            println!("  Public host  : {disp_host}");
            println!(
                "  SSL Cert     : {}",
                if s.panel_cert_file.trim().is_empty() {
                    "(disabled / HTTP)"
                } else {
                    s.panel_cert_file.trim()
                }
            );
            println!("  URL          : {scheme}://{url_host}:{}{}", s.panel_port, s.panel_base_path);
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
    acme_util::spawn_cert_maintenance_loop(state.clone());
    ops_util::spawn_auto_backup_loop(state.clone());
    ops_util::spawn_rule_source_loop(state.clone());

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
        state.set_panel_tls_config(tls_cfg.clone());

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
                    h2mux: Default::default(),
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
                    ..Default::default()
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
                ..Default::default()
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

    #[tokio::test]
    async fn x509_der_inspector_and_validation_rules() -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem) = crypto_util::generate_self_signed_cert(&[
            "node.example.test".to_string(),
            "1.1.1.1".to_string(),
            "2606:4700:4700::1111".to_string(),
        ])?;
        let info = acme_util::validate_cert_key_pair(&cert_pem, &key_pem).await?;
        assert!(info.is_self_signed);
        assert!(info.sans.iter().any(|s| s == "node.example.test"));
        assert!(info.sans.iter().any(|s| s == "1.1.1.1"));
        assert!(info.sans.iter().any(|s| s == "2606:4700:4700::1111"));
        let days = (info.not_after - info.not_before) / 86400;
        assert!((178..=182).contains(&days), "expected ~180d validity, got {days}d");

        // Mismatched key must be rejected
        let (_, other_key) = crypto_util::generate_self_signed_cert(&["other.test".to_string()])?;
        assert!(acme_util::validate_cert_key_pair(&cert_pem, &other_key).await.is_err());

        // Public IP validation rejects private/loopback/documentation IPs, accepts public IPv4/IPv6
        assert!(acme_util::parse_and_validate_ip_targets(&["127.0.0.1".into()], false).is_err());
        assert!(acme_util::parse_and_validate_ip_targets(&["192.168.1.10".into()], false).is_err());
        assert!(acme_util::parse_and_validate_ip_targets(&["10.0.0.1".into()], false).is_err());
        assert!(acme_util::parse_and_validate_ip_targets(&["100.64.0.1".into()], false).is_err());
        assert!(acme_util::parse_and_validate_ip_targets(&["203.0.113.10".into()], false).is_err());
        assert!(acme_util::parse_and_validate_ip_targets(&["fd00::1".into()], false).is_err());
        let ok_ips = acme_util::parse_and_validate_ip_targets(
            &["1.1.1.1".into(), "[2606:4700:4700::1111]".into()],
            false,
        )?;
        assert_eq!(ok_ips.len(), 2);

        // Domain ACME normalization lowercases, deduplicates, and rejects IPs/wildcards
        let norm = yaml_gen::normalize_acme_domains(&[
            "Proxy.Example.COM.".into(),
            "proxy.example.com".into(),
        ])?;
        assert_eq!(norm, vec!["proxy.example.com"]);
        assert!(yaml_gen::normalize_acme_domains(&["1.1.1.1".into()]).is_err());
        assert!(yaml_gen::normalize_acme_domains(&["*.example.com".into()]).is_err());

        // Distinct directory or domain produces distinct state_dir hash
        let tmp = tempfile::tempdir()?;
        let s1 = yaml_gen::acme_state_dir(tmp.path(), "main", "https://acme-staging-v02.api.letsencrypt.org/directory", &["a.example.com".into()]);
        let s2 = yaml_gen::acme_state_dir(tmp.path(), "main", "https://acme-v02.api.letsencrypt.org/directory", &["a.example.com".into()]);
        let s3 = yaml_gen::acme_state_dir(tmp.path(), "main", "https://acme-v02.api.letsencrypt.org/directory", &["b.example.com".into()]);
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        Ok(())
    }

    struct MockAcmeState {
        base_url: String,
        http01_port: u16,
        ca_cert: rcgen::Certificate,
        ca_key: rcgen::KeyPair,
        jwk_thumbprint: parking_lot::Mutex<Option<String>>,
        order_identifiers: parking_lot::Mutex<Vec<serde_json::Value>>,
        order_profile: parking_lot::Mutex<Option<String>>,
        authz_valid: std::sync::atomic::AtomicBool,
        http01_verified: std::sync::atomic::AtomicBool,
        issued_chain_pem: parking_lot::Mutex<Option<String>>,
        nonce_seq: std::sync::atomic::AtomicU64,
        cert_days: i64,
    }

    impl MockAcmeState {
        fn next_nonce(&self) -> String {
            let n = self.nonce_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            format!("mock-nonce-{n}")
        }
    }

    async fn spawn_mock_acme_ca(
        http01_port: u16,
        cert_days: i64,
    ) -> anyhow::Result<(String, Arc<MockAcmeState>, tokio::task::JoinHandle<()>)> {
        use axum::{
            extract::State as AState,
            http::{header, StatusCode},
            response::IntoResponse,
            routing::{get, head, post},
            Router,
        };
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use chrono::Datelike;

        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, "Shoes Panel Test ACME Root CA");
        ca_params.distinguished_name = ca_dn;
        let ca_key = rcgen::KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base_url = format!("http://127.0.0.1:{port}");

        let state = Arc::new(MockAcmeState {
            base_url: base_url.clone(),
            http01_port,
            ca_cert,
            ca_key,
            jwk_thumbprint: parking_lot::Mutex::new(None),
            order_identifiers: parking_lot::Mutex::new(Vec::new()),
            order_profile: parking_lot::Mutex::new(None),
            authz_valid: std::sync::atomic::AtomicBool::new(false),
            http01_verified: std::sync::atomic::AtomicBool::new(false),
            issued_chain_pem: parking_lot::Mutex::new(None),
            nonce_seq: std::sync::atomic::AtomicU64::new(0),
            cert_days,
        });

        let decode_jws = |body: &str| -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
            let v: serde_json::Value = serde_json::from_str(body)?;
            let prot_b64 = v["protected"].as_str().unwrap_or("");
            let pay_b64 = v["payload"].as_str().unwrap_or("");
            let prot: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(prot_b64)?)?;
            let pay: serde_json::Value = if pay_b64.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(pay_b64)?)?
            };
            Ok((prot, pay))
        };

        let app = Router::new()
            .route(
                "/directory",
                get(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let body = serde_json::json!({
                        "newNonce": format!("{}/new-nonce", st.base_url),
                        "newAccount": format!("{}/new-acct", st.base_url),
                        "newOrder": format!("{}/new-order", st.base_url),
                        "meta": {
                            "termsOfService": format!("{}/tos", st.base_url),
                            "profiles": {
                                "classic": format!("{}/profiles#classic", st.base_url),
                                "shortlived": format!("{}/profiles#shortlived", st.base_url)
                            }
                        }
                    });
                    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body.to_string())
                }),
            )
            .route(
                "/new-nonce",
                head(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    (StatusCode::OK, [("replay-nonce", st.next_nonce())], "")
                })
                .get(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    (StatusCode::OK, [("replay-nonce", st.next_nonce())], "")
                }),
            )
            .route(
                "/new-acct",
                post(move |AState(st): AState<Arc<MockAcmeState>>, body: String| async move {
                    let (prot, _) = decode_jws(&body).unwrap();
                    if let Some(jwk) = prot.get("jwk") {
                        let x = jwk["x"].as_str().unwrap_or("");
                        let y = jwk["y"].as_str().unwrap_or("");
                        let canon = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
                        let tp = URL_SAFE_NO_PAD.encode(
                            ring::digest::digest(&ring::digest::SHA256, canon.as_bytes()).as_ref(),
                        );
                        *st.jwk_thumbprint.lock() = Some(tp);
                    }
                    let resp = serde_json::json!({ "status": "valid" });
                    (
                        StatusCode::CREATED,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (header::LOCATION, format!("{}/acct/1", st.base_url)),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/acct/1",
                post(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let resp = serde_json::json!({ "status": "valid" });
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (header::LOCATION, format!("{}/acct/1", st.base_url)),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/new-order",
                post(move |AState(st): AState<Arc<MockAcmeState>>, body: String| async move {
                    let (_, pay) = decode_jws(&body).unwrap();
                    let ids = pay["identifiers"].as_array().cloned().unwrap_or_default();
                    *st.order_identifiers.lock() = ids.clone();
                    *st.order_profile.lock() =
                        pay.get("profile").and_then(|v| v.as_str()).map(str::to_string);
                    let resp = serde_json::json!({
                        "status": "pending",
                        "identifiers": ids,
                        "authorizations": [format!("{}/authz/1", st.base_url)],
                        "finalize": format!("{}/order/1/finalize", st.base_url)
                    });
                    (
                        StatusCode::CREATED,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (header::LOCATION, format!("{}/order/1", st.base_url)),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/authz/1",
                post(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let valid = st.authz_valid.load(std::sync::atomic::Ordering::SeqCst);
                    let status = if valid { "valid" } else { "pending" };
                    let id0 = st
                        .order_identifiers
                        .lock()
                        .first()
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({"type":"dns","value":"example.test"}));
                    let resp = serde_json::json!({
                        "identifier": id0,
                        "status": status,
                        "challenges": [{
                            "type": "http-01",
                            "url": format!("{}/chall/1", st.base_url),
                            "status": status,
                            "token": "mock-http01-token-abcdef"
                        }]
                    });
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/chall/1",
                post(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let token = "mock-http01-token-abcdef";
                    let host_hdr = st
                        .order_identifiers
                        .lock()
                        .first()
                        .and_then(|v| v["value"].as_str())
                        .unwrap_or("127.0.0.1")
                        .to_string();
                    let url = format!(
                        "http://127.0.0.1:{}/.well-known/acme-challenge/{token}",
                        st.http01_port
                    );
                    let cli = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .no_proxy()
                        .build()
                        .unwrap();
                    let resp_text = cli
                        .get(&url)
                        .header(header::HOST, host_hdr)
                        .send()
                        .await
                        .ok()
                        .and_then(|r| if r.status().is_success() { Some(r) } else { None });
                    let fetched = match resp_text {
                        Some(r) => r.text().await.unwrap_or_default(),
                        None => String::new(),
                    };
                    let expected_tp = st.jwk_thumbprint.lock().clone().unwrap_or_default();
                    let expected = format!("{token}.{expected_tp}");
                    let ok = !expected_tp.is_empty() && fetched.trim() == expected;
                    if ok {
                        st.http01_verified.store(true, std::sync::atomic::Ordering::SeqCst);
                        st.authz_valid.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    let status = if ok { "valid" } else { "invalid" };
                    let resp = serde_json::json!({
                        "type": "http-01",
                        "url": format!("{}/chall/1", st.base_url),
                        "status": status,
                        "token": token
                    });
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/order/1/finalize",
                post(move |AState(st): AState<Arc<MockAcmeState>>, body: String| async move {
                    let (_, pay) = decode_jws(&body).unwrap();
                    let csr_b64 = pay["csr"].as_str().unwrap_or("");
                    let csr_der = URL_SAFE_NO_PAD.decode(csr_b64).unwrap();

                    // Parse PKCS#10 CSR DER to extract SubjectPublicKeyInfo raw key bytes + check subject DN
                    fn read_tlv<'a>(buf: &mut &'a [u8]) -> (u8, &'a [u8]) {
                        let tag = buf[0];
                        let lb = buf[1];
                        let (len, hdr) = if lb & 0x80 == 0 {
                            (lb as usize, 2)
                        } else {
                            let c = (lb & 0x7f) as usize;
                            let mut l = 0usize;
                            for &b in &buf[2..2 + c] {
                                l = (l << 8) | (b as usize);
                            }
                            (l, 2 + c)
                        };
                        let body = &buf[hdr..hdr + len];
                        *buf = &buf[hdr + len..];
                        (tag, body)
                    }
                    let mut root = csr_der.as_slice();
                    let (_, csr_seq) = read_tlv(&mut root);
                    let mut c1 = csr_seq;
                    let (_, cri_seq) = read_tlv(&mut c1);
                    let mut cri = cri_seq;
                    let _ver = read_tlv(&mut cri);
                    let (_, subj_seq) = read_tlv(&mut cri);
                    let (_, spki_seq) = read_tlv(&mut cri);
                    let mut spki = spki_seq;
                    let _alg = read_tlv(&mut spki);
                    let (_, bit_str) = read_tlv(&mut spki);
                    let pub_key_bytes = bit_str[1..].to_vec(); // skip unused-bits byte

                    struct RawP256Pub(Vec<u8>);
                    impl rcgen::PublicKeyData for RawP256Pub {
                        fn der_bytes(&self) -> &[u8] {
                            &self.0
                        }
                        fn algorithm(&self) -> &rcgen::SignatureAlgorithm {
                            &rcgen::PKCS_ECDSA_P256_SHA256
                        }
                    }

                    let ids = st.order_identifiers.lock().clone();
                    let is_ip_order = ids.iter().any(|v| v["type"] == "ip");
                    if is_ip_order {
                        assert!(
                            subj_seq.is_empty(),
                            "Let's Encrypt IP CSR must have an empty Subject/CN!"
                        );
                    }

                    let mut leaf_params = rcgen::CertificateParams::default();
                    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
                    let mut sans = Vec::new();
                    for id in &ids {
                        let val = id["value"].as_str().unwrap_or("");
                        if id["type"] == "ip" {
                            sans.push(rcgen::SanType::IpAddress(val.parse().unwrap()));
                        } else {
                            sans.push(rcgen::SanType::DnsName(val.try_into().unwrap()));
                        }
                    }
                    leaf_params.subject_alt_names = sans;
                    let now = chrono::Utc::now();
                    let start = now - chrono::Duration::days(1);
                    let end = now + chrono::Duration::days(st.cert_days);
                    leaf_params.not_before = rcgen::date_time_ymd(
                        start.year(),
                        start.month() as u8,
                        start.day() as u8,
                    );
                    leaf_params.not_after = rcgen::date_time_ymd(
                        end.year(),
                        end.month() as u8,
                        end.day() as u8,
                    );
                    let leaf = leaf_params
                        .signed_by(&RawP256Pub(pub_key_bytes), &st.ca_cert, &st.ca_key)
                        .unwrap();
                    let fullchain = format!("{}{}", leaf.pem(), st.ca_cert.pem());
                    *st.issued_chain_pem.lock() = Some(fullchain);
                    let resp = serde_json::json!({
                        "status": "valid",
                        "identifiers": ids,
                        "authorizations": [format!("{}/authz/1", st.base_url)],
                        "finalize": format!("{}/order/1/finalize", st.base_url),
                        "certificate": format!("{}/cert/1", st.base_url)
                    });
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/order/1",
                post(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let has_cert = st.issued_chain_pem.lock().is_some();
                    let valid = st.authz_valid.load(std::sync::atomic::Ordering::SeqCst);
                    let status = if has_cert {
                        "valid"
                    } else if valid {
                        "ready"
                    } else {
                        "pending"
                    };
                    let ids = st.order_identifiers.lock().clone();
                    let mut resp = serde_json::json!({
                        "status": status,
                        "identifiers": ids,
                        "authorizations": [format!("{}/authz/1", st.base_url)],
                        "finalize": format!("{}/order/1/finalize", st.base_url)
                    });
                    if has_cert {
                        resp["certificate"] =
                            serde_json::json!(format!("{}/cert/1", st.base_url));
                    }
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        resp.to_string(),
                    )
                }),
            )
            .route(
                "/cert/1",
                post(|AState(st): AState<Arc<MockAcmeState>>| async move {
                    let pem = st.issued_chain_pem.lock().clone().unwrap_or_default();
                    (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                "application/pem-certificate-chain".to_string(),
                            ),
                            (
                                header::HeaderName::from_static("replay-nonce"),
                                st.next_nonce(),
                            ),
                        ],
                        pem,
                    )
                        .into_response()
                }),
            )
            .with_state(state.clone());

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok((format!("{base_url}/directory"), state, handle))
    }

    #[tokio::test]
    async fn acme_shortlived_ip_ssl_end_to_end_and_shoes_check() -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Reserve a free ephemeral port for temporary HTTP-01 listener
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let http01_port = probe.local_addr()?.port();
        drop(probe);

        let (dir_url, ca_state, ca_handle) = spawn_mock_acme_ca(http01_port, 6).await?;
        let tmp = tempfile::tempdir()?;

        // 1. Live directory metadata fetch
        let meta = acme_util::fetch_acme_directory_meta(&dir_url).await?;
        assert!(meta.supports_shortlived);
        assert!(meta.terms_of_service.as_deref().unwrap_or("").ends_with("/tos"));

        // 2. Issue real shortlived IP cert via RFC 8555 + RFC 8738 HTTP-01
        let issued = acme_util::issue_shortlived_ip_cert(
            tmp.path(),
            "my-ip-ssl",
            &["127.0.0.1".to_string()],
            "ops@example.test",
            &dir_url,
            &format!("127.0.0.1:{http01_port}"),
        )
        .await?;

        assert!(ca_state.http01_verified.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(ca_state.order_profile.lock().as_deref(), Some("shortlived"));
        assert_eq!(ca_state.order_identifiers.lock()[0]["type"], "ip");
        assert_eq!(ca_state.order_identifiers.lock()[0]["value"], "127.0.0.1");
        assert!(!issued.info.is_self_signed, "certificate must be CA-signed");
        assert!(issued.info.subject.is_empty(), "IP CSR must NOT set CommonName");
        assert_eq!(issued.info.sans, vec!["127.0.0.1"]);

        // 3. Persist as acme_ip cert source + verify shoes.exe check + subscription export
        let cert_path = tmp.path().join("certs/my-ip-ssl.crt");
        let key_path = tmp.path().join("certs/my-ip-ssl.key");
        acme_util::write_cert_and_key_atomic(&cert_path, &key_path, &issued.cert_pem, &issued.key_pem)?;

        let db = Database::open(&tmp.path().join("panel.db"), tmp.path())?;
        let cert_rec = db.save_certificate(CertificateRecord {
            id: 0,
            name: "my-ip-ssl".into(),
            cert_type: "acme_ip".into(),
            cert_file: cert_path.to_string_lossy().replace('\\', "/"),
            key_file: key_path.to_string_lossy().replace('\\', "/"),
            domains: vec!["127.0.0.1".into()],
            email: "ops@example.test".into(),
            directory_url: dir_url.clone(),
            terms_of_service: issued.terms_of_service.clone(),
            challenge_type: "http01".into(),
            http01_listen: format!("127.0.0.1:{http01_port}"),
            remark: "IP SSL".into(),
            created_at: 0,
        })?;

        let ib = db.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "remark": "ip-tls-vless",
            "port": 23443,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {
                    "cert_mode": "source",
                    "certificate_source": "my-ip-ssl",
                    "sni": "127.0.0.1",
                    "allow_insecure": false
                }
            },
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?)?;

        let settings = db.get_settings()?;
        let yaml = yaml_gen::build_shoes_yaml(
            tmp.path(),
            &settings,
            &db.list_certificates()?,
            &[],
            &[],
            &db.list_inbounds()?,
        )?;
        // IP SNI must map to default_tls_target (RFC 6066)
        assert!(yaml.contains("default_tls_target:"));
        assert!(!yaml.contains("tls_targets:"));

        // Subscription export for IP SSL must omit SNI and keep insecure=false
        let share = sub_gen::build_client_share_info(&ib, &ib.clients[0], "127.0.0.1");
        assert!(!share.uri.contains("sni="));
        assert!(!share.uri.contains("allowInsecure=1"));

        // Runtime status inspection reports issued + CA name
        let rt = acme_util::inspect_certificate_runtime(tmp.path(), &cert_rec, vec!["ip-tls-vless".into()], "");
        assert_eq!(rt.status, "issued");
        assert!(!rt.is_self_signed);

        // Validate against REAL shoes binary if present
        let shoes_bin = std::path::PathBuf::from("shoes/target/debug/shoes.exe");
        if shoes_bin.exists() {
            let yp = tmp.path().join("ip_ssl.yaml");
            std::fs::write(&yp, &yaml)?;
            let out = std::process::Command::new(&shoes_bin).arg("check").arg(&yp).output()?;
            assert!(
                out.status.success(),
                "shoes check failed on IP SSL config: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        ca_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn domain_acme_real_shoes_e2e_and_alpn_standby() -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let shoes_bin = std::path::PathBuf::from("shoes/target/debug/shoes.exe");
        if !shoes_bin.exists() {
            return Ok(());
        }

        let tmp = tempfile::tempdir()?;
        let db = Database::open(&tmp.path().join("panel.db"), tmp.path())?;
        let settings = db.get_settings()?;

        // 1. TLS-ALPN-01 saved BEFORE any inbound must pass `shoes check` (deferred until attached)
        let alpn_cert = db.save_certificate(CertificateRecord {
            id: 0,
            name: "alpn-domain".into(),
            cert_type: "acme".into(),
            cert_file: String::new(),
            key_file: String::new(),
            domains: vec!["ALPN.Example.TEST".into()],
            email: "admin@example.test".into(),
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            terms_of_service: DEFAULT_LETSENCRYPT_TOS.into(),
            challenge_type: "tls_alpn01".into(),
            http01_listen: String::new(),
            remark: String::new(),
            created_at: 0,
        })?;
        let yaml_standby = yaml_gen::build_shoes_yaml(
            tmp.path(),
            &settings,
            &db.list_certificates()?,
            &[],
            &[],
            &[],
        )?;
        assert!(!yaml_standby.contains("alpn-domain"));
        let standby_path = tmp.path().join("alpn_standby.yaml");
        std::fs::write(&standby_path, &yaml_standby)?;
        let out = std::process::Command::new(&shoes_bin).arg("check").arg(&standby_path).output()?;
        assert!(out.status.success(), "standby ALPN check failed: {}", String::from_utf8_lossy(&out.stderr));

        let rt_standby = acme_util::inspect_certificate_runtime(tmp.path(), &alpn_cert, vec![], "");
        assert_eq!(rt_standby.status, "unreferenced_alpn");

        // 2. Attach TLS-ALPN-01 to TCP TLS inbound with uppercase SNI -> normalized & passes `shoes check`
        let _ib = db.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "remark": "alpn-443",
            "port": 24443,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {
                    "cert_mode": "source",
                    "certificate_source": "alpn-domain",
                    "sni": "ALPN.Example.TEST",
                    "allow_insecure": false
                }
            },
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?)?;
        let yaml_bound = yaml_gen::build_shoes_yaml(
            tmp.path(),
            &settings,
            &db.list_certificates()?,
            &[],
            &[],
            &db.list_inbounds()?,
        )?;
        assert!(yaml_bound.contains("alpn-domain"));
        assert!(yaml_bound.contains("alpn.example.test"));
        let bound_path = tmp.path().join("alpn_bound.yaml");
        std::fs::write(&bound_path, &yaml_bound)?;
        let out2 = std::process::Command::new(&shoes_bin).arg("check").arg(&bound_path).output()?;
        assert!(out2.status.success(), "bound ALPN check failed: {}", String::from_utf8_lossy(&out2.stderr));

        // 3. LIVE REAL `shoes.exe` HTTP-01 domain ACME issuance against local loopback ACME CA!
        let probe_http = std::net::TcpListener::bind("127.0.0.1:0")?;
        let http01_port = probe_http.local_addr()?.port();
        drop(probe_http);
        let probe_proxy = std::net::TcpListener::bind("127.0.0.1:0")?;
        let proxy_port = probe_proxy.local_addr()?.port();
        drop(probe_proxy);

        let (dir_url, ca_state, ca_handle) = spawn_mock_acme_ca(http01_port, 90).await?;
        let meta = acme_util::fetch_acme_directory_meta(&dir_url).await?;

        let tmp2 = tempfile::tempdir()?;
        let db2 = Database::open(&tmp2.path().join("panel.db"), tmp2.path())?;
        // Disable clash api to avoid port collision with running services
        db2.set_setting_kv("clash_api_addr", "")?;
        let settings2 = db2.get_settings()?;

        let dom_cert = db2.save_certificate(CertificateRecord {
            id: 0,
            name: "live-domain".into(),
            cert_type: "acme".into(),
            cert_file: String::new(),
            key_file: String::new(),
            domains: vec!["proxy.example.test".into()],
            email: "admin@example.test".into(),
            directory_url: dir_url.clone(),
            terms_of_service: meta.terms_of_service.unwrap_or_default(),
            challenge_type: "http01".into(),
            http01_listen: format!("127.0.0.1:{http01_port}"),
            remark: String::new(),
            created_at: 0,
        })?;
        let _ib2 = db2.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "remark": "dom-tls",
            "listen": "127.0.0.1",
            "port": proxy_port,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {
                    "cert_mode": "source",
                    "certificate_source": "live-domain",
                    "sni": "proxy.example.test",
                    "allow_insecure": false
                }
            },
            "clients": [{"name": "u", "password": "secret-password-123"}]
        }))?)?;

        let yaml_live = yaml_gen::build_shoes_yaml(
            tmp2.path(),
            &settings2,
            &db2.list_certificates()?,
            &[],
            &[],
            &db2.list_inbounds()?,
        )?;
        let live_cfg = tmp2.path().join("live_acme.yaml");
        std::fs::write(&live_cfg, &yaml_live)?;

        let mut child = tokio::process::Command::new(&shoes_bin)
            .arg(&live_cfg)
            .env("RUST_LOG", "debug")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
        let mut issued_ok = false;
        while tokio::time::Instant::now() < deadline {
            let rt = acme_util::inspect_certificate_runtime(tmp2.path(), &dom_cert, vec!["dom-tls".into()], "");
            if rt.status == "issued" {
                assert!(rt.sans.iter().any(|s| s == "proxy.example.test"));
                assert!(!rt.is_self_signed);
                issued_ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        let _ = child.kill().await;
        let output = child.wait_with_output().await?;
        ca_handle.abort();

        let logs = format!(
            "YAML:\n{yaml_live}\nSTDOUT:\n{}\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            ca_state.http01_verified.load(std::sync::atomic::Ordering::SeqCst),
            "shoes did not complete HTTP-01 challenge.\n{logs}"
        );
        assert!(
            issued_ok,
            "real shoes.exe did not persist issued ACME certificate into state.json.\n{logs}"
        );

        // 4. Verify Panel HTTPS export from Shoes ACME state.json produces valid RustlsConfig!
        let (exp_cert, exp_key) = acme_util::export_acme_state_for_panel(tmp2.path(), &dom_cert)?;
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&exp_cert, &exp_key).await?;

        Ok(())
    }

    #[tokio::test]
    async fn certificate_http_api_validation_rollback_and_panel_https() -> anyhow::Result<()> {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&tmp.path().join("panel.db"), tmp.path())?);
        let settings = db.get_settings()?;
        let proc_mgr = ShoesProcessManager::new(db.clone());
        let monitor = RuntimeMonitor::new(db.clone(), proc_mgr.clone());
        let state = AppState::new(db.clone(), proc_mgr, monitor, &settings);
        let token = state.sessions.create_session("admin", 1);
        let app = build_inner_router(state.clone());

        let authed = |method: &str, uri: &str, body: Option<serde_json::Value>| -> Request<Body> {
            let mut b = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"));
            if let Some(v) = body {
                b = b.header(header::CONTENT_TYPE, "application/json");
                b.body(Body::from(v.to_string())).unwrap()
            } else {
                b.body(Body::empty()).unwrap()
            }
        };

        // 1. Mismatched cert/key upload must fail 400 without polluting DB
        let (c1, _) = crypto_util::generate_self_signed_cert(&["a.test".into()])?;
        let (_, k2) = crypto_util::generate_self_signed_cert(&["b.test".into()])?;
        let resp = app
            .clone()
            .oneshot(authed(
                "POST",
                "/api/certificates/upload",
                Some(serde_json::json!({
                    "name": "bad-pair",
                    "cert_pem": c1,
                    "key_pem": k2
                })),
            ))
            .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(db.list_certificates()?.is_empty());

        // 2. Self-signed IP cert creation succeeds & GET /api/certificates includes runtime status
        let resp = app
            .clone()
            .oneshot(authed(
                "POST",
                "/api/certificates/self-signed",
                Some(serde_json::json!({
                    "name": "ip-self",
                    "domains": ["1.1.1.1", "localhost"],
                    "remark": "No-Domain IP Self-Signed"
                })),
            ))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await?;
        let created: serde_json::Value = serde_json::from_slice(&body_bytes)?;
        let cert_id = created["data"]["id"].as_i64().unwrap();

        // Bind it to an inbound
        let ib = db.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "remark": "bound-node",
            "port": 25443,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {
                    "cert_mode": "source",
                    "certificate_source": "ip-self",
                    "allow_insecure": true
                }
            },
            "clients": [{"name": "u", "password": "pw"}]
        }))?)?;

        // 3. GET /api/certificates returns runtime metadata + bound inbound list
        let resp = app
            .clone()
            .oneshot(authed("GET", "/api/certificates", None))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let list_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await?;
        let list_json: serde_json::Value = serde_json::from_slice(&list_bytes)?;
        let item = &list_json["data"][0];
        assert_eq!(item["runtime"]["status"], "issued");
        assert!(item["runtime"]["sans"].as_array().unwrap().iter().any(|s| s == "1.1.1.1"));
        assert!(item["runtime"]["used_by"].as_array().unwrap()[0].as_str().unwrap().contains("bound-node"));

        // 4. Deleting in-use cert must be blocked (400) and keep cert intact
        let resp = app
            .clone()
            .oneshot(authed("DELETE", &format!("/api/certificates/{cert_id}"), None))
            .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(db.list_certificates()?.len(), 1);

        // 5. Apply to Panel HTTPS sets panel_cert_file & panel_key_file
        let resp = app
            .clone()
            .oneshot(authed(
                "POST",
                &format!("/api/certificates/{cert_id}/apply-panel-https"),
                None,
            ))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let updated_settings = db.get_settings()?;
        assert!(updated_settings.panel_cert_file.ends_with("ip-self.crt"));
        assert!(updated_settings.panel_key_file.ends_with("ip-self.key"));

        // 6. Deleting cert while used by Panel HTTPS is also blocked
        db.delete_inbound(ib.id)?;
        let resp = app
            .clone()
            .oneshot(authed("DELETE", &format!("/api/certificates/{cert_id}"), None))
            .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Clear panel HTTPS -> delete now succeeds!
        db.set_setting_kv("panel_cert_file", "")?;
        db.set_setting_kv("panel_key_file", "")?;
        let resp = app
            .clone()
            .oneshot(authed("DELETE", &format!("/api/certificates/{cert_id}"), None))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(db.list_certificates()?.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_change_bruteforce_guard_and_cert_cli() -> anyhow::Result<()> {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&tmp.path().join("panel.db"), tmp.path())?);
        assert!(db.is_default_credentials());

        // 1. Rename username ONLY (blank new_password keeps old password hash!)
        db.update_credentials(Some("admin"), "opsadmin", "")?;
        assert!(!db.is_default_credentials());
        assert!(db.verify_user("opsadmin", "admin")?);
        assert!(!db.verify_user("admin", "admin")?);

        // 2. Wrong current password must fail
        assert!(db.update_credentials(Some("wrong"), "opsadmin", "newpass123").is_err());

        // 3. Change password + verify HTTP /api/settings/password revokes session & clears cookie
        let settings = db.get_settings()?;
        let proc_mgr = ShoesProcessManager::new(db.clone());
        let monitor = RuntimeMonitor::new(db.clone(), proc_mgr.clone());
        let state = AppState::new(db.clone(), proc_mgr, monitor, &settings);
        let tok = state.sessions.create_session("opsadmin", 1);
        let app = build_inner_router(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/password")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "current_password": "admin",
                            "new_username": "rootpanel",
                            "new_password": "StrongPassword!2026"
                        })
                        .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie_hdr = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(cookie_hdr.contains("Max-Age=0"));
        assert!(state.sessions.validate(&tok).is_none());
        assert!(db.verify_user("rootpanel", "StrongPassword!2026")?);

        // 4. Brute-force protection: 8 failed logins trigger 429 Too Many Requests
        for attempt in 0..8 {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/login")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "username": "rootpanel",
                                "password": "wrong-password"
                            })
                            .to_string(),
                        ))?,
                )
                .await?;
            if attempt < 7 {
                assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }
        // Locked out even with right password until lockout expires
        let locked_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "rootpanel",
                            "password": "StrongPassword!2026"
                        })
                        .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(locked_resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // 5. CLI `cert self-signed --panel-https`, `cert clear`, and `cert ip --panel-https`
        run_cert_cli(
            &db,
            &[
                "self-signed".into(),
                "--ip".into(),
                "1.1.1.1".into(),
                "--panel-https".into(),
            ],
        )
        .await?;
        let s_https = db.get_settings()?;
        assert_eq!(s_https.scheme(), "https");
        assert!(s_https.panel_cert_file.ends_with("panel-self-ssl.crt"));
        axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &s_https.panel_cert_file,
            &s_https.panel_key_file,
        )
        .await?;

        run_cert_cli(&db, &["clear".into()]).await?;
        assert_eq!(db.get_settings()?.scheme(), "http");

        // CLI `cert ip --panel-https` against local RFC 8555 + RFC 8738 mock CA
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let http01_port = probe.local_addr()?.port();
        drop(probe);
        let (dir_url, _, ca_handle) = spawn_mock_acme_ca(http01_port, 6).await?;
        run_cert_cli(
            &db,
            &[
                "ip".into(),
                "--ip".into(),
                "127.0.0.1".into(),
                "--directory".into(),
                dir_url,
                "--listen".into(),
                format!("127.0.0.1:{http01_port}"),
                "--panel-https".into(),
            ],
        )
        .await?;
        ca_handle.abort();

        let s_le = db.get_settings()?;
        assert_eq!(s_le.scheme(), "https");
        assert!(s_le.panel_cert_file.ends_with("panel-ip-ssl.crt"));
        axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &s_le.panel_cert_file,
            &s_le.panel_key_file,
        )
        .await?;
        assert!(db
            .list_certificates()?
            .iter()
            .any(|c| c.name == "panel-ip-ssl" && c.cert_type == "acme_ip"));

        Ok(())
    }

    #[tokio::test]
    async fn backup_restore_multipart_telegram_and_upgrade_checks() -> anyhow::Result<()> {
        use axum::{
            body::Body,
            extract::Multipart as TestMultipart,
            http::{header, Request, StatusCode},
            routing::post,
            Router,
        };

        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&tmp.path().join("panel.db"), tmp.path())?);
        let settings = db.get_settings()?;
        let proc_mgr = ShoesProcessManager::new(db.clone());
        let monitor = RuntimeMonitor::new(db.clone(), proc_mgr.clone());
        let state = AppState::new(db.clone(), proc_mgr, monitor, &settings);
        let tok = state.sessions.create_session("admin", 1);
        let app = build_inner_router(state.clone());

        // 1. Seed distinctive inbound & create snapshot backup
        let _ib = db.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "remark": "restore-marker-node",
            "port": 26123
        }))?)?;
        let (b1, bytes1) = ops_util::create_local_backup(&db, "manual", Some(2))?;
        assert!(b1.size_bytes > 4096);
        assert!(ops_util::list_local_backups(tmp.path())?.iter().any(|x| x.filename == b1.filename));

        // 2. Reject invalid (non-SQLite) upload via HTTP /api/settings/restore-db
        let bad_boundary = "----TestBadBoundary123";
        let bad_body = format!(
            "--{bad_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"corrupt.db\"\r\nContent-Type: application/octet-stream\r\n\r\nnot-a-sqlite-db\r\n--{bad_boundary}--\r\n"
        );
        let bad_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/restore-db")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={bad_boundary}"),
                    )
                    .body(Body::from(bad_body))?,
            )
            .await?;
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);

        // 3. Delete inbound, then restore via HTTP multipart upload and confirm inbound returns + pre-restore safety snapshot saved!
        for ib in db.list_inbounds()? {
            db.delete_inbound(ib.id)?;
        }
        assert!(db.list_inbounds()?.is_empty());

        let ok_boundary = "----TestOkBoundary456";
        let mut ok_body = Vec::new();
        ok_body.extend_from_slice(
            format!(
                "--{ok_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"backup.db\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        ok_body.extend_from_slice(&bytes1);
        ok_body.extend_from_slice(format!("\r\n--{ok_boundary}--\r\n").as_bytes());

        let ok_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/restore-db")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={ok_boundary}"),
                    )
                    .body(Body::from(ok_body))?,
            )
            .await?;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        let resp_json: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(ok_resp.into_body(), 1024 * 1024).await?)?;
        let pre_name = resp_json["data"]["pre_restore_backup"].as_str().unwrap();
        assert!(pre_name.starts_with("pre-restore-"));
        assert!(ops_util::backups_dir(tmp.path()).join(pre_name).is_file());
        assert_eq!(db.list_inbounds()?.len(), 1);
        assert_eq!(db.list_inbounds()?[0].remark, "restore-marker-node");
        // Sessions must be revoked after DB restore
        assert!(state.sessions.validate(&tok).is_none());

        // 4. Retention pruning keeps only N auto/manual backups
        for i in 0..4 {
            let p = ops_util::backups_dir(tmp.path()).join(format!("auto-2026010{i}-000000.db"));
            std::fs::write(&p, &bytes1)?;
        }
        let _ = ops_util::prune_old_backups(tmp.path(), 2)?;
        let remaining_auto_manual: Vec<_> = ops_util::list_local_backups(tmp.path())?
            .into_iter()
            .filter(|b| b.filename.starts_with("auto-") || b.filename.starts_with("manual-"))
            .collect();
        assert_eq!(remaining_auto_manual.len(), 2);

        // Path traversal guard
        assert!(ops_util::sanitize_backup_filename("../panel.db").is_err());
        assert!(ops_util::sanitize_backup_filename("sub/a.db").is_err());
        assert!(ops_util::sanitize_backup_filename("ok-backup_1.db").is_ok());

        // 5. Real HTTP multipart Telegram sendDocument verification against local mock Telegram server
        let received = Arc::new(parking_lot::Mutex::new(Vec::<(String, String, usize)>::new()));
        let rec_clone = received.clone();
        let tg_app = Router::new().route(
            "/botTESTTOKEN/sendDocument",
            post(move |mut mp: TestMultipart| {
                let rec = rec_clone.clone();
                async move {
                    let mut chat = String::new();
                    let mut fname = String::new();
                    let mut doc_len = 0usize;
                    while let Ok(Some(f)) = mp.next_field().await {
                        let name = f.name().unwrap_or("").to_string();
                        if name == "chat_id" {
                            chat = f.text().await.unwrap_or_default();
                        } else if name == "document" {
                            fname = f.file_name().unwrap_or("").to_string();
                            doc_len = f.bytes().await.map(|b| b.len()).unwrap_or(0);
                        }
                    }
                    rec.lock().push((chat, fname, doc_len));
                    (StatusCode::OK, r#"{"ok":true,"result":{"message_id":1}}"#)
                }
            }),
        );
        let tg_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tg_addr = tg_listener.local_addr()?;
        let tg_handle = tokio::spawn(async move {
            let _ = axum::serve(tg_listener, tg_app).await;
        });

        let sent = ops_util::send_backup_to_telegram(
            Some(&format!("http://{tg_addr}")),
            "TESTTOKEN",
            "10001, 10002",
            "auto-test.db",
            &bytes1,
            "Test Caption",
        )
        .await?;
        tg_handle.abort();
        assert_eq!(sent, 2);
        let got = received.lock().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("10001".to_string(), "auto-test.db".to_string(), bytes1.len()));
        assert_eq!(got[1], ("10002".to_string(), "auto-test.db".to_string(), bytes1.len()));

        // 6. Semver comparison & SHA-256 verification
        assert!(ops_util::is_newer_version("0.1.2", "v0.1.3"));
        assert!(!ops_util::is_newer_version("0.1.3", "v0.1.2"));
        assert!(ops_util::is_newer_version("shoes 0.1.34 (abc)", "v0.1.35"));
        let sample = b"release-archive-bytes";
        let good_sum = hex::encode(ring::digest::digest(&ring::digest::SHA256, sample).as_ref());
        let sums = format!("{good_sum}  shoes-panel-x86_64-unknown-linux-musl.tar.gz\n");
        ops_util::verify_sha256_against_sums(&sums, "shoes-panel-x86_64-unknown-linux-musl.tar.gz", sample)?;
        assert!(ops_util::verify_sha256_against_sums(
            &sums,
            "shoes-panel-x86_64-unknown-linux-musl.tar.gz",
            b"tampered"
        )
        .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn h2mux_subscriptions_outbound_and_live_shoes_proxy_forwarding() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = tempfile::tempdir()?;
        let db = Database::open(&tmp.path().join("panel.db"), tmp.path())?;
        db.set_setting_kv("clash_api_addr", "")?;
        let settings = db.get_settings()?;

        let (cert_pem, key_pem) = crypto_util::generate_self_signed_cert(&["localhost".into(), "127.0.0.1".into()])?;
        let cert_path = tmp.path().join("certs/mux.crt");
        let key_path = tmp.path().join("certs/mux.key");
        acme_util::write_cert_and_key_atomic(&cert_path, &key_path, &cert_pem, &key_pem)?;
        db.save_certificate(CertificateRecord {
            id: 0,
            name: "mux-cert".into(),
            cert_type: "files".into(),
            cert_file: cert_path.to_string_lossy().replace('\\', "/"),
            key_file: key_path.to_string_lossy().replace('\\', "/"),
            domains: vec!["localhost".into(), "127.0.0.1".into()],
            email: String::new(),
            directory_url: String::new(),
            terms_of_service: String::new(),
            challenge_type: "http01".into(),
            http01_listen: String::new(),
            remark: "Self-Signed".into(),
            created_at: 0,
        })?;

        // 1. VLESS Vision + H2Mux must be rejected by yaml_gen
        let bad_vless: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "remark": "conflict-vless",
            "port": 27001,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {"cert_mode": "source", "certificate_source": "mux-cert", "sni": "localhost", "vision": true, "allow_insecure": true},
                "h2mux": {"enabled": true, "max_connections": 4, "min_streams": 4, "padding": true}
            },
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?;
        let err = yaml_gen::build_shoes_yaml(
            tmp.path(),
            &settings,
            &db.list_certificates()?,
            &[],
            &[],
            &[bad_vless],
        )
        .unwrap_err();
        let err_chain = format!("{err:#}");
        assert!(
            err_chain.contains("VLESS Vision cannot be enabled together with H2Mux"),
            "unexpected error: {err_chain}"
        );

        // 2. Verify 3-client subscription export for VLESS + H2Mux (max_connections/min_streams) & Trojan + H2Mux (max_streams) & SS TCP + H2Mux
        let vless_mux: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "remark": "vl-mux",
            "port": 27002,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {"cert_mode": "source", "certificate_source": "mux-cert", "sni": "localhost", "vision": false, "allow_insecure": true},
                "h2mux": {"enabled": true, "max_connections": 4, "min_streams": 4, "max_streams": 0, "padding": true}
            },
            "clients": [{"name": "u", "uuid": "7a5b94ba-e5ac-40d2-9f86-43002674ff4d"}]
        }))?;
        let share_vl = sub_gen::build_client_share_info(&vless_mux, &vless_mux.clients[0], "127.0.0.1");
        let shoes_vl: serde_yaml::Value = serde_yaml::from_str(&share_vl.shoes_client_yaml)?;
        let inner_vl = &shoes_vl[0]["rules"][0]["client_chain"]["protocol"]["protocol"];
        assert_eq!(inner_vl["type"], "vless");
        assert_eq!(inner_vl["h2mux"]["max_connections"], 4);
        assert_eq!(inner_vl["h2mux"]["min_streams"], 4);
        assert_eq!(inner_vl["h2mux"]["padding"], true);

        let clash_vl: serde_yaml::Value = serde_yaml::from_str(
            &sub_gen::generate_subscription_with_certs(&[vless_mux.clone()], &db.list_certificates()?, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml).body,
        )?;
        assert_eq!(clash_vl["proxies"][0]["smux"]["enabled"], true);
        assert_eq!(clash_vl["proxies"][0]["smux"]["protocol"], "h2mux");
        assert_eq!(clash_vl["proxies"][0]["smux"]["max-connections"], 4);
        assert_eq!(clash_vl["proxies"][0]["smux"]["min-streams"], 4);
        assert_eq!(clash_vl["proxies"][0]["smux"]["padding"], true);
        assert!(clash_vl["proxies"][0]["smux"].get("max-streams").is_none());

        let sb_vl: serde_json::Value = serde_json::from_str(
            &sub_gen::generate_subscription_with_certs(&[vless_mux], &db.list_certificates()?, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson).body,
        )?;
        let sb_vl_node = sb_vl["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "vless").unwrap();
        assert_eq!(sb_vl_node["multiplex"]["enabled"], true);
        assert_eq!(sb_vl_node["multiplex"]["protocol"], "h2mux");
        assert_eq!(sb_vl_node["multiplex"]["max_connections"], 4);
        assert_eq!(sb_vl_node["multiplex"]["min_streams"], 4);
        assert_eq!(sb_vl_node["multiplex"]["padding"], true);
        assert!(sb_vl_node["multiplex"].get("max_streams").is_none());

        // When max_streams > 0, Mihomo & sing-box emit max_streams and omit max_connections/min_streams (sing-mux rule)
        let trojan_max: Inbound = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "remark": "tj-mux",
            "port": 27003,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {"cert_mode": "source", "certificate_source": "mux-cert", "sni": "localhost", "allow_insecure": true},
                "h2mux": {"enabled": true, "max_connections": 4, "min_streams": 4, "max_streams": 16, "padding": false}
            },
            "clients": [{"name": "u", "password": "mux-secret-password"}]
        }))?;
        let clash_tj: serde_yaml::Value = serde_yaml::from_str(
            &sub_gen::generate_subscription_with_certs(&[trojan_max.clone()], &db.list_certificates()?, "*", "127.0.0.1", sub_gen::SubFormat::ClashYaml).body,
        )?;
        assert_eq!(clash_tj["proxies"][0]["smux"]["max-streams"], 16);
        assert!(clash_tj["proxies"][0]["smux"].get("max-connections").is_none());
        let sb_tj: serde_json::Value = serde_json::from_str(
            &sub_gen::generate_subscription_with_certs(&[trojan_max], &db.list_certificates()?, "*", "127.0.0.1", sub_gen::SubFormat::SingBoxJson).body,
        )?;
        let sb_tj_node = sb_tj["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "trojan").unwrap();
        assert_eq!(sb_tj_node["multiplex"]["max_streams"], 16);
        assert!(sb_tj_node["multiplex"].get("max_connections").is_none());

        // 3. Outbound group member H2Mux YAML generation + real `shoes.exe check`
        let mux_group = OutboundGroupRecord {
            id: 1,
            name: "mux-pool".into(),
            enable: true,
            group_type: "selector".into(),
            default_member: String::new(),
            test_url: String::new(),
            interval_secs: 300,
            timeout_ms: 5000,
            tolerance_ms: 50,
            members: vec![
                OutboundMember {
                    name: "up-vless".into(),
                    protocol: "vless".into(),
                    address: "198.51.100.10:443".into(),
                    uuid: "7a5b94ba-e5ac-40d2-9f86-43002674ff4d".into(),
                    username: String::new(),
                    password: String::new(),
                    cipher: String::new(),
                    tls: true,
                    sni: "edge.example.test".into(),
                    verify: false,
                    h2mux: H2MuxSettings {
                        enabled: true,
                        max_connections: 2,
                        min_streams: 4,
                        max_streams: 0,
                        padding: true,
                    },
                    ..Default::default()
                },
                OutboundMember {
                    name: "up-trojan".into(),
                    protocol: "trojan".into(),
                    address: "198.51.100.11:443".into(),
                    uuid: String::new(),
                    username: String::new(),
                    password: "secret".into(),
                    cipher: String::new(),
                    tls: true,
                    sni: "tj.example.test".into(),
                    verify: false,
                    h2mux: H2MuxSettings {
                        enabled: true,
                        max_connections: 4,
                        min_streams: 2,
                        max_streams: 0,
                        padding: false,
                    },
                    ..Default::default()
                },
            ],
            raw_chains_yaml: String::new(),
            remark: String::new(),
        };

        let shoes_bin = std::path::PathBuf::from("shoes/target/debug/shoes.exe");
        if !shoes_bin.exists() {
            return Ok(());
        }

        // Reserve free loopback ports for live shoes server, shoes client SOCKS5, and echo target
        let free_port = || -> anyhow::Result<u16> {
            let l = std::net::TcpListener::bind("127.0.0.1:0")?;
            Ok(l.local_addr()?.port())
        };
        let srv_port = free_port()?;
        let socks_port = free_port()?;

        // Local TCP echo server
        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let echo_port = echo_listener.local_addr()?.port();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = sock.read(&mut buf).await {
                        if n > 0 {
                            let _ = sock.write_all(&buf[..n]).await;
                        }
                    }
                });
            }
        });

        let live_ib = db.create_inbound(serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "remark": "live-h2mux-server",
            "listen": "127.0.0.1",
            "port": srv_port,
            "stream_settings": {
                "network": "tcp",
                "security": "tls",
                "tls": {
                    "cert_mode": "source",
                    "certificate_source": "mux-cert",
                    "sni": "localhost",
                    "allow_insecure": true
                },
                "h2mux": {
                    "enabled": true,
                    "max_connections": 2,
                    "min_streams": 2,
                    "max_streams": 0,
                    "padding": true
                }
            },
            "clients": [{"name": "u", "password": "live-h2mux-password"}]
        }))?)?;

        let server_yaml = yaml_gen::build_shoes_yaml(
            tmp.path(),
            &settings,
            &db.list_certificates()?,
            &[mux_group],
            &[],
            &db.list_inbounds()?,
        )?;
        let server_cfg = tmp.path().join("h2mux_server.yaml");
        std::fs::write(&server_cfg, &server_yaml)?;
        let chk = std::process::Command::new(&shoes_bin).arg("check").arg(&server_cfg).output()?;
        assert!(
            chk.status.success(),
            "shoes check failed on H2Mux outbound+server config:\n{}\nYAML:\n{}",
            String::from_utf8_lossy(&chk.stderr),
            server_yaml
        );

        // Generate real shoes client YAML directly from sub_gen and bind to our test socks_port
        let share = sub_gen::build_client_share_info(&live_ib, &live_ib.clients[0], "127.0.0.1");
        let client_yaml = share.shoes_client_yaml.replace("127.0.0.1:1080", &format!("127.0.0.1:{socks_port}"));
        assert!(client_yaml.contains("h2mux:"));
        let client_cfg = tmp.path().join("h2mux_client.yaml");
        std::fs::write(&client_cfg, &client_yaml)?;
        let chk2 = std::process::Command::new(&shoes_bin).arg("check").arg(&client_cfg).output()?;
        assert!(
            chk2.status.success(),
            "shoes check failed on generated H2Mux client YAML:\n{}\nYAML:\n{}",
            String::from_utf8_lossy(&chk2.stderr),
            client_yaml
        );

        // Spawn REAL shoes.exe server + REAL shoes.exe H2Mux client and push 5 concurrent streams!
        let mut srv_child = tokio::process::Command::new(&shoes_bin)
            .arg(&server_cfg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut cli_child = tokio::process::Command::new(&shoes_bin)
            .arg(&client_cfg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // Wait until both listeners accept TCP connections
        let ready_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        while tokio::time::Instant::now() < ready_deadline {
            let s_ok = tokio::net::TcpStream::connect(("127.0.0.1", srv_port)).await.is_ok();
            let c_ok = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await.is_ok();
            if s_ok && c_ok {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }

        let mut tasks = Vec::new();
        for idx in 0..5usize {
            tasks.push(tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
                // SOCKS5 greeting: ver=5, nmethods=1, no-auth=0
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut resp = [0u8; 2];
                stream.read_exact(&mut resp).await?;
                anyhow::ensure!(resp == [0x05, 0x00], "bad socks5 greeting: {resp:?}");

                // SOCKS5 CONNECT 127.0.0.1:echo_port
                let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
                req.extend_from_slice(&echo_port.to_be_bytes());
                stream.write_all(&req).await?;
                let mut rep = [0u8; 10];
                stream.read_exact(&mut rep).await?;
                anyhow::ensure!(rep[1] == 0x00, "socks5 connect failed: {rep:?}");

                let msg = format!("shoes-h2mux-stream-{idx}");
                stream.write_all(msg.as_bytes()).await?;
                let mut echoed = vec![0u8; msg.len()];
                stream.read_exact(&mut echoed).await?;
                anyhow::ensure!(echoed == msg.as_bytes(), "echo mismatch");
                Ok::<(), anyhow::Error>(())
            }));
        }

        for t in tasks {
            t.await??;
        }

        let _ = cli_child.kill().await;
        let _ = srv_child.kill().await;
        echo_task.abort();

        Ok(())
    }

    #[tokio::test]
    async fn global_limits_ntp_dns_hosts_and_remote_ruleset_pass_real_shoes_check() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);

        // 1. Local mock HTTP server serving a valid sing-box JSON rule-set
        let mock_app = axum::Router::new().route(
            "/openai.json",
            axum::routing::get(|| async {
                r#"{"version":2,"rules":[{"domain_suffix":["openai.com","chatgpt.com"]}]}"#
            }),
        );
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mock_addr = mock_listener.local_addr()?;
        let mock_task = tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });

        // 2. Configure DNS group with DoH + IPv4-only strategy + static unlock hosts
        let mut dns_hosts = std::collections::BTreeMap::new();
        dns_hosts.insert(
            "netflix.example".to_string(),
            vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
        );
        let dns_group = db.save_dns_group(models::DnsGroupRecord {
            id: 0,
            name: "cf-ipv4".to_string(),
            enable: true,
            servers: vec![models::DnsServerItem {
                url: "https://1.1.1.1/dns-query".to_string(),
                ip_strategy: "ipv4_only".to_string(),
                server_name: "cloudflare-dns.com".to_string(),
                bootstrap_url: "udp://1.1.1.1".to_string(),
                client_chain: String::new(),
                timeout_secs: Some(5),
                connect_timeout_secs: Some(5),
                attempts: Some(1),
                native_cache_secs: None,
            }],
            hosts: dns_hosts,
            remark: "Cloudflare DoH IPv4 only".to_string(),
            created_at: 0,
        })?;
        assert_eq!(dns_group.name, "cf-ipv4");

        // 3. Create & sync a panel-managed remote rule_source_group
        let mut rsg = models::RuleSourceGroupRecord {
            id: 0,
            name: "geosite-openai".to_string(),
            enable: true,
            items: vec![models::RuleSourceItem {
                source_type: "url".to_string(),
                sync_mode: "panel".to_string(),
                url: format!("http://{mock_addr}/openai.json"),
                path: String::new(),
                format: "singbox_json".to_string(),
                behavior: String::new(),
                code: String::new(),
                attributes: Vec::new(),
                update_interval: "24h".to_string(),
                download_chain: "direct".to_string(),
                bootstrap_url: "system".to_string(),
                last_updated_at: 0,
                file_size: 0,
                last_error: String::new(),
            }],
            remark: "OpenAI rule set".to_string(),
            created_at: 0,
        };
        let changed = ops_util::sync_rule_source_group(dir.path(), &mut rsg).await?;
        assert!(changed);
        assert!(rsg.items[0].file_size > 20);
        assert!(std::path::Path::new(&rsg.items[0].path).is_file());
        let saved_rsg = db.save_rule_source_group(rsg)?;
        assert_eq!(saved_rsg.name, "geosite-openai");

        // 4. Add routing rules referencing the rule_source_group + ip_cidr with no_resolve + domain_suffix
        db.save_routing_rule(models::RoutingRuleRecord {
            id: 0,
            priority: 10,
            enable: true,
            remark: "Block private LAN".to_string(),
            match_type: "ip_cidr".to_string(),
            match_value: "10.0.0.0/8, 192.168.0.0/16".to_string(),
            action: "block".to_string(),
            outbound: "direct".to_string(),
            no_resolve: true,
            override_address: String::new(),
        })?;
        db.save_routing_rule(models::RoutingRuleRecord {
            id: 0,
            priority: 20,
            enable: true,
            remark: "Route OpenAI via rule set".to_string(),
            match_type: "rule_source_group".to_string(),
            match_value: "geosite-openai".to_string(),
            action: "allow".to_string(),
            outbound: "direct".to_string(),
            no_resolve: false,
            override_address: String::new(),
        })?;

        // 5. Configure global_settings (admission limits, QUIC memory/window, NTP, default_dns + global hosts)
        let mut settings = db.get_settings()?;
        settings.core_global = models::CoreGlobalSettings {
            max_connections: Some(2048),
            max_connections_per_ip: Some(64),
            max_streams: Some(4096),
            max_streams_per_connection: Some(256),
            max_udp_destinations: Some(1024),
            quic_memory_bytes: Some(256 * 1024 * 1024),
            quic_receive_window: Some(4 * 1024 * 1024),
            quic_send_window: Some(4 * 1024 * 1024),
            quic_stream_window: Some(512 * 1024),
            quic_dns_memory_bytes: None,
            quic_socket_buffer: Some(8 * 1024 * 1024),
            reload_grace_secs: Some(120),
            ntp_enabled: true,
            ntp_server: "time.cloudflare.com:123".to_string(),
            ntp_interval_secs: 1800,
            ntp_timeout_secs: 5,
            default_dns_group: "cf-ipv4".to_string(),
            default_dns_ip_strategy: String::new(),
            default_dns_servers: Vec::new(),
            default_dns_hosts: {
                let mut h = std::collections::BTreeMap::new();
                h.insert("unlock.example".to_string(), vec!["198.51.100.7".to_string()]);
                h
            },
            rule_cache_dir: String::new(),
        };
        db.save_settings(&settings)?;

        // 6. Add an inbound bound to the named DNS group
        let mut ib = models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "SOCKS-DNS-RuleSet".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39100,
            protocol: "socks".to_string(),
            protocol_settings: models::ProtocolSettings {
                dns_group: "cf-ipv4".to_string(),
                ..Default::default()
            },
            stream_settings: models::StreamSettings::default(),
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
        let client = db::default_client_for_inbound(&ib, 1);
        ib.clients.push(client);
        db.create_inbound(ib)?;

        // 7. Validate full generated YAML with real shoes binary (`shoes check`)!
        let reloaded = db.get_settings()?;
        assert_eq!(reloaded.core_global.max_connections_per_ip, Some(64));
        assert!(reloaded.core_global.ntp_enabled);
        let yaml = yaml_gen::validated_config(&db, &reloaded).await?;
        assert!(yaml.contains("max_connections_per_ip: 64"));
        assert!(yaml.contains("quic_memory_bytes: 268435456"));
        assert!(yaml.contains("time.cloudflare.com:123"));
        assert!(yaml.contains("dns_group: cf-ipv4"));
        assert!(yaml.contains("ip_strategy: ipv4_only"));
        assert!(yaml.contains("unlock.example"));
        assert!(yaml.contains("rule_source_group: geosite-openai"));
        assert!(yaml.contains("no_resolve: true"));

        mock_task.abort();
        Ok(())
    }

    #[test]
    fn wireguard_conf_parser_keygen_and_yaml_schema() -> anyhow::Result<()> {
        let (priv_k, pub_k, psk) = crypto_util::generate_wireguard_keypair();
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &priv_k)?.len(),
            32
        );
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &pub_k)?.len(),
            32
        );
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &psk)?.len(),
            32
        );

        let conf = format!(
            "[Interface]\nPrivateKey = {priv_k}\nAddress = 172.16.0.2/32, 2606:4700:110:8a36:df92:102a:9602:fa18/128\nMTU = 1280\n\n[Peer]\nPublicKey = {pub_k}\nPresharedKey = {psk}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\nPersistentKeepalive = 25\n"
        );
        let parsed = ops_util::parse_wireguard_conf(&conf)?;
        assert_eq!(parsed.address, "engage.cloudflareclient.com:2408");
        assert_eq!(parsed.wg_private_key, priv_k);
        assert_eq!(parsed.wg_public_key, pub_k);
        assert_eq!(parsed.wg_preshared_key, psk);
        assert_eq!(parsed.wg_addresses.len(), 2);
        assert_eq!(parsed.wg_mtu, 1280);
        assert_eq!(parsed.wg_keepalive, 25);

        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("panel.db"), dir.path())?;
        let settings = db.get_settings()?;
        let wg_group = models::OutboundGroupRecord {
            id: 1,
            name: "warp".to_string(),
            enable: true,
            group_type: "selector".to_string(),
            default_member: "warp-cf".to_string(),
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            interval_secs: 300,
            timeout_ms: 5000,
            tolerance_ms: 50,
            members: vec![models::OutboundMember {
                name: "warp-cf".to_string(),
                protocol: "wireguard".to_string(),
                address: parsed.address,
                uuid: String::new(),
                username: String::new(),
                password: String::new(),
                cipher: String::new(),
                tls: false,
                sni: String::new(),
                verify: true,
                h2mux: models::H2MuxSettings::default(),
                bind_interface: "eth0".to_string(),
                wg_private_key: parsed.wg_private_key,
                wg_public_key: parsed.wg_public_key,
                wg_preshared_key: parsed.wg_preshared_key,
                wg_addresses: parsed.wg_addresses,
                wg_allowed_ips: parsed.wg_allowed_ips,
                wg_mtu: parsed.wg_mtu,
                wg_keepalive: parsed.wg_keepalive,
                wg_tcp_buffer_size: Some(262_144),
                wg_tcp_memory_bytes: Some(268_435_456),
                ..Default::default()
            }],
            raw_chains_yaml: String::new(),
            remark: "Cloudflare WARP".to_string(),
        };

        let yaml = yaml_gen::build_shoes_yaml_full(
            dir.path(),
            &settings,
            &[],
            &[],
            &[],
            &[wg_group],
            &[],
            &[],
        )?;
        assert!(yaml.contains("client_group: warp"));
        assert!(yaml.contains("type: wireguard"));
        assert!(yaml.contains("engage.cloudflareclient.com:2408"));
        assert!(yaml.contains("bind_interface: eth0"));
        assert!(yaml.contains("mtu: 1280"));
        assert!(yaml.contains("persistent_keepalive: 25"));
        assert!(yaml.contains("tcp_buffer_size: 262144"));
        assert!(yaml.contains("tcp_memory_bytes: 268435456"));
        Ok(())
    }

    #[tokio::test]
    async fn protocol_completions_vless_enc_mldsa65_portrange_portforward_shadowtls_pass_real_shoes_check()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);
        let settings = db.get_settings()?;
        let shoes_bin = std::path::PathBuf::from(&settings.shoes_bin_path);
        anyhow::ensure!(
            shoes_bin.is_file(),
            "shoes binary not found at {}",
            shoes_bin.display()
        );

        // 1. Generate real VLESS native encryption credentials (ML-KEM-768, native, 0-RTT)
        let enc_out = tokio::process::Command::new(&shoes_bin)
            .args([
                "generate-vless-encryption",
                "--auth",
                "mlkem768",
                "--mode",
                "native",
                "--rtt",
                "0rtt",
                "--lifetime",
                "600s",
            ])
            .output()
            .await?;
        anyhow::ensure!(enc_out.status.success(), "generate-vless-encryption failed");
        let enc_stdout = String::from_utf8_lossy(&enc_out.stdout);
        let mut vless_encryption = String::new();
        let mut vless_decryption = String::new();
        for line in enc_stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("encryption:") {
                vless_encryption = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            } else if let Some(rest) = trimmed.strip_prefix("decryption:") {
                vless_decryption = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            }
        }
        assert!(vless_encryption.starts_with("mlkem768x25519plus."));
        assert!(vless_decryption.starts_with("mlkem768x25519plus."));

        // 2. Generate real ML-DSA-65 post-quantum REALITY keypair
        let mldsa_out = tokio::process::Command::new(&shoes_bin)
            .arg("generate-reality-mldsa65-keypair")
            .output()
            .await?;
        anyhow::ensure!(
            mldsa_out.status.success(),
            "generate-reality-mldsa65-keypair failed"
        );
        let mldsa_stdout = String::from_utf8_lossy(&mldsa_out.stdout);
        let mut mldsa65_seed = String::new();
        let mut mldsa65_verify = String::new();
        for line in mldsa_stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("mldsa65_seed:") {
                mldsa65_seed = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            } else if let Some(rest) = trimmed.strip_prefix("mldsa65_verify:") {
                mldsa65_verify = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            }
        }
        assert!(!mldsa65_seed.is_empty());
        assert!(!mldsa65_verify.is_empty());

        // 3. Create self-signed certificate source for Hysteria2
        let (cert_pem, key_pem) =
            crypto_util::generate_self_signed_cert(&["localhost".to_string(), "127.0.0.1".to_string()])?;
        let cert_path = dir.path().join("hy2-self.crt");
        let key_path = dir.path().join("hy2-self.key");
        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, &key_pem)?;
        db.save_certificate(models::CertificateRecord {
            id: 0,
            name: "hy2-self".to_string(),
            cert_type: "files".to_string(),
            domains: vec!["localhost".to_string()],
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            email: String::new(),
            directory_url: String::new(),
            terms_of_service: String::new(),
            challenge_type: "http-01".to_string(),
            http01_listen: String::new(),
            remark: "Test self-signed".to_string(),
            created_at: 0,
        })?;

        // 4. Create Outbound Group with ShadowTLS v3 wrapping Shadowsocks
        db.save_outbound_group(models::OutboundGroupRecord {
            id: 0,
            name: "stls-relay".to_string(),
            enable: true,
            group_type: "selector".to_string(),
            default_member: "hk-stls".to_string(),
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            interval_secs: 300,
            timeout_ms: 5000,
            tolerance_ms: 50,
            members: vec![models::OutboundMember {
                name: "hk-stls".to_string(),
                protocol: "shadowsocks".to_string(),
                address: "198.51.100.55:443".to_string(),
                cipher: "aes-256-gcm".to_string(),
                password: "ss-relay-password".to_string(),
                shadowtls: true,
                shadowtls_password: "stls-outbound-secret".to_string(),
                sni: "www.microsoft.com".to_string(),
                ..Default::default()
            }],
            raw_chains_yaml: String::new(),
            remark: "ShadowTLS v3 relay".to_string(),
        })?;

        // 5a. VLESS + Native Encryption + Native Vision (plain TCP, no outer TLS)
        let mut ib_vless_enc = models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "VLESS-NativeEnc".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39201,
            protocol: "vless".to_string(),
            protocol_settings: models::ProtocolSettings {
                vless_decryption: vless_decryption.clone(),
                vless_encryption: vless_encryption.clone(),
                vless_native_vision: true,
                udp_enabled: true,
                ..Default::default()
            },
            stream_settings: models::StreamSettings {
                network: "tcp".to_string(),
                security: "none".to_string(),
                ..Default::default()
            },
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
        let c1 = db::default_client_for_inbound(&ib_vless_enc, 1);
        ib_vless_enc.clients.push(c1);
        let ib_vless_enc = db.create_inbound(ib_vless_enc)?;

        // 5b. VLESS + REALITY + ML-DSA-65
        let (rk_priv, rk_pub) = crypto_util::generate_reality_keypair();
        let mut ib_mldsa = models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "VLESS-REALITY-MLDSA65".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39202,
            protocol: "vless".to_string(),
            protocol_settings: models::ProtocolSettings {
                udp_enabled: true,
                ..Default::default()
            },
            stream_settings: models::StreamSettings {
                network: "tcp".to_string(),
                security: "reality".to_string(),
                reality: models::RealitySettings {
                    sni: "www.microsoft.com".to_string(),
                    dest: "www.microsoft.com:443".to_string(),
                    private_key: rk_priv,
                    public_key: rk_pub,
                    short_ids: vec!["0123456789abcdef".to_string()],
                    vision: true,
                    fingerprint: "chrome".to_string(),
                    mldsa65_seed: mldsa65_seed.clone(),
                    mldsa65_verify: mldsa65_verify.clone(),
                },
                ..Default::default()
            },
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
        let c2 = db::default_client_for_inbound(&ib_mldsa, 1);
        ib_mldsa.clients.push(c2);
        let ib_mldsa = db.create_inbound(ib_mldsa)?;

        // 5c. Hysteria2 + Port Range Hopping
        let mut ib_hy2 = models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "HY2-Hopping".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39300,
            protocol: "hysteria2".to_string(),
            protocol_settings: models::ProtocolSettings {
                port_range: "39300-39305".to_string(),
                udp_enabled: true,
                ..Default::default()
            },
            stream_settings: models::StreamSettings {
                network: "quic".to_string(),
                security: "tls".to_string(),
                tls: models::TlsSettings {
                    sni: "localhost".to_string(),
                    allow_any_sni: true,
                    cert_mode: "source".to_string(),
                    certificate_source: "hy2-self".to_string(),
                    allow_insecure: true,
                    ..Default::default()
                },
                ..Default::default()
            },
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
        let c3 = db::default_client_for_inbound(&ib_hy2, 1);
        ib_hy2.clients.push(c3);
        let ib_hy2 = db.create_inbound(ib_hy2)?;

        // 5d. PortForward (multi-target round-robin routed via stls-relay, no clients)
        let ib_pf = db.create_inbound(models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "PF-Relay".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39204,
            protocol: "portforward".to_string(),
            protocol_settings: models::ProtocolSettings {
                forward_targets: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
                rules_ref: "stls-relay".to_string(),
                ..Default::default()
            },
            stream_settings: models::StreamSettings {
                network: "tcp".to_string(),
                security: "none".to_string(),
                ..Default::default()
            },
            up_bytes: 0,
            down_bytes: 0,
            total_quota_bytes: 0,
            expiry_time: 0,
            auto_reset_day: 0,
            last_reset_month: String::new(),
            created_at: 0,
            updated_at: 0,
            clients: Vec::new(),
        })?;

        // 5e. Shadowsocks + ShadowTLS v3 (Remote Handshake)
        let mut ib_stls = models::Inbound {
            id: 0,
            tag: String::new(),
            remark: "SS-ShadowTLSv3".to_string(),
            enable: true,
            listen: "127.0.0.1".to_string(),
            port: 39205,
            protocol: "shadowsocks".to_string(),
            protocol_settings: models::ProtocolSettings {
                cipher: "aes-256-gcm".to_string(),
                udp_enabled: true,
                ..Default::default()
            },
            stream_settings: models::StreamSettings {
                network: "tcp".to_string(),
                security: "shadowtls".to_string(),
                shadowtls: models::ShadowTlsSettings {
                    sni: "www.microsoft.com".to_string(),
                    password: "stls-inbound-secret".to_string(),
                    handshake_mode: "remote".to_string(),
                    handshake_addr: "www.microsoft.com:443".to_string(),
                    cert_file: String::new(),
                    key_file: String::new(),
                },
                ..Default::default()
            },
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
        let c5 = db::default_client_for_inbound(&ib_stls, 1);
        ib_stls.clients.push(c5);
        let ib_stls = db.create_inbound(ib_stls)?;

        // 6. Validate entire server YAML via real `shoes check`!
        let yaml = yaml_gen::validated_config(&db, &settings).await?;
        assert!(yaml.contains(&format!("decryption: {vless_decryption}")));
        assert!(yaml.contains(&format!("mldsa65_seed: {mldsa65_seed}")));
        assert!(yaml.contains("127.0.0.1:39300-39305"));
        assert!(yaml.contains("type: portforward"));
        assert!(yaml.contains("127.0.0.1:8080"));
        assert!(yaml.contains("shadowtls_targets:"));
        assert!(yaml.contains("stls-inbound-secret"));
        assert!(yaml.contains("type: shadowtls"));
        assert!(yaml.contains("stls-outbound-secret"));

        // 7. Verify all 4 subscription export formats
        let all_ibs = vec![ib_vless_enc.clone(), ib_mldsa.clone(), ib_hy2.clone(), ib_pf.clone(), ib_stls.clone()];
        let certs = db.list_certificates()?;

        // 7a. Per-node URIs & Shoes client YAML
        let enc_share = sub_gen::build_client_share_info(&ib_vless_enc, &ib_vless_enc.clients[0], "example.com");
        assert!(enc_share.uri.contains("encryption="), "missing encryption= in {}", enc_share.uri);
        assert!(enc_share.uri.contains("flow=xtls-rprx-vision"), "missing native vision flow in {}", enc_share.uri);
        assert!(enc_share.shoes_client_yaml.contains(&vless_encryption));
        assert!(enc_share.shoes_client_yaml.contains("vision: true"));

        let mldsa_share = sub_gen::build_client_share_info(&ib_mldsa, &ib_mldsa.clients[0], "example.com");
        assert!(mldsa_share.uri.contains(&format!("pqv={mldsa65_verify}")), "missing pqv in {}", mldsa_share.uri);
        assert!(mldsa_share.shoes_client_yaml.contains(&format!("mldsa65_verify: {mldsa65_verify}")));

        let hy2_share = sub_gen::build_client_share_info(&ib_hy2, &ib_hy2.clients[0], "example.com");
        assert!(hy2_share.uri.contains("mport=39300-39305"), "missing mport in {}", hy2_share.uri);
        assert!(hy2_share.shoes_client_yaml.contains("hopping:"));
        assert!(hy2_share.shoes_client_yaml.contains("39300-39305"));

        let stls_share = sub_gen::build_client_share_info(&ib_stls, &ib_stls.clients[0], "example.com");
        assert!(stls_share.uri.contains("plugin=shadow-tls"), "missing shadow-tls plugin in {}", stls_share.uri);
        assert!(stls_share.shoes_client_yaml.contains("type: shadowtls"));
        assert!(stls_share.shoes_client_yaml.contains("stls-inbound-secret"));

        // 7b. Validate each exported Shoes client YAML directly with real `shoes check`!
        for (label, snippet) in [
            ("vless-native-enc", &enc_share.shoes_client_yaml),
            ("vless-reality-mldsa65", &mldsa_share.shoes_client_yaml),
            ("hy2-port-hopping", &hy2_share.shoes_client_yaml),
            ("ss-shadowtls-v3", &stls_share.shoes_client_yaml),
        ] {
            let client_cfg_path = dir.path().join(format!("client_{label}.yaml"));
            std::fs::write(&client_cfg_path, snippet)?;
            let cli_check = tokio::process::Command::new(&shoes_bin)
                .args(["check", &client_cfg_path.to_string_lossy()])
                .output()
                .await?;
            anyhow::ensure!(
                cli_check.status.success(),
                "shoes check rejected exported Shoes client config '{label}':\n{}\nYAML:\n{}",
                String::from_utf8_lossy(&cli_check.stderr),
                snippet
            );
        }

        // 7c. Clash / Mihomo YAML export
        let clash_yaml = sub_gen::generate_subscription_with_certs(
            &all_ibs,
            &certs,
            "*",
            "example.com",
            sub_gen::SubFormat::ClashYaml,
        )
        .body;
        assert!(clash_yaml.contains(&vless_encryption));
        assert!(clash_yaml.contains("ports: 39300-39305"));
        assert!(clash_yaml.contains("hop-interval: 30"));
        assert!(clash_yaml.contains("plugin: shadow-tls"));
        assert!(!clash_yaml.contains("PF-Relay"), "portforward must not be exported to Clash");

        // 7d. sing-box JSON export
        let sb_json: serde_json::Value = serde_json::from_str(
            &sub_gen::generate_subscription_with_certs(
                &all_ibs,
                &certs,
                "*",
                "example.com",
                sub_gen::SubFormat::SingBoxJson,
            )
            .body,
        )?;
        let outbounds = sb_json["outbounds"].as_array().unwrap();
        assert!(
            !outbounds.iter().any(|o| o["tag"].as_str().unwrap_or("").contains("VLESS-NativeEnc")),
            "sing-box must omit VLESS native encryption"
        );
        assert!(
            !outbounds.iter().any(|o| o["tag"].as_str().unwrap_or("").contains("PF-Relay")),
            "sing-box must omit portforward"
        );
        let hy2_sb = outbounds.iter().find(|o| o["type"] == "hysteria2").unwrap();
        assert_eq!(hy2_sb["server_ports"], serde_json::json!(["39300:39305"]));
        assert_eq!(hy2_sb["hop_interval"], "30s");
        let stls_detour = outbounds.iter().find(|o| o["type"] == "shadowtls").unwrap();
        assert_eq!(stls_detour["version"], 3);
        assert_eq!(stls_detour["password"], "stls-inbound-secret");
        let ss_sb = outbounds.iter().find(|o| o["type"] == "shadowsocks").unwrap();
        assert_eq!(ss_sb["detour"], stls_detour["tag"]);
        assert!(ss_sb.get("server").is_none());

        // 8. Negative guards
        assert_eq!(
            yaml_gen::normalize_port_range_spec(20000, "20010-20020")?,
            Some("20000,20010-20020".to_string())
        );
        assert!(yaml_gen::normalize_port_range_spec(20000, "20000-25000").is_err());

        let mut bad_fallback = ib_vless_enc.clone();
        bad_fallback.protocol_settings.fallback = "127.0.0.1:80".to_string();
        assert!(yaml_gen::build_shoes_yaml_full(
            dir.path(),
            &settings,
            &certs,
            &[],
            &[],
            &[],
            &[],
            &[bad_fallback],
        )
        .is_err());

        let mut bad_mux = ib_vless_enc.clone();
        bad_mux.stream_settings.h2mux.enabled = true;
        assert!(yaml_gen::build_shoes_yaml_full(
            dir.path(),
            &settings,
            &certs,
            &[],
            &[],
            &[],
            &[],
            &[bad_mux],
        )
        .is_err());

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires live internet access to Let's Encrypt ACME directories"]
    async fn live_letsencrypt_directories_match_tos_and_support_shortlived() -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for url in [
            DEFAULT_LETSENCRYPT_DIR,
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        ] {
            let meta = acme_util::fetch_acme_directory_meta(url).await?;
            assert!(
                meta.terms_of_service.as_deref().is_some_and(|t| t.starts_with("https://letsencrypt.org/documents/")),
                "unexpected ToS from {url}: {:?}",
                meta.terms_of_service
            );
            assert!(
                meta.supports_shortlived,
                "expected Let's Encrypt directory {url} to advertise shortlived profile, got {:?}",
                meta.profiles
            );
        }
        Ok(())
    }
}
