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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer};

use crate::api::build_inner_router;
use crate::db::{normalize_base_path, Database};
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
            if let Some(p) = port_arg {
                db.set_setting_kv("panel_port", &p.to_string())?;
                println!("Updated panel_port = {p}");
            }
            if let Some(bp) = base_path_arg {
                let norm = normalize_base_path(&bp);
                db.set_setting_kv("panel_base_path", &norm)?;
                println!("Updated panel_base_path = {norm}");
            }
            if let Some(bin) = shoes_bin_arg {
                db.set_setting_kv("shoes_bin_path", &bin)?;
                println!("Updated shoes_bin_path = {bin}");
            }
            return Ok(());
        }
        "info" => {
            let s = db.get_settings()?;
            let u = db.get_admin_username()?;
            let scheme = if !s.panel_cert_file.is_empty() {
                "https"
            } else {
                "http"
            };
            println!("==========================================");
            println!("shoes-panel current configuration:");
            println!("  Admin user   : {u}");
            println!("  Listen       : {}:{}", s.panel_listen, s.panel_port);
            println!("  Base path    : {}", s.panel_base_path);
            println!(
                "  URL          : {scheme}://127.0.0.1:{}{}",
                s.panel_port, s.panel_base_path
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

    let settings = db.get_settings()?;
    let proc_mgr = ShoesProcessManager::new(db.clone());
    let monitor = RuntimeMonitor::new(db.clone(), proc_mgr.clone());
    let state = AppState::new(db.clone(), proc_mgr.clone(), monitor);

    // Ensure initial shoes.config.yaml is generated and optionally auto-start shoes
    if let Err(e) = yaml_gen::sync_and_apply_config(&db, None).await {
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
            if path.starts_with("/sub/") {
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

    let bind_str = format!("{}:{}", settings.panel_listen.trim(), settings.panel_port);
    let addr: SocketAddr = bind_str
        .parse()
        .with_context(|| format!("invalid panel bind address '{bind_str}'"))?;

    let scheme =
        if !settings.panel_cert_file.trim().is_empty() && !settings.panel_key_file.trim().is_empty()
        {
            "https"
        } else {
            "http"
        };

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
            "proxy.example.com",
            sub_gen::SubFormat::ClashYaml,
        );
        assert!(clash_sub.body.contains("VLESS-Reality"));
        assert!(clash_sub.body.contains("Hy2-Node"));

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
}
