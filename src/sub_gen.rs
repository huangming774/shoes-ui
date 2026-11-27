use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping, Value as YamlValue};

use crate::crypto_util::derive_reality_public_key;
use crate::models::{
    CertificateRecord, ClientRecord, H2MuxSettings, Inbound, SubscriptionTemplateConfig,
};

/// RFC 3986 query value encode set: preserves unreserved chars (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`)
/// and `/`, encoding only controls, spaces, and query/URI delimiters (`#`, `%`, `&`, `+`, `=`, `?`).
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'=')
    .add(b'?')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// RFC 3986 userinfo encode set: preserves `-`, `.`, `_`, `~`, encodes `@`, `:`, `/`, `?`, `#`, `%`, etc.
const USERINFO_ENCODE_SET: &AsciiSet = &QUERY_ENCODE_SET
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|');

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFormat {
    V2rayBase64,
    ClashYaml,
    SingBoxJson,
    RawUris,
}

impl SubFormat {
    pub fn detect(query_format: Option<&str>, user_agent: Option<&str>) -> Self {
        if let Some(q) = query_format {
            match q.trim().to_lowercase().as_str() {
                "clash" | "mihomo" | "stash" | "yaml" => return Self::ClashYaml,
                "singbox" | "sing-box" | "sfa" | "sfi" | "json" => return Self::SingBoxJson,
                "raw" | "plain" | "uri" => return Self::RawUris,
                "v2ray" | "base64" | "shadowrocket" => return Self::V2rayBase64,
                _ => {}
            }
        }
        if let Some(ua) = user_agent {
            let ua_l = ua.to_lowercase();
            if ua_l.contains("clash")
                || ua_l.contains("mihomo")
                || ua_l.contains("stash")
                || ua_l.contains("verge")
                || ua_l.contains("flclash")
            {
                return Self::ClashYaml;
            }
            if ua_l.contains("sing-box") || ua_l.contains("sfa") || ua_l.contains("sfi") {
                return Self::SingBoxJson;
            }
        }
        Self::V2rayBase64
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareInfo {
    pub name: String,
    pub protocol: String,
    pub uri: String,
    pub shoes_client_yaml: String,
}

#[derive(Debug, Clone)]
pub struct SubscriptionPayload {
    pub content_type: &'static str,
    pub body: String,
    pub userinfo_header: String,
}

fn enc_query(s: &str) -> String {
    utf8_percent_encode(s, QUERY_ENCODE_SET).to_string()
}

fn enc_path_param(s: &str) -> String {
    // Encode `&`, `?`, `#`, `%`, `=`, `+`, space, while keeping `/` or encoding `/` cleanly?
    // Standard Xray/Shadowrocket URI query `path=%2Fws` works everywhere, while UUID/SNI/pbk stay unescaped!
    const PATH_SET: &AsciiSet = &QUERY_ENCODE_SET.add(b'/');
    utf8_percent_encode(s, PATH_SET).to_string()
}

fn enc_userinfo(s: &str) -> String {
    utf8_percent_encode(s, USERINFO_ENCODE_SET).to_string()
}

fn enc_fragment(s: &str) -> String {
    utf8_percent_encode(s, USERINFO_ENCODE_SET).to_string()
}

fn format_host(host: &str) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') {
        format!("[{h}]")
    } else {
        h.to_string()
    }
}

fn node_display_name(ib: &Inbound, c: &ClientRecord) -> String {
    if ib.supports_multi_user() && c.name.trim() != ib.remark.trim() && !c.name.trim().is_empty() {
        format!("{}-{}", ib.remark.trim(), c.name.trim())
    } else if !ib.remark.trim().is_empty() {
        ib.remark.trim().to_string()
    } else {
        c.name.trim().to_string()
    }
}

fn effective_reality_pubkey(ib: &Inbound) -> String {
    let explicit = ib.stream_settings.reality.public_key.trim();
    if !explicit.is_empty() {
        explicit.to_string()
    } else {
        derive_reality_public_key(&ib.stream_settings.reality.private_key).unwrap_or_default()
    }
}

/// Resolves effective TLS SNI: if user left SNI empty on a self-signed (`allow_insecure`) inbound,
/// fallback to `"localhost"` (which matches our generated self-signed cert SAN) so QUIC/TLS clients don't fail on empty SNI.
/// RFC 6066 forbids literal IP addresses in TLS SNI, so IP-valued SNIs return empty string
/// (clients validate the certificate's IP SAN directly against the server IP).
fn effective_tls_sni(ib: &Inbound) -> String {
    if ib.uses_auto_quic_cert() {
        return "localhost".into();
    }
    let sni = ib.stream_settings.tls.sni.trim();
    if !sni.is_empty() {
        if sni.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
            return String::new();
        }
        sni.to_string()
    } else if ib.stream_settings.tls.allow_insecure {
        "localhost".to_string()
    } else {
        String::new()
    }
}

pub fn build_wireguard_peer_conf(ib: &Inbound, c: &ClientRecord, host: &str) -> String {
    let ps = &ib.protocol_settings;
    let server_pub = if !ps.wg_server_public_key.trim().is_empty() {
        ps.wg_server_public_key.trim().to_string()
    } else if !ps.wg_server_private_key.trim().is_empty() {
        crate::crypto_util::derive_wireguard_public_key(&ps.wg_server_private_key)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let priv_key = if c.wg_private_key.trim().is_empty() {
        "<YOUR_CLIENT_PRIVATE_KEY>"
    } else {
        c.wg_private_key.trim()
    };
    let addrs = if c.wg_allowed_ips.trim().is_empty() {
        "10.77.0.2/32"
    } else {
        c.wg_allowed_ips.trim()
    };
    let dns = if ps.wg_dns.trim().is_empty() {
        "1.1.1.1"
    } else {
        ps.wg_dns.trim()
    };
    let mtu = if ps.wg_mtu > 0 { ps.wg_mtu } else { 1408 };
    let endpoint = format!("{}:{}", format_host(host), ib.port);
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {priv_key}"),
        format!("Address = {addrs}"),
        format!("DNS = {dns}"),
        format!("MTU = {mtu}"),
        String::new(),
        "[Peer]".to_string(),
        format!("PublicKey = {server_pub}"),
    ];
    if !c.wg_preshared_key.trim().is_empty() {
        lines.push(format!("PresharedKey = {}", c.wg_preshared_key.trim()));
    }
    lines.push(format!("Endpoint = {endpoint}"));
    lines.push("AllowedIPs = 0.0.0.0/0, ::/0".to_string());
    if c.wg_keepalive > 0 {
        lines.push(format!("PersistentKeepalive = {}", c.wg_keepalive));
    }
    lines.join("\n")
}

pub fn build_client_share_info(ib: &Inbound, c: &ClientRecord, host: &str) -> ShareInfo {
    let name = node_display_name(ib, c);
    let uri = if ib.protocol == "wireguard" {
        build_wireguard_peer_conf(ib, c, host)
    } else {
        build_uri(ib, c, host, &name)
    };
    let shoes_client_yaml = build_shoes_client_snippet(ib, c, host, &name);
    ShareInfo {
        name,
        protocol: ib.protocol.clone(),
        uri,
        shoes_client_yaml,
    }
}

fn effective_snell_cipher(ib: &Inbound) -> &str {
    let c = ib.protocol_settings.cipher.trim();
    if c.is_empty() {
        "aes-128-gcm"
    } else {
        c
    }
}

fn has_non_host_ws_headers(ib: &Inbound) -> bool {
    ib.stream_settings
        .ws
        .headers
        .keys()
        .any(|key| !key.eq_ignore_ascii_case("host"))
}

/// Reads the inbound's public TLS certificate PEM (never private keys) so strict TLS
/// clients like sing-box NaiveProxy (Cronet) can pin self-signed certs cleanly.
fn resolve_inbound_cert_pem(
    ib: &Inbound,
    certs: &[CertificateRecord],
    cert_pems: Option<&std::collections::HashMap<String, String>>,
) -> Option<String> {
    let tls = &ib.stream_settings.tls;
    if let Some(pems) = cert_pems {
        if tls.cert_mode == "source" && !tls.certificate_source.trim().is_empty() {
            if let Some(pem) = pems.get(tls.certificate_source.trim()) {
                if pem.contains("-----BEGIN CERTIFICATE-----") {
                    return Some(pem.trim().to_string());
                }
            }
        }
        if !tls.cert_file.trim().is_empty() {
            if let Some(pem) = pems.get(tls.cert_file.trim()) {
                if pem.contains("-----BEGIN CERTIFICATE-----") {
                    return Some(pem.trim().to_string());
                }
            }
        }
    }
    let cert_path = if tls.cert_mode == "files" && !tls.cert_file.trim().is_empty() {
        tls.cert_file.trim().to_string()
    } else if tls.cert_mode == "source" && !tls.certificate_source.trim().is_empty() {
        certs
            .iter()
            .find(|c| {
                c.name.trim() == tls.certificate_source.trim()
                    && matches!(c.cert_type.as_str(), "files" | "acme_ip")
            })
            .map(|c| c.cert_file.trim().to_string())
            .filter(|p| !p.is_empty())?
    } else {
        return None;
    };
    let pem = std::fs::read_to_string(&cert_path).ok()?;
    if pem.contains("-----BEGIN CERTIFICATE-----") {
        Some(pem.trim().to_string())
    } else {
        None
    }
}

/// Collects public TLS certificate PEMs referenced by enabled inbounds (never private keys)
/// for inclusion in read-only cluster export snapshots.
pub fn collect_public_cert_pems(
    inbounds: &[Inbound],
    certs: &[CertificateRecord],
) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for ib in inbounds
        .iter()
        .filter(|i| i.enable && i.stream_settings.tls.allow_insecure)
    {
        if let Some(pem) = resolve_inbound_cert_pem(ib, certs, None) {
            let tls = &ib.stream_settings.tls;
            if tls.cert_mode == "source" && !tls.certificate_source.trim().is_empty() {
                out.insert(tls.certificate_source.trim().to_string(), pem.clone());
            }
            if !tls.cert_file.trim().is_empty() {
                out.insert(tls.cert_file.trim().to_string(), pem);
            }
        }
    }
    out
}

fn extract_pem_cert_raw(pem: &str) -> Option<String> {
    let mut in_cert = false;
    let mut body = String::new();
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            continue;
        }
        if trimmed == "-----END CERTIFICATE-----" {
            if !body.is_empty() {
                return Some(body);
            }
            return None;
        }
        if in_cert {
            body.push_str(trimmed);
        }
    }
    None
}

fn can_export_uri_transport(ib: &Inbound) -> bool {
    let ss = &ib.stream_settings;
    if ss.sudoku.enabled {
        return false;
    }
    match ib.protocol.as_str() {
        "portforward" | "wireguard" => false,
        "tuic" | "hysteria2" => true,
        "snell" => {
            ss.network == "tcp"
                && ss.security == "none"
                && matches!(
                    effective_snell_cipher(ib),
                    "aes-128-gcm" | "chacha20-ietf-poly1305"
                )
        }
        "shadowsocks" => {
            (ss.network == "tcp" && matches!(ss.security.as_str(), "none" | "shadowtls"))
                || (ss.network == "ws"
                    && matches!(ss.security.as_str(), "none" | "tls")
                    && !has_non_host_ws_headers(ib))
        }
        "vless" => ss.security != "shadowtls" && matches!(ss.network.as_str(), "tcp" | "ws" | "xhttp"),
        "vmess" | "trojan" => ss.security != "shadowtls" && matches!(ss.network.as_str(), "tcp" | "ws"),
        _ => ss.network == "tcp" && ss.security != "shadowtls",
    }
}

pub fn build_uri(ib: &Inbound, c: &ClientRecord, host: &str, name: &str) -> String {
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let addr = format_host(host);
    let port = ib.port;
    let tag = enc_fragment(name);

    if !can_export_uri_transport(ib)
        || (ss.network == "ws" && has_non_host_ws_headers(ib))
        || (ss.security == "reality" && matches!(ib.protocol.as_str(), "vmess" | "naiveproxy"))
        || (ss.security == "tls" && matches!(ib.protocol.as_str(), "socks" | "mixed"))
    {
        return String::new();
    }

    match ib.protocol.as_str() {
        "vless" => {
            let mut params = Vec::new();
            let has_vless_enc = ib.has_vless_native_encryption();
            if has_vless_enc && !ps.vless_encryption.trim().is_empty() {
                params.push(format!("encryption={}", enc_query(ps.vless_encryption.trim())));
            } else {
                params.push("encryption=none".to_string());
            }
            let net = match ss.network.as_str() {
                "ws" => "ws",
                "xhttp" => "xhttp",
                _ => "tcp",
            };

            if has_vless_enc && ps.vless_native_vision {
                params.push("flow=xtls-rprx-vision".to_string());
            }

            if ss.security == "reality" {
                if !has_vless_enc && ss.network == "tcp" && ss.reality.vision {
                    params.push("flow=xtls-rprx-vision".to_string());
                }
                params.push("security=reality".to_string());
                if !ss.reality.sni.trim().is_empty() {
                    params.push(format!("sni={}", enc_query(ss.reality.sni.trim())));
                }
                let fp = if ss.reality.fingerprint.trim().is_empty() {
                    "chrome"
                } else {
                    ss.reality.fingerprint.trim()
                };
                params.push(format!("fp={}", enc_query(fp)));
                let pbk = effective_reality_pubkey(ib);
                params.push(format!("pbk={}", enc_query(&pbk)));
                if let Some(sid) = ss.reality.short_ids.first() {
                    if !sid.trim().is_empty() {
                        params.push(format!("sid={}", enc_query(sid.trim())));
                    }
                }
                if !ss.reality.mldsa65_verify.trim().is_empty() {
                    params.push(format!("pqv={}", enc_query(ss.reality.mldsa65_verify.trim())));
                }
            } else if ss.security == "tls" {
                if !has_vless_enc && ss.network == "tcp" && ss.tls.vision {
                    params.push("flow=xtls-rprx-vision".to_string());
                }
                params.push("security=tls".to_string());
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    params.push(format!("sni={}", enc_query(&sni)));
                }
                if !ss.tls.fingerprint.trim().is_empty() {
                    params.push(format!("fp={}", enc_query(ss.tls.fingerprint.trim())));
                }
                if !ss.tls.alpn.is_empty() {
                    params.push(format!("alpn={}", enc_path_param(&ss.tls.alpn.join(","))));
                }
                if ss.tls.allow_insecure {
                    params.push("allowInsecure=1".to_string());
                }
            } else {
                params.push("security=none".to_string());
            }

            params.push(format!("type={net}"));
            if net == "tcp" {
                params.push("headerType=none".to_string());
            } else if net == "ws" {
                params.push(format!("path={}", enc_path_param(ss.ws.path.trim())));
                if !ss.ws.host_header().is_empty() {
                    params.push(format!("host={}", enc_query(ss.ws.host_header())));
                }
            } else if net == "xhttp" {
                params.push(format!("path={}", enc_path_param(ss.xhttp.path.trim())));
                if !ss.xhttp.host.trim().is_empty() {
                    params.push(format!("host={}", enc_query(ss.xhttp.host.trim())));
                }
                if !ss.xhttp.mode.trim().is_empty() {
                    params.push(format!("mode={}", enc_query(ss.xhttp.mode.trim())));
                }
                if !ss.xhttp.headers.is_empty() {
                    let extra = json!({ "headers": ss.xhttp.headers }).to_string();
                    params.push(format!("extra={}", utf8_percent_encode(&extra, percent_encoding::NON_ALPHANUMERIC)));
                }
            }

            format!(
                "vless://{}@{}:{}?{}#{}",
                c.uuid.trim(),
                addr,
                port,
                params.join("&"),
                tag
            )
        }
        "vmess" => {
            let cipher = match ps.cipher.trim() {
                "" | "any" | "auto" => "aes-128-gcm",
                other => other,
            };
            let net = if ss.network == "ws" { "ws" } else { "tcp" };
            let tls_str = if ss.security == "tls" { "tls" } else { "" };
            let host_hdr = if net == "ws" {
                ss.ws.host_header()
            } else {
                ""
            };
            let path_str = if net == "ws" {
                ss.ws.path.trim()
            } else {
                ""
            };
            let sni = effective_tls_sni(ib);
            let vmess_obj = json!({
                "v": "2",
                "ps": name,
                "add": host.trim(),
                "port": port.to_string(),
                "id": c.uuid.trim(),
                "aid": "0",
                "scy": cipher,
                "net": net,
                "type": "none",
                "host": host_hdr,
                "path": path_str,
                "tls": tls_str,
                "sni": sni,
                "alpn": ss.tls.alpn.join(","),
                "fp": ss.tls.fingerprint.trim(),
                "allowInsecure": if ss.tls.allow_insecure { 1 } else { 0 },
            });
            format!(
                "vmess://{}",
                STANDARD.encode(serde_json::to_string(&vmess_obj).unwrap_or_default())
            )
        }
        "trojan" => {
            let mut params = Vec::new();
            let net = if ss.network == "ws" { "ws" } else { "tcp" };
            params.push(format!("type={net}"));
            if ss.security == "reality" {
                params.push("security=reality".to_string());
                let pbk = effective_reality_pubkey(ib);
                params.push(format!("pbk={}", enc_query(&pbk)));
                let fp = if ss.reality.fingerprint.trim().is_empty() {
                    "chrome"
                } else {
                    ss.reality.fingerprint.trim()
                };
                params.push(format!("fp={}", enc_query(fp)));
                if !ss.reality.sni.trim().is_empty() {
                    params.push(format!("sni={}", enc_query(ss.reality.sni.trim())));
                }
                if let Some(sid) = ss.reality.short_ids.first() {
                    if !sid.trim().is_empty() {
                        params.push(format!("sid={}", enc_query(sid.trim())));
                    }
                }
            } else if ss.security == "tls" {
                params.push("security=tls".to_string());
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    params.push(format!("sni={}", enc_query(&sni)));
                    params.push(format!("peer={}", enc_query(&sni)));
                }
                if ss.tls.allow_insecure {
                    params.push("allowInsecure=1".to_string());
                }
            } else {
                params.push("security=none".to_string());
            }
            if ss.network == "ws" {
                params.push(format!("path={}", enc_path_param(ss.ws.path.trim())));
                if !ss.ws.host_header().is_empty() {
                    params.push(format!("host={}", enc_query(ss.ws.host_header())));
                }
            }
            format!(
                "trojan://{}@{}:{}?{}#{}",
                enc_userinfo(c.password.trim()),
                addr,
                port,
                params.join("&"),
                tag
            )
        }
        "shadowsocks" => {
            let cipher = if ps.cipher.trim().is_empty() {
                "2022-blake3-aes-256-gcm"
            } else if ps.cipher.trim() == "2022-blake3-chacha20-ietf-poly1305" {
                "2022-blake3-chacha20-poly1305"
            } else {
                ps.cipher.trim()
            };
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{cipher}:{}", c.password.trim()));
            if ss.network == "ws" {
                let mut opts = vec!["v2ray-plugin".to_string(), "mode=websocket".to_string(), "mux=0".to_string()];
                if ss.security == "tls" {
                    opts.push("tls".to_string());
                }
                let ws_host = ss.ws.host_header();
                let sni = effective_tls_sni(ib);
                let host_val = if !ws_host.is_empty() { ws_host } else { sni.as_str() };
                if !host_val.is_empty() {
                    opts.push(format!("host={host_val}"));
                }
                let path = ss.ws.path.trim();
                if !path.is_empty() {
                    opts.push(format!("path={path}"));
                }
                let plugin_param = enc_userinfo(&opts.join(";"));
                format!("ss://{userinfo}@{addr}:{port}/?plugin={plugin_param}#{tag}")
            } else if ss.security == "shadowtls" {
                let st = &ss.shadowtls;
                let opts = format!(
                    "shadow-tls;host={};password={};version=3",
                    st.sni.trim(),
                    st.password.trim()
                );
                let plugin_param = enc_userinfo(&opts);
                format!("ss://{userinfo}@{addr}:{port}/?plugin={plugin_param}#{tag}")
            } else {
                format!("ss://{userinfo}@{addr}:{port}#{tag}")
            }
        }
        "hysteria2" => {
            let mut params = Vec::new();
            if let Ok(Some(mport)) = crate::yaml_gen::normalize_port_range_spec(ib.port, &ps.port_range) {
                params.push(format!("mport={}", enc_query(&mport)));
            }
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                params.push(format!("sni={}", enc_query(&sni)));
                // Shadowrocket compatibility alias
                params.push(format!("peer={}", enc_query(&sni)));
            }
            if ss.tls.allow_insecure {
                params.push("insecure=1".to_string());
            }
            let q = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "hysteria2://{}@{}:{}{}#{}",
                enc_userinfo(c.password.trim()),
                addr,
                port,
                q,
                tag
            )
        }
        "tuic" => {
            let mut params = vec![
                "congestion_control=bbr".to_string(),
                "udp_relay_mode=native".to_string(),
                "alpn=h3".to_string(),
            ];
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                params.push(format!("sni={}", enc_query(&sni)));
            }
            if ss.tls.allow_insecure {
                params.push("allow_insecure=1".to_string());
                params.push("insecure=1".to_string());
            }
            format!(
                "tuic://{}:{}@{}:{}?{}#{}",
                c.uuid.trim(),
                enc_userinfo(c.password.trim()),
                addr,
                port,
                params.join("&"),
                tag
            )
        }
        "anytls" => {
            let mut params = Vec::new();
            if ss.security == "reality" {
                params.push("security=reality".to_string());
                let pbk = effective_reality_pubkey(ib);
                params.push(format!("pbk={}", enc_query(&pbk)));
                if !ss.reality.sni.trim().is_empty() {
                    params.push(format!("sni={}", enc_query(ss.reality.sni.trim())));
                }
                if let Some(sid) = ss.reality.short_ids.first() {
                    if !sid.trim().is_empty() {
                        params.push(format!("sid={}", enc_query(sid.trim())));
                    }
                }
            } else {
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    params.push(format!("sni={}", enc_query(&sni)));
                    params.push(format!("peer={}", enc_query(&sni)));
                }
                if ss.tls.allow_insecure {
                    params.push("insecure=1".to_string());
                }
            }
            let q = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            format!(
                "anytls://{}@{}:{}{}#{}",
                enc_userinfo(c.password.trim()),
                addr,
                port,
                q,
                tag
            )
        }
        "naiveproxy" => {
            let uname = if c.username.trim().is_empty() {
                c.name.trim()
            } else {
                c.username.trim()
            };
            let sni_host = if !ss.tls.sni.trim().is_empty() {
                format_host(ss.tls.sni.trim())
            } else {
                addr
            };
            format!(
                "naive+https://{}:{}@{}:{}?padding=true#{}",
                enc_userinfo(uname),
                enc_userinfo(c.password.trim()),
                sni_host,
                port,
                tag
            )
        }
        "snell" => {
            let version = match effective_snell_cipher(ib) {
                "chacha20-ietf-poly1305" => 1,
                _ => 3,
            };
            format!(
                "{} = snell, {}, {}, psk={}, version={}, reuse=true",
                name,
                host.trim(),
                port,
                c.password.trim(),
                version
            )
        }
        "socks" | "mixed" => {
            if !c.username.trim().is_empty() && !c.password.trim().is_empty() {
                let auth =
                    URL_SAFE_NO_PAD.encode(format!("{}:{}", c.username.trim(), c.password.trim()));
                format!("socks://{auth}@{addr}:{port}#{tag}")
            } else {
                format!("socks://{addr}:{port}#{tag}")
            }
        }
        "http" => {
            let scheme = if ss.security == "tls" { "https" } else { "http" };
            if !c.username.trim().is_empty() && !c.password.trim().is_empty() {
                format!(
                    "{scheme}://{}:{}@{addr}:{port}#{tag}",
                    enc_userinfo(c.username.trim()),
                    enc_userinfo(c.password.trim())
                )
            } else {
                format!("{scheme}://{addr}:{port}#{tag}")
            }
        }
        _ => String::new(),
    }
}

fn inbound_effective_h2mux(ib: &Inbound) -> Option<&H2MuxSettings> {
    let mux = &ib.stream_settings.h2mux;
    if mux.enabled && ib.supports_h2mux() && !ib.has_vless_vision() {
        Some(mux)
    } else {
        None
    }
}

fn build_shoes_h2mux_json(mux: &H2MuxSettings) -> JsonValue {
    let mut obj = serde_json::Map::new();
    if mux.max_connections > 0 {
        obj.insert("max_connections".to_string(), json!(mux.max_connections));
    }
    if mux.min_streams > 0 {
        obj.insert("min_streams".to_string(), json!(mux.min_streams));
    }
    if mux.max_streams > 0 {
        obj.insert("max_streams".to_string(), json!(mux.max_streams));
    }
    if mux.padding {
        obj.insert("padding".to_string(), json!(true));
    }
    JsonValue::Object(obj)
}

fn build_clash_smux_json(mux: &H2MuxSettings) -> JsonValue {
    let mut obj = json!({
        "enabled": true,
        "protocol": "h2mux",
        "padding": mux.padding,
    });
    if mux.max_streams > 0 {
        obj["max-streams"] = json!(mux.max_streams);
    } else {
        obj["max-connections"] = json!(mux.max_connections.max(1));
        obj["min-streams"] = json!(mux.min_streams.max(1));
    }
    obj
}

fn build_singbox_multiplex_json(mux: &H2MuxSettings) -> JsonValue {
    let mut obj = json!({
        "enabled": true,
        "protocol": "h2mux",
        "padding": mux.padding,
    });
    if mux.max_streams > 0 {
        obj["max_streams"] = json!(mux.max_streams);
    } else {
        obj["max_connections"] = json!(mux.max_connections.max(1));
        obj["min_streams"] = json!(mux.min_streams.max(1));
    }
    obj
}

fn build_shoes_client_snippet(ib: &Inbound, c: &ClientRecord, host: &str, name: &str) -> String {
    if ib.protocol == "portforward" {
        return String::new();
    }
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let target_addr = format!("{}:{}", format_host(host), ib.port);

    if ib.protocol == "wireguard" {
        let server_pub = if !ps.wg_server_public_key.trim().is_empty() {
            ps.wg_server_public_key.trim().to_string()
        } else if !ps.wg_server_private_key.trim().is_empty() {
            crate::crypto_util::derive_wireguard_public_key(&ps.wg_server_private_key)
                .unwrap_or_default()
        } else {
            String::new()
        };
        let addrs: Vec<String> = c
            .wg_allowed_ips
            .split([',', ';', ' ', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let mut wg_proto = json!({
            "type": "wireguard",
            "private_key": if c.wg_private_key.trim().is_empty() { "<YOUR_CLIENT_PRIVATE_KEY>" } else { c.wg_private_key.trim() },
            "public_key": server_pub,
            "addresses": if addrs.is_empty() { vec!["10.77.0.2/32".to_string()] } else { addrs },
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "mtu": if ps.wg_mtu > 0 { ps.wg_mtu } else { 1408 },
        });
        if !c.wg_preshared_key.trim().is_empty() {
            wg_proto["pre_shared_key"] = json!(c.wg_preshared_key.trim());
        }
        if c.wg_keepalive > 0 {
            wg_proto["persistent_keepalive"] = json!(c.wg_keepalive);
        }
        let full = json!([
            {
                "address": "127.0.0.1:1080",
                "protocol": { "type": "mixed", "udp_enabled": true },
                "rules": [
                    {
                        "masks": "0.0.0.0/0",
                        "action": "allow",
                        "client_chain": {
                            "name": name,
                            "address": target_addr,
                            "protocol": wg_proto
                        }
                    }
                ]
            }
        ]);
        return serde_yaml::to_string(&full).unwrap_or_default();
    }

    let active_mux = inbound_effective_h2mux(ib);
    let has_vless_enc = ib.has_vless_native_encryption();

    let inner = match ib.protocol.as_str() {
        "vless" => {
            let mut m = json!({"type": "vless", "user_id": c.uuid.trim()});
            if has_vless_enc && !ps.vless_encryption.trim().is_empty() {
                m["encryption"] = json!(ps.vless_encryption.trim());
                if ps.vless_native_vision {
                    m["vision"] = json!(true);
                }
            }
            if let Some(mux) = active_mux {
                m["h2mux"] = build_shoes_h2mux_json(mux);
            }
            m
        }
        "vmess" => {
            let cipher = match ps.cipher.trim() {
                "" | "any" | "auto" => "aes-128-gcm",
                other => other,
            };
            let mut m = json!({"type": "vmess", "cipher": cipher, "user_id": c.uuid.trim()});
            if let Some(mux) = active_mux {
                m["h2mux"] = build_shoes_h2mux_json(mux);
            }
            m
        }
        "trojan" => {
            let mut m = json!({"type": "trojan", "password": c.password.trim()});
            if let Some(mux) = active_mux {
                m["h2mux"] = build_shoes_h2mux_json(mux);
            }
            m
        }
        "shadowsocks" => {
            let cipher = if ps.cipher.trim().is_empty() {
                "2022-blake3-aes-256-gcm"
            } else if ps.cipher.trim() == "2022-blake3-chacha20-ietf-poly1305" {
                "2022-blake3-chacha20-poly1305"
            } else {
                ps.cipher.trim()
            };
            json!({"type": "shadowsocks", "cipher": cipher, "password": c.password.trim()})
        }
        "hysteria2" => {
            let mut m = json!({"type": "hysteria2", "password": c.password.trim(), "udp_enabled": true});
            if let Ok(Some(ports)) = crate::yaml_gen::normalize_port_range_spec(ib.port, &ps.port_range) {
                m["hopping"] = json!({"ports": ports, "interval_secs": 30});
            }
            m
        }
        "tuic" => {
            json!({"type": "tuic", "uuid": c.uuid.trim(), "password": c.password.trim(), "udp_enabled": true})
        }
        "anytls" => json!({"type": "anytls", "password": c.password.trim(), "udp_enabled": true}),
        "naiveproxy" => {
            let uname = if c.username.trim().is_empty() {
                c.name.trim()
            } else {
                c.username.trim()
            };
            json!({"type": "naiveproxy", "username": uname, "password": c.password.trim()})
        }
        "snell" => {
            let cipher = effective_snell_cipher(ib);
            json!({"type": "snell", "cipher": cipher, "password": c.password.trim()})
        }
        "socks" | "mixed" => {
            let mut m = json!({"type": "socks"});
            if !c.username.trim().is_empty() {
                m["username"] = json!(c.username.trim());
                m["password"] = json!(c.password.trim());
            }
            m
        }
        _ => {
            let mut m = json!({"type": "http"});
            if !c.username.trim().is_empty() {
                m["username"] = json!(c.username.trim());
                m["password"] = json!(c.password.trim());
            }
            m
        }
    };

    let transported = if !ib.is_quic() && ss.network == "ws" {
        let mut ws = json!({"type": "websocket", "protocol": inner});
        if !ss.ws.path.trim().is_empty() {
            ws["matching_path"] = json!(ss.ws.path.trim());
        }
        let headers = ss.ws.matching_headers();
        if !headers.is_empty() {
            ws["matching_headers"] = json!(headers);
        }
        if ss.ws.max_early_data > 0 {
            ws["max_early_data"] = json!(ss.ws.max_early_data);
            if !ss.ws.early_data_header_name.trim().is_empty() {
                ws["early_data_header_name"] = json!(ss.ws.early_data_header_name.trim());
            }
        }
        ws
    } else if !ib.is_quic() && ss.network == "xhttp" {
        let mut xhttp = json!({
            "type": "xhttp",
            "mode": if ss.xhttp.mode.trim().is_empty() { "auto" } else { ss.xhttp.mode.trim() },
            "protocol": inner
        });
        if !ss.xhttp.path.trim().is_empty() {
            xhttp["path"] = json!(ss.xhttp.path.trim());
        }
        if !ss.xhttp.host.trim().is_empty() {
            xhttp["host"] = json!(ss.xhttp.host.trim());
        }
        if !ss.xhttp.headers.is_empty() {
            xhttp["headers"] = json!(ss.xhttp.headers);
        }
        xhttp
    } else {
        inner
    };

    let mut client_hop = if ib.is_quic() {
        let mut sni = effective_tls_sni(ib);
        if sni.is_empty() {
            sni = host.trim().to_string();
        }
        let mut qcfg = json!({
            "alpn_protocols": if ss.tls.alpn.is_empty() { json!(["h3"]) } else { json!(ss.tls.alpn) },
            "sni_hostname": sni,
            "verify": !ss.tls.allow_insecure
        });
        if !ss.tls.key_exchange_groups.is_empty() {
            qcfg["key_exchange_groups"] = json!(ss.tls.key_exchange_groups);
        }
        json!({
            "name": name,
            "address": target_addr,
            "transport": "quic",
            "quic_settings": qcfg,
            "protocol": transported
        })
    } else if ss.security == "reality" {
        let pbk = effective_reality_pubkey(ib);
        let sid = ss
            .reality
            .short_ids
            .first()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let vision = ib.protocol == "vless" && ss.network == "tcp" && ss.reality.vision && !has_vless_enc;
        let mut hop = json!({
            "name": name,
            "address": target_addr,
            "protocol": {
                "type": "reality",
                "public_key": pbk,
                "short_id": sid,
                "sni_hostname": ss.reality.sni.trim(),
                "vision": vision,
                "protocol": transported
            }
        });
        if !ss.reality.mldsa65_verify.trim().is_empty() {
            hop["protocol"]["mldsa65_verify"] = json!(ss.reality.mldsa65_verify.trim());
        }
        hop
    } else if ss.security == "tls" {
        let vision = ib.protocol == "vless" && ss.network == "tcp" && ss.tls.vision && !has_vless_enc;
        let mut sni = effective_tls_sni(ib);
        if sni.is_empty() {
            sni = host.trim().to_string();
        }
        let mut hop = json!({
            "name": name,
            "address": target_addr,
            "protocol": {
                "type": "tls",
                "sni_hostname": sni,
                "verify": !ss.tls.allow_insecure,
                "vision": vision,
                "protocol": transported
            }
        });
        if !ss.tls.key_exchange_groups.is_empty() {
            hop["protocol"]["key_exchange_groups"] = json!(ss.tls.key_exchange_groups);
        }
        if ib.protocol == "naiveproxy" {
            hop["protocol"]["alpn_protocols"] = json!(["h2", "http/1.1"]);
        } else if !ss.tls.alpn.is_empty() {
            hop["protocol"]["alpn_protocols"] = json!(ss.tls.alpn);
        }
        hop
    } else if ss.security == "shadowtls" {
        json!({
            "name": name,
            "address": target_addr,
            "protocol": {
                "type": "shadowtls",
                "password": ss.shadowtls.password.trim(),
                "sni_hostname": ss.shadowtls.sni.trim(),
                "protocol": transported
            }
        })
    } else {
        json!({
            "name": name,
            "address": target_addr,
            "protocol": transported
        })
    };

    // Wrap outermost TCP protocol in Sudoku FinalMask when enabled
    if !ib.is_quic() && ss.sudoku.enabled {
        let inner_proto = client_hop["protocol"].clone();
        let mut mask = json!({
            "type": "sudoku_mask",
            "protocol": inner_proto
        });
        if !ss.sudoku.password.is_empty() {
            mask["password"] = json!(ss.sudoku.password);
        }
        if !ss.sudoku.ascii.trim().is_empty() {
            mask["ascii"] = json!(ss.sudoku.ascii.trim().to_ascii_lowercase());
        }
        if !ss.sudoku.custom_tables.is_empty() {
            mask["custom_tables"] = json!(ss.sudoku.custom_tables);
        } else if !ss.sudoku.custom_table.trim().is_empty() {
            mask["custom_table"] = json!(ss.sudoku.custom_table.trim());
        }
        if ss.sudoku.padding_min > 0 {
            mask["padding_min"] = json!(ss.sudoku.padding_min.min(100));
        }
        if ss.sudoku.padding_max > 0 {
            mask["padding_max"] = json!(ss.sudoku.padding_max.min(100).max(ss.sudoku.padding_min.min(100)));
        }
        client_hop["protocol"] = mask;
    }

    let full = json!([
        {
            "address": "127.0.0.1:1080",
            "protocol": { "type": "mixed", "udp_enabled": true },
            "rules": [
                {
                    "masks": "0.0.0.0/0",
                    "action": "allow",
                    "client_chain": client_hop
                }
            ]
        }
    ]);
    serde_yaml::to_string(&full).unwrap_or_default()
}

fn build_clash_proxy(ib: &Inbound, c: &ClientRecord, host: &str, name: &str) -> Option<JsonValue> {
    if ib.protocol == "portforward" || ib.stream_settings.sudoku.enabled {
        return None;
    }
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let server = host.trim();
    let port = ib.port;
    let has_vless_enc = ib.has_vless_native_encryption();

    if ib.protocol == "wireguard" {
        if c.wg_private_key.trim().is_empty() {
            return None;
        }
        let server_pub = if !ps.wg_server_public_key.trim().is_empty() {
            ps.wg_server_public_key.trim().to_string()
        } else {
            crate::crypto_util::derive_wireguard_public_key(&ps.wg_server_private_key).ok()?
        };
        let mut ip4 = String::new();
        let mut ip6 = String::new();
        for tok in c.wg_allowed_ips.split([',', ';', ' ', '\n']) {
            let ip_part = tok.split('/').next().unwrap_or("").trim();
            if ip_part.is_empty() {
                continue;
            }
            if ip_part.contains(':') && ip6.is_empty() {
                ip6 = ip_part.to_string();
            } else if !ip_part.contains(':') && ip4.is_empty() {
                ip4 = ip_part.to_string();
            }
        }
        if ip4.is_empty() && ip6.is_empty() {
            ip4 = "10.77.0.2".to_string();
        }
        let mut obj = json!({
            "name": name,
            "type": "wireguard",
            "server": server,
            "port": port,
            "private-key": c.wg_private_key.trim(),
            "public-key": server_pub,
            "udp": true,
            "mtu": if ps.wg_mtu > 0 { ps.wg_mtu } else { 1408 },
        });
        if !ip4.is_empty() {
            obj["ip"] = json!(ip4);
        }
        if !ip6.is_empty() {
            obj["ipv6"] = json!(ip6);
        }
        if !c.wg_preshared_key.trim().is_empty() {
            obj["pre-shared-key"] = json!(c.wg_preshared_key.trim());
        }
        return Some(obj);
    }

    if ss.security == "shadowtls" && ib.protocol != "shadowsocks" {
        return None;
    }

    let mut obj = match ib.protocol.as_str() {
        "vless" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws" | "xhttp") {
                return None;
            }
            // Mihomo v1.19.x WebSocket path (`case "ws":`) ignores `reality-opts` and dials plain TLS.
            if ss.network == "ws" && ss.security == "reality" {
                return None;
            }
            let mut obj = json!({
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": c.uuid.trim(),
                "udp": ps.udp_enabled,
                "network": if ss.network == "ws" { "ws" } else { "tcp" },
            });
            if has_vless_enc && !ps.vless_encryption.trim().is_empty() {
                obj["encryption"] = json!(ps.vless_encryption.trim());
                if ps.vless_native_vision {
                    obj["flow"] = json!("xtls-rprx-vision");
                }
            }
            if !has_vless_enc && ss.security == "reality" && ss.network == "tcp" && ss.reality.vision {
                obj["flow"] = json!("xtls-rprx-vision");
            }
            if ss.security == "tls" {
                obj["tls"] = json!(true);
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    obj["servername"] = json!(sni);
                }
                obj["skip-cert-verify"] = json!(ss.tls.allow_insecure);
                if !ss.tls.fingerprint.trim().is_empty() {
                    obj["client-fingerprint"] = json!(ss.tls.fingerprint.trim());
                }
                if !has_vless_enc && ss.network == "tcp" && ss.tls.vision {
                    obj["flow"] = json!("xtls-rprx-vision");
                }
            }
            if ss.network == "xhttp" {
                obj["network"] = json!("xhttp");
                obj["xhttp-opts"] = json!({
                    "path": ss.xhttp.path.trim(),
                    "host": ss.xhttp.host.trim(),
                    "mode": ss.xhttp.mode.trim(),
                    "headers": ss.xhttp.headers,
                });
            }
            Some(obj)
        }
        "vmess" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws") {
                return None;
            }
            // Mihomo v1.19.x WebSocket path ignores `reality-opts`.
            if ss.network == "ws" && ss.security == "reality" {
                return None;
            }
            // Mihomo uses sing-vmess which omits RequestOptionChunkStream for cipher=none on TCP,
            // whereas shoes strictly requires chunked VMess streams.
            if ps.cipher.trim().eq_ignore_ascii_case("none") {
                return None;
            }
            let cipher = match ps.cipher.trim() {
                "" | "any" | "auto" => "aes-128-gcm",
                other => other,
            };
            let mut obj = json!({
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": c.uuid.trim(),
                "alterId": 0,
                "cipher": cipher,
                "udp": ps.udp_enabled,
                "network": if ss.network == "ws" { "ws" } else { "tcp" },
            });
            if ss.security == "tls" {
                obj["tls"] = json!(true);
                obj["skip-cert-verify"] = json!(ss.tls.allow_insecure);
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    obj["servername"] = json!(sni);
                }
            }
            Some(obj)
        }
        "trojan" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws") {
                return None;
            }
            // Mihomo Trojan always requires TLS and ignores `reality-opts` on WS.
            if ss.security == "none" || (ss.network == "ws" && ss.security == "reality") {
                return None;
            }
            let mut obj = json!({
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": c.password.trim(),
                "udp": true,
                "network": if ss.network == "ws" { "ws" } else { "tcp" },
            });
            if ss.security == "tls" {
                obj["skip-cert-verify"] = json!(ss.tls.allow_insecure);
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    obj["sni"] = json!(sni);
                }
            }
            Some(obj)
        }
        "shadowsocks" => {
            let cipher = if ps.cipher.trim().is_empty() {
                "2022-blake3-aes-256-gcm"
            } else if ps.cipher.trim() == "2022-blake3-chacha20-ietf-poly1305" {
                "2022-blake3-chacha20-poly1305"
            } else {
                ps.cipher.trim()
            };
            let mut obj = json!({
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": cipher,
                "password": c.password.trim(),
                "udp": ps.udp_enabled,
            });
            if ss.network == "tcp" && ss.security == "none" {
                Some(obj)
            } else if ss.network == "tcp" && ss.security == "shadowtls" {
                let st = &ss.shadowtls;
                obj["plugin"] = json!("shadow-tls");
                obj["plugin-opts"] = json!({
                    "host": st.sni.trim(),
                    "password": st.password.trim(),
                    "version": 3,
                });
                Some(obj)
            } else if ss.network == "ws" && matches!(ss.security.as_str(), "none" | "tls") {
                let ws_host = ss.ws.host_header();
                let sni = effective_tls_sni(ib);
                if ss.security == "tls"
                    && !ss.tls.allow_any_sni
                    && !sni.is_empty()
                    && !ws_host.is_empty()
                    && !sni.eq_ignore_ascii_case(ws_host)
                {
                    // Mihomo v2ray-plugin shares one `host` for both TLS SNI and HTTP Host header.
                    return None;
                }
                let mut plugin_opts = json!({
                    "mode": "websocket",
                    "path": if ss.ws.path.trim().is_empty() { "/" } else { ss.ws.path.trim() },
                    "tls": ss.security == "tls",
                    "mux": false,
                });
                let effective_host = if !ws_host.is_empty() {
                    ws_host.to_string()
                } else if ss.security == "tls" {
                    sni
                } else {
                    String::new()
                };
                if !effective_host.is_empty() {
                    plugin_opts["host"] = json!(effective_host);
                }
                let headers = ss.ws.matching_headers();
                if !headers.is_empty() {
                    plugin_opts["headers"] = json!(headers);
                }
                if ss.security == "tls" {
                    plugin_opts["skip-cert-verify"] = json!(ss.tls.allow_insecure);
                }
                obj["plugin"] = json!("v2ray-plugin");
                obj["plugin-opts"] = plugin_opts;
                Some(obj)
            } else {
                None
            }
        }
        "hysteria2" => {
            let mut obj = json!({
                "name": name,
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": c.password.trim(),
                "skip-cert-verify": ss.tls.allow_insecure,
            });
            if let Ok(Some(ports)) = crate::yaml_gen::normalize_port_range_spec(ib.port, &ps.port_range) {
                obj["ports"] = json!(ports);
                obj["hop-interval"] = json!(30);
            }
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                obj["sni"] = json!(sni);
            }
            Some(obj)
        }
        "tuic" => {
            let mut obj = json!({
                "name": name,
                "type": "tuic",
                "server": server,
                "port": port,
                "uuid": c.uuid.trim(),
                "password": c.password.trim(),
                "alpn": if ss.tls.alpn.is_empty() { json!(["h3"]) } else { json!(ss.tls.alpn) },
                "udp-relay-mode": "native",
                "congestion-controller": "bbr",
                "skip-cert-verify": ss.tls.allow_insecure,
            });
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                obj["sni"] = json!(sni);
            }
            Some(obj)
        }
        "anytls" => {
            // Mihomo AnyTLSOption does not support `reality-opts`.
            if ss.network != "tcp" || ss.security != "tls" {
                return None;
            }
            let mut obj = json!({
                "name": name,
                "type": "anytls",
                "server": server,
                "port": port,
                "password": c.password.trim(),
                "udp": ps.udp_enabled,
                "skip-cert-verify": ss.tls.allow_insecure,
            });
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                obj["sni"] = json!(sni);
            }
            Some(obj)
        }
        "snell" => {
            if ss.network != "tcp" || ss.security != "none" {
                return None;
            }
            // Mihomo Snell transport maps version 1 -> chacha20-ietf-poly1305 (TCP only),
            // version 2/3 -> aes-128-gcm (v3 supports UDP); aes-256-gcm is unsupported by Mihomo.
            let (version, udp) = match effective_snell_cipher(ib) {
                "aes-128-gcm" => (3, ps.udp_enabled),
                "chacha20-ietf-poly1305" => (1, false),
                _ => return None,
            };
            Some(json!({
                "name": name,
                "type": "snell",
                "server": server,
                "port": port,
                "psk": c.password.trim(),
                "version": version,
                "udp": udp,
            }))
        }
        "socks" | "mixed" => {
            if ss.network != "tcp" {
                return None;
            }
            let mut obj = json!({
                "name": name,
                "type": "socks5",
                "server": server,
                "port": port,
                "udp": ps.udp_enabled,
            });
            if !c.username.trim().is_empty() {
                obj["username"] = json!(c.username.trim());
                obj["password"] = json!(c.password.trim());
            }
            Some(obj)
        }
        "http" => {
            if ss.network != "tcp" {
                return None;
            }
            let mut obj = json!({
                "name": name,
                "type": "http",
                "server": server,
                "port": port,
                "tls": ss.security == "tls",
            });
            if !c.username.trim().is_empty() {
                obj["username"] = json!(c.username.trim());
                obj["password"] = json!(c.password.trim());
            }
            Some(obj)
        }
        _ => None,
    }?;
    if ss.security == "reality" {
        let sni_key = if matches!(ib.protocol.as_str(), "vless" | "vmess") { "servername" } else { "sni" };
        obj[sni_key] = json!(ss.reality.sni.trim());
        obj["tls"] = json!(true);
        let fp = ss.reality.fingerprint.trim();
        obj["client-fingerprint"] = json!(if fp.is_empty() { "chrome" } else { fp });
        obj["reality-opts"] = json!({
            "public-key": effective_reality_pubkey(ib),
            "short-id": ss.reality.short_ids.first().map(|s| s.trim()).unwrap_or("")
        });
    }
    if ss.network == "ws" && ib.protocol != "shadowsocks" {
        let mut ws_opts = json!({ "path": ss.ws.path.trim() });
        let headers = ss.ws.matching_headers();
        if !headers.is_empty() {
            ws_opts["headers"] = json!(headers);
        }
        if ss.ws.max_early_data > 0 {
            ws_opts["max-early-data"] = json!(ss.ws.max_early_data);
            if !ss.ws.early_data_header_name.trim().is_empty() {
                ws_opts["early-data-header-name"] = json!(ss.ws.early_data_header_name.trim());
            }
        }
        obj["ws-opts"] = ws_opts;
    }
    if ss.security == "tls" && matches!(ib.protocol.as_str(), "socks" | "mixed" | "http") {
        obj["tls"] = json!(true);
        obj["skip-cert-verify"] = json!(ss.tls.allow_insecure);
        let sni = effective_tls_sni(ib);
        if !sni.is_empty() {
            obj["sni"] = json!(sni);
        }
    }
    if let Some(mux) = inbound_effective_h2mux(ib) {
        obj["smux"] = build_clash_smux_json(mux);
    }
    Some(obj)
}

fn build_singbox_outbound(
    ib: &Inbound,
    c: &ClientRecord,
    host: &str,
    name: &str,
    certs: &[CertificateRecord],
    cert_pems: Option<&std::collections::HashMap<String, String>>,
) -> Option<(JsonValue, Option<JsonValue>)> {
    if ib.protocol == "portforward" || ib.stream_settings.sudoku.enabled {
        return None;
    }
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let server = host.trim();
    let port = ib.port;

    if ib.protocol == "wireguard" {
        if c.wg_private_key.trim().is_empty() {
            return None;
        }
        let server_pub = if !ps.wg_server_public_key.trim().is_empty() {
            ps.wg_server_public_key.trim().to_string()
        } else {
            crate::crypto_util::derive_wireguard_public_key(&ps.wg_server_private_key).ok()?
        };
        let local_addrs: Vec<String> = c
            .wg_allowed_ips
            .split([',', ';', ' ', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let mut obj = json!({
            "tag": name,
            "type": "wireguard",
            "server": server,
            "server_port": port,
            "local_address": if local_addrs.is_empty() { vec!["10.77.0.2/32".to_string()] } else { local_addrs },
            "private_key": c.wg_private_key.trim(),
            "peer_public_key": server_pub,
            "mtu": if ps.wg_mtu > 0 { ps.wg_mtu } else { 1408 },
        });
        if !c.wg_preshared_key.trim().is_empty() {
            obj["pre_shared_key"] = json!(c.wg_preshared_key.trim());
        }
        return Some((obj, None));
    }

    if ib.has_vless_native_encryption() {
        // sing-box does not support Xray/Shoes VLESS native encryption.
        return None;
    }

    let shadowtls_detour = if ss.security == "shadowtls" {
        if ss.network != "tcp" || !matches!(ib.protocol.as_str(), "shadowsocks" | "vless" | "vmess" | "trojan") {
            return None;
        }
        let detour_tag = format!("{name}-stls");
        Some((
            detour_tag.clone(),
            json!({
                "tag": detour_tag,
                "type": "shadowtls",
                "server": server,
                "server_port": port,
                "version": 3,
                "password": ss.shadowtls.password.trim(),
                "tls": {
                    "enabled": true,
                    "server_name": ss.shadowtls.sni.trim(),
                }
            }),
        ))
    } else {
        None
    };

    let tls_block = if ib.is_quic() || ss.security == "tls" {
        let mut t = json!({
            "enabled": true,
            "insecure": ss.tls.allow_insecure,
        });
        let sni = effective_tls_sni(ib);
        if !sni.is_empty() {
            t["server_name"] = json!(sni);
        }
        if ib.is_quic() {
            t["alpn"] = if ss.tls.alpn.is_empty() {
                json!(["h3"])
            } else {
                json!(ss.tls.alpn)
            };
        } else if !ss.tls.alpn.is_empty() {
            t["alpn"] = json!(ss.tls.alpn);
        }
        Some(t)
    } else if ss.security == "reality" {
        let fp = if ss.reality.fingerprint.trim().is_empty() {
            "chrome"
        } else {
            ss.reality.fingerprint.trim()
        };
        Some(json!({
            "enabled": true,
            "server_name": ss.reality.sni.trim(),
            "utls": {
                "enabled": true,
                "fingerprint": fp
            },
            "reality": {
                "enabled": true,
                "public_key": effective_reality_pubkey(ib),
                "short_id": ss.reality.short_ids.first().map(|s| s.trim()).unwrap_or("")
            }
        }))
    } else {
        None
    };

    let mut obj = match ib.protocol.as_str() {
        "vless" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws" | "quic") {
                return None;
            }
            let mut obj = json!({
                "tag": name,
                "type": "vless",
                "server": server,
                "server_port": port,
                "uuid": c.uuid.trim(),
            });
            if ss.network == "tcp"
                && ((ss.security == "reality" && ss.reality.vision)
                    || (ss.security == "tls" && ss.tls.vision))
            {
                obj["flow"] = json!("xtls-rprx-vision");
            }
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            if ss.network == "quic" {
                obj["transport"] = json!({ "type": "quic" });
            }
            Some(obj)
        }
        "vmess" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws") {
                return None;
            }
            // sing-vmess omits RequestOptionChunkStream for security=none on TCP,
            // which shoes VMess server rejects.
            if ps.cipher.trim().eq_ignore_ascii_case("none") {
                return None;
            }
            let cipher = match ps.cipher.trim() {
                "" | "any" | "auto" => "aes-128-gcm",
                other => other,
            };
            let mut obj = json!({
                "tag": name,
                "type": "vmess",
                "server": server,
                "server_port": port,
                "uuid": c.uuid.trim(),
                "security": cipher,
            });
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            Some(obj)
        }
        "trojan" => {
            if !matches!(ss.network.as_str(), "tcp" | "ws") {
                return None;
            }
            let mut obj = json!({
                "tag": name,
                "type": "trojan",
                "server": server,
                "server_port": port,
                "password": c.password.trim(),
            });
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            Some(obj)
        }
        "shadowsocks" => {
            let cipher = if ps.cipher.trim().is_empty() {
                "2022-blake3-aes-256-gcm"
            } else if ps.cipher.trim() == "2022-blake3-chacha20-ietf-poly1305" {
                "2022-blake3-chacha20-poly1305"
            } else {
                ps.cipher.trim()
            };
            let mut obj = json!({
                "tag": name,
                "type": "shadowsocks",
                "server": server,
                "server_port": port,
                "method": cipher,
                "password": c.password.trim(),
            });
            if ss.network == "tcp" && matches!(ss.security.as_str(), "none" | "shadowtls") {
                Some(obj)
            } else if ss.network == "ws"
                && matches!(ss.security.as_str(), "none" | "tls")
                && !has_non_host_ws_headers(ib)
            {
                let ws_host = ss.ws.host_header();
                let sni = effective_tls_sni(ib);
                let path = if ss.ws.path.trim().is_empty() {
                    "/"
                } else {
                    ss.ws.path.trim()
                };
                let mut opts = vec![
                    "mode=websocket".to_string(),
                    "mux=0".to_string(),
                    format!("path={path}"),
                ];
                if ss.security == "tls" {
                    // sing-box v2ray-plugin shares `host` for both TLS SNI and HTTP Host
                    // and has no `insecure` flag (only `certRaw` for self-signed cert pinning).
                    if !ss.tls.allow_any_sni
                        && !sni.is_empty()
                        && !ws_host.is_empty()
                        && !sni.eq_ignore_ascii_case(ws_host)
                    {
                        return None;
                    }
                    opts.push("tls".to_string());
                    let effective_host = if !ws_host.is_empty() {
                        ws_host.to_string()
                    } else {
                        sni.clone()
                    };
                    if !effective_host.is_empty() {
                        opts.push(format!("host={effective_host}"));
                    }
                    if ss.tls.allow_insecure {
                        if !ws_host.is_empty() && !sni.is_empty() && !ws_host.eq_ignore_ascii_case(&sni) {
                            // Self-signed cert SAN usually matches SNI, not a different WS Host.
                            return None;
                        }
                        let pem = resolve_inbound_cert_pem(ib, certs, cert_pems)?;
                        let raw = extract_pem_cert_raw(&pem)?;
                        opts.push(format!("certRaw={raw}"));
                    }
                } else if !ws_host.is_empty() {
                    opts.push(format!("host={ws_host}"));
                }
                obj["plugin"] = json!("v2ray-plugin");
                obj["plugin_opts"] = json!(opts.join(";"));
                Some(obj)
            } else {
                None
            }
        }
        "hysteria2" => {
            let mut obj = json!({
                "tag": name,
                "type": "hysteria2",
                "server": server,
                "server_port": port,
                "password": c.password.trim(),
            });
            if let Ok(Some(ports)) = crate::yaml_gen::normalize_port_range_spec(ib.port, &ps.port_range) {
                let sb_ports: Vec<String> = ports
                    .split(',')
                    .map(|seg| {
                        if let Some((a, b)) = seg.split_once('-') {
                            format!("{a}:{b}")
                        } else {
                            format!("{seg}:{seg}")
                        }
                    })
                    .collect();
                obj["server_ports"] = json!(sb_ports);
                obj["hop_interval"] = json!("30s");
            }
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            Some(obj)
        }
        "tuic" => {
            let mut obj = json!({
                "tag": name,
                "type": "tuic",
                "server": server,
                "server_port": port,
                "uuid": c.uuid.trim(),
                "password": c.password.trim(),
                "congestion_control": "bbr",
                "udp_relay_mode": "native",
            });
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            Some(obj)
        }
        "anytls" => {
            if ss.network != "tcp" || !matches!(ss.security.as_str(), "tls" | "reality") {
                return None;
            }
            let mut obj = json!({
                "tag": name,
                "type": "anytls",
                "server": server,
                "server_port": port,
                "password": c.password.trim(),
            });
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            Some(obj)
        }
        "naiveproxy" => {
            // sing-box Cronet naive outbound requires TLS (no reality, no insecure, no alpn);
            // for self-signed certs we embed the server's public cert PEM in `tls.certificate`.
            if ss.network != "tcp" || ss.security != "tls" {
                return None;
            }
            let uname = if c.username.trim().is_empty() {
                c.name.trim()
            } else {
                c.username.trim()
            };
            let mut naive_tls = json!({ "enabled": true });
            let sni = effective_tls_sni(ib);
            if !sni.is_empty() {
                naive_tls["server_name"] = json!(sni);
            }
            if ss.tls.allow_insecure {
                let pem = resolve_inbound_cert_pem(ib, certs, cert_pems)?;
                naive_tls["certificate"] = json!([pem]);
            }
            Some(json!({
                "tag": name,
                "type": "naive",
                "server": server,
                "server_port": port,
                "username": uname,
                "password": c.password.trim(),
                "tls": naive_tls,
            }))
        }
        "http" | "mixed" if ss.network == "tcp" && (ib.protocol == "http" || ss.security == "tls") => {
            let mut obj = json!({
                "tag": name, "type": "http", "server": server, "server_port": port,
            });
            if let Some(t) = tls_block {
                obj["tls"] = t;
            }
            if !c.username.trim().is_empty() {
                obj["username"] = json!(c.username.trim());
                obj["password"] = json!(c.password.trim());
            }
            Some(obj)
        }
        "socks" | "mixed" if ss.network == "tcp" && ss.security == "none" => {
            let mut obj = json!({
                "tag": name,
                "type": "socks",
                "server": server,
                "server_port": port,
            });
            if !c.username.trim().is_empty() {
                obj["username"] = json!(c.username.trim());
                obj["password"] = json!(c.password.trim());
            }
            Some(obj)
        }
        _ => None,
    }?;
    if ss.network == "ws" && ib.protocol != "shadowsocks" {
        obj["transport"] = json!({
            "type": "ws",
            "path": ss.ws.path.trim(),
        });
        let headers = ss.ws.matching_headers();
        if !headers.is_empty() {
            obj["transport"]["headers"] = json!(headers);
        }
        if ss.ws.max_early_data > 0 {
            obj["transport"]["max_early_data"] = json!(ss.ws.max_early_data);
            if !ss.ws.early_data_header_name.trim().is_empty() {
                obj["transport"]["early_data_header_name"] = json!(ss.ws.early_data_header_name.trim());
            }
        }
    }
    if let Some(mux) = inbound_effective_h2mux(ib) {
        obj["multiplex"] = build_singbox_multiplex_json(mux);
    }
    if let Some((detour_tag, detour_obj)) = shadowtls_detour {
        if let Some(map) = obj.as_object_mut() {
            map.remove("server");
            map.remove("server_port");
            map.insert("detour".to_string(), json!(detour_tag));
        }
        return Some((obj, Some(detour_obj)));
    }
    Some((obj, None))
}

/// Ensures fields like `short-id`, `password`, `uuid`, `psk` in Clash YAML are never coerced
/// to YAML numbers/booleans when hex/random strings happen to look numeric (e.g. `01234567` or `12e4`).
fn quote_sensitive_clash_strings(yaml: &str) -> String {
    let mut out = String::with_capacity(yaml.len() + 128);
    for line in yaml.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if let Some((key, val)) = trimmed.split_once(':') {
            let k = key.trim();
            let v = val.trim();
            if matches!(k, "short-id" | "password" | "uuid" | "psk" | "public-key")
                && !v.is_empty()
                && !v.starts_with('\'')
                && !v.starts_with('"')
            {
                let escaped = v.replace('\'', "''");
                out.push_str(&format!("{indent}{k}: '{escaped}'\n"));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

const CN_DIRECT_DOMAINS: &[&str] = &[
    "cn",
    "baidu.com",
    "bdimg.com",
    "bdstatic.com",
    "qq.com",
    "weixin.qq.com",
    "wechat.com",
    "qpic.cn",
    "taobao.com",
    "tmall.com",
    "alicdn.com",
    "aliyun.com",
    "aliyuncs.com",
    "alipay.com",
    "jd.com",
    "360buyimg.com",
    "bilibili.com",
    "hdslb.com",
    "zhihu.com",
    "douyin.com",
    "bytedance.com",
    "163.com",
    "126.com",
    "126.net",
    "weibo.com",
    "xiaomi.com",
    "mi.com",
    "huawei.com",
    "tencent.com",
    "meituan.com",
    "ctrip.com",
    "douban.com",
    "csdn.net",
];

const AI_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "perplexity.ai",
    "copilot.microsoft.com",
    "x.ai",
    "grok.com",
];

const NETFLIX_DOMAINS: &[&str] = &[
    "netflix.com",
    "netflix.net",
    "nflximg.net",
    "nflxvideo.net",
    "nflxso.net",
    "nflxext.com",
];

const YOUTUBE_DOMAINS: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
];

const TELEGRAM_DOMAINS: &[&str] = &[
    "t.me",
    "telegram.org",
    "telegram.me",
    "telegra.ph",
    "tdesktop.com",
];

const TELEGRAM_CIDRS: &[&str] = &[
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
];

const GOOGLE_DOMAINS: &[&str] = &[
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "gmail.com",
    "googleusercontent.com",
];

const APPLE_DOMAINS: &[&str] = &[
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cdn-apple.com",
    "apple-cloudkit.com",
];

const GLOBAL_PROXY_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "claude.ai",
    "anthropic.com",
    "google.com",
    "googleapis.com",
    "youtube.com",
    "googlevideo.com",
    "github.com",
    "githubusercontent.com",
    "t.me",
    "telegram.org",
    "x.com",
    "twitter.com",
    "discord.com",
    "wikipedia.org",
    "reddit.com",
    "netflix.com",
];

const ADBLOCK_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "ads.yahoo.com",
    "adnxs.com",
    "taboola.com",
    "outbrain.com",
    "criteo.com",
    "scorecardresearch.com",
    "ads-twitter.com",
    "ad.doubleclick.net",
    "pagead2.googlesyndication.com",
];

fn parse_clash_custom_rules(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim().trim_start_matches('-').trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_matches('\'').trim_matches('"').to_string())
        .collect()
}

fn map_policy_to_singbox_tag(raw: &str) -> String {
    let t = raw.trim();
    match t.to_ascii_lowercase().as_str() {
        "direct" => "direct".to_string(),
        "reject" | "block" => "block".to_string(),
        "proxy" | "🚀 proxy" => "proxy".to_string(),
        "auto" | "⚡ auto" => "auto".to_string(),
        "ai" | "🤖 ai" => "ai".to_string(),
        "netflix" | "🎬 netflix" => "netflix".to_string(),
        "youtube" | "📺 youtube" => "youtube".to_string(),
        "telegram" | "✈️ telegram" => "telegram".to_string(),
        "google" | "🌍 google" => "google".to_string(),
        "apple" | "🍎 apple" => "apple".to_string(),
        "🎯 direct" => "direct".to_string(),
        _ => t.to_string(),
    }
}

fn parse_singbox_custom_rules(raw: &str) -> Vec<JsonValue> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        if let Ok(JsonValue::Array(arr)) = serde_json::from_str::<JsonValue>(trimmed) {
            return arr;
        }
    } else if trimmed.starts_with('{') {
        if let Ok(obj) = serde_json::from_str::<JsonValue>(trimmed) {
            return vec![obj];
        }
    }

    // Fallback: parse Clash-style lines (`DOMAIN-SUFFIX,example.com,proxy` / `IP-CIDR,1.2.3.0/24,direct`)
    let mut rules = Vec::new();
    for line in trimmed.lines() {
        let l = line.trim().trim_start_matches('-').trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = l.split(',').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        let kind = parts[0].to_ascii_uppercase();
        let val = parts[1];
        let outbound = map_policy_to_singbox_tag(parts[2]);
        if val.is_empty() || outbound.is_empty() {
            continue;
        }
        let rule = match kind.as_str() {
            "DOMAIN" => json!({ "domain": [val], "outbound": outbound }),
            "DOMAIN-SUFFIX" => json!({ "domain_suffix": [val], "outbound": outbound }),
            "DOMAIN-KEYWORD" => json!({ "domain_keyword": [val], "outbound": outbound }),
            "IP-CIDR" | "IP-CIDR6" => json!({ "ip_cidr": [val], "outbound": outbound }),
            "DST-PORT" => {
                if let Ok(p) = val.parse::<u16>() {
                    json!({ "port": [p], "outbound": outbound })
                } else {
                    continue;
                }
            }
            "PROCESS-NAME" => json!({ "process_name": [val], "outbound": outbound }),
            _ => continue,
        };
        rules.push(rule);
    }
    rules
}

/// Represents one VPS panel source (local master or mounted remote cluster node)
/// contributing inbounds to a unified multi-node subscription.
pub struct SubSourceNode<'a> {
    pub region: &'a str,
    pub region_flag: &'a str,
    pub prefix: &'a str,
    pub host: &'a str,
    pub inbounds: &'a [Inbound],
    pub certs: &'a [CertificateRecord],
    pub cert_pems: Option<&'a std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone)]
struct RegionGroupSpec {
    label: String,
    members: Vec<String>,
}

/// Canonical `(code, flag, display_label, sort_rank)` catalog for regional auto-grouping.
const REGION_CATALOG: &[(&str, &str, &str, usize)] = &[
    ("HK", "🇭🇰", "🇭🇰 香港", 1),
    ("JP", "🇯🇵", "🇯🇵 日本", 2),
    ("SG", "🇸🇬", "🇸🇬 新加坡", 3),
    ("TW", "🇹🇼", "🇹🇼 台湾", 4),
    ("US", "🇺🇸", "🇺🇸 美国", 5),
    ("KR", "🇰🇷", "🇰🇷 韩国", 6),
    ("UK", "🇬🇧", "🇬🇧 英国", 7),
    ("DE", "🇩🇪", "🇩🇪 德国", 8),
    ("NL", "🇳🇱", "🇳🇱 荷兰", 9),
    ("FR", "🇫🇷", "🇫🇷 法国", 10),
    ("CA", "🇨🇦", "🇨🇦 加拿大", 11),
    ("AU", "🇦🇺", "🇦🇺 澳大利亚", 12),
    ("TR", "🇹🇷", "🇹🇷 土耳其", 13),
    ("IN", "🇮🇳", "🇮🇳 印度", 14),
    ("RU", "🇷🇺", "🇷🇺 俄罗斯", 15),
];

fn lookup_canonical_region(raw: &str) -> Option<(&'static str, &'static str, usize)> {
    let up = raw.trim().to_ascii_uppercase();
    let norm = match up.as_str() {
        "HK" | "HONG KONG" | "HONGKONG" | "香港" => "HK",
        "JP" | "JAPAN" | "TOKYO" | "OSAKA" | "日本" => "JP",
        "SG" | "SINGAPORE" | "新加坡" | "狮城" => "SG",
        "TW" | "TAIWAN" | "TAIPEI" | "台湾" | "台灣" => "TW",
        "US" | "USA" | "UNITED STATES" | "AMERICA" | "美国" | "美國" => "US",
        "KR" | "KOREA" | "SOUTH KOREA" | "SEOUL" | "韩国" | "韓國" => "KR",
        "UK" | "GB" | "UNITED KINGDOM" | "BRITAIN" | "LONDON" | "英国" | "英國" => "UK",
        "DE" | "GERMANY" | "FRANKFURT" | "德国" | "德國" => "DE",
        "NL" | "NETHERLANDS" | "AMSTERDAM" | "荷兰" | "荷蘭" => "NL",
        "FR" | "FRANCE" | "PARIS" | "法国" | "法國" => "FR",
        "CA" | "CANADA" | "TORONTO" | "加拿大" => "CA",
        "AU" | "AUSTRALIA" | "SYDNEY" | "澳大利亚" | "澳洲" => "AU",
        "TR" | "TURKEY" | "TURKIYE" | "土耳其" => "TR",
        "IN" | "INDIA" | "印度" => "IN",
        "RU" | "RUSSIA" | "俄罗斯" | "俄羅斯" => "RU",
        _ => return None,
    };
    REGION_CATALOG
        .iter()
        .find(|(code, _, _, _)| *code == norm)
        .map(|(code, _, label, rank)| (*code, *label, *rank))
}

fn contains_ascii_word(haystack_upper: &str, needle: &str) -> bool {
    let bytes = haystack_upper.as_bytes();
    let nbytes = needle.as_bytes();
    if nbytes.is_empty() || bytes.len() < nbytes.len() {
        return false;
    }
    for i in 0..=bytes.len() - nbytes.len() {
        if &bytes[i..i + nbytes.len()] == nbytes {
            let left_ok = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
            let right_ok =
                i + nbytes.len() == bytes.len() || !bytes[i + nbytes.len()].is_ascii_alphabetic();
            if left_ok && right_ok {
                return true;
            }
        }
    }
    false
}

/// Resolves `(region_key, display_label, sort_rank)` for a proxy node.
/// Uses explicit node `region` / `region_flag` first, falling back to emoji/keyword inference on node name.
fn resolve_node_region(
    explicit_region: &str,
    explicit_flag: &str,
    node_name: &str,
) -> Option<(String, String, usize)> {
    let reg = explicit_region.trim();
    if !reg.is_empty() {
        if let Some((code, label, rank)) = lookup_canonical_region(reg) {
            return Some((code.to_string(), label.to_string(), rank));
        }
        let flag = explicit_flag.trim();
        let label = if !flag.is_empty() && !reg.starts_with(flag) {
            format!("{flag} {reg}")
        } else {
            reg.to_string()
        };
        return Some((reg.to_ascii_uppercase(), label, 50));
    }

    // Infer from flag emojis or well-known region keywords in node display name
    for (code, flag, label, rank) in REGION_CATALOG {
        if node_name.contains(flag) {
            return Some(((*code).to_string(), (*label).to_string(), *rank));
        }
    }
    const KEYWORD_RULES: &[(&str, &[&str], &[&str])] = &[
        ("HK", &["香港"], &["HK", "HONGKONG", "HKG"]),
        ("JP", &["日本", "东京", "大阪"], &["JP", "JAPAN", "TOKYO", "OSAKA", "NRT", "KIX"]),
        ("SG", &["新加坡", "狮城"], &["SG", "SINGAPORE", "SIN"]),
        ("TW", &["台湾", "台灣", "台北"], &["TW", "TAIWAN", "TAIPEI", "TPE"]),
        ("US", &["美国", "美國", "洛杉矶", "圣何塞", "纽约", "西雅图"], &["US", "USA", "LAX", "SJC", "NYC", "SEA"]),
        ("KR", &["韩国", "韓國", "首尔"], &["KR", "KOREA", "SEOUL", "ICN"]),
        ("UK", &["英国", "英國", "伦敦"], &["UK", "GB", "LONDON", "LHR"]),
        ("DE", &["德国", "德國", "法兰克福"], &["DE", "GERMANY", "FRANKFURT", "FRA"]),
        ("NL", &["荷兰", "荷蘭", "阿姆斯特丹"], &["NL", "AMSTERDAM", "AMS"]),
        ("FR", &["法国", "法國", "巴黎"], &["FR", "FRANCE", "PARIS", "CDG"]),
        ("CA", &["加拿大", "多伦多"], &["CA", "CANADA", "TORONTO"]),
        ("AU", &["澳大利亚", "澳洲", "悉尼"], &["AU", "AUSTRALIA", "SYDNEY"]),
    ];
    let upper = node_name.to_ascii_uppercase();
    for (code, cn_kws, en_kws) in KEYWORD_RULES {
        if cn_kws.iter().any(|k| node_name.contains(k))
            || en_kws.iter().any(|k| contains_ascii_word(&upper, k))
        {
            if let Some((_, _, label, rank)) = REGION_CATALOG.iter().find(|(c, _, _, _)| c == code) {
                return Some(((*code).to_string(), (*label).to_string(), *rank));
            }
        }
    }
    None
}

fn build_region_groups(
    entries: &[(String, Option<(String, String, usize)>)],
    multi_source: bool,
    enable_region_groups: bool,
) -> Vec<RegionGroupSpec> {
    if !enable_region_groups || entries.is_empty() {
        return Vec::new();
    }
    let mut named_map: std::collections::HashMap<String, (String, usize, Vec<String>)> =
        std::collections::HashMap::new();
    let mut unlabeled: Vec<String> = Vec::new();

    for (name, reg) in entries {
        if let Some((key, label, rank)) = reg {
            let entry = named_map
                .entry(key.clone())
                .or_insert_with(|| (label.clone(), *rank, Vec::new()));
            entry.2.push(name.clone());
        } else {
            unlabeled.push(name.clone());
        }
    }

    // Emit regional groups when we have >= 2 distinct regions, or a multi-node cluster with >= 1 labeled region.
    if named_map.len() < 2 && !(multi_source && !named_map.is_empty()) {
        return Vec::new();
    }

    let mut groups: Vec<(usize, String, Vec<String>)> = named_map
        .into_values()
        .map(|(label, rank, members)| (rank, label, members))
        .collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut out: Vec<RegionGroupSpec> = groups
        .into_iter()
        .map(|(_, label, members)| RegionGroupSpec { label, members })
        .collect();
    if !unlabeled.is_empty() {
        out.push(RegionGroupSpec {
            label: "🌐 其他".to_string(),
            members: unlabeled,
        });
    }
    out
}

fn build_clash_document(
    proxies: Vec<JsonValue>,
    names: &[String],
    region_groups: &[RegionGroupSpec],
    tpl: &SubscriptionTemplateConfig,
) -> JsonValue {
    let preset = tpl.preset.trim().to_ascii_lowercase();
    let region_labels: Vec<String> = region_groups.iter().map(|rg| rg.label.clone()).collect();

    let mut selector_members = vec!["⚡ Auto".to_string()];
    selector_members.extend(region_labels.iter().cloned());
    selector_members.extend(names.iter().cloned());
    selector_members.push("DIRECT".to_string());

    let auto_members = if names.is_empty() {
        vec!["DIRECT".to_string()]
    } else {
        names.to_vec()
    };

    let mut proxy_groups = vec![
        json!({
            "name": "🚀 Proxy",
            "type": "select",
            "proxies": selector_members
        }),
        json!({
            "name": "⚡ Auto",
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": auto_members
        }),
    ];

    if preset == "streaming" {
        let mut service_proxies = vec!["🚀 Proxy".to_string(), "⚡ Auto".to_string()];
        service_proxies.extend(region_labels.iter().cloned());
        service_proxies.extend(names.iter().cloned());
        service_proxies.push("DIRECT".to_string());

        let mut direct_first = vec!["DIRECT".to_string(), "🚀 Proxy".to_string(), "⚡ Auto".to_string()];
        direct_first.extend(region_labels.iter().cloned());
        direct_first.extend(names.iter().cloned());

        for group_name in ["🤖 AI", "🎬 Netflix", "📺 YouTube", "✈️ Telegram", "🌍 Google"] {
            proxy_groups.push(json!({
                "name": group_name,
                "type": "select",
                "proxies": service_proxies
            }));
        }
        proxy_groups.push(json!({
            "name": "🍎 Apple",
            "type": "select",
            "proxies": direct_first
        }));
        proxy_groups.push(json!({
            "name": "🎯 Direct",
            "type": "select",
            "proxies": ["DIRECT", "🚀 Proxy"]
        }));
    }

    // Per-region automatic latency-tested groups (url-test)
    for rg in region_groups {
        proxy_groups.push(json!({
            "name": rg.label,
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": rg.members
        }));
    }

    // Optional user-supplied extra Clash proxy-groups YAML list
    if !tpl.clash_extra_groups_yaml.trim().is_empty() {
        if let Ok(extra_yaml) = serde_yaml::from_str::<YamlValue>(tpl.clash_extra_groups_yaml.trim()) {
            if let Ok(JsonValue::Array(arr)) = serde_json::to_value(extra_yaml) {
                for g in arr {
                    if g.is_object() {
                        proxy_groups.push(g);
                    }
                }
            }
        }
    }

    // Build preset rules (without trailing MATCH so custom rules can be placed cleanly)
    let mut preset_rules: Vec<String> = Vec::new();
    if tpl.enable_adblock {
        for d in ADBLOCK_DOMAINS {
            preset_rules.push(format!("DOMAIN-SUFFIX,{d},REJECT"));
        }
    }

    // Always bypass private LAN ranges cleanly
    preset_rules.extend([
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve".to_string(),
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve".to_string(),
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".to_string(),
    ]);

    let final_policy = match preset.as_str() {
        "global_direct" => {
            for d in GLOBAL_PROXY_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🚀 Proxy"));
            }
            "DIRECT"
        }
        "bypass_cn" => {
            for d in CN_DIRECT_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},DIRECT"));
            }
            preset_rules.push("GEOIP,LAN,DIRECT,no-resolve".to_string());
            preset_rules.push("GEOIP,CN,DIRECT,no-resolve".to_string());
            "🚀 Proxy"
        }
        "streaming" => {
            for d in AI_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🤖 AI"));
            }
            for d in NETFLIX_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🎬 Netflix"));
            }
            for d in YOUTUBE_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},📺 YouTube"));
            }
            for d in TELEGRAM_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},✈️ Telegram"));
            }
            for cidr in TELEGRAM_CIDRS {
                preset_rules.push(format!("IP-CIDR,{cidr},✈️ Telegram,no-resolve"));
            }
            for d in GOOGLE_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🌍 Google"));
            }
            for d in APPLE_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🍎 Apple"));
            }
            for d in CN_DIRECT_DOMAINS {
                preset_rules.push(format!("DOMAIN-SUFFIX,{d},🎯 Direct"));
            }
            preset_rules.push("GEOIP,LAN,🎯 Direct,no-resolve".to_string());
            preset_rules.push("GEOIP,CN,🎯 Direct,no-resolve".to_string());
            "🚀 Proxy"
        }
        _ => "🚀 Proxy", // "minimal"
    };

    let custom_rules = parse_clash_custom_rules(&tpl.clash_custom_rules);
    let custom_has_match = custom_rules
        .iter()
        .any(|r| r.to_ascii_uppercase().starts_with("MATCH,"));

    let mut rules = Vec::new();
    if tpl.prepend_custom_rules {
        rules.extend(custom_rules);
        rules.extend(preset_rules);
    } else {
        rules.extend(preset_rules);
        rules.extend(custom_rules);
    }
    if !custom_has_match {
        rules.push(format!("MATCH,{final_policy}"));
    }

    json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": true,
            "ipv6": tpl.enable_ipv6,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"]
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules
    })
}

fn build_singbox_document(
    outbounds: Vec<JsonValue>,
    tags: &[String],
    region_groups: &[RegionGroupSpec],
    tpl: &SubscriptionTemplateConfig,
) -> JsonValue {
    let preset = tpl.preset.trim().to_ascii_lowercase();
    let region_labels: Vec<String> = region_groups.iter().map(|rg| rg.label.clone()).collect();

    let mut select_tags = vec!["auto".to_string()];
    select_tags.extend(region_labels.iter().cloned());
    select_tags.extend(tags.iter().cloned());
    select_tags.push("direct".to_string());

    let mut all_outbounds = vec![json!({
        "tag": "proxy",
        "type": "selector",
        "outbounds": select_tags,
    })];
    if !tags.is_empty() {
        all_outbounds.push(json!({
            "tag": "auto",
            "type": "urltest",
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
            "tolerance": 50
        }));
    } else {
        all_outbounds.push(json!({
            "tag": "auto",
            "type": "direct"
        }));
    }

    if preset == "streaming" {
        let mut service_tags = vec!["proxy".to_string(), "auto".to_string()];
        service_tags.extend(region_labels.iter().cloned());
        service_tags.extend(tags.iter().cloned());
        service_tags.push("direct".to_string());

        let mut apple_tags = vec!["direct".to_string(), "proxy".to_string(), "auto".to_string()];
        apple_tags.extend(region_labels.iter().cloned());
        apple_tags.extend(tags.iter().cloned());

        for g in ["ai", "netflix", "youtube", "telegram", "google"] {
            all_outbounds.push(json!({
                "tag": g,
                "type": "selector",
                "outbounds": service_tags
            }));
        }
        all_outbounds.push(json!({
            "tag": "apple",
            "type": "selector",
            "outbounds": apple_tags
        }));
    }

    // Per-region automatic latency-tested groups (urltest)
    for rg in region_groups {
        all_outbounds.push(json!({
            "tag": rg.label,
            "type": "urltest",
            "outbounds": rg.members,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
            "tolerance": 50
        }));
    }

    all_outbounds.extend(outbounds);
    all_outbounds.push(json!({ "tag": "direct", "type": "direct" }));
    if tpl.enable_adblock
        || tpl.singbox_custom_rules.to_ascii_lowercase().contains("block")
        || tpl.singbox_custom_rules.to_ascii_lowercase().contains("reject")
    {
        all_outbounds.push(json!({ "tag": "block", "type": "block" }));
    }

    let mut preset_rules: Vec<JsonValue> = Vec::new();
    let mut rule_sets: Vec<JsonValue> = Vec::new();

    if tpl.enable_adblock {
        preset_rules.push(json!({
            "domain_suffix": ADBLOCK_DOMAINS,
            "outbound": "block"
        }));
    }

    let final_tag = match preset.as_str() {
        "global_direct" => {
            preset_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
            preset_rules.push(json!({
                "domain_suffix": GLOBAL_PROXY_DOMAINS,
                "outbound": "proxy"
            }));
            "direct"
        }
        "bypass_cn" => {
            preset_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
            preset_rules.push(json!({
                "domain_suffix": CN_DIRECT_DOMAINS,
                "outbound": "direct"
            }));
            preset_rules.push(json!({
                "rule_set": ["geosite-cn", "geoip-cn"],
                "outbound": "direct"
            }));
            rule_sets.push(json!({
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                "download_detour": "proxy"
            }));
            rule_sets.push(json!({
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                "download_detour": "proxy"
            }));
            "proxy"
        }
        "streaming" => {
            preset_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
            preset_rules.push(json!({ "domain_suffix": AI_DOMAINS, "outbound": "ai" }));
            preset_rules.push(json!({ "domain_suffix": NETFLIX_DOMAINS, "outbound": "netflix" }));
            preset_rules.push(json!({ "domain_suffix": YOUTUBE_DOMAINS, "outbound": "youtube" }));
            preset_rules.push(json!({
                "domain_suffix": TELEGRAM_DOMAINS,
                "ip_cidr": TELEGRAM_CIDRS,
                "outbound": "telegram"
            }));
            preset_rules.push(json!({ "domain_suffix": GOOGLE_DOMAINS, "outbound": "google" }));
            preset_rules.push(json!({ "domain_suffix": APPLE_DOMAINS, "outbound": "apple" }));
            preset_rules.push(json!({ "domain_suffix": CN_DIRECT_DOMAINS, "outbound": "direct" }));
            preset_rules.push(json!({
                "rule_set": ["geosite-cn", "geoip-cn"],
                "outbound": "direct"
            }));
            rule_sets.push(json!({
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                "download_detour": "proxy"
            }));
            rule_sets.push(json!({
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                "download_detour": "proxy"
            }));
            "proxy"
        }
        _ => "proxy", // "minimal"
    };

    let custom_rules = parse_singbox_custom_rules(&tpl.singbox_custom_rules);
    let mut rules = Vec::new();
    if tpl.prepend_custom_rules {
        rules.extend(custom_rules);
        rules.extend(preset_rules);
    } else {
        rules.extend(preset_rules);
        rules.extend(custom_rules);
    }

    let mut route = json!({
        "final": final_tag,
        "auto_detect_interface": true
    });
    if !rules.is_empty() {
        route["rules"] = JsonValue::Array(rules);
    }
    if !rule_sets.is_empty() {
        route["rule_set"] = JsonValue::Array(rule_sets);
    }

    let mut cfg = json!({
        "log": { "level": "info" },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890
            }
        ],
        "outbounds": all_outbounds,
        "route": route
    });
    if !tpl.enable_ipv6 && preset != "minimal" {
        cfg["dns"] = json!({
            "strategy": "ipv4_only"
        });
    }
    cfg
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn generate_subscription(
    inbounds: &[Inbound],
    sub_id_filter: &str,
    host: &str,
    format: SubFormat,
) -> SubscriptionPayload {
    generate_subscription_with_certs(inbounds, &[], sub_id_filter, host, format)
}

pub fn generate_subscription_with_certs(
    inbounds: &[Inbound],
    certs: &[CertificateRecord],
    sub_id_filter: &str,
    host: &str,
    format: SubFormat,
) -> SubscriptionPayload {
    generate_subscription_with_options(
        inbounds,
        certs,
        sub_id_filter,
        host,
        format,
        &SubscriptionTemplateConfig::default(),
    )
}

pub fn generate_subscription_with_options(
    inbounds: &[Inbound],
    certs: &[CertificateRecord],
    sub_id_filter: &str,
    host: &str,
    format: SubFormat,
    template: &SubscriptionTemplateConfig,
) -> SubscriptionPayload {
    let local = SubSourceNode {
        region: "",
        region_flag: "",
        prefix: "",
        host,
        inbounds,
        certs,
        cert_pems: None,
    };
    generate_aggregated_subscription(&[local], sub_id_filter, format, template)
}

/// Generates a unified subscription across one or more VPS nodes (local + remote cluster nodes),
/// merging traffic/quota headers, deduplicating proxy names, and automatically generating
/// per-region `url-test` / `urltest` groups in Clash / sing-box configs.
pub fn generate_aggregated_subscription(
    sources: &[SubSourceNode<'_>],
    sub_id_filter: &str,
    format: SubFormat,
    template: &SubscriptionTemplateConfig,
) -> SubscriptionPayload {
    let match_all = sub_id_filter.eq_ignore_ascii_case("all") || sub_id_filter == "*";
    let multi_source = sources.len() > 1;

    struct MatchedNode<'a> {
        source: &'a SubSourceNode<'a>,
        ib: &'a Inbound,
        client: &'a ClientRecord,
        unique_name: String,
        region: Option<(String, String, usize)>,
    }

    let mut matched: Vec<MatchedNode<'_>> = Vec::new();
    let mut used_names = std::collections::HashSet::new();

    let mut total_up: i64 = 0;
    let mut total_down: i64 = 0;
    let mut total_quota: i64 = 0;
    let mut has_unlimited_quota = false;
    let mut earliest_expiry_ms: i64 = 0;

    for source in sources {
        if source.host.trim().is_empty() {
            continue;
        }
        for ib in source
            .inbounds
            .iter()
            .filter(|i| i.enable && i.protocol != "portforward")
        {
            let mut inbound_counted = false;
            for c in ib.clients.iter().filter(|c| c.enable) {
                if match_all || c.sub_id.trim() == sub_id_filter.trim() {
                    if !inbound_counted {
                        inbound_counted = true;
                        total_up = total_up.saturating_add(ib.up_bytes);
                        total_down = total_down.saturating_add(ib.down_bytes);
                        if ib.total_quota_bytes > 0 {
                            total_quota = total_quota.saturating_add(ib.total_quota_bytes);
                        } else {
                            has_unlimited_quota = true;
                        }
                        if ib.expiry_time > 0
                            && (earliest_expiry_ms == 0 || ib.expiry_time < earliest_expiry_ms)
                        {
                            earliest_expiry_ms = ib.expiry_time;
                        }
                    }
                    let raw_name = node_display_name(ib, c);
                    let base_name = if !source.prefix.trim().is_empty() {
                        let p = source.prefix.trim();
                        if raw_name.starts_with(p) {
                            raw_name
                        } else {
                            format!("{p} | {raw_name}")
                        }
                    } else {
                        raw_name
                    };
                    let mut unique_name = base_name.clone();
                    let mut suffix = 2;
                    while !used_names.insert(unique_name.clone()) {
                        unique_name = format!("{base_name}-{suffix}");
                        suffix += 1;
                    }
                    let region =
                        resolve_node_region(source.region, source.region_flag, &unique_name);
                    matched.push(MatchedNode {
                        source,
                        ib,
                        client: c,
                        unique_name,
                        region,
                    });
                }
            }
        }
    }

    let quota_report = if has_unlimited_quota { 0 } else { total_quota };
    let expire_secs = if earliest_expiry_ms > 0 {
        earliest_expiry_ms / 1000
    } else {
        0
    };
    let userinfo_header = format!(
        "upload={total_up}; download={total_down}; total={quota_report}; expire={expire_secs}"
    );

    match format {
        SubFormat::RawUris | SubFormat::V2rayBase64 => {
            let uris: Vec<String> = matched
                .iter()
                .map(|m| build_uri(m.ib, m.client, m.source.host, &m.unique_name))
                .filter(|s| !s.is_empty() && !s.contains(" = snell,"))
                .collect();
            let joined = uris.join("\n");
            let body = if format == SubFormat::V2rayBase64 {
                STANDARD.encode(joined)
            } else {
                joined
            };
            SubscriptionPayload {
                content_type: "text/plain; charset=utf-8",
                body,
                userinfo_header,
            }
        }
        SubFormat::ClashYaml => {
            let mut proxies = Vec::new();
            let mut names = Vec::new();
            let mut reg_entries = Vec::new();
            for m in &matched {
                if let Some(p) = build_clash_proxy(m.ib, m.client, m.source.host, &m.unique_name) {
                    names.push(m.unique_name.clone());
                    reg_entries.push((m.unique_name.clone(), m.region.clone()));
                    proxies.push(p);
                }
            }
            let region_groups =
                build_region_groups(&reg_entries, multi_source, template.enable_region_groups);
            let doc = build_clash_document(proxies, &names, &region_groups, template);
            let yaml_val: YamlValue =
                serde_yaml::to_value(&doc).unwrap_or(YamlValue::Mapping(Mapping::new()));
            let raw_body = serde_yaml::to_string(&yaml_val).unwrap_or_default();
            let body = quote_sensitive_clash_strings(&raw_body);
            SubscriptionPayload {
                content_type: "text/yaml; charset=utf-8",
                body,
                userinfo_header,
            }
        }
        SubFormat::SingBoxJson => {
            let mut outbounds = Vec::new();
            let mut tags = Vec::new();
            let mut reg_entries = Vec::new();
            for m in &matched {
                if let Some((o, detour)) = build_singbox_outbound(
                    m.ib,
                    m.client,
                    m.source.host,
                    &m.unique_name,
                    m.source.certs,
                    m.source.cert_pems,
                ) {
                    tags.push(m.unique_name.clone());
                    reg_entries.push((m.unique_name.clone(), m.region.clone()));
                    outbounds.push(o);
                    if let Some(d) = detour {
                        outbounds.push(d);
                    }
                }
            }
            let region_groups =
                build_region_groups(&reg_entries, multi_source, template.enable_region_groups);
            let cfg = build_singbox_document(outbounds, &tags, &region_groups, template);
            SubscriptionPayload {
                content_type: "application/json; charset=utf-8",
                body: serde_json::to_string_pretty(&cfg).unwrap_or_default(),
                userinfo_header,
            }
        }
    }
}
