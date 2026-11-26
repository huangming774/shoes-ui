use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping, Value as YamlValue};

use crate::crypto_util::derive_reality_public_key;
use crate::models::{CertificateRecord, ClientRecord, H2MuxSettings, Inbound};

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

pub fn build_client_share_info(ib: &Inbound, c: &ClientRecord, host: &str) -> ShareInfo {
    let name = node_display_name(ib, c);
    let uri = build_uri(ib, c, host, &name);
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
fn resolve_inbound_cert_pem(ib: &Inbound, certs: &[CertificateRecord]) -> Option<String> {
    let tls = &ib.stream_settings.tls;
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
    match ib.protocol.as_str() {
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
            (ss.network == "tcp" && ss.security == "none")
                || (ss.network == "ws"
                    && matches!(ss.security.as_str(), "none" | "tls")
                    && !has_non_host_ws_headers(ib))
        }
        "vless" => matches!(ss.network.as_str(), "tcp" | "ws" | "xhttp"),
        "vmess" | "trojan" => matches!(ss.network.as_str(), "tcp" | "ws"),
        _ => ss.network == "tcp",
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
            params.push("encryption=none".to_string());
            let net = match ss.network.as_str() {
                "ws" => "ws",
                "xhttp" => "xhttp",
                _ => "tcp",
            };

            if ss.security == "reality" {
                if ss.network == "tcp" && ss.reality.vision {
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
                if ss.network == "tcp" && ss.tls.vision {
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
            } else {
                format!("ss://{userinfo}@{addr}:{port}#{tag}")
            }
        }
        "hysteria2" => {
            let mut params = Vec::new();
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
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let target_addr = format!("{}:{}", format_host(host), ib.port);
    let active_mux = inbound_effective_h2mux(ib);

    let inner = match ib.protocol.as_str() {
        "vless" => {
            let mut m = json!({"type": "vless", "user_id": c.uuid.trim()});
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
            json!({"type": "hysteria2", "password": c.password.trim(), "udp_enabled": true})
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

    let client_hop = if ib.is_quic() {
        let mut sni = effective_tls_sni(ib);
        if sni.is_empty() {
            sni = host.trim().to_string();
        }
        json!({
            "name": name,
            "address": target_addr,
            "transport": "quic",
            "quic_settings": {
                "alpn_protocols": if ss.tls.alpn.is_empty() { json!(["h3"]) } else { json!(ss.tls.alpn) },
                "sni_hostname": sni,
                "verify": !ss.tls.allow_insecure
            },
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
        let vision = ib.protocol == "vless" && ss.network == "tcp" && ss.reality.vision;
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
        let vision = ib.protocol == "vless" && ss.network == "tcp" && ss.tls.vision;
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
        if ib.protocol == "naiveproxy" {
            hop["protocol"]["alpn_protocols"] = json!(["h2", "http/1.1"]);
        } else if !ss.tls.alpn.is_empty() {
            hop["protocol"]["alpn_protocols"] = json!(ss.tls.alpn);
        }
        hop
    } else {
        json!({
            "name": name,
            "address": target_addr,
            "protocol": transported
        })
    };

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
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let server = host.trim();
    let port = ib.port;

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
            if ss.security == "reality" && ss.network == "tcp" && ss.reality.vision {
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
                if ss.network == "tcp" && ss.tls.vision {
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
) -> Option<JsonValue> {
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let server = host.trim();
    let port = ib.port;

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
            if ss.network == "tcp" && ss.security == "none" {
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
                        let pem = resolve_inbound_cert_pem(ib, certs)?;
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
                let pem = resolve_inbound_cert_pem(ib, certs)?;
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
    Some(obj)
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
    let match_all = sub_id_filter.eq_ignore_ascii_case("all") || sub_id_filter == "*";

    let mut matched_pairs: Vec<(&Inbound, &ClientRecord, String)> = Vec::new();
    let mut used_names = std::collections::HashSet::new();

    let mut total_up: i64 = 0;
    let mut total_down: i64 = 0;
    let mut total_quota: i64 = 0;
    let mut has_unlimited_quota = false;
    let mut earliest_expiry_ms: i64 = 0;

    for ib in inbounds.iter().filter(|i| i.enable) {
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
                let base_name = node_display_name(ib, c);
                let mut unique_name = base_name.clone();
                let mut suffix = 2;
                while !used_names.insert(unique_name.clone()) {
                    unique_name = format!("{base_name}-{suffix}");
                    suffix += 1;
                }
                matched_pairs.push((ib, c, unique_name));
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
            let uris: Vec<String> = matched_pairs
                .iter()
                .map(|(ib, c, name)| build_uri(ib, c, host, name))
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
            for (ib, c, name) in &matched_pairs {
                if let Some(p) = build_clash_proxy(ib, c, host, name) {
                    names.push(name.clone());
                    proxies.push(p);
                }
            }
            let mut selector_members = vec!["⚡ Auto".to_string()];
            selector_members.extend(names.iter().cloned());
            selector_members.push("DIRECT".to_string());

            let auto_members = if names.is_empty() {
                vec!["DIRECT".to_string()]
            } else {
                names.clone()
            };

            // Zero-MMDB pure IP-CIDR + MATCH rules: works out-of-the-box on Classic Clash,
            // Mihomo, Clash Verge, Stash, ClashX, and Shadowrocket without needing GeoIP.dat!
            let doc = json!({
                "mixed-port": 7890,
                "allow-lan": false,
                "mode": "rule",
                "log-level": "info",
                "dns": {
                    "enable": true,
                    "ipv6": false,
                    "enhanced-mode": "fake-ip",
                    "fake-ip-range": "198.18.0.1/16",
                    "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"]
                },
                "proxies": proxies,
                "proxy-groups": [
                    {
                        "name": "🚀 Proxy",
                        "type": "select",
                        "proxies": selector_members
                    },
                    {
                        "name": "⚡ Auto",
                        "type": "url-test",
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": 300,
                        "proxies": auto_members
                    }
                ],
                "rules": [
                    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                    "MATCH,🚀 Proxy"
                ]
            });
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
            for (ib, c, name) in &matched_pairs {
                if let Some(o) = build_singbox_outbound(ib, c, host, name, certs) {
                    tags.push(name.clone());
                    outbounds.push(o);
                }
            }
            let mut select_tags = vec!["auto".to_string()];
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
                    "interval": "5m"
                }));
            } else {
                all_outbounds.push(json!({
                    "tag": "auto",
                    "type": "direct"
                }));
            }
            all_outbounds.extend(outbounds);
            all_outbounds.push(json!({ "tag": "direct", "type": "direct" }));

            let cfg = json!({
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
                "route": {
                    "final": "proxy",
                    "auto_detect_interface": true
                }
            });
            SubscriptionPayload {
                content_type: "application/json; charset=utf-8",
                body: serde_json::to_string_pretty(&cfg).unwrap_or_default(),
                userinfo_header,
            }
        }
    }
}
