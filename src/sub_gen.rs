use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping, Value as YamlValue};

use crate::crypto_util::derive_reality_public_key;
use crate::models::{ClientRecord, Inbound};

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
fn effective_tls_sni(ib: &Inbound) -> String {
    let sni = ib.stream_settings.tls.sni.trim();
    if !sni.is_empty() {
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

pub fn build_uri(ib: &Inbound, c: &ClientRecord, host: &str, name: &str) -> String {
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let addr = format_host(host);
    let port = ib.port;
    let tag = enc_fragment(name);

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
                if !ss.ws.host.trim().is_empty() {
                    params.push(format!("host={}", enc_query(ss.ws.host.trim())));
                }
            } else if net == "xhttp" {
                params.push(format!("path={}", enc_path_param(ss.xhttp.path.trim())));
                if !ss.xhttp.host.trim().is_empty() {
                    params.push(format!("host={}", enc_query(ss.xhttp.host.trim())));
                }
                if !ss.xhttp.mode.trim().is_empty() {
                    params.push(format!("mode={}", enc_query(ss.xhttp.mode.trim())));
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
                "" | "any" => "auto",
                other => other,
            };
            let net = if ss.network == "ws" { "ws" } else { "tcp" };
            let tls_str = if ss.security == "tls" { "tls" } else { "" };
            let host_hdr = if net == "ws" {
                ss.ws.host.trim()
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
            }
            if ss.network == "ws" {
                params.push(format!("path={}", enc_path_param(ss.ws.path.trim())));
                if !ss.ws.host.trim().is_empty() {
                    params.push(format!("host={}", enc_query(ss.ws.host.trim())));
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
            format!("ss://{userinfo}@{addr}:{port}#{tag}")
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
            format!(
                "{} = snell, {}, {}, psk={}, version=4, reuse=true",
                name,
                host.trim(),
                port,
                c.password.trim()
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

fn build_shoes_client_snippet(ib: &Inbound, c: &ClientRecord, host: &str, name: &str) -> String {
    let ss = &ib.stream_settings;
    let ps = &ib.protocol_settings;
    let target_addr = format!("{}:{}", format_host(host), ib.port);

    let inner = match ib.protocol.as_str() {
        "vless" => json!({"type": "vless", "user_id": c.uuid.trim()}),
        "vmess" => {
            let cipher = match ps.cipher.trim() {
                "" | "any" | "auto" => "aes-128-gcm",
                other => other,
            };
            json!({"type": "vmess", "cipher": cipher, "user_id": c.uuid.trim()})
        }
        "trojan" => json!({"type": "trojan", "password": c.password.trim()}),
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
            let cipher = if ps.cipher.trim().is_empty() {
                "chacha20-ietf-poly1305"
            } else {
                ps.cipher.trim()
            };
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
        json!({
            "type": "websocket",
            "matching_path": ss.ws.path.trim(),
            "protocol": inner
        })
    } else if !ib.is_quic() && ss.network == "xhttp" {
        json!({
            "type": "xhttp",
            "path": ss.xhttp.path.trim(),
            "mode": if ss.xhttp.mode.trim().is_empty() { "auto" } else { ss.xhttp.mode.trim() },
            "protocol": inner
        })
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
            "quic_settings": {
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
        json!({
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
        })
    } else if ss.security == "tls" {
        let vision = ib.protocol == "vless" && ss.network == "tcp" && ss.tls.vision;
        let mut sni = effective_tls_sni(ib);
        if sni.is_empty() {
            sni = host.trim().to_string();
        }
        json!({
            "name": name,
            "address": target_addr,
            "protocol": {
                "type": "tls",
                "sni_hostname": sni,
                "verify": !ss.tls.allow_insecure,
                "vision": vision,
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

    match ib.protocol.as_str() {
        "vless" => {
            if ss.network == "xhttp" {
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
            if ss.security == "reality" {
                let fp = if ss.reality.fingerprint.trim().is_empty() {
                    "chrome"
                } else {
                    ss.reality.fingerprint.trim()
                };
                obj["tls"] = json!(true);
                obj["servername"] = json!(ss.reality.sni.trim());
                obj["client-fingerprint"] = json!(fp);
                if ss.network == "tcp" && ss.reality.vision {
                    obj["flow"] = json!("xtls-rprx-vision");
                }
                obj["reality-opts"] = json!({
                    "public-key": effective_reality_pubkey(ib),
                    "short-id": ss.reality.short_ids.first().map(|s| s.trim()).unwrap_or("")
                });
            } else if ss.security == "tls" {
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
            if ss.network == "ws" {
                let mut ws_opts = json!({ "path": ss.ws.path.trim() });
                if !ss.ws.host.trim().is_empty() {
                    ws_opts["headers"] = json!({ "Host": ss.ws.host.trim() });
                }
                obj["ws-opts"] = ws_opts;
            }
            Some(obj)
        }
        "vmess" => {
            let cipher = match ps.cipher.trim() {
                "" | "any" => "auto",
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
            if ss.network == "ws" {
                let mut ws_opts = json!({ "path": ss.ws.path.trim() });
                if !ss.ws.host.trim().is_empty() {
                    ws_opts["headers"] = json!({ "Host": ss.ws.host.trim() });
                }
                obj["ws-opts"] = ws_opts;
            }
            Some(obj)
        }
        "trojan" => {
            let mut obj = json!({
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": c.password.trim(),
                "udp": true,
                "network": if ss.network == "ws" { "ws" } else { "tcp" },
            });
            if ss.security == "reality" {
                let fp = if ss.reality.fingerprint.trim().is_empty() {
                    "chrome"
                } else {
                    ss.reality.fingerprint.trim()
                };
                obj["sni"] = json!(ss.reality.sni.trim());
                obj["client-fingerprint"] = json!(fp);
                obj["reality-opts"] = json!({
                    "public-key": effective_reality_pubkey(ib),
                    "short-id": ss.reality.short_ids.first().map(|s| s.trim()).unwrap_or("")
                });
            } else {
                obj["skip-cert-verify"] = json!(ss.tls.allow_insecure);
                let sni = effective_tls_sni(ib);
                if !sni.is_empty() {
                    obj["sni"] = json!(sni);
                }
            }
            if ss.network == "ws" {
                obj["ws-opts"] = json!({ "path": ss.ws.path.trim() });
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
            Some(json!({
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": cipher,
                "password": c.password.trim(),
                "udp": ps.udp_enabled,
            }))
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
                "alpn": ["h3"],
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
        "snell" => Some(json!({
            "name": name,
            "type": "snell",
            "server": server,
            "port": port,
            "psk": c.password.trim(),
            "version": 4,
            "udp": ps.udp_enabled,
        })),
        "socks" | "mixed" => {
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
    }
}

fn build_singbox_outbound(
    ib: &Inbound,
    c: &ClientRecord,
    host: &str,
    name: &str,
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
            t["alpn"] = json!(["h3"]);
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

    match ib.protocol.as_str() {
        "vless" => {
            if ss.network == "xhttp" {
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
            if ss.network == "ws" {
                obj["transport"] = json!({
                    "type": "ws",
                    "path": ss.ws.path.trim(),
                });
            }
            Some(obj)
        }
        "vmess" => {
            let cipher = match ps.cipher.trim() {
                "" | "any" => "auto",
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
            if ss.network == "ws" {
                obj["transport"] = json!({
                    "type": "ws",
                    "path": ss.ws.path.trim(),
                });
            }
            Some(obj)
        }
        "trojan" => {
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
            if ss.network == "ws" {
                obj["transport"] = json!({
                    "type": "ws",
                    "path": ss.ws.path.trim(),
                });
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
            Some(json!({
                "tag": name,
                "type": "shadowsocks",
                "server": server,
                "server_port": port,
                "method": cipher,
                "password": c.password.trim(),
            }))
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
        "socks" | "mixed" => {
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
    }
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

pub fn generate_subscription(
    inbounds: &[Inbound],
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
                if let Some(o) = build_singbox_outbound(ib, c, host, name) {
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
