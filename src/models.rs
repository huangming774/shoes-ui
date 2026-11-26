use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn default_true() -> bool {
    true
}

pub fn default_listen() -> String {
    "0.0.0.0".to_string()
}

pub fn default_network() -> String {
    "tcp".to_string()
}

pub fn default_security() -> String {
    "none".to_string()
}

pub fn default_sub_id() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize)]
pub struct InboundTotals {
    pub up_bytes: i64,
    pub down_bytes: i64,
    pub inbounds_total: i64,
    pub inbounds_enabled: i64,
    pub clients_total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub tag: String,
    pub remark: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub protocol_settings: ProtocolSettings,
    #[serde(default)]
    pub stream_settings: StreamSettings,
    #[serde(default)]
    pub up_bytes: i64,
    #[serde(default)]
    pub down_bytes: i64,
    #[serde(default)]
    pub total_quota_bytes: i64,
    #[serde(default)]
    pub expiry_time: i64,
    #[serde(default)]
    pub auto_reset_day: i64,
    #[serde(default)]
    pub last_reset_month: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub clients: Vec<ClientRecord>,
}

impl Inbound {
    /// Whether this protocol supports multiple users on a single port in upstream `shoes`.
    pub fn supports_multi_user(&self) -> bool {
        matches!(self.protocol.as_str(), "anytls" | "naiveproxy" | "wireguard")
    }

    pub fn uses_auto_quic_cert(&self) -> bool {
        let tls = &self.stream_settings.tls;
        matches!(self.protocol.as_str(), "tuic" | "hysteria2")
            && (tls.cert_mode == "auto"
                || (tls.cert_mode == "source" && tls.certificate_source.trim().is_empty()
                    && tls.cert_file.trim().is_empty() && tls.key_file.trim().is_empty()))
    }

    pub fn is_quic(&self) -> bool {
        matches!(self.protocol.as_str(), "hysteria2" | "tuic")
            || self.stream_settings.network == "quic"
    }

    /// True for UDP-based transports (QUIC protocols + WireGuard).
    pub fn is_udp_transport(&self) -> bool {
        self.is_quic() || self.protocol == "wireguard"
    }

    /// True when this inbound can share a single TCP `(listen, port)` listener via
    /// outer TLS / REALITY / ShadowTLS SNI multiplexing (`tls_targets`, `reality_targets`, `shadowtls_targets`).
    pub fn can_share_sni_port(&self) -> bool {
        !self.is_udp_transport()
            && self.protocol != "portforward"
            && self.protocol_settings.raw_override_yaml.trim().is_empty()
            && self.protocol_settings.port_range.trim().is_empty()
            && !self.stream_settings.sudoku.enabled
            && matches!(
                self.stream_settings.security.as_str(),
                "tls" | "reality" | "shadowtls"
            )
    }

    /// Normalized SNI routing key for port-443 SNI multiplexing.
    /// `None` represents the default/fallback TLS target (`default_tls_target`).
    pub fn sni_mux_key(&self) -> Option<String> {
        let ss = &self.stream_settings;
        let raw = match ss.security.as_str() {
            "reality" => ss.reality.sni.trim(),
            "shadowtls" => ss.shadowtls.sni.trim(),
            "tls" => ss.tls.sni.trim(),
            _ => "",
        };
        if raw.is_empty() {
            None
        } else {
            Some(raw.trim_end_matches('.').to_ascii_lowercase())
        }
    }

    pub fn has_vless_native_encryption(&self) -> bool {
        self.protocol == "vless"
            && !matches!(
                self.protocol_settings.vless_decryption.trim(),
                "" | "none"
            )
    }

    pub fn has_vless_vision(&self) -> bool {
        if self.protocol != "vless" {
            return false;
        }
        if self.has_vless_native_encryption() && self.protocol_settings.vless_native_vision {
            return true;
        }
        self.stream_settings.network == "tcp"
            && ((self.stream_settings.security == "tls" && self.stream_settings.tls.vision)
                || (self.stream_settings.security == "reality"
                    && self.stream_settings.reality.vision))
    }

    /// Protocols/transports where H2Mux (`sing-mux` / `h2mux`) applies cleanly.
    /// QUIC / Hysteria2 / TUIC / AnyTLS / NaiveProxy / XHTTP / WireGuard / PortForward are excluded.
    pub fn supports_h2mux(&self) -> bool {
        let ss = &self.stream_settings;
        if ss.security == "shadowtls" {
            return false;
        }
        match self.protocol.as_str() {
            "vless" => matches!(ss.network.as_str(), "tcp" | "ws") && !self.has_vless_vision(),
            "vmess" | "trojan" => matches!(ss.network.as_str(), "tcp" | "ws"),
            "shadowsocks" => ss.network == "tcp" && ss.security == "none",
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientRecord {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub inbound_id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default = "default_sub_id")]
    pub sub_id: String,
    #[serde(default)]
    pub up_bytes: i64,
    #[serde(default)]
    pub down_bytes: i64,
    #[serde(default)]
    pub total_quota_bytes: i64,
    #[serde(default)]
    pub expiry_time: i64,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub created_at: i64,
    // WireGuard server peer fields (only used when inbound.protocol == "wireguard")
    #[serde(default)]
    pub wg_private_key: String,
    #[serde(default)]
    pub wg_public_key: String,
    #[serde(default)]
    pub wg_preshared_key: String,
    #[serde(default)]
    pub wg_allowed_ips: String,
    #[serde(default)]
    pub wg_keepalive: u16,
}

fn default_wg_mtu() -> u16 {
    1408
}

fn default_wg_dns() -> String {
    "1.1.1.1".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSettings {
    #[serde(default = "default_true")]
    pub udp_enabled: bool,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub fallback: String,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default = "default_true")]
    pub padding: bool,
    #[serde(default)]
    pub padding_scheme: Vec<String>,
    #[serde(default)]
    pub sniff: bool,
    #[serde(default)]
    pub rules_ref: String,
    #[serde(default)]
    pub dns_group: String,
    #[serde(default)]
    pub vless_decryption: String,
    #[serde(default)]
    pub vless_encryption: String,
    #[serde(default)]
    pub vless_native_vision: bool,
    #[serde(default)]
    pub port_range: String,
    #[serde(default)]
    pub forward_targets: Vec<String>,
    // WireGuard server inbound settings
    #[serde(default)]
    pub wg_server_private_key: String,
    #[serde(default)]
    pub wg_server_public_key: String,
    #[serde(default)]
    pub wg_server_addresses: Vec<String>,
    #[serde(default = "default_wg_mtu")]
    pub wg_mtu: u16,
    #[serde(default = "default_wg_dns")]
    pub wg_dns: String,
    #[serde(default)]
    pub wg_bind_interface: String,
    #[serde(default = "default_true")]
    pub wg_block_private: bool,
    #[serde(default)]
    pub wg_tcp_buffer_size: Option<u32>,
    #[serde(default)]
    pub wg_tcp_memory_bytes: Option<u64>,
    #[serde(default)]
    pub raw_override_yaml: String,
}

impl Default for ProtocolSettings {
    fn default() -> Self {
        Self {
            udp_enabled: true,
            cipher: String::new(),
            fallback: String::new(),
            zero_rtt_handshake: false,
            padding: true,
            padding_scheme: Vec::new(),
            sniff: false,
            rules_ref: String::new(),
            dns_group: String::new(),
            vless_decryption: String::new(),
            vless_encryption: String::new(),
            vless_native_vision: false,
            port_range: String::new(),
            forward_targets: Vec::new(),
            wg_server_private_key: String::new(),
            wg_server_public_key: String::new(),
            wg_server_addresses: Vec::new(),
            wg_mtu: default_wg_mtu(),
            wg_dns: default_wg_dns(),
            wg_bind_interface: String::new(),
            wg_block_private: true,
            wg_tcp_buffer_size: None,
            wg_tcp_memory_bytes: None,
            raw_override_yaml: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SudokuMaskSettings {
    pub enabled: bool,
    pub password: String,
    pub ascii: String, // "" | "prefer_entropy" | "entropy" | "prefer_ascii" | "ascii"
    pub custom_table: String,
    pub custom_tables: Vec<String>,
    pub padding_min: u32,
    pub padding_max: u32,
}

fn default_h2mux_max_connections() -> u32 {
    4
}

fn default_h2mux_min_streams() -> u32 {
    4
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2MuxSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_h2mux_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_h2mux_min_streams")]
    pub min_streams: u32,
    #[serde(default)]
    pub max_streams: u32,
    #[serde(default)]
    pub padding: bool,
}

impl Default for H2MuxSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: 4,
            min_streams: 4,
            max_streams: 0,
            padding: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub tls: TlsSettings,
    #[serde(default)]
    pub reality: RealitySettings,
    #[serde(default)]
    pub shadowtls: ShadowTlsSettings,
    #[serde(default)]
    pub ws: WsSettings,
    #[serde(default)]
    pub xhttp: XhttpSettings,
    #[serde(default)]
    pub h2mux: H2MuxSettings,
    #[serde(default)]
    pub sudoku: SudokuMaskSettings,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            network: "tcp".to_string(),
            security: "none".to_string(),
            tls: TlsSettings::default(),
            reality: RealitySettings::default(),
            shadowtls: ShadowTlsSettings::default(),
            ws: WsSettings::default(),
            xhttp: XhttpSettings::default(),
            h2mux: H2MuxSettings::default(),
            sudoku: SudokuMaskSettings::default(),
        }
    }
}

fn default_shadowtls_mode() -> String {
    "remote".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowTlsSettings {
    #[serde(default = "default_reality_sni")]
    pub sni: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_shadowtls_mode")]
    pub handshake_mode: String, // "remote" | "local"
    #[serde(default = "default_reality_dest")]
    pub handshake_addr: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub client_ca_certs: Vec<String>,
    #[serde(default)]
    pub client_fingerprints: Vec<String>,
}

impl Default for ShadowTlsSettings {
    fn default() -> Self {
        Self {
            sni: default_reality_sni(),
            password: String::new(),
            handshake_mode: default_shadowtls_mode(),
            handshake_addr: default_reality_dest(),
            cert_file: String::new(),
            key_file: String::new(),
            client_ca_certs: Vec::new(),
            client_fingerprints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default)]
    pub sni: String,
    #[serde(default = "default_true")]
    pub allow_any_sni: bool,
    #[serde(default = "default_cert_mode")]
    pub cert_mode: String, // "source" | "files" | "auto" (native QUIC)
    #[serde(default)]
    pub certificate_source: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub vision: bool,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub key_exchange_groups: Vec<String>,
    #[serde(default)]
    pub client_ca_certs: Vec<String>,
    #[serde(default)]
    pub client_fingerprints: Vec<String>,
}

fn default_cert_mode() -> String {
    "source".to_string()
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            sni: String::new(),
            allow_any_sni: true,
            cert_mode: "source".to_string(),
            certificate_source: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            alpn: Vec::new(),
            vision: false,
            fingerprint: "chrome".to_string(),
            allow_insecure: false,
            key_exchange_groups: Vec::new(),
            client_ca_certs: Vec::new(),
            client_fingerprints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealitySettings {
    #[serde(default = "default_reality_sni")]
    pub sni: String,
    #[serde(default = "default_reality_dest")]
    pub dest: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default = "default_short_ids")]
    pub short_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub vision: bool,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    #[serde(default)]
    pub mldsa65_seed: String,
    #[serde(default)]
    pub mldsa65_verify: String,
}

fn default_reality_sni() -> String {
    "www.microsoft.com".to_string()
}

fn default_reality_dest() -> String {
    "www.microsoft.com:443".to_string()
}

fn default_short_ids() -> Vec<String> {
    vec!["0123456789abcdef".to_string()]
}

impl Default for RealitySettings {
    fn default() -> Self {
        Self {
            sni: default_reality_sni(),
            dest: default_reality_dest(),
            private_key: String::new(),
            public_key: String::new(),
            short_ids: default_short_ids(),
            vision: true,
            fingerprint: "chrome".to_string(),
            mldsa65_seed: String::new(),
            mldsa65_verify: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettings {
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub max_early_data: usize,
    #[serde(default)]
    pub early_data_header_name: String,
}

impl WsSettings {
    pub fn host_header(&self) -> &str {
        self.headers.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim())
            .unwrap_or(self.host.trim())
    }

    pub fn matching_headers(&self) -> BTreeMap<String, String> {
        let mut headers = self.headers.clone();
        if !self.host.trim().is_empty() && !headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
            headers.insert("Host".into(), self.host.trim().into());
        }
        headers
    }
}

fn default_ws_path() -> String {
    "/ws".to_string()
}

impl Default for WsSettings {
    fn default() -> Self {
        Self {
            path: "/ws".to_string(),
            host: String::new(),
            headers: BTreeMap::new(),
            max_early_data: 0,
            early_data_header_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(default = "default_xhttp_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_xhttp_mode")]
    pub mode: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_xhttp_path() -> String {
    "/xhttp".to_string()
}

fn default_xhttp_mode() -> String {
    "auto".to_string()
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
            path: "/xhttp".to_string(),
            host: String::new(),
            mode: "auto".to_string(),
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    pub cert_type: String, // "files" | "acme" | "acme_ip"
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub email: String,
    #[serde(default = "default_acme_dir")]
    pub directory_url: String,
    #[serde(default = "default_acme_tos")]
    pub terms_of_service: String,
    #[serde(default = "default_acme_challenge")]
    pub challenge_type: String, // "http01" | "tls_alpn01"
    #[serde(default = "default_http01_listen")]
    pub http01_listen: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub created_at: i64,
}

pub const DEFAULT_LETSENCRYPT_DIR: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const DEFAULT_LETSENCRYPT_TOS: &str =
    "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf";

fn default_acme_dir() -> String {
    DEFAULT_LETSENCRYPT_DIR.to_string()
}

fn default_acme_tos() -> String {
    DEFAULT_LETSENCRYPT_TOS.to_string()
}

fn default_acme_challenge() -> String {
    "http01".to_string()
}

fn default_http01_listen() -> String {
    "0.0.0.0:80".to_string()
}

/// Single hop inside a visual multi-hop outbound chain (used for hop 2..N in `OutboundMember.extra_hops`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutboundHop {
    pub protocol: String, // "direct" | "group" | "socks" | "http" | "shadowsocks" | "vless" | "vmess" | "trojan" | "hysteria2" | "tuic" | "anytls" | "wireguard" | "snell"
    pub address: String,
    pub uuid: String,
    pub username: String,
    pub password: String,
    pub cipher: String,
    pub security: String, // "" | "none" | "tls" | "reality" | "shadowtls"
    pub tls: bool,
    pub shadowtls: bool,
    pub shadowtls_password: String,
    pub sni: String,
    pub verify: bool,
    pub alpn: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub server_fingerprints: Vec<String>,
    pub key_exchange_groups: Vec<String>,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub reality_mldsa65_verify: String,
    pub vision: bool,
    pub vless_encryption: String,
    pub network: String, // "" | "tcp" | "ws" | "xhttp"
    pub ws_path: String,
    pub ws_host: String,
    pub xhttp_path: String,
    pub xhttp_host: String,
    pub xhttp_mode: String,
    pub hy2_obfs_password: String,
    pub hy2_hopping_ports: String,
    pub tuic_udp_mode: String, // "native" | "quic"
    pub h2mux: H2MuxSettings,
    pub sudoku: SudokuMaskSettings,
    pub bind_interface: String,
    pub wg_private_key: String,
    pub wg_public_key: String,
    pub wg_preshared_key: String,
    pub wg_addresses: Vec<String>,
    pub wg_allowed_ips: Vec<String>,
    pub wg_mtu: u16,
    pub wg_keepalive: u16,
    pub wg_tcp_buffer_size: Option<u32>,
    pub wg_tcp_memory_bytes: Option<u64>,
}

impl Default for OutboundHop {
    fn default() -> Self {
        Self {
            protocol: "socks".to_string(),
            address: String::new(),
            uuid: String::new(),
            username: String::new(),
            password: String::new(),
            cipher: String::new(),
            security: String::new(),
            tls: false,
            shadowtls: false,
            shadowtls_password: String::new(),
            sni: String::new(),
            verify: true,
            alpn: Vec::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            server_fingerprints: Vec::new(),
            key_exchange_groups: Vec::new(),
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            reality_mldsa65_verify: String::new(),
            vision: false,
            vless_encryption: String::new(),
            network: String::new(),
            ws_path: String::new(),
            ws_host: String::new(),
            xhttp_path: String::new(),
            xhttp_host: String::new(),
            xhttp_mode: String::new(),
            hy2_obfs_password: String::new(),
            hy2_hopping_ports: String::new(),
            tuic_udp_mode: String::new(),
            h2mux: H2MuxSettings::default(),
            sudoku: SudokuMaskSettings::default(),
            bind_interface: String::new(),
            wg_private_key: String::new(),
            wg_public_key: String::new(),
            wg_preshared_key: String::new(),
            wg_addresses: Vec::new(),
            wg_allowed_ips: Vec::new(),
            wg_mtu: 0,
            wg_keepalive: 0,
            wg_tcp_buffer_size: None,
            wg_tcp_memory_bytes: None,
        }
    }
}

impl OutboundHop {
    pub fn effective_security(&self) -> &str {
        let sec = self.security.trim();
        if !sec.is_empty() {
            sec
        } else if self.shadowtls {
            "shadowtls"
        } else if !self.reality_public_key.trim().is_empty() {
            "reality"
        } else if self.tls {
            "tls"
        } else {
            "none"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutboundMember {
    pub name: String,
    pub protocol: String, // "direct" | "socks" | "http" | "shadowsocks" | "vless" | "vmess" | "trojan" | "hysteria2" | "tuic" | "anytls" | "wireguard" | "snell" | "group"
    pub address: String,
    pub uuid: String,
    pub username: String,
    pub password: String,
    pub cipher: String,
    pub security: String, // "" | "none" | "tls" | "reality" | "shadowtls"
    pub tls: bool,
    pub shadowtls: bool,
    pub shadowtls_password: String,
    pub sni: String,
    pub verify: bool,
    pub alpn: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub server_fingerprints: Vec<String>,
    pub key_exchange_groups: Vec<String>,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub reality_mldsa65_verify: String,
    pub vision: bool,
    pub vless_encryption: String,
    pub network: String, // "" | "tcp" | "ws" | "xhttp"
    pub ws_path: String,
    pub ws_host: String,
    pub xhttp_path: String,
    pub xhttp_host: String,
    pub xhttp_mode: String,
    pub hy2_obfs_password: String,
    pub hy2_hopping_ports: String,
    pub tuic_udp_mode: String,
    pub h2mux: H2MuxSettings,
    pub sudoku: SudokuMaskSettings,
    pub bind_interface: String,
    pub wg_private_key: String,
    pub wg_public_key: String,
    pub wg_preshared_key: String,
    pub wg_addresses: Vec<String>,
    pub wg_allowed_ips: Vec<String>,
    pub wg_mtu: u16,
    pub wg_keepalive: u16,
    pub wg_tcp_buffer_size: Option<u32>,
    pub wg_tcp_memory_bytes: Option<u64>,
    /// Additional sequential proxy hops appended after hop 0 (visual multi-hop chain builder).
    pub extra_hops: Vec<OutboundHop>,
}

impl Default for OutboundMember {
    fn default() -> Self {
        Self {
            name: String::new(),
            protocol: String::new(),
            address: String::new(),
            uuid: String::new(),
            username: String::new(),
            password: String::new(),
            cipher: String::new(),
            security: String::new(),
            tls: false,
            shadowtls: false,
            shadowtls_password: String::new(),
            sni: String::new(),
            verify: true,
            alpn: Vec::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            server_fingerprints: Vec::new(),
            key_exchange_groups: Vec::new(),
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            reality_mldsa65_verify: String::new(),
            vision: false,
            vless_encryption: String::new(),
            network: String::new(),
            ws_path: String::new(),
            ws_host: String::new(),
            xhttp_path: String::new(),
            xhttp_host: String::new(),
            xhttp_mode: String::new(),
            hy2_obfs_password: String::new(),
            hy2_hopping_ports: String::new(),
            tuic_udp_mode: String::new(),
            h2mux: H2MuxSettings::default(),
            sudoku: SudokuMaskSettings::default(),
            bind_interface: String::new(),
            wg_private_key: String::new(),
            wg_public_key: String::new(),
            wg_preshared_key: String::new(),
            wg_addresses: Vec::new(),
            wg_allowed_ips: Vec::new(),
            wg_mtu: 0,
            wg_keepalive: 0,
            wg_tcp_buffer_size: None,
            wg_tcp_memory_bytes: None,
            extra_hops: Vec::new(),
        }
    }
}

impl OutboundMember {
    pub fn primary_hop(&self) -> OutboundHop {
        OutboundHop {
            protocol: self.protocol.clone(),
            address: self.address.clone(),
            uuid: self.uuid.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            cipher: self.cipher.clone(),
            security: self.security.clone(),
            tls: self.tls,
            shadowtls: self.shadowtls,
            shadowtls_password: self.shadowtls_password.clone(),
            sni: self.sni.clone(),
            verify: self.verify,
            alpn: self.alpn.clone(),
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            server_fingerprints: self.server_fingerprints.clone(),
            key_exchange_groups: self.key_exchange_groups.clone(),
            reality_public_key: self.reality_public_key.clone(),
            reality_short_id: self.reality_short_id.clone(),
            reality_mldsa65_verify: self.reality_mldsa65_verify.clone(),
            vision: self.vision,
            vless_encryption: self.vless_encryption.clone(),
            network: self.network.clone(),
            ws_path: self.ws_path.clone(),
            ws_host: self.ws_host.clone(),
            xhttp_path: self.xhttp_path.clone(),
            xhttp_host: self.xhttp_host.clone(),
            xhttp_mode: self.xhttp_mode.clone(),
            hy2_obfs_password: self.hy2_obfs_password.clone(),
            hy2_hopping_ports: self.hy2_hopping_ports.clone(),
            tuic_udp_mode: self.tuic_udp_mode.clone(),
            h2mux: self.h2mux.clone(),
            sudoku: self.sudoku.clone(),
            bind_interface: self.bind_interface.clone(),
            wg_private_key: self.wg_private_key.clone(),
            wg_public_key: self.wg_public_key.clone(),
            wg_preshared_key: self.wg_preshared_key.clone(),
            wg_addresses: self.wg_addresses.clone(),
            wg_allowed_ips: self.wg_allowed_ips.clone(),
            wg_mtu: self.wg_mtu,
            wg_keepalive: self.wg_keepalive,
            wg_tcp_buffer_size: self.wg_tcp_buffer_size,
            wg_tcp_memory_bytes: self.wg_tcp_memory_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundGroupRecord {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_group_type")]
    pub group_type: String, // "selector" | "url-test" | "round-robin"
    #[serde(default)]
    pub default_member: String,
    #[serde(default = "default_probe_url")]
    pub test_url: String,
    #[serde(default = "default_probe_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_probe_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_probe_tolerance")]
    pub tolerance_ms: u64,
    #[serde(default)]
    pub members: Vec<OutboundMember>,
    #[serde(default)]
    pub raw_chains_yaml: String,
    #[serde(default)]
    pub remark: String,
}

fn default_group_type() -> String {
    "selector".to_string()
}

fn default_probe_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}

fn default_probe_interval() -> u64 {
    300
}

fn default_probe_timeout() -> u64 {
    5000
}

fn default_probe_tolerance() -> u64 {
    50
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingRuleRecord {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub remark: String,
    pub match_type: String, // "masks" | "domain" | "domain_suffix" | "domain_keyword" | "ip_cidr" | "destination_port" | "network" | "udp_stun" | "rule_source_group" | "any" | "raw_yaml"
    #[serde(default)]
    pub match_value: String,
    #[serde(default = "default_rule_action")]
    pub action: String, // "allow" | "block"
    #[serde(default = "default_rule_outbound")]
    pub outbound: String, // "direct" | group_name
    #[serde(default)]
    pub no_resolve: bool,
    #[serde(default)]
    pub override_address: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsServerItem {
    pub url: String,
    #[serde(default)]
    pub ip_strategy: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub bootstrap_url: String,
    #[serde(default)]
    pub client_chain: String,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u32>,
    #[serde(default)]
    pub attempts: Option<usize>,
    #[serde(default)]
    pub native_cache_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsGroupRecord {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub servers: Vec<DnsServerItem>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub created_at: i64,
}

fn default_rule_source_type() -> String {
    "url".to_string()
}

fn default_rule_sync_mode() -> String {
    "panel".to_string()
}

fn default_rule_update_interval() -> String {
    "24h".to_string()
}

fn default_rule_download_chain() -> String {
    "direct".to_string()
}

fn default_rule_bootstrap_url() -> String {
    "system".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourceItem {
    #[serde(default = "default_rule_source_type")]
    pub source_type: String, // "url" | "local"
    #[serde(default = "default_rule_sync_mode")]
    pub sync_mode: String, // "panel" | "shoes_native"
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub format: String, // "" | "srs" | "mrs" | "singbox_json" | "mihomo_yaml" | "mihomo_text" | "geosite_dat" | "geoip_dat"
    #[serde(default)]
    pub behavior: String, // "" | "domain" | "ipcidr" | "classical"
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub attributes: Vec<String>,
    #[serde(default = "default_rule_update_interval")]
    pub update_interval: String,
    #[serde(default = "default_rule_download_chain")]
    pub download_chain: String,
    #[serde(default = "default_rule_bootstrap_url")]
    pub bootstrap_url: String,
    #[serde(default)]
    pub last_updated_at: i64,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourceGroupRecord {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub items: Vec<RuleSourceItem>,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub created_at: i64,
}

fn default_ntp_server() -> String {
    "time.cloudflare.com:123".to_string()
}

fn default_ntp_interval_secs() -> u64 {
    1800
}

fn default_ntp_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreGlobalSettings {
    #[serde(default)]
    pub max_connections: Option<u64>,
    #[serde(default)]
    pub max_connections_per_ip: Option<u64>,
    #[serde(default)]
    pub max_streams: Option<u64>,
    #[serde(default)]
    pub max_streams_per_connection: Option<u64>,
    #[serde(default)]
    pub max_udp_destinations: Option<u64>,
    #[serde(default)]
    pub quic_memory_bytes: Option<u64>,
    #[serde(default)]
    pub quic_receive_window: Option<u64>,
    #[serde(default)]
    pub quic_send_window: Option<u64>,
    #[serde(default)]
    pub quic_stream_window: Option<u64>,
    #[serde(default)]
    pub quic_dns_memory_bytes: Option<u64>,
    #[serde(default)]
    pub quic_socket_buffer: Option<u64>,
    #[serde(default)]
    pub reload_grace_secs: Option<u64>,
    #[serde(default)]
    pub ntp_enabled: bool,
    #[serde(default = "default_ntp_server")]
    pub ntp_server: String,
    #[serde(default = "default_ntp_interval_secs")]
    pub ntp_interval_secs: u64,
    #[serde(default = "default_ntp_timeout_secs")]
    pub ntp_timeout_secs: u64,
    #[serde(default)]
    pub default_dns_group: String,
    #[serde(default)]
    pub default_dns_ip_strategy: String,
    #[serde(default)]
    pub default_dns_servers: Vec<DnsServerItem>,
    #[serde(default)]
    pub default_dns_hosts: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub rule_cache_dir: String,
}

impl Default for CoreGlobalSettings {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_connections_per_ip: None,
            max_streams: None,
            max_streams_per_connection: None,
            max_udp_destinations: None,
            quic_memory_bytes: None,
            quic_receive_window: None,
            quic_send_window: None,
            quic_stream_window: None,
            quic_dns_memory_bytes: None,
            quic_socket_buffer: None,
            reload_grace_secs: None,
            ntp_enabled: false,
            ntp_server: default_ntp_server(),
            ntp_interval_secs: default_ntp_interval_secs(),
            ntp_timeout_secs: default_ntp_timeout_secs(),
            default_dns_group: String::new(),
            default_dns_ip_strategy: String::new(),
            default_dns_servers: Vec::new(),
            default_dns_hosts: BTreeMap::new(),
            rule_cache_dir: String::new(),
        }
    }
}

fn default_rule_action() -> String {
    "allow".to_string()
}

fn default_rule_outbound() -> String {
    "direct".to_string()
}

fn default_sub_template_preset() -> String {
    "minimal".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SubscriptionTemplateConfig {
    /// "minimal" | "global_direct" | "bypass_cn" | "streaming"
    #[serde(default = "default_sub_template_preset")]
    pub preset: String,
    #[serde(default = "default_true")]
    pub prepend_custom_rules: bool,
    #[serde(default)]
    pub enable_adblock: bool,
    #[serde(default)]
    pub enable_ipv6: bool,
    #[serde(default)]
    pub clash_custom_rules: String,
    #[serde(default)]
    pub clash_extra_groups_yaml: String,
    #[serde(default)]
    pub singbox_custom_rules: String,
}

impl Default for SubscriptionTemplateConfig {
    fn default() -> Self {
        Self {
            preset: default_sub_template_preset(),
            prepend_custom_rules: true,
            enable_adblock: false,
            enable_ipv6: false,
            clash_custom_rules: String::new(),
            clash_extra_groups_yaml: String::new(),
            singbox_custom_rules: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    #[serde(default)]
    pub id: i64,
    pub sub_id: String,
    pub token: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub template: String, // "" = inherit global default, or preset name
    #[serde(default)]
    pub created_at: i64,
}

fn default_backup_interval_hours() -> u64 {
    24
}

fn default_backup_retain_count() -> u64 {
    7
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelSettings {
    pub panel_listen: String,
    pub panel_port: u16,
    pub panel_base_path: String,
    pub panel_cert_file: String,
    pub panel_key_file: String,
    pub public_host: String,
    pub sub_public_url: String,
    pub shoes_bin_path: String,
    pub shoes_config_path: String,
    pub clash_api_addr: String,
    pub clash_api_secret: String,
    pub shoes_auto_start: bool,
    pub shoes_extra_yaml: String,
    pub session_ttl_hours: u64,
    #[serde(default)]
    pub auto_backup_enabled: bool,
    #[serde(default = "default_backup_interval_hours")]
    pub auto_backup_interval_hours: u64,
    #[serde(default = "default_backup_retain_count")]
    pub auto_backup_retain_count: u64,
    #[serde(default)]
    pub tg_bot_token: String,
    #[serde(default)]
    pub tg_chat_id: String,
    #[serde(default)]
    pub tg_backup_enabled: bool,
    #[serde(default)]
    pub core_global: CoreGlobalSettings,
    #[serde(default)]
    pub sub_template: SubscriptionTemplateConfig,
}

impl PanelSettings {
    pub fn listen_addr(&self) -> anyhow::Result<std::net::SocketAddr> {
        use anyhow::Context;
        let host = self.panel_listen.trim();
        if let Ok(ip) = host.parse() {
            return Ok(std::net::SocketAddr::new(ip, self.panel_port));
        }
        // Preserve bracketed IPv6 addresses, including numeric scope IDs.
        format!("{host}:{}", self.panel_port)
            .parse()
            .with_context(|| format!("Invalid panel listen IP '{host}'"))
    }

    pub fn scheme(&self) -> &'static str {
        if self.panel_cert_file.trim().is_empty() || self.panel_key_file.trim().is_empty() {
            "http"
        } else {
            "https"
        }
    }
}
