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
        matches!(self.protocol.as_str(), "anytls" | "naiveproxy")
    }

    pub fn is_quic(&self) -> bool {
        matches!(self.protocol.as_str(), "hysteria2" | "tuic")
            || self.stream_settings.network == "quic"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            raw_override_yaml: String::new(),
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
    pub ws: WsSettings,
    #[serde(default)]
    pub xhttp: XhttpSettings,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            network: "tcp".to_string(),
            security: "none".to_string(),
            tls: TlsSettings::default(),
            reality: RealitySettings::default(),
            ws: WsSettings::default(),
            xhttp: XhttpSettings::default(),
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
    pub cert_mode: String, // "source" | "files"
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
    pub cert_type: String, // "files" | "acme"
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

fn default_acme_dir() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_tos() -> String {
    "https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf".to_string()
}

fn default_acme_challenge() -> String {
    "http01".to_string()
}

fn default_http01_listen() -> String {
    "0.0.0.0:80".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMember {
    pub name: String,
    pub protocol: String, // "direct" | "socks" | "http" | "shadowsocks" | "vless" | "vmess" | "trojan" | "group"
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default = "default_true")]
    pub verify: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRuleRecord {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub remark: String,
    pub match_type: String, // "masks" | "domain" | "destination_port" | "udp_stun" | "any" | "raw_yaml"
    #[serde(default)]
    pub match_value: String,
    #[serde(default = "default_rule_action")]
    pub action: String, // "allow" | "block"
    #[serde(default = "default_rule_outbound")]
    pub outbound: String, // "direct" | group_name
}

fn default_rule_action() -> String {
    "allow".to_string()
}

fn default_rule_outbound() -> String {
    "direct".to_string()
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
    pub created_at: i64,
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
}
