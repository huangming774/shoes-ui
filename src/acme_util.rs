use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path as AxumPath, State as AxumState},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{NaiveDate, Utc};
use parking_lot::RwLock;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::models::{CertificateRecord, DEFAULT_LETSENCRYPT_DIR};
use crate::state::AppState;
use crate::yaml_gen::{acme_state_dir, ensure_private_dir, normalize_acme_domains};

/// Renew 6-day shortlived IP certificates when fewer than 48 hours remain.
const IP_CERT_RENEW_THRESHOLD_SECS: i64 = 48 * 3600;
const MAINTENANCE_POLL_SECS: u64 = 1800;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDirectoryMeta {
    pub directory_url: String,
    pub terms_of_service: Option<String>,
    pub profiles: Vec<String>,
    pub supports_shortlived: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertInfo {
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRuntimeStatus {
    /// "issued" | "pending" | "unreferenced_alpn" | "expired" | "missing" | "invalid"
    pub status: String,
    pub message: String,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub days_left: Option<i64>,
    pub hours_left: Option<i64>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub sans: Vec<String>,
    pub is_self_signed: bool,
    pub used_by: Vec<String>,
    pub is_panel_https: bool,
    pub state_dir: Option<String>,
}

// ==================== PEM & X.509 ASN.1 DER Inspection ====================

pub fn extract_pem_blocks(pem: &str, expected_label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start_idx) = rest.find(&begin) {
        let after_begin = &rest[start_idx + begin.len()..];
        let Some(end_idx) = after_begin.find(&end) else {
            break;
        };
        let b64: String = after_begin[..end_idx]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Ok(der) = STANDARD.decode(&b64) {
            out.push(der);
        }
        rest = &after_begin[end_idx + end.len()..];
    }
    out
}

struct DerCursor<'a>(&'a [u8]);

impl<'a> DerCursor<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.0.len() < 2 {
            return Err(anyhow!("unexpected end of DER structure"));
        }
        let tag = self.0[0];
        let len_byte = self.0[1];
        let (len, header_len) = if len_byte & 0x80 == 0 {
            (len_byte as usize, 2)
        } else {
            let count = (len_byte & 0x7f) as usize;
            if count == 0 || count > 4 || self.0.len() < 2 + count {
                return Err(anyhow!("invalid DER length encoding"));
            }
            let mut len = 0usize;
            for &b in &self.0[2..2 + count] {
                len = (len << 8) | (b as usize);
            }
            (len, 2 + count)
        };
        let end = header_len
            .checked_add(len)
            .ok_or_else(|| anyhow!("DER length overflow"))?;
        if end > self.0.len() {
            return Err(anyhow!("truncated DER element"));
        }
        let body = &self.0[header_len..end];
        self.0 = &self.0[end..];
        Ok((tag, body))
    }

    fn expect_tag(&mut self, expected: u8) -> Result<&'a [u8]> {
        let (tag, body) = self.read_tlv()?;
        if tag != expected {
            return Err(anyhow!(
                "unexpected DER tag 0x{tag:02x}, expected 0x{expected:02x}"
            ));
        }
        Ok(body)
    }
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(bytes).map_err(|_| anyhow!("non-UTF8 ASN.1 time"))?;
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSS
            if s.len() < 12 {
                return Err(anyhow!("short UTCTime"));
            }
            let yy: i32 = s[0..2].parse()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSS
            if s.len() < 14 {
                return Err(anyhow!("short GeneralizedTime"));
            }
            let yyyy: i32 = s[0..4].parse()?;
            (yyyy, &s[4..])
        }
        _ => return Err(anyhow!("invalid ASN.1 Time tag 0x{tag:02x}")),
    };
    let month: u32 = rest[0..2].parse()?;
    let day: u32 = rest[2..4].parse()?;
    let hour: u32 = rest[4..6].parse()?;
    let min: u32 = rest[6..8].parse()?;
    let sec: u32 = rest[8..10].parse()?;
    let dt = NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, min, sec))
        .ok_or_else(|| anyhow!("invalid calendar time in X.509 certificate"))?;
    Ok(dt.and_utc().timestamp())
}

fn parse_x509_name(name_der: &[u8]) -> String {
    let mut cn = String::new();
    let mut org = String::new();
    let mut cur = DerCursor(name_der);
    while !cur.is_empty() {
        let Ok((0x31, rdn_body)) = cur.read_tlv() else {
            break;
        };
        let mut rdn = DerCursor(rdn_body);
        while !rdn.is_empty() {
            let Ok((0x30, atv_body)) = rdn.read_tlv() else {
                break;
            };
            let mut atv = DerCursor(atv_body);
            let Ok((0x06, oid)) = atv.read_tlv() else {
                continue;
            };
            let Ok((_, val)) = atv.read_tlv() else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(val) else {
                continue;
            };
            // OID 2.5.4.3 = CN, 2.5.4.10 = O
            if oid == [0x55, 0x04, 0x03] && cn.is_empty() {
                cn = text.to_string();
            } else if oid == [0x55, 0x04, 0x0a] && org.is_empty() {
                org = text.to_string();
            }
        }
    }
    match (cn.is_empty(), org.is_empty()) {
        (false, false) if cn != org => format!("{cn} ({org})"),
        (false, _) => cn,
        (true, false) => org,
        (true, true) => String::new(),
    }
}

fn parse_san_extension(extn_val: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    let mut outer = DerCursor(extn_val);
    let Ok(seq) = outer.expect_tag(0x30) else {
        return sans;
    };
    let mut cur = DerCursor(seq);
    while !cur.is_empty() {
        let Ok((tag, val)) = cur.read_tlv() else {
            break;
        };
        match tag {
            0x82 => {
                // dNSName
                if let Ok(s) = std::str::from_utf8(val) {
                    sans.push(s.to_string());
                }
            }
            0x87 => {
                // iPAddress
                if val.len() == 4 {
                    let ip = Ipv4Addr::new(val[0], val[1], val[2], val[3]);
                    sans.push(ip.to_string());
                } else if val.len() == 16 {
                    if let Ok(arr) = <[u8; 16]>::try_from(val) {
                        sans.push(Ipv6Addr::from(arr).to_string());
                    }
                }
            }
            _ => {}
        }
    }
    sans
}

pub fn inspect_cert_der(der: &[u8]) -> Result<ParsedCertInfo> {
    let mut root = DerCursor(der);
    let cert_seq = root.expect_tag(0x30)?;
    let mut cert = DerCursor(cert_seq);
    let tbs_seq = cert.expect_tag(0x30)?;
    let mut tbs = DerCursor(tbs_seq);

    // Optional version [0]
    if tbs.peek_tag() == Some(0xa0) {
        let _ = tbs.read_tlv()?;
    }
    // serialNumber
    let _ = tbs.expect_tag(0x02)?;
    // signature
    let _ = tbs.expect_tag(0x30)?;
    // issuer
    let issuer_raw = tbs.expect_tag(0x30)?;
    // validity
    let validity_raw = tbs.expect_tag(0x30)?;
    let mut val = DerCursor(validity_raw);
    let (nb_tag, nb_bytes) = val.read_tlv()?;
    let (na_tag, na_bytes) = val.read_tlv()?;
    let not_before = parse_asn1_time(nb_tag, nb_bytes)?;
    let not_after = parse_asn1_time(na_tag, na_bytes)?;
    // subject
    let subject_raw = tbs.expect_tag(0x30)?;
    // subjectPublicKeyInfo
    let _ = tbs.expect_tag(0x30)?;

    let mut sans = Vec::new();
    while !tbs.is_empty() {
        let (tag, body) = tbs.read_tlv()?;
        if tag == 0xa3 {
            // extensions [3] EXPLICIT SEQUENCE OF Extension
            let mut ext_outer = DerCursor(body);
            if let Ok(ext_seq) = ext_outer.expect_tag(0x30) {
                let mut exts = DerCursor(ext_seq);
                while !exts.is_empty() {
                    let Ok((0x30, ext_body)) = exts.read_tlv() else {
                        break;
                    };
                    let mut ext = DerCursor(ext_body);
                    let Ok((0x06, oid)) = ext.read_tlv() else {
                        continue;
                    };
                    // Optional critical BOOLEAN
                    if ext.peek_tag() == Some(0x01) {
                        let _ = ext.read_tlv();
                    }
                    let Ok((0x04, octets)) = ext.read_tlv() else {
                        continue;
                    };
                    // OID 2.5.29.17 = subjectAltName
                    if oid == [0x55, 0x1d, 0x11] {
                        sans = parse_san_extension(octets);
                    }
                }
            }
            break;
        }
    }

    let issuer = parse_x509_name(issuer_raw);
    let subject = parse_x509_name(subject_raw);
    let is_self_signed = !issuer_raw.is_empty() && issuer_raw == subject_raw;

    Ok(ParsedCertInfo {
        not_before,
        not_after,
        issuer,
        subject,
        sans,
        is_self_signed,
    })
}

pub fn inspect_cert_pem(cert_pem: &str) -> Result<ParsedCertInfo> {
    let blocks = extract_pem_blocks(cert_pem, "CERTIFICATE");
    let leaf = blocks
        .first()
        .ok_or_else(|| anyhow!("No valid -----BEGIN CERTIFICATE----- block found"))?;
    inspect_cert_der(leaf)
}

/// Cryptographically verifies that the PEM certificate chain and private key are valid and match.
pub async fn validate_cert_key_pair(cert_pem: &str, key_pem: &str) -> Result<ParsedCertInfo> {
    let info = inspect_cert_pem(cert_pem)?;
    axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.trim().as_bytes().to_vec(),
        key_pem.trim().as_bytes().to_vec(),
    )
    .await
    .map_err(|e| anyhow!("Certificate and private key are invalid or do not match: {e}"))?;
    Ok(info)
}

// ==================== ACME Directory Metadata & URL Checks ====================

pub fn is_loopback_acme_url(raw: &str) -> bool {
    let Ok(u) = url::Url::parse(raw.trim()) else {
        return false;
    };
    u.scheme() == "http"
        && u.host_str().is_some_and(|h| {
            h.trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
}

pub fn validate_acme_directory_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw.trim()).context("Invalid ACME directory URL")?;
    let ok_scheme = url.scheme() == "https" || is_loopback_acme_url(raw);
    if !ok_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "ACME directory URL must use HTTPS (HTTP is allowed only for 127.0.0.1 / [::1] test CAs)"
        ));
    }
    Ok(url)
}

pub async fn fetch_acme_directory_meta(directory_url: &str) -> Result<AcmeDirectoryMeta> {
    let url = validate_acme_directory_url(directory_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .get(url.as_str())
        .send()
        .await
        .with_context(|| format!("Failed to reach ACME directory {}", url.as_str()))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "ACME directory {} returned HTTP {}",
            url.as_str(),
            resp.status().as_u16()
        ));
    }
    let body: Value = resp
        .json()
        .await
        .context("ACME directory did not return valid JSON")?;
    let terms_of_service = body
        .pointer("/meta/termsOfService")
        .and_then(Value::as_str)
        .map(str::to_string);
    let profiles: Vec<String> = body
        .pointer("/meta/profiles")
        .and_then(Value::as_object)
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    let supports_shortlived = profiles.iter().any(|p| p == "shortlived");
    Ok(AcmeDirectoryMeta {
        directory_url: directory_url.trim().to_string(),
        terms_of_service,
        profiles,
        supports_shortlived,
    })
}

// ==================== Runtime Status & Panel HTTPS Export ====================

#[derive(Deserialize)]
struct ShoesAcmeStatePreview {
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
}

pub fn read_shoes_acme_state_pem(
    data_dir: &Path,
    cert: &CertificateRecord,
) -> Result<Option<(String, String)>> {
    let dir_url = if cert.directory_url.trim().is_empty() {
        DEFAULT_LETSENCRYPT_DIR
    } else {
        cert.directory_url.trim()
    };
    let domains = normalize_acme_domains(&cert.domains)?;
    let state_dir = acme_state_dir(data_dir, &cert.name, dir_url, &domains);
    let state_file = state_dir.join("state.json");
    if !state_file.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&state_file)?;
    let parsed: ShoesAcmeStatePreview = serde_json::from_str(&raw)?;
    match (parsed.certificate, parsed.private_key) {
        (Some(c), Some(k)) if !c.trim().is_empty() && !k.trim().is_empty() => Ok(Some((c, k))),
        _ => Ok(None),
    }
}

pub fn export_acme_state_for_panel(
    data_dir: &Path,
    cert: &CertificateRecord,
) -> Result<(PathBuf, PathBuf)> {
    let (cert_pem, key_pem) = read_shoes_acme_state_pem(data_dir, cert)?.ok_or_else(|| {
        anyhow!(
            "ACME certificate '{}' has not been issued yet; wait for Shoes to finish ACME validation first",
            cert.name
        )
    })?;
    let safe_name = sanitize_cert_filename(&cert.name);
    let cert_dir = data_dir.join("certs");
    std::fs::create_dir_all(&cert_dir)?;
    let cert_path = cert_dir.join(format!("acme-export-{safe_name}.crt"));
    let key_path = cert_dir.join(format!("acme-export-{safe_name}.key"));
    write_cert_and_key_atomic(&cert_path, &key_path, &cert_pem, &key_pem)?;
    Ok((cert_path, key_path))
}

pub fn inspect_certificate_runtime(
    data_dir: &Path,
    cert: &CertificateRecord,
    used_by: Vec<String>,
    panel_cert_file: &str,
) -> CertRuntimeStatus {
    let now = Utc::now().timestamp();
    let panel_norm = panel_cert_file.trim().replace('\\', "/");
    let cert_norm = cert.cert_file.trim().replace('\\', "/");
    let safe_name = sanitize_cert_filename(&cert.name);
    let exported_norm = data_dir
        .join("certs")
        .join(format!("acme-export-{safe_name}.crt"))
        .to_string_lossy()
        .replace('\\', "/");
    let is_panel_https = !panel_norm.is_empty()
        && ((!cert_norm.is_empty() && panel_norm == cert_norm)
            || (cert.cert_type == "acme" && panel_norm == exported_norm));

    if cert.cert_type == "acme" {
        let dir_url = if cert.directory_url.trim().is_empty() {
            DEFAULT_LETSENCRYPT_DIR
        } else {
            cert.directory_url.trim()
        };
        let state_dir_str = normalize_acme_domains(&cert.domains)
            .ok()
            .map(|d| {
                acme_state_dir(data_dir, &cert.name, dir_url, &d)
                    .to_string_lossy()
                    .replace('\\', "/")
            });

        if let Ok(Some((cert_pem, _))) = read_shoes_acme_state_pem(data_dir, cert) {
            if let Ok(info) = inspect_cert_pem(&cert_pem) {
                let secs_left = info.not_after - now;
                let status = if secs_left <= 0 { "expired" } else { "issued" }.to_string();
                return CertRuntimeStatus {
                    status,
                    message: if secs_left <= 0 {
                        "Certificate expired, awaiting ACME renewal".to_string()
                    } else {
                        "Issued & managed by Shoes ACME".to_string()
                    },
                    not_before: Some(info.not_before),
                    not_after: Some(info.not_after),
                    days_left: Some(secs_left / 86400),
                    hours_left: Some(secs_left / 3600),
                    issuer: Some(info.issuer),
                    subject: Some(info.subject),
                    sans: info.sans,
                    is_self_signed: info.is_self_signed,
                    used_by,
                    is_panel_https,
                    state_dir: state_dir_str,
                };
            }
        }

        if cert.challenge_type == "tls_alpn01" && used_by.is_empty() {
            return CertRuntimeStatus {
                status: "unreferenced_alpn".to_string(),
                message: "Attach this TLS-ALPN-01 cert to a TCP 443 TLS inbound to begin issuance"
                    .to_string(),
                not_before: None,
                not_after: None,
                days_left: None,
                hours_left: None,
                issuer: None,
                subject: None,
                sans: cert.domains.clone(),
                is_self_signed: false,
                used_by,
                is_panel_https,
                state_dir: state_dir_str,
            };
        }

        return CertRuntimeStatus {
            status: "pending".to_string(),
            message: "Waiting for Shoes ACME issuance (check Shoes logs for challenge progress)"
                .to_string(),
            not_before: None,
            not_after: None,
            days_left: None,
            hours_left: None,
            issuer: None,
            subject: None,
            sans: cert.domains.clone(),
            is_self_signed: false,
            used_by,
            is_panel_https,
            state_dir: state_dir_str,
        };
    }

    // "files" or "acme_ip"
    let cert_path = Path::new(cert.cert_file.trim());
    if !cert_path.is_file() {
        return CertRuntimeStatus {
            status: "missing".to_string(),
            message: format!("Certificate file not found: {}", cert.cert_file),
            not_before: None,
            not_after: None,
            days_left: None,
            hours_left: None,
            issuer: None,
            subject: None,
            sans: cert.domains.clone(),
            is_self_signed: false,
            used_by,
            is_panel_https,
            state_dir: None,
        };
    }
    match std::fs::read_to_string(cert_path).and_then(|pem| {
        inspect_cert_pem(&pem).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }) {
        Ok(info) => {
            let secs_left = info.not_after - now;
            let status = if secs_left <= 0 { "expired" } else { "issued" }.to_string();
            let message = if secs_left <= 0 {
                "Certificate expired".to_string()
            } else if cert.cert_type == "acme_ip" {
                "Free IP SSL (auto-renews before expiry)".to_string()
            } else if info.is_self_signed {
                "Self-signed certificate".to_string()
            } else {
                "Valid CA-signed certificate".to_string()
            };
            CertRuntimeStatus {
                status,
                message,
                not_before: Some(info.not_before),
                not_after: Some(info.not_after),
                days_left: Some(secs_left / 86400),
                hours_left: Some(secs_left / 3600),
                issuer: Some(info.issuer),
                subject: Some(info.subject),
                sans: info.sans,
                is_self_signed: info.is_self_signed,
                used_by,
                is_panel_https,
                state_dir: None,
            }
        }
        Err(e) => CertRuntimeStatus {
            status: "invalid".to_string(),
            message: format!("Failed to parse certificate PEM: {e}"),
            not_before: None,
            not_after: None,
            days_left: None,
            hours_left: None,
            issuer: None,
            subject: None,
            sans: cert.domains.clone(),
            is_self_signed: false,
            used_by,
            is_panel_https,
            state_dir: None,
        },
    }
}

// ==================== Atomic File Helpers ====================

pub fn sanitize_cert_filename(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if s.is_empty() {
        "cert".to_string()
    } else {
        s
    }
}

pub fn set_private_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub fn write_cert_and_key_atomic(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write key first with private permissions, then cert, via atomic rename in same directory.
    let key_parent = key_path.parent().unwrap_or_else(|| Path::new("."));
    let mut key_tmp = tempfile::NamedTempFile::new_in(key_parent)?;
    key_tmp.write_all(key_pem.trim().as_bytes())?;
    key_tmp.write_all(b"\n")?;
    key_tmp.flush()?;
    set_private_file_permissions(key_tmp.path());
    key_tmp
        .persist(key_path)
        .map_err(|e| anyhow!("failed to persist private key {}: {}", key_path.display(), e.error))?;
    set_private_file_permissions(key_path);

    let cert_parent = cert_path.parent().unwrap_or_else(|| Path::new("."));
    let mut cert_tmp = tempfile::NamedTempFile::new_in(cert_parent)?;
    cert_tmp.write_all(cert_pem.trim().as_bytes())?;
    cert_tmp.write_all(b"\n")?;
    cert_tmp.flush()?;
    cert_tmp
        .persist(cert_path)
        .map_err(|e| anyhow!("failed to persist certificate {}: {}", cert_path.display(), e.error))?;
    Ok(())
}

// ==================== Public IP Check (RFC 8738 / Let's Encrypt) ====================

pub fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64; // 100.64.0.0/10
            let is_benchmark = o[0] == 198 && (o[1] == 18 || o[1] == 19); // 198.18.0.0/15
            let is_reserved = o[0] >= 240; // 240.0.0.0/4
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !is_cgnat
                && !is_benchmark
                && !is_reserved
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let is_ula = (seg[0] & 0xfe00) == 0xfc00;
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
            let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_ula
                && !is_link_local
                && !is_doc
        }
    }
}

pub fn parse_and_validate_ip_targets(raw_ips: &[String], allow_loopback: bool) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for item in raw_ips {
        let trimmed = item.trim().trim_start_matches('[').trim_end_matches(']');
        if trimmed.is_empty() {
            continue;
        }
        let ip: IpAddr = trimmed.parse().map_err(|_| {
            anyhow!(
                "'{trimmed}' is not a valid IPv4 or IPv6 address (for domain names, use Domain ACME instead)"
            )
        })?;
        if !allow_loopback && !is_globally_routable_ip(ip) {
            return Err(anyhow!(
                "IP '{ip}' is a private/local address. Let's Encrypt only issues free IP certificates for publicly routable IPs (use Self-Signed IP Cert or REALITY for private/LAN IPs)."
            ));
        }
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        return Err(anyhow!("At least one public IPv4 or IPv6 address is required"));
    }
    Ok(ips)
}

// ==================== RFC 8555 + RFC 8738 Shortlived IP ACME Client ====================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    #[serde(default)]
    meta: Option<AcmeDirectoryMetaRaw>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectoryMetaRaw {
    #[serde(default)]
    terms_of_service: Option<String>,
    #[serde(default)]
    profiles: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
struct StoredIpAccount {
    directory_url: String,
    pkcs8_b64: String,
    account_url: String,
}

#[derive(Debug, Clone)]
pub struct IssuedIpCertResult {
    pub cert_pem: String,
    pub key_pem: String,
    pub info: ParsedCertInfo,
    pub terms_of_service: String,
}

struct AcmeEs256Client {
    http: reqwest::Client,
    rng: SystemRandom,
    key: EcdsaKeyPair,
    x_b64: String,
    y_b64: String,
    thumbprint: String,
    kid: Option<String>,
    nonce: Option<String>,
    new_nonce_url: String,
}

impl AcmeEs256Client {
    fn from_pkcs8(
        http: reqwest::Client,
        pkcs8_der: &[u8],
        new_nonce_url: String,
        kid: Option<String>,
    ) -> Result<Self> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_der, &rng)
            .map_err(|e| anyhow!("invalid ACME account PKCS#8 key: {e}"))?;
        let pub_bytes = key.public_key().as_ref();
        if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
            return Err(anyhow!("unexpected P-256 public key format"));
        }
        let x_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let canonical_jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
        let thumbprint = URL_SAFE_NO_PAD.encode(
            digest::digest(&digest::SHA256, canonical_jwk.as_bytes()).as_ref(),
        );
        Ok(Self {
            http,
            rng,
            key,
            x_b64,
            y_b64,
            thumbprint,
            kid,
            nonce: None,
            new_nonce_url,
        })
    }

    async fn ensure_nonce(&mut self) -> Result<String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let resp = self
            .http
            .head(&self.new_nonce_url)
            .send()
            .await
            .context("Failed to fetch ACME Replay-Nonce")?;
        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("ACME server did not return Replay-Nonce header"))
    }

    fn sign_jws(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<Value> {
        let protected = if let Some(kid) = &self.kid {
            json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url,
            })
        } else {
            json!({
                "alg": "ES256",
                "jwk": {
                    "crv": "P-256",
                    "kty": "EC",
                    "x": self.x_b64,
                    "y": self.y_b64,
                },
                "nonce": nonce,
                "url": url,
            })
        };
        let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
        let payload_b64 = match payload {
            Some(v) => URL_SAFE_NO_PAD.encode(serde_json::to_vec(v)?),
            None => String::new(), // RFC 8555 POST-as-GET
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = self
            .key
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| anyhow!("ES256 JWS signing failed"))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }))
    }

    async fn post_signed(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        accept: Option<&str>,
    ) -> Result<(StatusCode, reqwest::header::HeaderMap, String)> {
        for attempt in 0..2 {
            let nonce = self.ensure_nonce().await?;
            let jws = self.sign_jws(url, &nonce, payload)?;
            let mut req = self
                .http
                .post(url)
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(serde_json::to_vec(&jws)?);
            if let Some(a) = accept {
                req = req.header(header::ACCEPT, a);
            }
            let resp = req
                .send()
                .await
                .with_context(|| format!("ACME POST {url} failed"))?;
            let status = resp.status();
            let headers = resp.headers().clone();
            if let Some(next_nonce) = headers
                .get("replay-nonce")
                .and_then(|v| v.to_str().ok())
            {
                self.nonce = Some(next_nonce.to_string());
            }
            let body = resp.text().await.unwrap_or_default();
            if attempt == 0 && status == StatusCode::BAD_REQUEST && body.contains("badNonce") {
                continue;
            }
            return Ok((status, headers, body));
        }
        unreachable!()
    }
}

fn format_acme_problem(context_label: &str, status: StatusCode, body: &str) -> anyhow::Error {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let detail = v.get("detail").and_then(Value::as_str).unwrap_or("");
        let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
        if !detail.is_empty() {
            return anyhow!("{context_label} (HTTP {}): {detail} [{kind}]", status.as_u16());
        }
    }
    anyhow!(
        "{context_label} (HTTP {}): {}",
        status.as_u16(),
        body.trim()
    )
}

struct Http01ChallengeGuard {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Http01ChallengeGuard {
    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        }
    }
}

impl Drop for Http01ChallengeGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

async fn start_temporary_http01_server(
    listen_str: &str,
    challenges: Arc<RwLock<HashMap<String, String>>>,
) -> Result<Http01ChallengeGuard> {
    let addr: SocketAddr = listen_str.trim().parse().map_err(|_| {
        anyhow!("Invalid HTTP-01 listen address '{listen_str}' (expected e.g. 0.0.0.0:80)")
    })?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        anyhow!(
            "Failed to bind HTTP-01 listener on {addr}: {e}. Ensure port {} is free (stop Nginx/Caddy or another HTTP-01 listener temporarily) and reachable from the internet.",
            addr.port()
        )
    })?;

    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(
                |AxumState(map): AxumState<Arc<RwLock<HashMap<String, String>>>>,
                 AxumPath(token): AxumPath<String>| async move {
                    if let Some(val) = map.read().get(&token).cloned() {
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            val,
                        )
                            .into_response()
                    } else {
                        (StatusCode::NOT_FOUND, "challenge token not found").into_response()
                    }
                },
            ),
        )
        .with_state(challenges);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });

    Ok(Http01ChallengeGuard {
        shutdown: Some(tx),
        handle: Some(handle),
    })
}

/// Issues a free CA-trusted IP address certificate using ACME `shortlived` profile + HTTP-01 (RFC 8555 + RFC 8738).
pub async fn issue_shortlived_ip_cert(
    data_dir: &Path,
    cert_name: &str,
    raw_ips: &[String],
    email: &str,
    directory_url: &str,
    http01_listen: &str,
) -> Result<IssuedIpCertResult> {
    let dir_url = if directory_url.trim().is_empty() {
        DEFAULT_LETSENCRYPT_DIR
    } else {
        directory_url.trim()
    };
    let _ = validate_acme_directory_url(dir_url)?;
    let is_loopback = is_loopback_acme_url(dir_url);
    let ips = parse_and_validate_ip_targets(raw_ips, is_loopback)?;

    let listen = if http01_listen.trim().is_empty() {
        "0.0.0.0:80"
    } else {
        http01_listen.trim()
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(format!("shoes-panel/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // 1. Fetch ACME directory
    let dir_resp = http
        .get(dir_url)
        .send()
        .await
        .with_context(|| format!("Failed to reach ACME directory {dir_url}"))?;
    if !dir_resp.status().is_success() {
        return Err(anyhow!(
            "ACME directory {dir_url} returned HTTP {}",
            dir_resp.status().as_u16()
        ));
    }
    let directory: AcmeDirectory = dir_resp
        .json()
        .await
        .context("Invalid ACME directory JSON")?;

    let tos_url = directory
        .meta
        .as_ref()
        .and_then(|m| m.terms_of_service.clone())
        .unwrap_or_default();
    let supports_shortlived = directory
        .meta
        .as_ref()
        .is_some_and(|m| m.profiles.contains_key("shortlived"));
    if let Some(meta) = &directory.meta {
        if !meta.profiles.is_empty() && !supports_shortlived {
            return Err(anyhow!(
                "ACME CA at {dir_url} does not advertise the 'shortlived' profile required for IP address certificates"
            ));
        }
    }

    // 2. Load or create persistent ECDSA P-256 account key
    let safe_name = sanitize_cert_filename(cert_name);
    let acct_dir = data_dir.join("acme-ip").join(&safe_name);
    ensure_private_dir(&acct_dir)?;
    let acct_file = acct_dir.join("account.json");

    let stored: Option<StoredIpAccount> = std::fs::read_to_string(&acct_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(|a: &StoredIpAccount| a.directory_url == dir_url);

    let (pkcs8_der, existing_kid) = if let Some(s) = stored {
        let der = STANDARD
            .decode(s.pkcs8_b64.trim())
            .context("corrupted stored ACME IP account key")?;
        (der, Some(s.account_url))
    } else {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("failed to generate ACME ES256 account key"))?;
        (doc.as_ref().to_vec(), None)
    };

    let mut client =
        AcmeEs256Client::from_pkcs8(http.clone(), &pkcs8_der, directory.new_nonce.clone(), existing_kid)?;

    // 3. Register/fetch account if not already stored
    if client.kid.is_none() {
        let mut acct_payload = json!({ "termsOfServiceAgreed": true });
        let trimmed_email = email.trim();
        if !trimmed_email.is_empty() {
            let contact = if trimmed_email.starts_with("mailto:") {
                trimmed_email.to_string()
            } else {
                format!("mailto:{trimmed_email}")
            };
            acct_payload["contact"] = json!([contact]);
        }
        let (status, headers, body) = client
            .post_signed(&directory.new_account, Some(&acct_payload), None)
            .await?;
        if !status.is_success() {
            return Err(format_acme_problem("ACME account registration failed", status, &body));
        }
        let kid = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("ACME newAccount did not return Location header"))?;
        client.kid = Some(kid.clone());

        let record = StoredIpAccount {
            directory_url: dir_url.to_string(),
            pkcs8_b64: STANDARD.encode(&pkcs8_der),
            account_url: kid,
        };
        std::fs::write(&acct_file, serde_json::to_vec_pretty(&record)?)?;
        set_private_file_permissions(&acct_file);
    }

    // 4. Bind temporary HTTP-01 listener BEFORE requesting order/challenges
    let challenge_map = Arc::new(RwLock::new(HashMap::<String, String>::new()));
    let http_guard = start_temporary_http01_server(listen, challenge_map.clone()).await?;

    // 5. Create newOrder with IP identifiers + `shortlived` profile
    let identifiers: Vec<Value> = ips
        .iter()
        .map(|ip| json!({ "type": "ip", "value": ip.to_string() }))
        .collect();
    let mut order_payload = json!({ "identifiers": identifiers });
    if supports_shortlived {
        order_payload["profile"] = json!("shortlived");
    }

    let (status, headers, body) = client
        .post_signed(&directory.new_order, Some(&order_payload), None)
        .await?;
    if !status.is_success() {
        http_guard.stop().await;
        return Err(format_acme_problem("ACME IP order creation failed", status, &body));
    }
    let order_url = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("ACME newOrder response missing Location header"))?;
    let order_json: Value = serde_json::from_str(&body).context("invalid ACME order JSON")?;
    let finalize_url = order_json
        .get("finalize")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("ACME order missing finalize URL"))?
        .to_string();
    let authz_urls: Vec<String> = order_json
        .get("authorizations")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // 6. Solve HTTP-01 challenges for each IP authorization
    let mut triggered_challenges = Vec::new();
    for authz_url in &authz_urls {
        let (st, _, abody) = client.post_signed(authz_url, None, None).await?;
        if !st.is_success() {
            http_guard.stop().await;
            return Err(format_acme_problem("ACME authorization fetch failed", st, &abody));
        }
        let authz: Value = serde_json::from_str(&abody)?;
        if authz.get("status").and_then(Value::as_str) == Some("valid") {
            continue;
        }
        let challenges = authz
            .get("challenges")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("ACME authorization missing challenges array"))?;
        let http01 = challenges
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("http-01"))
            .ok_or_else(|| {
                anyhow!("ACME CA did not offer an http-01 challenge for IP authorization")
            })?;
        let token = http01
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ACME http-01 challenge missing token"))?;
        let chall_url = http01
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ACME http-01 challenge missing url"))?
            .to_string();

        let key_auth = format!("{token}.{}", client.thumbprint);
        challenge_map.write().insert(token.to_string(), key_auth);
        triggered_challenges.push((authz_url.clone(), chall_url));
    }

    for (_, chall_url) in &triggered_challenges {
        let empty = json!({});
        let (st, _, cbody) = client.post_signed(chall_url, Some(&empty), None).await?;
        if !st.is_success() {
            http_guard.stop().await;
            return Err(format_acme_problem("ACME challenge trigger failed", st, &cbody));
        }
    }

    // Poll every authorization until valid
    let poll_interval = if is_loopback {
        Duration::from_millis(150)
    } else {
        Duration::from_secs(2)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    for (authz_url, _) in &triggered_challenges {
        loop {
            let (st, _, abody) = client.post_signed(authz_url, None, None).await?;
            if !st.is_success() {
                http_guard.stop().await;
                return Err(format_acme_problem("ACME authorization poll failed", st, &abody));
            }
            let authz: Value = serde_json::from_str(&abody)?;
            match authz.get("status").and_then(Value::as_str) {
                Some("valid") => break,
                Some("invalid") => {
                    http_guard.stop().await;
                    let detail = authz
                        .get("challenges")
                        .and_then(Value::as_array)
                        .and_then(|arr| {
                            arr.iter()
                                .find(|c| c.get("type").and_then(Value::as_str) == Some("http-01"))
                        })
                        .and_then(|c| c.pointer("/error/detail"))
                        .and_then(Value::as_str)
                        .unwrap_or("HTTP-01 validation failed (check that port 80 is publicly reachable and not blocked by firewall/cloud security group)");
                    return Err(anyhow!("ACME IP validation failed: {detail}"));
                }
                _ => {
                    if tokio::time::Instant::now() >= deadline {
                        http_guard.stop().await;
                        return Err(anyhow!(
                            "Timed out waiting for ACME HTTP-01 validation on {listen}"
                        ));
                    }
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    // Release port 80 immediately once validation finishes!
    http_guard.stop().await;

    // 7. Generate ECDSA P-256 leaf key + CSR with IP SANs and EMPTY CommonName (required by Let's Encrypt!)
    let mut csr_params = CertificateParams::default();
    csr_params.distinguished_name = DistinguishedName::new();
    csr_params.subject_alt_names = ips.iter().map(|ip| SanType::IpAddress(*ip)).collect();
    let leaf_key = KeyPair::generate()?;
    let csr = csr_params.serialize_request(&leaf_key)?;
    let csr_b64 = URL_SAFE_NO_PAD.encode(csr.der());

    let (st, _, fbody) = client
        .post_signed(&finalize_url, Some(&json!({ "csr": csr_b64 })), None)
        .await?;
    if !st.is_success() {
        return Err(format_acme_problem("ACME order finalization failed", st, &fbody));
    }

    // 8. Poll order until certificate URL is ready
    let mut cert_url: Option<String> = serde_json::from_str::<Value>(&fbody)
        .ok()
        .and_then(|v| v.get("certificate").and_then(Value::as_str).map(str::to_string));

    let finalize_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while cert_url.is_none() {
        let (ost, _, obody) = client.post_signed(&order_url, None, None).await?;
        if !ost.is_success() {
            return Err(format_acme_problem("ACME order status poll failed", ost, &obody));
        }
        let ov: Value = serde_json::from_str(&obody)?;
        match ov.get("status").and_then(Value::as_str) {
            Some("valid") => {
                cert_url = ov
                    .get("certificate")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if cert_url.is_none() {
                    return Err(anyhow!("ACME order is valid but missing certificate URL"));
                }
            }
            Some("invalid") => {
                let detail = ov
                    .pointer("/error/detail")
                    .and_then(Value::as_str)
                    .unwrap_or("Order became invalid during finalization");
                return Err(anyhow!("ACME IP certificate finalization failed: {detail}"));
            }
            _ => {
                if tokio::time::Instant::now() >= finalize_deadline {
                    return Err(anyhow!("Timed out waiting for ACME certificate issuance"));
                }
                tokio::time::sleep(poll_interval).await;
            }
        }
    }

    // 9. Download fullchain PEM & verify against leaf private key
    let (cst, _, cert_pem) = client
        .post_signed(
            cert_url.as_deref().unwrap(),
            None,
            Some("application/pem-certificate-chain"),
        )
        .await?;
    if !cst.is_success() {
        return Err(format_acme_problem("ACME certificate download failed", cst, &cert_pem));
    }
    let key_pem = leaf_key.serialize_pem();
    let info = validate_cert_key_pair(&cert_pem, &key_pem).await?;

    Ok(IssuedIpCertResult {
        cert_pem,
        key_pem,
        info,
        terms_of_service: tos_url,
    })
}

/// Renews an existing `acme_ip` certificate on disk and hot-reloads Panel HTTPS if used.
pub async fn renew_ip_certificate_record(state: &AppState, cert: &CertificateRecord) -> Result<ParsedCertInfo> {
    if cert.cert_type != "acme_ip" {
        return Err(anyhow!("Certificate '{}' is not a panel-managed IP ACME certificate", cert.name));
    }
    let issued = issue_shortlived_ip_cert(
        &state.db.data_dir,
        &cert.name,
        &cert.domains,
        &cert.email,
        &cert.directory_url,
        &cert.http01_listen,
    )
    .await?;

    let cert_path = PathBuf::from(cert.cert_file.trim());
    let key_path = PathBuf::from(cert.key_file.trim());
    write_cert_and_key_atomic(&cert_path, &key_path, &issued.cert_pem, &issued.key_pem)?;

    // Reload panel HTTPS TLS listener if it uses this certificate.
    let _ = reload_panel_https_if_matching(state, &cert_path, &key_path).await;

    Ok(issued.info)
}

pub async fn reload_panel_https_if_matching(
    state: &AppState,
    cert_path: &Path,
    key_path: &Path,
) -> Result<bool> {
    let settings = state.db.get_settings()?;
    let cur_cert = settings.panel_cert_file.trim().replace('\\', "/");
    let target_cert = cert_path.to_string_lossy().replace('\\', "/");
    if cur_cert.is_empty() || cur_cert != target_cert {
        return Ok(false);
    }
    let cfg = state.panel_tls_config.read().clone();
    if let Some(tls_cfg) = cfg {
        tls_cfg
            .reload_from_pem_file(cert_path, key_path)
            .await
            .context("failed to hot-reload Panel HTTPS certificate")?;
        tracing::info!("Hot-reloaded Panel HTTPS TLS certificate from {}", cert_path.display());
        return Ok(true);
    }
    Ok(false)
}

/// Background maintenance loop:
/// 1. Automatically renews 6-day `acme_ip` certificates when < 48 hours remain.
/// 2. Keeps Panel HTTPS exported PEM synced when a Shoes-managed `acme` cert renews.
pub fn spawn_cert_maintenance_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_POLL_SECS));
        // Skip immediate startup tick; first check runs after 60s so startup stays crisp.
        interval.tick().await;
        tokio::time::sleep(Duration::from_secs(60)).await;

        loop {
            if let Ok(certs) = state.db.list_certificates() {
                let now = Utc::now().timestamp();
                let settings = state.db.get_settings().ok();

                for cert in certs {
                    if cert.cert_type == "acme_ip" {
                        let needs_renew = match std::fs::read_to_string(cert.cert_file.trim())
                            .ok()
                            .and_then(|pem| inspect_cert_pem(&pem).ok())
                        {
                            Some(info) => (info.not_after - now) < IP_CERT_RENEW_THRESHOLD_SECS,
                            None => true,
                        };
                        if needs_renew {
                            tracing::info!(
                                "Auto-renewing shortlived IP SSL certificate '{}' ({:?})...",
                                cert.name,
                                cert.domains
                            );
                            match renew_ip_certificate_record(&state, &cert).await {
                                Ok(info) => {
                                    tracing::info!(
                                        "Successfully renewed IP SSL certificate '{}', valid until {}",
                                        cert.name,
                                        info.not_after
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Auto-renewal failed for IP SSL certificate '{}': {e}",
                                        cert.name
                                    );
                                }
                            }
                        }
                    } else if cert.cert_type == "acme" {
                        // If Panel HTTPS uses this Shoes-managed ACME cert's exported PEM, keep it synced.
                        if let Some(s) = &settings {
                            let safe_name = sanitize_cert_filename(&cert.name);
                            let exported_cert = state
                                .db
                                .data_dir
                                .join("certs")
                                .join(format!("acme-export-{safe_name}.crt"));
                            let cur_panel_cert = s.panel_cert_file.trim().replace('\\', "/");
                            if !cur_panel_cert.is_empty()
                                && cur_panel_cert
                                    == exported_cert.to_string_lossy().replace('\\', "/")
                            {
                                if let Ok(Some((new_cert, _))) =
                                    read_shoes_acme_state_pem(&state.db.data_dir, &cert)
                                {
                                    let existing =
                                        std::fs::read_to_string(&exported_cert).unwrap_or_default();
                                    if existing.trim() != new_cert.trim() {
                                        if let Ok((cp, kp)) =
                                            export_acme_state_for_panel(&state.db.data_dir, &cert)
                                        {
                                            let _ = reload_panel_https_if_matching(&state, &cp, &kp)
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            interval.tick().await;
        }
    });
}
