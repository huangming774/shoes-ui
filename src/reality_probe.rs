use anyhow::{anyhow, Result};
use chrono::Utc;
use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::acme_util::inspect_cert_der;

/// TLS 1.3 HelloRetryRequest sentinel random (RFC 8446 §4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Curated REALITY destination candidates for one-click concurrent probing.
pub const DEFAULT_REALITY_CANDIDATES: &[&str] = &[
    "www.microsoft.com:443",
    "www.apple.com:443",
    "aws.amazon.com:443",
    "www.icloud.com:443",
    "learn.microsoft.com:443",
    "updates.cdn-apple.com:443",
    "dl.google.com:443",
    "cdn.jsdelivr.net:443",
    "www.bing.com:443",
    "www.cloudflare.com:443",
];

#[derive(Debug, Clone, Deserialize)]
pub struct RealityProbeTarget {
    pub dest: String,
    #[serde(default)]
    pub sni: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RealityProbeResult {
    pub dest: String,
    pub sni: String,
    pub reachable: bool,
    pub suitable: bool,
    /// "excellent" | "good" | "warn" | "fail"
    pub verdict: String,
    pub score: u8,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub tls_version: String,
    pub cipher_suite: String,
    pub alpn: String,
    pub x25519: bool,
    pub hello_retry: bool,
    /// "combined" | "separate" | "other" | ""
    pub flight_mode: String,
    pub flight_records: usize,
    pub cert_capacity_bytes: usize,
    pub mldsa65_compatible: bool,
    pub cert_subject: String,
    pub cert_issuer: String,
    pub cert_sans: Vec<String>,
    pub cert_days_left: Option<i64>,
    pub cert_self_signed: bool,
    pub sni_matched: bool,
    pub reasons: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
struct CapturedCerts {
    leaf_der: Vec<u8>,
    chain_total_bytes: usize,
}

#[derive(Debug)]
struct CaptureCertVerifier {
    captured: Arc<Mutex<Option<CapturedCerts>>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CaptureCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let mut total = end_entity.as_ref().len();
        for ic in intermediates {
            total = total.saturating_add(ic.as_ref().len());
        }
        *self.captured.lock() = Some(CapturedCerts {
            leaf_der: end_entity.as_ref().to_vec(),
            chain_total_bytes: total,
        });
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Normalizes a user-supplied dest (e.g. `www.microsoft.com`, `https://www.apple.com`, `1.2.3.4:443`)
/// into `(connect_addr, normalized_dest, effective_sni)`.
pub fn normalize_probe_target(raw_dest: &str, raw_sni: &str) -> Result<(String, String, String)> {
    let mut d = raw_dest.trim();
    if d.is_empty() {
        return Err(anyhow!("Destination domain or host:port must not be empty"));
    }
    if let Some(rest) = d.strip_prefix("https://").or_else(|| d.strip_prefix("http://")) {
        d = rest;
    }
    if let Some((before_slash, _)) = d.split_once('/') {
        d = before_slash;
    }
    let d = d.trim();
    if d.is_empty() {
        return Err(anyhow!("Invalid destination host"));
    }

    let (host, port) = if let Some(rest) = d.strip_prefix('[') {
        let (ip, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("Invalid IPv6 address '{d}'"))?;
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| anyhow!("Invalid port in '{d}'"))?
        } else if after.is_empty() {
            443
        } else {
            return Err(anyhow!("Invalid IPv6 host:port '{d}'"));
        };
        (ip.to_string(), port)
    } else if let Some((h, p)) = d.rsplit_once(':') {
        if !h.contains(':') {
            let port = p
                .parse::<u16>()
                .map_err(|_| anyhow!("Invalid port in '{d}'"))?;
            (h.trim().to_string(), port)
        } else {
            (d.to_string(), 443)
        }
    } else {
        (d.to_string(), 443)
    };

    if host.is_empty() || port == 0 {
        return Err(anyhow!("Invalid host or port in '{raw_dest}'"));
    }

    let normalized_dest = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let sni = if raw_sni.trim().is_empty() {
        host.clone()
    } else {
        raw_sni
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    };

    Ok((normalized_dest.clone(), normalized_dest, sni))
}

/// Checks RFC 6125 DNS wildcard / exact matching against SANs (or CN fallback).
pub fn sni_matches_cert(sni: &str, sans: &[String], subject: &str) -> bool {
    let target = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    let matches_pattern = |pat: &str| -> bool {
        let p = pat.trim().trim_end_matches('.').to_ascii_lowercase();
        if p == target {
            return true;
        }
        if let Some(rest) = p.strip_prefix("*.") {
            if let Some((_, tail)) = target.split_once('.') {
                return tail == rest && !tail.is_empty();
            }
        }
        false
    };

    if !sans.is_empty() {
        return sans.iter().any(|s| matches_pattern(s));
    }
    // Fallback to CN when SAN extension is absent
    let cn = subject.split(" (").next().unwrap_or(subject);
    matches_pattern(cn)
}

#[derive(Debug, Default)]
pub struct RawFlightAnalysis {
    pub server_hello_tls13: bool,
    pub server_hello_x25519: bool,
    pub hello_retry: bool,
    pub flight_mode: String,
    pub flight_records: usize,
    pub cert_capacity_bytes: usize,
    pub shoes_layout_valid: bool,
}

fn parse_server_hello_record(record: &[u8]) -> (bool, bool, bool) {
    // Returns (is_tls13, is_x25519_or_hybrid, is_hello_retry)
    if record.len() < 5 + 4 + 2 + 32 + 1 || record[0] != 22 {
        return (false, false, false);
    }
    let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + rec_len || rec_len < 4 + 2 + 32 + 1 {
        return (false, false, false);
    }
    let hs = &record[5..5 + rec_len];
    if hs[0] != 2 {
        return (false, false, false); // Not ServerHello
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if 4 + hs_len > hs.len() || hs_len < 2 + 32 + 1 {
        return (false, false, false);
    }
    let body = &hs[4..4 + hs_len];
    let random = &body[2..34];
    let is_hrr = random == HELLO_RETRY_RANDOM;

    let mut pos = 34;
    let sid_len = body[pos] as usize;
    pos += 1;
    if pos + sid_len + 3 > body.len() {
        return (false, false, is_hrr);
    }
    pos += sid_len;
    // Skip cipher suite (2) + compression (1)
    pos += 3;
    if pos + 2 > body.len() {
        return (false, false, is_hrr);
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_total > body.len() {
        return (false, false, is_hrr);
    }
    let mut ext = &body[pos..pos + ext_total];
    let mut is_tls13 = false;
    let mut is_x25519 = false;
    while ext.len() >= 4 {
        let eid = u16::from_be_bytes([ext[0], ext[1]]);
        let elen = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        if 4 + elen > ext.len() {
            break;
        }
        let edata = &ext[4..4 + elen];
        match eid {
            43 => {
                // supported_versions
                if edata == [0x03, 0x04] {
                    is_tls13 = true;
                }
            }
            51 => {
                // key_share: group(2) + key_exchange_len(2) + key_exchange
                if edata.len() >= 4 {
                    let group = u16::from_be_bytes([edata[0], edata[1]]);
                    let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
                    if (group == 0x001d && klen == 32) || (group == 0x11ec && klen == 1120) {
                        is_x25519 = true;
                    }
                }
            }
            _ => {}
        }
        ext = &ext[4 + elen..];
    }
    (is_tls13, is_x25519, is_hrr)
}

/// Analyzes raw server flight TLS records using the exact same layout heuristic as
/// upstream `cfal/shoes` (`reality_target_flight.rs` & `reality_server_handler.rs`).
pub fn analyze_server_flight(records: &[Vec<u8>]) -> RawFlightAnalysis {
    let mut out = RawFlightAnalysis {
        flight_records: records.len(),
        flight_mode: "other".to_string(),
        ..Default::default()
    };
    let Some(first) = records.first() else {
        return out;
    };
    let (tls13, x25519, hrr) = parse_server_hello_record(first);
    out.server_hello_tls13 = tls13;
    out.server_hello_x25519 = x25519;
    out.hello_retry = hrr;

    if records.len() < 3 {
        return out;
    }

    let has_ccs = records[1].as_slice() == [20, 3, 3, 0, 1, 1];
    let all_app_after_ccs = records[2..].iter().all(|r| r.first() == Some(&23));

    if has_ccs && all_app_after_ccs {
        if records.len() == 3 && records[2].len() > 512 {
            out.flight_mode = "combined".to_string();
            out.cert_capacity_bytes = records[2].len().saturating_sub(22);
            out.shoes_layout_valid = true;
        } else if matches!(records.len(), 6 | 7) && records[2].len() <= 512 {
            out.flight_mode = "separate".to_string();
            // Separate mode: [0]=SH, [1]=CCS, [2]=EE, [3]=Certificate, [4]=CertVerify, [5]=Finished
            out.cert_capacity_bytes = records[3].len().saturating_sub(22);
            out.shoes_layout_valid = true;
        } else {
            // Still compute largest encrypted record for diagnostic display
            out.cert_capacity_bytes = records[2..]
                .iter()
                .map(|r| r.len().saturating_sub(22))
                .max()
                .unwrap_or(0);
        }
    } else {
        // Server omitted middlebox CCS or used non-standard framing
        out.cert_capacity_bytes = records[1..]
            .iter()
            .filter(|r| r.first() == Some(&23))
            .map(|r| r.len().saturating_sub(22))
            .max()
            .unwrap_or(0);
    }

    out
}

fn extract_complete_tls_records(buf: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
    loop {
        if buf.len() < 5 {
            break;
        }
        let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total_len = 5 + payload_len;
        if buf.len() < total_len {
            break;
        }
        let rec: Vec<u8> = buf.drain(..total_len).collect();
        out.push(rec);
        if out.len() >= 12 {
            break;
        }
    }
}

/// Performs a real TLS 1.3 + X25519 + ALPN `h2` handshake against `raw_dest` (with SNI `raw_sni`)
/// and evaluates REALITY & ML-DSA-65 suitability against upstream `cfal/shoes` criteria.
pub async fn probe_reality_target(
    raw_dest: &str,
    raw_sni: &str,
    timeout: Duration,
) -> RealityProbeResult {
    let (connect_addr, norm_dest, sni) = match normalize_probe_target(raw_dest, raw_sni) {
        Ok(v) => v,
        Err(e) => {
            return RealityProbeResult {
                dest: raw_dest.trim().to_string(),
                sni: raw_sni.trim().to_string(),
                reachable: false,
                suitable: false,
                verdict: "fail".to_string(),
                score: 0,
                tcp_ms: None,
                tls_ms: None,
                tls_version: String::new(),
                cipher_suite: String::new(),
                alpn: String::new(),
                x25519: false,
                hello_retry: false,
                flight_mode: String::new(),
                flight_records: 0,
                cert_capacity_bytes: 0,
                mldsa65_compatible: false,
                cert_subject: String::new(),
                cert_issuer: String::new(),
                cert_sans: Vec::new(),
                cert_days_left: None,
                cert_self_signed: false,
                sni_matched: false,
                reasons: vec![e.to_string()],
                error: Some(e.to_string()),
            };
        }
    };

    let mut res = RealityProbeResult {
        dest: norm_dest,
        sni: sni.clone(),
        reachable: false,
        suitable: false,
        verdict: "fail".to_string(),
        score: 0,
        tcp_ms: None,
        tls_ms: None,
        tls_version: String::new(),
        cipher_suite: String::new(),
        alpn: String::new(),
        x25519: false,
        hello_retry: false,
        flight_mode: String::new(),
        flight_records: 0,
        cert_capacity_bytes: 0,
        mldsa65_compatible: false,
        cert_subject: String::new(),
        cert_issuer: String::new(),
        cert_sans: Vec::new(),
        cert_days_left: None,
        cert_self_signed: false,
        sni_matched: false,
        reasons: Vec::new(),
        error: None,
    };

    let server_name = match ServerName::try_from(sni.clone()) {
        Ok(sn) => sn,
        Err(_) => {
            let msg = format!("Invalid SNI server name '{sni}'");
            res.reasons.push(msg.clone());
            res.error = Some(msg);
            return res;
        }
    };

    // Build an X25519-only rustls provider so we verify native X25519 without HRR
    let mut provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let captured = Arc::new(Mutex::new(None::<CapturedCerts>));
    let verifier = Arc::new(CaptureCertVerifier {
        captured: captured.clone(),
        algs,
    });

    let mut cfg = match ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
        Err(e) => {
            res.error = Some(format!("TLS client init failed: {e}"));
            res.reasons.push(res.error.clone().unwrap());
            return res;
        }
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg.enable_sni = true;

    let mut conn = match ClientConnection::new(Arc::new(cfg), server_name) {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("TLS connection init failed: {e}"));
            res.reasons.push(res.error.clone().unwrap());
            return res;
        }
    };

    let deadline = tokio::time::Instant::now() + timeout;
    let tcp_start = Instant::now();
    let mut stream = match tokio::time::timeout_at(deadline, TcpStream::connect(&connect_addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let msg = format!("TCP connect failed: {e}");
            res.error = Some(msg.clone());
            res.reasons.push(msg);
            return res;
        }
        Err(_) => {
            let msg = "TCP connect timed out".to_string();
            res.error = Some(msg.clone());
            res.reasons.push(msg);
            return res;
        }
    };
    let _ = stream.set_nodelay(true);
    res.reachable = true;
    res.tcp_ms = Some(tcp_start.elapsed().as_millis() as u64);

    // Send ClientHello
    let tls_start = Instant::now();
    let mut out_buf = Vec::with_capacity(1024);
    while conn.wants_write() {
        if let Err(e) = conn.write_tls(&mut out_buf) {
            res.error = Some(format!("ClientHello write failed: {e}"));
            res.reasons.push(res.error.clone().unwrap());
            return res;
        }
    }
    if let Err(e) = tokio::time::timeout_at(deadline, stream.write_all(&out_buf)).await {
        let msg = format!("Sending ClientHello timed out: {e}");
        res.error = Some(msg.clone());
        res.reasons.push(msg);
        return res;
    } else if let Err(e) = stream.flush().await {
        let msg = format!("TCP write error: {e}");
        res.error = Some(msg.clone());
        res.reasons.push(msg);
        return res;
    }

    // Read server handshake flight while recording raw TLS record boundaries
    let mut raw_pending: Vec<u8> = Vec::with_capacity(8192);
    let mut raw_records: Vec<Vec<u8>> = Vec::new();
    let mut read_buf = [0u8; 4096];

    while conn.is_handshaking() {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut read_buf)).await {
            Ok(Ok(0)) => {
                let msg = "Peer closed connection during TLS handshake".to_string();
                res.error = Some(msg.clone());
                res.reasons.push(msg);
                return res;
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                let msg = format!("TLS read error: {e}");
                res.error = Some(msg.clone());
                res.reasons.push(msg);
                return res;
            }
            Err(_) => {
                let msg = "TLS handshake timed out".to_string();
                res.error = Some(msg.clone());
                res.reasons.push(msg);
                return res;
            }
        };

        raw_pending.extend_from_slice(&read_buf[..n]);
        extract_complete_tls_records(&mut raw_pending, &mut raw_records);

        let mut cursor = Cursor::new(&read_buf[..n]);
        while (cursor.position() as usize) < n {
            match conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("TLS framing error: {e}");
                    res.error = Some(msg.clone());
                    res.reasons.push(msg);
                    return res;
                }
            }
            if let Err(e) = conn.process_new_packets() {
                let msg = format!("TLS handshake rejected: {e}");
                res.error = Some(msg.clone());
                res.reasons.push(msg);
                // Even if TLS 1.3 failed, still record raw ServerHello findings (e.g. HRR)
                let flight = analyze_server_flight(&raw_records);
                res.hello_retry = flight.hello_retry;
                res.x25519 = flight.server_hello_x25519;
                return res;
            }
        }

        // Flush client response if TLS 1.2 or TLS 1.3 Finished needs to be sent
        if conn.wants_write() {
            let mut reply = Vec::new();
            while conn.wants_write() {
                let _ = conn.write_tls(&mut reply);
            }
            if !reply.is_empty() {
                let _ = tokio::time::timeout_at(deadline, stream.write_all(&reply)).await;
            }
        }
    }

    res.tls_ms = Some(tls_start.elapsed().as_millis() as u64);

    // Inspect negotiated TLS parameters
    let proto_ver = conn.protocol_version();
    res.tls_version = match proto_ver {
        Some(ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(other) => format!("{other:?}"),
        None => String::new(),
    };
    if let Some(cs) = conn.negotiated_cipher_suite() {
        res.cipher_suite = format!("{:?}", cs.suite());
    }
    if let Some(alpn) = conn.alpn_protocol() {
        res.alpn = String::from_utf8_lossy(alpn).to_string();
    }

    let is_tls13 = proto_ver == Some(ProtocolVersion::TLSv1_3);
    let flight = analyze_server_flight(&raw_records);
    res.hello_retry = flight.hello_retry;
    res.x25519 = flight.server_hello_x25519 && is_tls13;
    res.flight_mode = flight.flight_mode;
    res.flight_records = flight.flight_records;
    res.cert_capacity_bytes = flight.cert_capacity_bytes;

    // Inspect captured leaf certificate via our X.509 DER parser
    let mut cert_valid_time = false;
    if let Some(cap) = captured.lock().take() {
        if let Ok(info) = inspect_cert_der(&cap.leaf_der) {
            let now = Utc::now().timestamp();
            let days_left = (info.not_after - now) / 86400;
            cert_valid_time = now >= info.not_before && now < info.not_after;
            res.sni_matched = sni_matches_cert(&sni, &info.sans, &info.subject);
            res.cert_subject = info.subject;
            res.cert_issuer = info.issuer;
            res.cert_sans = info.sans;
            res.cert_days_left = Some(days_left);
            res.cert_self_signed = info.is_self_signed;
        }
        if res.cert_capacity_bytes == 0 {
            res.cert_capacity_bytes = cap.chain_total_bytes;
        }
    }

    // Evaluate ML-DSA-65 compatibility based on shoes's exact flight length requirements:
    // Synthetic ML-DSA-65 certificate is ~3,520 bytes (Ed25519 cert + 3,309B ML-DSA-65 signature).
    let mldsa_threshold = if res.flight_mode == "separate" {
        3600
    } else {
        3750
    };
    res.mldsa65_compatible = is_tls13
        && res.x25519
        && !res.hello_retry
        && flight.shoes_layout_valid
        && res.cert_capacity_bytes >= mldsa_threshold;

    // Scoring & human-readable diagnostics
    let mut score: i32 = 100;
    if !is_tls13 {
        score = 0;
        res.reasons.push(format!(
            "Target negotiated {} instead of TLS 1.3 (REALITY requires TLS 1.3)",
            if res.tls_version.is_empty() {
                "unknown TLS"
            } else {
                &res.tls_version
            }
        ));
    }
    if res.hello_retry {
        score = 0;
        res.reasons
            .push("Server sent HelloRetryRequest (REALITY cannot synthesize HRR)".to_string());
    }
    if is_tls13 && !res.x25519 {
        score = 0;
        res.reasons
            .push("Server did not accept X25519 key share".to_string());
    }
    if is_tls13 && !flight.shoes_layout_valid {
        score -= 45;
        res.reasons.push(format!(
            "Non-standard TLS 1.3 server flight layout ({} records, mode={}); shoes may fall back to transparent forward",
            res.flight_records, res.flight_mode
        ));
    }
    if res.alpn != "h2" {
        score -= 15;
        res.reasons.push(format!(
            "ALPN is '{}' (HTTP/2 'h2' is strongly recommended for browser fingerprints)",
            if res.alpn.is_empty() { "none" } else { &res.alpn }
        ));
    }
    if !cert_valid_time {
        score -= 40;
        res.reasons
            .push("Server certificate is expired or not yet valid".to_string());
    }
    if res.cert_self_signed {
        score -= 35;
        res.reasons
            .push("Server uses a self-signed certificate".to_string());
    }
    if !res.sni_matched {
        score -= 30;
        res.reasons.push(format!(
            "Certificate SAN/CN does not match SNI '{}'",
            res.sni
        ));
    }
    if is_tls13 && flight.shoes_layout_valid && !res.mldsa65_compatible {
        score -= 5;
        res.reasons.push(format!(
            "Standard REALITY OK, but cert flight capacity ({} B < {} B) is too small for ML-DSA-65",
            res.cert_capacity_bytes, mldsa_threshold
        ));
    }
    if let Some(ms) = res.tls_ms {
        if ms > 600 {
            score -= 15;
            res.reasons
                .push(format!("High handshake latency ({ms} ms)"));
        } else if ms > 250 {
            score -= 5;
        }
    }

    let final_score = score.clamp(0, 100) as u8;
    res.score = final_score;
    res.suitable = is_tls13
        && res.x25519
        && !res.hello_retry
        && flight.shoes_layout_valid
        && cert_valid_time
        && !res.cert_self_signed;
    res.verdict = if !res.suitable {
        if is_tls13 && res.x25519 && !res.hello_retry && final_score >= 45 {
            "warn".to_string()
        } else {
            "fail".to_string()
        }
    } else if final_score >= 85 && res.alpn == "h2" && res.sni_matched {
        "excellent".to_string()
    } else {
        "good".to_string()
    };

    res
}

/// Probes multiple REALITY targets concurrently (max 16 targets) and sorts by suitability & latency.
pub async fn probe_reality_batch(
    targets: Vec<RealityProbeTarget>,
    timeout: Duration,
) -> Vec<RealityProbeResult> {
    let mut handles = Vec::new();
    for t in targets.into_iter().take(16) {
        handles.push(tokio::spawn(async move {
            probe_reality_target(&t.dest, &t.sni, timeout).await
        }));
    }
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }
    results.sort_by(|a, b| {
        b.suitable
            .cmp(&a.suitable)
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| {
                a.tls_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.tls_ms.unwrap_or(u64::MAX))
            })
    });
    results
}
