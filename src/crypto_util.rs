use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rand::RngCore;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::net::IpAddr;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!("salt error: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash error: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_random_alnum(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|b| CHARSET[(b as usize) % CHARSET.len()] as char)
        .collect()
}

pub fn generate_short_id(hex_len: usize) -> String {
    let byte_len = hex_len.div_ceil(2).max(4);
    let mut bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = hex::encode(bytes);
    s.truncate(hex_len.min(16));
    s
}

/// Generates an RFC 7748 X25519 keypair encoded in unpadded base64url,
/// matching `shoes generate-reality-keypair`, Xray, and sing-box.
pub fn generate_reality_keypair() -> (String, String) {
    let mut priv_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut priv_bytes);
    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;

    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    (
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

pub fn derive_reality_public_key(private_key_b64: &str) -> Result<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(private_key_b64.trim())
        .map_err(|e| anyhow!("invalid base64url private key: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Reality private key must be 32 bytes"))?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(URL_SAFE_NO_PAD.encode(public.as_bytes()))
}

/// Generates a standard WireGuard Curve25519 keypair + optional pre-shared key
/// encoded in standard padded Base64 (matching `wg genkey` / `wg pubkey` / `wg genpsk`).
pub fn generate_wireguard_keypair() -> (String, String, String) {
    let mut priv_bytes = [0u8; 32];
    let mut psk_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut priv_bytes);
    rng.fill_bytes(&mut psk_bytes);
    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;

    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);
    (
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
        STANDARD.encode(psk_bytes),
    )
}

/// Derives the standard padded Base64 WireGuard public key from a 32-byte Base64 private key.
pub fn derive_wireguard_public_key(private_key_b64: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(private_key_b64.trim())
        .map_err(|e| anyhow!("invalid WireGuard base64 private key: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("WireGuard private key must be 32 bytes"))?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.as_bytes()))
}

/// Generates an ECDSA P-256 client certificate + private key PEM for mTLS authentication
/// along with its SHA-256 DER fingerprint formatted as `AA:BB:...` (accepted by `shoes`).
pub fn generate_mtls_client_cert(common_name: &str) -> Result<(String, String, String)> {
    let cn = if common_name.trim().is_empty() {
        "shoes-mtls-client"
    } else {
        common_name.trim()
    };
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::days(1);
    let end = now + chrono::Duration::days(365);
    params.not_before = rcgen::date_time_ymd(start.year(), start.month() as u8, start.day() as u8);
    params.not_after = rcgen::date_time_ymd(end.year(), end.month() as u8, end.day() as u8);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let der = cert.der();
    let digest = ring::digest::digest(&ring::digest::SHA256, der.as_ref());
    let fp = digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok((cert.pem(), key_pair.serialize_pem(), fp))
}

pub fn generate_ss2022_password(cipher: &str) -> Result<String> {
    let key_len = match cipher {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305"
        | "2022-blake3-chacha20-ietf-poly1305" => 32,
        _ => return Ok(generate_random_alnum(24)),
    };
    let mut bytes = vec![0u8; key_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(STANDARD.encode(bytes))
}

/// Generates a valid X.509 self-signed certificate and ECDSA P-256 private key PEM.
pub fn generate_self_signed_cert(domains: &[String]) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    let primary = domains
        .first()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost");
    dn.push(DnType::CommonName, primary);
    params.distinguished_name = dn;

    let mut sans = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let list: Vec<String> = if domains.is_empty() {
        vec!["localhost".to_string(), "127.0.0.1".to_string()]
    } else {
        domains.to_vec()
    };
    for item in list {
        let trimmed = item.trim().trim_matches(['[', ']']);
        if trimmed.is_empty() || !seen.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else if let Ok(ia5) = trimmed.try_into() {
            sans.push(SanType::DnsName(ia5));
        }
    }
    if sans.is_empty() {
        return Err(anyhow!("At least one valid domain name or IP address is required"));
    }
    params.subject_alt_names = sans;

    // Keep validity within 180 days (< 200-day 2026 CA/B Forum / Chromium / Cronet TLS limit).
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::days(1);
    let end = now + chrono::Duration::days(179);
    params.not_before = rcgen::date_time_ymd(
        start.year(),
        start.month() as u8,
        start.day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        end.year(),
        end.month() as u8,
        end.day() as u8,
    );

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

use chrono::Datelike;
