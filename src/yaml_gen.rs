use anyhow::{anyhow, Context, Result};
use ring::digest;
use serde_yaml::{Mapping, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::db::Database;
use crate::models::{
    CertificateRecord, ClientRecord, CoreGlobalSettings, DnsGroupRecord, DnsServerItem, Inbound,
    OutboundGroupRecord, OutboundHop, OutboundMember, PanelSettings, RoutingRuleRecord,
    RuleSourceGroupRecord, SudokuMaskSettings, DEFAULT_LETSENCRYPT_DIR,
};

fn str_val(s: &str) -> Value {
    Value::String(s.to_string())
}

fn bool_val(b: bool) -> Value {
    Value::Bool(b)
}

fn num_u64(n: u64) -> Value {
    Value::Number(n.into())
}

fn insert(map: &mut Mapping, k: &str, v: Value) {
    map.insert(str_val(k), v);
}

#[allow(dead_code)]
pub fn build_shoes_yaml(
    data_dir: &Path,
    settings: &PanelSettings,
    certs: &[CertificateRecord],
    groups: &[OutboundGroupRecord],
    rules: &[RoutingRuleRecord],
    inbounds: &[Inbound],
) -> Result<String> {
    build_shoes_yaml_full(data_dir, settings, certs, &[], &[], groups, rules, inbounds)
}

#[allow(clippy::too_many_arguments)]
pub fn build_shoes_yaml_full(
    data_dir: &Path,
    settings: &PanelSettings,
    certs: &[CertificateRecord],
    dns_groups: &[DnsGroupRecord],
    rule_sources: &[RuleSourceGroupRecord],
    groups: &[OutboundGroupRecord],
    rules: &[RoutingRuleRecord],
    inbounds: &[Inbound],
) -> Result<String> {
    let mut top_entries: Vec<Value> = Vec::new();

    // 1. Clash Controller listener for traffic stats, connections & selector control
    if !settings.clash_api_addr.trim().is_empty() && !settings.clash_api_secret.trim().is_empty() {
        let mut api_map = Mapping::new();
        insert(
            &mut api_map,
            "clash_api_address",
            str_val(settings.clash_api_addr.trim()),
        );
        insert(
            &mut api_map,
            "secret",
            str_val(settings.clash_api_secret.trim()),
        );
        top_entries.push(Value::Mapping(api_map));

        let cache_path = data_dir
            .join("shoes.cache.json")
            .to_string_lossy()
            .replace('\\', "/");
        let mut cache_map = Mapping::new();
        insert(&mut cache_map, "cache_file_path", str_val(&cache_path));
        top_entries.push(Value::Mapping(cache_map));
    }

    // Collect enabled names first for cross-references
    let enabled_group_names: HashSet<String> = groups
        .iter()
        .filter(|g| g.enable)
        .map(|g| g.name.trim().to_string())
        .collect();
    let enabled_dns_names: HashSet<String> = dns_groups
        .iter()
        .filter(|g| g.enable)
        .map(|g| g.name.trim().to_string())
        .collect();
    let enabled_rule_source_names: HashSet<String> = rule_sources
        .iter()
        .filter(|g| g.enable)
        .map(|g| g.name.trim().to_string())
        .collect();

    // Check whether any enabled rule_source uses native Shoes remote mode on Unix
    let has_native_remote_rules = rule_sources.iter().any(|g| {
        g.enable
            && g.items
                .iter()
                .any(|item| item.source_type == "url" && item.sync_mode == "shoes_native")
    });

    // 1b. Managed global_settings (limits, QUIC tuning, NTP, default_dns, rule_cache_dir)
    if let Some(gs_entry) = build_global_settings_entry(
        data_dir,
        &settings.core_global,
        &enabled_dns_names,
        &enabled_group_names,
        has_native_remote_rules,
    )? {
        top_entries.push(gs_entry);
    }

    // Collect certificate sources actively referenced by enabled inbounds.
    let mut referenced_cert_sources = HashSet::new();
    for ib in inbounds.iter().filter(|i| i.enable) {
        if !ib.protocol_settings.raw_override_yaml.trim().is_empty() {
            continue;
        }
        let has_enabled_clients = ib.clients.iter().any(|c| c.enable)
            || matches!(ib.protocol.as_str(), "socks" | "http" | "mixed" | "portforward");
        if !has_enabled_clients {
            continue;
        }
        if ib.is_quic() || ib.stream_settings.security == "tls" {
            let tls = &ib.stream_settings.tls;
            let src = tls.certificate_source.trim();
            if !src.is_empty()
                && (tls.cert_mode == "source"
                    || (tls.cert_file.trim().is_empty() && tls.key_file.trim().is_empty()))
            {
                referenced_cert_sources.insert(src.to_string());
            }
        }
    }

    let mut acme_cert_names = HashSet::new();

    // 2. Managed certificate_source entries
    for cert in certs {
        if cert.cert_type == "acme" {
            acme_cert_names.insert(cert.name.trim().to_string());
            // shoes rejects TLS-ALPN-01 ACME sources unless an enabled TCP TLS inbound binds every domain.
            // Defer emitting unreferenced TLS-ALPN-01 sources so users can create the cert first, then attach an inbound.
            if cert.challenge_type == "tls_alpn01"
                && !referenced_cert_sources.contains(cert.name.trim())
            {
                continue;
            }
        }
        top_entries.push(build_certificate_entry(data_dir, cert)?);
    }

    // 3. Outbound client_group entries
    for g in groups.iter().filter(|g| g.enable) {
        top_entries.push(build_outbound_group_entry(g)?);
    }

    // 3b. Managed dns_group entries
    for dg in dns_groups.iter().filter(|g| g.enable) {
        top_entries.push(build_dns_group_entry(dg, &enabled_group_names)?);
    }

    // 3c. Managed rule_source_group entries (GeoIP / GeoSite / SRS / MRS / YAML)
    for rsg in rule_sources.iter().filter(|g| g.enable) {
        top_entries.push(build_rule_source_group_entry(
            data_dir,
            rsg,
            &enabled_group_names,
        )?);
    }

    // 4. Shared routing rule_group (`panel-routing`) if enabled routing rules exist
    let enabled_rules: Vec<&RoutingRuleRecord> = rules.iter().filter(|r| r.enable).collect();
    let has_panel_routing = !enabled_rules.is_empty();
    if has_panel_routing {
        top_entries.push(build_rule_group_entry(
            &enabled_rules,
            &enabled_group_names,
            &enabled_rule_source_names,
        )?);
    }

    // 5. Enabled Inbound Server entries (with automatic multi-SNI multiplexing on shared TCP ports)
    let enabled_inbounds: Vec<&Inbound> = inbounds.iter().filter(|i| i.enable).collect();
    let mut sni_group_counts: std::collections::HashMap<(String, u16), usize> =
        std::collections::HashMap::new();
    for ib in &enabled_inbounds {
        if ib.can_share_sni_port() {
            let listen = if ib.listen.trim().is_empty() {
                "0.0.0.0".to_string()
            } else {
                ib.listen.trim().to_string()
            };
            *sni_group_counts.entry((listen, ib.port)).or_insert(0) += 1;
        }
    }

    let mut emitted_shared_keys: HashSet<(String, u16)> = HashSet::new();
    for ib in &enabled_inbounds {
        if ib.can_share_sni_port() {
            let listen = if ib.listen.trim().is_empty() {
                "0.0.0.0".to_string()
            } else {
                ib.listen.trim().to_string()
            };
            let key = (listen, ib.port);
            if sni_group_counts.get(&key).copied().unwrap_or(0) >= 2 {
                if emitted_shared_keys.insert(key.clone()) {
                    let members: Vec<&Inbound> = enabled_inbounds
                        .iter()
                        .copied()
                        .filter(|other| {
                            other.can_share_sni_port()
                                && other.port == key.1
                                && (if other.listen.trim().is_empty() {
                                    "0.0.0.0"
                                } else {
                                    other.listen.trim()
                                }) == key.0
                        })
                        .collect();
                    if let Some(entry) = build_shared_sni_server_entry(
                        &members,
                        has_panel_routing,
                        &enabled_group_names,
                        &enabled_dns_names,
                        &acme_cert_names,
                    )
                    .with_context(|| format!("shared SNI listener on {}:{}", key.0, key.1))?
                    {
                        top_entries.push(entry);
                    }
                }
                continue;
            }
        }

        if let Some(entry) = build_inbound_entry(
            data_dir,
            ib,
            has_panel_routing,
            &enabled_group_names,
            &enabled_dns_names,
            &acme_cert_names,
        )
        .with_context(|| format!("inbound '{}' (port {})", ib.remark, ib.port))?
        {
            top_entries.push(entry);
        }
    }

    // 6. Extra raw top-level YAML entries (global_settings, ntp, dns_group, tun, etc.)
    if !settings.shoes_extra_yaml.trim().is_empty() {
        let extra_val: Value = serde_yaml::from_str(&settings.shoes_extra_yaml)
            .context("invalid YAML in shoes_extra_yaml")?;
        match extra_val {
            Value::Sequence(seq) => top_entries.extend(seq),
            Value::Mapping(_) => top_entries.push(extra_val),
            Value::Null => {}
            _ => {
                return Err(anyhow!(
                    "shoes_extra_yaml must be a YAML list of entries or a mapping"
                ))
            }
        }
    }

    let yaml = serde_yaml::to_string(&top_entries)?;
    Ok(format!(
        "# Generated by shoes-panel — DO NOT EDIT DIRECTLY (changes will be overwritten)\n{yaml}"
    ))
}

/// Ensures a directory exists and has owner-only (`0700`) permissions on Unix,
/// as strictly required by `shoes` ACME `state_dir` checks.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("failed to create private directory '{}'", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod 0700 '{}'", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
            .with_context(|| format!("failed to create directory '{}'", path.display()))?;
    }
    Ok(())
}

/// Validates and normalizes DNS domain names for Shoes built-in ACME
/// (unique lowercase ASCII DNS names; rejects wildcards and IP literals).
pub fn normalize_acme_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in domains {
        let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        if d.starts_with("*.") || d.contains('*') {
            return Err(anyhow!(
                "ACME domain '{d}' uses a wildcard, which HTTP-01 / TLS-ALPN-01 cannot issue"
            ));
        }
        if d.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            return Err(anyhow!(
                "'{d}' is an IP address. Shoes built-in ACME only supports DNS domain names; for no-domain IP SSL, use 'Free Public IP SSL (Let's Encrypt shortlived)' or 'Self-Signed IP Cert'."
            ));
        }
        let valid_dns = d.len() <= 253
            && d.contains('.')
            && d.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        if !valid_dns {
            return Err(anyhow!(
                "Invalid ACME DNS domain '{d}' (must be a valid ASCII domain like proxy.example.com)"
            ));
        }
        if seen.insert(d.clone()) {
            out.push(d);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("ACME certificate requires at least one valid DNS domain"));
    }
    Ok(out)
}

/// Computes an isolated `state_dir` path scoped by `(cert_name, directory_url, normalized_domains)`
/// so changing Staging -> Production or editing domains never collides with Shoes's ACME identity lock.
pub fn acme_state_dir(
    data_dir: &Path,
    cert_name: &str,
    directory_url: &str,
    norm_domains: &[String],
) -> PathBuf {
    let safe_name: String = cert_name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let safe_name = if safe_name.is_empty() {
        "acme".to_string()
    } else {
        safe_name
    };
    let mut identity = String::from(directory_url.trim());
    for d in norm_domains {
        identity.push('\0');
        identity.push_str(d);
    }
    let hash = digest::digest(&digest::SHA256, identity.as_bytes());
    let suffix = hex::encode(&hash.as_ref()[..4]);
    data_dir.join("acme").join(format!("{safe_name}-{suffix}"))
}

fn build_certificate_entry(data_dir: &Path, c: &CertificateRecord) -> Result<Value> {
    let mut m = Mapping::new();
    insert(&mut m, "certificate_source", str_val(c.name.trim()));
    match c.cert_type.as_str() {
        "acme" => {
            let norm_domains = normalize_acme_domains(&c.domains)
                .with_context(|| format!("ACME certificate '{}'", c.name))?;
            insert(&mut m, "type", str_val("acme"));
            insert(
                &mut m,
                "domains",
                Value::Sequence(norm_domains.iter().map(|d| str_val(d)).collect()),
            );
            let dir_url = if c.directory_url.trim().is_empty() {
                DEFAULT_LETSENCRYPT_DIR
            } else {
                c.directory_url.trim()
            };
            insert(&mut m, "directory_url", str_val(dir_url));
            let state_dir_path = acme_state_dir(data_dir, &c.name, dir_url, &norm_domains);
            ensure_private_dir(&state_dir_path)?;
            let state_dir = state_dir_path.to_string_lossy().replace('\\', "/");
            insert(&mut m, "state_dir", str_val(&state_dir));
            if !c.email.trim().is_empty() {
                let contact = if c.email.trim().starts_with("mailto:") {
                    c.email.trim().to_string()
                } else {
                    format!("mailto:{}", c.email.trim())
                };
                insert(&mut m, "contacts", Value::Sequence(vec![str_val(&contact)]));
            }
            if !c.terms_of_service.trim().is_empty() {
                insert(
                    &mut m,
                    "terms_of_service",
                    str_val(c.terms_of_service.trim()),
                );
            }
            let mut ch = Mapping::new();
            if c.challenge_type == "tls_alpn01" {
                insert(&mut ch, "type", str_val("tls_alpn01"));
            } else {
                insert(&mut ch, "type", str_val("http01"));
                let listen = if c.http01_listen.trim().is_empty() {
                    "0.0.0.0:80"
                } else {
                    c.http01_listen.trim()
                };
                insert(&mut ch, "listen", Value::Sequence(vec![str_val(listen)]));
            }
            insert(&mut m, "challenge", Value::Mapping(ch));
        }
        _ => {
            // Covers both "files" (manual / uploaded / self-signed) and "acme_ip" (panel-managed IP SSL PEMs)
            if c.cert_file.trim().is_empty() || c.key_file.trim().is_empty() {
                return Err(anyhow!(
                    "File certificate '{}' requires both cert_file and key_file",
                    c.name
                ));
            }
            insert(&mut m, "type", str_val("files"));
            insert(
                &mut m,
                "cert",
                str_val(&c.cert_file.trim().replace('\\', "/")),
            );
            insert(
                &mut m,
                "key",
                str_val(&c.key_file.trim().replace('\\', "/")),
            );
        }
    }
    Ok(Value::Mapping(m))
}

fn build_outbound_group_entry(g: &OutboundGroupRecord) -> Result<Value> {
    let mut m = Mapping::new();
    insert(&mut m, "client_group", str_val(g.name.trim()));
    let gtype = match g.group_type.as_str() {
        "selector" | "url-test" | "round-robin" => g.group_type.as_str(),
        _ => "selector",
    };
    insert(&mut m, "type", str_val(gtype));

    if gtype == "selector" && !g.default_member.trim().is_empty() {
        insert(&mut m, "default", str_val(g.default_member.trim()));
    } else if gtype == "url-test" {
        let url = if g.test_url.trim().is_empty() {
            "https://www.gstatic.com/generate_204"
        } else {
            g.test_url.trim()
        };
        insert(&mut m, "url", str_val(url));
        insert(&mut m, "interval", num_u64(g.interval_secs.clamp(1, 86400)));
        insert(&mut m, "timeout", num_u64(g.timeout_ms.clamp(100, 60000)));
        insert(&mut m, "tolerance", num_u64(g.tolerance_ms.min(65535)));
    }

    if !g.raw_chains_yaml.trim().is_empty() {
        let chains_val: Value = serde_yaml::from_str(&g.raw_chains_yaml)
            .with_context(|| format!("invalid raw_chains_yaml in group '{}'", g.name))?;
        insert(&mut m, "client_chains", chains_val);
    } else {
        if g.members.is_empty() {
            return Err(anyhow!(
                "Outbound group '{}' must have at least one member or raw YAML",
                g.name
            ));
        }
        let mut chains = Vec::new();
        for member in &g.members {
            chains.push(build_outbound_member_chain(member)?);
        }
        insert(&mut m, "client_chains", Value::Sequence(chains));
    }

    Ok(Value::Mapping(m))
}

fn build_shoes_h2mux_value(mux: &crate::models::H2MuxSettings) -> Value {
    let mut m = Mapping::new();
    if mux.max_connections > 0 {
        insert(&mut m, "max_connections", num_u64(mux.max_connections as u64));
    }
    if mux.min_streams > 0 {
        insert(&mut m, "min_streams", num_u64(mux.min_streams as u64));
    }
    if mux.max_streams > 0 {
        insert(&mut m, "max_streams", num_u64(mux.max_streams as u64));
    }
    if mux.padding {
        insert(&mut m, "padding", bool_val(true));
    }
    Value::Mapping(m)
}

const VALID_TLS_KX_GROUPS: &[&str] = &[
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "X25519",
    "SecP256r1",
    "SecP384r1",
];

pub fn validate_key_exchange_groups(
    groups: &[String],
    vision: bool,
    zero_rtt: bool,
) -> Result<Option<Vec<Value>>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut all_hybrid = true;
    for raw in groups {
        let g = raw.trim();
        if g.is_empty() {
            continue;
        }
        if !VALID_TLS_KX_GROUPS.contains(&g) {
            return Err(anyhow!(
                "Unsupported TLS key_exchange_group '{g}'. Allowed: {}",
                VALID_TLS_KX_GROUPS.join(", ")
            ));
        }
        if !seen.insert(g.to_string()) {
            continue;
        }
        if !matches!(g, "X25519MLKEM768" | "SecP256r1MLKEM768") {
            all_hybrid = false;
        }
        out.push(str_val(g));
    }
    if out.is_empty() {
        return Ok(None);
    }
    if all_hybrid && vision {
        return Err(anyhow!(
            "Hybrid-only key_exchange_groups cannot be combined with TLS Vision (add X25519 fallback or disable Vision)"
        ));
    }
    if all_hybrid && zero_rtt {
        return Err(anyhow!(
            "Hybrid-only key_exchange_groups cannot be combined with TUIC 0-RTT handshake"
        ));
    }
    Ok(Some(out))
}

fn normalize_fingerprints(raw_fps: &[String]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for raw in raw_fps {
        for part in raw.split([',', '\n', ';']) {
            let mut s = part.trim();
            if s.is_empty() {
                continue;
            }
            for prefix in ["SHA256 Fingerprint=", "sha256:", "SHA256:", "sha-256:"] {
                if let Some(rest) = s.strip_prefix(prefix) {
                    s = rest.trim();
                }
            }
            let hex_only: String = s.chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect();
            if hex_only.len() % 2 != 0
                || hex_only.is_empty()
                || !hex_only.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(anyhow!(
                    "Invalid TLS certificate fingerprint '{part}': expected hex SHA-256 bytes (e.g. AA:BB:...)"
                ));
            }
            let upper = hex_only.to_ascii_uppercase();
            let colon = upper
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(":");
            out.push(str_val(&colon));
        }
    }
    Ok(out)
}

fn apply_mtls_fields(
    target: &mut Mapping,
    ca_certs: &[String],
    fingerprints: &[String],
) -> Result<()> {
    let cas: Vec<Value> = ca_certs
        .iter()
        .flat_map(|s| split_items(s))
        .map(|p| str_val(&p.replace('\\', "/")))
        .collect();
    if !cas.is_empty() {
        insert(target, "client_ca_certs", Value::Sequence(cas));
    }
    let fps = normalize_fingerprints(fingerprints)?;
    if !fps.is_empty() {
        insert(target, "client_fingerprints", Value::Sequence(fps));
    }
    Ok(())
}

pub fn wrap_sudoku_mask(inner: Value, mask: &SudokuMaskSettings) -> Result<Value> {
    if !mask.enabled {
        return Ok(inner);
    }
    let mut sm = Mapping::new();
    insert(&mut sm, "type", str_val("sudoku_mask"));
    if !mask.password.is_empty() {
        insert(&mut sm, "password", str_val(&mask.password));
    }
    let ascii = mask.ascii.trim();
    if !ascii.is_empty() {
        let lower = ascii.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "prefer_entropy" | "entropy" | "prefer_ascii" | "ascii"
        ) {
            return Err(anyhow!(
                "Invalid Sudoku ascii mode '{ascii}' (expected prefer_entropy, entropy, prefer_ascii, or ascii)"
            ));
        }
        insert(&mut sm, "ascii", str_val(&lower));
    }
    let tables: Vec<String> = mask
        .custom_tables
        .iter()
        .flat_map(|s| split_items(s))
        .collect();
    if !tables.is_empty() {
        insert(
            &mut sm,
            "custom_tables",
            Value::Sequence(tables.into_iter().map(|t| str_val(&t)).collect()),
        );
    } else if !mask.custom_table.trim().is_empty() {
        insert(&mut sm, "custom_table", str_val(mask.custom_table.trim()));
    }
    if mask.padding_min > 0 {
        insert(&mut sm, "padding_min", num_u64(mask.padding_min.min(100) as u64));
    }
    if mask.padding_max > 0 {
        let pmax = mask.padding_max.min(100).max(mask.padding_min.min(100));
        insert(&mut sm, "padding_max", num_u64(pmax as u64));
    }
    insert(&mut sm, "protocol", inner);
    Ok(Value::Mapping(sm))
}

fn build_outbound_hop_value(
    hop_cfg: &OutboundHop,
    hop_name: Option<&str>,
    label: &str,
    hop_index: usize,
) -> Result<Value> {
    let proto = hop_cfg.protocol.trim().to_ascii_lowercase();
    if proto == "group" {
        let target_group = hop_cfg.address.trim();
        if target_group.is_empty() {
            return Err(anyhow!("{label}: group reference hop requires group name"));
        }
        return Ok(str_val(target_group));
    }

    let mut hop = Mapping::new();
    if let Some(n) = hop_name.filter(|s| !s.trim().is_empty()) {
        insert(&mut hop, "name", str_val(n.trim()));
    }
    if !hop_cfg.bind_interface.trim().is_empty() {
        insert(
            &mut hop,
            "bind_interface",
            str_val(hop_cfg.bind_interface.trim()),
        );
    }

    if proto == "direct" {
        let mut p = Mapping::new();
        insert(&mut p, "type", str_val("direct"));
        insert(&mut hop, "protocol", Value::Mapping(p));
        return Ok(Value::Mapping(hop));
    }

    if proto == "wireguard" {
        if hop_index > 0 {
            return Err(anyhow!(
                "{label}: WireGuard outbound can only be used as hop 1 (entry hop)"
            ));
        }
        if hop_cfg.address.trim().is_empty() {
            return Err(anyhow!("{label}: WireGuard requires peer endpoint (host:port)"));
        }
        if hop_cfg.wg_private_key.trim().is_empty() || hop_cfg.wg_public_key.trim().is_empty() {
            return Err(anyhow!(
                "{label}: WireGuard requires both private_key and peer public_key"
            ));
        }
        let addrs: Vec<String> = hop_cfg
            .wg_addresses
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if addrs.is_empty() {
            return Err(anyhow!(
                "{label}: WireGuard requires at least one tunnel interface address (e.g. 172.16.0.2/32)"
            ));
        }
        if hop_cfg.effective_security() != "none" || hop_cfg.h2mux.enabled || hop_cfg.sudoku.enabled {
            return Err(anyhow!(
                "{label}: WireGuard outbound cannot be wrapped with TLS, ShadowTLS, H2Mux, or Sudoku mask"
            ));
        }

        insert(&mut hop, "address", str_val(hop_cfg.address.trim()));

        let mut wg = Mapping::new();
        insert(&mut wg, "type", str_val("wireguard"));
        insert(&mut wg, "private_key", str_val(hop_cfg.wg_private_key.trim()));
        insert(&mut wg, "public_key", str_val(hop_cfg.wg_public_key.trim()));
        if !hop_cfg.wg_preshared_key.trim().is_empty() {
            insert(
                &mut wg,
                "pre_shared_key",
                str_val(hop_cfg.wg_preshared_key.trim()),
            );
        }
        insert(
            &mut wg,
            "addresses",
            Value::Sequence(addrs.into_iter().map(|s| str_val(&s)).collect()),
        );
        let allowed: Vec<String> = hop_cfg
            .wg_allowed_ips
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let allowed = if allowed.is_empty() {
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        } else {
            allowed
        };
        insert(
            &mut wg,
            "allowed_ips",
            Value::Sequence(allowed.into_iter().map(|s| str_val(&s)).collect()),
        );
        if hop_cfg.wg_mtu > 0 {
            if !(1280..=1420).contains(&hop_cfg.wg_mtu) {
                return Err(anyhow!("{label}: WireGuard MTU must be between 1280 and 1420"));
            }
            insert(&mut wg, "mtu", num_u64(hop_cfg.wg_mtu as u64));
        }
        if hop_cfg.wg_keepalive > 0 {
            insert(
                &mut wg,
                "persistent_keepalive",
                num_u64(hop_cfg.wg_keepalive as u64),
            );
        }
        if hop_cfg.wg_tcp_buffer_size.is_some() || hop_cfg.wg_tcp_memory_bytes.is_some() {
            let mut rl = Mapping::new();
            if let Some(buf) = hop_cfg.wg_tcp_buffer_size.filter(|&v| v > 0) {
                insert(&mut rl, "tcp_buffer_size", num_u64(buf as u64));
            }
            if let Some(mem) = hop_cfg.wg_tcp_memory_bytes.filter(|&v| v > 0) {
                insert(&mut rl, "tcp_memory_bytes", num_u64(mem));
            }
            if !rl.is_empty() {
                insert(&mut wg, "resource_limits", Value::Mapping(rl));
            }
        }
        insert(&mut hop, "protocol", Value::Mapping(wg));
        return Ok(Value::Mapping(hop));
    }

    if hop_cfg.address.trim().is_empty() {
        return Err(anyhow!("{label}: server address (host:port) is required"));
    }
    insert(&mut hop, "address", str_val(hop_cfg.address.trim()));

    // Native QUIC outbound protocols (Hysteria2 & TUIC v5)
    if matches!(proto.as_str(), "hysteria2" | "tuic") {
        if hop_index > 0 {
            return Err(anyhow!(
                "{label}: native QUIC protocol '{proto}' can only be used as hop 1 (entry hop)"
            ));
        }
        if hop_cfg.sudoku.enabled {
            return Err(anyhow!(
                "{label}: Sudoku TCP mask cannot be used on QUIC protocol '{proto}'"
            ));
        }
        insert(&mut hop, "transport", str_val("quic"));
        let mut inner = Mapping::new();
        if proto == "hysteria2" {
            if hop_cfg.password.trim().is_empty() {
                return Err(anyhow!("{label}: Hysteria2 outbound requires password"));
            }
            insert(&mut inner, "type", str_val("hysteria2"));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
            if !hop_cfg.hy2_obfs_password.trim().is_empty() {
                let mut obfs = Mapping::new();
                insert(&mut obfs, "type", str_val("salamander"));
                insert(&mut obfs, "password", str_val(hop_cfg.hy2_obfs_password.trim()));
                insert(&mut inner, "obfs", Value::Mapping(obfs));
            }
            if !hop_cfg.hy2_hopping_ports.trim().is_empty() {
                let mut hmap = Mapping::new();
                insert(&mut hmap, "ports", str_val(hop_cfg.hy2_hopping_ports.trim()));
                insert(&mut hmap, "interval_secs", num_u64(30));
                insert(&mut inner, "hopping", Value::Mapping(hmap));
            }
        } else {
            if hop_cfg.uuid.trim().is_empty() || hop_cfg.password.trim().is_empty() {
                return Err(anyhow!("{label}: TUIC outbound requires uuid and password"));
            }
            insert(&mut inner, "type", str_val("tuic"));
            insert(&mut inner, "uuid", str_val(hop_cfg.uuid.trim()));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
            let mode = match hop_cfg.tuic_udp_mode.trim().to_ascii_lowercase().as_str() {
                "quic" => "quic",
                _ => "native",
            };
            insert(&mut inner, "udp_relay_mode", str_val(mode));
        }
        insert(&mut hop, "protocol", Value::Mapping(inner));

        let mut qmap = Mapping::new();
        insert(&mut qmap, "verify", bool_val(hop_cfg.verify));
        if !hop_cfg.sni.trim().is_empty() {
            insert(&mut qmap, "sni_hostname", str_val(hop_cfg.sni.trim()));
        }
        if !hop_cfg.alpn.is_empty() {
            insert(
                &mut qmap,
                "alpn_protocols",
                Value::Sequence(hop_cfg.alpn.iter().map(|a| str_val(a.trim())).collect()),
            );
        }
        if !hop_cfg.tls_cert.trim().is_empty() && !hop_cfg.tls_key.trim().is_empty() {
            insert(&mut qmap, "cert", str_val(&hop_cfg.tls_cert.trim().replace('\\', "/")));
            insert(&mut qmap, "key", str_val(&hop_cfg.tls_key.trim().replace('\\', "/")));
        }
        let sfps = normalize_fingerprints(&hop_cfg.server_fingerprints)?;
        if !sfps.is_empty() {
            insert(&mut qmap, "server_fingerprints", Value::Sequence(sfps));
        }
        if hop_index == 0 {
            if let Some(kx) = validate_key_exchange_groups(&hop_cfg.key_exchange_groups, false, false)? {
                insert(&mut qmap, "key_exchange_groups", Value::Sequence(kx));
            }
        }
        insert(&mut hop, "quic_settings", Value::Mapping(qmap));
        return Ok(Value::Mapping(hop));
    }

    // Standard TCP-based outbound protocols
    let has_vless_enc = proto == "vless" && !hop_cfg.vless_encryption.trim().is_empty();
    let mut inner = Mapping::new();
    match proto.as_str() {
        "socks" | "socks5" => {
            insert(&mut inner, "type", str_val("socks"));
            if !hop_cfg.username.trim().is_empty() {
                insert(&mut inner, "username", str_val(hop_cfg.username.trim()));
            }
            if !hop_cfg.password.trim().is_empty() {
                insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
            }
        }
        "http" => {
            insert(&mut inner, "type", str_val("http"));
            if !hop_cfg.username.trim().is_empty() {
                insert(&mut inner, "username", str_val(hop_cfg.username.trim()));
            }
            if !hop_cfg.password.trim().is_empty() {
                insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
            }
        }
        "shadowsocks" | "ss" => {
            insert(&mut inner, "type", str_val("shadowsocks"));
            let cipher = if hop_cfg.cipher.trim().is_empty() {
                "aes-256-gcm"
            } else {
                hop_cfg.cipher.trim()
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
        }
        "snell" => {
            insert(&mut inner, "type", str_val("snell"));
            let cipher = if hop_cfg.cipher.trim().is_empty() {
                "aes-128-gcm"
            } else {
                hop_cfg.cipher.trim()
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
        }
        "vless" => {
            insert(&mut inner, "type", str_val("vless"));
            insert(&mut inner, "user_id", str_val(hop_cfg.uuid.trim()));
            if has_vless_enc {
                insert(
                    &mut inner,
                    "encryption",
                    str_val(hop_cfg.vless_encryption.trim()),
                );
                if hop_cfg.vision {
                    insert(&mut inner, "vision", bool_val(true));
                }
            }
            if hop_cfg.h2mux.enabled {
                insert(&mut inner, "h2mux", build_shoes_h2mux_value(&hop_cfg.h2mux));
            }
        }
        "vmess" => {
            insert(&mut inner, "type", str_val("vmess"));
            let cipher = if hop_cfg.cipher.trim().is_empty() || hop_cfg.cipher == "auto" {
                "aes-128-gcm"
            } else {
                hop_cfg.cipher.trim()
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "user_id", str_val(hop_cfg.uuid.trim()));
            if hop_cfg.h2mux.enabled {
                insert(&mut inner, "h2mux", build_shoes_h2mux_value(&hop_cfg.h2mux));
            }
        }
        "trojan" => {
            insert(&mut inner, "type", str_val("trojan"));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
            if hop_cfg.h2mux.enabled {
                insert(&mut inner, "h2mux", build_shoes_h2mux_value(&hop_cfg.h2mux));
            }
        }
        "anytls" => {
            insert(&mut inner, "type", str_val("anytls"));
            insert(&mut inner, "password", str_val(hop_cfg.password.trim()));
        }
        other => return Err(anyhow!("{label}: unsupported outbound protocol '{other}'")),
    }

    if hop_cfg.h2mux.enabled && !matches!(proto.as_str(), "vless" | "vmess" | "trojan") {
        return Err(anyhow!(
            "{label}: Shoes client H2Mux only supports VLESS, VMess, and Trojan"
        ));
    }

    // Optional stream transport (WebSocket / XHTTP)
    let net = hop_cfg.network.trim().to_ascii_lowercase();
    let transported = if net == "ws" {
        let mut ws = Mapping::new();
        insert(&mut ws, "type", str_val("websocket"));
        if !hop_cfg.ws_path.trim().is_empty() {
            insert(&mut ws, "matching_path", str_val(hop_cfg.ws_path.trim()));
        }
        if !hop_cfg.ws_host.trim().is_empty() {
            let mut hdrs = Mapping::new();
            insert(&mut hdrs, "Host", str_val(hop_cfg.ws_host.trim()));
            insert(&mut ws, "matching_headers", Value::Mapping(hdrs));
        }
        insert(&mut ws, "protocol", Value::Mapping(inner));
        Value::Mapping(ws)
    } else if net == "xhttp" {
        let mut xh = Mapping::new();
        insert(&mut xh, "type", str_val("xhttp"));
        if !hop_cfg.xhttp_path.trim().is_empty() {
            insert(&mut xh, "path", str_val(hop_cfg.xhttp_path.trim()));
        }
        if !hop_cfg.xhttp_host.trim().is_empty() {
            insert(&mut xh, "host", str_val(hop_cfg.xhttp_host.trim()));
        }
        if !hop_cfg.xhttp_mode.trim().is_empty() {
            insert(&mut xh, "mode", str_val(hop_cfg.xhttp_mode.trim()));
        }
        insert(&mut xh, "protocol", Value::Mapping(inner));
        Value::Mapping(xh)
    } else {
        Value::Mapping(inner)
    };

    // Security layer (TLS / REALITY / ShadowTLS v3 / None)
    if hop_cfg.shadowtls && hop_cfg.tls && hop_cfg.security.trim().is_empty() {
        return Err(anyhow!(
            "{label}: cannot enable both TLS and ShadowTLS at the same time"
        ));
    }
    let sec = hop_cfg.effective_security();
    let secured = match sec {
        "shadowtls" => {
            if hop_cfg.shadowtls_password.trim().is_empty() {
                return Err(anyhow!("{label}: ShadowTLS v3 requires shadowtls_password"));
            }
            let mut stls = Mapping::new();
            insert(&mut stls, "type", str_val("shadowtls"));
            insert(
                &mut stls,
                "password",
                str_val(hop_cfg.shadowtls_password.trim()),
            );
            if !hop_cfg.sni.trim().is_empty() {
                insert(&mut stls, "sni_hostname", str_val(hop_cfg.sni.trim()));
            }
            insert(&mut stls, "protocol", transported);
            Value::Mapping(stls)
        }
        "reality" => {
            if hop_cfg.reality_public_key.trim().is_empty() {
                return Err(anyhow!("{label}: REALITY outbound requires public_key"));
            }
            if hop_cfg.sni.trim().is_empty() {
                return Err(anyhow!("{label}: REALITY outbound requires sni_hostname"));
            }
            let mut rm = Mapping::new();
            insert(&mut rm, "type", str_val("reality"));
            insert(
                &mut rm,
                "public_key",
                str_val(hop_cfg.reality_public_key.trim()),
            );
            insert(
                &mut rm,
                "short_id",
                str_val(hop_cfg.reality_short_id.trim()),
            );
            insert(&mut rm, "sni_hostname", str_val(hop_cfg.sni.trim()));
            if !hop_cfg.reality_mldsa65_verify.trim().is_empty() {
                insert(
                    &mut rm,
                    "mldsa65_verify",
                    str_val(hop_cfg.reality_mldsa65_verify.trim()),
                );
            }
            if proto == "vless" && net != "ws" && net != "xhttp" && hop_cfg.vision && !has_vless_enc {
                insert(&mut rm, "vision", bool_val(true));
            }
            insert(&mut rm, "protocol", transported);
            Value::Mapping(rm)
        }
        "tls" => {
            let outer_vision =
                proto == "vless" && net != "ws" && net != "xhttp" && hop_cfg.vision && !has_vless_enc;
            let mut tls_map = Mapping::new();
            insert(&mut tls_map, "type", str_val("tls"));
            insert(&mut tls_map, "verify", bool_val(hop_cfg.verify));
            if !hop_cfg.sni.trim().is_empty() {
                insert(&mut tls_map, "sni_hostname", str_val(hop_cfg.sni.trim()));
            }
            if !hop_cfg.alpn.is_empty() {
                insert(
                    &mut tls_map,
                    "alpn_protocols",
                    Value::Sequence(hop_cfg.alpn.iter().map(|a| str_val(a.trim())).collect()),
                );
            }
            if !hop_cfg.tls_cert.trim().is_empty() && !hop_cfg.tls_key.trim().is_empty() {
                insert(
                    &mut tls_map,
                    "cert",
                    str_val(&hop_cfg.tls_cert.trim().replace('\\', "/")),
                );
                insert(
                    &mut tls_map,
                    "key",
                    str_val(&hop_cfg.tls_key.trim().replace('\\', "/")),
                );
            }
            let sfps = normalize_fingerprints(&hop_cfg.server_fingerprints)?;
            if !sfps.is_empty() {
                insert(&mut tls_map, "server_fingerprints", Value::Sequence(sfps));
            }
            if let Some(kx) =
                validate_key_exchange_groups(&hop_cfg.key_exchange_groups, outer_vision, false)?
            {
                insert(&mut tls_map, "key_exchange_groups", Value::Sequence(kx));
            }
            if outer_vision {
                insert(&mut tls_map, "vision", bool_val(true));
            }
            insert(&mut tls_map, "protocol", transported);
            Value::Mapping(tls_map)
        }
        _ => transported,
    };

    // Outermost Sudoku TCP FinalMask wrapper (optional)
    let final_proto = wrap_sudoku_mask(secured, &hop_cfg.sudoku)?;
    insert(&mut hop, "protocol", final_proto);
    Ok(Value::Mapping(hop))
}

fn build_outbound_member_chain(m: &OutboundMember) -> Result<Value> {
    let mut wrapper = Mapping::new();
    let primary = m.primary_hop();
    let is_multi_hop = !m.extra_hops.is_empty();

    if is_multi_hop {
        if !m.name.trim().is_empty() {
            insert(&mut wrapper, "name", str_val(m.name.trim()));
        }
        let mut hops_seq = Vec::with_capacity(1 + m.extra_hops.len());
        hops_seq.push(build_outbound_hop_value(
            &primary,
            None,
            &format!("Outbound '{}' hop 1", m.name),
            0,
        )?);
        for (idx, extra) in m.extra_hops.iter().enumerate() {
            hops_seq.push(build_outbound_hop_value(
                extra,
                None,
                &format!("Outbound '{}' hop {}", m.name, idx + 2),
                idx + 1,
            )?);
        }
        insert(&mut wrapper, "chain", Value::Sequence(hops_seq));
        return Ok(Value::Mapping(wrapper));
    }

    if primary.protocol == "group" {
        insert(
            &mut wrapper,
            "chain",
            Value::Sequence(vec![str_val(primary.address.trim())]),
        );
        return Ok(Value::Mapping(wrapper));
    }

    let hop0 = build_outbound_hop_value(
        &primary,
        Some(m.name.as_str()),
        &format!("Outbound '{}'", m.name),
        0,
    )?;
    insert(&mut wrapper, "chain", Value::Sequence(vec![hop0]));
    Ok(Value::Mapping(wrapper))
}

fn validate_ip_strategy(s: &str) -> Result<Option<&'static str>> {
    match s.trim() {
        "" => Ok(None),
        "ipv4_then_ipv6" => Ok(Some("ipv4_then_ipv6")),
        "ipv6_then_ipv4" => Ok(Some("ipv6_then_ipv4")),
        "ipv4_only" => Ok(Some("ipv4_only")),
        "ipv6_only" => Ok(Some("ipv6_only")),
        "ipv4_and_ipv6" => Ok(Some("ipv4_and_ipv6")),
        other => Err(anyhow!(
            "Unsupported DNS ip_strategy '{other}' (expected ipv4_then_ipv6, ipv6_then_ipv4, ipv4_only, ipv6_only, or ipv4_and_ipv6)"
        )),
    }
}

fn build_hosts_map(hosts: &std::collections::BTreeMap<String, Vec<String>>) -> Result<Mapping> {
    let mut out = Mapping::new();
    for (raw_host, raw_ips) in hosts {
        let host = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        if host.contains('*') || host.parse::<IpAddr>().is_ok() {
            return Err(anyhow!(
                "Invalid static DNS host '{host}' (must be an exact ASCII/punycode hostname without wildcards)"
            ));
        }
        let mut ips = Vec::new();
        for raw_ip in raw_ips {
            let trimmed = raw_ip.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: IpAddr = trimmed.parse().with_context(|| {
                format!("Invalid IP '{trimmed}' in static DNS host '{host}'")
            })?;
            if parsed.is_unspecified() {
                return Err(anyhow!(
                    "Static DNS host '{host}' cannot use unspecified IP '{trimmed}'"
                ));
            }
            ips.push(str_val(trimmed));
        }
        if ips.is_empty() {
            return Err(anyhow!(
                "Static DNS host '{host}' must specify at least one valid IP address"
            ));
        }
        insert(&mut out, &host, Value::Sequence(ips));
    }
    Ok(out)
}

fn build_dns_server_value(
    item: &DnsServerItem,
    group_names: &HashSet<String>,
) -> Result<Value> {
    let url = item.url.trim();
    if url.is_empty() {
        return Err(anyhow!("DNS server URL must not be empty"));
    }
    let is_system = url == "system";
    if !is_system
        && !url.starts_with("udp://")
        && !url.starts_with("tcp://")
        && !url.starts_with("tls://")
        && !url.starts_with("https://")
        && !url.starts_with("h3://")
    {
        return Err(anyhow!(
            "Invalid DNS server URL '{url}' (expected system, udp://, tcp://, tls://, https://, or h3://)"
        ));
    }
    let strategy = validate_ip_strategy(&item.ip_strategy)?;
    let server_name = item.server_name.trim();
    let bootstrap_url = item.bootstrap_url.trim();
    let client_chain = item.client_chain.trim();

    if !client_chain.is_empty() && !client_chain.eq_ignore_ascii_case("direct") {
        if is_system || url.starts_with("udp://") || url.starts_with("h3://") {
            return Err(anyhow!(
                "DNS server '{url}': client_chain is only supported for tcp://, tls://, and https:// upstreams"
            ));
        }
        if !group_names.contains(client_chain) {
            return Err(anyhow!(
                "DNS server '{url}' references unknown or disabled outbound group '{client_chain}'"
            ));
        }
    }

    let has_options = strategy.is_some()
        || !server_name.is_empty()
        || !bootstrap_url.is_empty()
        || (!client_chain.is_empty() && !client_chain.eq_ignore_ascii_case("direct"))
        || item.timeout_secs.is_some()
        || item.connect_timeout_secs.is_some()
        || item.attempts.is_some()
        || (is_system && item.native_cache_secs.is_some());

    if !has_options {
        return Ok(str_val(url));
    }

    let mut m = Mapping::new();
    insert(&mut m, "url", str_val(url));
    if let Some(st) = strategy {
        insert(&mut m, "ip_strategy", str_val(st));
    }
    if !server_name.is_empty() && !is_system {
        insert(&mut m, "server_name", str_val(server_name));
    }
    if !bootstrap_url.is_empty() && !is_system {
        insert(&mut m, "bootstrap_url", str_val(bootstrap_url));
    }
    if !client_chain.is_empty() && !client_chain.eq_ignore_ascii_case("direct") {
        insert(&mut m, "client_chain", str_val(client_chain));
    }
    if let Some(t) = item.timeout_secs {
        insert(&mut m, "timeout_secs", num_u64(t as u64));
    }
    if let Some(ct) = item.connect_timeout_secs {
        insert(&mut m, "connect_timeout_secs", num_u64(ct as u64));
    }
    if let Some(att) = item.attempts.filter(|&v| v > 0) {
        insert(&mut m, "attempts", num_u64(att as u64));
    }
    if is_system {
        if let Some(nc) = item.native_cache_secs {
            insert(&mut m, "native_cache_secs", num_u64(nc as u64));
        }
    }
    Ok(Value::Mapping(m))
}

fn build_dns_group_entry(
    g: &DnsGroupRecord,
    group_names: &HashSet<String>,
) -> Result<Value> {
    let mut m = Mapping::new();
    insert(&mut m, "dns_group", str_val(g.name.trim()));
    if !g.hosts.is_empty() {
        let hosts_map = build_hosts_map(&g.hosts)?;
        if !hosts_map.is_empty() {
            insert(&mut m, "hosts", Value::Mapping(hosts_map));
        }
    }
    if g.servers.is_empty() {
        insert(&mut m, "dns_servers", str_val("system"));
    } else {
        let mut seq = Vec::new();
        for s in &g.servers {
            seq.push(build_dns_server_value(s, group_names)?);
        }
        insert(&mut m, "dns_servers", Value::Sequence(seq));
    }
    Ok(Value::Mapping(m))
}

fn build_global_settings_entry(
    data_dir: &Path,
    cg: &CoreGlobalSettings,
    dns_names: &HashSet<String>,
    group_names: &HashSet<String>,
    has_native_remote_rules: bool,
) -> Result<Option<Value>> {
    let mut gs = Mapping::new();

    if let Some(v) = cg.max_connections.filter(|&v| v > 0) {
        insert(&mut gs, "max_connections", num_u64(v));
    }
    if let Some(v) = cg.max_connections_per_ip.filter(|&v| v > 0) {
        insert(&mut gs, "max_connections_per_ip", num_u64(v));
    }
    if let Some(v) = cg.max_streams.filter(|&v| v > 0) {
        insert(&mut gs, "max_streams", num_u64(v));
    }
    if let Some(v) = cg.max_streams_per_connection.filter(|&v| v > 0) {
        if v > 65_535 {
            return Err(anyhow!(
                "global_settings.max_streams_per_connection must be in 1..=65535"
            ));
        }
        insert(&mut gs, "max_streams_per_connection", num_u64(v));
    }
    if let Some(v) = cg.max_udp_destinations.filter(|&v| v > 0) {
        insert(&mut gs, "max_udp_destinations", num_u64(v));
    }
    if let Some(v) = cg.quic_memory_bytes.filter(|&v| v > 0) {
        insert(&mut gs, "quic_memory_bytes", num_u64(v));
    }

    for (name, opt, min, max) in [
        ("quic_receive_window", cg.quic_receive_window, 65_536u64, 64 << 20),
        ("quic_send_window", cg.quic_send_window, 65_536u64, 64 << 20),
        ("quic_stream_window", cg.quic_stream_window, 16_384u64, 64 << 20),
        (
            "quic_dns_memory_bytes",
            cg.quic_dns_memory_bytes,
            1 << 20,
            1 << 30,
        ),
        ("quic_socket_buffer", cg.quic_socket_buffer, 65_536u64, 16 << 20),
        ("reload_grace_secs", cg.reload_grace_secs, 0u64, 86_400),
    ] {
        if let Some(v) = opt {
            if !(min..=max).contains(&v) {
                return Err(anyhow!(
                    "global_settings.{name} must be in {min}..={max}"
                ));
            }
            insert(&mut gs, name, num_u64(v));
        }
    }

    if cg.ntp_enabled {
        let raw_server = cg.ntp_server.trim();
        if raw_server.is_empty() {
            return Err(anyhow!("NTP server address is required when NTP is enabled"));
        }
        let server = if raw_server.contains(':') {
            raw_server.to_string()
        } else {
            format!("{raw_server}:123")
        };
        let mut ntp = Mapping::new();
        insert(&mut ntp, "server", str_val(&server));
        insert(
            &mut ntp,
            "interval_secs",
            num_u64(cg.ntp_interval_secs.clamp(60, 86_400)),
        );
        insert(
            &mut ntp,
            "timeout_secs",
            num_u64(cg.ntp_timeout_secs.clamp(1, 30)),
        );
        insert(&mut gs, "ntp", Value::Mapping(ntp));
    }

    // Default DNS
    let mut default_dns = Mapping::new();
    let dns_grp = cg.default_dns_group.trim();
    if !dns_grp.is_empty() {
        if !dns_names.contains(dns_grp) {
            return Err(anyhow!(
                "global_settings.default_dns references unknown or disabled DNS group '{dns_grp}'"
            ));
        }
        insert(&mut default_dns, "servers", str_val(dns_grp));
    } else if !cg.default_dns_servers.is_empty() {
        let mut seq = Vec::new();
        for s in &cg.default_dns_servers {
            seq.push(build_dns_server_value(s, group_names)?);
        }
        insert(&mut default_dns, "servers", Value::Sequence(seq));
    } else if let Some(st) = validate_ip_strategy(&cg.default_dns_ip_strategy)? {
        let mut sys = Mapping::new();
        insert(&mut sys, "url", str_val("system"));
        insert(&mut sys, "ip_strategy", str_val(st));
        insert(
            &mut default_dns,
            "servers",
            Value::Sequence(vec![Value::Mapping(sys)]),
        );
    }
    if !cg.default_dns_hosts.is_empty() {
        let hosts_map = build_hosts_map(&cg.default_dns_hosts)?;
        if !hosts_map.is_empty() {
            insert(&mut default_dns, "hosts", Value::Mapping(hosts_map));
        }
    }
    if !default_dns.is_empty() {
        insert(&mut gs, "default_dns", Value::Mapping(default_dns));
    }

    // Optional native rule_cache_dir (Unix only in shoes)
    let cache_dir_str = if !cg.rule_cache_dir.trim().is_empty() {
        Some(cg.rule_cache_dir.trim().to_string())
    } else if has_native_remote_rules && cfg!(unix) {
        let dir = data_dir.join("rule-cache");
        let _ = ensure_private_dir(&dir);
        Some(
            std::path::absolute(&dir)
                .unwrap_or(dir)
                .to_string_lossy()
                .replace('\\', "/"),
        )
    } else {
        None
    };
    if let Some(dir) = cache_dir_str {
        insert(&mut gs, "rule_cache_dir", str_val(&dir));
    }

    if gs.is_empty() {
        Ok(None)
    } else {
        let mut wrapper = Mapping::new();
        insert(&mut wrapper, "global_settings", Value::Mapping(gs));
        Ok(Some(Value::Mapping(wrapper)))
    }
}

fn build_rule_source_group_entry(
    data_dir: &Path,
    g: &RuleSourceGroupRecord,
    group_names: &HashSet<String>,
) -> Result<Value> {
    if g.items.is_empty() {
        return Err(anyhow!(
            "Rule source group '{}' must contain at least one rule source item",
            g.name
        ));
    }
    let mut seq = Vec::new();
    for (idx, item) in g.items.iter().enumerate() {
        let mut rm = Mapping::new();
        if item.source_type == "url" && item.sync_mode == "shoes_native" {
            let url = item.url.trim();
            if url.is_empty() {
                return Err(anyhow!(
                    "Rule source group '{}' item #{idx}: URL is required",
                    g.name
                ));
            }
            insert(&mut rm, "url", str_val(url));
            if !item.update_interval.trim().is_empty() {
                insert(&mut rm, "update_interval", str_val(item.update_interval.trim()));
            }
            let mut dl = Mapping::new();
            let chain = item.download_chain.trim();
            if chain.is_empty() || chain.eq_ignore_ascii_case("direct") {
                insert(&mut dl, "client_chain", str_val("direct"));
            } else if group_names.contains(chain) {
                insert(&mut dl, "client_chain", str_val(chain));
            } else {
                return Err(anyhow!(
                    "Rule source '{}' references unknown or disabled download outbound group '{chain}'",
                    g.name
                ));
            }
            let bs = if item.bootstrap_url.trim().is_empty() {
                "system"
            } else {
                item.bootstrap_url.trim()
            };
            insert(&mut dl, "bootstrap_url", str_val(bs));
            insert(&mut rm, "download", Value::Mapping(dl));
        } else {
            let path = if item.source_type == "local" {
                item.path.trim().replace('\\', "/")
            } else if !item.path.trim().is_empty() {
                item.path.trim().replace('\\', "/")
            } else {
                crate::ops_util::managed_rule_file_path(data_dir, &g.name, idx, item)
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            if path.is_empty() {
                return Err(anyhow!(
                    "Rule source group '{}' item #{idx}: local file path is empty (sync the remote URL first)",
                    g.name
                ));
            }
            insert(&mut rm, "path", str_val(&path));
        }

        if !item.format.trim().is_empty() && item.format.trim() != "auto" {
            insert(&mut rm, "format", str_val(item.format.trim()));
        }
        if !item.behavior.trim().is_empty() {
            insert(&mut rm, "behavior", str_val(item.behavior.trim()));
        }
        if !item.code.trim().is_empty() {
            insert(&mut rm, "code", str_val(item.code.trim()));
        }
        let attrs: Vec<Value> = item
            .attributes
            .iter()
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
            .map(str_val)
            .collect();
        if !attrs.is_empty() {
            insert(&mut rm, "attributes", Value::Sequence(attrs));
        }
        seq.push(Value::Mapping(rm));
    }

    let mut out = Mapping::new();
    insert(&mut out, "rule_source_group", str_val(g.name.trim()));
    insert(&mut out, "rules", Value::Sequence(seq));
    Ok(Value::Mapping(out))
}

fn split_items(s: &str) -> Vec<String> {
    s.split([',', '\n', ';'])
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

fn build_rule_group_entry(
    rules: &[&RoutingRuleRecord],
    group_names: &HashSet<String>,
    rule_source_names: &HashSet<String>,
) -> Result<Value> {
    let mut seq = Vec::new();
    let mut has_catch_all = false;

    for r in rules {
        if r.match_type == "raw_yaml" {
            let raw: Value = serde_yaml::from_str(&r.match_value)
                .with_context(|| format!("invalid raw_yaml in routing rule '{}'", r.remark))?;
            seq.push(raw);
            continue;
        }

        let mut rm = Mapping::new();
        match r.match_type.as_str() {
            "any" => {
                has_catch_all = true;
                let mut cond = Mapping::new();
                insert(&mut cond, "any_destination", bool_val(true));
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            "rule_source_group" => {
                let target = r.match_value.trim();
                if target.is_empty() {
                    continue;
                }
                if !rule_source_names.contains(target) {
                    return Err(anyhow!(
                        "Routing rule '{}' references unknown or disabled rule_source_group '{target}'",
                        r.remark
                    ));
                }
                let mut cond = Mapping::new();
                insert(&mut cond, "rule_source_group", str_val(target));
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            "domain" | "domain_suffix" | "domain_keyword" | "ip_cidr" => {
                let list = split_items(&r.match_value);
                if list.is_empty() {
                    continue;
                }
                let mut cond = Mapping::new();
                insert(
                    &mut cond,
                    r.match_type.as_str(),
                    Value::Sequence(list.into_iter().map(|v| str_val(&v)).collect()),
                );
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            "network" => {
                let list: Vec<String> = split_items(&r.match_value)
                    .into_iter()
                    .map(|v| v.to_ascii_lowercase())
                    .filter(|v| matches!(v.as_str(), "tcp" | "udp"))
                    .collect();
                if list.is_empty() {
                    continue;
                }
                let mut cond = Mapping::new();
                insert(
                    &mut cond,
                    "network",
                    Value::Sequence(list.into_iter().map(|v| str_val(&v)).collect()),
                );
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            "destination_port" => {
                let ports: Vec<Value> = split_items(&r.match_value)
                    .into_iter()
                    .filter_map(|p| p.parse::<u64>().ok().map(num_u64))
                    .collect();
                if ports.is_empty() {
                    continue;
                }
                let mut cond = Mapping::new();
                insert(&mut cond, "destination_port", Value::Sequence(ports));
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            "udp_stun" => {
                let mut net = Mapping::new();
                insert(&mut net, "network", str_val("udp"));
                let mut proto = Mapping::new();
                insert(
                    &mut proto,
                    "protocol",
                    Value::Sequence(vec![str_val("stun"), str_val("dtls")]),
                );
                let mut cond = Mapping::new();
                insert(
                    &mut cond,
                    "all",
                    Value::Sequence(vec![Value::Mapping(net), Value::Mapping(proto)]),
                );
                insert(&mut rm, "conditions", Value::Mapping(cond));
            }
            _ => {
                // "masks" (CIDR or hostname masks)
                let list = split_items(&r.match_value);
                if list.is_empty() {
                    continue;
                }
                if list.iter().any(|m| m == "0.0.0.0/0") {
                    has_catch_all = true;
                }
                insert(
                    &mut rm,
                    "masks",
                    Value::Sequence(list.into_iter().map(|v| str_val(&v)).collect()),
                );
            }
        }

        if r.no_resolve {
            insert(&mut rm, "no_resolve", bool_val(true));
        }

        if r.action == "block" {
            insert(&mut rm, "action", str_val("block"));
        } else {
            insert(&mut rm, "action", str_val("allow"));
            if !r.override_address.trim().is_empty() {
                insert(
                    &mut rm,
                    "override_address",
                    str_val(r.override_address.trim()),
                );
            }
            apply_outbound_to_rule(&mut rm, r.outbound.trim(), group_names)?;
        }
        seq.push(Value::Mapping(rm));
    }

    // Append default allow-direct fallback unless user explicitly added a catch-all rule
    if !has_catch_all {
        let mut fallback = Mapping::new();
        let mut cond = Mapping::new();
        insert(&mut cond, "any_destination", bool_val(true));
        insert(&mut fallback, "conditions", Value::Mapping(cond));
        insert(&mut fallback, "action", str_val("allow"));
        apply_outbound_to_rule(&mut fallback, "direct", group_names)?;
        seq.push(Value::Mapping(fallback));
    }

    let mut group_map = Mapping::new();
    insert(&mut group_map, "rule_group", str_val("panel-routing"));
    insert(&mut group_map, "rules", Value::Sequence(seq));
    Ok(Value::Mapping(group_map))
}

fn apply_outbound_to_rule(
    rule_map: &mut Mapping,
    outbound: &str,
    group_names: &HashSet<String>,
) -> Result<()> {
    if outbound.is_empty() || outbound.eq_ignore_ascii_case("direct") {
        let mut p = Mapping::new();
        insert(&mut p, "type", str_val("direct"));
        let mut cc = Mapping::new();
        insert(&mut cc, "protocol", Value::Mapping(p));
        insert(rule_map, "client_chain", Value::Mapping(cc));
    } else if group_names.contains(outbound) {
        insert(rule_map, "client_chain", str_val(outbound));
    } else {
        return Err(anyhow!(
            "Routing rule references unknown or disabled outbound group '{outbound}'"
        ));
    }
    Ok(())
}

/// Validates and normalizes an inbound port range string (e.g. `"20000-20100"` or `"20000,20010-20020"`),
/// ensuring the primary `port` is included and total expanded ports stay within safe bounds.
pub fn normalize_port_range_spec(port: u16, raw: &str) -> Result<Option<String>> {
    let parts: Vec<_> = parse_port_ranges(port, raw)?.into_iter().map(|(start, end)| {
        if start == end { start.to_string() } else { format!("{start}-{end}") }
    }).collect();
    Ok((!parts.is_empty()).then(|| parts.join(",")))
}

pub(crate) fn parse_port_ranges(port: u16, raw: &str) -> Result<Vec<(u16, u16)>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    let mut total_ports: usize = 0;
    let mut includes_primary = false;

    for token in trimmed.split([',', ';', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = token.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .with_context(|| format!("Invalid port range start in '{token}'"))?;
            let end: u16 = b
                .trim()
                .parse()
                .with_context(|| format!("Invalid port range end in '{token}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(anyhow!(
                    "Invalid port range '{token}': ports must be in 1..=65535 with start <= end"
                ));
            }
            let count = usize::from(end - start) + 1;
            total_ports = total_ports.saturating_add(count);
            if port >= start && port <= end {
                includes_primary = true;
            }
            parts.push((start, end));
        } else {
            let p: u16 = token
                .parse()
                .with_context(|| format!("Invalid port number '{token}' in port_range"))?;
            if p == 0 {
                return Err(anyhow!("Port 0 is invalid in port_range"));
            }
            total_ports = total_ports.saturating_add(1);
            if p == port {
                includes_primary = true;
            }
            parts.push((p, p));
        }
    }

    if parts.is_empty() {
        return Ok(parts);
    }
    if !includes_primary {
        parts.insert(0, (port, port));
        total_ports = total_ports.saturating_add(1);
    }
    if total_ports > 2048 {
        return Err(anyhow!(
            "port_range expands to {total_ports} ports (maximum supported per inbound is 2048)"
        ));
    }
    Ok(parts)
}

fn build_rules_value_opt(
    rules_ref: &str,
    has_panel_routing: bool,
    group_names: &HashSet<String>,
    is_override: bool,
) -> Option<Value> {
    let rref = rules_ref.trim();
    if rref.eq_ignore_ascii_case("direct") {
        if is_override {
            let mut r = Mapping::new();
            insert(&mut r, "masks", str_val("0.0.0.0/0"));
            insert(&mut r, "action", str_val("allow"));
            let mut p = Mapping::new();
            insert(&mut p, "type", str_val("direct"));
            let mut cc = Mapping::new();
            insert(&mut cc, "protocol", Value::Mapping(p));
            insert(&mut r, "client_chain", Value::Mapping(cc));
            Some(Value::Sequence(vec![Value::Mapping(r)]))
        } else {
            None
        }
    } else if rref.eq_ignore_ascii_case("block") {
        let mut cond = Mapping::new();
        insert(&mut cond, "any_destination", bool_val(true));
        let mut r = Mapping::new();
        insert(&mut r, "conditions", Value::Mapping(cond));
        insert(&mut r, "action", str_val("block"));
        Some(Value::Sequence(vec![Value::Mapping(r)]))
    } else if !rref.is_empty() {
        if group_names.contains(rref) {
            let mut r = Mapping::new();
            insert(&mut r, "masks", str_val("0.0.0.0/0"));
            insert(&mut r, "action", str_val("allow"));
            insert(&mut r, "client_chain", str_val(rref));
            Some(Value::Sequence(vec![Value::Mapping(r)]))
        } else {
            Some(str_val(rref))
        }
    } else if !is_override && has_panel_routing {
        Some(str_val("panel-routing"))
    } else {
        None
    }
}

fn build_wireguard_server_entry(
    ib: &Inbound,
    enabled_clients: &[&ClientRecord],
    has_panel_routing: bool,
    group_names: &HashSet<String>,
    dns_names: &HashSet<String>,
) -> Result<Option<Value>> {
    if enabled_clients.is_empty() {
        return Ok(None);
    }
    let ps = &ib.protocol_settings;
    let ss = &ib.stream_settings;
    if ss.sudoku.enabled {
        return Err(anyhow!(
            "Sudoku TCP mask cannot be enabled on WireGuard inbound"
        ));
    }
    if !ps.port_range.trim().is_empty() {
        return Err(anyhow!(
            "WireGuard server inbound does not support port ranges in shoes"
        ));
    }
    let priv_key = ps.wg_server_private_key.trim();
    if priv_key.is_empty() {
        return Err(anyhow!("WireGuard server inbound requires private_key"));
    }
    let addrs: Vec<String> = if ps.wg_server_addresses.is_empty() {
        vec!["10.77.0.1/32".to_string(), "fd77::1/128".to_string()]
    } else {
        ps.wg_server_addresses
            .iter()
            .flat_map(|s| split_items(s))
            .collect()
    };
    if addrs.is_empty() {
        return Err(anyhow!(
            "WireGuard server inbound requires at least one tunnel address (e.g. 10.77.0.1/32)"
        ));
    }

    let mut peers_seq = Vec::new();
    for c in enabled_clients {
        let peer_pub = if !c.wg_public_key.trim().is_empty() {
            c.wg_public_key.trim().to_string()
        } else if !c.wg_private_key.trim().is_empty() {
            crate::crypto_util::derive_wireguard_public_key(&c.wg_private_key)?
        } else {
            return Err(anyhow!(
                "WireGuard peer '{}' requires public_key (or private_key)",
                c.name
            ));
        };
        let allowed: Vec<String> = split_items(&c.wg_allowed_ips);
        if allowed.is_empty() {
            return Err(anyhow!(
                "WireGuard peer '{}' requires allowed_ips (e.g. 10.77.0.2/32)",
                c.name
            ));
        }
        let mut pm = Mapping::new();
        insert(&mut pm, "public_key", str_val(&peer_pub));
        if !c.wg_preshared_key.trim().is_empty() {
            insert(&mut pm, "pre_shared_key", str_val(c.wg_preshared_key.trim()));
        }
        insert(
            &mut pm,
            "allowed_ips",
            Value::Sequence(allowed.into_iter().map(|a| str_val(&a)).collect()),
        );
        if c.wg_keepalive > 0 {
            insert(&mut pm, "persistent_keepalive", num_u64(c.wg_keepalive as u64));
        }
        peers_seq.push(Value::Mapping(pm));
    }

    let mut wg = Mapping::new();
    insert(&mut wg, "type", str_val("wireguard"));
    insert(&mut wg, "wireguard_name", str_val(&ib.tag));
    insert(&mut wg, "private_key", str_val(priv_key));
    insert(
        &mut wg,
        "addresses",
        Value::Sequence(addrs.into_iter().map(|a| str_val(&a)).collect()),
    );
    insert(&mut wg, "peers", Value::Sequence(peers_seq));
    if ps.wg_mtu > 0 {
        if !(1280..=1420).contains(&ps.wg_mtu) {
            return Err(anyhow!("WireGuard server MTU must be between 1280 and 1420"));
        }
        insert(&mut wg, "mtu", num_u64(ps.wg_mtu as u64));
    }
    if !ps.wg_bind_interface.trim().is_empty() {
        insert(&mut wg, "bind_interface", str_val(ps.wg_bind_interface.trim()));
    }
    if ps.wg_tcp_buffer_size.is_some() || ps.wg_tcp_memory_bytes.is_some() {
        let mut rl = Mapping::new();
        if let Some(buf) = ps.wg_tcp_buffer_size.filter(|&v| v > 0) {
            insert(&mut rl, "tcp_buffer_size", num_u64(buf as u64));
        }
        if let Some(mem) = ps.wg_tcp_memory_bytes.filter(|&v| v > 0) {
            insert(&mut rl, "tcp_memory_bytes", num_u64(mem));
        }
        if !rl.is_empty() {
            insert(&mut wg, "resource_limits", Value::Mapping(rl));
        }
    }

    let mut server = Mapping::new();
    insert(&mut server, "name", str_val(&ib.tag));
    let bind_ip = if ib.listen.trim().is_empty() {
        "0.0.0.0"
    } else {
        ib.listen.trim()
    };
    let bind_addr = if bind_ip.contains(':') && !bind_ip.starts_with('[') {
        format!("[{bind_ip}]:{}", ib.port)
    } else {
        format!("{bind_ip}:{}", ib.port)
    };
    insert(&mut server, "address", str_val(&bind_addr));
    insert(&mut server, "transport", str_val("udp"));
    if ps.sniff {
        insert(&mut server, "sniff", bool_val(true));
    }
    insert(&mut server, "protocol", Value::Mapping(wg));

    // WireGuard server strictly requires explicit non-empty top-level `rules`.
    let rref = ps.rules_ref.trim();
    if rref.is_empty() && has_panel_routing && !ps.wg_block_private {
        insert(&mut server, "rules", str_val("panel-routing"));
    } else {
        let mut rules_seq: Vec<Value> = Vec::new();
        if ps.wg_block_private {
            let mut blk = Mapping::new();
            insert(
                &mut blk,
                "masks",
                Value::Sequence(vec![
                    str_val("127.0.0.0/8"),
                    str_val("::1/128"),
                    str_val("169.254.0.0/16"),
                    str_val("fe80::/10"),
                ]),
            );
            insert(&mut blk, "action", str_val("block"));
            rules_seq.push(Value::Mapping(blk));
        }
        if rref.eq_ignore_ascii_case("block") {
            let mut blk = Mapping::new();
            insert(
                &mut blk,
                "masks",
                Value::Sequence(vec![str_val("0.0.0.0/0"), str_val("::/0")]),
            );
            insert(&mut blk, "action", str_val("block"));
            rules_seq.push(Value::Mapping(blk));
        } else if !rref.is_empty() && !rref.eq_ignore_ascii_case("direct") {
            if group_names.contains(rref) {
                let mut alw = Mapping::new();
                insert(
                    &mut alw,
                    "masks",
                    Value::Sequence(vec![str_val("0.0.0.0/0"), str_val("::/0")]),
                );
                insert(&mut alw, "action", str_val("allow"));
                insert(&mut alw, "client_chain", str_val(rref));
                rules_seq.push(Value::Mapping(alw));
            } else {
                rules_seq.push(str_val(rref));
            }
        } else if has_panel_routing {
            rules_seq.push(str_val("panel-routing"));
        } else {
            let mut alw = Mapping::new();
            insert(
                &mut alw,
                "masks",
                Value::Sequence(vec![str_val("0.0.0.0/0"), str_val("::/0")]),
            );
            insert(&mut alw, "action", str_val("allow"));
            rules_seq.push(Value::Mapping(alw));
        }
        insert(&mut server, "rules", Value::Sequence(rules_seq));
    }

    let dref = ps.dns_group.trim();
    if dref == "__system__" {
        insert(&mut server, "dns", Value::Mapping(Mapping::new()));
    } else if !dref.is_empty() {
        if !dns_names.contains(dref) {
            return Err(anyhow!(
                "Inbound references unknown or disabled DNS group '{dref}'"
            ));
        }
        let mut dm = Mapping::new();
        insert(&mut dm, "servers", str_val(dref));
        insert(&mut server, "dns", Value::Mapping(dm));
    }

    Ok(Some(Value::Mapping(server)))
}

fn build_transported_inner_protocol(
    ib: &Inbound,
    enabled_clients: &[&ClientRecord],
) -> Result<Value> {
    let primary = enabled_clients.first().copied();
    let ps = &ib.protocol_settings;
    let ss = &ib.stream_settings;
    let has_vless_enc = ib.has_vless_native_encryption();

    if ss.h2mux.enabled && ib.has_vless_vision() {
        return Err(anyhow!(
            "VLESS Vision cannot be enabled together with H2Mux multiplexing"
        ));
    }

    let mut inner = Mapping::new();
    match ib.protocol.as_str() {
        "vless" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("vless"));
            insert(&mut inner, "user_id", str_val(c.uuid.trim()));
            if has_vless_enc {
                if !ps.fallback.trim().is_empty() {
                    return Err(anyhow!(
                        "VLESS native encryption (decryption) cannot be combined with fallback"
                    ));
                }
                insert(&mut inner, "decryption", str_val(ps.vless_decryption.trim()));
                if ps.vless_native_vision {
                    insert(&mut inner, "vision", bool_val(true));
                }
            }
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
            if !has_vless_enc && !ps.fallback.trim().is_empty() {
                insert(&mut inner, "fallback", str_val(ps.fallback.trim()));
            }
        }
        "portforward" => {
            let targets: Vec<String> = ps
                .forward_targets
                .iter()
                .flat_map(|s| split_items(s))
                .collect();
            if targets.is_empty() {
                return Err(anyhow!(
                    "PortForward inbound requires at least one target address (host:port)"
                ));
            }
            insert(&mut inner, "type", str_val("portforward"));
            insert(
                &mut inner,
                "targets",
                Value::Sequence(targets.into_iter().map(|t| str_val(&t)).collect()),
            );
        }
        "vmess" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("vmess"));
            let cipher = match ps.cipher.trim() {
                "" | "auto" => "any",
                other => other,
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "user_id", str_val(c.uuid.trim()));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        "trojan" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("trojan"));
            insert(&mut inner, "password", str_val(c.password.trim()));
        }
        "shadowsocks" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("shadowsocks"));
            let cipher = if ps.cipher.trim().is_empty() {
                "2022-blake3-aes-256-gcm"
            } else if ps.cipher.trim() == "2022-blake3-chacha20-ietf-poly1305" {
                "2022-blake3-chacha20-poly1305"
            } else {
                ps.cipher.trim()
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "password", str_val(c.password.trim()));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        "hysteria2" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("hysteria2"));
            insert(&mut inner, "password", str_val(c.password.trim()));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        "tuic" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("tuic"));
            insert(&mut inner, "uuid", str_val(c.uuid.trim()));
            insert(&mut inner, "password", str_val(c.password.trim()));
            if ps.zero_rtt_handshake {
                insert(&mut inner, "zero_rtt_handshake", bool_val(true));
            }
        }
        "anytls" => {
            if !matches!(ss.security.as_str(), "tls" | "reality") {
                return Err(anyhow!("AnyTLS requires TLS or Reality security"));
            }
            insert(&mut inner, "type", str_val("anytls"));
            let users: Vec<Value> = enabled_clients
                .iter()
                .map(|c| {
                    let mut u = Mapping::new();
                    if !c.name.trim().is_empty() {
                        insert(&mut u, "name", str_val(c.name.trim()));
                    }
                    insert(&mut u, "password", str_val(c.password.trim()));
                    Value::Mapping(u)
                })
                .collect();
            insert(&mut inner, "users", Value::Sequence(users));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
            if !ps.padding_scheme.is_empty() {
                insert(
                    &mut inner,
                    "padding_scheme",
                    Value::Sequence(ps.padding_scheme.iter().map(|s| str_val(s)).collect()),
                );
            }
            if !ps.fallback.trim().is_empty() {
                insert(&mut inner, "fallback", str_val(ps.fallback.trim()));
            }
        }
        "naiveproxy" => {
            if !matches!(ss.security.as_str(), "tls" | "reality") {
                return Err(anyhow!("NaiveProxy requires TLS or Reality security"));
            }
            insert(&mut inner, "type", str_val("naiveproxy"));
            let users: Vec<Value> = enabled_clients
                .iter()
                .map(|c| {
                    let mut u = Mapping::new();
                    if !c.name.trim().is_empty() {
                        insert(&mut u, "name", str_val(c.name.trim()));
                    }
                    let uname = if c.username.trim().is_empty() {
                        c.name.trim()
                    } else {
                        c.username.trim()
                    };
                    insert(&mut u, "username", str_val(uname));
                    insert(&mut u, "password", str_val(c.password.trim()));
                    Value::Mapping(u)
                })
                .collect();
            insert(&mut inner, "users", Value::Sequence(users));
            insert(&mut inner, "padding", bool_val(ps.padding));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
            if !ps.fallback.trim().is_empty() {
                insert(&mut inner, "fallback", str_val(ps.fallback.trim()));
            }
        }
        "snell" => {
            let c = primary.unwrap();
            insert(&mut inner, "type", str_val("snell"));
            let cipher = if ps.cipher.trim().is_empty() {
                "aes-128-gcm"
            } else {
                ps.cipher.trim()
            };
            insert(&mut inner, "cipher", str_val(cipher));
            insert(&mut inner, "password", str_val(c.password.trim()));
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        "socks" => {
            insert(&mut inner, "type", str_val("socks"));
            if let Some(c) = primary {
                if !c.username.trim().is_empty() && !c.password.trim().is_empty() {
                    insert(&mut inner, "username", str_val(c.username.trim()));
                    insert(&mut inner, "password", str_val(c.password.trim()));
                }
            }
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        "http" => {
            insert(&mut inner, "type", str_val("http"));
            if let Some(c) = primary {
                if !c.username.trim().is_empty() && !c.password.trim().is_empty() {
                    insert(&mut inner, "username", str_val(c.username.trim()));
                    insert(&mut inner, "password", str_val(c.password.trim()));
                }
            }
        }
        "mixed" => {
            insert(&mut inner, "type", str_val("mixed"));
            if let Some(c) = primary {
                if !c.username.trim().is_empty() && !c.password.trim().is_empty() {
                    insert(&mut inner, "username", str_val(c.username.trim()));
                    insert(&mut inner, "password", str_val(c.password.trim()));
                }
            }
            insert(&mut inner, "udp_enabled", bool_val(ps.udp_enabled));
        }
        other => return Err(anyhow!("Unsupported protocol '{other}'")),
    }

    let is_quic = ib.is_quic();
    let transported = if !is_quic && ss.network == "ws" {
        let mut target = Mapping::new();
        if !ss.ws.path.trim().is_empty() {
            insert(&mut target, "matching_path", str_val(ss.ws.path.trim()));
        }
        let headers = ss.ws.matching_headers();
        if !headers.is_empty() {
            let mut hmap = Mapping::new();
            for (k, v) in headers {
                insert(&mut hmap, &k, str_val(&v));
            }
            insert(&mut target, "matching_headers", Value::Mapping(hmap));
        }
        if ss.ws.max_early_data > 0 {
            insert(
                &mut target,
                "max_early_data",
                num_u64(ss.ws.max_early_data as u64),
            );
            if !ss.ws.early_data_header_name.trim().is_empty() {
                insert(
                    &mut target,
                    "early_data_header_name",
                    str_val(ss.ws.early_data_header_name.trim()),
                );
            }
        }
        insert(&mut target, "protocol", Value::Mapping(inner));

        let mut ws_map = Mapping::new();
        insert(&mut ws_map, "type", str_val("websocket"));
        insert(
            &mut ws_map,
            "targets",
            Value::Sequence(vec![Value::Mapping(target)]),
        );
        Value::Mapping(ws_map)
    } else if ss.network == "xhttp" && !matches!(ib.protocol.as_str(), "hysteria2" | "tuic") {
        let mut xmap = Mapping::new();
        insert(&mut xmap, "type", str_val("xhttp"));
        if !ss.xhttp.path.trim().is_empty() {
            insert(&mut xmap, "path", str_val(ss.xhttp.path.trim()));
        }
        if !ss.xhttp.host.trim().is_empty() {
            insert(&mut xmap, "host", str_val(ss.xhttp.host.trim()));
        }
        let mode = if ss.xhttp.mode.trim().is_empty() {
            "auto"
        } else {
            ss.xhttp.mode.trim()
        };
        insert(&mut xmap, "mode", str_val(mode));
        if !ss.xhttp.headers.is_empty() {
            let mut hmap = Mapping::new();
            for (k, v) in &ss.xhttp.headers {
                insert(&mut hmap, k, str_val(v));
            }
            insert(&mut xmap, "matching_headers", Value::Mapping(hmap));
        }
        insert(&mut xmap, "protocol", Value::Mapping(inner));
        Value::Mapping(xmap)
    } else {
        Value::Mapping(inner)
    };

    Ok(transported)
}

fn build_tls_target_mapping(
    ib: &Inbound,
    transported: Value,
    override_rules: Option<Value>,
) -> Result<Mapping> {
    let ss = &ib.stream_settings;
    let has_vless_enc = ib.has_vless_native_encryption();
    let tls_vision = ib.protocol == "vless" && ss.network == "tcp" && ss.tls.vision && !has_vless_enc;

    let mut target = Mapping::new();
    apply_cert_fields(&mut target, &ss.tls, &ib.remark)?;
    if ib.protocol == "naiveproxy"
        && !ss.tls.alpn.is_empty()
        && !ss.tls.alpn.iter().any(|a| a == "h2")
    {
        return Err(anyhow!("NaiveProxy requires h2 in TLS ALPN"));
    }
    let alpn: Vec<String> = if ib.protocol == "naiveproxy" {
        if ss.tls.alpn.is_empty() || (ss.tls.alpn.len() == 1 && ss.tls.alpn[0] == "h2") {
            vec!["h2".to_string(), "http/1.1".to_string()]
        } else {
            ss.tls.alpn.clone()
        }
    } else if !ss.tls.alpn.is_empty() {
        ss.tls.alpn.clone()
    } else {
        Vec::new()
    };
    if !alpn.is_empty() {
        insert(
            &mut target,
            "alpn_protocols",
            Value::Sequence(alpn.iter().map(|a| str_val(a)).collect()),
        );
    }
    if let Some(kx) = validate_key_exchange_groups(&ss.tls.key_exchange_groups, tls_vision, false)? {
        insert(&mut target, "key_exchange_groups", Value::Sequence(kx));
    }
    apply_mtls_fields(&mut target, &ss.tls.client_ca_certs, &ss.tls.client_fingerprints)?;
    if tls_vision {
        insert(&mut target, "vision", bool_val(true));
    }
    insert(&mut target, "protocol", transported);
    if let Some(ov) = override_rules {
        insert(&mut target, "override_rules", ov);
    }
    Ok(target)
}

fn build_reality_target_mapping(
    ib: &Inbound,
    transported: Value,
    override_rules: Option<Value>,
) -> Result<(String, Mapping)> {
    let ss = &ib.stream_settings;
    let has_vless_enc = ib.has_vless_native_encryption();
    let sni = ss.reality.sni.trim();
    if sni.is_empty() {
        return Err(anyhow!("Reality requires SNI hostname"));
    }
    if ss.reality.private_key.trim().is_empty() {
        return Err(anyhow!("Reality requires private_key"));
    }
    let dest = if ss.reality.dest.trim().is_empty() {
        format!("{sni}:443")
    } else {
        ss.reality.dest.trim().to_string()
    };
    if dest.parse::<std::net::SocketAddr>().is_ok() || dest.parse::<std::net::IpAddr>().is_ok() {
        return Err(anyhow!(
            "REALITY destination must use a DNS hostname, such as example.com:443"
        ));
    }
    let mut rtarget = Mapping::new();
    insert(
        &mut rtarget,
        "private_key",
        str_val(ss.reality.private_key.trim()),
    );
    if !ss.reality.mldsa65_seed.trim().is_empty() {
        insert(
            &mut rtarget,
            "mldsa65_seed",
            str_val(ss.reality.mldsa65_seed.trim()),
        );
    }
    let sids: Vec<Value> = if ss.reality.short_ids.is_empty() {
        vec![str_val("")]
    } else {
        ss.reality
            .short_ids
            .iter()
            .map(|s| str_val(s.trim()))
            .collect()
    };
    insert(&mut rtarget, "short_ids", Value::Sequence(sids));
    insert(&mut rtarget, "dest", str_val(&dest));
    if ib.protocol == "vless" && ss.network == "tcp" && ss.reality.vision && !has_vless_enc {
        insert(&mut rtarget, "vision", bool_val(true));
    }
    insert(&mut rtarget, "protocol", transported);
    if let Some(ov) = override_rules {
        insert(&mut rtarget, "override_rules", ov);
    }
    Ok((sni.to_string(), rtarget))
}

fn build_shadowtls_target_mapping(
    ib: &Inbound,
    transported: Value,
    override_rules: Option<Value>,
) -> Result<(String, Mapping)> {
    let st = &ib.stream_settings.shadowtls;
    let sni = st.sni.trim();
    if sni.is_empty() {
        return Err(anyhow!("ShadowTLS v3 requires an SNI hostname"));
    }
    if st.password.trim().is_empty() {
        return Err(anyhow!("ShadowTLS v3 requires a password"));
    }
    let mut handshake = Mapping::new();
    if st.handshake_mode.trim() == "local" {
        if st.cert_file.trim().is_empty() || st.key_file.trim().is_empty() {
            return Err(anyhow!(
                "ShadowTLS v3 local handshake requires both cert_file and key_file"
            ));
        }
        insert(
            &mut handshake,
            "cert",
            str_val(&st.cert_file.trim().replace('\\', "/")),
        );
        insert(
            &mut handshake,
            "key",
            str_val(&st.key_file.trim().replace('\\', "/")),
        );
        apply_mtls_fields(&mut handshake, &st.client_ca_certs, &st.client_fingerprints)?;
    } else {
        let raw_addr = if st.handshake_addr.trim().is_empty() {
            format!("{sni}:443")
        } else if st.handshake_addr.trim().contains(':') {
            st.handshake_addr.trim().to_string()
        } else {
            format!("{}:443", st.handshake_addr.trim())
        };
        insert(&mut handshake, "address", str_val(&raw_addr));
    }

    let mut st_target = Mapping::new();
    insert(&mut st_target, "password", str_val(st.password.trim()));
    insert(&mut st_target, "handshake", Value::Mapping(handshake));
    insert(&mut st_target, "protocol", transported);
    if let Some(ov) = override_rules {
        insert(&mut st_target, "override_rules", ov);
    }
    Ok((sni.to_string(), st_target))
}

/// Merges multiple TLS / REALITY / ShadowTLS TCP inbounds sharing the same `(listen, port)`
/// into a single `type: tls` listener with SNI-based dispatch and per-target `override_rules`.
fn build_shared_sni_server_entry(
    members: &[&Inbound],
    has_panel_routing: bool,
    group_names: &HashSet<String>,
    dns_names: &HashSet<String>,
    acme_cert_names: &HashSet<String>,
) -> Result<Option<Value>> {
    let mut tls_targets = Mapping::new();
    let mut reality_targets = Mapping::new();
    let mut shadowtls_targets = Mapping::new();
    let mut default_tls_target: Option<Mapping> = None;
    let mut claimed_snis: HashSet<String> = HashSet::new();
    let mut any_sniff = false;
    let mut shared_dns: Option<String> = None;
    let mut primary_tag: Option<String> = None;
    let mut active_count = 0usize;

    for ib in members {
        let enabled_clients: Vec<&ClientRecord> = ib.clients.iter().filter(|c| c.enable).collect();
        if enabled_clients.is_empty()
            && !matches!(ib.protocol.as_str(), "socks" | "http" | "mixed")
        {
            continue;
        }
        active_count += 1;
        if primary_tag.is_none() {
            primary_tag = Some(ib.tag.clone());
        }
        if ib.protocol_settings.sniff {
            any_sniff = true;
        }
        let dref = ib.protocol_settings.dns_group.trim();
        if !dref.is_empty() {
            if let Some(ref prev) = shared_dns {
                if prev != dref {
                    return Err(anyhow!(
                        "Inbounds sharing port {} cannot use conflicting dns_group settings ('{}' vs '{}')",
                        ib.port,
                        prev,
                        dref
                    ));
                }
            } else {
                shared_dns = Some(dref.to_string());
            }
        }

        let transported = build_transported_inner_protocol(ib, &enabled_clients)
            .with_context(|| format!("inbound '{}' (port {})", ib.remark, ib.port))?;
        let ov_rules = build_rules_value_opt(
            &ib.protocol_settings.rules_ref,
            has_panel_routing,
            group_names,
            true,
        );

        match ib.stream_settings.security.as_str() {
            "tls" => {
                let target = build_tls_target_mapping(ib, transported, ov_rules)
                    .with_context(|| format!("inbound '{}'", ib.remark))?;
                let raw_sni = ib.stream_settings.tls.sni.trim();
                let is_ip_sni = !raw_sni.is_empty()
                    && raw_sni.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
                let uses_acme = ib.stream_settings.tls.cert_mode == "source"
                    && acme_cert_names.contains(ib.stream_settings.tls.certificate_source.trim());
                let sni = if is_ip_sni {
                    String::new()
                } else if uses_acme {
                    raw_sni.trim_end_matches('.').to_ascii_lowercase()
                } else {
                    raw_sni.to_string()
                };
                if sni.is_empty() {
                    if default_tls_target.is_some() {
                        return Err(anyhow!(
                            "Port {} already has a default TLS target; specify a unique SNI on inbound '{}'",
                            ib.port,
                            ib.remark
                        ));
                    }
                    default_tls_target = Some(target);
                } else {
                    let key = sni.trim_end_matches('.').to_ascii_lowercase();
                    if !claimed_snis.insert(key) {
                        return Err(anyhow!(
                            "Duplicate SNI '{sni}' on shared port {} (inbound '{}')",
                            ib.port,
                            ib.remark
                        ));
                    }
                    insert(&mut tls_targets, &sni, Value::Mapping(target));
                }
            }
            "reality" => {
                let (sni, rtarget) = build_reality_target_mapping(ib, transported, ov_rules)
                    .with_context(|| format!("inbound '{}'", ib.remark))?;
                let key = sni.trim_end_matches('.').to_ascii_lowercase();
                if !claimed_snis.insert(key) {
                    return Err(anyhow!(
                        "Duplicate SNI '{sni}' on shared port {} (inbound '{}')",
                        ib.port,
                        ib.remark
                    ));
                }
                insert(&mut reality_targets, &sni, Value::Mapping(rtarget));
            }
            "shadowtls" => {
                let (sni, st_target) = build_shadowtls_target_mapping(ib, transported, ov_rules)
                    .with_context(|| format!("inbound '{}'", ib.remark))?;
                let key = sni.trim_end_matches('.').to_ascii_lowercase();
                if !claimed_snis.insert(key) {
                    return Err(anyhow!(
                        "Duplicate SNI '{sni}' on shared port {} (inbound '{}')",
                        ib.port,
                        ib.remark
                    ));
                }
                insert(&mut shadowtls_targets, &sni, Value::Mapping(st_target));
            }
            other => {
                return Err(anyhow!(
                    "Inbound '{}' with security '{other}' cannot share SNI port {}",
                    ib.remark,
                    ib.port
                ));
            }
        }
    }

    if active_count == 0 {
        return Ok(None);
    }

    let first = members[0];
    let bind_ip = if first.listen.trim().is_empty() {
        "0.0.0.0"
    } else {
        first.listen.trim()
    };
    let bind_addr = if bind_ip.contains(':') && !bind_ip.starts_with('[') {
        format!("[{bind_ip}]:{}", first.port)
    } else {
        format!("{bind_ip}:{}", first.port)
    };

    let mut tls_outer = Mapping::new();
    insert(&mut tls_outer, "type", str_val("tls"));
    if !tls_targets.is_empty() {
        insert(&mut tls_outer, "tls_targets", Value::Mapping(tls_targets));
    }
    if let Some(def) = default_tls_target {
        insert(&mut tls_outer, "default_tls_target", Value::Mapping(def));
    }
    if !reality_targets.is_empty() {
        insert(
            &mut tls_outer,
            "reality_targets",
            Value::Mapping(reality_targets),
        );
    }
    if !shadowtls_targets.is_empty() {
        insert(
            &mut tls_outer,
            "shadowtls_targets",
            Value::Mapping(shadowtls_targets),
        );
    }

    let mut server = Mapping::new();
    if let Some(tag) = primary_tag {
        insert(&mut server, "name", str_val(&tag));
    }
    insert(&mut server, "address", str_val(&bind_addr));
    if any_sniff {
        insert(&mut server, "sniff", bool_val(true));
    }
    insert(&mut server, "protocol", Value::Mapping(tls_outer));

    if has_panel_routing {
        insert(&mut server, "rules", str_val("panel-routing"));
    }

    if let Some(dref) = shared_dns {
        if dref == "__system__" {
            insert(&mut server, "dns", Value::Mapping(Mapping::new()));
        } else {
            if !dns_names.contains(&dref) {
                return Err(anyhow!(
                    "Shared SNI port references unknown or disabled DNS group '{dref}'"
                ));
            }
            let mut dm = Mapping::new();
            insert(&mut dm, "servers", str_val(&dref));
            insert(&mut server, "dns", Value::Mapping(dm));
        }
    }

    Ok(Some(Value::Mapping(server)))
}

fn build_inbound_entry(
    data_dir: &Path,
    ib: &Inbound,
    has_panel_routing: bool,
    group_names: &HashSet<String>,
    dns_names: &HashSet<String>,
    acme_cert_names: &HashSet<String>,
) -> Result<Option<Value>> {
    // Allow full raw YAML override for advanced power-user protocols
    if !ib.protocol_settings.raw_override_yaml.trim().is_empty() {
        let mut raw_val: Value = serde_yaml::from_str(&ib.protocol_settings.raw_override_yaml)
            .context("invalid raw_override_yaml")?;
        if let Value::Mapping(ref mut m) = raw_val {
            // Ensure stable dashboard identity for traffic tracking
            insert(m, "name", str_val(&ib.tag));
        }
        return Ok(Some(raw_val));
    }

    let enabled_clients: Vec<&ClientRecord> = ib.clients.iter().filter(|c| c.enable).collect();
    if enabled_clients.is_empty()
        && !matches!(ib.protocol.as_str(), "socks" | "http" | "mixed" | "portforward")
    {
        // No enabled credentials -> do not open listener
        return Ok(None);
    }

    if ib.protocol == "wireguard" {
        return build_wireguard_server_entry(
            ib,
            &enabled_clients,
            has_panel_routing,
            group_names,
            dns_names,
        );
    }

    let ps = &ib.protocol_settings;
    let ss = &ib.stream_settings;
    let is_quic = ib.is_quic();

    if ss.sudoku.enabled && is_quic {
        return Err(anyhow!(
            "Sudoku TCP mask cannot be enabled on QUIC inbound '{}'",
            ib.remark
        ));
    }

    // 1-2. Build innermost protocol + stream transport (WS/XHTTP)
    let transported = build_transported_inner_protocol(ib, &enabled_clients)?;

    // 3. Build outer server record + TLS / Reality / ShadowTLS / QUIC + optional Sudoku mask
    let mut server = Mapping::new();
    insert(&mut server, "name", str_val(&ib.tag));
    let bind_ip = if ib.listen.trim().is_empty() {
        "0.0.0.0"
    } else {
        ib.listen.trim()
    };
    let port_spec = normalize_port_range_spec(ib.port, &ps.port_range)?
        .unwrap_or_else(|| ib.port.to_string());
    let bind_addr = if bind_ip.contains(':') && !bind_ip.starts_with('[') {
        format!("[{bind_ip}]:{port_spec}")
    } else {
        format!("{bind_ip}:{port_spec}")
    };
    insert(&mut server, "address", str_val(&bind_addr));
    if ps.sniff {
        insert(&mut server, "sniff", bool_val(true));
    }

    if is_quic {
        insert(&mut server, "transport", str_val("quic"));
        let mut qmap = Mapping::new();
        if ib.uses_auto_quic_cert() {
            let dir = auto_quic_cert_dir(data_dir);
            insert(
                &mut qmap,
                "cert",
                str_val(&dir.join("cert.pem").to_string_lossy()),
            );
            insert(
                &mut qmap,
                "key",
                str_val(&dir.join("key.pem").to_string_lossy()),
            );
        } else {
            apply_cert_fields(&mut qmap, &ss.tls, &ib.remark)?;
        }
        let q_alpn: Vec<String> = if !ss.tls.alpn.is_empty() {
            ss.tls.alpn.clone()
        } else {
            vec!["h3".to_string()]
        };
        insert(
            &mut qmap,
            "alpn_protocols",
            Value::Sequence(q_alpn.iter().map(|a| str_val(a)).collect()),
        );
        if let Some(kx) = validate_key_exchange_groups(
            &ss.tls.key_exchange_groups,
            false,
            ib.protocol == "tuic" && ps.zero_rtt_handshake,
        )? {
            insert(&mut qmap, "key_exchange_groups", Value::Sequence(kx));
        }
        apply_mtls_fields(&mut qmap, &ss.tls.client_ca_certs, &ss.tls.client_fingerprints)?;
        insert(&mut server, "quic_settings", Value::Mapping(qmap));
        insert(&mut server, "protocol", transported);
    } else {
        let outer_proto = if ss.security == "tls" {
            let target = build_tls_target_mapping(ib, transported, None)?;
            let mut tls_outer = Mapping::new();
            insert(&mut tls_outer, "type", str_val("tls"));
            let raw_sni = ss.tls.sni.trim();
            let is_ip_sni = !raw_sni.is_empty()
                && raw_sni.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
            let uses_acme = ss.tls.cert_mode == "source"
                && acme_cert_names.contains(ss.tls.certificate_source.trim());
            let sni = if is_ip_sni {
                String::new()
            } else if uses_acme {
                raw_sni.trim_end_matches('.').to_ascii_lowercase()
            } else {
                raw_sni.to_string()
            };
            if !sni.is_empty() && !ss.tls.allow_any_sni {
                let mut targets = Mapping::new();
                insert(&mut targets, &sni, Value::Mapping(target));
                insert(&mut tls_outer, "tls_targets", Value::Mapping(targets));
            } else if !sni.is_empty() && ss.tls.allow_any_sni {
                let mut targets = Mapping::new();
                insert(&mut targets, &sni, Value::Mapping(target.clone()));
                insert(&mut tls_outer, "tls_targets", Value::Mapping(targets));
                insert(&mut tls_outer, "default_tls_target", Value::Mapping(target));
            } else {
                insert(&mut tls_outer, "default_tls_target", Value::Mapping(target));
            }
            Value::Mapping(tls_outer)
        } else if ss.security == "reality" {
            let (sni, rtarget) = build_reality_target_mapping(ib, transported, None)?;
            let mut targets = Mapping::new();
            insert(&mut targets, &sni, Value::Mapping(rtarget));
            let mut tls_outer = Mapping::new();
            insert(&mut tls_outer, "type", str_val("tls"));
            insert(&mut tls_outer, "reality_targets", Value::Mapping(targets));
            Value::Mapping(tls_outer)
        } else if ss.security == "shadowtls" {
            let (sni, st_target) = build_shadowtls_target_mapping(ib, transported, None)?;
            let mut targets = Mapping::new();
            insert(&mut targets, &sni, Value::Mapping(st_target));
            let mut tls_outer = Mapping::new();
            insert(&mut tls_outer, "type", str_val("tls"));
            insert(&mut tls_outer, "shadowtls_targets", Value::Mapping(targets));
            Value::Mapping(tls_outer)
        } else {
            transported
        };

        let final_proto = wrap_sudoku_mask(outer_proto, &ss.sudoku)?;
        insert(&mut server, "protocol", final_proto);
    }

    // 4. Attach routing rules if configured
    if let Some(rules_val) = build_rules_value_opt(&ps.rules_ref, has_panel_routing, group_names, false)
    {
        insert(&mut server, "rules", rules_val);
    }

    // 4b. Attach per-inbound DNS override if configured
    let dref = ps.dns_group.trim();
    if dref == "__system__" {
        insert(&mut server, "dns", Value::Mapping(Mapping::new()));
    } else if !dref.is_empty() {
        if !dns_names.contains(dref) {
            return Err(anyhow!(
                "Inbound references unknown or disabled DNS group '{dref}'"
            ));
        }
        let mut dm = Mapping::new();
        insert(&mut dm, "servers", str_val(dref));
        insert(&mut server, "dns", Value::Mapping(dm));
    }

    Ok(Some(Value::Mapping(server)))
}

fn apply_cert_fields(
    target: &mut Mapping,
    tls: &crate::models::TlsSettings,
    remark: &str,
) -> Result<()> {
    if tls.cert_mode == "source" && !tls.certificate_source.trim().is_empty() {
        insert(
            target,
            "certificate_source",
            str_val(tls.certificate_source.trim()),
        );
    } else if !tls.cert_file.trim().is_empty() && !tls.key_file.trim().is_empty() {
        insert(
            target,
            "cert",
            str_val(&tls.cert_file.trim().replace('\\', "/")),
        );
        insert(
            target,
            "key",
            str_val(&tls.key_file.trim().replace('\\', "/")),
        );
    } else if !tls.certificate_source.trim().is_empty() {
        insert(
            target,
            "certificate_source",
            str_val(tls.certificate_source.trim()),
        );
    } else {
        return Err(anyhow!(
            "Inbound '{remark}' uses TLS/QUIC and requires either a Certificate Source or cert/key file paths"
        ));
    }
    Ok(())
}

fn auto_quic_cert_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("certs").join("auto-quic")
}

fn ensure_auto_quic_cert(data_dir: &Path) -> Result<()> {
    use std::io::Write;
    let dir = auto_quic_cert_dir(data_dir);
    let complete = || dir.join("cert.pem").is_file() && dir.join("key.pem").is_file();
    if dir.exists() {
        anyhow::ensure!(complete(), "Incomplete automatic QUIC certificate in {}", dir.display());
        return Ok(());
    }
    let parent = data_dir.join("certs");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let (cert, key) = crate::crypto_util::generate_self_signed_cert(&[])?;
    let mut private = tempfile::NamedTempFile::new_in(staging.path())?;
    private.write_all(key.as_bytes())?;
    drop(private.persist(staging.path().join("key.pem"))?);
    std::fs::write(staging.path().join("cert.pem"), cert)?;
    if let Err(e) = std::fs::rename(staging.path(), &dir) {
        if !complete() {
            return Err(e).context("Could not install automatic QUIC certificate");
        }
    }
    Ok(())
}

/// Render and check the candidate without modifying the active configuration.
pub async fn validated_config(db: &Database, settings: &PanelSettings) -> Result<String> {
    let certs = db.list_certificates()?;
    let dns_groups = db.list_dns_groups()?;
    let rule_sources = db.list_rule_source_groups()?;
    let groups = db.list_outbound_groups()?;
    let rules = db.list_routing_rules()?;
    let inbounds = db.list_inbounds()?;

    let yaml = build_shoes_yaml_full(
        &db.data_dir,
        settings,
        &certs,
        &dns_groups,
        &rule_sources,
        &groups,
        &rules,
        &inbounds,
    )?;

    if inbounds.iter().any(|ib| ib.enable && ib.uses_auto_quic_cert()
        && ib.protocol_settings.raw_override_yaml.trim().is_empty()
        && ib.clients.iter().any(|c| c.enable)) {
        ensure_auto_quic_cert(&db.data_dir)?;
    }

    let cfg_path = Path::new(settings.shoes_config_path.trim());
    let parent = cfg_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let bin_path = Path::new(settings.shoes_bin_path.trim());
    if bin_path.is_file() {
        use std::io::Write;
        let mut tmp = tempfile::Builder::new()
            .prefix(".shoes-check-")
            .suffix(".yaml")
            .tempfile_in(parent)?;
        tmp.write_all(yaml.as_bytes())?;
        let tmp_path = tmp.into_temp_path();
        let output = tokio::process::Command::new(&bin_path)
            .arg("check")
            .arg(tmp_path.as_os_str())
            .output()
            .await
            .with_context(|| format!("failed to execute '{} check'", bin_path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "shoes config validation failed:\n{}{}",
                stderr.trim(),
                if stdout.trim().is_empty() {
                    String::new()
                } else {
                    format!("\n{}", stdout.trim())
                }
            ));
        }
    }

    Ok(yaml)
}

pub async fn sync_and_apply_config(db: &Database, shoes_pid: Option<u32>) -> Result<String> {
    let settings = db.get_settings()?;
    let yaml = validated_config(db, &settings).await?;
    // Preserve the inode for file watchers and Docker bind mounts.
    std::fs::write(&settings.shoes_config_path, &yaml)
        .with_context(|| format!("failed to write config to {}", settings.shoes_config_path))?;

    // Windows uses the core's file watcher. Unix also supports an explicit reload.
    #[cfg(unix)]
    if let Some(pid) = shoes_pid {
        let status = std::process::Command::new("sh")
            .args(["-c", &format!("kill -HUP {pid}")])
            .status()
            .context("failed to signal Shoes to reload")?;
        anyhow::ensure!(
            status.success(),
            "Failed to signal Shoes PID {pid} to reload"
        );
    }
    #[cfg(not(unix))]
    let _ = shoes_pid;
    Ok(yaml)
}

/// Builds a minimal, isolated Shoes YAML configuration for ephemeral egress probing:
/// binds a single authenticated loopback HTTP proxy (`127.0.0.1:<listen_port>`)
/// and routes all destinations through `target_group_name` (optionally pinned to a single
/// member and/or DNS IPv4/IPv6 strategy) without touching the live running Shoes instance.
#[allow(clippy::too_many_arguments)]
pub fn build_egress_probe_yaml(
    listen_port: u16,
    proxy_user: &str,
    proxy_pass: &str,
    target_group_name: &str,
    member_override: Option<&str>,
    ip_strategy_override: Option<&str>,
    settings: &PanelSettings,
    dns_groups: &[DnsGroupRecord],
    outbound_groups: &[OutboundGroupRecord],
) -> Result<String> {
    let target_name = target_group_name.trim();
    if target_name.is_empty() {
        return Err(anyhow!("Target outbound group name must not be empty"));
    }

    let mut target_found = false;
    let mut active_groups: Vec<OutboundGroupRecord> = Vec::new();
    let mut group_names: HashSet<String> = HashSet::new();

    for g in outbound_groups {
        let is_target = g.name.trim() == target_name;
        if !g.enable && !is_target {
            continue;
        }
        let mut cloned = g.clone();
        if is_target {
            target_found = true;
            if let Some(mname) = member_override.map(str::trim).filter(|s| !s.is_empty()) {
                if !cloned.raw_chains_yaml.trim().is_empty() {
                    if cloned.group_type == "selector" {
                        cloned.default_member = mname.to_string();
                    }
                } else {
                    let matched: Vec<_> = cloned
                        .members
                        .iter()
                        .filter(|m| m.name.trim() == mname)
                        .cloned()
                        .collect();
                    if matched.is_empty() {
                        return Err(anyhow!(
                            "Member '{mname}' not found in outbound group '{target_name}'"
                        ));
                    }
                    cloned.members = matched;
                    cloned.group_type = "selector".to_string();
                    cloned.default_member = mname.to_string();
                }
            }
        }
        group_names.insert(cloned.name.trim().to_string());
        active_groups.push(cloned);
    }

    if !target_found {
        return Err(anyhow!("Outbound group '{target_name}' not found"));
    }

    let mut top_entries: Vec<Value> = Vec::new();
    let enabled_dns_names: HashSet<String> = dns_groups
        .iter()
        .filter(|g| g.enable)
        .map(|g| g.name.trim().to_string())
        .collect();

    // Global DNS settings (either forced IPv4/IPv6 strategy override, or inherited from panel settings)
    if let Some(st) = ip_strategy_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let validated = validate_ip_strategy(st)?
            .ok_or_else(|| anyhow!("Invalid ip_strategy override '{st}'"))?;
        let mut sys = Mapping::new();
        insert(&mut sys, "url", str_val("system"));
        insert(&mut sys, "ip_strategy", str_val(validated));
        let mut default_dns = Mapping::new();
        insert(
            &mut default_dns,
            "servers",
            Value::Sequence(vec![Value::Mapping(sys)]),
        );
        if !settings.core_global.default_dns_hosts.is_empty() {
            let hosts_map = build_hosts_map(&settings.core_global.default_dns_hosts)?;
            if !hosts_map.is_empty() {
                insert(&mut default_dns, "hosts", Value::Mapping(hosts_map));
            }
        }
        let mut gs = Mapping::new();
        insert(&mut gs, "default_dns", Value::Mapping(default_dns));
        let mut wrap = Mapping::new();
        insert(&mut wrap, "global_settings", Value::Mapping(gs));
        top_entries.push(Value::Mapping(wrap));
    } else {
        let mut dns_only = CoreGlobalSettings::default();
        dns_only.default_dns_group = settings.core_global.default_dns_group.clone();
        dns_only.default_dns_ip_strategy = settings.core_global.default_dns_ip_strategy.clone();
        dns_only.default_dns_servers = settings.core_global.default_dns_servers.clone();
        dns_only.default_dns_hosts = settings.core_global.default_dns_hosts.clone();
        if let Some(gs_entry) = build_global_settings_entry(
            Path::new("."),
            &dns_only,
            &enabled_dns_names,
            &group_names,
            false,
        )? {
            top_entries.push(gs_entry);
        }
    }

    for g in &active_groups {
        top_entries.push(build_outbound_group_entry(g)?);
    }
    if ip_strategy_override.map(str::trim).unwrap_or("").is_empty() {
        for dg in dns_groups.iter().filter(|g| g.enable) {
            top_entries.push(build_dns_group_entry(dg, &group_names)?);
        }
    }

    // Ephemeral loopback HTTP proxy routing all destinations via target_name
    let mut proto = Mapping::new();
    insert(&mut proto, "type", str_val("http"));
    if !proxy_user.is_empty() || !proxy_pass.is_empty() {
        insert(&mut proto, "username", str_val(proxy_user));
        insert(&mut proto, "password", str_val(proxy_pass));
    }

    let mut cond = Mapping::new();
    insert(&mut cond, "any_destination", bool_val(true));
    let mut rule = Mapping::new();
    insert(&mut rule, "conditions", Value::Mapping(cond));
    insert(&mut rule, "action", str_val("allow"));
    insert(&mut rule, "client_chain", str_val(target_name));

    let mut server = Mapping::new();
    insert(
        &mut server,
        "address",
        str_val(&format!("127.0.0.1:{listen_port}")),
    );
    insert(&mut server, "protocol", Value::Mapping(proto));
    insert(&mut server, "rules", Value::Sequence(vec![Value::Mapping(rule)]));
    top_entries.push(Value::Mapping(server));

    let yaml = serde_yaml::to_string(&top_entries)?;
    Ok(yaml)
}
