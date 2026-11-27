<div align="center">

# ⚡ Shoes Panel (`shoes-ui`)

**A 3x-ui Style Multi-Protocol Web Management Panel for [cfal/shoes](https://github.com/cfal/shoes)**  
*Single-Binary Rust Backend · Embedded Vue 3 + Ant Design Vue 10-Language SPA (with RTL) · Zero-Patch Hot Reload*

[![Release](https://img.shields.io/github/v/release/huangming774/shoes-ui?logo=github)](https://github.com/huangming774/shoes-ui/releases)
[![Build & Release](https://github.com/huangming774/shoes-ui/actions/workflows/release.yml/badge.svg)](https://github.com/huangming774/shoes-ui/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Backend-Rust%20%2B%20Axum-orange.svg)](https://www.rust-lang.org/)
[![Vue](https://img.shields.io/badge/Frontend-Vue%203%20%2B%20Ant%20Design-42b883.svg)](https://vuejs.org/)
[![Core](https://img.shields.io/badge/Powered%20by-cfal%2Fshoes-purple.svg)](https://github.com/cfal/shoes)

**[简体中文](./README.md)** | **English**

</div>

---

> [!NOTE]
> **Unofficial Project Notice**  
> `shoes-ui` (`shoes-panel`) is an **unofficial third-party web control panel** built around the upstream [cfal/shoes](https://github.com/cfal/shoes) proxy core (MIT License). It does not modify or fork `shoes` source code. Please open panel/UI/installer issues in this repository rather than the upstream `cfal/shoes` repository.

---

## Screenshots

![Dashboard Preview](./docs/screenshots/dashboard.png)

| Multi-Protocol Inbounds (VLESS Native Enc / ML-DSA-65 / Port Hopping / ShadowTLS / H2Mux / PortForward) | Outbound Groups (WARP / ShadowTLS / H2Mux) & Live Clash Selector |
| :---: | :---: |
| ![Inbounds Preview](./docs/screenshots/inbounds.png) | ![Routing Outbounds Preview](./docs/screenshots/routing.png) |

| Routing Rules & Remote Rule Sets (GeoIP / GeoSite `.srs`/`.mrs`) | DNS Groups, IPv4/IPv6 Strategy & Streaming Unlock Hosts |
| :---: | :---: |
| ![Routing Rules Preview](./docs/screenshots/rules.png) | ![DNS and Hosts Preview](./docs/screenshots/dns.png) |

| Core Global Limits, QUIC Memory Tuning, Built-in NTP & Online Upgrade | Login (Bilingual & Dark/Light Mode) |
| :---: | :---: |
| ![Settings Global Limits & NTP Preview](./docs/screenshots/settings.png) | ![Login Preview](./docs/screenshots/login.png) |

---

## Key Features

- **Zero-Modification Upstream `shoes` Integration**: Validates every candidate YAML with `shoes check` before atomic replacement (rolling back DB changes on validation failure) and triggers zero-downtime hot reload (`SIGHUP` on Unix).
- **Two-Layer `Inbound -> Clients` Model, Single-Port 443 Multi-SNI Mux, Batch Ops & 3x-ui Migration**:
  - Dedicated port per client (`1 Client = 1 Port`) for single-credential protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC v5, Snell, SOCKS5, HTTP, Mixed) with accurate per-inbound traffic accounting, quotas, expiration dates, monthly auto-reset, and **1-click Dedicated-Port Client Cloning (`+Port`)**.
  - Native multi-user support on a single port for **AnyTLS**, **NaiveProxy**, and **WireGuard Server (Multi-Peer VPN Gateway)**, plus credential-free **PortForward** TCP relays.
  - **Single-Port 443 Multi-SNI Multiplexing (Virtual Host)**: Multiple TCP `TLS`, `REALITY`, and `ShadowTLS v3` inbounds sharing the same `(listen, port)` (e.g., `0.0.0.0:443`) with distinct SNIs automatically merge into a single `type: tls` listener combining `tls_targets`, `reality_targets`, and `shadowtls_targets` with independent per-SNI `override_rules`, coexisting cleanly with **UDP/QUIC 443** (Hysteria2 / TUIC).
  - **Batch Operations & 1-Click Migration (3x-ui / Share URIs)**: Multi-select inbounds to **batch enable, disable, extend expiry** (by days, exact date, or never-expire, with optional client sync & expired-node resurrection), **reset traffic**, or **delete** with a single atomic reload & rollback. Built-in **Migration Importer** parses **3x-ui JSON** (single inbound, array, or `/panel/api/inbounds/list` dump), Xray `config.json`, or plain/Base64 share URIs — automatically splitting multi-client single-user protocols onto consecutive ports, flagging warnings/conflicts, and offering 1-click free-port reassignment.
- **Full Protocol Suite + REALITY Probe Picker + Advanced Security & Obfuscation**:
  - Covers **14 inbound protocols** (including **WireGuard Server**) plus TCP, WebSocket, XHTTP/SplitHTTP, QUIC, and UDP transports with built-in 1-click generators for UUID, Reality X25519 + **post-quantum ML-DSA-65** keypairs, **VLESS Native Encryption (`ML-KEM-768` / `X25519`)**, SS-2022 keys, WireGuard Curve25519 keys, **mTLS client certificates & SHA-256 fingerprints**, and ECDSA self-signed certificates.
  - **1-Click REALITY Destination (Dest / SNI) Probe & Picker**: Performs real **TLS 1.3 + X25519 + ALPN `h2`** handshakes directly from the panel host, measuring TCP/TLS RTT, verifying cert SAN match & expiry, rejecting HelloRetryRequest, and analyzing server flight capacity against upstream `cfal/shoes` rules to report **ML-DSA-65 post-quantum compatibility** — supporting both single-host checks and 1-click concurrent scans across 10 curated candidates.
  - **WireGuard Userspace VPN Server (Multi-Peer Gateway)**: Auto-generates server keys and dual-stack tunnel subnets (`10.77.0.1/32, fd77::1/128`), auto-allocates non-overlapping peer IPs as devices are added, and exports official **WireGuard App QR codes & `.conf` downloads** alongside Shoes, Clash/Mihomo, and sing-box subscriptions.
  - **Hybrid Post-Quantum TLS, mTLS & Sudoku FinalMask**:
    - **Hybrid PQ TLS Key Exchange (`key_exchange_groups`)**: Supports `X25519MLKEM768`, `SecP256r1MLKEM768`, `X25519`, `SecP256r1`, and `SecP384r1` on TLS & QUIC inbounds/outbounds while guarding against hybrid-only + Vision / TUIC 0-RTT conflicts.
    - **mTLS Mutual Certificate Authentication**: Configure `client_ca_certs` and `client_fingerprints` (auto-normalizing `sha256:` prefixes) with a 1-click mTLS client certificate & fingerprint generator.
    - **Sudoku TCP FinalMask**: Wraps outermost TCP streams in Xray-compatible `type: sudoku_mask` (inbound, outbound, and Shoes client YAML) while cleanly omitting unsupported nodes from generic URI / Clash / sing-box subscriptions.
  - **VLESS Native Encryption & REALITY ML-DSA-65**: Supports `ML-KEM-768` / `X25519` native encryption (`native`/`xorpub`/`random`, `0rtt`/`1rtt`) with native Vision (guarding against `fallback`, outer Vision, and H2Mux conflicts), exporting to `vless://`, Shoes client YAML, and Clash/Mihomo while automatically omitting unsupported sing-box nodes. REALITY ML-DSA-65 fields sync to `pqv=` and Shoes `mldsa65_verify`.
  - **Hysteria2 Port Range / Port Hopping**: Supports port ranges (e.g. `20100-20120`) natively in `shoes` listener addresses and exports `mport=`, Shoes `hopping`, Clash `ports` / `hop-interval`, and sing-box `server_ports` / `hop_interval`.
  - **ShadowTLS v3 (Inbound & Outbound)**: Inbound supports both remote camouflage handshake (cert-free) and local certificate handshake; outbound members support ShadowTLS v3 wrapping. Exports cleanly to Shoes, `ss://` (SIP003), Clash/Mihomo, and sing-box paired detour chains.
  - **PortForward Native TCP Relay**: Multi-target round-robin (`targets`) with optional outbound group routing (e.g., forwarding through WARP or a ShadowTLS relay) without polluting proxy subscriptions.
  - **H2Mux Multiplexing**: Supported on both compatible inbounds and outbound group members (preventing conflicts with `VLESS XTLS-Vision` / `ShadowTLS`), synced to **Shoes (`h2mux`)**, **Clash / Mihomo (`smux`)**, and **sing-box (`multiplex`)**.
- **Enhanced Outbound Groups (URI Import / Visual Multi-Hop / WARP), Remote Rule Sets, DNS & Global Limits**:
  - **13-Protocol Outbounds, Share URI Import & Visual Multi-Hop Chains**: Supports full outbound protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, WireGuard, Snell, SOCKS5, HTTP, Direct, Group Ref) with REALITY / TLS / ShadowTLS v3 / WS / XHTTP / mTLS / PQ-KX / Sudoku / H2Mux, **1-click Share URI & Base64 subscription import** into outbound members, and a **visual multi-hop chain builder** (`extra_hops` compiling to named `chain` sequences).
  - **WireGuard Outbound & 1-Click Cloudflare WARP**: Register a free Cloudflare WARP profile in 1 click, import standard WireGuard `.conf` files, generate local Curve25519 keys, and configure high-throughput buffer limits (userspace WireGuard on Linux/Unix, no root/TUN needed).
  - **VPS Egress Quality & Streaming / AI Unlock Diagnostics (Closed-Loop Routing)**: Built directly into the Routing view (plus 1-click check on every Outbound Group row), concurrently compares host **Direct (IPv4/IPv6)** against any outbound group (including WARP or exit relays) via an isolated authenticated loopback `shoes` sidecar with zero downtime. Reports IPv4/IPv6 exit IPs & RTT, ASN/ISP, Cloudflare PoP & `warp` status, and unlock verdicts across **ChatGPT / OpenAI, Claude, Google Gemini, Netflix, Disney+, and YouTube Premium** — surfacing **1-click routing rule recommendations** right in the results matrix.
  - **Remote / Local Rule Sets (`rule_source_group`) & Advanced Routing**: Supports `.srs` (sing-box), `.mrs` (Mihomo), `.dat` (V2Ray GeoIP/GeoSite), and YAML/JSON with 1-click presets (OpenAI, Netflix, Claude, CN, Ads, Private), panel-managed auto-sync (cross-platform + GitHub redirect safe), or Linux native Shoes fetch. Routing rules support `rule_source_group`, `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`, `network`, `destination_port`, `no_resolve`, and `override_address` with 1-click routing templates.
  - **DNS Groups, IPv4/IPv6 Strategy & Static Hosts**: Configure global default DNS (`global_settings.default_dns`) and per-inbound named `dns_group` bindings with DoH / DoT / DoQ / DoH3 / UDP / System upstreams, 5 IPv4/IPv6 strategies (`ipv4_only`, `ipv4_then_ipv6`, etc.), and static unlock `hosts` mappings.
  - **Core Global Limits, QUIC Memory Tuning & Built-in NTP (`global_settings`)**: Configure per-IP connection limits, global connection / stream / UDP destination caps, QUIC memory budget & window sizes (anti-OOM), reload grace period, and built-in NTP clock sync.
- **Share Links, QR Codes, Lightweight Multi-Node Cluster, Aggregated Subscriptions & Rule Templates**:
  - **Lightweight Multi-Node Cluster & Regional Aggregated Subscriptions**: Mount multiple remote `shoes-panel` VPS nodes from any master panel using a dedicated **read-only Cluster API Token** (exports telemetry, enabled proxy nodes, and public cert PEMs only — **never private keys or admin access** — with **1-click JSON Pairing Codes**, live connection testing, and self-loop protection). Monitor unified cluster online status, RTT latency, Shoes core status, CPU/RAM, aggregate live speeds, active connections, and cumulative traffic from one dashboard, and serve **a single aggregated `/sub/<token>` subscription** merging Local + remote VPS nodes (summing `Subscription-Userinfo` headers, supporting `?cluster=0|1` and `?region_groups=0|1`) with automatic **per-region `url-test` / `urltest` groups** (e.g., `🇭🇰 香港`, `🇯🇵 日本`, `🇸🇬 新加坡`, `🇺🇸 美国`) wired directly into `🚀 Proxy` / `proxy` and `streaming` AI/media selectors in **Clash / Mihomo YAML** and **sing-box JSON**.
  - Generates standard client URIs, WireGuard `.conf` files, QR codes, `shoes` client YAML snippets, and `/sub/<token>` subscriptions in **v2rayN Base64**, **Clash / Mihomo YAML**, and **sing-box JSON** formats (auto-detected by User-Agent or `?format=`, auto-filtering incompatible combinations per client core, including `Subscription-Userinfo` headers).
  - **Customizable Clash / sing-box Subscription Rule Templates**: Ships with 4 built-in presets (**Minimal**, **Global Direct**, **Bypass Mainland CN**, and **Streaming & AI Groups** with dedicated `AI`, `Netflix`, `YouTube`, `Telegram`, `Google`, and `Apple` selectors), AdBlock & IPv6 toggles, custom Clash rules/extra proxy-groups YAML, custom sing-box rules (JSON array or Clash-style shorthand lines), per-subscription and `?template=` URL overrides, plus a live preview modal.
- **Dashboard Observability, Traffic Accounting & Quota Enforcement**:
  - **Last-2-Minute Live Charts**: Host CPU/memory utilization and NIC throughput.
  - **Network Health (Linux `/proc`)**: Clearly scoped to either the **Shoes process** (FDs used / soft limit, e.g. `8,200 / 1,048,576`) or **Host** (active TCP congestion control algorithm plus ~1-minute deltas for `ListenOverflows`, TCP `RetransSegs`, and UDP `RcvbufErrors` / `SndbufErrors`).
  - **Shoes Core 24-Hour History**: Minute-level aggregated **Core CPU, resident memory (RSS), active connections, and proxy throughput** persisted in SQLite, with **core start / restart / config reload** events marked as dashed vertical lines and a collapsible timeline list.
  - **30-Day Daily Proxy Traffic & Quota Enforcement**: Polls `shoes` Clash Controller API (`/connections`) every second to persist byte deltas and daily totals to SQLite, automatically disabling expired or over-quota inbounds while terminating active connections.
- **Certificate Center (with Free Public IP HTTPS) & Live Selector**:
  - Supports **Let's Encrypt free public IP certificates** (`shortlived` 6-day profile per RFC 8555 / RFC 8738 with automatic background renewal when `< 48h` remain), domain ACME auto-renewal (HTTP-01 / TLS-ALPN-01 with live ToS metadata sync), PEM uploads, self-signed certs, X.509 expiry inspection, in-use delete protection, and **1-click Panel HTTPS apply with zero-downtime hot reload**.
  - Manage `client_group` (`selector` / `url-test` / `round-robin`) with live Clash API node switching & latency probes.
- **Backup/Restore, Web Operations & Security Hardening**:
  - Embedded Vue 3 SPA via `rust-embed` with zero external runtime dependencies and **10 built-in languages** (简体中文, 繁體中文, English, Русский, فارسی with native RTL layout, 日本語, 한국어, Tiếng Việt, Türkçe, Español), automatic browser locale detection, and synchronized Ant Design component locales.
  - **SQLite Online Backup & 1-Click Restore**: Upload `.db` files directly in the web UI to restore online (with SQLite integrity checks and automatic `pre-restore-*.db` safety snapshots), manage local backup snapshots, and configure **scheduled local + Telegram Bot auto-backups**.
  - **Web UI Operations**: 1-click panel restart, GitHub release update checks, SHA-256 verified **1-click panel online upgrade**, and **1-click `shoes` core upgrade** (with automatic rollback).
  - **Security**: Argon2id password hashing, login brute-force lockout (8 failed attempts -> 5-minute `429` cooldown), `HttpOnly` + automatic `Secure` cookies on HTTPS, username-only rename, default weak-credential banner, and instant dynamic secret base path (e.g., `/secret`).

---

## Quick Start

### Option 1: Linux VPS One-Click Script (`systemd` + `s-ui` CLI Menu)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huangming774/shoes-ui/main/install.sh)
```

Automatically installs the official `shoes` binary and `shoes-panel`, generates random admin credentials (or lets you customize port `54321`, base path, and credentials), **provisions Panel HTTPS automatically via a free Let's Encrypt public IP certificate** (falling back to a self-signed HTTPS certificate if port 80 HTTP-01 validation is unavailable), opens local firewall rules (`ufw` / `firewalld` / `iptables`), enables and verifies the `shoes-panel` systemd service, and installs the `s-ui` management CLI.

For an existing installation, run `sudo bash install.sh --install-cli` from the updated source directory to refresh the menu. In `sudo s-ui`:
- Option `10`: Panel HTTPS certificate manager (free public IP SSL / self-signed HTTPS / clear HTTPS).
- Options `11`, `12`, `16`: Update panel, `shoes` core, or `s-ui` script individually (`17` updates all three).
- Option `13`: Local SQLite backup and 1-click snapshot restore.
- Option `14`: Full uninstall (requires typing `PURGE` before deleting database, certificates, and backups).
- Option `15`: **TCP Congestion Control & Acceleration Manager** — enable **BBRv1 + FQ**, install/switch **BBR Plus (UJX6N)**, **Mod BBR (Tsunami)**, or **PCC / PCC Vivace**, hot-switch available kernel algorithms & qdiscs (`fq` / `fq_codel` / `cake`), apply proxy buffer sysctl tuning, or restore defaults.

### Option 2: Prebuilt Multi-Arch Docker Image (`linux/amd64` & `linux/arm64`)

```bash
docker run -d --name shoes-panel \
  --net=host --restart=unless-stopped \
  -v $(pwd)/data:/etc/shoes-panel \
  ghcr.io/huangming774/shoes-ui:latest
```

Default URL on first start: `http://<SERVER_IP>:54321/` (`admin` / `admin` — change immediately in **Panel Settings**).

### Option 3: Prebuilt Release Binaries ([GitHub Releases](https://github.com/huangming774/shoes-ui/releases))

GitHub Actions automatically builds and publishes single-binary archives + `SHA256SUMS.txt` for:
- `shoes-panel-x86_64-unknown-linux-musl.tar.gz` / `gnu`
- `shoes-panel-aarch64-unknown-linux-musl.tar.gz` / `gnu`
- `shoes-panel-armv7-unknown-linux-musleabihf.tar.gz`
- `shoes-panel-x86_64-pc-windows-msvc.zip`
- `shoes-panel-aarch64-apple-darwin.tar.gz` & `shoes-panel-x86_64-apple-darwin.tar.gz`

### Option 4: Build from Source

```bash
cd web && npm install && npm run build && cd ..
cargo build --release
./target/release/shoes-panel serve --data-dir ./data --port 54321 --shoes-bin /usr/local/bin/shoes
```

---

## Acknowledgements & License

- Powered by [cfal/shoes](https://github.com/cfal/shoes) (Copyright © Alex Lau, MIT License).
- UI workflow inspired by [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui).
- Licensed under the [Apache License 2.0](./LICENSE).
