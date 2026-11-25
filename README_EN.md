<div align="center">

# ⚡ Shoes Panel (`shoes-ui`)

**A 3x-ui Style Multi-Protocol Web Management Panel for [cfal/shoes](https://github.com/cfal/shoes)**  
*Single-Binary Rust Backend · Embedded Vue 3 + Ant Design Vue Bilingual SPA · Zero-Patch Hot Reload*

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

| Login (Bilingual & Dark/Light Mode) | Two-Layer Inbounds & Clients Management |
| :---: | :---: |
| ![Login Preview](./docs/screenshots/login.png) | ![Inbounds Preview](./docs/screenshots/inbounds.png) |

---

## Key Features

- **Zero-Modification Upstream `shoes` Integration**: Validates every candidate YAML with `shoes check` before atomic replacement (rolling back DB changes on validation failure) and triggers zero-downtime hot reload (`SIGHUP` on Unix).
- **Two-Layer `Inbound -> Clients` Data Model**:
  - Dedicated port per client (`1 Client = 1 Port`) for single-credential protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC v5, Snell, SOCKS5, HTTP, Mixed) with accurate per-inbound traffic accounting, quotas, expiration dates, monthly auto-reset, and **1-click Dedicated-Port Client Cloning (`+Port`)**.
  - Native multi-user support on a single port for **AnyTLS** and **NaiveProxy**.
- **Full Protocol Form + 1-Click Key Generators**: VLESS (TLS / REALITY / XTLS-Vision), VMess, Trojan, Shadowsocks (Classic & 2022 AEAD), Hysteria2 (QUIC), TUIC v5 (QUIC), AnyTLS, NaiveProxy, Snell, SOCKS5, HTTP, Mixed, plus WebSocket & XHTTP/SplitHTTP transports. Built-in generators for UUID, Reality X25519 keypairs, SS-2022 keys, and ECDSA self-signed certificates.
- **Share Links, QR Codes & Multi-Format Subscriptions**: Generates standard client URIs, QR codes, `shoes` client YAML snippets, and `/sub/<token>` subscriptions in **v2rayN Base64**, **Clash / Mihomo YAML**, and **sing-box JSON** formats (auto-detected by User-Agent or `?format=`, including `Subscription-Userinfo` headers).
- **Real-Time Traffic Accounting & Quota Enforcement**: Polls `shoes` Clash Controller API (`/connections`) every second to persist byte deltas to SQLite, and automatically disables expired or over-quota inbounds while terminating active connections.
- **Certificates, Outbound Groups & Routing Rules**: Manage ACME auto-renewing certificates, PEM uploads, self-signed certs, `client_group` (`selector` / `url-test` / `round-robin` with live node switching & latency probes), and `panel-routing` rules.
- **Single Binary & Security**: Embedded Vue 3 SPA via `rust-embed`, Argon2id password hashing, panel HTTPS support, and instant dynamic secret base path (e.g., `/secret`).

---

## Quick Start

### Option 1: Linux VPS One-Click Script (`systemd` + `s-ui` CLI Menu)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huangming774/shoes-ui/main/install.sh)
```

Automatically installs the official `shoes` binary and `shoes-panel`, lets you customize (or accept defaults `54321` / `/`) the panel port, base path, and admin credentials, opens local firewall rules (`ufw` / `firewalld` / `iptables`), enables and verifies the `shoes-panel` systemd service, and installs the `s-ui` management CLI.

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
