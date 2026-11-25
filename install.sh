#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# shoes-panel One-Click Linux VPS Installer & Management Script (3x-ui style)
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DATA_DIR="/etc/shoes-panel"
WORK_DIR="/usr/local/shoes-panel"
PANEL_BIN="/usr/local/bin/shoes-panel"
SHOES_BIN="/usr/local/bin/shoes"
SERVICE_FILE="/etc/systemd/system/shoes-panel.service"
PANEL_REPO="${PANEL_REPO:-huangming774/shoes-ui}"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: Please run this script as root (sudo -i).${NC}"
  exit 1
fi

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
    armv7l|armv7|armhf) echo "armv7-unknown-linux-musleabihf" ;;
    *)
      echo -e "${RED}Unsupported CPU architecture: $(uname -m)${NC}" >&2
      exit 1
      ;;
  esac
}

rand_str() {
  local len="${1:-12}"
  tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "$len" || true
}

install_shoes_core() {
  local target
  target="$(detect_arch)"
  echo -e "${CYAN}>>> Installing cfal/shoes core (${target})...${NC}"

  local latest_url
  latest_url="https://github.com/cfal/shoes/releases/latest/download/shoes-${target}.tar.gz"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  if curl -fsSL "$latest_url" -o "${tmp_dir}/shoes.tar.gz"; then
    tar -xzf "${tmp_dir}/shoes.tar.gz" -C "${tmp_dir}"
    local extracted
    extracted="$(find "${tmp_dir}" -type f -name 'shoes' | head -n 1)"
    if [[ -n "$extracted" ]]; then
      install -m 0755 "$extracted" "$SHOES_BIN"
      echo -e "${GREEN}Installed shoes: $($SHOES_BIN -V)${NC}"
    fi
  else
    echo -e "${YELLOW}Warning: Could not download prebuilt shoes tarball from ${latest_url}.${NC}"
    echo -e "${YELLOW}You can place the 'shoes' binary at ${SHOES_BIN} manually.${NC}"
  fi
  rm -rf "${tmp_dir}"
}

install_panel_binary() {
  mkdir -p "$DATA_DIR" "$WORK_DIR"
  local target tmp_dl
  target="$(detect_arch)"
  tmp_dl="$(mktemp -d)"

  if [[ -f "./target/release/shoes-panel" ]]; then
    echo -e "${CYAN}>>> Installing local release binary ./target/release/shoes-panel...${NC}"
    install -m 0755 "./target/release/shoes-panel" "$PANEL_BIN"
  elif [[ -n "$PANEL_REPO" ]] && curl -fsSL "https://github.com/${PANEL_REPO}/releases/latest/download/shoes-panel-${target}.tar.gz" -o "${tmp_dl}/panel.tar.gz" 2>/dev/null; then
    tar -xzf "${tmp_dl}/panel.tar.gz" -C "${tmp_dl}"
    install -m 0755 "$(find "${tmp_dl}" -type f -name 'shoes-panel' | head -n 1)" "$PANEL_BIN"
    echo -e "${GREEN}Downloaded prebuilt shoes-panel (${target}) from GitHub Releases.${NC}"
  else
    echo -e "${CYAN}>>> Building shoes-panel from source...${NC}"
    if ! command -v npm >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
      rm -rf "${tmp_dl}"
      echo -e "${RED}Error: Prebuilt release not found and cargo/npm are not installed.${NC}"
      exit 1
    fi
    (cd web && npm install && npm run build)
    cargo build --release
    install -m 0755 "./target/release/shoes-panel" "$PANEL_BIN"
  fi
  rm -rf "${tmp_dl}"
}

install_management_cli() {
  cat >/usr/local/bin/s-ui <<'EOF'
#!/usr/bin/env bash
set -e
DATA_DIR="/etc/shoes-panel"
echo "=========================================="
echo "       Shoes Panel Management Menu        "
echo "=========================================="
echo "  1) Start panel"
echo "  2) Stop panel"
echo "  3) Restart panel"
echo "  4) Panel status"
echo "  5) Show panel info (port / base path)"
echo "  6) Reset admin username & password"
echo "  7) Change panel port / base path"
echo "  8) Set public IP / domain for share links"
echo "  9) View panel systemd logs"
echo "  0) Exit"
echo "=========================================="
read -rp "Select [0-9]: " choice
case "$choice" in
  1) systemctl start shoes-panel && systemctl status shoes-panel --no-pager ;;
  2) systemctl stop shoes-panel ;;
  3) systemctl restart shoes-panel && systemctl status shoes-panel --no-pager ;;
  4) systemctl status shoes-panel --no-pager ;;
  5) /usr/local/bin/shoes-panel info --data-dir "$DATA_DIR" ;;
  6)
    read -rp "New username [admin]: " u
    read -rp "New password: " p
    /usr/local/bin/shoes-panel reset --username "${u:-admin}" --password "$p" --data-dir "$DATA_DIR"
    systemctl restart shoes-panel
    ;;
  7)
    read -rp "New panel port (empty to keep): " port
    read -rp "New base path e.g. /secret (empty to keep): " bp
    args=(setting --data-dir "$DATA_DIR")
    [[ -n "$port" ]] && args+=(--port "$port")
    [[ -n "$bp" ]] && args+=(--base-path "$bp")
    /usr/local/bin/shoes-panel "${args[@]}"
    systemctl restart shoes-panel
    ;;
  8)
    read -rp "Enter server public IP or domain (e.g. 203.0.113.88): " ph
    /usr/local/bin/shoes-panel setting --public-host "$ph" --data-dir "$DATA_DIR"
    systemctl restart shoes-panel
    ;;
  9) journalctl -u shoes-panel -n 100 -f ;;
  *) exit 0 ;;
esac
EOF
  chmod +x /usr/local/bin/s-ui
}

setup_systemd() {
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Shoes Panel - Multi-Protocol Proxy Management Panel for cfal/shoes
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
Environment="SHOES_PANEL_DATA=${DATA_DIR}"
Environment="RUST_LOG=shoes_panel=info"
ExecStart=${PANEL_BIN} serve --data-dir ${DATA_DIR}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable shoes-panel
}

first_time_init() {
  local is_fresh=0
  [[ ! -f "${DATA_DIR}/panel.db" ]] && is_fresh=1

  local pub_ip
  pub_ip="$(curl -fsSL4 --max-time 4 https://api4.ipify.org 2>/dev/null || curl -fsSL4 --max-time 4 https://4.ipw.cn 2>/dev/null || hostname -I | awk '{print $1}')"

  "$PANEL_BIN" setting --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null

  if [[ $is_fresh -eq 1 ]]; then
    local init_user init_pass init_port init_path
    init_user="admin"
    init_pass="$(rand_str 14)"
    init_port="$((RANDOM % 40000 + 15000))"
    init_path="/$(rand_str 8)"

    "$PANEL_BIN" reset --username "$init_user" --password "$init_pass" --data-dir "$DATA_DIR" >/dev/null
    "$PANEL_BIN" setting --port "$init_port" --base-path "$init_path" --public-host "$pub_ip" --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      ufw allow "${init_port}/tcp" >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
      firewall-cmd --permanent --add-port="${init_port}/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    fi

    systemctl restart shoes-panel

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Shoes Panel installed and started successfully!           ${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "  Panel URL   : ${CYAN}http://${pub_ip}:${init_port}${init_path}/${NC}"
    echo -e "  Public Host : ${GREEN}${pub_ip}${NC}"
    echo -e "  Username    : ${YELLOW}${init_user}${NC}"
    echo -e "  Password    : ${YELLOW}${init_pass}${NC}"
    echo -e "  CLI Menu    : ${CYAN}s-ui${NC}"
    echo -e "${YELLOW}  Note: Remember to allow your Inbound ports in cloud security group / ufw!${NC}"
    echo -e "${GREEN}============================================================${NC}"
  else
    # On upgrade, if public_host was not set yet, populate it automatically
    if "$PANEL_BIN" info --data-dir "$DATA_DIR" | grep -q "Public host  : <auto>" && [[ -n "$pub_ip" ]]; then
      "$PANEL_BIN" setting --public-host "$pub_ip" --data-dir "$DATA_DIR" >/dev/null
    fi
    systemctl restart shoes-panel
    echo -e "${GREEN}Shoes Panel upgraded & restarted! Run 's-ui' to manage.${NC}"
  fi
}

install_shoes_core
install_panel_binary
install_management_cli
setup_systemd
first_time_init
