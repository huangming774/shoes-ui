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

DATA_DIR="${DATA_DIR:-/etc/shoes-panel}"
WORK_DIR="${WORK_DIR:-/usr/local/shoes-panel}"
PANEL_BIN="${PANEL_BIN:-/usr/local/bin/shoes-panel}"
SHOES_BIN="${SHOES_BIN:-/usr/local/bin/shoes}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/shoes-panel.service}"
PANEL_REPO="${PANEL_REPO:-huangming774/shoes-ui}"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: 请使用 root 权限运行此脚本 (sudo -i 或 sudo bash install.sh)${NC}"
  exit 1
fi

ensure_deps() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=(curl ca-certificates)
  command -v tar >/dev/null 2>&1 || missing+=(tar)
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${CYAN}>>> 正在安装基础依赖 (${missing[*]})...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y "${missing[@]}" >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y "${missing[@]}" >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y "${missing[@]}" >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache "${missing[@]}" >/dev/null 2>&1 || true
    fi
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
    armv7l|armv7|armhf) echo "armv7-unknown-linux-musleabihf" ;;
    *)
      echo -e "${RED}不支持的 CPU 架构: $(uname -m)${NC}" >&2
      exit 1
      ;;
  esac
}

rand_str() {
  local len="${1:-12}"
  LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom 2>/dev/null | head -c "$len" || true
}

is_port_in_use() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:|\\])${p}$" && return 0
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:|\\])${p}$" && return 0
  fi
  return 1
}

open_firewall_port() {
  local port="$1"
  [[ -z "$port" ]] && return 0

  # 1. UFW (use LC_ALL=C so Chinese locale '状态： 激活' is properly matched!)
  if command -v ufw >/dev/null 2>&1; then
    if LC_ALL=C ufw status 2>/dev/null | grep -qi "Status: active"; then
      ufw allow "${port}/tcp" >/dev/null 2>&1 || true
      echo -e "${GREEN}>>> 已在 UFW 防火墙放行端口 ${port}/tcp${NC}"
    fi
  fi

  # 2. firewalld (CentOS / Rocky / Alma / RHEL / openEuler)
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}>>> 已在 firewalld 防火墙放行端口 ${port}/tcp${NC}"
  fi

  # 3. iptables (Oracle Cloud / Ubuntu / CentOS templates with INPUT REJECT/DROP rules)
  if command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT 2>/dev/null | grep -Eq '^-A INPUT .* -j (REJECT|DROP)'; then
      if ! iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
        iptables -I INPUT 1 -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1 || true
        echo -e "${GREEN}>>> 已在 iptables INPUT 链放行端口 ${port}/tcp${NC}"
      fi
    fi
  fi
}

detect_public_ip() {
  local ip=""
  local url
  for url in "https://4.ipw.cn" "https://api4.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
    ip="$(curl -fsSL4 --connect-timeout 3 --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  for url in "https://6.ipw.cn" "https://api64.ipify.org"; do
    ip="$(curl -fsSL6 --connect-timeout 3 --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ -n "$ip" && "$ip" == *:* ]]; then
      echo "$ip"
      return 0
    fi
  done
  if command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  echo "${ip:-127.0.0.1}"
}

format_url_host() {
  local h="$1"
  if [[ "$h" == *:* && "$h" != \[*\] ]]; then
    echo "[${h}]"
  else
    echo "$h"
  fi
}

prompt_tty() {
  local prompt_msg="$1"
  local default_val="$2"
  local reply=""
  if [[ -z "${NONINTERACTIVE:-}" ]] && [[ -t 1 ]] && ( : </dev/tty ) 2>/dev/null; then
    printf "%s" "$prompt_msg" >/dev/tty
    if read -r -t 30 reply </dev/tty; then
      echo "${reply:-$default_val}"
      return 0
    else
      printf "\n" >/dev/tty || true
    fi
  fi
  echo "$default_val"
}

check_docker_conflict() {
  if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'shoes-panel'; then
      echo -e "${YELLOW}>>> 检测到正在运行的 Docker 容器 'shoes-panel'（可能占用 54321 或 19090 端口）${NC}"
      local stop_dk
      stop_dk="$(prompt_tty "是否停止旧的 Docker 容器 shoes-panel 以避免端口冲突？[Y/n]: " "Y")"
      if [[ "$stop_dk" =~ ^[Yy]$ ]]; then
        docker stop shoes-panel >/dev/null 2>&1 || true
        echo -e "${GREEN}>>> 已停止旧 Docker 容器 shoes-panel${NC}"
      fi
    fi
  fi
}

install_shoes_core() {
  local target
  target="$(detect_arch)"
  echo -e "${CYAN}>>> 正在下载并安装 cfal/shoes 内核 (${target})...${NC}"

  local latest_url="https://github.com/cfal/shoes/releases/latest/download/shoes-${target}.tar.gz"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  if curl -fL --connect-timeout 10 --max-time 180 "$latest_url" -o "${tmp_dir}/shoes.tar.gz"; then
    tar -xzf "${tmp_dir}/shoes.tar.gz" -C "${tmp_dir}"
    local extracted
    extracted="$(find "${tmp_dir}" -type f -name 'shoes' -print -quit)"
    if [[ -n "$extracted" ]]; then
      install -m 0755 "$extracted" "$SHOES_BIN"
      restorecon -f "$SHOES_BIN" >/dev/null 2>&1 || true
      echo -e "${GREEN}>>> 已安装 shoes 内核: $($SHOES_BIN -V 2>/dev/null || echo 'OK')${NC}"
    fi
  else
    echo -e "${YELLOW}Warning: 无法从 ${latest_url} 下载 shoes 内核，稍后可手动放入 ${SHOES_BIN}${NC}"
  fi
  rm -rf "${tmp_dir}"
}

install_panel_binary() {
  mkdir -p "$DATA_DIR" "$WORK_DIR"
  local target tmp_dl
  target="$(detect_arch)"
  tmp_dl="$(mktemp -d)"

  if [[ -f "./target/release/shoes-panel" ]]; then
    echo -e "${CYAN}>>> 安装本地编译版 ./target/release/shoes-panel...${NC}"
    install -m 0755 "./target/release/shoes-panel" "$PANEL_BIN"
  else
    local dl_url="https://github.com/${PANEL_REPO}/releases/latest/download/shoes-panel-${target}.tar.gz"
    echo -e "${CYAN}>>> 正在从 GitHub Releases 下载 shoes-panel (${target})...${NC}"
    if [[ -n "$PANEL_REPO" ]] && curl -fL --connect-timeout 10 --max-time 180 "$dl_url" -o "${tmp_dl}/panel.tar.gz"; then
      tar -xzf "${tmp_dl}/panel.tar.gz" -C "${tmp_dl}"
      local bin_found
      bin_found="$(find "${tmp_dl}" -type f -name 'shoes-panel' -print -quit)"
      if [[ -z "$bin_found" ]]; then
        rm -rf "${tmp_dl}"
        echo -e "${RED}Error: 解压安装包失败，未找到 shoes-panel 可执行文件${NC}"
        exit 1
      fi
      install -m 0755 "$bin_found" "$PANEL_BIN"
      echo -e "${GREEN}>>> 已安装 shoes-panel: $($PANEL_BIN version 2>/dev/null || echo 'OK')${NC}"
    else
      echo -e "${CYAN}>>> 未获取到预编译包，尝试本地编译...${NC}"
      if ! command -v npm >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
        rm -rf "${tmp_dl}"
        echo -e "${RED}Error: 从 GitHub 下载失败，且本机未安装 cargo/npm，请检查服务器访问 GitHub 网络！${NC}"
        exit 1
      fi
      (cd web && npm install && npm run build)
      cargo build --release
      install -m 0755 "./target/release/shoes-panel" "$PANEL_BIN"
    fi
  fi
  restorecon -f "$PANEL_BIN" >/dev/null 2>&1 || true
  rm -rf "${tmp_dl}"
}

install_management_cli() {
  cat >/usr/local/bin/s-ui <<'EOF'
#!/usr/bin/env bash
set -e
DATA_DIR="/etc/shoes-panel"

open_fw() {
  local p="$1"
  [[ -z "$p" ]] && return 0
  if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -qi "Status: active"; then
    ufw allow "${p}/tcp" >/dev/null 2>&1 || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -Eq '^-A INPUT .* -j (REJECT|DROP)'; then
    if ! iptables -C INPUT -p tcp --dport "${p}" -j ACCEPT >/dev/null 2>&1; then
      iptables -I INPUT 1 -p tcp --dport "${p}" -j ACCEPT >/dev/null 2>&1 || true
    fi
  fi
}

echo "=========================================="
echo "       Shoes Panel 管理菜单 (s-ui)        "
echo "=========================================="
echo "  1) 启动面板 (Start)"
echo "  2) 停止面板 (Stop)"
echo "  3) 重启面板 (Restart)"
echo "  4) 查看运行状态 (Status)"
echo "  5) 查看面板地址与端口信息 (Info)"
echo "  6) 重置管理员账号密码 (Reset Credentials)"
echo "  7) 修改面板端口 / 安全根路径 (Port / Path)"
echo "  8) 设置节点公网 IP / 域名 (Public Host)"
echo "  9) 查看面板实时日志 (Logs)"
echo "  0) 退出 (Exit)"
echo "=========================================="
read -rp "请选择 [0-9]: " choice
case "$choice" in
  1) systemctl start shoes-panel && systemctl status shoes-panel --no-pager ;;
  2) systemctl stop shoes-panel ;;
  3) systemctl restart shoes-panel && systemctl status shoes-panel --no-pager ;;
  4) systemctl status shoes-panel --no-pager ;;
  5) /usr/local/bin/shoes-panel info --data-dir "$DATA_DIR" ;;
  6)
    read -rp "新用户名 [默认 admin]: " u
    read -rp "新密码 (至少 4 位): " p
    /usr/local/bin/shoes-panel reset --username "${u:-admin}" --password "$p" --data-dir "$DATA_DIR"
    systemctl restart shoes-panel
    ;;
  7)
    read -rp "新面板端口 (直接回车保持不变，如 54321): " port
    read -rp "新安全根路径 (直接回车保持不变，输入 / 设为根路径): " bp
    args=(setting --data-dir "$DATA_DIR")
    if [[ -n "$port" ]]; then
      args+=(--port "$port")
      open_fw "$port"
    fi
    if [[ -n "$bp" ]]; then
      args+=(--base-path "$bp")
    fi
    /usr/local/bin/shoes-panel "${args[@]}"
    systemctl restart shoes-panel
    /usr/local/bin/shoes-panel info --data-dir "$DATA_DIR"
    ;;
  8)
    read -rp "请输入服务器公网 IP 或域名: " ph
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
  if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
    echo -e "${RED}Error: 当前系统未使用 systemd（如容器或 Alpine OpenRC），请直接运行: ${PANEL_BIN} serve --data-dir ${DATA_DIR}${NC}"
    exit 1
  fi

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
  systemctl enable shoes-panel >/dev/null 2>&1 || true
}

configure_and_start() {
  local is_fresh=0
  if [[ ! -f "${DATA_DIR}/panel.db" ]]; then
    is_fresh=1
  fi

  local pub_ip
  pub_ip="$(detect_public_ip)"
  local url_host
  url_host="$(format_url_host "$pub_ip")"

  local final_port=""
  local final_path=""
  local init_user=""
  local init_pass=""

  if [[ $is_fresh -eq 1 ]]; then
    local def_port="${PANEL_PORT:-54321}"
    if is_port_in_use "$def_port"; then
      def_port="$((RANDOM % 30000 + 20000))"
    fi

    echo ""
    local in_port
    in_port="$(prompt_tty "请设置面板端口 Panel Port [回车默认 ${def_port}]: " "$def_port")"
    if [[ ! "$in_port" =~ ^[0-9]+$ ]] || (( in_port < 1 || in_port > 65535 )); then
      in_port="$def_port"
    fi
    final_port="$in_port"

    local in_path
    in_path="$(prompt_tty "请设置面板访问路径 Base Path [回车默认 / ，输入 random 随机生成]: " "/")"
    if [[ "$in_path" == "random" ]]; then
      final_path="/$(rand_str 8)"
    else
      final_path="$in_path"
    fi

    init_user="$(prompt_tty "请设置管理员账号 Username [回车默认 admin]: " "admin")"
    local def_pass
    def_pass="$(rand_str 12)"
    init_pass="$(prompt_tty "请设置管理员密码 Password [回车随机生成 ${def_pass}]: " "$def_pass")"
    if [[ ${#init_pass} -lt 4 ]]; then
      init_pass="$def_pass"
    fi

    "$PANEL_BIN" reset --username "$init_user" --password "$init_pass" --data-dir "$DATA_DIR" >/dev/null
    "$PANEL_BIN" setting --port "$final_port" --base-path "$final_path" --public-host "$pub_ip" --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null
  else
    "$PANEL_BIN" setting --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null
    local info_out
    info_out="$("$PANEL_BIN" info --data-dir "$DATA_DIR")"
    if echo "$info_out" | grep -q "Public host  : <auto>" && [[ -n "$pub_ip" && "$pub_ip" != "127.0.0.1" ]]; then
      "$PANEL_BIN" setting --public-host "$pub_ip" --data-dir "$DATA_DIR" >/dev/null
      info_out="$("$PANEL_BIN" info --data-dir "$DATA_DIR")"
    fi

    local cur_port cur_path
    cur_port="$(echo "$info_out" | awk -F':' '/Listen       :/ {print $NF}' | tr -d '[:space:]')"
    cur_path="$(echo "$info_out" | awk -F': ' '/Base path    :/ {print $2}' | tr -d '[:space:]')"
    cur_port="${cur_port:-54321}"
    cur_path="${cur_path:-/}"

    echo ""
    echo -e "${CYAN}>>> 检测到已有面板数据 (当前端口: ${cur_port}，访问根路径: ${cur_path})${NC}"
    local new_port
    new_port="$(prompt_tty "如需修改面板端口请输入新端口 [直接回车保持 ${cur_port}]: " "$cur_port")"
    if [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1 && new_port <= 65535 )) && [[ "$new_port" != "$cur_port" ]]; then
      "$PANEL_BIN" setting --port "$new_port" --data-dir "$DATA_DIR" >/dev/null
      final_port="$new_port"
    else
      final_port="$cur_port"
    fi

    if [[ "$cur_path" != "/" ]]; then
      local rst_path
      rst_path="$(prompt_tty "当前设置了安全路径 ${cur_path}，输入 / 可改为直接根路径访问 [回车保持 ${cur_path}]: " "$cur_path")"
      if [[ -n "$rst_path" && "$rst_path" != "$cur_path" ]]; then
        "$PANEL_BIN" setting --base-path "$rst_path" --data-dir "$DATA_DIR" >/dev/null
        final_path="$rst_path"
      else
        final_path="$cur_path"
      fi
    else
      final_path="$cur_path"
    fi

    init_user="$(echo "$info_out" | awk -F': ' '/Admin user   :/ {print $2}' | tr -d '[:space:]')"
  fi

  # Always normalize trailing slash for display & local probe
  local url_suffix="/"
  if [[ "$final_path" != "/" ]]; then
    url_suffix="${final_path%/}/"
  fi

  open_firewall_port "$final_port"

  systemctl restart shoes-panel

  # Verify systemd process & local HTTP responsiveness
  local ok_http=0
  local code="000"
  local attempt
  for attempt in 1 2 3 4 5 6 7 8; do
    sleep 0.5
    if ! systemctl is-active --quiet shoes-panel; then
      continue
    fi
    code="$(curl -ksS -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:${final_port}${url_suffix}" 2>/dev/null || echo "000")"
    if [[ "$code" == "200" || "$code" == "302" ]]; then
      ok_http=1
      break
    fi
    code="$(curl -ksS -o /dev/null -w "%{http_code}" --max-time 2 "https://127.0.0.1:${final_port}${url_suffix}" 2>/dev/null || echo "000")"
    if [[ "$code" == "200" || "$code" == "302" ]]; then
      ok_http=1
      break
    fi
  done

  echo ""
  if [[ $ok_http -eq 1 ]]; then
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  ✓ Shoes Panel 已成功启动并通过本机端口自检 (HTTP ${code})   ${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "  面板访问地址 : ${CYAN}http://${url_host}:${final_port}${url_suffix}${NC}"
    echo -e "  节点公网地址 : ${GREEN}${pub_ip}${NC}"
    echo -e "  管理员用户名 : ${YELLOW}${init_user}${NC}"
    if [[ $is_fresh -eq 1 ]]; then
      echo -e "  管理员密码   : ${YELLOW}${init_pass}${NC}"
    else
      echo -e "  管理员密码   : ${YELLOW}(保持原密码不变，忘记密码可执行 s-ui 选 6 重置)${NC}"
    fi
    echo -e "  管理快捷命令 : ${CYAN}s-ui${NC}"
    echo -e "${GREEN}------------------------------------------------------------${NC}"
    echo -e "${YELLOW}  ⚠️ 重要提示：如果浏览器仍打不开上面的地址，100% 是云服务器控制台${NC}"
    echo -e "${YELLOW}     （阿里云/腾讯云/AWS/甲骨文等【安全组/防火墙】）未放行 TCP ${final_port} 端口！${NC}"
    echo -e "${GREEN}============================================================${NC}"
  else
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}  ✗ shoes-panel 启动异常！以下是 systemd 错误日志：           ${NC}"
    echo -e "${RED}============================================================${NC}"
    journalctl -u shoes-panel -n 30 --no-pager || true
    exit 1
  fi
}

ensure_deps
systemctl stop shoes-panel >/dev/null 2>&1 || true
check_docker_conflict
install_shoes_core
install_panel_binary
install_management_cli
setup_systemd
configure_and_start
