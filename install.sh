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

if [[ "${1:-}" != "--render-cli" && $EUID -ne 0 ]]; then
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

rand_lower() {
  local len="${1:-8}"
  LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c "$len" || true
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

render_management_cli() {
  printf '#!/usr/bin/env bash\nset -euo pipefail\n'
  printf '%s=%q\n' DATA_DIR "$DATA_DIR" WORK_DIR "$WORK_DIR" PANEL_BIN "$PANEL_BIN" SHOES_BIN "$SHOES_BIN" \
    SERVICE_FILE "$SERVICE_FILE" PANEL_REPO "$PANEL_REPO" RED "$RED" NC "$NC"
  declare -f detect_arch
  cat <<'EOF'

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

TCP_SYSCTL_FILE=/etc/sysctl.d/99-shoes-panel-bbr.conf
TCP_MODLOAD_FILE=/etc/modules-load.d/99-shoes-panel-tcp.conf

tcp_virt_type() {
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    systemd-detect-virt 2>/dev/null || echo "none"
  else
    echo "unknown"
  fi
}

tcp_warn_container() {
  local virt
  virt="$(tcp_virt_type)"
  case "$virt" in
    openvz|lxc|lxc-libvirt|docker|podman)
      echo "⚠️ 检测到当前运行在容器虚拟化环境 ($virt)，共享宿主机内核，无法自行更换内核或加载内核模块。" >&2
      return 1
      ;;
  esac
  return 0
}

tcp_read_previous() {
  if [[ -f "$TCP_SYSCTL_FILE" ]] && grep -q '^# s-ui previous: ' "$TCP_SYSCTL_FILE"; then
    sed -n '1s/^# s-ui previous: //p' "$TCP_SYSCTL_FILE"
  else
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "cubic"
  fi
}

tcp_has_tuning() {
  [[ -f "$TCP_SYSCTL_FILE" ]] && grep -q '^# s-ui tuning: on$' "$TCP_SYSCTL_FILE"
}

tcp_write_sysctl_file() {
  local algo="$1" qdisc="$2" tuning="${3:-0}" previous tmp
  previous="$(tcp_read_previous)"
  if [[ -e "$TCP_SYSCTL_FILE" ]] && ! grep -q '^# s-ui previous: ' "$TCP_SYSCTL_FILE"; then
    echo "配置文件已被其他程序占用，拒绝覆盖: $TCP_SYSCTL_FILE" >&2
    return 1
  fi
  mkdir -p /etc/sysctl.d
  tmp="$(mktemp /etc/sysctl.d/.s-ui-bbr.XXXXXX)"
  {
    printf '# s-ui previous: %s\n' "$previous"
    printf 'net.core.default_qdisc = %s\n' "$qdisc"
    printf 'net.ipv4.tcp_congestion_control = %s\n' "$algo"
    if [[ "$tuning" == "1" ]]; then
      cat <<'TUNING'
# s-ui tuning: on
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
TUNING
    fi
  } > "$tmp"
  chmod 644 "$tmp"
  mv -fT -- "$tmp" "$TCP_SYSCTL_FILE"
}

tcp_set_autoload_module() {
  local mod="$1"
  mkdir -p /etc/modules-load.d
  if [[ -n "$mod" ]]; then
    printf '# Managed by s-ui TCP acceleration\n%s\n' "$mod" > "$TCP_MODLOAD_FILE"
  else
    rm -f -- "$TCP_MODLOAD_FILE"
  fi
}

tcp_apply_cc() {
  local algo="$1" qdisc="${2:-fq}" tuning="${3:-auto}" mod_name="${4:-}"
  if [[ "$tuning" == "auto" ]]; then
    if tcp_has_tuning; then tuning=1; else tuning=0; fi
  fi
  modprobe "sch_${qdisc}" >/dev/null 2>&1 || true
  if [[ -n "$mod_name" ]]; then
    modprobe "$mod_name" >/dev/null 2>&1 || true
  else
    modprobe "tcp_${algo}" >/dev/null 2>&1 || true
  fi
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "$algo"; then
    echo "错误: 当前运行内核 ($(uname -r)) 不支持拥塞控制算法 '$algo'。" >&2
    echo "当前内核可用算法: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)" >&2
    return 1
  fi
  tcp_write_sysctl_file "$algo" "$qdisc" "$tuning"
  if [[ -n "$mod_name" ]]; then
    tcp_set_autoload_module "$mod_name"
  elif [[ "$algo" != "cubic" && "$algo" != "reno" ]]; then
    tcp_set_autoload_module "tcp_${algo}"
  fi
  sysctl -p "$TCP_SYSCTL_FILE" >/dev/null 2>&1 || {
    sysctl -w "net.core.default_qdisc=$qdisc" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.tcp_congestion_control=$algo"
  }
  local live_cc live_qd
  live_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  live_qd="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
  if [[ "$live_cc" != "$algo" ]]; then
    echo "切换失败：当前实际生效算法为 $live_cc（预期 $algo）" >&2
    return 1
  fi
  echo "✓ 已成功切换并持久化: 拥塞控制 = ${live_cc}，队列算法 = ${live_qd} (${TCP_SYSCTL_FILE})"
}

enable_bbr() {
  tcp_apply_cc bbr fq auto tcp_bbr
}

tcp_install_build_deps() {
  local kver
  kver="$(uname -r)"
  echo ">>> 正在安装编译工具链与内核头文件 (${kver})..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y build-essential curl tar "linux-headers-${kver}" || \
      apt-get install -y build-essential curl tar linux-headers-amd64 || \
      apt-get install -y build-essential curl tar linux-headers-arm64 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make curl tar "kernel-devel-${kver}" "kernel-headers-${kver}" || \
      dnf install -y gcc make curl tar kernel-devel kernel-headers || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make curl tar "kernel-devel-${kver}" "kernel-headers-${kver}" || \
      yum install -y gcc make curl tar kernel-devel kernel-headers || true
  else
    echo "未识别包管理器，请手动安装 gcc / make 与当前内核头文件后再重试。" >&2
    return 1
  fi
  if [[ ! -d "/lib/modules/${kver}/build" ]]; then
    echo "错误: 找不到当前内核头文件目录 /lib/modules/${kver}/build，无法编译内核模块。" >&2
    return 1
  fi
}

tcp_install_bbrplus_kernel() {
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbrplus || modprobe tcp_bbrplus >/dev/null 2>&1; then
    echo ">>> 当前内核已内置 BBR Plus，直接启用..."
    tcp_apply_cc bbrplus fq auto
    return 0
  fi
  tcp_warn_container || return 1
  local arch pkg_type arch_tag repo_choice repo
  arch="$(uname -m)"
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    pkg_type="deb"
    case "$arch" in
      x86_64|amd64) arch_tag="amd64" ;;
      aarch64|arm64) arch_tag="arm64" ;;
      *) echo "暂不支持此架构自动安装 BBR Plus 内核: $arch" >&2; return 1 ;;
    esac
  elif command -v rpm >/dev/null 2>&1; then
    pkg_type="rpm"
    case "$arch" in
      x86_64|amd64) arch_tag="x86_64" ;;
      aarch64|arm64) arch_tag="aarch64" ;;
      *) echo "暂不支持此架构自动安装 BBR Plus 内核: $arch" >&2; return 1 ;;
    esac
  else
    echo "暂不支持当前系统的内核包格式，请使用菜单项 5 (tcpx.sh) 或手动安装。" >&2
    return 1
  fi

  echo "------------------------------------------"
  echo "  请选择 UJX6N BBR Plus 预编译内核分支（保留原系统内核作为兜底）："
  echo "  1) bbrplus-6.6       (LTS 推荐，适配 Debian 12 / Ubuntu 22.04-24.04)"
  echo "  2) bbrplus-6.x_stable (最新 6.x 主线)"
  echo "  3) bbrplus-6.1       (LTS 长期支持版)"
  echo "  4) bbrplus-5.15      (经典 5.15 LTS)"
  echo "  0) 取消"
  echo "------------------------------------------"
  read -rp "请选择 [0-4，默认 1]: " repo_choice
  case "${repo_choice:-1}" in
    1) repo="UJX6N/bbrplus-6.6" ;;
    2) repo="UJX6N/bbrplus-6.x_stable" ;;
    3) repo="UJX6N/bbrplus-6.1" ;;
    4) repo="UJX6N/bbrplus-5.15" ;;
    *) return 0 ;;
  esac

  echo ">>> 正在查询 https://github.com/${repo} 最新 Release (${pkg_type}/${arch_tag})..."
  local rel_json urls tmp_k pkg_url fname installed=0
  rel_json="$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/${repo}/releases/latest")"
  if [[ "$pkg_type" == "deb" ]]; then
    urls="$(printf '%s\n' "$rel_json" | grep -Eo "https://[^\"]+${arch_tag}\.deb" | grep -E 'linux-(image|headers)' | grep -v 'dbg' || true)"
  else
    urls="$(printf '%s\n' "$rel_json" | grep -Eo "https://[^\"]+${arch_tag}\.rpm" | grep -E 'kernel-(bbrplus|headers|devel)|kernel-[0-9]' | grep -v 'debug' || true)"
  fi
  if [[ -z "$urls" ]]; then
    echo "未在 ${repo} 最新 Release 中找到匹配 ${pkg_type}/${arch_tag} 的内核安装包，可尝试使用菜单项 5 (tcpx.sh)。" >&2
    return 1
  fi

  tmp_k="$(mktemp -d)"
  trap 'rm -rf -- "$tmp_k"' RETURN
  while IFS= read -r pkg_url; do
    [[ -z "$pkg_url" ]] && continue
    fname="$(basename "$pkg_url")"
    echo ">>> 下载 ${fname}..."
    curl -fL --connect-timeout 15 --max-time 300 "$pkg_url" -o "${tmp_k}/${fname}"
    installed=1
  done <<< "$urls"

  if [[ "$installed" -eq 0 ]]; then
    echo "未下载到任何内核包。" >&2
    return 1
  fi

  echo ">>> 正在安装 BBR Plus 内核（不删除原有内核）..."
  if [[ "$pkg_type" == "deb" ]]; then
    dpkg -i "${tmp_k}"/*.deb || apt-get install -f -y
    command -v update-grub >/dev/null 2>&1 && update-grub || true
  else
    rpm -ivh --force "${tmp_k}"/*.rpm || {
      if command -v dnf >/dev/null 2>&1; then dnf localinstall -y "${tmp_k}"/*.rpm; else yum localinstall -y "${tmp_k}"/*.rpm; fi
    }
    if command -v grub2-mkconfig >/dev/null 2>&1; then
      [[ -f /boot/grub2/grub.cfg ]] && grub2-mkconfig -o /boot/grub2/grub.cfg || true
      [[ -f /boot/efi/EFI/centos/grub.cfg ]] && grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg || true
    fi
  fi

  local cur_tuning=0
  tcp_has_tuning && cur_tuning=1 || true
  tcp_write_sysctl_file bbrplus fq "$cur_tuning"
  tcp_set_autoload_module ""
  echo "=========================================="
  echo "✓ BBR Plus 内核安装完成，已预配置开机启用 bbrplus + fq！"
  echo "  注意：请重启服务器进入新内核后自动生效。"
  echo "=========================================="
  read -rp "是否立即重启服务器以切换至 BBR Plus 内核？[y/N]: " do_rb
  if [[ "$do_rb" =~ ^[Yy]$ ]]; then
    reboot
  fi
}

tcp_install_mod_bbr() {
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw tsunami || modprobe tcp_tsunami >/dev/null 2>&1; then
    echo ">>> 当前内核已支持魔改 BBR (tsunami)，直接启用..."
    tcp_apply_cc tsunami fq auto tcp_tsunami
    return 0
  fi
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw nanqinlang || modprobe tcp_nanqinlang >/dev/null 2>&1; then
    echo ">>> 当前内核已支持暴力魔改 BBR (nanqinlang)，直接启用..."
    tcp_apply_cc nanqinlang fq auto tcp_nanqinlang
    return 0
  fi
  tcp_warn_container || return 1
  echo "------------------------------------------"
  echo "  1) 为当前内核编译加载魔改 BBR (tcp_tsunami.ko，无需换核，适配 Linux 4.9-5.4)"
  echo "  2) 启动 ylx2016 tcpx.sh 安装兼容魔改 BBR / BBR Plus / XanMod BBRv3 的完整内核"
  echo "  0) 返回"
  echo "------------------------------------------"
  read -rp "请选择 [0-2]: " mc
  case "$mc" in
    1)
      tcp_install_build_deps || return 1
      local src_dir=/usr/local/src/shoes-tcp-tsunami kver build_log
      kver="$(uname -r)"
      rm -rf "$src_dir"
      mkdir -p "$src_dir"
      echo ">>> 正在下载 tcp_tsunami.c..."
      curl -fsSL --retry 2 --max-time 60 "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp_tsunami.c" -o "${src_dir}/tcp_tsunami.c"
      cat >"${src_dir}/Makefile" <<'MK'
obj-m := tcp_tsunami.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
MK
      build_log="${src_dir}/build.log"
      echo ">>> 正在针对当前内核 (${kver}) 编译 tcp_tsunami.ko..."
      if ! (cd "$src_dir" && make >"$build_log" 2>&1); then
        echo "✗ tcp_tsunami.ko 编译失败（通常是 Linux 5.10+/6.x 内核 TCP 结构体变更导致魔改源码不兼容）。" >&2
        echo "  最后 15 行编译日志：" >&2
        tail -n 15 "$build_log" >&2 || true
        echo "  建议：现代 6.x 内核请选择菜单项 2 (BBR Plus 6.6) 或菜单项 5 (tcpx.sh 安装 XanMod BBRv3)。" >&2
        return 1
      fi
      install -D -m 644 "${src_dir}/tcp_tsunami.ko" "/lib/modules/${kver}/extra/tcp_tsunami.ko"
      depmod -a
      tcp_apply_cc tsunami fq auto tcp_tsunami
      ;;
    2) tcp_run_tcpx ;;
    *) return 0 ;;
  esac
}

tcp_install_pcc() {
  tcp_warn_container || return 1
  echo "------------------------------------------"
  echo "  PCC / PCC Vivace (PCCproject/PCC-Kernel)"
  echo "  1) 编译并启用 PCC Vivace (推荐，vivace 分支 — 低延迟在线学习)"
  echo "  2) 编译并启用 PCC Allegro (经典版，master 分支)"
  echo "  3) 仅切换启用内核已安装的 pcc 算法 (免重编译)"
  echo "  0) 返回"
  echo "------------------------------------------"
  read -rp "请选择 [0-3]: " pc
  local branch=""
  case "$pc" in
    1) branch="vivace" ;;
    2) branch="master" ;;
    3) tcp_apply_cc pcc fq auto tcp_pcc; return $? ;;
    *) return 0 ;;
  esac

  tcp_install_build_deps || return 1
  local kver src_dir tar_url build_log
  kver="$(uname -r)"
  src_dir="/usr/local/src/shoes-pcc-${branch}"
  tar_url="https://github.com/PCCproject/PCC-Kernel/archive/refs/heads/${branch}.tar.gz"
  rm -rf "$src_dir"
  mkdir -p "$src_dir"
  echo ">>> 正在下载 PCC-Kernel (${branch})..."
  curl -fL --retry 2 --max-time 120 "$tar_url" -o "${src_dir}/pcc.tar.gz"
  tar -xzf "${src_dir}/pcc.tar.gz" -C "$src_dir" --strip-components=1

  if [[ ! -f "${src_dir}/src/Makefile" ]]; then
    echo "错误: 下载的 PCC-Kernel 压缩包中未找到 src/Makefile。" >&2
    return 1
  fi

  # Linux 6.1+ removed prandom_u32 in favor of get_random_u32
  if grep -q 'prandom_u32' "${src_dir}/src/"*.c 2>/dev/null; then
    local kmaj kmin
    kmaj="$(printf '%s' "$kver" | cut -d. -f1)"
    kmin="$(printf '%s' "$kver" | cut -d. -f2)"
    if (( kmaj > 6 || (kmaj == 6 && kmin >= 1) )); then
      sed -i 's/prandom_u32/get_random_u32/g' "${src_dir}/src/"*.c || true
    fi
  fi

  build_log="${src_dir}/build.log"
  echo ">>> 正在针对当前内核 (${kver}) 编译 tcp_pcc.ko (${branch})..."
  if ! (cd "${src_dir}/src" && make -C "/lib/modules/${kver}/build" M="${src_dir}/src" modules >"$build_log" 2>&1); then
    echo "✗ PCC (${branch}) 模块编译失败！" >&2
    echo "  最后 15 行编译日志：" >&2
    tail -n 15 "$build_log" >&2 || true
    echo "  说明：上游 PCCproject/PCC-Kernel 源码主要面向 Linux 4.14-5.15 内核 API；" >&2
    echo "  若当前为 6.x 新内核且接口已变动，建议切换使用 BBRv1 / BBR Plus 6.6 / XanMod BBRv3。" >&2
    return 1
  fi

  if [[ ! -f "${src_dir}/src/tcp_pcc.ko" ]]; then
    echo "错误: 编译完成但未生成 tcp_pcc.ko。" >&2
    return 1
  fi

  # If old tcp_pcc (e.g., Allegro vs Vivace) is active, switch temporarily to cubic before replacing module
  if lsmod 2>/dev/null | awk '{print $1}' | grep -qx tcp_pcc; then
    if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" == "pcc" ]]; then
      sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
    fi
    rmmod tcp_pcc >/dev/null 2>&1 || true
  fi

  install -D -m 644 "${src_dir}/src/tcp_pcc.ko" "/lib/modules/${kver}/extra/tcp_pcc.ko"
  depmod -a
  tcp_apply_cc pcc fq auto tcp_pcc
  echo "✓ PCC (${branch}) 模块已安装并实时生效！"
}

tcp_run_tcpx() {
  tcp_warn_container || return 1
  echo "⚠️ 即将下载并运行第三方开源多内核加速脚本 ylx2016/Linux-NetSpeed (tcpx.sh)。"
  echo "   该脚本支持安装 XanMod BBRv3 / BBR Plus / 魔改 BBR 等内核且不卸载原内核。"
  read -rp "确认下载并启动 tcpx.sh？[y/N]: " yn
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "已取消"; return 0; }
  local tmp_s
  tmp_s="$(mktemp /tmp/tcpx.XXXXXX.sh)"
  trap 'rm -f -- "$tmp_s"' RETURN
  curl -fL --retry 2 --max-time 60 "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh" -o "$tmp_s" || \
    curl -fL --retry 2 --max-time 60 "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh" -o "$tmp_s"
  bash -n "$tmp_s"
  chmod +x "$tmp_s"
  bash "$tmp_s"
}

tcp_hot_switch_available() {
  local m
  for m in tcp_bbr tcp_bbrplus tcp_bbr2 tcp_bbr3 tcp_tsunami tcp_nanqinlang tcp_pcc tcp_hybla tcp_westwood tcp_vegas; do
    modprobe "$m" >/dev/null 2>&1 || true
  done
  local avail_str
  avail_str="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo cubic)"
  local -a algos=()
  read -r -a algos <<< "$avail_str"
  echo "当前内核可直接免重启切换的拥塞算法："
  local i
  for i in "${!algos[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${algos[i]}"
  done
  read -rp "请选择算法编号 [1-${#algos[@]}]: " idx
  if [[ ! "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#algos[@]} )); then
    echo "已取消"
    return 0
  fi
  local chosen_algo="${algos[idx - 1]}"
  echo "请选择队列调度算法 (default_qdisc)："
  echo "  1) fq       (BBR / BBR Plus / PCC 官方推荐)"
  echo "  2) fq_codel (低延迟通用)"
  echo "  3) cake     (抗缓冲膨胀，需内核支持 sch_cake)"
  read -rp "请选择 [1-3，默认 1]: " qc
  local chosen_qd="fq"
  case "${qc:-1}" in
    2) chosen_qd="fq_codel" ;;
    3) chosen_qd="cake" ;;
    *) chosen_qd="fq" ;;
  esac
  tcp_apply_cc "$chosen_algo" "$chosen_qd" auto
}

tcp_apply_proxy_tuning() {
  local cur_cc cur_qd
  cur_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo cubic)"
  cur_qd="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo fq)"
  tcp_apply_cc "$cur_cc" "$cur_qd" 1
  echo "✓ 已应用高并发代理网络缓冲与 TCP 参数调优（64MB 套接字缓冲 / TFO / MTU 探测）。"
}

tcp_restore_default() {
  local previous
  previous="$(tcp_read_previous)"
  rm -f -- "$TCP_SYSCTL_FILE" "$TCP_MODLOAD_FILE"
  sysctl -w "net.ipv4.tcp_congestion_control=${previous:-cubic}" >/dev/null 2>&1 || \
    sysctl -w "net.ipv4.tcp_congestion_control=cubic" >/dev/null 2>&1 || true
  sysctl -w "net.core.default_qdisc=fq_codel" >/dev/null 2>&1 || true
  echo "✓ 已清除 ${TCP_SYSCTL_FILE}，当前拥塞算法恢复为: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo cubic)"
}

manage_tcp_cc() {
  local kver arch virt cur_cc cur_qd avail
  kver="$(uname -r)"
  arch="$(uname -m)"
  virt="$(tcp_virt_type)"
  cur_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  cur_qd="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
  avail="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"

  echo "=========================================="
  echo "   TCP 拥塞控制 / 加速协议管理 (s-ui)     "
  echo "=========================================="
  echo "  当前内核     : ${kver} (${arch}) [虚拟化: ${virt}]"
  echo "  当前拥塞协议 : ${cur_cc}"
  echo "  当前队列算法 : ${cur_qd}"
  echo "  内核可用算法 : ${avail}"
  echo "------------------------------------------"
  echo "  1) 一键开启 / 切换 原版 BBRv1 + FQ (推荐，零换核风险)"
  echo "  2) 安装并启用 BBR Plus 内核 (UJX6N 6.6/6.x/6.1/5.15，保留原内核)"
  echo "  3) 安装并启用 魔改版 BBR (Tsunami 模块编译 / tcpx.sh)"
  echo "  4) 安装并启用 PCC / PCC Vivace 模块 (PCCproject/PCC-Kernel)"
  echo "  5) 高级多内核加速脚本 (ylx2016 tcpx.sh：BBRv3/XanMod/BBRPlus/魔改)"
  echo "  6) 免重启热切换当前内核已支持的任意算法 & 队列 (fq/fq_codel/cake)"
  echo "  7) 应用高并发代理 TCP/UDP 网络参数调优 (64MB缓冲/TFO/MTU探测)"
  echo "  8) 恢复系统默认拥塞控制 (清除 99-shoes-panel-bbr.conf)"
  echo "  0) 返回"
  echo "=========================================="
  read -rp "请选择 [0-8]: " tcp_c
  case "$tcp_c" in
    1) enable_bbr ;;
    2) tcp_install_bbrplus_kernel ;;
    3) tcp_install_mod_bbr ;;
    4) tcp_install_pcc ;;
    5) tcp_run_tcpx ;;
    6) tcp_hot_switch_available ;;
    7) tcp_apply_proxy_tuning ;;
    8) tcp_restore_default ;;
    *) return 0 ;;
  esac
}

update_components() (
  local part dest repo member archive entry target stage backup i tmp
  local was_active=0 restart_needed=0
  local -a targets=() stages=() backups=() committed=()
  target=$(detect_arch)
  tmp=$(mktemp -d)
  finish_update() {
    local status=$? idx path
    trap - EXIT
    set +e
    if ((status)); then
      for idx in "${committed[@]}"; do
        if ! mv -fT -- "${backups[idx]}" "${targets[idx]}"; then
          echo "自动回退失败，旧文件位于 ${backups[idx]}" >&2
          backups[idx]=''
        fi
      done
      if ((was_active && restart_needed)); then systemctl restart shoes-panel; fi
      echo "更新失败" >&2
    fi
    for path in "${stages[@]}" "${backups[@]}"; do
      [[ -z "$path" ]] || rm -f -- "$path"
    done
    rm -rf -- "$tmp"
    exit "$status"
  }
  trap finish_update EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  for part in "$@"; do
    if [[ "$part" == script ]]; then
      dest=/usr/local/bin/s-ui
      curl -fLsS --retry 2 --max-time 120 "https://raw.githubusercontent.com/$PANEL_REPO/main/install.sh" -o "$tmp/installer"
      bash -n "$tmp/installer"
      grep -Fq -- '--render-cli' "$tmp/installer" || { echo "远程脚本不支持独立更新菜单" >&2; exit 1; }
      DATA_DIR="$DATA_DIR" WORK_DIR="$WORK_DIR" PANEL_BIN="$PANEL_BIN" SHOES_BIN="$SHOES_BIN" \
        SERVICE_FILE="$SERVICE_FILE" PANEL_REPO="$PANEL_REPO" bash "$tmp/installer" --render-cli > "$tmp/$part"
      grep -q '^#!/usr/bin/env bash' "$tmp/$part"
      bash -n "$tmp/$part"
    else
      if [[ "$part" == panel ]]; then
        dest=$PANEL_BIN; repo=$PANEL_REPO; member=shoes-panel
      else
        dest=$("$PANEL_BIN" info --data-dir "$DATA_DIR" | sed -n 's/^ *shoes binary : //p')
        repo=cfal/shoes; member=shoes
      fi
      archive="$member-$target.tar.gz"
      curl -fLsS --retry 2 --max-time 180 "https://github.com/$repo/releases/latest/download/$archive" -o "$tmp/$archive"
      if [[ "$part" == panel ]]; then
        curl -fLsS --retry 2 --max-time 60 "https://github.com/$repo/releases/latest/download/SHA256SUMS.txt" -o "$tmp/sums"
        awk -v f="$archive" '$2 == f || $2 == "*"f {print}' "$tmp/sums" > "$tmp/panel.sum"
        (cd "$tmp" && sha256sum -c panel.sum)
      fi
      entry=$(tar -tzf "$tmp/$archive" | awk -F/ -v name="$member" '$NF == name {print}')
      [[ -n "$entry" && "$entry" != *$'\n'* ]] || { echo "发布包缺少唯一的 $member" >&2; exit 1; }
      tar -xzOf "$tmp/$archive" -- "$entry" > "$tmp/$part"
      chmod 755 "$tmp/$part"
      "$tmp/$part" -V
      if [[ "$part" == core ]]; then
        local config
        config=$("$PANEL_BIN" info --data-dir "$DATA_DIR" | sed -n 's/^ *shoes config : //p')
        if [[ -f "$config" ]]; then "$tmp/$part" check "$config"; fi
      fi
    fi
    [[ "$dest" == /* && -f "$dest" && ! -L "$dest" ]] || { echo "安装路径无效: $dest" >&2; exit 1; }
    stage=$(mktemp "$dest.new.XXXXXX"); stages+=("$stage")
    backup=$(mktemp "$dest.old.XXXXXX"); backups+=("$backup")
    targets+=("$dest")
    cp -p -- "$dest" "$backup"
    install -m 755 "$tmp/$part" "$stage"
  done
  if systemctl is-active --quiet shoes-panel; then was_active=1; fi
  for i in "${!targets[@]}"; do
    dest=${targets[i]}
    mv -fT -- "${stages[i]}" "$dest"
    committed+=("$i")
    if [[ "$dest" != /usr/local/bin/s-ui ]]; then restart_needed=1; fi
    if command -v restorecon >/dev/null; then restorecon "$dest"; fi
  done
  if ((was_active && restart_needed)); then
    systemctl restart shoes-panel
    sleep 2
    systemctl is-active --quiet shoes-panel
  fi
  echo "更新完成: $*"
)

uninstall_panel_cli() {
  local dir answer previous file=/etc/sysctl.d/99-shoes-panel-bbr.conf
  for dir in "$DATA_DIR" "$WORK_DIR"; do
    [[ -d "$dir" ]] || continue
    if [[ "$dir" == / || "$(realpath -e -- "$dir")" != "$dir" ]]; then
      echo "拒绝删除非规范目录: $dir" >&2; return 1
    fi
    if [[ "$dir" != /etc/shoes-panel && "$dir" != /usr/local/shoes-panel && ! -f "$dir/.s-ui-owned" ]]; then
      echo "自定义目录缺少安装器归属标记: $dir" >&2; return 1
    fi
  done
  printf '将永久删除以下安装文件和目录，含数据库、证书和备份：\n'
  printf '  %s\n' "$SERVICE_FILE" "$PANEL_BIN" "$SHOES_BIN" "$DATA_DIR" "$WORK_DIR" /usr/local/bin/s-ui
  read -rp '输入 PURGE 确认，其他输入取消: ' answer
  [[ "$answer" == PURGE ]] || { echo "已取消"; return 0; }
  if [[ -f "$SERVICE_FILE" ]]; then
    systemctl disable --now shoes-panel
    rm -f -- "$SERVICE_FILE"
  fi
  systemctl daemon-reload
  if [[ -f "$file" ]] && grep -q '^# s-ui previous: ' "$file"; then
    previous=$(sed -n '1s/^# s-ui previous: //p' "$file")
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true) =~ ^(bbr|bbrplus|bbr2|bbr3|tsunami|nanqinlang|pcc)$ ]]; then
      sysctl -w "net.ipv4.tcp_congestion_control=${previous:-cubic}" >/dev/null 2>&1 || true
    fi
    rm -f -- "$file" "$TCP_MODLOAD_FILE"
  fi
  rm -rf --one-file-system -- "$DATA_DIR" "$WORK_DIR"
  rm -f -- "$PANEL_BIN" "$SHOES_BIN" /usr/local/bin/s-ui
  echo "Shoes Panel 已彻底卸载"
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
echo " 10) 面板 SSL 证书管理 (免费公网 IP SSL / 自签 / 关闭)"
echo " 11) 一键更新面板 (Update Panel)"
echo " 12) 一键更新 Shoes 内核 (Update Shoes Core)"
echo " 13) 备份 / 还原面板数据库 (Backup / Restore DB)"
echo " 14) 彻底卸载面板 (Uninstall)"
echo " 15) TCP 拥塞控制 / 加速管理 (BBRv1 / BBR Plus / 魔改 BBR / PCC / Vivace)"
echo " 16) 更新 s-ui 管理脚本"
echo " 17) 同时更新脚本、面板和内核"
echo "  0) 退出 (Exit)"
echo "=========================================="
if [[ "${1:-}" == "tcp" || "${1:-}" == "bbr" ]]; then
  choice=15
else
  read -rp "请选择 [0-17]: " choice
fi
if [[ "$choice" =~ ^(11|12|14|15|16|17)$ ]]; then
  (( EUID == 0 )) || { echo "请使用 sudo s-ui" >&2; exit 1; }
  exec 9>/run/lock/s-ui-maintenance.lock
  flock -n 9 || { echo "另一个维护操作正在运行" >&2; exit 1; }
fi
case "$choice" in
  1) systemctl start shoes-panel && systemctl status shoes-panel --no-pager ;;
  2) systemctl stop shoes-panel ;;
  3) systemctl restart shoes-panel && systemctl status shoes-panel --no-pager ;;
  4) systemctl status shoes-panel --no-pager ;;
  5) "$PANEL_BIN" info --data-dir "$DATA_DIR" ;;
  6)
    read -rp "新用户名 (直接回车随机生成): " u
    read -rp "新密码 (直接回车随机生成，手动输入至少 4 位): " p
    args=(reset --data-dir "$DATA_DIR")
    if [[ -n "$u" ]]; then
      args+=(--username "$u")
    fi
    if [[ -n "$p" ]]; then
      args+=(--password "$p")
    fi
    if [[ -z "$u" || -z "$p" ]]; then
      args+=(--random)
    fi
    "$PANEL_BIN" "${args[@]}"
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
    "$PANEL_BIN" "${args[@]}"
    systemctl restart shoes-panel
    "$PANEL_BIN" info --data-dir "$DATA_DIR"
    ;;
  8)
    read -rp "请输入服务器公网 IP 或域名: " ph
    "$PANEL_BIN" setting --public-host "$ph" --data-dir "$DATA_DIR"
    systemctl restart shoes-panel
    ;;
  9) journalctl -u shoes-panel -n 100 -f ;;
  10)
    echo "------------------------------------------"
    echo "  1) 申请免费公网 IP SSL (Let's Encrypt 6天自动续签，需 80 端口可达)"
    echo "  2) 生成自签 IP SSL 证书 (180天，无需 80 端口)"
    echo "  3) 关闭面板 HTTPS 加密 (切回 HTTP)"
    echo "  0) 返回"
    echo "------------------------------------------"
    read -rp "请选择 [0-3]: " ssl_c
    case "$ssl_c" in
      1)
        read -rp "公网 IP (直接回车自动探测): " ip_in
        open_fw 80
        cmd=("$PANEL_BIN" cert ip --panel-https --data-dir "$DATA_DIR")
        [[ -n "$ip_in" ]] && cmd+=(--ip "$ip_in")
        "${cmd[@]}"
        systemctl restart shoes-panel
        "$PANEL_BIN" info --data-dir "$DATA_DIR"
        ;;
      2)
        read -rp "公网 IP / 域名 (直接回车自动探测): " ip_in
        cmd=("$PANEL_BIN" cert self-signed --panel-https --data-dir "$DATA_DIR")
        [[ -n "$ip_in" ]] && cmd+=(--ip "$ip_in")
        "${cmd[@]}"
        systemctl restart shoes-panel
        "$PANEL_BIN" info --data-dir "$DATA_DIR"
        ;;
      3)
        "$PANEL_BIN" cert clear --data-dir "$DATA_DIR"
        systemctl restart shoes-panel
        "$PANEL_BIN" info --data-dir "$DATA_DIR"
        ;;
      *) exit 0 ;;
    esac
    ;;
  11) update_components panel ;;
  12) update_components core ;;
  13)
    echo "------------------------------------------"
    echo "  1) 立即备份数据库到 ${DATA_DIR}/backups/"
    echo "  2) 从备份文件还原数据库"
    echo "  0) 返回"
    echo "------------------------------------------"
    read -rp "请选择 [0-2]: " bk_c
    case "$bk_c" in
      1) "$PANEL_BIN" backup --data-dir "$DATA_DIR" ;;
      2)
        ls -lh "${DATA_DIR}/backups/"*.db 2>/dev/null || echo "(尚无本地备份文件)"
        read -rp "请输入要还原的 .db 完整路径: " rf
        if [[ -n "$rf" ]]; then
          systemctl stop shoes-panel >/dev/null 2>&1 || true
          "$PANEL_BIN" restore "$rf" --data-dir "$DATA_DIR"
          systemctl start shoes-panel
        fi
        ;;
      *) exit 0 ;;
    esac
    ;;
  14) uninstall_panel_cli ;;
  15) manage_tcp_cc ;;
  16) update_components script ;;
  17) update_components script panel core ;;
  *) exit 0 ;;
esac
EOF
}

install_management_cli() (
  local stage
  stage=$(mktemp /usr/local/bin/.s-ui.XXXXXX)
  trap 'rm -f -- "$stage"' EXIT
  render_management_cli > "$stage"
  bash -n "$stage"
  chmod 755 "$stage"
  mv -fT -- "$stage" /usr/local/bin/s-ui
)

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
RestartSec=2s
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
  local ssl_note=""

  setup_panel_ip_ssl() {
    local mode="${1:-auto}"
    if [[ "$mode" == "off" ]]; then
      ssl_note="HTTP (未加密)"
      return 0
    fi
    if [[ "$mode" == "self" ]]; then
      if "$PANEL_BIN" cert self-signed --ip "$pub_ip" --panel-https --data-dir "$DATA_DIR" >/dev/null 2>&1; then
        ssl_note="自签 IP SSL (180天，首次浏览器访问请信任)"
      fi
      return 0
    fi

    # Try Let's Encrypt free shortlived IP SSL first (3x-ui style)
    if [[ -n "$pub_ip" && "$pub_ip" != "127.0.0.1" ]]; then
      if is_port_in_use 80; then
        echo -e "${YELLOW}>>> 检测到 80 端口已被占用，跳过 Let's Encrypt 免费公网 IP SSL 申请${NC}"
      else
        open_firewall_port 80
        echo -e "${CYAN}>>> 正在为公网 IP (${pub_ip}) 申请 Let's Encrypt 免费 SSL 证书 (shortlived 自动续签)...${NC}"
        if "$PANEL_BIN" cert ip --ip "$pub_ip" --panel-https --data-dir "$DATA_DIR"; then
          ssl_note="Let's Encrypt 免费公网 IP SSL (6天自动续签，浏览器原生信任)"
          return 0
        else
          echo -e "${YELLOW}>>> Let's Encrypt 免费 IP 证书申请失败（通常是云服务器安全组未放行 TCP 80 端口或网络受限）${NC}"
        fi
      fi
    fi

    if [[ "$mode" == "le" ]]; then
      ssl_note="HTTP (Let's Encrypt 申请失败)"
      return 0
    fi

    local use_self
    use_self="$(prompt_tty "是否自动改用【自签 IP 证书】开启面板 HTTPS 加密？[Y/n]: " "Y")"
    if [[ "$use_self" =~ ^[Yy]$ ]]; then
      if "$PANEL_BIN" cert self-signed --ip "$pub_ip" --panel-https --data-dir "$DATA_DIR" >/dev/null 2>&1; then
        echo -e "${GREEN}>>> 已生成 180 天自签 IP 证书并启用面板 HTTPS${NC}"
        ssl_note="自签 IP SSL (180天，首次浏览器访问请点击继续访问)"
      fi
    else
      ssl_note="HTTP (未加密)"
    fi
  }

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
    in_path="$(prompt_tty "请设置面板访问路径 Base Path [回车默认 / ，输入 r 随机生成安全路径]: " "/")"
    if [[ "$in_path" == "random" || "$in_path" == "r" ]]; then
      final_path="/$(rand_lower 8)"
    else
      final_path="$in_path"
    fi

    local def_user def_pass
    def_user="$(rand_lower 8)"
    def_pass="$(rand_str 12)"
    init_user="$(prompt_tty "请设置管理员账号 Username [回车随机生成 ${def_user}]: " "$def_user")"
    init_pass="$(prompt_tty "请设置管理员密码 Password [回车随机生成 ${def_pass}]: " "$def_pass")"
    if [[ ${#init_pass} -lt 4 ]]; then
      init_pass="$def_pass"
    fi

    "$PANEL_BIN" reset --username "$init_user" --password "$init_pass" --data-dir "$DATA_DIR" >/dev/null
    "$PANEL_BIN" setting --port "$final_port" --base-path "$final_path" --public-host "$pub_ip" --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null

    local ssl_pref="${PANEL_SSL:-auto}"
    if [[ "$ssl_pref" == "auto" ]]; then
      local enable_ssl
      enable_ssl="$(prompt_tty "是否为面板自动申请 IP SSL 证书并默认开启 HTTPS 加密？[Y/n]: " "Y")"
      if [[ "$enable_ssl" =~ ^[Yy]$ ]]; then
        setup_panel_ip_ssl "auto"
      else
        ssl_note="HTTP (未加密)"
      fi
    else
      setup_panel_ip_ssl "$ssl_pref"
    fi
  else
    "$PANEL_BIN" setting --shoes-bin "$SHOES_BIN" --data-dir "$DATA_DIR" >/dev/null
    local info_out
    info_out="$("$PANEL_BIN" info --data-dir "$DATA_DIR")"
    if echo "$info_out" | grep -q "Public host  : <auto>" && [[ -n "$pub_ip" && "$pub_ip" != "127.0.0.1" ]]; then
      "$PANEL_BIN" setting --public-host "$pub_ip" --data-dir "$DATA_DIR" >/dev/null
      info_out="$("$PANEL_BIN" info --data-dir "$DATA_DIR")"
    fi

    local cur_port cur_path cur_scheme
    cur_port="$(echo "$info_out" | awk -F':' '/Listen       :/ {print $NF}' | tr -d '[:space:]')"
    cur_path="$(echo "$info_out" | awk -F': ' '/Base path    :/ {print $2}' | tr -d '[:space:]')"
    cur_scheme="$(echo "$info_out" | awk -F': ' '/Scheme       :/ {print $2}' | tr -d '[:space:]')"
    cur_port="${cur_port:-54321}"
    cur_path="${cur_path:-/}"
    cur_scheme="${cur_scheme:-http}"

    echo ""
    echo -e "${CYAN}>>> 检测到已有面板数据 (协议: ${cur_scheme}，端口: ${cur_port}，访问路径: ${cur_path})${NC}"
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

    if [[ "$cur_scheme" != "https" ]]; then
      local want_ssl
      want_ssl="$(prompt_tty "当前面板为 HTTP 明文运行，是否立即申请公网 IP SSL 开启 HTTPS 加密？[y/N]: " "N")"
      if [[ "$want_ssl" =~ ^[Yy]$ ]]; then
        setup_panel_ip_ssl "auto"
      else
        ssl_note="HTTP (未加密，可随时运行 s-ui 选 10 开启 HTTPS)"
      fi
    else
      ssl_note="HTTPS 已启用 (保持原有证书配置)"
    fi

    init_user="$(echo "$info_out" | awk -F': ' '/Admin user   :/ {print $2}' | tr -d '[:space:]')"
  fi

  local final_info final_scheme
  final_info="$("$PANEL_BIN" info --data-dir "$DATA_DIR")"
  final_scheme="$(echo "$final_info" | awk -F': ' '/Scheme       :/ {print $2}' | tr -d '[:space:]')"
  final_scheme="${final_scheme:-http}"

  # Always normalize trailing slash for display & local probe
  local url_suffix="/"
  if [[ "$final_path" != "/" ]]; then
    url_suffix="${final_path%/}/"
  fi

  open_firewall_port "$final_port"

  systemctl restart shoes-panel

  # Verify systemd process & local HTTP/HTTPS responsiveness
  local ok_http=0
  local code="000"
  local attempt
  for attempt in 1 2 3 4 5 6 7 8; do
    sleep 0.5
    if ! systemctl is-active --quiet shoes-panel; then
      continue
    fi
    code="$(curl -ksS -o /dev/null -w "%{http_code}" --max-time 2 "${final_scheme}://127.0.0.1:${final_port}${url_suffix}" 2>/dev/null || echo "000")"
    if [[ "$code" == "200" || "$code" == "302" ]]; then
      ok_http=1
      break
    fi
  done

  echo ""
  if [[ $ok_http -eq 1 ]]; then
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  ✓ Shoes Panel 已成功启动并通过本机端口自检 (${final_scheme^^} ${code})  ${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "  面板访问地址 : ${CYAN}${final_scheme}://${url_host}:${final_port}${url_suffix}${NC}"
    echo -e "  SSL 加密状态 : ${GREEN}${ssl_note:-$final_scheme}${NC}"
    echo -e "  节点公网地址 : ${GREEN}${pub_ip}${NC}"
    echo -e "  管理员用户名 : ${YELLOW}${init_user}${NC}"
    if [[ $is_fresh -eq 1 ]]; then
      echo -e "  管理员密码   : ${YELLOW}${init_pass}${NC}"
    else
      echo -e "  管理员密码   : ${YELLOW}(保持原密码不变，忘记密码可执行 s-ui 选 6 重置)${NC}"
    fi
    echo -e "  管理快捷命令 : ${CYAN}s-ui${NC}"
    echo -e "${GREEN}------------------------------------------------------------${NC}"
    echo -e "${YELLOW}  ⚠️ 提示：如果浏览器打不开上面的地址，请检查云服务器安全组${NC}"
    echo -e "${YELLOW}     （阿里云/腾讯云/AWS/甲骨文等）是否已放行 TCP ${final_port} 端口！${NC}"
    echo -e "${GREEN}============================================================${NC}"
  else
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}  ✗ shoes-panel 启动异常！以下是 systemd 错误日志：           ${NC}"
    echo -e "${RED}============================================================${NC}"
    journalctl -u shoes-panel -n 30 --no-pager || true
    exit 1
  fi
}

uninstall_all() {
  echo -e "${YELLOW}>>> 正在卸载 shoes-panel...${NC}"
  systemctl stop shoes-panel >/dev/null 2>&1 || true
  systemctl disable shoes-panel >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f "$PANEL_BIN" /usr/local/bin/s-ui
  rm -rf "$WORK_DIR"
  local del_data
  del_data="$(prompt_tty "是否同时删除数据目录 ${DATA_DIR} (含数据库与证书)？[y/N]: " "N")"
  if [[ "$del_data" =~ ^[Yy]$ ]]; then
    rm -rf "$DATA_DIR"
    echo -e "${GREEN}>>> 已删除 ${DATA_DIR}${NC}"
  fi
  local del_core
  del_core="$(prompt_tty "是否同时删除 shoes 内核 (${SHOES_BIN})？[y/N]: " "N")"
  if [[ "$del_core" =~ ^[Yy]$ ]]; then
    rm -f "$SHOES_BIN"
    echo -e "${GREEN}>>> 已删除 ${SHOES_BIN}${NC}"
  fi
  echo -e "${GREEN}✓ shoes-panel 已卸载完成。${NC}"
}

if [[ "${1:-}" == "uninstall" || "${1:-}" == "--uninstall" ]]; then
  uninstall_all
  exit 0
fi

if [[ "${1:-}" == --render-cli ]]; then
  render_management_cli
  exit 0
fi
if [[ "${1:-}" == --install-cli ]]; then
  install_management_cli
  exit 0
fi

for dir in "$WORK_DIR" "$DATA_DIR"; do
  if [[ ! -e "$dir" ]]; then
    mkdir -p -- "$dir"
    touch -- "$dir/.s-ui-owned"
  fi
done
ensure_deps
systemctl stop shoes-panel >/dev/null 2>&1 || true
check_docker_conflict
install_shoes_core
install_panel_binary
install_management_cli
setup_systemd
configure_and_start
