#!/bin/bash
# sys_conf.sh - System configuration menu (timezone/DNS/swap/IPv4-IPv6/BBR3/BBR-TCP/cron/SSH/Firewall)

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PLAIN="\033[0m"
tianlan='\033[96m'
hui='\e[37m'

red(){ echo -e "${RED}\033[01m$1${PLAIN}"; }
green(){ echo -e "${GREEN}\033[01m$1${PLAIN}"; }
yellow(){ echo -e "${YELLOW}\033[01m$1${PLAIN}"; }
skyblue(){ echo -e "\033[1;36m$1\033[0m"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    red "注意: 请在 root 用户下运行脚本"
    exit 1
  fi
}

# -----------------------------
# Wait apt locks (Debian/Ubuntu)
# -----------------------------
wait_for_apt_lock() {
  local max_attempts=60
  local attempt=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ $attempt -ge $max_attempts ]; then
      red "apt 锁等待超时，请手动检查进程并释放锁（例如 kill <PID>），然后重试。"
      return 1
    fi
    yellow "apt 锁被占用（可能有其他更新进程），等待中... ($attempt/$max_attempts)"
    sleep 1
    attempt=$((attempt + 1))
  done
  return 0
}

# -----------------------------
# Package helpers
# -----------------------------
pkg_update() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || return 1
    DEBIAN_FRONTEND=noninteractive apt-get update -y
  elif command -v yum >/dev/null 2>&1; then
    yum -y update
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y update
  else
    return 1
  fi
}

pkg_install() {
  local pkgs=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum -y install "${pkgs[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y install "${pkgs[@]}"
  else
    red "未知的包管理器，无法自动安装依赖。"
    return 1
  fi
}

# -----------------------------
# Get current SSH port
# -----------------------------
get_ssh_port() {
  local port
  port=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}')
  [[ -z "$port" ]] && port=22
  echo "$port"
}

# -----------------------------
# 1) Change timezone
# -----------------------------
change_tz(){
  need_root
  local tz
  read -rp "请输入要设置的时区（默认 Asia/Shanghai，留空使用默认）: " tz
  [[ -z "$tz" ]] && tz="Asia/Shanghai"
  if ! timedatectl list-timezones | grep -qx "$tz"; then
    red "时区无效：$tz"
    yellow "提示：timedatectl list-timezones 查看可用时区"
    return 1
  fi
  timedatectl set-timezone "$tz"
  green "系统时区已经改为：$tz"
  timedatectl
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 2) Set DNS and lock resolv.conf
# -----------------------------
set_dns_ui() {
  need_root

  if ! command -v curl >/dev/null 2>&1; then
    pkg_update || true
    pkg_install curl || return 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    pkg_update || true
    pkg_install sudo || return 1
  fi

  yellow "将把 DNS 固定为 8.8.8.8 / 1.1.1.1，并对 /etc/resolv.conf 加不可变锁。"
  yellow "注意：这可能影响 systemd-resolved / 网络管理自动更新 DNS。"
  read -rp "确认继续？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
    touch /etc/resolv.conf
  fi

  chattr -i /etc/resolv.conf 2>/dev/null || true

  cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

  chattr +i /etc/resolv.conf
  green "resolv.conf 已设置并锁定"

  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; then
    if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
      yellow "正在禁用 systemd-resolved..."
      systemctl disable --now systemd-resolved || true
      green "systemd-resolved 已禁用"
    fi
  fi

  read -rp "回车返回菜单..." _
}

# -----------------------------
# 3) Swap cache - keep only /swapfile
# -----------------------------
swap_cache() {
  need_root
  local size_mb confirm fs_type keep="/swapfile"

  echo "当前 Swap："
  free -h | awk 'NR==1 || /Swap:/ {print}'
  echo ""

  read -rp "请输入 Swap 大小（MB，建议 >=512）: " size_mb
  [[ "$size_mb" =~ ^[0-9]+$ ]] || { red "请输入有效数字"; return 1; }

  read -rp "确认创建/重建 Swap=${size_mb}MB ? (y/n): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  while read -r sw; do
    [[ -z "$sw" ]] && continue
    [[ "$sw" == "$keep" ]] && continue
    swapoff "$sw" >/dev/null 2>&1 || true
    if [[ -f /etc/fstab ]]; then
      sed -i -E "s|^(\s*${sw//\//\\/}\s+.*\s+swap\s+.*)$|# disabled_by_swap_cache: \1|g" /etc/fstab >/dev/null 2>&1 || true
    fi
    if [[ "$sw" == /* && -f "$sw" ]]; then
      rm -f "$sw" >/dev/null 2>&1 || true
    fi
  done < <(swapon --noheadings --raw --show=NAME 2>/dev/null)

  if swapon --noheadings --raw --show=NAME 2>/dev/null | grep -qx "$keep"; then
    swapoff "$keep" >/dev/null 2>&1 || true
  fi
  rm -f "$keep" >/dev/null 2>&1 || true

  fs_type="$(stat -f -c %T / 2>/dev/null || true)"
  touch "$keep" || { red "无法创建 $keep"; return 1; }

  if [[ "$fs_type" == "btrfs" ]] && command -v chattr >/dev/null 2>&1; then
    chattr +C "$keep" >/dev/null 2>&1 || true
  fi

  if command -v fallocate >/dev/null 2>&1; then
    if ! fallocate -l "${size_mb}M" "$keep" 2>/dev/null; then
      yellow "fallocate 失败，改用 dd 创建（会慢一点）"
      dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress || { red "dd 创建失败"; rm -f "$keep"; return 1; }
    fi
  else
    yellow "系统无 fallocate，使用 dd 创建（会慢一点）"
    dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress || { red "dd 创建失败"; rm -f "$keep"; return 1; }
  fi

  chmod 600 "$keep" || { red "chmod 600 失败"; rm -f "$keep"; return 1; }
  mkswap "$keep" >/dev/null 2>&1 || { red "mkswap 失败（文件系统可能不支持 swapfile）"; rm -f "$keep"; return 1; }
  swapon "$keep" >/dev/null 2>&1 || { red "swapon 失败（容器限制或文件系统限制）"; rm -f "$keep"; return 1; }

  if ! grep -qE '^\s*/swapfile\s' /etc/fstab 2>/dev/null; then
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
  fi

  green "Swap 已启用（只保留 /swapfile）："
  swapon --show
  free -h | awk 'NR==1 || /Swap:/ {print}'
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 4) IPv4 / IPv6 priority
# -----------------------------
set_ip_priority() {
  need_root
  while true; do
    clear
    echo "设置 v4/v6 优先级"
    echo "------------------------"
    local ipv6_disabled
    ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)
    if [[ "$ipv6_disabled" -eq 1 ]]; then
      echo -e "当前网络优先级: ${YELLOW}IPv4${PLAIN} 优先"
    else
      echo -e "当前网络优先级: ${YELLOW}IPv6${PLAIN} 优先"
    fi
    echo ""
    echo "1. IPv4 优先"
    echo "2. IPv6 优先"
    echo "3. IPv6 修复工具（外部脚本）"
    echo "0. 返回"
    read -rp "选择: " choice
    case "$choice" in
      1) sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true; green "已切换为 IPv4 优先"; sleep 1 ;;
      2) sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true; green "已切换为 IPv6 优先"; sleep 1 ;;
      3) yellow "将运行外部 IPv6 修复脚本（jhb.ovh/jb/v6.sh）"; bash <(curl -fsSL jhb.ovh/jb/v6.sh) || red "脚本执行失败"; read -rp "回车返回..." _ ;;
      0) break ;;
      *) yellow "无效选择"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# 5) Install BBRv3 (Debian/Ubuntu preferred)
# -----------------------------
bbr() {
  set -Eeuo pipefail

  local SYSCTL_FILE="/etc/sysctl.d/99-bbr.conf"

  local G Y R C N
  if [ -t 1 ]; then
    G='\033[32m'
    Y='\033[33m'
    R='\033[31m'
    C='\033[36m'
    N='\033[0m'
  else
    G=''; Y=''; R=''; C=''; N=''
  fi

  info()  { echo -e "${C}[信息]${N} $*"; }
  warn()  { echo -e "${Y}[警告]${N} $*"; }
  error() { echo -e "${R}[错误]${N} $*" >&2; }
  ok()    { echo -e "${G}[完成]${N} $*"; }

  require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
      error "请使用 root 运行"
      return 1
    fi
  }

  pause() {
    echo
    read -r -p "按回车继续..." _
  }

  backup_if_exists() {
    local f="$1"
    if [ -f "$f" ]; then
      cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
    fi
  }

  get_os_id() {
    local id=""
    if [ -r /etc/os-release ]; then
      . /etc/os-release
      id="${ID:-}"
    fi
    echo "$id"
  }

  is_debian_like() {
    local id
    id="$(get_os_id)"
    [[ "$id" == "debian" || "$id" == "ubuntu" ]]
  }

  is_x86_64() {
    [[ "$(uname -m)" == "x86_64" ]]
  }

  bbr_supported() {
    local available
    available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
    echo "$available" | grep -qw bbr
  }

  show_status() {
    local kern cc qdisc headers_status="unknown" available="unknown"

    kern="$(uname -r)"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
    available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"

    if command -v dpkg-query >/dev/null 2>&1; then
      if dpkg-query -W -f='${Status}\n' "linux-headers-$(uname -r)" 2>/dev/null | grep -q '^install ok installed$'; then
        headers_status="installed"
      else
        headers_status="not installed"
      fi
    elif command -v rpm >/dev/null 2>&1; then
      if rpm -q "kernel-headers-$(uname -r)" >/dev/null 2>&1 || rpm -qa | grep -q '^kernel-headers'; then
        headers_status="installed"
      else
        headers_status="not installed"
      fi
    fi

    echo
    echo "内核版本: $kern"
    echo "当前拥塞控制算法: $cc"
    echo "当前队列算法: $qdisc"
    echo "可用拥塞控制算法: $available"
    echo "headers: $headers_status"
    echo
  }

  install_base_packages() {
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y wget gnupg ca-certificates apt-transport-https
    else
      error "当前系统不支持自动安装依赖"
      return 1
    fi
  }

  setup_xanmod_repo() {
    install_base_packages || return 1

    mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
    local keyring="/usr/share/keyrings/xanmod-archive-keyring.gpg"
    local repo_file="/etc/apt/sources.list.d/xanmod-release.list"
    local tmp
    tmp="$(mktemp)"

    if ! wget -qO "$tmp" https://dl.xanmod.org/archive.key; then
      rm -f "$tmp"
      error "下载 XanMod GPG 密钥失败"
      return 1
    fi

    if ! gpg --dearmor -o "$keyring" --yes < "$tmp"; then
      rm -f "$tmp"
      error "导入 XanMod GPG 密钥失败"
      return 1
    fi
    rm -f "$tmp"

    echo "deb [signed-by=${keyring}] https://deb.xanmod.org releases main" > "$repo_file"
    apt-get update -y
  }

  cpu_level_to_flavor() {
    local level="2"
    if grep -qiE 'avx512f|avx512bw|avx512dq|avx512vl' /proc/cpuinfo 2>/dev/null; then
      level="4"
    elif grep -qiE 'avx2|bmi1|bmi2|fma|movbe' /proc/cpuinfo 2>/dev/null; then
      level="3"
    elif grep -qiE 'sse4_2|cx16|popcnt' /proc/cpuinfo 2>/dev/null; then
      level="2"
    else
      level="1"
    fi
    echo "x64v${level}"
  }

  install_bbr_kernel_if_needed() {
    if bbr_supported; then
      info "当前内核已支持 bbr，跳过内核安装"
      return 0
    fi

    warn "当前内核不支持 bbr，需要安装支持 BBR 的内核"

    if ! is_debian_like; then
      error "自动安装仅支持 Debian/Ubuntu"
      return 1
    fi

    if ! is_x86_64; then
      error "自动安装仅支持 x86_64"
      return 1
    fi

    setup_xanmod_repo || return 1

    local flavor pkg
    flavor="$(cpu_level_to_flavor)"
    pkg="linux-xanmod-${flavor}"

    info "准备安装支持 BBR 的 XanMod 内核: ${pkg}"
    if apt-get install -y "$pkg"; then
      update-grub >/dev/null 2>&1 || true
      ok "XanMod 内核安装完成"
    else
      error "XanMod 内核安装失败"
      return 1
    fi

    if bbr_supported; then
      info "当前会话已检测到 bbr 支持"
      return 0
    fi

    warn "新内核已安装，但当前系统可能仍在运行旧内核"
    warn "请先 reboot 重启系统，然后再次执行 bbr"
    return 2
  }

  disable_conflicts() {
    local ts f
    ts="$(date +%Y%m%d_%H%M%S)"

    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
      [ -f "$f" ] || continue
      [ "$f" = "$SYSCTL_FILE" ] && continue

      if grep -Eq '^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=' "$f" 2>/dev/null ||
         grep -Eq '^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=' "$f" 2>/dev/null; then
        backup_if_exists "$f"
        sed -ri \
          -e 's@^[[:space:]]*(net\.core\.default_qdisc[[:space:]]*=.*)$@# disabled by bbr '"$ts"': \1@' \
          -e 's@^[[:space:]]*(net\.ipv4\.tcp_congestion_control[[:space:]]*=.*)$@# disabled by bbr '"$ts"': \1@' \
          "$f"
        warn "已处理可能冲突的配置: $f"
      fi
    done
  }

  write_bbr_config() {
    mkdir -p /etc/sysctl.d
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" <<'EOF'
# Minimal stable BBR config
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  }

  apply_bbr_config() {
    if ! bbr_supported; then
      error "当前内核还不支持 bbr，无法启用"
      return 1
    fi

    disable_conflicts
    write_bbr_config

    if ! sysctl --system >/dev/null; then
      error "sysctl 应用失败"
      return 1
    fi

    local cc qdisc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"

    echo
    echo "最终结果:"
    echo "拥塞控制算法: $cc"
    echo "队列算法: $qdisc"
    echo

    if [ "$cc" = "bbr" ] && [ "$qdisc" = "fq" ]; then
      ok "已成功启用 bbr + fq"
      return 0
    else
      error "结果不符合预期，请检查是否有其他配置覆盖"
      return 1
    fi
  }

  remove_bbr_config() {
    if [ -f "$SYSCTL_FILE" ]; then
      backup_if_exists "$SYSCTL_FILE"
      rm -f "$SYSCTL_FILE"
      sysctl --system >/dev/null 2>&1 || true
      ok "已删除本脚本写入的 BBR 配置: $SYSCTL_FILE"
    else
      warn "未发现本脚本写入的配置文件"
    fi
  }

  install_and_enable_bbr() {
    install_bbr_kernel_if_needed
    local rc=$?
    if [ "$rc" -eq 2 ]; then
      return 0
    elif [ "$rc" -ne 0 ]; then
      return "$rc"
    fi

    apply_bbr_config
  }

  menu() {
    while true; do
      clear
      echo -e "${C}========== BBR 管理菜单 ========== ${N}"
      show_status
      echo "1. 查看当前状态"
      echo "2. 安装支持 BBR 的内核"
      echo "3. 启用 BBR + FQ"
      echo "4. 安装并启用 BBR"
      echo "5. 删除本脚本写入的 BBR 配置"
      echo "0. 退出"
      echo

      local choice
      read -r -p "请输入选择: " choice
      echo

      case "$choice" in
        1)
          show_status
          pause
          ;;
        2)
          install_bbr_kernel_if_needed || true
          pause
          ;;
        3)
          apply_bbr_config || true
          pause
          ;;
        4)
          install_and_enable_bbr || true
          pause
          ;;
        5)
          remove_bbr_config || true
          pause
          ;;
        0)
          return 0
          ;;
        *)
          warn "无效选择"
          sleep 1
          ;;
      esac
    done
  }

  require_root || return 1

  if [ $# -gt 0 ]; then
    case "${1:-}" in
      status)
        show_status
        ;;
      install)
        install_bbr_kernel_if_needed
        ;;
      enable)
        apply_bbr_config
        ;;
      all)
        install_and_enable_bbr
        ;;
      remove)
        remove_bbr_config
        ;;
      menu)
        menu
        ;;
      *)
        echo "用法:"
        echo "  bbr menu     打开菜单"
        echo "  bbr status   查看状态"
        echo "  bbr install  安装支持 BBR 的内核"
        echo "  bbr enable   启用 bbr + fq"
        echo "  bbr all      安装并启用"
        echo "  bbr remove   删除本脚本写入的配置"
        return 1
        ;;
    esac
  else
    menu
  fi
}

# -----------------------------
# 7) Schedule reboot (cron)
# -----------------------------
cron_reboot() {
  need_root
  yellow "将下载定时任务文件到 /etc/cron.d/mdadm，并重启系统。"
  read -rp "确认继续？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  if ! command -v wget >/dev/null 2>&1; then
    pkg_update || true
    pkg_install wget || return 1
  fi

  wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/vps/main/mdadm -O /etc/cron.d/mdadm || {
    red "文件下载失败"
    return 1
  }

  green "文件下载成功：/etc/cron.d/mdadm"
  yellow "即将重启..."
  reboot
}

# -----------------------------
# 8) Change SSH port (default 2222)
# -----------------------------
ssh_port() {
  need_root
  local new_port="$1"
  [[ -z "$new_port" ]] && { red "请提供新的端口号"; return 1; }
  [[ "$new_port" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; return 1; }
  (( new_port >= 1 && new_port <= 65535 )) || { red "端口范围必须 1-65535"; return 1; }

  local SSH_CONFIG="/etc/ssh/sshd_config"
  [[ -f "$SSH_CONFIG" ]] || { red "未找到 $SSH_CONFIG"; return 1; }

  if grep -qE '^[#[:space:]]*Port[[:space:]]+' "$SSH_CONFIG"; then
    sed -i -E "s|^[#[:space:]]*Port[[:space:]]+[0-9]+|Port ${new_port}|g" "$SSH_CONFIG"
  else
    echo "Port ${new_port}" >> "$SSH_CONFIG"
  fi

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || {
    red "重启 SSH 服务失败，请检查日志"
    return 1
  }

  # 如果新端口是 2222，则自动打开防火墙端口
  if [[ "$new_port" -eq 2222 ]]; then
    local firewall_opened=false
    # 检测 firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
      if firewall-cmd --add-port=2222/tcp --permanent &>/dev/null && firewall-cmd --reload &>/dev/null; then
        green "已通过 firewalld 放行端口 2222/tcp"
        firewall_opened=true
      else
        red "firewalld 放行端口失败，请手动检查"
      fi
    # 检测 ufw
    elif command -v ufw &>/dev/null; then
      if ufw allow 2222/tcp &>/dev/null; then
        green "已通过 ufw 放行端口 2222/tcp"
        firewall_opened=true
      else
        red "ufw 放行端口失败，请手动检查"
      fi
    # 检测 iptables
    elif command -v iptables &>/dev/null; then
      if iptables -A INPUT -p tcp --dport 2222 -j ACCEPT; then
        # 尝试持久化 iptables 规则
        if command -v iptables-save &>/dev/null; then
          if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save &>/dev/null
          elif command -v iptables-save >/dev/null && [ -f /etc/iptables/rules.v4 ]; then
            iptables-save > /etc/iptables/rules.v4
          elif command -v service iptables save &>/dev/null; then
            service iptables save &>/dev/null
          else
            yellow "无法自动持久化 iptables 规则，重启后可能失效"
          fi
        fi
        green "已通过 iptables 放行端口 2222/tcp"
        firewall_opened=true
      else
        red "iptables 放行端口失败，请手动检查"
      fi
    else
      yellow "未检测到常见防火墙（firewalld/ufw/iptables），请手动放行端口 2222"
    fi

    green "SSH 端口已经修改为：2222"
    if [[ "$firewall_opened" == true ]]; then
      yellow "防火墙已自动放行端口 2222，请确认 SSH 服务正常运行后再断开当前连接。"
    else
      yellow "请确保防火墙放行该端口，避免被锁在外面。"
    fi
  else
    green "SSH 端口已经修改为：$new_port"
    yellow "请确保防火墙放行该端口，避免被锁在外面。"
  fi

  read -rp "回车返回菜单..." _
}

# -----------------------------
# 9) Firewall (ufw)
# -----------------------------
firewall() {
  need_root

  _check_listen_ports() {
    local ports="$1"
    ports="${ports//,/ }"
    ports="${ports//，/ }"

    local listen_ports
    listen_ports="$(ss -lntuH 2>/dev/null | awk '{print $5}' | sed 's/.*://')"

    local p start end i found any=0
    for p in $ports; do
      [[ -z "$p" ]] && continue
      any=1
      if [[ "$p" =~ ^[0-9]+$ ]]; then
        if echo "$listen_ports" | grep -qx "$p"; then
          echo "  ✅ 端口 $p 正在监听"
        else
          echo "  ❌ 端口 $p 未监听（防火墙放行≠服务已启动）"
        fi
      elif [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
        IFS='-' read -r start end <<< "$p"
        found=0
        for i in "$start" "$(( (start+end)/2 ))" "$end"; do
          if echo "$listen_ports" | grep -qx "$i"; then
            found=1
            break
          fi
        done
        if [[ $found -eq 1 ]]; then
          echo "  ✅ 端口范围 $p 内检测到有端口在监听（抽样）"
        else
          echo "  ❌ 端口范围 $p 内未检测到监听（抽样：$start,$(( (start+end)/2 )),$end）"
        fi
      else
        echo "  ⚠️ 忽略非法端口格式：$p"
      fi
    done
    [[ $any -eq 0 ]] && echo "  （未提供额外端口，略过监听检查）"
  }

  _purge_except_ssh() {
    if ! command -v ufw >/dev/null 2>&1; then
      yellow "未检测到 ufw。"
      return 1
    fi

    local sshp
    sshp="$(get_ssh_port)"
    yellow "将清除除 SSH(${sshp}) 以外的所有 UFW 入站规则（含 v6），SSH tcp/udp 会保留。"
    read -rp "确认执行？输入 YES 继续: " confirm
    [[ "$confirm" == "YES" ]] || { yellow "已取消"; return 0; }

    # 取编号并从大到小删除，避免编号重排影响
    # 只删除“不是 ssh 端口”的规则
    local nums
    nums="$(
      ufw status numbered 2>/dev/null \
      | sed -nE 's/^\[\s*([0-9]+)\]\s+(.+)$/\1|\2/p' \
      | awk -F'|' -v p="$sshp" '
          {
            line=$2
            # 保留 SSH 规则：端口/tcp 或端口/udp，含 (v6)
            if (line ~ ("^" p "/tcp") || line ~ ("^" p "/udp") ) next
            print $1
          }'
    )"

    if [[ -z "$nums" ]]; then
      green "没有需要清除的规则（除了 SSH 外已无其它规则）。"
      return 0
    fi

    # sort -nr 倒序
    while read -r n; do
      [[ -z "$n" ]] && continue
      ufw --force delete "$n" >/dev/null 2>&1 || true
    done < <(echo "$nums" | sort -nr)

    ufw reload >/dev/null 2>&1 || true
    green "清理完成。当前规则如下："
    ufw status numbered
    return 0
  }

  while true; do
    clear
    echo "---------------- 防火墙设置 (ufw) ----------------"
    echo " 1) 开启防火墙并设置放行端口"
    echo " 2) 关闭防火墙"
    echo " 3) 查看当前防火墙状态/规则（并检查监听）"
    echo " 4) 清除除 SSH 以外的所有放行规则"
    echo " 0) 返回上级菜单"
    echo "-------------------------------------------------"
    read -rp " 请选择 [0-4]: " ans

    case "$ans" in
      1)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，尝试安装"
          pkg_update || true
          pkg_install ufw || { red "安装 ufw 失败"; read -rp "回车返回..." _; continue; }
        fi

        local sshp ports base_ports all_ports
        sshp="$(get_ssh_port)"
        base_ports="2222 443 80"
        yellow "当前 SSH 端口：$sshp，将自动放行 tcp/udp 防止失联。"
        yellow "默认额外放行端口：2222、443、80"
        read -rp "请输入需要额外放行的端口（例如：51000-52000，可留空）: " ports

        ufw --force enable
        ufw allow "${sshp}/tcp"
        ufw allow "${sshp}/udp"
        ufw allow "2222/tcp"
        ufw allow "443/tcp"
        ufw allow "80/tcp"

        ports="${ports//,/ }"
        ports="${ports//，/ }"
        all_ports="$(printf '%s\n' $base_ports $ports | awk 'NF && !seen[$1]++ {print $1}')"

        for p in $ports; do
          if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
            local start end
            IFS='-' read -r start end <<< "$p"
            ufw allow "${start}:${end}/tcp"
            ufw allow "${start}:${end}/udp"
          elif [[ "$p" =~ ^[0-9]+$ ]]; then
            ufw allow "${p}/tcp"
            ufw allow "${p}/udp"
          else
            yellow "忽略非法端口格式：$p"
          fi
        done

        ufw reload >/dev/null 2>&1 || true

        echo ""
        ufw status numbered
        echo ""
        yellow "监听检查（用于判断“端口不通”是否其实是服务没起来）："
        _check_listen_ports "$all_ports"
        read -rp "回车返回菜单..." _
        ;;
      2)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，无需关闭。"
          read -rp "回车返回..." _
          continue
        fi
        ufw disable
        ufw status
        read -rp "回车返回菜单..." _
        ;;
      3)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw。"
          read -rp "回车返回..." _
          continue
        fi
        echo ""
        ufw status verbose
        echo ""
        ufw status numbered
        echo ""
        yellow "当前系统监听端口（节选）："
        ss -lntu | head -n 30
        read -rp "回车返回菜单..." _
        ;;
      4)
        _purge_except_ssh
        read -rp "回车返回菜单..." _
        ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}
# -----------------------------
#  系统清理
# -----------------------------
sys_cle() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_cle.sh"
  local script="/root/sys_cle.sh"
  local cron_line='0 0 * * * /bin/bash /root/sys_cle.sh >> /root/sys_cle.cron.log 2>&1'

  # 1) 先下载/更新脚本
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget >/dev/null 2>&1 || true
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$script" || { echo "下载失败"; return 1; }
  else
    wget -qO "$script" "$url" || { echo "下载失败"; return 1; }
  fi
  chmod +x "$script" >/dev/null 2>&1 || true

  # 2) 对话菜单
  echo ""
  echo "=============================="
  echo "sys_cle 管理菜单（已更新脚本）"
  echo "脚本位置: $script"
  echo "=============================="
  echo "1) 添加 cron：每天 00:00 执行"
  echo "2) 删除 cron：移除该定时任务"
  echo "3) 立即执行一次清理"
  echo "4) 查看当前 cron 状态"
  echo "0) 退出"
  echo "------------------------------"
  read -r -p "请选择 [0-4]: " choice

  case "$choice" in
    1)
      # 去重后添加
      ( crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh" ; echo "$cron_line" ) | crontab -
      echo "OK: 已添加每日 00:00 cron"
      ;;
    2)
      # 删除包含 /root/sys_cle.sh 的行
      crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh" | crontab - 2>/dev/null || true
      echo "OK: 已删除 sys_cle 的 cron"
      ;;
    3)
      /bin/bash "$script"
      echo "OK: 已执行一次清理"
      ;;
    4)
      echo "当前 crontab 中与 sys_cle 相关的条目："
      crontab -l 2>/dev/null | grep -F "/root/sys_cle.sh" || echo "（未设置）"
      ;;
    0)
      echo "已退出"
      ;;
    *)
      echo "输入无效：$choice（只允许 0-4）"
      return 1
      ;;
  esac
}
# -----------------------------
#  acme证书清理
# -----------------------------
acme_purge_keep_xui() {
  set +e

  local DOMAIN="${1:-}"

  echo "=============================="
  echo "[INFO] 开始清理 acme.sh 痕迹(保留 x-ui 依赖)"
  [ -n "$DOMAIN" ] && echo "[INFO] 指定域名: $DOMAIN" || echo "[INFO] 未指定域名"
  echo "=============================="

  if [ "$(id -u)" != "0" ]; then
    echo "[ERR] 请使用 root 执行"
    return 1
  fi

  if [ -z "$DOMAIN" ]; then
    echo "[ERR] 必须指定域名，避免误删"
    return 1
  fi

  echo
  echo "[STEP 1] 停止可能占用 80 端口的服务"
  for svc in nginx apache2 httpd caddy; do
    systemctl stop "$svc" 2>/dev/null
  done

  echo
  echo "[STEP 2] 确保 acme.sh 主程序存在"
  if [ ! -f /root/.acme.sh/acme.sh ]; then
    echo "[WARN] /root/.acme.sh/acme.sh 不存在，尝试重装"
    curl -fsSL https://get.acme.sh | sh
    chmod +x /root/.acme.sh/acme.sh 2>/dev/null
  fi

  if [ ! -f /root/.acme.sh/acme.sh ]; then
    echo "[ERR] acme.sh 主程序恢复失败"
    return 1
  fi

  echo
  echo "[STEP 3] 删除域名申请记录"
  /root/.acme.sh/acme.sh --remove -d "$DOMAIN" 2>/dev/null
  rm -rf "/root/.acme.sh/${DOMAIN}"
  rm -rf "/root/.acme.sh/${DOMAIN}_ecc"
  find /root/.acme.sh -maxdepth 1 -name "*${DOMAIN}*" -exec rm -rf {} \; 2>/dev/null

  echo
  echo "[STEP 4] 清理 cron 中与该域名相关项目"
  if crontab -l >/dev/null 2>&1; then
    crontab -l | grep -v "$DOMAIN" | crontab -
  fi

  echo
  echo "[STEP 5] 清理旧证书文件"
  local CERT_PATHS=(
    /etc/nginx/ssl
    /etc/nginx/certs
    /etc/caddy
    /etc/apache2
    /etc/httpd
    /root/cert
    /root/certs
    /etc/x-ui
    /usr/local/x-ui
  )

  for p in "${CERT_PATHS[@]}"; do
    [ -d "$p" ] || continue
    find "$p" -type f 2>/dev/null | grep "$DOMAIN" | while read -r f; do
      rm -f "$f"
      echo "[DEL] $f"
    done
  done

  echo
  echo "[STEP 6] 清理临时文件"
  find /tmp /var/tmp -maxdepth 2 \( -iname "*acme*" -o -iname "*.csr" -o -iname "*${DOMAIN}*" \) 2>/dev/null | while read -r f; do
    rm -rf "$f"
    echo "[DEL] $f"
  done

  echo
  echo "[STEP 7] 验证 x-ui 依赖"
  if [ -f /root/.acme.sh/acme.sh ]; then
    echo "[OK] acme.sh 主程序仍存在"
  else
    echo "[ERR] acme.sh 主程序缺失"
    return 1
  fi

  echo
  echo "[DONE] 清理完成"
}

# -----------------------------
# Menu
# -----------------------------
menu_sys_conf() {
  need_root
  while true; do
    clear
    echo "#############################################################"
    echo -e "# ${tianlan}系统参数配置（sys_conf.sh）#"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${tianlan} 修改时区"
    echo -e " ${GREEN}2.${tianlan} 修改DNS"
    echo -e " ${GREEN}3.${tianlan} 设置缓存"
    echo -e " ${GREEN}4.${tianlan} 设置IPV4/6优先级"
    echo -e " ${GREEN}5.${tianlan} BBR优化"
    echo -e " ${GREEN}6.${tianlan} 设置定时重启"
    echo -e " ${GREEN}7.${tianlan} 修改SSH端口2222"
    echo -e " ${GREEN}8.${tianlan} 设置防火墙"
    echo -e " ${GREEN}9.${tianlan} 系统清理"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回/退出"
    echo ""
    read -rp "请选择 [0-9]: " choice
    case "$choice" in
      1) change_tz ;;
      2) set_dns_ui ;;
      3) swap_cache ;;
      4) set_ip_priority ;;
      5) bbr ;;
      6) cron_reboot ;;
      7) ssh_port 2222 ;;
      8) firewall ;;
      9) sys_cle ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

menu_sys_conf
