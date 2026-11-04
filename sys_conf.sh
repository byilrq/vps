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

msg_ok() { green "$*"; }
msg_err() { red "$*"; }
msg_inf() { skyblue "$*"; }
msg_warn() { yellow "$*"; }


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
change_tz() {
  need_root

  local tz_choice
  local tz

  echo "请选择要设置的时区："
  echo "1. Shanghai"
  echo "2. Tokyo"
  echo "3. Los_Angeles"
  echo "4. Singapore"
  echo "5. Netherlands"
  read -rp "请输入选项 [1-5]（默认 1）: " tz_choice

  [[ -z "$tz_choice" ]] && tz_choice="1"

  case "$tz_choice" in
    1)
      tz="Asia/Shanghai"
      ;;
    2)
      tz="Asia/Tokyo"
      ;;
    3)
      tz="America/Los_Angeles"
      ;;
    4)
      tz="Asia/Singapore"
      ;;
    5)
      tz="Europe/Amsterdam"
      ;;
    *)
      red "无效选项：$tz_choice"
      return 1
      ;;
  esac

  if command -v timedatectl >/dev/null 2>&1 && timedatectl list-timezones >/dev/null 2>&1; then
    if ! timedatectl list-timezones | grep -qx "$tz"; then
      red "时区无效：$tz"
      yellow "提示：timedatectl list-timezones 查看可用时区"
      return 1
    fi
    timedatectl set-timezone "$tz"
  else
    if [[ ! -f "/usr/share/zoneinfo/$tz" ]]; then
      red "时区无效：$tz"
      yellow "提示：ls /usr/share/zoneinfo/ 查看可用时区"
      return 1
    fi
    ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
  fi

  green "系统时区已经改为：$tz"
  [[ -x "$(command -v timedatectl)" ]] && timedatectl || date '+%Z'

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
# 3) Swap - set an absolute target, never increment existing swap
# -----------------------------
swap_cache() (
  need_root || exit 1

  local keep="/swapfile" size_mb confirm cur_file_mb
  local used_kb used_mb available_mb bridge_mb free_mb need_mb
  local stage="" old_backup="" fstab_backup="" fstab_temp=""
  local stage_active=0 new_active=0 new_created=0 old_saved=0 fstab_changed=0 committed=0
  local fs_type stamp sw i is_active rc
  local -a old_swaps=()

  # The function runs in a subshell: traps and transient state cannot leak into other menus.
  swap_make_file() {
    local path="$1" mb="$2" kind
    kind="$(stat -f -c %T "$(dirname "$path")" 2>/dev/null)" || return 1
    (umask 077; : > "$path") || return 1
    chmod 600 "$path" || return 1
    if [[ "$kind" == "btrfs" ]]; then
      if ! command -v chattr >/dev/null 2>&1 || ! chattr +C "$path" >/dev/null 2>&1; then
        red "Btrfs 文件无法设置 NOCOW，已中止以免创建不可用的 SWAP。"
        return 1
      fi
    fi
    if ! command -v fallocate >/dev/null 2>&1 || ! fallocate -l "${mb}M" "$path" 2>/dev/null; then
      yellow "fallocate 不可用，改用 dd 创建 ${mb} MiB 文件。"
      dd if=/dev/zero of="$path" bs=1M count="$mb" conv=fsync status=none || return 1
    fi
    [[ "$(stat -c %s "$path" 2>/dev/null)" == "$((mb * 1048576))" ]] || return 1
    mkswap "$path" >/dev/null 2>&1 || return 1
  }

  swap_is_active() {
    awk -v name="$1" 'NR>1 && $1==name {found=1} END {exit !found}' /proc/swaps
  }

  # Report total active swap usage, including partitions and files.
  # /proc/swaps uses KiB; keep percentages accurate for multi-swap systems.
  swap_show_usage() {
    local label="$1" summary
    if [[ ! -r /proc/swaps ]]; then
      yellow "${label} SWAP：无法读取占用率（/proc/swaps 不可用）"
      return 0
    fi
    summary="$(awk '
      NR > 1 {total += $3; used += $4}
      END {
        pct = (total > 0 ? 100 * used / total : 0)
        printf "总量 %.1f MiB，已用 %.1f MiB，占用率 %.2f%%", total / 1024, used / 1024, pct
      }
    ' /proc/swaps)" || return 0
    green "${label} SWAP：${summary}"
  }

  swap_rollback() {
    rc="$1"
    trap - EXIT HUP INT TERM
    (( committed == 1 )) && return 0
    yellow "SWAP 设置未完成，正在尽可能恢复原状态..."

    if (( fstab_changed == 1 )) && [[ -f "$fstab_backup" ]]; then
      cp -p "$fstab_backup" /etc/fstab || red "无法自动恢复 /etc/fstab，请检查备份 $fstab_backup"
    fi
    if (( new_active == 1 )); then
      if ! swapoff "$keep" 2>/dev/null; then
        red "新的 $keep 无法停用，保留文件和原备份；请人工检查 swapon --show。"
        return 0
      fi
    fi
    if (( new_created == 1 )); then
      rm -f -- "$keep"
    fi
    if (( old_saved == 1 )) && [[ -f "$old_backup" ]]; then
      mv -f -- "$old_backup" "$keep" || red "无法还原旧 SWAP 文件：$old_backup"
    fi
    for sw in "${old_swaps[@]}"; do
      if ! swap_is_active "$sw"; then
        swapon "$sw" 2>/dev/null || red "无法重新启用旧 SWAP：$sw"
      fi
    done
    if (( stage_active == 1 )); then
      if ! swapoff "$stage" 2>/dev/null; then
        red "临时 SWAP 无法停用，请检查：$stage"
      else
        stage_active=0
      fi
    fi
    if (( stage_active == 0 )) && [[ -n "$stage" ]]; then
      rm -f -- "$stage"
    fi
    [[ -n "$fstab_temp" ]] && rm -f -- "$fstab_temp"
    red "未完成目标设置。请通过 swapon --show 检查当前 SWAP。"
    swap_show_usage "失败回滚后"
    return 0
  }

  echo "当前 SWAP："
  swapon --show 2>/dev/null || true
  free -h | awk 'NR==1 || /Swap:/ {print}'
  swap_show_usage "修改前"
  echo ""
  echo "输入的是最终目标容量，不是在现有 SWAP 上增加。"
  echo "单位：MiB（通常简称 MB），最小 512；例如 512 / 1024 / 1536 / 2048。"
  echo "输入 q 可取消。"
  while true; do
    read -rp "请输入最终 SWAP 容量（MB，最小 512）: " size_mb || return 0
    case "$size_mb" in
      q|Q) yellow "已取消"; return 0 ;;
    esac
    if [[ ! "$size_mb" =~ ^[0-9]{1,7}$ ]]; then
      red "请输入不小于 512 的整数 MB。"
      continue
    fi
    size_mb=$((10#$size_mb))
    if (( size_mb < 512 )); then
      red "最小允许 512 MB，不能输入 $size_mb MB。"
      continue
    fi
    break
  done

  [[ -r /proc/swaps ]] || { red "无法读取 /proc/swaps，无法安全设置。"; return 1; }
  [[ ! -L "$keep" ]] || { red "$keep 是符号链接，拒绝覆盖。"; return 1; }
  [[ ! -e "$keep" || -f "$keep" ]] || { red "$keep 不是普通文件，拒绝覆盖。"; return 1; }
  [[ -f /etc/fstab ]] || { red "未找到 /etc/fstab，拒绝修改。"; return 1; }
  for sw in swapon swapoff mkswap awk stat df cp mv mktemp; do
    command -v "$sw" >/dev/null 2>&1 || { red "缺少必需命令：$sw"; return 1; }
  done

  mapfile -t old_swaps < <(awk 'NR>1 {print $1}' /proc/swaps)
  used_kb="$(awk 'NR>1 {sum+=$4} END {printf "%.0f", sum+0}' /proc/swaps)"
  used_mb=$(( (used_kb + 1023) / 1024 ))
  available_mb="$(awk '/^MemAvailable:/ {printf "%.0f", $2/1024}' /proc/meminfo)"
  [[ "$available_mb" =~ ^[0-9]+$ ]] || available_mb=0
  bridge_mb=$((used_mb + 128))
  (( bridge_mb < 512 )) && bridge_mb=512

  if (( size_mb + available_mb < used_mb + 64 )); then
    red "当前已用 SWAP 约 ${used_mb}MiB、可用内存约 ${available_mb}MiB；目标 ${size_mb}MiB 可能无法容纳。"
    yellow "请先降低内存占用，避免缩小 SWAP 时导致内存耗尽。"
    return 1
  fi
  free_mb="$(df -Pm / | awk 'NR==2 {print $4}')"
  [[ "$free_mb" =~ ^[0-9]+$ ]] || { red "无法读取磁盘剩余空间。"; return 1; }
  need_mb=$((size_mb + bridge_mb + 64))
  if (( free_mb < need_mb )); then
    red "磁盘空间不足：至少需要约 ${need_mb}MiB 空闲，当前仅 ${free_mb}MiB。"
    yellow "采用安全过渡方案，不会先删除正在使用的 SWAP 文件。"
    return 1
  fi

  cur_file_mb=0
  if [[ -f "$keep" ]]; then
    cur_file_mb=$(( $(stat -c %s "$keep") / 1048576 ))
  fi
  if (( ${#old_swaps[@]} == 1 )) && [[ "${old_swaps[0]}" == "$keep" ]] &&
     [[ -f "$keep" ]] && [[ "$(stat -c %s "$keep")" == "$((size_mb * 1048576))" ]]; then
    green "当前已是唯一活动 SWAP，文件大小正好 ${size_mb}MiB，无需增加或重建。"
    swap_show_usage "修改后（无需变更）"
    return 0
  fi

  echo ""
  echo "目标文件：$keep（${size_mb}MiB）"
  echo "当前活跃 SWAP：${#old_swaps[@]} 个；当前已用约 ${used_mb}MiB"
  echo "安全过渡临时 SWAP：${bridge_mb}MiB（完成后自动关闭和删除）"
  yellow "本操作会停用其他活动 SWAP，并注释 /etc/fstab 中其余 SWAP 项。"
  yellow "原有其他 SWAP 文件或分区不会被删除；重启后也只自动启用 /swapfile。"
  read -rp "确认将 SWAP 最终设置为 ${size_mb}MiB？(y/N): " confirm || return 0
  [[ "$confirm" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  stamp="$(date +%Y%m%d_%H%M%S)"
  stage="/swapfile.sysconf-stage-${stamp}-$$"
  old_backup="/swapfile.sysconf-old-${stamp}-$$"
  fstab_backup="/etc/fstab.sysconf-swap-${stamp}-$$.bak"
  trap 'swap_rollback "$?"' EXIT
  trap 'exit 1' HUP INT TERM

  cp -p /etc/fstab "$fstab_backup" || { red "无法备份 /etc/fstab"; exit 1; }
  echo "[1/5] 创建过渡 SWAP ..."
  swap_make_file "$stage" "$bridge_mb" || { red "临时 SWAP 创建失败。"; exit 1; }
  swapon "$stage" || { red "临时 SWAP 启用失败。"; exit 1; }
  stage_active=1

  echo "[2/5] 停用原有 SWAP ..."
  for sw in "${old_swaps[@]}"; do
    if ! swapoff "$sw"; then
      red "无法停用旧 SWAP：$sw，已取消本次设置，防止容量叠加。"
      exit 1
    fi
  done
  if [[ -e "$keep" ]]; then
    mv -- "$keep" "$old_backup" || { red "无法保存原有 $keep"; exit 1; }
    old_saved=1
  fi

  echo "[3/5] 创建新 SWAP（目标 ${size_mb}MiB）..."
  new_created=1
  swap_make_file "$keep" "$size_mb" || { red "目标 SWAP 文件创建失败。"; exit 1; }
  swapon "$keep" || { red "目标 SWAP 启用失败。"; exit 1; }
  new_active=1

  echo "[4/5] 更新开机配置 ..."
  fstab_temp="$(mktemp /etc/.fstab.sysconf-swap.XXXXXX)" || exit 1
  awk '
    /^[[:space:]]*#/ {print; next}
    NF >= 3 && $3 == "swap" {
      if ($1 == "/swapfile") {
        if (!found) {print "/swapfile none swap sw 0 0"; found=1}
      } else {
        print "# disabled_by_sys_conf_swap: " $0
      }
      next
    }
    {print}
    END {if (!found) print "/swapfile none swap sw 0 0"}
  ' /etc/fstab > "$fstab_temp" || exit 1
  chmod --reference=/etc/fstab "$fstab_temp" || exit 1
  chown --reference=/etc/fstab "$fstab_temp" || exit 1
  mv -f -- "$fstab_temp" /etc/fstab || { red "更新 /etc/fstab 失败。"; exit 1; }
  fstab_temp=""
  fstab_changed=1

  echo "[5/5] 停用过渡 SWAP 并校验最终容量 ..."
  if ! swapoff "$stage"; then
    red "临时 SWAP 无法停用，未达到目标容量；尝试恢复原状态。"
    exit 1
  fi
  stage_active=0
  rm -f -- "$stage"

  if ! swap_is_active "$keep" || [[ "$(awk 'END {print NR-1}' /proc/swaps)" != "1" ]] ||
     [[ "$(stat -c %s "$keep")" != "$((size_mb * 1048576))" ]]; then
    red "最终状态不符合预期，尝试恢复原状态。"
    exit 1
  fi
  committed=1
  trap - EXIT HUP INT TERM
  [[ "$old_saved" == 0 ]] || rm -f -- "$old_backup" || yellow "旧文件备份清理失败：$old_backup"

  green "已完成：最终 SWAP 文件大小 = ${size_mb}MiB（非增量）。"
  echo "注意：系统显示的可用 SWAP 容量可能因文件头预留而略小于 ${size_mb}MiB。"
  echo "fstab 原始备份：$fstab_backup"
  swapon --show
  free -h | awk 'NR==1 || /Swap:/ {print}'
  swap_show_usage "修改后"
  read -rp "回车返回菜单..." _ || true
)

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

    mkdir -p /etc/apt/keyrings /etc/apt/sources.list.d
    local keyring="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
    local repo_file="/etc/apt/sources.list.d/xanmod-release.list"
    local tmp codename
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

    codename=""
    if [ -r /etc/os-release ]; then
      . /etc/os-release
      codename="${VERSION_CODENAME:-}"
    fi
    if [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1; then
      codename="$(lsb_release -sc 2>/dev/null || true)"
    fi
    if [ -z "$codename" ]; then
      error "无法识别系统发行版代号，不能配置 XanMod 源"
      return 1
    fi

    echo "deb [signed-by=${keyring}] http://deb.xanmod.org ${codename} main" > "$repo_file"
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

    local flavor pkg fallback_pkgs cand
    flavor="$(cpu_level_to_flavor)"
    pkg="linux-xanmod-${flavor}"

    if ! apt-cache show "$pkg" >/dev/null 2>&1; then
      warn "仓库中未找到 ${pkg}，尝试选择可用的 XanMod 内核包"

      local level
      level="${flavor#x64v}"

      fallback_pkgs="linux-xanmod-${flavor} linux-xanmod-lts-${flavor}"
      case "$level" in
        4)
          fallback_pkgs="$fallback_pkgs linux-xanmod-x64v4 linux-xanmod-lts-x64v4 linux-xanmod-x64v3 linux-xanmod-lts-x64v3 linux-xanmod-x64v2 linux-xanmod-lts-x64v2 linux-xanmod-x64v1 linux-xanmod-lts-x64v1 linux-xanmod"
          ;;
        3)
          fallback_pkgs="$fallback_pkgs linux-xanmod-x64v3 linux-xanmod-lts-x64v3 linux-xanmod-x64v2 linux-xanmod-lts-x64v2 linux-xanmod-x64v1 linux-xanmod-lts-x64v1 linux-xanmod"
          ;;
        2)
          fallback_pkgs="$fallback_pkgs linux-xanmod-x64v2 linux-xanmod-lts-x64v2 linux-xanmod-x64v1 linux-xanmod-lts-x64v1 linux-xanmod"
          ;;
        *)
          fallback_pkgs="$fallback_pkgs linux-xanmod-x64v1 linux-xanmod-lts-x64v1 linux-xanmod"
          ;;
      esac

      pkg=""
      for cand in $fallback_pkgs; do
        if apt-cache show "$cand" >/dev/null 2>&1; then
          pkg="$cand"
          break
        fi
      done

      if [ -z "$pkg" ]; then
        error "未找到可安装的 XanMod 内核包，请检查 XanMod 源是否支持当前系统版本"
        return 1
      fi

      info "已选择可用的 XanMod 内核包: ${pkg}"
    fi

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
        base_ports="2222 443 80 8443 2053 8183 8196 8168"
        yellow "当前 SSH 端口：$sshp，将自动放行 tcp/udp 防止失联。"
        yellow "默认额外放行端口：2222、443(TCP+UDP)、80、8443、2053、8183、8196、8168 (其余TCP)"
        read -rp "请输入需要额外放行的端口（例如：51000-52000，可留空）: " ports

        ufw --force enable
        ufw allow "${sshp}/tcp"
        ufw allow "${sshp}/udp"
        ufw allow "2222/tcp"
        ufw allow "443/tcp"
        ufw allow "80/tcp"
        # HTTPS/3 QUIC and the previously requested service ports.
        ufw allow "443/udp"
        local default_tcp_port
        for default_tcp_port in 8443 2053 8183 8196 8168; do
          ufw allow "${default_tcp_port}/tcp"
        done

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
#  设置 SSH 登录方式
# -----------------------------
auth_key() {
    local target_user="${1:-root}"
    local target_group user_home ssh_dir ak pubkey cfg bak choice new_pass
    local sshd_bin cloud_cfg cloud_bak

    if [[ $EUID -ne 0 ]]; then
        msg_err "请使用 root 权限执行此函数。"
        return 1
    fi

    user_home="$(getent passwd "$target_user" | cut -d: -f6)"
    target_group="$(id -gn "$target_user" 2>/dev/null)"
    target_group="${target_group:-$target_user}"

    cfg="/etc/ssh/sshd_config"
    cloud_cfg="/etc/ssh/sshd_config.d/50-cloud-init.conf"
    sshd_bin="$(command -v sshd 2>/dev/null)"

    if [[ -z "$user_home" || ! -d "$user_home" ]]; then
        msg_err "找不到用户或家目录：$target_user"
        return 1
    fi

    if [[ ! -f "$cfg" ]]; then
        msg_err "找不到 SSH 配置文件：$cfg"
        return 1
    fi

    _auth_key_backup_cfg() {
        bak="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$cfg" "$bak" || return 1
    }

    _auth_key_backup_cloud_cfg() {
        if [[ -f "$cloud_cfg" ]]; then
            cloud_bak="${cloud_cfg}.bak.$(date +%Y%m%d-%H%M%S)"
            cp -a "$cloud_cfg" "$cloud_bak" || return 1
        fi
    }

    _auth_key_set_cfg() {
        local key="$1"
        local value="$2"

        if grep -qE "^[#[:space:]]*${key}[[:space:]]+" "$cfg"; then
            sed -i -E "s#^[#[:space:]]*${key}[[:space:]].*#${key} ${value}#g" "$cfg"
        else
            echo "${key} ${value}" >> "$cfg"
        fi
    }

    _auth_key_set_cloud_password_auth() {
        local value="$1"

        mkdir -p /etc/ssh/sshd_config.d || return 1

        if [[ -f "$cloud_cfg" ]]; then
            _auth_key_backup_cloud_cfg || return 1
        fi

        cat > "$cloud_cfg" <<EOF
PasswordAuthentication ${value}
EOF
    }

    _auth_key_restore_on_fail() {
        [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$cfg"
        [[ -n "$cloud_bak" && -f "$cloud_bak" ]] && cp -a "$cloud_bak" "$cloud_cfg"
    }

    _auth_key_check_and_restart() {
        if [[ -n "$sshd_bin" ]]; then
            if ! "$sshd_bin" -t -f "$cfg" >/dev/null 2>&1; then
                _auth_key_restore_on_fail
                msg_err "sshd_config 校验失败，已恢复备份。"
                return 1
            fi
        fi

        if systemctl restart ssh >/dev/null 2>&1 \
            || systemctl restart sshd >/dev/null 2>&1 \
            || service ssh restart >/dev/null 2>&1 \
            || service sshd restart >/dev/null 2>&1; then
            return 0
        fi

        _auth_key_restore_on_fail
        msg_err "SSH 服务重启失败，已恢复备份。"
        return 1
    }

    _auth_key_gen_password() {
        local upper lower digit special all result

        upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower='abcdefghijklmnopqrstuvwxyz'
        digit='0123456789'
        special='$%*&#'
        all="${upper}${lower}${digit}${special}"

        # 用 openssl 生成随机字节，保证更强的随机性
        _pick_one() {
            local chars="$1"
            local idx
            idx=$(od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' ')
            idx=$(( idx % ${#chars} ))
            printf '%s' "${chars:$idx:1}"
        }

        result="$(_pick_one "$upper")"
        result+="$(_pick_one "$lower")"
        result+="$(_pick_one "$digit")"
        result+="$(_pick_one "$special")"

        while [[ ${#result} -lt 16 ]]; do
            result+="$(_pick_one "$all")"
        done

        # 最终打乱顺序：将每个字符转为一行后用 sort -R（比 fold|shuf 更随机）
        printf '%s' "$result" | grep -o . | sort -R | tr -d '\n'
    }

    while true; do
        echo "=============================="
        echo " SSH 管理用户：$target_user"
        echo " 1. 仅 SSH 密钥登录"
        echo " 2. 仅 SSH 密码登录"
        echo " 3. 重置 SSH 密码"
        echo " 0. 返回上一级"
        echo "=============================="
        read -rp "请选择 [0-3]： " choice

        bak=""
        cloud_bak=""

        case "$choice" in
            1)
                echo "请输入公钥字符串（一整行，以 ssh-ed25519/ssh-rsa/ecdsa... 开头）："
                read -r pubkey

                if ! printf '%s\n' "$pubkey" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+([[:space:]].*)?$'; then
                    msg_err "公钥格式不正确。"
                    echo
                    continue
                fi

                ssh_dir="$user_home/.ssh"
                ak="$ssh_dir/authorized_keys"

                mkdir -p "$ssh_dir" || { msg_err "创建 .ssh 目录失败。"; echo; continue; }
                chmod 700 "$ssh_dir"
                touch "$ak" || { msg_err "创建 authorized_keys 失败。"; echo; continue; }
                chmod 600 "$ak"
                chown -R "$target_user:$target_group" "$ssh_dir"

                if ! awk '{print $1" "$2}' "$ak" | grep -Fxq "$(printf '%s\n' "$pubkey" | awk '{print $1" "$2}')"; then
                    printf '%s\n' "$pubkey" >> "$ak"
                fi

                _auth_key_backup_cfg || {
                    msg_err "备份 SSH 配置失败。"
                    echo
                    continue
                }

                _auth_key_set_cfg "PubkeyAuthentication" "yes"
                _auth_key_set_cfg "PasswordAuthentication" "no"
                _auth_key_set_cfg "KbdInteractiveAuthentication" "no"
                _auth_key_set_cfg "ChallengeResponseAuthentication" "no"
                _auth_key_set_cfg "UsePAM" "yes"
                _auth_key_set_cfg "AuthorizedKeysFile" ".ssh/authorized_keys"

                if [[ "$target_user" == "root" ]]; then
                    _auth_key_set_cfg "PermitRootLogin" "yes"
                fi

                _auth_key_set_cloud_password_auth "no" || {
                    msg_err "写入 cloud-init SSH 配置失败。"
                    echo
                    continue
                }

                if _auth_key_check_and_restart; then
                    msg_ok "已切换为仅 SSH 密钥登录。建议保留当前会话，并新开终端先测试登录。"
                fi
                echo
                ;;

            2)
                _auth_key_backup_cfg || {
                    msg_err "备份 SSH 配置失败。"
                    echo
                    continue
                }

                _auth_key_set_cfg "PubkeyAuthentication" "no"
                _auth_key_set_cfg "PasswordAuthentication" "yes"
                _auth_key_set_cfg "KbdInteractiveAuthentication" "no"
                _auth_key_set_cfg "ChallengeResponseAuthentication" "no"
                _auth_key_set_cfg "UsePAM" "yes"

                if [[ "$target_user" == "root" ]]; then
                    _auth_key_set_cfg "PermitRootLogin" "yes"
                fi

                _auth_key_set_cloud_password_auth "yes" || {
                    msg_err "写入 cloud-init SSH 配置失败。"
                    echo
                    continue
                }

                if _auth_key_check_and_restart; then
                    msg_ok "已切换为仅 SSH 密码登录。测试示例：ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no ${target_user}@IP"
                fi
                echo
                ;;

            3)
                echo "=============================="
                echo " 重置 SSH 密码：$target_user"
                echo " 1. 生成随机密码"
                echo " 2. 手动输入密码（可视，支持退格修改）"
                echo " 0. 取消"
                echo "=============================="
                read -rp "请选择 [0-2]： " pass_choice

                case "$pass_choice" in
                    1)
                        new_pass="$(_auth_key_gen_password)"

                        if [[ -z "$new_pass" || ${#new_pass} -ne 16 ]]; then
                            msg_err "生成随机密码失败。"
                            echo
                            continue
                        fi
                        ;;
                    2)
                        while true; do
                            read -e -r -p "请输入新 SSH 密码（可视，支持退格修改）: " new_pass
                            read -e -r -p "请再次输入新 SSH 密码（可视，支持退格修改）: " new_pass_confirm

                            if [[ -z "$new_pass" ]]; then
                                msg_err "密码不能为空，请重新输入。"
                                echo
                                continue
                            fi

                            if [[ "$new_pass" != "$new_pass_confirm" ]]; then
                                msg_err "两次输入的密码不一致，请重新输入。"
                                echo
                                continue
                            fi

                            break
                        done
                        ;;
                    0)
                        msg_warn "已取消重置密码。"
                        echo
                        continue
                        ;;
                    *)
                        msg_err "无效选项，请重新输入。"
                        echo
                        continue
                        ;;
                esac

                if ! printf '%s:%s\n' "$target_user" "$new_pass" | chpasswd; then
                    msg_err "重置密码失败。"
                    echo
                    continue
                fi

                msg_ok "用户 [$target_user] 的 SSH 密码已重置。"
                echo "新密码：$new_pass"

                if grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no\b' "$cfg" \
                    || [[ -f "$cloud_cfg" && -n "$(grep -iE '^[[:space:]]*PasswordAuthentication[[:space:]]+no\b' "$cloud_cfg" 2>/dev/null)" ]]; then
                    echo "注意：当前 SSH 可能未开启密码登录，如需使用密码登录，请执行菜单 2。"
                fi
                echo
                ;;

            0)
                return 0
                ;;

            *)
                msg_err "无效选项，请重新输入。"
                echo
                ;;
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
#  SSH 防爆破：1小时内认证失败6次后永久封禁
# -----------------------------
ssh_fail2ban_guard() {
  need_root

  local jail_name="ssh-permanent-guard"
  local jail_file="/etc/fail2ban/jail.d/ssh-permanent-guard.local"
  local maxretry="6"
  local findtime="3600"
  local bantime="-1"

  _ssh_guard_pause() {
    echo ""
    read -rp "回车返回 SSH 防爆破菜单..." _
  }

  _ssh_guard_install() {
    if command -v fail2ban-client >/dev/null 2>&1; then
      return 0
    fi

    yellow "未检测到 Fail2Ban，正在安装..."
    pkg_update || true
    pkg_install fail2ban || {
      red "Fail2Ban 安装失败。"
      return 1
    }

    # systemd 日志后端需要 python3-systemd；Debian/Ubuntu 尽量自动补齐。
    if command -v apt-get >/dev/null 2>&1; then
      if ! python3 -c 'import systemd.journal' >/dev/null 2>&1; then
        pkg_install python3-systemd >/dev/null 2>&1 || true
      fi
    fi
    return 0
  }

  _ssh_guard_action() {
    if [[ -f /etc/fail2ban/action.d/nftables-allports.conf ]] && command -v nft >/dev/null 2>&1; then
      echo "nftables-allports"
      return 0
    fi

    if [[ -f /etc/fail2ban/action.d/iptables-allports.conf ]]; then
      if ! command -v iptables >/dev/null 2>&1; then
        pkg_install iptables >/dev/null 2>&1 || true
      fi
      if command -v iptables >/dev/null 2>&1; then
        echo "iptables-allports"
        return 0
      fi
    fi

    return 1
  }

  _ssh_guard_write_config() {
    local action_name backend_line logpath_line sshp
    sshp="$(get_ssh_port)"
    action_name="$(_ssh_guard_action)" || {
      red "未找到可用的 Fail2Ban 全端口封禁动作（nftables/iptables）。"
      return 1
    }

    backend_line="backend = systemd"
    logpath_line=""

    if ! command -v journalctl >/dev/null 2>&1 || ! python3 -c 'import systemd.journal' >/dev/null 2>&1; then
      if [[ -f /var/log/auth.log ]]; then
        backend_line="backend = auto"
        logpath_line="logpath = /var/log/auth.log"
      elif [[ -f /var/log/secure ]]; then
        backend_line="backend = auto"
        logpath_line="logpath = /var/log/secure"
      else
        red "无法确定 SSH 登录失败日志来源：systemd journal 不可用，且未找到 auth.log/secure。"
        return 1
      fi
    fi

    mkdir -p /etc/fail2ban/jail.d || return 1
    if [[ -f "$jail_file" ]]; then
      cp -a "$jail_file" "${jail_file}.bak.$(date +%Y%m%d_%H%M%S)" || true
    fi

    cat > "$jail_file" <<EOF
# Managed by sys_conf.sh - SSH permanent guard
# Rule: same IP fails SSH authentication 6 times within 1 hour => permanent ban.
# bantime=-1 means no automatic unban; use the SSH menu to unban manually.
[$jail_name]
enabled = true
filter = sshd
port = $sshp
$backend_line
$logpath_line
findtime = $findtime
maxretry = $maxretry
bantime = $bantime
usedns = no
# Block all TCP and UDP ports from the banned source IP, not only the SSH port.
action = $action_name[name=${jail_name}-tcp, protocol=tcp]
         $action_name[name=${jail_name}-udp, protocol=udp]
EOF

    if ! fail2ban-client -t >/dev/null 2>&1; then
      red "Fail2Ban 配置校验失败，未启用。"
      fail2ban-client -t 2>&1 | tail -n 20
      return 1
    fi

    if command -v systemctl >/dev/null 2>&1; then
      systemctl enable fail2ban >/dev/null 2>&1 || true
      if ! systemctl restart fail2ban; then
        red "Fail2Ban 服务启动/重启失败。"
        return 1
      fi
    else
      service fail2ban restart || {
        red "Fail2Ban 服务启动/重启失败。"
        return 1
      }
    fi

    sleep 1
    if fail2ban-client status "$jail_name" >/dev/null 2>&1; then
      green "SSH 防爆破已启用。"
      echo "规则：同一 IP 在 1 小时内 SSH 认证失败累计 6 次 -> 永久封禁"
      echo "范围：封禁该 IP 对本机全部 TCP/UDP 端口的访问"
      echo "SSH 端口：$sshp"
      echo "封禁时长：永久（仅手动解封）"
      echo "配置文件：$jail_file"
      yellow "注意：如果你自己连续输错密码达到 6 次，也会被永久封禁。"
      return 0
    fi

    red "Fail2Ban 已启动，但未发现 jail：$jail_name"
    fail2ban-client status 2>/dev/null || true
    return 1
  }

  _ssh_guard_status() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
      yellow "Fail2Ban 尚未安装，SSH 防爆破未启用。"
      return 0
    fi

    echo "=============================="
    echo " SSH 防爆破状态"
    echo "=============================="
    if [[ -f "$jail_file" ]]; then
      echo "配置文件：$jail_file"
      echo "规则：1小时内失败 6 次 -> 永久封禁"
    else
      echo "配置文件：未创建"
    fi
    echo ""

    if fail2ban-client status "$jail_name" >/dev/null 2>&1; then
      fail2ban-client status "$jail_name"
    else
      yellow "jail [$jail_name] 当前未运行。"
      fail2ban-client status 2>/dev/null || true
    fi
  }

  _ssh_guard_banned() {
    if ! command -v fail2ban-client >/dev/null 2>&1 || ! fail2ban-client status "$jail_name" >/dev/null 2>&1; then
      yellow "SSH 防爆破当前未运行。"
      return 0
    fi

    local banned
    banned="$(fail2ban-client get "$jail_name" banip 2>/dev/null || true)"
    echo "当前永久封禁 IP："
    if [[ -n "$banned" ]]; then
      printf '%s\n' "$banned"
    else
      echo "（无）"
    fi
  }

  _ssh_guard_unban() {
    if ! command -v fail2ban-client >/dev/null 2>&1 || ! fail2ban-client status "$jail_name" >/dev/null 2>&1; then
      yellow "SSH 防爆破当前未运行。"
      return 0
    fi

    local ip
    read -erp "请输入要解除封禁的 IPv4/IPv6 地址: " ip
    [[ -n "$ip" ]] || { yellow "未输入 IP，已取消。"; return 0; }

    if fail2ban-client set "$jail_name" unbanip "$ip" >/dev/null 2>&1; then
      green "已解除封禁：$ip"
    else
      red "解除封禁失败：$ip（可能未被当前 jail 封禁，或 IP 格式不正确）"
      return 1
    fi
  }

  _ssh_guard_disable() {
    if [[ ! -f "$jail_file" ]]; then
      yellow "未发现本脚本创建的 SSH 防爆破配置，无需关闭。"
      return 0
    fi

    yellow "关闭后，本 jail 当前施加的封禁规则会被移除。"
    read -rp "确认关闭 SSH 防爆破？输入 YES 继续: " confirm
    [[ "$confirm" == "YES" ]] || { yellow "已取消。"; return 0; }

    mv "$jail_file" "${jail_file}.disabled.$(date +%Y%m%d_%H%M%S)"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart fail2ban >/dev/null 2>&1 || true
    else
      service fail2ban restart >/dev/null 2>&1 || true
    fi
    green "SSH 防爆破已关闭。"
  }

  while true; do
    clear
    echo "=========================================="
    echo " SSH 防爆破 / 自动永久封禁"
    echo "=========================================="
    echo " 规则：1小时内 SSH 认证失败 6 次 -> 永久封禁"
    echo " 范围：封禁来源 IP 的全部 TCP/UDP 访问"
    echo ""
    echo " 1. 安装/启用（或更新配置）"
    echo " 2. 查看运行状态"
    echo " 3. 查看已封禁 IP"
    echo " 4. 手动解除封禁 IP"
    echo " 5. 关闭 SSH 防爆破"
    echo " 0. 返回上一级"
    echo "=========================================="
    read -rp "请选择 [0-5]： " guard_choice

    case "$guard_choice" in
      1)
        _ssh_guard_install && _ssh_guard_write_config
        _ssh_guard_pause
        ;;
      2)
        _ssh_guard_status
        _ssh_guard_pause
        ;;
      3)
        _ssh_guard_banned
        _ssh_guard_pause
        ;;
      4)
        _ssh_guard_unban
        _ssh_guard_pause
        ;;
      5)
        _ssh_guard_disable
        _ssh_guard_pause
        ;;
      0)
        return 0
        ;;
      *)
        yellow "无效选项。"
        sleep 1
        ;;
    esac
  done
}

# -----------------------------
#  SSH 设置
# -----------------------------
ssh_settings() {
  need_root
  while true; do
    clear
    echo "=============================="
    echo " SSH 设置"
    echo " 1. 修改 SSH 端口2222"
    echo " 2. 设置 SSH 登录方式"
    echo " 3. SSH 防爆破（1小时失败6次永久封禁）"
    echo " 0. 返回上一级"
    echo "=============================="
    read -rp "请选择 [0-3]： " ssh_choice

    case "$ssh_choice" in
      1) ssh_port 2222 ;;
      2) auth_key root ;;
      3) ssh_fail2ban_guard ;;
      0) return 0 ;;
      *) return 0 ;;
    esac
  done
}

# ============================================
# 函数：修改 Debian/Ubuntu 系统主机名
# 菜单模式：change_hostname（交互式输入）
# 直接调用：change_hostname <新主机名>
# ============================================
change_hostname() {
    local current_hostname new_hostname="${1:-}"
    local hosts_backup="" temp_hosts=""

    if [[ $EUID -ne 0 ]]; then
        red "请使用 root 权限修改主机名"
        return 1
    fi

    current_hostname="$(hostname 2>/dev/null)" || {
        red "无法读取当前主机名"
        return 1
    }
    echo "当前主机名：${current_hostname}"

    # 菜单选择 10 时没有传参，先询问新主机名；带参数调用时直接使用。
    if [[ -z "$new_hostname" ]]; then
        printf "请输入新的主机名（留空取消）: "
        if ! read -er new_hostname; then
            yellow "已取消修改主机名"
            return 0
        fi
        if [[ -z "$new_hostname" ]]; then
            yellow "已取消修改主机名"
            return 0
        fi
    fi

    # Linux 主机名标签：1-63 个字符，字母/数字/连字符，不能以连字符开头或结尾。
    if (( ${#new_hostname} > 63 )) ||
       [[ ! "$new_hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
        red "主机名格式无效：仅允许 1-63 位英文字母、数字和连字符，且不能以连字符开头或结尾"
        return 1
    fi

    if [[ "$new_hostname" == "$current_hostname" ]]; then
        green "主机名已经是 ${new_hostname}，无需修改"
        return 0
    fi

    if ! command -v hostnamectl >/dev/null 2>&1; then
        red "系统未找到 hostnamectl，无法安全修改静态主机名"
        return 1
    fi

    # 先备份并准备 /etc/hosts 的内容，再修改主机名。
    # 仅替换 hosts 中精确匹配的旧主机名，保留其它主机和域名记录。
    if [[ -f /etc/hosts ]]; then
        hosts_backup="/etc/hosts.bak.$(date +%Y%m%d_%H%M%S)"
        cp -a /etc/hosts "$hosts_backup" || {
            red "备份 /etc/hosts 失败，未执行修改"
            return 1
        }
        temp_hosts="$(mktemp)" || {
            red "创建 /etc/hosts 临时文件失败"
            return 1
        }
        if ! awk -v old="$current_hostname" -v new="$new_hostname" '
            BEGIN { mapped = 0 }
            {
                if ($0 !~ /^[[:space:]]*#/ && NF >= 2) {
                    for (i = 2; i <= NF; ++i) {
                        if ($i ~ /^#/) break
                        if ($i == old) {
                            $i = new
                            mapped = 1
                        } else if ($i == new) {
                            mapped = 1
                        }
                    }
                }
                print
            }
            END { if (!mapped) print "127.0.1.1 " new }
        ' /etc/hosts > "$temp_hosts"; then
            rm -f "$temp_hosts"
            red "生成新的 /etc/hosts 内容失败，未执行修改"
            return 1
        fi
    fi

    echo "正在修改主机名：${current_hostname} -> ${new_hostname}"
    if ! hostnamectl set-hostname "$new_hostname"; then
        [[ -n "$temp_hosts" ]] && rm -f "$temp_hosts"
        red "修改系统主机名失败"
        return 1
    fi

    if [[ -n "$temp_hosts" ]]; then
        if ! cat "$temp_hosts" > /etc/hosts; then
            cp -a "$hosts_backup" /etc/hosts >/dev/null 2>&1 || true
            hostnamectl set-hostname "$current_hostname" >/dev/null 2>&1 || true
            rm -f "$temp_hosts"
            red "更新 /etc/hosts 失败，已尝试恢复原来的主机名和 hosts 文件"
            return 1
        fi
        rm -f "$temp_hosts"
        green "/etc/hosts 已更新（原文件备份：${hosts_backup}）"
    fi

    green "主机名修改完成！当前主机名：$(hostname)"
    yellow "如果 SSH 提示符未更新，重新登录即可"
    return 0
}

# ============================================
# 函数：获取当前主机名信息（辅助函数）
# ============================================
show_hostname_info() {
    echo "=========================================="
    echo "📊 主机名信息"
    echo "=========================================="
    echo "内核主机名   : $(hostname)"
    echo "静态主机名   : $(hostnamectl --static 2>/dev/null || echo 'N/A')"
    echo "易读主机名   : $(hostnamectl --pretty 2>/dev/null || echo 'N/A')"
    echo "临时主机名   : $(hostnamectl --transient 2>/dev/null || echo 'N/A')"
    echo "=========================================="
}

# -----------------------------
# 11) 修复站点 nginx 配置 — 重建 quant-* 站点配置，不干扰其他 nginx 用户
# -----------------------------
fix_nginx_site() {
  need_root

  echo "============================================"
  echo "修复站点 nginx 配置"
  echo "提示：此功能用于重建某个服务的 nginx 配置文件"
  echo "（如 quant 的 HTTPS 反代），不修改其他 nginx 站点。"
  echo "============================================"

  local domain="" backend_port="" public_port="" cert_file key_file
  local nginx_conf nginx_link

  read -erp "请输入域名（如 wow.xyrq.de）: " domain
  [ -z "$domain" ] && { red "域名不能为空"; return 1; }

  read -erp "请输入内部服务端口（如 2097）: " backend_port
  [[ "$backend_port" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; return 1; }

  read -erp "请输入对外 HTTPS 端口（如 2096）: " public_port
  [[ "$public_port" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; return 1; }

  cert_file="/etc/letsencrypt/live/${domain}/fullchain.pem"
  key_file="/etc/letsencrypt/live/${domain}/privkey.pem"

  if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
    red "证书文件不存在："
    red "  ${cert_file}"
    red "  ${key_file}"
    yellow "请先使用 certbot 为 ${domain} 申请证书，例如："
    echo "  certbot certonly --standalone -d ${domain}"
    return 1
  fi

  yellow "将创建 nginx 配置："
  echo "  域名：${domain}"
  echo "  反代后端：http://127.0.0.1:${backend_port}"
  echo "  对外端口：${public_port}（HTTPS）"
  echo "  证书：${cert_file}"
  read -erp "确认创建？(y/n): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  nginx_conf="/etc/nginx/sites-available/${domain//./-}-${public_port}.conf"
  nginx_link="/etc/nginx/sites-enabled/${domain//./-}-${public_port}.conf"

  cat > "$nginx_conf" <<EOF
server {
    listen ${public_port} ssl http2;
    listen [::]:${public_port} ssl http2;
    server_name ${domain};

    ssl_certificate     ${cert_file};
    ssl_certificate_key ${key_file};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:${backend_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    return 301 https://\$server_name:${public_port}\$request_uri;
}
EOF

  ln -sf "$nginx_conf" "$nginx_link"
  nginx -t 2>&1 || { red "nginx 配置检查失败，已取消启用"; rm -f "$nginx_link"; return 1; }
  systemctl reload nginx && green "nginx 配置已生效" || red "nginx 重载失败"

  # 放行防火墙端口
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw allow "${public_port}/tcp" >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
    green "UFW 已放行端口 ${public_port}"
  fi

  echo ""
  green "✅ 站点配置完成"
  echo "  访问地址：https://${domain}:${public_port}"
  echo "  配置文件：${nginx_conf}"
  echo ""
  read -erp "回车返回菜单..." _
}

# ---------------------------------------------------------
# 12) TCP BDP buffer tuning (integrated; no external files)
# Runs in a subshell so its strict mode and helper functions
# cannot alter the behavior of other sys_conf.sh menu items.
# ---------------------------------------------------------
tcp_bdp_tune() (
  set -euo pipefail
export LC_ALL=C
umask 077

VERSION='1.0.0'
CONF='/etc/sysctl.d/99-zz-tcp-bdp-lite.conf'
STATE='/var/lib/tcp-bdp-lite'
BASE="$STATE/original.sysctl"
HEADER='# tcp-bdp-lite managed configuration'
KEYS=(
  net.core.rmem_max
  net.core.wmem_max
  net.ipv4.tcp_rmem
  net.ipv4.tcp_wmem
  net.ipv4.tcp_mem
  net.ipv4.tcp_window_scaling
  net.ipv4.tcp_moderate_rcvbuf
)

info() { printf '[i] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }
ask() {
  local __name="$1" prompt="$2" default="$3" input=''
  read -r -p "$prompt" input || :
  printf -v "$__name" '%s' "${input:-$default}"
}
need_root() { (( EUID == 0 )) || die '写入或回滚需要 root，请使用 sudo bash tcp-bdp-lite.sh'; }
check_num() {
  local n="$1" lower="$2" upper="$3" label="$4"
  [[ "$n" =~ ^[1-9][0-9]*$ ]] && ((${#n} <= 6)) && ((n >= lower && n <= upper)) \
    || die "$label 请输入 $lower 到 $upper 的正整数。"
}

# Effective memory = min(MemTotal, cgroup v1/v2 quota if one exists).
mem_kb() {
  local kb cg bytes
  kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
  [[ "$kb" =~ ^[0-9]+$ ]] || die '无法读取 /proc/meminfo'
  for cg in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    [[ -r "$cg" ]] || continue
    read -r bytes < "$cg" || :
    if [[ "$bytes" =~ ^[0-9]+$ ]] && ((${#bytes} <= 16)); then
      # Use awk for large unsigned cgroup numbers without bash overflow.
      kb=$(awk -v old="$kb" -v n="$bytes" 'BEGIN{v=int(n/1024); if(v>0 && v<old) print v; else print old}')
    fi
  done
  printf '%s' "$kb"
}

# Derivation matches the tcpfit 0.5.9 strategy, including RAM/32 cap.
# Goal: 2x BDP + 2 MiB, but never exceed RAM/32 nor 256 MiB; floor 4 MiB.
calculate() {
  local bw="$1" rtt="$2" role="$3" ram_kb="$4" page_size
  check_num "$bw" 1 10000 '带宽 Mbps'
  check_num "$rtt" 1 1000 'RTT ms'
  [[ "$role" == proxy || "$role" == bulk ]] || die '用途只能是 proxy 或 bulk'
  [[ "$ram_kb" =~ ^[0-9]+$ ]] || die '内存读数不合法'
  (( ram_kb >= 262144 )) || die '可用内存不足 256 MiB；出于安全考虑，拒绝自动调优。'
  page_size=$(getconf PAGESIZE) || die '无法获取内存页大小'
  [[ "$page_size" =~ ^[0-9]+$ ]] && (( page_size >= 4096 )) || die '内存页大小异常'

  read -r BDP_BYTES GOAL_BYTES MAX_BYTES DEFAULT_BYTES CAP_BYTES < <(
    awk -v bw="$bw" -v rtt="$rtt" -v m="$ram_kb" -v role="$role" 'BEGIN {
      bdp = bw*1000000*rtt/8000
      goal = 2*bdp + 2097152
      cap = m*1024/32
      if (cap>268435456) cap=268435456
      max=goal
      if (max>cap) max=cap
      if (max<4194304) max=4194304
      def=1048576
      if (role=="bulk") { def=bdp; if(def>8388608) def=8388608; if(def<1048576) def=1048576 }
      if (def>max) def=max
      printf "%.0f %.0f %.0f %.0f %.0f\n", bdp,goal,max,def,cap
    }'
  )
  # tcp_mem is measured in system pages, not bytes.
  read -r MEM_LOW MEM_PRESSURE MEM_MAX < <(
    awk -v m="$ram_kb" -v p="$page_size" 'BEGIN {
      pages=m*1024/p
      a=int(pages/16); b=int(pages/8); c=int(pages/4)
      al=int(16777216/p); bl=int(33554432/p); cl=int(67108864/p)
      if (a<al) a=al; if (b<bl) b=bl; if (c<cl) c=cl
      printf "%.0f %.0f %.0f\n", a,b,c
    }'
  )
  BW="$bw" RTT="$rtt" ROLE="$role" RAM_KB="$ram_kb" PAGE_SIZE="$page_size"
}

mib() { awk -v n="$1" 'BEGIN{printf "%.2f", n/1048576}'; }
show_calc() {
  printf '\n===== BDP 计算结果 =====\n'
  printf '目标带宽           %s Mbps\n' "$BW"
  printf '目标 RTT          %s ms\n' "$RTT"
  printf '用途               %s\n' "$ROLE"
  printf '有效内存           %s MiB\n' "$((RAM_KB / 1024))"
  printf 'BDP               %s MiB\n' "$(mib "$BDP_BYTES")"
  printf '2 x BDP + 2 MiB   %s MiB\n' "$(mib "$GOAL_BYTES")"
  printf '内存保护上限       %s MiB\n' "$(mib "$CAP_BYTES")"
  printf '最终缓冲区上限     %s MiB (%s 字节)\n' "$(mib "$MAX_BYTES")" "$MAX_BYTES"
  printf 'TCP 初始缓冲值    %s MiB (%s 字节)\n' "$(mib "$DEFAULT_BYTES")" "$DEFAULT_BYTES"
  printf 'TCP 内存阈值      %s / %s / %s 页\n' "$MEM_LOW" "$MEM_PRESSURE" "$MEM_MAX"
  if (( MAX_BYTES < GOAL_BYTES )); then
    warn '缓冲区上限受到内存预算约束；如小于实际路径需求，单线程无法保证跑满目标带宽。'
  fi
  if (( MAX_BYTES < BDP_BYTES )); then
    warn '缓冲区上限甚至低于目标 BDP；建议降低目标带宽或在更大内存机器上测试。'
  fi
  printf '\n只修改 7 个 TCP 缓冲/窗口 sysctl；不改 BBR/fq、路由、initcwnd、整形。\n'
}

# Capture and restore only keys owned by this script.
read_value() { sysctl -n "$1" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//;s/ *$//'; }
validate_keys() {
  local key
  for key in "${KEYS[@]}"; do
    sysctl -n "$key" >/dev/null 2>&1 || die "当前内核不支持 $key；没有修改任何内容。"
  done
}
save_live() {
  local file="$1" key value
  : > "$file"
  for key in "${KEYS[@]}"; do
    value=$(read_value "$key") || return 1
    [[ "$value" =~ ^[0-9]+(\ [0-9]+)*$ ]] || { warn "无法安全备份 $key: $value"; return 1; }
    printf '%s|%s\n' "$key" "$value" >> "$file"
  done
}
restore_live() {
  local file="$1" key value failed=0
  while IFS='|' read -r key value; do
    [[ -n "$key" ]] || continue
    [[ " ${KEYS[*]} " == *" $key "* ]] || { warn "跳过未知参数: $key"; failed=1; continue; }
    [[ "$value" =~ ^[0-9]+(\ [0-9]+)*$ ]] || { warn "备份值异常: $key"; failed=1; continue; }
    sysctl -q -w "$key=$value" || failed=1
  done < "$file"
  (( failed == 0 ))
}
write_config() {
  local output="$1"
  cat > "$output" <<TEXT
$HEADER
# version=$VERSION bandwidth=${BW}Mbps rtt=${RTT}ms role=$ROLE
# BDP=${BDP_BYTES} bytes, target 2xBDP+2MiB=${GOAL_BYTES} bytes
# RAM budget limits each buffer to ${CAP_BYTES} bytes; effective max ${MAX_BYTES}
# This override sorts AFTER /etc/sysctl.d/99-tcpfit.conf.
net.core.rmem_max = $MAX_BYTES
net.core.wmem_max = $MAX_BYTES
net.ipv4.tcp_rmem = 4096 $DEFAULT_BYTES $MAX_BYTES
net.ipv4.tcp_wmem = 4096 $DEFAULT_BYTES $MAX_BYTES
net.ipv4.tcp_mem = $MEM_LOW $MEM_PRESSURE $MEM_MAX
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
TEXT
}
apply_values() {
  sysctl -q -w "net.core.rmem_max=$MAX_BYTES" || return 1
  sysctl -q -w "net.core.wmem_max=$MAX_BYTES" || return 1
  sysctl -q -w "net.ipv4.tcp_rmem=4096 $DEFAULT_BYTES $MAX_BYTES" || return 1
  sysctl -q -w "net.ipv4.tcp_wmem=4096 $DEFAULT_BYTES $MAX_BYTES" || return 1
  sysctl -q -w "net.ipv4.tcp_mem=$MEM_LOW $MEM_PRESSURE $MEM_MAX" || return 1
  sysctl -q -w 'net.ipv4.tcp_window_scaling=1' || return 1
  sysctl -q -w 'net.ipv4.tcp_moderate_rcvbuf=1' || return 1
}
check_applied() {
  [[ "$(read_value net.core.rmem_max)" == "$MAX_BYTES" ]] &&
  [[ "$(read_value net.core.wmem_max)" == "$MAX_BYTES" ]] &&
  [[ "$(read_value net.ipv4.tcp_rmem)" == "4096 $DEFAULT_BYTES $MAX_BYTES" ]] &&
  [[ "$(read_value net.ipv4.tcp_wmem)" == "4096 $DEFAULT_BYTES $MAX_BYTES" ]] &&
  [[ "$(read_value net.ipv4.tcp_mem)" == "$MEM_LOW $MEM_PRESSURE $MEM_MAX" ]] &&
  [[ "$(read_value net.ipv4.tcp_window_scaling)" == 1 ]] &&
  [[ "$(read_value net.ipv4.tcp_moderate_rcvbuf)" == 1 ]]
}

# Never destroy the tcpfit snapshot or configuration. This script owns its own file only.
apply() {
  need_root
  validate_keys
  if [[ -f "$CONF" ]] && ! grep -Fxq "$HEADER" "$CONF"; then
    die "$CONF 已存在但不是本脚本创建的文件；为避免覆盖，操作取消。"
  fi
  if [[ -f /etc/sysctl.d/99-tcpfit.conf ]]; then
    warn '检测到 tcpfit：本脚本仅生成独立覆盖文件，不改动 99-tcpfit.conf。以后重跑 tcpfit tune 会暂时覆盖运行值。'
  fi
  mkdir -p -m 0700 "$STATE"
  chmod 0700 "$STATE"
  local live tmp old='' first=0 failed=0
  live=$(mktemp "$STATE/.live.XXXXXX")
  tmp=$(mktemp /etc/sysctl.d/.tcp-bdp-lite.XXXXXX)
  if [[ -f "$CONF" ]]; then
    old=$(mktemp "$STATE/.old.XXXXXX")
    cp -p -- "$CONF" "$old"
  fi
  if ! save_live "$live"; then
    rm -f -- "$live" "$tmp" "${old:-}"
    die '无法保存当前内核参数，操作取消。'
  fi
  # original.sysctl is immutable until rollback; repeated tune preserves first baseline.
  if [[ ! -f "$BASE" ]]; then
    cp -- "$live" "$BASE"
    chmod 0600 "$BASE"
    first=1
  fi
  write_config "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$CONF"
  if ! apply_values || ! check_applied; then
    warn '参数写入或校验失败，正在恢复本次操作前的内核参数和配置。'
    restore_live "$live" || warn '部分内核参数恢复失败，请手动检查。'
    if [[ -n "$old" ]]; then cp -p -- "$old" "$CONF"; else rm -f -- "$CONF"; fi
    (( first == 0 )) || rm -f -- "$BASE"
    failed=1
  fi
  rm -f -- "$live" "${old:-}"
  (( failed == 0 )) || return 1
  ok '已立即生效，并写入开机持久化配置。'
  printf '配置：%s\n首次修改前的备份：%s\n' "$CONF" "$BASE"
  if [[ -f /etc/sysctl.conf ]]; then
    warn '若 /etc/sysctl.conf 存在相同参数，部分系统上的 sysctl --system 可能会覆盖此配置。'
  fi
  info '修改后新建立的 TCP 连接更适合用于测速；不会自动更换正在运行的 TCP 连接。'
}

status() {
  printf '\n===== 当前 TCP 状态 =====\n'
  local key
  for key in "${KEYS[@]}"; do
    printf '%-35s %s\n' "$key" "$(read_value "$key" 2>/dev/null || echo N/A)"
  done
  printf '拥塞控制                          %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo N/A)"
  printf '默认队列                          %s\n' "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo N/A)"
  if [[ -f "$CONF" ]]; then
    printf '\n本脚本持久化配置：%s\n' "$CONF"
    grep '^# version=' "$CONF" || :
  else
    printf '\n本脚本持久化配置：未安装\n'
  fi
  [[ -f "$BASE" ]] && printf '原始备份：%s\n' "$BASE" || :
}

rollback() {
  need_root
  [[ -f "$BASE" ]] || die '没有找到首次修改前的快照，无法自动回滚。'
  if [[ -f "$CONF" ]] && ! grep -Fxq "$HEADER" "$CONF"; then
    die '配置文件的归属标识已改变；为防止误删，拒绝回滚。'
  fi
  local answer
  ask answer '撤销本脚本的 7 个参数修改，并恢复首次执行前快照？[y/N]: ' n
  [[ "$answer" == [yY] ]] || { info '已取消。'; return 0; }
  validate_keys
  local live
  mkdir -p -m 0700 "$STATE"
  live=$(mktemp "$STATE/.rollback.XXXXXX")
  if ! save_live "$live"; then rm -f -- "$live"; die '无法保存回滚前状态。'; fi
  if ! restore_live "$BASE"; then
    warn '回滚未全部成功，恢复回滚前状态。'
    restore_live "$live" || warn '请检查实时 sysctl 参数。'
    rm -f -- "$live"
    return 1
  fi
  rm -f -- "$CONF" "$BASE" "$live"
  ok '已恢复到本脚本首次执行前的实时参数，且移除本脚本的开机配置。'
  info '未动 tcpfit 配置、BBR、fq、路由与原有 initcwnd。'
}

interactive_apply() {
  local b r role_sel role confirm ram
  printf '\n===== TCP BDP 精简调优 =====\n'
  ask b '输入目标带宽 Mbps [1000]: ' 1000
  ask r '输入目标链路 RTT 毫秒 [150]: ' 150
  printf '用途：1) 代理/多并发（默认）  2) 少数大文件传输\n'
  ask role_sel '选择 [1]: ' 1
  case "$role_sel" in 1) role=proxy ;; 2) role=bulk ;; *) die '用途请选择 1 或 2。' ;; esac
  ram=$(mem_kb)
  calculate "$b" "$r" "$role" "$ram"
  show_calc
  ask confirm '确认写入系统并持久化？[y/N]: ' n
  if [[ "$confirm" == [yY] ]]; then apply; else info '未执行任何修改。'; fi
}

usage() {
  cat <<'HELP'
用法：
  sudo bash tcp-bdp-lite.sh             # 交互菜单
  bash tcp-bdp-lite.sh --dry-run 1000 150 proxy
  sudo bash tcp-bdp-lite.sh --apply     # 直接进入输入向导
  bash tcp-bdp-lite.sh --status         # 检查当前参数
  sudo bash tcp-bdp-lite.sh --rollback  # 恢复首次执行前的 7 个参数

说明：脚本只改变 7 个 sysctl 项；不安装 iperf3，不测速，不修改 BBR/fq，
      不修改 tc 整形、initcwnd 或现有 tcpfit 的配置文件。
HELP
}
main() {
  local option ram role choice
  case "${1:-}" in
    --dry-run)
      [[ $# == 4 ]] || { usage; exit 1; }
      ram=$(mem_kb); calculate "$2" "$3" "$4" "$ram"; show_calc
      ;;
    --apply) interactive_apply ;;
    --status) status ;;
    --rollback) rollback ;;
    -h|--help) usage ;;
    '')
      while :; do
        printf '\nTCP BDP Lite v%s\n' "$VERSION"
        printf '1. 根据带宽 + RTT 计算并应用（默认推荐）\n'
        printf '2. 查看当前参数\n'
        printf '3. 回滚到首次调整前\n'
        printf '0. 退出\n'
        ask choice '选择 [1]: ' 1
        case "$choice" in
          1) interactive_apply ;;
          2) status ;;
          3) rollback ;;
          0) break ;;
          *) warn '请选择 0-3。' ;;
        esac
      done
      ;;
    *) usage; exit 1 ;;
  esac
}
main "$@"
)

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
    echo -e " ${GREEN}1.${tianlan} BBR 优化"
    echo -e " ${GREEN}2.${tianlan} 设置firewall"
    echo -e " ${GREEN}3.${tianlan} 设置时区"
    echo -e " ${GREEN}4.${tianlan} 修改 DNS"
    echo -e " ${GREEN}5.${tianlan} 设置 Swap（固定容量，最小512MB）"
    echo -e " ${GREEN}6.${tianlan} 设置 SSH"
    echo -e " ${GREEN}7.${tianlan} 设置系统清理"
    echo -e " ${GREEN}8.${tianlan} 设置IP优先级"
    echo -e " ${GREEN}9.${tianlan} 设置定时重启"
    echo -e " ${GREEN}10.${tianlan} 修改主机名"
    echo -e " ${GREEN}11.${tianlan} 修复站点 nginx 配置（域名+端口）"
    echo -e " ${GREEN}12.${tianlan} TCP BDP 缓冲区调优（带宽 + RTT）"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回/退出"
    echo ""
    read -rp "请选择 [0-12]: " choice
    case "$choice" in
      1) bbr ;;
      2) firewall ;;
      3) change_tz ;;
      4) set_dns_ui ;;
      5) swap_cache ;;
      6) ssh_settings ;;
      7) sys_cle ;;
      8) set_ip_priority ;;
      9) cron_reboot ;;
      10) change_hostname; read -rp "回车返回菜单..." _ ;;
      11) fix_nginx_site ;;
      12) tcp_bdp_tune || red "TCP BDP 操作失败，请检查上方信息" ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

menu_sys_conf
