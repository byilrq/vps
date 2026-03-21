#!/usr/bin/env bash
set -u

SCRIPT_VERSION="1.0.0"
SYSCTL_CONF="/etc/sysctl.d/99-bbr-direct.conf"
AUTO_MODE=""

# Colors
if [ -t 1 ]; then
  gl_bai='\033[0m'
  gl_hong='\033[31m'
  gl_lv='\033[32m'
  gl_huang='\033[33m'
  gl_lan='\033[36m'
  gl_zi='\033[35m'
  gl_kjlan='\033[96m'
else
  gl_bai=''; gl_hong=''; gl_lv=''; gl_huang=''; gl_lan=''; gl_zi=''; gl_kjlan=''
fi

check_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${gl_hong}错误:${gl_bai} 请用 root 运行此脚本"
    echo "用法: sudo bash $0"
    exit 1
  fi
}

break_end() {
  [ "$AUTO_MODE" = "1" ] && return
  echo ""
  echo -e "${gl_lv}操作完成${gl_bai}"
  read -r -n 1 -s -p "按任意键继续..." _
  echo ""
}

install_package() {
  local packages=("$@")
  local missing=()
  local os_id="" os_like=""
  [ -r /etc/os-release ] && . /etc/os-release
  os_id="${ID:-}"
  os_like="${ID_LIKE:-}"

  local p
  for p in "${packages[@]}"; do
    command -v "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  [ ${#missing[@]} -eq 0 ] && return 0

  if [[ "${os_id} ${os_like}" =~ (debian|ubuntu) ]]; then
    apt-get update && apt-get install -y "${missing[@]}"
  elif [[ "${os_id} ${os_like}" =~ (rhel|centos|fedora|rocky|alma) ]]; then
    if command -v dnf >/dev/null 2>&1; then
      dnf makecache && dnf install -y "${missing[@]}"
    else
      yum makecache && yum install -y "${missing[@]}"
    fi
  else
    echo -e "${gl_hong}错误:${gl_bai} 当前发行版不支持自动安装依赖，请手动安装: ${missing[*]}"
    return 1
  fi
}

check_disk_space() {
  local required_gb="$1"
  local required_mb=$((required_gb * 1024))
  local avail_mb
  avail_mb=$(df -Pm / | awk 'NR==2{print $4}')
  if [ -n "$avail_mb" ] && [ "$avail_mb" -lt "$required_mb" ]; then
    echo -e "${gl_huang}警告:${gl_bai} 根分区可用空间不足"
    echo "当前可用: $((avail_mb / 1024))G，建议至少: ${required_gb}G"
    read -r -p "仍然继续吗？(Y/N): " ans
    [[ "$ans" =~ ^[Yy]$ ]]
    return $?
  fi
  return 0
}

check_swap() {
  local swap_total
  swap_total=$(free -m | awk 'NR==3{print $2}')
  if [ "${swap_total:-0}" -eq 0 ]; then
    echo -e "${gl_huang}检测到系统无 SWAP，尝试创建 1024MB /swapfile...${gl_bai}"
    add_swap 1024 || echo -e "${gl_huang}SWAP 创建失败，但不影响继续执行${gl_bai}"
  fi
}

add_swap() {
  local new_swap="$1"
  swapoff /swapfile >/dev/null 2>&1 || true
  rm -f /swapfile
  if ! fallocate -l "$(( (new_swap + 1) * 1024 * 1024 ))" /swapfile 2>/dev/null; then
    dd if=/dev/zero of=/swapfile bs=1M count="$((new_swap + 1))" status=none || return 1
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null 2>&1 || return 1
  swapon /swapfile || return 1
  sed -i '\|/swapfile|d' /etc/fstab
  echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
  echo -e "${gl_lv}已创建 ${new_swap}MB SWAP${gl_bai}"
}

server_reboot() {
  read -r -p "现在重启服务器使配置生效吗？(Y/N): " rboot
  if [[ "$rboot" =~ ^[Yy]$ ]]; then
    reboot
  else
    echo "请稍后手动执行 reboot"
  fi
}

ensure_debian_or_ubuntu() {
  [ -r /etc/os-release ] || { echo -e "${gl_hong}错误:${gl_bai} 无法识别系统"; return 1; }
  . /etc/os-release
  if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" ]]; then
    echo -e "${gl_hong}错误:${gl_bai} XanMod 安装/卸载/更新仅支持 Debian/Ubuntu"
    return 1
  fi
}

ensure_x86_64() {
  local arch
  arch=$(uname -m)
  if [ "$arch" != "x86_64" ]; then
    echo -e "${gl_hong}错误:${gl_bai} 当前脚本的 XanMod 安装/更新/卸载流程仅支持 x86_64，当前为: $arch"
    return 1
  fi
}

setup_xanmod_repo() {
  install_package wget gpg ca-certificates apt-transport-https || return 1
  mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
  local keyring="/usr/share/keyrings/xanmod-archive-keyring.gpg"
  local repo_file="/etc/apt/sources.list.d/xanmod-release.list"
  local tmp
  tmp=$(mktemp) || return 1

  if ! wget -qO "$tmp" https://dl.xanmod.org/archive.key; then
    rm -f "$tmp"
    echo -e "${gl_hong}错误:${gl_bai} 下载 XanMod GPG 密钥失败"
    return 1
  fi
  if ! gpg --dearmor -o "$keyring" --yes < "$tmp"; then
    rm -f "$tmp"
    echo -e "${gl_hong}错误:${gl_bai} 导入 XanMod GPG 密钥失败"
    return 1
  fi
  rm -f "$tmp"

  echo "deb [signed-by=${keyring}] https://deb.xanmod.org releases main" > "$repo_file"
  apt-get update
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

install_xanmod_kernel() {
  clear
  echo -e "${gl_kjlan}=== 安装 XanMod 内核 + BBR v3 ===${gl_bai}"
  echo "支持系统: Debian/Ubuntu x86_64"
  echo -e "${gl_huang}警告:${gl_bai} 安装内核前请先做好快照或备份"
  read -r -p "确定继续安装吗？(Y/N): " choice
  [[ "$choice" =~ ^[Yy]$ ]] || { echo "已取消安装"; return 1; }

  ensure_debian_or_ubuntu || return 1
  ensure_x86_64 || return 1
  check_disk_space 3 || return 1
  check_swap
  setup_xanmod_repo || return 1

  local flavor pkg
  flavor=$(cpu_level_to_flavor)
  pkg="linux-xanmod-${flavor}"

  echo -e "${gl_lan}检测到 CPU 档位: ${flavor}${gl_bai}"
  echo -e "${gl_lan}将安装包: ${pkg}${gl_bai}"

  if apt-get install -y "$pkg"; then
    update-grub >/dev/null 2>&1 || true
    echo -e "${gl_lv}XanMod 内核安装成功${gl_bai}"
    echo -e "${gl_huang}需要重启后新内核才会生效${gl_bai}"
    return 0
  else
    echo -e "${gl_hong}XanMod 内核安装失败${gl_bai}"
    return 1
  fi
}

update_xanmod_kernel() {
  clear
  echo -e "${gl_kjlan}=== 更新 XanMod 内核 ===${gl_bai}"
  ensure_debian_or_ubuntu || { break_end; return 1; }
  ensure_x86_64 || { break_end; return 1; }
  setup_xanmod_repo || { break_end; return 1; }

  local installed_packages
  installed_packages=$(dpkg -l 2>/dev/null | awk '/^ii\s+linux-.*xanmod/ {print $2}')
  if [ -z "$installed_packages" ]; then
    echo -e "${gl_hong}未检测到已安装的 XanMod 内核包${gl_bai}"
    break_end
    return 1
  fi

  echo "当前已安装的 XanMod 包:"
  echo "$installed_packages" | sed 's/^/  - /'
  echo ""
  apt-get update >/dev/null 2>&1 || true
  local upgradable
  upgradable=$(apt list --upgradable 2>/dev/null | grep xanmod || true)
  if [ -z "$upgradable" ]; then
    echo -e "${gl_lv}当前未发现可用更新${gl_bai}"
    echo -e "当前运行内核: ${gl_huang}$(uname -r)${gl_bai}"
    break_end
    return 0
  fi

  echo -e "${gl_huang}发现可用更新:${gl_bai}"
  echo "$upgradable"
  echo ""
  read -r -p "确定更新吗？(Y/N): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "已取消更新"; break_end; return 1; }

  if apt-get install --only-upgrade -y $(echo "$installed_packages" | tr '\n' ' '); then
    update-grub >/dev/null 2>&1 || true
    echo -e "${gl_lv}XanMod 内核更新成功${gl_bai}"
    echo -e "${gl_huang}请重启系统使新内核生效${gl_bai}"
    return 0
  else
    echo -e "${gl_hong}XanMod 内核更新失败${gl_bai}"
    break_end
    return 1
  fi
}

uninstall_xanmod() {
  clear
  echo -e "${gl_kjlan}=== 卸载 XanMod 内核 ===${gl_bai}"
  ensure_debian_or_ubuntu || { break_end; return 1; }

  local non_xanmod_kernels
  non_xanmod_kernels=$(dpkg -l 2>/dev/null | awk '/^ii\s+linux-image-/ && $2 !~ /xanmod/ && $2 !~ /dbg/ {c++} END{print c+0}')
  if [ "$non_xanmod_kernels" -eq 0 ]; then
    echo -e "${gl_hong}安全检查未通过：未检测到可回退的非 XanMod 内核${gl_bai}"
    echo "请先安装默认内核，再执行卸载："
    echo "  Debian: apt install -y linux-image-amd64"
    echo "  Ubuntu: apt install -y linux-image-generic"
    break_end
    return 1
  fi

  echo -e "${gl_lv}检测到 ${non_xanmod_kernels} 个可回退内核，可安全卸载${gl_bai}"
  read -r -p "确定继续卸载吗？(Y/N): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "已取消"; return 1; }

  if apt-get purge -y 'linux-*xanmod*'; then
    rm -f /etc/apt/sources.list.d/xanmod-release.list
    rm -f /usr/share/keyrings/xanmod-archive-keyring.gpg
    update-grub >/dev/null 2>&1 || true
    echo -e "${gl_lv}XanMod 内核包已卸载，软件源已清理${gl_bai}"
    read -r -p "是否同时删除本脚本写入的 BBR 优化配置 ${SYSCTL_CONF} ? (Y/N): " clean_ans
    if [[ "$clean_ans" =~ ^[Yy]$ ]]; then
      rm -f "$SYSCTL_CONF"
      sysctl --system >/dev/null 2>&1 || true
      echo -e "${gl_lv}已清理 BBR 配置文件${gl_bai}"
    fi
    server_reboot
  else
    echo -e "${gl_hong}卸载失败，请手动检查 apt 输出${gl_bai}"
    break_end
    return 1
  fi
}

# ===== BBR direct optimization =====

detect_bandwidth() {
  echo "" >&2
  echo -e "${gl_kjlan}=== 服务器带宽检测 ===${gl_bai}" >&2
  echo "1. 自动检测（speedtest）" >&2
  echo "2. 手动输入带宽" >&2
  echo "3. 预设档位" >&2
  echo "" >&2
  read -r -p "请输入选择 [1]: " bw_choice
  bw_choice=${bw_choice:-1}

  case "$bw_choice" in
    1)
      if ! command -v speedtest >/dev/null 2>&1; then
        echo -e "${gl_huang}未检测到 speedtest，切换到手动输入${gl_bai}" >&2
        bw_choice=2
      else
        echo -e "${gl_huang}正在执行 speedtest，请稍候...${gl_bai}" >&2
        local output upload
        output=$(speedtest --accept-license --accept-gdpr 2>&1 || true)
        echo "$output" >&2
        upload=$(echo "$output" | sed -nE 's/.*Upload:[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)
        if [ -n "$upload" ]; then
          echo "${upload%.*}"
          return 0
        fi
        echo -e "${gl_huang}自动测速失败，切换到手动输入${gl_bai}" >&2
        bw_choice=2
      fi
      ;;
  esac

  case "$bw_choice" in
    2)
      local manual
      while true; do
        read -r -p "请输入上传带宽 Mbps（如 100/500/1000）: " manual
        if [[ "$manual" =~ ^[0-9]+$ ]] && [ "$manual" -gt 0 ]; then
          echo "$manual"
          return 0
        fi
        echo -e "${gl_hong}请输入有效正整数${gl_bai}" >&2
      done
      ;;
    3)
      echo "1) 100   2) 200   3) 300   4) 500   5) 700"
      echo "6) 1000  7) 1500  8) 2000  9) 2500"
      read -r -p "选择档位 [6]: " preset
      case "${preset:-6}" in
        1) echo 100;; 2) echo 200;; 3) echo 300;; 4) echo 500;; 5) echo 700;;
        6) echo 1000;; 7) echo 1500;; 8) echo 2000;; 9) echo 2500;;
        *) echo 1000;;
      esac
      return 0
      ;;
    *)
      echo 1000
      return 0
      ;;
  esac
}

calculate_buffer_size() {
  local bandwidth="$1"
  local region="${2:-asia}"
  local buffer_mb

  if ! [[ "$bandwidth" =~ ^[0-9]+$ ]] || [ "$bandwidth" -le 0 ]; then
    echo 16
    return 0
  fi

  if [ "$region" = "overseas" ]; then
    if [ "$bandwidth" -le 100 ]; then buffer_mb=8
    elif [ "$bandwidth" -le 200 ]; then buffer_mb=16
    elif [ "$bandwidth" -le 300 ]; then buffer_mb=20
    elif [ "$bandwidth" -le 500 ]; then buffer_mb=32
    elif [ "$bandwidth" -le 700 ]; then buffer_mb=48
    else buffer_mb=64
    fi
  else
    if [ "$bandwidth" -le 100 ]; then buffer_mb=6
    elif [ "$bandwidth" -le 200 ]; then buffer_mb=8
    elif [ "$bandwidth" -le 300 ]; then buffer_mb=10
    elif [ "$bandwidth" -le 500 ]; then buffer_mb=12
    elif [ "$bandwidth" -le 700 ]; then buffer_mb=14
    elif [ "$bandwidth" -le 1000 ]; then buffer_mb=16
    elif [ "$bandwidth" -le 1500 ]; then buffer_mb=20
    elif [ "$bandwidth" -le 2000 ]; then buffer_mb=24
    elif [ "$bandwidth" -le 5000 ]; then buffer_mb=28
    else buffer_mb=32
    fi
  fi

  echo -e "${gl_lan}推荐缓冲区: ${buffer_mb}MB（带宽 ${bandwidth} Mbps，地区 ${region}）${gl_bai}" >&2
  read -r -p "是否使用推荐值 ${buffer_mb}MB？(Y/N) [Y]: " confirm
  confirm=${confirm:-Y}
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "$buffer_mb"
  else
    [ "$region" = "overseas" ] && echo 32 || echo 16
  fi
}

check_and_suggest_swap() {
  local mem_total swap_total recommended_swap need_swap=0 confirm
  mem_total=$(free -m | awk 'NR==2{print $2}')
  swap_total=$(free -m | awk 'NR==3{print $2}')

  if [ "$mem_total" -lt 2048 ]; then
    need_swap=1
  elif [ "$mem_total" -lt 4096 ] && [ "$swap_total" -eq 0 ]; then
    need_swap=1
  fi
  [ "$need_swap" -eq 0 ] && return 0

  if [ "$mem_total" -lt 512 ]; then
    recommended_swap=1024
  elif [ "$mem_total" -lt 1024 ]; then
    recommended_swap=$((mem_total * 2))
  elif [ "$mem_total" -lt 2048 ]; then
    recommended_swap=$((mem_total * 3 / 2))
  elif [ "$mem_total" -lt 4096 ]; then
    recommended_swap=$mem_total
  else
    recommended_swap=4096
  fi

  echo -e "${gl_huang}当前内存 ${mem_total}MB，SWAP ${swap_total}MB，推荐设置 ${recommended_swap}MB SWAP${gl_bai}"
  read -r -p "是否现在创建/调整 SWAP？(Y/N): " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    add_swap "$recommended_swap"
  fi
}

clean_sysctl_conf() {
  [ -f /etc/sysctl.conf ] || return 0
  [ -f /etc/sysctl.conf.bak.original ] || cp /etc/sysctl.conf /etc/sysctl.conf.bak.original
  sed -i '/^net\.core\.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
  sed -i '/^net\.core\.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
  sed -i '/^net\.ipv4\.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
  sed -i '/^net\.ipv4\.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
  sed -i '/^net\.core\.default_qdisc/s/^/# /' /etc/sysctl.conf 2>/dev/null
  sed -i '/^net\.ipv4\.tcp_congestion_control/s/^/# /' /etc/sysctl.conf 2>/dev/null
}

check_and_clean_conflicts() {
  local conflicts=() conf base num ans has_sysctl_conflict=0
  for conf in /etc/sysctl.d/[0-9]*-*.conf /etc/sysctl.d/[0-9][0-9][0-9]-*.conf; do
    [ -f "$conf" ] || continue
    [ "$conf" = "$SYSCTL_CONF" ] && continue
    if grep -qE '(^|\s)net\.(ipv4\.tcp_(rmem|wmem)|core\.(rmem_max|wmem_max|default_qdisc))' "$conf" 2>/dev/null; then
      base=$(basename "$conf")
      num=$(echo "$base" | sed -n 's/^\([0-9]\+\).*/\1/p')
      if [ -n "$num" ] && [ "$num" -ge 99 ]; then
        conflicts+=("$conf")
      fi
    fi
  done

  if [ -f /etc/sysctl.conf ] && grep -qE '(^|\s)net\.(ipv4\.tcp_(rmem|wmem)|core\.(rmem_max|wmem_max|default_qdisc|netdev_max_backlog))' /etc/sysctl.conf; then
    has_sysctl_conflict=1
  fi

  if [ ${#conflicts[@]} -eq 0 ] && [ "$has_sysctl_conflict" -eq 0 ]; then
    echo -e "${gl_lv}未发现明显 sysctl 覆盖冲突${gl_bai}"
    return 0
  fi

  echo -e "${gl_huang}发现可能冲突的 sysctl 配置${gl_bai}"
  printf '  - %s\n' "${conflicts[@]}"
  [ "$has_sysctl_conflict" -eq 1 ] && echo '  - /etc/sysctl.conf'
  read -r -p "是否自动注释/禁用这些配置？(Y/N): " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    [ "$has_sysctl_conflict" -eq 1 ] && clean_sysctl_conf
    local f
    for f in "${conflicts[@]}"; do
      mv "$f" "${f}.disabled.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    done
  fi
}

eligible_ifaces() {
  local d dev
  for d in /sys/class/net/*; do
    [ -e "$d" ] || continue
    dev=$(basename "$d")
    case "$dev" in
      lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue ;;
    esac
    echo "$dev"
  done
}

apply_tc_fq_now() {
  command -v tc >/dev/null 2>&1 || { echo -e "${gl_huang}未检测到 tc，跳过即时 fq 应用${gl_bai}"; return 0; }
  local dev applied=0
  while read -r dev; do
    [ -n "$dev" ] || continue
    tc qdisc replace dev "$dev" root fq 2>/dev/null && applied=$((applied+1))
  done < <(eligible_ifaces)
  echo -e "${gl_lv}已对 ${applied} 个网卡应用 fq${gl_bai}"
}

apply_mss_clamp() {
  local action="${1:-enable}"
  command -v iptables >/dev/null 2>&1 || { echo -e "${gl_huang}未检测到 iptables，跳过 MSS clamp${gl_bai}"; return 0; }
  if [ "$action" = "enable" ]; then
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || \
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  else
    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
  fi
}

bbr_configure_direct() {
  clear
  echo -e "${gl_kjlan}=== BBR 直连/落地优化（智能带宽检测） ===${gl_bai}"
  install_package iproute2 procps iptables || true

  echo -e "${gl_zi}[1/6] 检测 SWAP 建议...${gl_bai}"
  check_and_suggest_swap

  echo -e "${gl_zi}[2/6] 检测带宽与缓冲区...${gl_bai}"
  local detected_bandwidth region_choice region buffer_mb buffer_bytes
  detected_bandwidth=$(detect_bandwidth)
  echo ""
  echo "1. 亚太地区（推荐）"
  echo "2. 美国/欧洲"
  read -r -p "请选择主要服务地区 [1]: " region_choice
  case "${region_choice:-1}" in
    2) region="overseas" ;;
    *) region="asia" ;;
  esac
  buffer_mb=$(calculate_buffer_size "$detected_bandwidth" "$region")
  buffer_bytes=$((buffer_mb * 1024 * 1024))

  echo -e "${gl_zi}[3/6] 清理潜在冲突...${gl_bai}"
  clean_sysctl_conf
  check_and_clean_conflicts

  echo -e "${gl_zi}[4/6] 写入优化配置...${gl_bai}"
  local mem_total vm_swappiness=5 vm_dirty_ratio=15 vm_min_free_kbytes=65536
  mem_total=$(free -m | awk 'NR==2{print $2}')
  if [ "$mem_total" -lt 2048 ]; then
    vm_swappiness=20
    vm_dirty_ratio=20
    vm_min_free_kbytes=32768
  fi

  mkdir -p /etc/sysctl.d
  cat > "$SYSCTL_CONF" <<CFG
# Generated by bbr.sh on $(date)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=${buffer_bytes}
net.core.wmem_max=${buffer_bytes}
net.ipv4.tcp_rmem=4096 87380 ${buffer_bytes}
net.ipv4.tcp_wmem=4096 65536 ${buffer_bytes}
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=5000
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_max_tw_buckets=5000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_syncookies=1
vm.swappiness=${vm_swappiness}
vm.dirty_ratio=${vm_dirty_ratio}
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.min_free_kbytes=${vm_min_free_kbytes}
vm.vfs_cache_pressure=50
kernel.sched_autogroup_enabled=0
kernel.numa_balancing=0
CFG

  echo -e "${gl_zi}[5/6] 应用优化参数...${gl_bai}"
  if ! sysctl -p "$SYSCTL_CONF"; then
    echo -e "${gl_huang}部分 sysctl 项可能未被当前内核支持，但已支持项仍然生效${gl_bai}"
  fi
  apply_tc_fq_now
  apply_mss_clamp enable

  if [ -d /etc/systemd/system ]; then
    cat > /usr/local/bin/bbr-optimize-apply.sh <<'APPLYEOF'
#!/usr/bin/env bash
for d in /sys/class/net/*; do
  [ -e "$d" ] || continue
  dev=$(basename "$d")
  case "$dev" in
    lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue ;;
  esac
  tc qdisc replace dev "$dev" root fq 2>/dev/null
 done
if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || \
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
fi
APPLYEOF
    chmod +x /usr/local/bin/bbr-optimize-apply.sh

    cat > /etc/systemd/system/bbr-optimize-persist.service <<'SVCEOF'
[Unit]
Description=Restore BBR optimize qdisc and MSS clamp
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bbr-optimize-apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable bbr-optimize-persist.service >/dev/null 2>&1 || true
  fi

  echo -e "${gl_zi}[6/6] 验证当前状态...${gl_bai}"
  echo "队列算法: $(sysctl -n net.core.default_qdisc 2>/dev/null)"
  echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  echo "发送缓冲区: $(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')"
  echo "接收缓冲区: $(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')"
  echo -e "${gl_lv}BBR 直连/落地优化已完成${gl_bai}"
  echo -e "${gl_lan}配置文件: ${SYSCTL_CONF}${gl_bai}"
}

check_bbr_status() {
  echo -e "${gl_kjlan}=== 当前系统状态 ===${gl_bai}"
  echo "内核版本: $(uname -r)"
  echo "拥塞控制算法: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  echo "队列调度算法: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"

  local status=1
  if command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | grep -qE '^ii\s+linux-.*xanmod'; then
    echo -e "XanMod 内核: ${gl_lv}已安装${gl_bai}"
    status=0
  elif uname -r | grep -qi xanmod; then
    echo -e "XanMod 内核: ${gl_huang}当前正在运行，但软件包状态未完整检测到${gl_bai}"
    status=0
  else
    echo -e "XanMod 内核: ${gl_huang}未安装${gl_bai}"
  fi
  return "$status"
}

show_main_menu() {
  clear
  check_bbr_status
  local is_installed=$?
  echo ""
  echo -e "${gl_zi}━━━━━━━━━━━━ 核心功能 ━━━━━━━━━━━━${gl_bai}"
  echo -e "${gl_kjlan}[内核管理]${gl_bai}"
  echo "1. 安装/更新 XanMod 内核 + BBR v3"
  echo "2. 卸载 XanMod 内核"
  echo ""
  echo -e "${gl_kjlan}[BBR/网络优化]${gl_bai}"
  echo "3. BBR 直连/落地优化（智能带宽检测）"
  echo ""
  echo "0. 退出"
  echo ""
  read -r -p "请输入选择: " choice

  case "$choice" in
    1)
      if [ "$is_installed" -eq 0 ]; then
        update_xanmod_kernel
      else
        install_xanmod_kernel && server_reboot
      fi
      ;;
    2)
      if [ "$is_installed" -eq 0 ]; then
        uninstall_xanmod
      else
        echo -e "${gl_huang}当前未检测到 XanMod 内核，无需卸载${gl_bai}"
        break_end
      fi
      ;;
    3)
      bbr_configure_direct
      break_end
      ;;
    0)
      exit 0
      ;;
    *)
      echo -e "${gl_huang}无效选择${gl_bai}"
      sleep 1
      ;;
  esac
}

main() {
  check_root
  while true; do
    show_main_menu
  done
}

main "$@"
