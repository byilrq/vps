#!/usr/bin/env bash
#=================================================
# System Required: CentOS 7/8, Debian/Ubuntu, oraclelinux (部分功能按发行版实现)
# Description: BBR + BBRplus + BBRplusNew 管理精简版（已补全 2/3 安装逻辑）
# Version: 100.0.4.15 (menu slim patched)
#=================================================

set -euo pipefail

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="100.0.4.15"

Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

github_network=1

# ---- root check ----
if [ "${EUID:-0}" -ne 0 ]; then
  echo "请使用 root 用户身份运行此脚本"
  exit 1
fi

# -----------------------------
# 基础工具
# -----------------------------
_exists() {
  command -v "$1" >/dev/null 2>&1
}

# -----------------------------
# 系统识别/依赖
# -----------------------------
release=""
OS_type=""
version=""

check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif [[ -f /etc/debian_version ]]; then
    release="debian"
  elif grep -qi "ubuntu" /etc/issue 2>/dev/null; then
    release="ubuntu"
  else
    release="unknown"
  fi

  if [[ -f /etc/debian_version ]]; then
    OS_type="Debian"
  elif [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/fedora-release ]]; then
    OS_type="CentOS"
  else
    OS_type="Unknown"
  fi

  # 依赖最小化：curl/wget/dmidecode/lsb_release(尽量)
  if [[ "${OS_type}" == "CentOS" ]]; then
    for pkg in ca-certificates curl wget dmidecode; do
      rpm -q "$pkg" >/dev/null 2>&1 || yum install -y "$pkg" >/dev/null 2>&1 || true
    done
    if ! _exists lsb_release; then
      yum install -y redhat-lsb-core >/dev/null 2>&1 || true
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    for pkg in ca-certificates curl wget dmidecode; do
      dpkg -s "$pkg" >/dev/null 2>&1 || apt-get install -y "$pkg" >/dev/null 2>&1 || true
    done
    if ! _exists lsb_release; then
      apt-get install -y lsb-release >/dev/null 2>&1 || true
    fi
  fi
}

check_version() {
  if [[ -s /etc/redhat-release ]]; then
    version="$(grep -oE "[0-9.]+" /etc/redhat-release | cut -d . -f 1 || echo "")"
  else
    version="$(grep -oE "[0-9.]+" /etc/issue 2>/dev/null | cut -d . -f 1 || echo "")"
  fi
}

get_opsy() {
  if [[ -f /etc/os-release ]]; then
    awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5,$6,$7}' /etc/os-release
  elif [[ -f /etc/lsb-release ]]; then
    awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release
  elif [[ -f /etc/system-release ]]; then
    awk '{print $1,$2,$3}' /etc/system-release
  else
    echo "Unknown"
  fi
}

virt_check() {
  local virtual="Unknown"
  if _exists systemd-detect-virt; then
    local vt
    vt="$(systemd-detect-virt 2>/dev/null || echo "")"
    case "$vt" in
      kvm) virtual="KVM" ;;
      qemu) virtual="QEMU" ;;
      vmware) virtual="VMware" ;;
      microsoft) virtual="Microsoft Hyper-V" ;;
      xen) virtual="Xen" ;;
      docker) virtual="Docker" ;;
      lxc|lxc-libvirt) virtual="LXC" ;;
      none) virtual="None" ;;
      *) virtual="${vt:-Unknown}" ;;
    esac
  elif [[ -f "/.dockerenv" ]]; then
    virtual="Docker"
  else
    virtual="Unknown"
  fi
  echo "$virtual"
}

get_system_info() {
  opsy="$(get_opsy)"
  arch="$(uname -m)"
  kern="$(uname -r)"
  virtual="$(virt_check)"
}

# -----------------------------
# 状态检测：拥塞/队列/headers
# -----------------------------
kernel_status="noinstall"
run_status="未安装加速模块"
headers_status="未安装"
brutal=""
net_congestion_control="unknown"
net_qdisc="unknown"
opsy=""
virtual=""
arch=""
kern=""
kernel_version_full=""
kernel_version=""

check_status() {
  kernel_version_full="$(uname -r)"
  kernel_version="$(uname -r | awk -F "-" '{print $1}')"

  net_congestion_control="$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo "unknown")"
  net_qdisc="$(cat /proc/sys/net/core/default_qdisc 2>/dev/null || echo "unknown")"

  # 内核类型识别
  if [[ "$kernel_version_full" == *bbrplus* ]]; then
    kernel_status="BBRplus"
  elif read -r major minor <<<"$(echo "$kernel_version" | awk -F'.' '{print $1, $2}')" && \
       { [[ "$major" == "4" && "$minor" -ge 9 ]] || [[ "$major" == "5" ]] || [[ "$major" == "6" ]] || [[ "$major" == "7" ]]; }; then
    kernel_status="BBR"
  else
    kernel_status="noinstall"
  fi

  # 运行状态
  if [[ "$kernel_status" == "BBR" ]]; then
    case "$net_congestion_control" in
      bbr)  run_status="BBR启动成功" ;;
      bbr2) run_status="BBR2启动成功" ;;
      *)    run_status="未安装加速模块" ;;
    esac
  elif [[ "$kernel_status" == "BBRplus" ]]; then
    case "$net_congestion_control" in
      bbrplus) run_status="BBRplus启动成功" ;;
      bbr)     run_status="BBR启动成功" ;;
      *)       run_status="未安装加速模块" ;;
    esac
  else
    run_status="未安装加速模块"
  fi

  # headers 匹配
  local os_type="unknown"
  if [[ -f /etc/redhat-release ]]; then
    os_type="centos"
  elif [[ -f /etc/debian_version ]]; then
    os_type="debian"
  fi

  if [[ "$os_type" == "centos" ]]; then
    local installed_headers
    installed_headers="$(rpm -qa | grep -E "kernel-devel|kernel-headers" || true)"
    if [[ -z "$installed_headers" ]]; then
      headers_status="未安装"
    else
      if echo "$installed_headers" | grep -q "kernel-devel-${kernel_version_full}\|kernel-headers-${kernel_version_full}"; then
        headers_status="已匹配"
      else
        headers_status="未匹配"
      fi
    fi
  elif [[ "$os_type" == "debian" ]]; then
    if dpkg -l 2>/dev/null | grep -q "linux-headers-${kernel_version_full}"; then
      headers_status="已匹配"
    else
      if dpkg -l 2>/dev/null | grep -q "linux-headers"; then
        headers_status="未匹配"
      else
        headers_status="未安装"
      fi
    fi
  else
    headers_status="不支持的操作系统"
  fi

  brutal=""
  if lsmod 2>/dev/null | grep -q "brutal"; then
    brutal="brutal已加载"
  fi
}

# -----------------------------
# GitHub/下载辅助（补全 2/3 安装逻辑）
# -----------------------------
check_cn() {
  if ! _exists curl; then
    echo "$1"
    return 0
  fi

  local country="unknown"
  country="$(curl -fsS --max-time 3 https://ip.im/info -4 2>/dev/null | sed -n '/CountryCode/s/.*://p' | tr -d ' ,"')"
  [[ -z "$country" ]] && country="unknown"

  if [[ "$country" != "CN" ]]; then
    echo "$1"
    return 0
  fi

  local raw="$1"
  local prefixes=(
    "https://gh-proxy.com/"
    "https://hub.gitmirror.com/"
    "https://gh.ddlc.top/"
  )

  local p url code
  for p in "${prefixes[@]}"; do
    url="${p}${raw}"
    code="$(curl -fsSIL --max-time 2 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)"
    if [[ "$code" =~ ^2|^3 ]]; then
      echo "$url"
      return 0
    fi
  done

  echo "$raw"
  return 0
}

download_file() {
  local url="$1"
  local filename="$2"
  if _exists curl; then
    curl -fL --retry 3 --connect-timeout 10 --max-time 300 "$url" -o "$filename"
  else
    wget -t 3 -T 10 -O "$filename" "$url"
  fi
}

detele_kernel_head() {
  local kv="${kernel_version:-}"
  [[ -z "$kv" ]] && return 0

  if [[ "${OS_type}" == "CentOS" ]]; then
    local del
    del="$(rpm -qa | grep -E 'kernel-(headers|devel)' | grep -v "${kv}" || true)"
    [[ -n "$del" ]] && rpm --nodeps -e $del || true
  elif [[ "${OS_type}" == "Debian" ]]; then
    local del
    del="$(dpkg -l 2>/dev/null | awk '/linux-headers/{print $2}' | grep -v "${kv}" || true)"
    if [[ -n "$del" ]]; then
      apt-get purge -y $del || true
      apt-get autoremove -y || true
    fi
  fi
}

BBR_grub() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    if _exists grub2-mkconfig; then
      grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || true
      grub2-set-default 0 >/dev/null 2>&1 || true
    elif _exists grub-mkconfig; then
      grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
      grub-set-default 0 >/dev/null 2>&1 || true
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    if _exists update-grub; then
      update-grub >/dev/null 2>&1 || true
    fi
  fi
}

install_bbrplus_real() {
  echo -e "${Info} 安装 BBRplus 内核（4.14.129-bbrplus）..."

  local bit
  bit="$(uname -m)"
  if [[ "$bit" != "x86_64" ]]; then
    echo -e "${Error} BBRplus 仅支持 x86_64"
    return 1
  fi

  rm -rf /tmp/bbrplus && mkdir -p /tmp/bbrplus && cd /tmp/bbrplus

  if [[ "${OS_type}" == "CentOS" ]]; then
    [[ "${version}" != "7" ]] && { echo -e "${Error} CentOS 仅支持 7"; return 1; }

    kernel_version="4.14.129-bbrplus"
    detele_kernel_head

    local headurl imgurl
    headurl="https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-headers-4.14.129-bbrplus.rpm"
    imgurl="https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-4.14.129-bbrplus.rpm"

    headurl="$(check_cn "$headurl")"
    imgurl="$(check_cn "$imgurl")"

    download_file "$imgurl" kernel.rpm
    download_file "$headurl" kernel-headers.rpm

    yum install -y kernel.rpm
    yum install -y kernel-headers.rpm

  elif [[ "${OS_type}" == "Debian" ]]; then
    kernel_version="4.14.129-bbrplus"
    detele_kernel_head

    local headurl imgurl
    headurl="https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-headers-4.14.129-bbrplus.deb"
    imgurl="https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-image-4.14.129-bbrplus.deb"

    headurl="$(check_cn "$headurl")"
    imgurl="$(check_cn "$imgurl")"

    download_file "$imgurl" linux-image.deb
    download_file "$headurl" linux-headers.deb

    dpkg -i linux-image.deb || apt-get -f install -y
    dpkg -i linux-headers.deb || apt-get -f install -y
  else
    echo -e "${Error} 不支持的系统"
    return 1
  fi

  cd / && rm -rf /tmp/bbrplus
  BBR_grub
  echo -e "${Tip} 安装完成：请重启后生效。"
  return 0
}

install_bbrplusnew_real() {
  echo -e "${Info} 安装 BBRplusNew 内核（UJX6N/bbrplus-6.x_stable 最新 release）..."

  if ! _exists curl; then
    echo -e "${Error} 需要 curl 才能从 GitHub API 获取最新版本"
    return 1
  fi

  local github_ver_plus github_ver_plus_num
  github_ver_plus="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep /tag/ | head -1 | awk -F'[/"]' '{print $8}')"
  github_ver_plus_num="$(echo "$github_ver_plus" | awk -F'-' '{print $1}')"

  if [[ -z "$github_ver_plus" || -z "$github_ver_plus_num" ]]; then
    echo -e "${Error} 获取 release 版本失败（可能 GitHub API 受限）"
    return 1
  fi

  echo -e "${Info} 最新版本: ${github_ver_plus}"

  rm -rf /tmp/bbrplusnew && mkdir -p /tmp/bbrplusnew && cd /tmp/bbrplusnew

  local bit
  bit="$(uname -m)"

  if [[ "${OS_type}" == "CentOS" ]]; then
    [[ "$bit" != "x86_64" ]] && { echo -e "${Error} CentOS 仅支持 x86_64"; return 1; }
    [[ "${version}" != "7" && "${version}" != "8" ]] && { echo -e "${Error} CentOS 仅支持 7/8"; return 1; }

    kernel_version="${github_ver_plus_num}-bbrplus"
    detele_kernel_head

    local headurl imgurl
    if [[ "${version}" == "7" ]]; then
      headurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'rpm' | grep -E 'headers' | grep -E 'el7' | awk -F'"' '{print $4}' | head -1)"
      imgurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'rpm' | grep -vE 'devel|headers|Source' | grep -E 'el7' | awk -F'"' '{print $4}' | head -1)"
    else
      headurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'rpm' | grep -E 'headers' | grep -E 'el8' | awk -F'"' '{print $4}' | head -1)"
      imgurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'rpm' | grep -vE 'devel|headers|Source' | grep -E 'el8' | awk -F'"' '{print $4}' | head -1)"
    fi

    [[ -z "$headurl" || -z "$imgurl" ]] && { echo -e "${Error} 未找到 rpm 资源链接"; return 1; }

    headurl="$(check_cn "$headurl")"
    imgurl="$(check_cn "$imgurl")"

    # 修正：image -> kernel.rpm, headers -> kernel-headers.rpm
    download_file "$imgurl" kernel.rpm
    download_file "$headurl" kernel-headers.rpm

    yum install -y kernel.rpm
    yum install -y kernel-headers.rpm

  elif [[ "${OS_type}" == "Debian" ]]; then
    kernel_version="${github_ver_plus_num}-bbrplus"
    detele_kernel_head

    local headurl imgurl
    if [[ "$bit" == "x86_64" ]]; then
      headurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'amd64\.deb' | grep -E 'headers' | awk -F'"' '{print $4}' | head -1)"
      imgurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'amd64\.deb' | grep -E 'image' | awk -F'"' '{print $4}' | head -1)"
    elif [[ "$bit" == "aarch64" || "$bit" == "arm64" ]]; then
      headurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'arm64\.deb' | grep -E 'headers' | awk -F'"' '{print $4}' | head -1)"
      imgurl="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep "${github_ver_plus}" | grep -E 'arm64\.deb' | grep -E 'image' | awk -F'"' '{print $4}' | head -1)"
    else
      echo -e "${Error} Debian 仅支持 x86_64 / arm64"
      return 1
    fi

    [[ -z "$headurl" || -z "$imgurl" ]] && { echo -e "${Error} 未找到 deb 资源链接"; return 1; }

    headurl="$(check_cn "$headurl")"
    imgurl="$(check_cn "$imgurl")"

    download_file "$imgurl" linux-image.deb
    download_file "$headurl" linux-headers.deb

    dpkg -i linux-image.deb || apt-get -f install -y
    dpkg -i linux-headers.deb || apt-get -f install -y
  else
    echo -e "${Error} 不支持的系统"
    return 1
  fi

  cd / && rm -rf /tmp/bbrplusnew
  BBR_grub
  echo -e "${Tip} 安装完成：请重启后生效。"
  return 0
}

# -----------------------------
# 系统优化（保留你脚本里的“优化新”）
# -----------------------------
optimizing_system_johnrosen1() {
  if [[ ! -f "/etc/sysctl.d/99-sysctl.conf" ]]; then
    touch /etc/sysctl.d/99-sysctl.conf
  fi

  cat >'/etc/sysctl.d/99-sysctl.conf' <<'EOF'
net.ipv4.tcp_fack = 1
net.ipv4.tcp_early_retrans = 3
net.ipv4.neigh.default.unres_qlen=10000
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
#net.ipv6.conf.all.forwarding = 1  #awsipv6问题
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.core.netdev_max_backlog = 100000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.core.optmem_max = 65536
net.core.somaxconn = 1000000
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 2
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 819200
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_frto = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.neigh.default.gc_thresh3=8192
net.ipv4.neigh.default.gc_thresh2=4096
net.ipv4.neigh.default.gc_thresh1=2048
net.ipv6.neigh.default.gc_thresh3=8192
net.ipv6.neigh.default.gc_thresh2=4096
net.ipv6.neigh.default.gc_thresh1=2048
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_retries2 = 5
vm.swappiness = 1
vm.overcommit_memory = 1
kernel.pid_max=64000
net.netfilter.nf_conntrack_max = 262144
net.nf_conntrack_max = 262144
## Enable bbr
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_low_latency = 1
EOF

  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} 系统配置优化新已应用（部分可能需要重启生效）"
}

# -----------------------------
# 手动编辑 sysctl
# -----------------------------
edit_sysctl_interactive() {
  local target_file="/etc/sysctl.d/99-sysctl.conf"
  local editor_cmd=""

  if [[ ! -f "$target_file" ]]; then
    echo "文件 $target_file 不存在，将创建后打开编辑。"
    touch "$target_file"
  fi

  if _exists nano; then
    editor_cmd="nano"
  else
    editor_cmd="vi"
    echo "提示：vi 按 i 进入编辑，Esc 后输入 :wq 保存退出"
  fi

  "$editor_cmd" "$target_file"
  echo ""
  echo "编辑完成，正在应用 $target_file ..."
  sysctl -p "$target_file" || true
  echo "已执行应用，部分可能需要重启生效"
}

# -----------------------------
# 卸载全部加速（更安全：只删 99-sysctl.conf）
# -----------------------------
remove_all() {
  rm -f /etc/sysctl.d/99-sysctl.conf || true
  if [[ ! -f "/etc/sysctl.conf" ]]; then
    touch /etc/sysctl.conf
  else
    : > /etc/sysctl.conf
  fi
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} 已清理加速配置（sysctl）。如有自定义内核不在此处卸载。"
}

# -----------------------------
# 仅清除队列/拥塞控制相关（切换用）
# -----------------------------
remove_bbr_lotserver() {
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.d/99-sysctl.conf 2>/dev/null || true
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.d/99-sysctl.conf 2>/dev/null || true
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.d/99-sysctl.conf 2>/dev/null || true
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
}

# -----------------------------
# 加速启用（菜单 4-10）
# -----------------------------
startbbrfq() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR+FQ 修改成功，建议重启后确认"
}

startbbrfqpie() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq_pie" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR+FQ_PIE 修改成功，建议重启后确认"
}

startbbrcake() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=cake" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR+CAKE 修改成功，建议重启后确认"
}

startbbr2fq() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr2" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR2+FQ 修改成功，建议重启后确认"
}

startbbr2fqpie() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq_pie" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr2" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR2+FQ_PIE 修改成功，建议重启后确认"
}

startbbr2cake() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=cake" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr2" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBR2+CAKE 修改成功，建议重启后确认"
}

startbbrplus() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbrplus" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} BBRplus+FQ 修改成功，建议重启后确认"
}

# -----------------------------
# 内核安装（菜单 1-3）
# -----------------------------
install_bbr_official() {
  echo -e "${Info} 安装 BBR 原版内核（官方源/仓库）..."
  if [[ "${OS_type}" == "Debian" ]]; then
    apt-get update -y
    if [[ "${release}" == "ubuntu" ]]; then
      apt-get install -y linux-image-generic linux-headers-generic
    else
      if [[ "$(uname -m)" == "x86_64" ]]; then
        apt-get install -y linux-image-amd64 linux-headers-amd64
      else
        apt-get install -y linux-image-arm64 linux-headers-arm64
      fi
    fi
  elif [[ "${OS_type}" == "CentOS" ]]; then
    if [[ "$version" == "7" ]]; then
      yum install -y kernel kernel-headers
    else
      yum install -y kernel kernel-core kernel-headers
    fi
  else
    echo -e "${Error} 不支持的系统"
    return 1
  fi
  echo -e "${Tip} 内核安装完成，请重启后生效。"
}

# -----------------------------
# 菜单
# -----------------------------
start_menu() {
  while true; do
    clear || true
    check_status
    get_system_info

    echo -e " TCP加速 一键安装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix} 不卸内核 from blog.ylx.me 母鸡慎用"
    echo -e " ———————————————————————————— 内核安装 —————————————————————————————"
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 安装 BBR原版内核          ${Green_font_prefix}2.${Font_color_suffix} 安装 BBRplus版内核"
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 安装 BBRplus新版内核"
    echo -e " ———————————————————————————— 加速启用 —————————————————————————————"
    echo -e " ${Green_font_prefix}4.${Font_color_suffix} 使用BBR+FQ加速           ${Green_font_prefix}5.${Font_color_suffix} 使用BBR+FQ_PIE加速"
    echo -e " ${Green_font_prefix}6.${Font_color_suffix} 使用BBR+CAKE加速         ${Green_font_prefix}7.${Font_color_suffix} 使用BBR2+FQ加速"
    echo -e " ${Green_font_prefix}8.${Font_color_suffix} 使用BBR2+FQ_PIE加速      ${Green_font_prefix}9.${Font_color_suffix} 使用BBR2+CAKE加速"
    echo -e " ${Green_font_prefix}10.${Font_color_suffix} 使用BBRplus+FQ版加速"
    echo -e " ———————————————————————————— 系统配置 —————————————————————————————"
    echo -e " ${Green_font_prefix}11.${Font_color_suffix} 系统配置优化新           ${Green_font_prefix}12.${Font_color_suffix} 手动编辑内核参数"
    echo -e " ${Green_font_prefix}13.${Font_color_suffix} 卸载全部加速"
    echo -e " ———————————————————————————— 内核管理 —————————————————————————————"
    echo -e " ${Green_font_prefix}0.${Font_color_suffix} 退出脚本"
    echo -e "————————————————————————————————————————————————————————————————"

    echo -e " 系统信息： ${Font_color_suffix}${opsy} ${Green_font_prefix}${virtual}${Font_color_suffix} ${arch} ${Green_font_prefix}${kern}${Font_color_suffix}"
    if [[ "${kernel_status}" == "noinstall" ]]; then
      echo -e " 状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核"
    else
      echo -e " 状态: ${Green_font_prefix}已安装${Font_color_suffix} ${Red_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix} ${Red_font_prefix}${brutal}${Font_color_suffix}"
    fi
    echo -e " 拥塞控制算法:: ${Green_font_prefix}${net_congestion_control}${Font_color_suffix} 队列算法: ${Green_font_prefix}${net_qdisc}${Font_color_suffix} 内核headers：${Green_font_prefix}${headers_status}${Font_color_suffix}"
    echo ""

    read -r -p " 请输入数字: " num
    case "${num}" in
      1) install_bbr_official || true ;;
      2) install_bbrplus_real || true ;;
      3) install_bbrplusnew_real || true ;;
      4) startbbrfq ;;
      5) startbbrfqpie ;;
      6) startbbrcake ;;
      7) startbbr2fq ;;
      8) startbbr2fqpie ;;
      9) startbbr2cake ;;
      10) startbbrplus ;;
      11) optimizing_system_johnrosen1 ;;
      12) edit_sysctl_interactive ;;
      13) remove_all ;;
      0) exit 0 ;;
      *) echo -e "${Error} 请输入正确数字 [0-13]"; sleep 1 ;;
    esac

    echo ""
    read -r -p "回车返回菜单..." _ || true
  done
}

# -----------------------------
# 启动
# -----------------------------
check_sys
check_version
start_menu
