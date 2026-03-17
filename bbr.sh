#!/usr/bin/env bash
#=================================================
# Minimal BBR / BBRplus / BBRplusNew menu (0-12)
# CentOS 7/8, Debian/Ubuntu
#=================================================
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

sh_ver="100.0.4.15"

G="\033[32m"; R="\033[31m"; N="\033[0m"
Info="${G}[信息]${N}"
Error="${R}[错误]${N}"
Tip="${G}[注意]${N}"

# root
[[ "${EUID:-0}" -eq 0 ]] || { echo "请使用 root 用户身份运行此脚本"; exit 1; }

_exists(){ command -v "$1" >/dev/null 2>&1; }

# -----------------------------
# OS detect + deps
# -----------------------------
OS_type="Unknown"
release="unknown"
version=""

check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    OS_type="CentOS"
    release="centos"
  elif [[ -f /etc/debian_version ]]; then
    OS_type="Debian"
    release="debian"
    grep -qi ubuntu /etc/issue 2>/dev/null && release="ubuntu"
  fi

  if [[ "$OS_type" == "CentOS" ]]; then
    for p in ca-certificates curl wget; do rpm -q "$p" >/dev/null 2>&1 || yum -y install "$p" >/dev/null 2>&1 || true; done
  elif [[ "$OS_type" == "Debian" ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    for p in ca-certificates curl wget; do dpkg -s "$p" >/dev/null 2>&1 || apt-get install -y "$p" >/dev/null 2>&1 || true; done
  fi
}

check_version() {
  if [[ -s /etc/redhat-release ]]; then
    version="$(grep -oE "[0-9]+" /etc/redhat-release | head -1 || true)"
  else
    version="$(grep -oE "[0-9]+" /etc/issue 2>/dev/null | head -1 || true)"
  fi
}

opsy() {
  if [[ -f /etc/os-release ]]; then
    awk -F'[= "]' '/PRETTY_NAME/{for(i=3;i<=7;i++) if($i!="") printf $i" "; print ""}' /etc/os-release
  else
    echo "Unknown"
  fi
}

# -----------------------------
# status
# -----------------------------
kernel_status="noinstall"
run_status="未安装加速模块"
headers_status="未知"
net_cc="unknown"
net_qdisc="unknown"
kern=""
arch=""
virtual="Unknown"
os_pretty=""

virt_check() {
  if _exists systemd-detect-virt; then
    local vt; vt="$(systemd-detect-virt 2>/dev/null || echo "")"
    [[ -n "$vt" ]] && echo "$vt" || echo "Unknown"
  elif [[ -f "/.dockerenv" ]]; then
    echo "docker"
  else
    echo "Unknown"
  fi
}

check_status() {
  local kfull kbase major minor
  kfull="$(uname -r)"
  kbase="$(uname -r | awk -F'-' '{print $1}')"
  major="$(echo "$kbase" | awk -F. '{print $1}')"
  minor="$(echo "$kbase" | awk -F. '{print $2}')"

  net_cc="$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || echo unknown)"
  net_qdisc="$(cat /proc/sys/net/core/default_qdisc 2>/dev/null || echo unknown)"

  if [[ "$kfull" == *bbrplus* ]]; then
    kernel_status="BBRplus"
  elif [[ "$major" =~ ^[0-9]+$ ]] && [[ "$minor" =~ ^[0-9]+$ ]] && { [[ "$major" -gt 4 ]] || { [[ "$major" -eq 4 ]] && [[ "$minor" -ge 9 ]]; }; }; then
    kernel_status="BBR"
  else
    kernel_status="noinstall"
  fi

  case "$net_cc" in
    bbr)     run_status="BBR启动成功" ;;
    bbrplus) run_status="BBRplus启动成功" ;;
    *)       run_status="未安装加速模块" ;;
  esac

  # headers (极简：只判断“是否存在同名 headers”)
  if [[ -f /etc/redhat-release ]]; then
    rpm -qa | grep -qE "kernel-headers|kernel-devel" && headers_status="已安装" || headers_status="未安装"
  elif [[ -f /etc/debian_version ]]; then
    dpkg -l 2>/dev/null | grep -q "linux-headers" && headers_status="已安装" || headers_status="未安装"
  else
    headers_status="未知"
  fi

  os_pretty="$(opsy)"
  arch="$(uname -m)"
  kern="$(uname -r)"
  virtual="$(virt_check)"
}

# -----------------------------
# download helper
# -----------------------------
download_file() {
  local url="$1" out="$2"
  if _exists curl; then
    curl -fL --retry 3 --connect-timeout 10 --max-time 300 "$url" -o "$out"
  else
    wget -t 3 -T 10 -O "$out" "$url"
  fi
}

BBR_grub() {
  if [[ "$OS_type" == "CentOS" ]]; then
    _exists grub2-mkconfig && grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || true
    _exists grub2-set-default && grub2-set-default 0 >/dev/null 2>&1 || true
    _exists grub-mkconfig && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
    _exists grub-set-default && grub-set-default 0 >/dev/null 2>&1 || true
  elif [[ "$OS_type" == "Debian" ]]; then
    _exists update-grub && update-grub >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# kernel install (1-3)
# -----------------------------
install_bbr_official() {
  echo -e "${Info} 安装 BBR 原版内核（官方源/仓库）..."
  if [[ "$OS_type" == "Debian" ]]; then
    apt-get update -y
    if [[ "$release" == "ubuntu" ]]; then
      apt-get install -y linux-image-generic linux-headers-generic
    else
      [[ "$(uname -m)" == "x86_64" ]] && apt-get install -y linux-image-amd64 linux-headers-amd64 || apt-get install -y linux-image-arm64 linux-headers-arm64
    fi
  elif [[ "$OS_type" == "CentOS" ]]; then
    [[ "$version" == "7" ]] && yum install -y kernel kernel-headers || yum install -y kernel kernel-core kernel-headers
  else
    echo -e "${Error} 不支持的系统"; return 1
  fi
  echo -e "${Tip} 内核安装完成，请重启后生效。"
}

install_bbrplus_real() {
  echo -e "${Info} 安装 BBRplus 内核（4.14.129-bbrplus）..."
  [[ "$(uname -m)" == "x86_64" ]] || { echo -e "${Error} BBRplus 仅支持 x86_64"; return 1; }

  rm -rf /tmp/bbrplus && mkdir -p /tmp/bbrplus && cd /tmp/bbrplus

  if [[ "$OS_type" == "CentOS" ]]; then
    [[ "$version" == "7" ]] || { echo -e "${Error} CentOS 仅支持 7"; return 1; }
    download_file "https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-4.14.129-bbrplus.rpm" kernel.rpm
    download_file "https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-headers-4.14.129-bbrplus.rpm" kernel-headers.rpm
    yum install -y kernel.rpm kernel-headers.rpm
  elif [[ "$OS_type" == "Debian" ]]; then
    download_file "https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-image-4.14.129-bbrplus.deb" linux-image.deb
    download_file "https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-headers-4.14.129-bbrplus.deb" linux-headers.deb
    dpkg -i linux-image.deb || apt-get -f install -y
    dpkg -i linux-headers.deb || apt-get -f install -y
  else
    echo -e "${Error} 不支持的系统"; return 1
  fi

  cd / && rm -rf /tmp/bbrplus
  BBR_grub
  echo -e "${Tip} 安装完成：请重启后生效。"
}

install_bbrplusnew_real() {
  echo -e "${Info} 安装 BBRplusNew 内核（UJX6N/bbrplus-6.x_stable 最新 release）..."
  _exists curl || { echo -e "${Error} 需要 curl 才能从 GitHub API 获取最新版本"; return 1; }

  local tag num
  tag="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases | grep /tag/ | head -1 | awk -F'[/"]' '{print $8}')"
  num="$(echo "$tag" | awk -F'-' '{print $1}')"
  [[ -n "$tag" && -n "$num" ]] || { echo -e "${Error} 获取 release 版本失败"; return 1; }
  echo -e "${Info} 最新版本: ${tag}"

  rm -rf /tmp/bbrplusnew && mkdir -p /tmp/bbrplusnew && cd /tmp/bbrplusnew

  local bit; bit="$(uname -m)"

  if [[ "$OS_type" == "CentOS" ]]; then
    [[ "$bit" == "x86_64" ]] || { echo -e "${Error} CentOS 仅支持 x86_64"; return 1; }
    [[ "$version" == "7" || "$version" == "8" ]] || { echo -e "${Error} CentOS 仅支持 7/8"; return 1; }

    local api headurl imgurl el
    api="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases)"
    el="el${version}"
    headurl="$(echo "$api" | grep "$tag" | grep -E 'rpm' | grep -E 'headers' | grep -E "${el}" | awk -F'"' '{print $4}' | head -1)"
    imgurl="$(echo "$api" | grep "$tag" | grep -E 'rpm' | grep -vE 'devel|headers|Source' | grep -E "${el}" | awk -F'"' '{print $4}' | head -1)"
    [[ -n "$headurl" && -n "$imgurl" ]] || { echo -e "${Error} 未找到 rpm 资源链接"; return 1; }

    download_file "$imgurl" kernel.rpm
    download_file "$headurl" kernel-headers.rpm
    yum install -y kernel.rpm kernel-headers.rpm

  elif [[ "$OS_type" == "Debian" ]]; then
    local api headurl imgurl archsuf
    api="$(curl -fsSL https://api.github.com/repos/UJX6N/bbrplus-6.x_stable/releases)"
    if [[ "$bit" == "x86_64" ]]; then archsuf="amd64"; elif [[ "$bit" == "aarch64" || "$bit" == "arm64" ]]; then archsuf="arm64"; else
      echo -e "${Error} Debian 仅支持 x86_64 / arm64"; return 1
    fi
    headurl="$(echo "$api" | grep "$tag" | grep -E "${archsuf}\.deb" | grep -E 'headers' | awk -F'"' '{print $4}' | head -1)"
    imgurl="$(echo "$api" | grep "$tag" | grep -E "${archsuf}\.deb" | grep -E 'image' | awk -F'"' '{print $4}' | head -1)"
    [[ -n "$headurl" && -n "$imgurl" ]] || { echo -e "${Error} 未找到 deb 资源链接"; return 1; }

    download_file "$imgurl" linux-image.deb
    download_file "$headurl" linux-headers.deb
    dpkg -i linux-image.deb || apt-get -f install -y
    dpkg -i linux-headers.deb || apt-get -f install -y
  else
    echo -e "${Error} 不支持的系统"; return 1
  fi

  cd / && rm -rf /tmp/bbrplusnew
  BBR_grub
  echo -e "${Tip} 安装完成：请重启后生效。"
}

# -----------------------------
# sysctl: minimal switch + edit + optimize + remove
# -----------------------------
SYSCTL_FILE="/etc/sysctl.d/99-sysctl.conf"
ensure_sysctl_file(){ [[ -f "$SYSCTL_FILE" ]] || touch "$SYSCTL_FILE"; }

remove_bbr_lines() {
  ensure_sysctl_file
  sed -i '/net.core.default_qdisc/d' "$SYSCTL_FILE" 2>/dev/null || true
  sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_FILE" 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
}

apply_cc_qdisc() {
  local q="$1" cc="$2"
  remove_bbr_lines
  echo "net.core.default_qdisc=${q}" >>"$SYSCTL_FILE"
  echo "net.ipv4.tcp_congestion_control=${cc}" >>"$SYSCTL_FILE"
  sysctl --system >/dev/null 2>&1 || true
}

optimizing_system_min() {
  ensure_sysctl_file
  cat >"$SYSCTL_FILE" <<'EOF'
# minimal safe tuning + enable bbr
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
EOF
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} 系统配置优化已应用（极简版）"
}

edit_sysctl_interactive() {
  ensure_sysctl_file
  if _exists nano; then
    nano "$SYSCTL_FILE"
  else
    echo "提示：vi 按 i 进入编辑，Esc 后输入 :wq 保存退出"
    vi "$SYSCTL_FILE"
  fi
  sysctl -p "$SYSCTL_FILE" || true
  echo -e "${Info} 已应用 $SYSCTL_FILE（部分可能需要重启）"
}

remove_all() {
  rm -f "$SYSCTL_FILE" || true
  : > /etc/sysctl.conf || true
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${Info} 已清理加速配置（sysctl）。"
}

# accelerate (4-9)
startbbrfq()        { apply_cc_qdisc fq     bbr;     echo -e "${Info} BBR+FQ 修改成功"; }
startbbrfqpie()     { apply_cc_qdisc fq_pie bbr;     echo -e "${Info} BBR+FQ_PIE 修改成功"; }
startbbrcake()      { apply_cc_qdisc cake   bbr;     echo -e "${Info} BBR+CAKE 修改成功"; }
startbbrplusfq()    { apply_cc_qdisc fq     bbrplus; echo -e "${Info} BBRplus+FQ 修改成功"; }
startbbrpluscake()  { apply_cc_qdisc cake   bbrplus; echo -e "${Info} BBRplus+CAKE 修改成功"; }
startbbrplusfqpie() { apply_cc_qdisc fq_pie bbrplus; echo -e "${Info} BBRplus+FQ_PIE 修改成功"; }

# -----------------------------
# menu
# -----------------------------
start_menu() {
  while true; do
    clear || true
    check_status

    echo -e " TCP加速 一键安装管理脚本 ${R}[v${sh_ver}]${N} 不卸内核 from blog.ylx.me 母鸡慎用"
    echo -e " ———————————————————————————— 内核安装 —————————————————————————————"
    echo -e " ${G}1.${N} 安装 BBR原版内核          ${G}2.${N} 安装 BBRplus版内核"
    echo -e " ${G}3.${N} 安装 BBRplus新版内核"
    echo -e " ———————————————————————————— 加速启用 —————————————————————————————"
    echo -e " ${G}4.${N} 使用BBR+FQ加速           ${G}5.${N} 使用BBR+FQ_PIE加速"
    echo -e " ${G}6.${N} 使用BBR+CAKE加速        ${G}7.${N} 使用BBRplus+FQ版加速"
    echo -e " ${G}8.${N} 使用BBRplus+CAKE加速   ${G}9.${N} 使用BBRplus+FQ_PIE版加速"
    echo -e " ———————————————————————————— 系统配置 —————————————————————————————"
    echo -e " ${G}10.${N} 系统配置优化新           ${G}11.${N} 手动编辑内核参数"
    echo -e " ${G}12.${N} 卸载全部加速"
    echo -e " ———————————————————————————— 内核管理 —————————————————————————————"
    echo -e " ${G}0.${N} 退出脚本"
    echo -e "————————————————————————————————————————————————————————————————"

    echo -e " 系统信息： ${os_pretty} ${G}${virtual}${N} ${arch} ${G}${kern}${N}"
    if [[ "$kernel_status" == "noinstall" ]]; then
      echo -e " 状态: ${G}未安装${N} 加速内核"
    else
      echo -e " 状态: ${G}已安装${N} ${R}${kernel_status}${N} 加速内核 , ${G}${run_status}${N}"
    fi
    echo -e " 拥塞控制算法:: ${G}${net_cc}${N} 队列算法: ${G}${net_qdisc}${N} headers：${G}${headers_status}${N}"
    echo ""

    read -r -p " 请输入数字: " num
    case "${num}" in
      1) install_bbr_official || true ;;
      2) install_bbrplus_real || true ;;
      3) install_bbrplusnew_real || true ;;
      4) startbbrfq ;;
      5) startbbrfqpie ;;
      6) startbbrcake ;;
      7) startbbrplusfq ;;
      8) startbbrpluscake ;;
      9) startbbrplusfqpie ;;
      10) optimizing_system_min ;;
      11) edit_sysctl_interactive ;;
      12) remove_all ;;
      0) exit 0 ;;
      *) echo -e "${Error} 请输入正确数字 [0-12]"; sleep 1 ;;
    esac

    echo ""
    read -r -p "回车返回菜单..." _ || true
  done
}

# -----------------------------
# start
# -----------------------------
check_sys
check_version
start_menu
