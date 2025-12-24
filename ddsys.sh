#!/usr/bin/env bash
# =============================================================================
#  一键全自动重装 Debian / Ubuntu（x86_64） - 2025 精简国外优化版
#  功能：preseed 全自动网络安装 + BBR 默认启用 + 基础网络与分区
#  支持：Debian 10~12 / Ubuntu 20.04~24.04
#  使用示例：
#    sudo bash $0 -debian 12 --ip-addr 192.0.2.10 --ip-mask 24 --ip-gate 192.0.2.1
#    sudo bash $0 -ubuntu 24.04 -pwd MyStrongPass123
# =============================================================================

set -euo pipefail

# ── 颜色与日志 ───────────────────────────────────────────────────────────────
RED='\033[31m' GREEN='\033[32m' YELLOW='\033[33m' BLUE='\033[34m' PLAIN='\033[0m'

info()    { echo -e "${BLUE}[信息]${PLAIN} $*"; }
warn()    { echo -e "${YELLOW}[警告]${PLAIN} $*"; }
error()   { echo -e "${RED}[错误]${PLAIN} $*" >&2; exit 1; }
success() { echo -e "${GREEN}[成功]${PLAIN} $*"; }

# ── 默认配置 ─────────────────────────────────────────────────────────────────
DEFAULT_PASS="LeitboGi0ro"
DEFAULT_DNS="8.8.8.8 1.1.1.1"
DEFAULT_DNS6="2001:4860:4860::8888 2606:4700:4700::1111"
DEFAULT_TIMEZONE="UTC"

# 国际镜像（国外主机优先）
DEB_MIRROR="http://deb.debian.org/debian"
UBU_MIRROR="http://archive.ubuntu.com/ubuntu"

# ── 全局配置（通过命令行覆盖） ─────────────────────────────────────────────
TARGET=""           # debian / ubuntu
VERSION=""
PASSWORD="$DEFAULT_PASS"
IP_ADDR=""
IP_MASK=""
IP_GATE=""
IP_DNS="$DEFAULT_DNS"
TIMEZONE="$DEFAULT_TIMEZONE"
IS_CHINA=0

# ── 参数解析 ─────────────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -debian)  TARGET="debian";  shift; VERSION="${1:-}"; shift ;;
            -ubuntu)  TARGET="ubuntu";  shift; VERSION="${1:-}"; shift ;;
            -pwd)     PASSWORD="$2";    shift 2 ;;
            --ip-addr) IP_ADDR="$2";    shift 2 ;;
            --ip-mask) IP_MASK="$2";    shift 2 ;;
            --ip-gate) IP_GATE="$2";    shift 2 ;;
            --ip-dns)  IP_DNS="$2";     shift 2 ;;
            --timezone) TIMEZONE="$2";  shift 2 ;;
            *) error "未知参数: $1" ;;
        esac
    done

    [[ -z "$TARGET" || -z "$VERSION" ]] && {
        error "用法示例：\n  -debian 12\n  -ubuntu 24.04\n必须指定目标系统和版本"
    }
}

# ── 基础环境检测 ─────────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -ne 0 ]] && error "请使用 root 权限运行此脚本"
}

detect_arch() {
    local arch=$(uname -m)
    [[ "$arch" != "x86_64" ]] && error "本脚本仅支持 x86_64 架构（检测到: $arch）"
}

detect_china() {
    # 简单判断：能否 ping 通 223.5.5.5（阿里 DNS）
    if ping -c 1 -W 1 223.5.5.5 &>/dev/null; then
        IS_CHINA=1
        warn "检测到疑似中国大陆网络环境"
        warn "建议在国外主机使用本脚本以获得最佳体验"
    fi
}

# ── 选择镜像源 ───────────────────────────────────────────────────────────────
select_mirror() {
    if [[ $IS_CHINA -eq 1 ]]; then
        DEB_MIRROR="https://mirrors.tuna.tsinghua.edu.cn/debian"
        UBU_MIRROR="https://mirrors.tuna.tsinghua.edu.cn/ubuntu"
        IP_DNS="119.29.29.29 223.6.6.6"
    fi

    info "使用镜像源："
    info "  Debian  → $DEB_MIRROR"
    info "  Ubuntu  → $UBU_MIRROR"
}

# ── 网络配置（静态 IP 优先） ────────────────────────────────────────────────
get_network_info() {
    # 寻找主网卡（默认路由所在）
    local iface
    iface=$(ip -4 route show default | grep -oP '(?<=dev\s)\S+' | head -1)
    [[ -z "$iface" ]] && error "无法找到主网卡"

    # 如果用户没提供 IP，则尝试获取当前 IP
    if [[ -z "$IP_ADDR" ]]; then
        IP_ADDR=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        [[ -z "$IP_ADDR" ]] && error "无法自动获取当前 IP，请手动指定 --ip-addr"
        
        IP_MASK=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\K\d+' | head -1)
        IP_GATE=$(ip -4 route show default | grep -oP '(?<=via\s)\d+(\.\d+){3}' | head -1)
    fi

    info "网络配置："
    info "  接口   : $iface"
    info "  IP     : $IP_ADDR/$IP_MASK"
    info "  网关   : $IP_GATE"
    info "  DNS    : $IP_DNS"
}

# ── 磁盘自动识别（取第一个 ≥10G 的磁盘） ────────────────────────────────────
get_main_disk() {
    local disk
    disk=$(lsblk -dno NAME,SIZE,TYPE | awk '$3=="disk" && $2~/[0-9]+[GT]/ {print "/dev/"$1; exit}')
    [[ -z "$disk" ]] && error "无法找到合适的安装磁盘（需 ≥10GB）"
    echo "$disk"
}

# ── 生成 preseed 配置文件 ────────────────────────────────────────────────────
generate_preseed() {
    local distro_codename mirror_url
    local disk=$(get_main_disk)

    if [[ $TARGET == "debian" ]]; then
        case $VERSION in
            10)  distro_codename="buster" ;;
            11)  distro_codename="bullseye" ;;
            12)  distro_codename="bookworm" ;;
            *)   error "不支持的 Debian 版本: $VERSION" ;;
        esac
        mirror_url="$DEB_MIRROR"
    else
        case $VERSION in
            20.04) distro_codename="focal" ;;
            22.04) distro_codename="jammy" ;;
            24.04) distro_codename="noble" ;;
            *)   error "不支持的 Ubuntu 版本: $VERSION" ;;
        esac
        mirror_url="$UBU_MIRROR"
    fi

    cat > /preseed.cfg <<EOF
# Locale and keyboard
d-i debian-installer/locale string en_US
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/modelcode string pc105
d-i keyboard-configuration/layoutcode string us

# Network
d-i netcfg/choose_interface select auto
d-i netcfg/get_ipaddress string $IP_ADDR
d-i netcfg/get_netmask string $(awk -v m=$IP_MASK 'BEGIN{ printf "%d.%d.%d.%d", (m>=8)*255, (m>=16)*255, (m>=24)*255, (m>=32)*255 }')
d-i netcfg/get_gateway string $IP_GATE
d-i netcfg/get_nameservers string $IP_DNS
d-i netcfg/confirm_static boolean true

# Mirror
d-i mirror/country string manual
d-i mirror/http/hostname string $(echo "$mirror_url" | cut -d'/' -f3)
d-i mirror/http/directory string $(echo "$mirror_url" | cut -d'/' -f4-)
d-i mirror/http/proxy string

# Clock and timezone
d-i clock-setup/utc boolean true
d-i time/zone string $TIMEZONE
d-i clock-setup/ntp boolean true

# Users
d-i passwd/root-password password $PASSWORD
d-i passwd/root-password-again password $PASSWORD
d-i passwd/make-user boolean false

# Partitioning (简单单盘方案)
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_label string gpt
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-auto/disk string $disk

# Base system
d-i base-installer/install-recommends boolean false

# GRUB
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string $disk

# Finish
d-i finish-install/reboot_in_progress note
EOF

    info "已生成 preseed 配置文件：/preseed.cfg"
}

# ── 修改 GRUB（添加 console 参数） ──────────────────────────────────────────
modify_grub() {
    # 备份原始 grub
    cp /etc/default/grub /etc/default/grub.bak 2>/dev/null || true

    cat > /etc/default/grub <<'EOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0"
GRUB_TERMINAL=serial
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF

    if command -v update-grub >/dev/null; then
        update-grub
    elif command -v grub-mkconfig >/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg
    fi

    info "GRUB 已更新（已添加 serial console 支持）"
}

# ── 启用 BBR ─────────────────────────────────────────────────────────────────
enable_bbr() {
    cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p /etc/sysctl.d/99-bbr.conf 2>/dev/null || true
    info "TCP BBR 已启用（重启后生效）"
}

# ── 主流程 ───────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    check_root
    detect_arch
    detect_china
    select_mirror
    get_network_info

    info "开始准备安装环境..."
    generate_preseed
    modify_grub
    enable_bbr

    success "所有准备工作已完成！"
    echo ""
    echo "请执行以下命令继续："
    echo "  1. 确认 /preseed.cfg 内容正确"
    echo "  2. 重启进入救援模式或使用网络引导"
    echo "  3. 在引导菜单输入："
    echo "     auto url=file:///preseed.cfg"
    echo ""
    echo "或直接重启服务器（部分主机支持自动加载 preseed）"
}

main "$@"
