#!/usr/bin/env bash
# tcpfit.sh
# Debian / Ubuntu TCP tuning script
#
# Target profile:
#   net.core.rmem_max / wmem_max       = 22 MiB
#   net.ipv4.tcp_rmem / tcp_wmem       = default 1 MiB, max 22 MiB
#   net.ipv4.tcp_mem                   = 100 / 199 / 399 MiB (converted to pages)
#   default route initcwnd / initrwnd = 32
#   tcp_slow_start_after_idle          = 0
#   netdev_max_backlog                 = 16384
#   somaxconn                          = 8192
#   tcp_max_syn_backlog                = 8192
#   tcp_mtu_probing                    = 1
#   tcp_fin_timeout                    = 15
#   tcp_keepalive_time                 = 600
#   ip_local_port_range                = 1024 65535
#   optmem_max                         = 65536
#   netdev_budget                      = 600
#   vm.min_free_kbytes                 = 32768
#
# Usage:
#   bash tcpfit.sh apply
#   bash tcpfit.sh status
#   bash tcpfit.sh rollback
#
# First-run snapshot:
#   /var/lib/tcpfit/pre-tune.snapshot

set -uo pipefail

STATE_DIR="/var/lib/tcpfit"
SNAPSHOT="${STATE_DIR}/pre-tune.snapshot"
SYSCTL_SNAPSHOT="${STATE_DIR}/pre-tune.sysctl"
ROUTE4_SNAPSHOT="${STATE_DIR}/pre-tune.route4"
ROUTE6_SNAPSHOT="${STATE_DIR}/pre-tune.route6"
SYSCTL_CONF="/etc/sysctl.d/99-tcpfit.conf"
ROUTE_HELPER="/usr/local/sbin/tcpfit-route-apply"
ROUTE_SERVICE="/etc/systemd/system/tcpfit-route.service"

BUFFER_MAX=$((22 * 1024 * 1024))
TCP_BUFFER_DEFAULT=$((1 * 1024 * 1024))
INITCWND=32
INITRWND=32
TCP_MEM_LOW_MB=100
TCP_MEM_PRESSURE_MB=199
TCP_MEM_HIGH_MB=399

SYSCTL_KEYS=(
    "net.core.rmem_max"
    "net.core.wmem_max"
    "net.ipv4.tcp_rmem"
    "net.ipv4.tcp_wmem"
    "net.ipv4.tcp_mem"
    "net.ipv4.tcp_slow_start_after_idle"
    "net.core.netdev_max_backlog"
    "net.core.somaxconn"
    "net.ipv4.tcp_max_syn_backlog"
    "net.ipv4.tcp_mtu_probing"
    "net.ipv4.tcp_fin_timeout"
    "net.ipv4.tcp_keepalive_time"
    "net.ipv4.ip_local_port_range"
    "net.core.optmem_max"
    "net.core.netdev_budget"
    "vm.min_free_kbytes"
)

c_green='\033[1;32m'
c_yellow='\033[1;33m'
c_red='\033[1;31m'
c_blue='\033[1;36m'
c_reset='\033[0m'

green()  { printf "%b%s%b\n" "$c_green" "$*" "$c_reset"; }
yellow() { printf "%b%s%b\n" "$c_yellow" "$*" "$c_reset"; }
red()    { printf "%b%s%b\n" "$c_red" "$*" "$c_reset"; }
blue()   { printf "%b%s%b\n" "$c_blue" "$*" "$c_reset"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        red "错误：请使用 root 权限运行。"
        exit 1
    fi
}

check_dependencies() {
    local missing=0
    for cmd in sysctl ip awk sed grep getconf; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            red "缺少命令：$cmd"
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "Debian/Ubuntu 可执行：apt update && apt install -y procps iproute2"
        exit 1
    fi
}

check_system() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            debian|ubuntu) ;;
            *) yellow "提示：当前系统 ${PRETTY_NAME:-unknown}，脚本主要针对 Debian/Ubuntu。" ;;
        esac
    fi
}

sysctl_exists() {
    sysctl -n "$1" >/dev/null 2>&1
}

get_sysctl() {
    sysctl -n "$1" 2>/dev/null || true
}

mb_to_pages() {
    local mb="$1"
    local page_size="$2"
    echo $(( (mb * 1024 * 1024 + page_size - 1) / page_size ))
}

create_snapshot() {
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"

    if [ -f "$SYSCTL_SNAPSHOT" ]; then
        yellow "已存在首次调优前快照，不覆盖：$SNAPSHOT"
        return 0
    fi

    blue "保存首次调优前参数快照..."
    : > "$SYSCTL_SNAPSHOT"

    {
        echo "============================================================"
        echo " tcpfit pre-tune snapshot"
        echo "============================================================"
        echo "Time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "Kernel: $(uname -a)"
        echo "PAGE_SIZE: $(getconf PAGESIZE 2>/dev/null || echo unknown)"
        echo
        echo "Memory:"
        free -h 2>/dev/null || true
        echo
        echo "================ SYSCTL ================="
    } > "$SNAPSHOT"

    local key value
    for key in "${SYSCTL_KEYS[@]}"; do
        if sysctl_exists "$key"; then
            value="$(get_sysctl "$key")"
            printf '%s|%s\n' "$key" "$value" >> "$SYSCTL_SNAPSHOT"
            printf '%-42s = %s\n' "$key" "$value" >> "$SNAPSHOT"
        else
            printf '%-42s = NOT_SUPPORTED\n' "$key" >> "$SNAPSHOT"
        fi
    done

    ip -4 route show default 2>/dev/null > "$ROUTE4_SNAPSHOT" || true
    ip -6 route show default 2>/dev/null > "$ROUTE6_SNAPSHOT" || true

    {
        echo
        echo "================ IPv4 DEFAULT ROUTE ================="
        cat "$ROUTE4_SNAPSHOT" 2>/dev/null || true
        echo
        echo "================ IPv6 DEFAULT ROUTE ================="
        cat "$ROUTE6_SNAPSHOT" 2>/dev/null || true
    } >> "$SNAPSHOT"

    chmod 600 "$SNAPSHOT" "$SYSCTL_SNAPSHOT" "$ROUTE4_SNAPSHOT" "$ROUTE6_SNAPSHOT" 2>/dev/null || true
    green "快照已保存：$SNAPSHOT"
}

append_setting() {
    local key="$1"
    local value="$2"
    if sysctl_exists "$key"; then
        printf '%s = %s\n' "$key" "$value" >> "$SYSCTL_CONF"
    else
        yellow "内核不支持，跳过：$key"
    fi
}

write_sysctl_config() {
    local page_size low pressure high
    local tcp_rmem_min=4096
    local tcp_wmem_min=4096

    page_size="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
    low="$(mb_to_pages "$TCP_MEM_LOW_MB" "$page_size")"
    pressure="$(mb_to_pages "$TCP_MEM_PRESSURE_MB" "$page_size")"
    high="$(mb_to_pages "$TCP_MEM_HIGH_MB" "$page_size")"

    if sysctl_exists net.ipv4.tcp_rmem; then
        tcp_rmem_min="$(get_sysctl net.ipv4.tcp_rmem | awk '{print $1}')"
    fi
    if sysctl_exists net.ipv4.tcp_wmem; then
        tcp_wmem_min="$(get_sysctl net.ipv4.tcp_wmem | awk '{print $1}')"
    fi

    cat > "$SYSCTL_CONF" <<EOF_SYSCTL
# tcpfit TCP tuning for Debian/Ubuntu
# 22 MiB socket buffer ceiling
# tcp_mem uses pages, not bytes.
# PAGE_SIZE=${page_size}
# tcp_mem=${TCP_MEM_LOW_MB}/${TCP_MEM_PRESSURE_MB}/${TCP_MEM_HIGH_MB} MiB

EOF_SYSCTL

    append_setting "net.core.rmem_max" "$BUFFER_MAX"
    append_setting "net.core.wmem_max" "$BUFFER_MAX"
    append_setting "net.ipv4.tcp_rmem" "${tcp_rmem_min} ${TCP_BUFFER_DEFAULT} ${BUFFER_MAX}"
    append_setting "net.ipv4.tcp_wmem" "${tcp_wmem_min} ${TCP_BUFFER_DEFAULT} ${BUFFER_MAX}"
    append_setting "net.ipv4.tcp_mem" "${low} ${pressure} ${high}"
    append_setting "net.ipv4.tcp_slow_start_after_idle" "0"
    append_setting "net.core.netdev_max_backlog" "16384"
    append_setting "net.core.somaxconn" "8192"
    append_setting "net.ipv4.tcp_max_syn_backlog" "8192"
    append_setting "net.ipv4.tcp_mtu_probing" "1"
    append_setting "net.ipv4.tcp_fin_timeout" "15"
    append_setting "net.ipv4.tcp_keepalive_time" "600"
    append_setting "net.ipv4.ip_local_port_range" "1024 65535"
    append_setting "net.core.optmem_max" "65536"
    append_setting "net.core.netdev_budget" "600"
    append_setting "vm.min_free_kbytes" "32768"

    chmod 644 "$SYSCTL_CONF"

    blue "tcp_mem 换算：PAGE_SIZE=${page_size} bytes"
    echo "  100 MiB -> ${low} pages"
    echo "  199 MiB -> ${pressure} pages"
    echo "  399 MiB -> ${high} pages"
}

install_route_helper() {
    cat > "$ROUTE_HELPER" <<'EOF_HELPER'
#!/usr/bin/env bash
set -u
INITCWND=32
INITRWND=32

clean_route_line() {
    sed -E \
        -e 's/(^|[[:space:]])initcwnd[[:space:]]+[0-9]+//g' \
        -e 's/(^|[[:space:]])initrwnd[[:space:]]+[0-9]+//g' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/^ //' \
        -e 's/ $//'
}

apply_family() {
    local family="$1"
    local route clean

    while IFS= read -r route; do
        [ -n "$route" ] || continue
        clean="$(printf '%s\n' "$route" | clean_route_line)"
        [ -n "$clean" ] || continue

        # Intentional word splitting: iproute2 consumes the route as separate tokens.
        # shellcheck disable=SC2086
        if ip "$family" route replace $clean initcwnd "$INITCWND" initrwnd "$INITRWND" 2>/dev/null; then
            echo "[tcpfit] tuned: $clean initcwnd $INITCWND initrwnd $INITRWND"
        else
            echo "[tcpfit] warning: unable to tune route: $route" >&2
        fi
    done < <(ip "$family" route show default 2>/dev/null)
}

apply_family -4
apply_family -6
EOF_HELPER
    chmod 755 "$ROUTE_HELPER"

    cat > "$ROUTE_SERVICE" <<EOF_SERVICE
[Unit]
Description=tcpfit default-route initcwnd/initrwnd tuning
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${ROUTE_HELPER}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SERVICE

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable tcpfit-route.service >/dev/null 2>&1 || yellow "无法 enable tcpfit-route.service"
    else
        yellow "未检测到运行中的 systemd，initcwnd/initrwnd 将立即生效，但不会通过本服务开机重载。"
    fi
}

apply_sysctl() {
    blue "应用 sysctl 参数..."
    if sysctl -p "$SYSCTL_CONF"; then
        green "sysctl 参数应用完成。"
    else
        yellow "有参数应用失败。LXC/OpenVZ/Docker 等受限环境可能禁止修改部分内核参数。"
    fi
}

apply_routes() {
    blue "设置默认路由 initcwnd=${INITCWND} / initrwnd=${INITRWND}..."
    if [ -x "$ROUTE_HELPER" ]; then
        "$ROUTE_HELPER" || true
    fi
}

show_status() {
    echo "============================================================"
    echo "                     tcpfit status"
    echo "============================================================"
    echo "Kernel:    $(uname -r)"
    echo "PAGE_SIZE: $(getconf PAGESIZE 2>/dev/null || echo unknown)"
    echo

    local key value
    for key in "${SYSCTL_KEYS[@]}"; do
        if sysctl_exists "$key"; then
            value="$(get_sysctl "$key")"
            printf '%-42s = %s\n' "$key" "$value"
        else
            printf '%-42s = NOT_SUPPORTED\n' "$key"
        fi
    done

    echo
    echo "IPv4 default route:"
    ip -4 route show default 2>/dev/null || true
    echo
    echo "IPv6 default route:"
    ip -6 route show default 2>/dev/null || true
    echo

    if [ -f "$SNAPSHOT" ]; then
        echo "Original snapshot: $SNAPSHOT"
    else
        echo "Original snapshot: not found"
    fi
}

restore_route_file() {
    local family="$1"
    local file="$2"
    local route

    [ -s "$file" ] || return 0

    while IFS= read -r route; do
        [ -n "$route" ] || continue
        # Intentional word splitting for iproute2 route tokens.
        # shellcheck disable=SC2086
        ip "$family" route replace $route 2>/dev/null || \
            yellow "无法恢复路由：$route"
    done < "$file"
}

rollback() {
    if [ ! -f "$SYSCTL_SNAPSHOT" ]; then
        red "找不到原始快照：$SYSCTL_SNAPSHOT"
        exit 1
    fi

    blue "恢复调优前 sysctl 参数..."
    local key value
    while IFS='|' read -r key value; do
        [ -n "$key" ] || continue
        if sysctl_exists "$key"; then
            sysctl -w "$key=$value" >/dev/null 2>&1 || yellow "恢复失败：$key"
        fi
    done < "$SYSCTL_SNAPSHOT"

    blue "恢复调优前默认路由..."
    restore_route_file -4 "$ROUTE4_SNAPSHOT"
    restore_route_file -6 "$ROUTE6_SNAPSHOT"

    rm -f "$SYSCTL_CONF"

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable tcpfit-route.service >/dev/null 2>&1 || true
        rm -f "$ROUTE_SERVICE"
        systemctl daemon-reload >/dev/null 2>&1 || true
    else
        rm -f "$ROUTE_SERVICE"
    fi
    rm -f "$ROUTE_HELPER"

    green "已恢复首次执行 tcpfit 前的参数，并移除 tcpfit 持久化配置。"
    yellow "原始快照仍保留在：$SNAPSHOT"
}

apply_all() {
    create_snapshot
    write_sysctl_config
    install_route_helper
    apply_sysctl
    apply_routes

    echo
    green "TCP 调优完成。"
    echo "持久化配置：$SYSCTL_CONF"
    echo "原始快照：  $SNAPSHOT"
    echo
    echo "查看状态：bash $0 status"
    echo "恢复参数：bash $0 rollback"
}

usage() {
    cat <<EOF_USAGE
Usage:
  bash $0 apply       应用并永久保存 TCP 调优
  bash $0 status      查看当前 TCP 参数
  bash $0 rollback    恢复首次调优前参数
EOF_USAGE
}

main() {
    require_root
    check_dependencies
    check_system

    case "${1:-apply}" in
        apply)
            apply_all
            ;;
        status)
            show_status
            ;;
        rollback)
            rollback
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
