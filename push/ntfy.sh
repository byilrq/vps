#!/usr/bin/env bash
set -euo pipefail

# ntfy one-click installer/manager for Debian/Ubuntu VPS
# - Docker Compose deployment
# - Nginx reverse proxy
# - Reuses the same DOMAIN state and Let's Encrypt cert path style from ism.sh:
#   /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
#   /etc/letsencrypt/live/${DOMAIN}/privkey.pem
#
# Safety revision: Nginx-aware, WebSocket-aware, external-vhost-safe
# Usage:
#   bash ntfy.sh

NTFY_ROOT="/root/ntfy"
NTFY_CACHE_DIR="${NTFY_ROOT}/cache"
NTFY_ETC_DIR="${NTFY_ROOT}/etc"
NTFY_LIB_DIR="${NTFY_ROOT}/lib"
NTFY_ATTACH_DIR="${NTFY_LIB_DIR}/attachments"
NTFY_COMPOSE_FILE="${NTFY_ROOT}/docker-compose.yml"
NTFY_SERVER_FILE="${NTFY_ETC_DIR}/server.yml"
NTFY_STATE_FILE="/root/.ntfy_install.conf"
ISM_STATE_FILE="/root/.asset_manager_install.conf"
NTFY_BOOT_GUARD_SCRIPT="/usr/local/sbin/ntfy-boot-guard.sh"
NTFY_BOOT_GUARD_SERVICE="/etc/systemd/system/ntfy-boot-guard.service"

SERVICE_NAME="ntfy"
CONTAINER_NAME="ntfy"
INTERNAL_PORT="8083"
PUBLIC_PORT="8183"
DOMAIN=""
NTFY_BASE_URL=""
NTFY_ENABLE_AUTH="true"
NTFY_ADMIN_USER="admin"
NTFY_ADMIN_PASS=""
NTFY_DEFAULT_TOPIC="let-rss"
NTFY_DEFAULT_PRIORITY="4"
NTFY_DEFAULT_TAGS="rss,white_check_mark"

# 新安装默认只把 ntfy 后端暴露给本机 Nginx；旧安装会自动保留现有绑定。
NTFY_BIND_HOST=""
# 记录“本脚本自己管理”的 Nginx 文件，端口变化时也只清理这一份。
NTFY_MANAGED_NGINX_FILE=""
NTFY_MANAGED_NGINX_LINK=""
NGINX_MANAGED_MARKER="# Managed by ntfy.sh"

NGINX_SITE_FILE="/etc/nginx/sites-available/${SERVICE_NAME}_${PUBLIC_PORT}.conf"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/${SERVICE_NAME}_${PUBLIC_PORT}.conf"

NC='\033[0m'
BOLD='\033[1m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
CYAN='\033[96m'
BLUE='\033[94m'
MAGENTA='\033[95m'
WHITE='\033[97m'

green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }
cyan() { printf '\033[36m%s\033[0m\n' "$*"; }

info() { cyan "[INFO] $*"; }
ok() { green "[OK] $*"; }
warn() { yellow "[WARN] $*"; }
err() { red "[ERR] $*"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "请使用 root 运行：sudo bash ntfy.sh"
        exit 1
    fi
}

load_ism_domain_once() {
    if [ -z "${DOMAIN:-}" ] && [ -f "$ISM_STATE_FILE" ]; then
        # shellcheck disable=SC1090
        . "$ISM_STATE_FILE" || true
        : "${DOMAIN:=}"
    fi
}

load_state() {
    if [ -f "$NTFY_STATE_FILE" ]; then
        # shellcheck disable=SC1090
        . "$NTFY_STATE_FILE"
    else
        load_ism_domain_once
    fi
    : "${NTFY_ROOT:=/root/ntfy}"
    : "${NTFY_CACHE_DIR:=${NTFY_ROOT}/cache}"
    : "${NTFY_ETC_DIR:=${NTFY_ROOT}/etc}"
    : "${NTFY_LIB_DIR:=${NTFY_ROOT}/lib}"
    : "${NTFY_ATTACH_DIR:=${NTFY_LIB_DIR}/attachments}"
    : "${NTFY_COMPOSE_FILE:=${NTFY_ROOT}/docker-compose.yml}"
    : "${NTFY_SERVER_FILE:=${NTFY_ETC_DIR}/server.yml}"
    : "${INTERNAL_PORT:=8083}"
    : "${PUBLIC_PORT:=2085}"
    : "${DOMAIN:=}"
    : "${NTFY_BASE_URL:=}"
    : "${NTFY_ENABLE_AUTH:=true}"
    : "${NTFY_ADMIN_USER:=admin}"
    : "${NTFY_ADMIN_PASS:=}"
    : "${NTFY_DEFAULT_TOPIC:=let-rss}"
    : "${NTFY_DEFAULT_PRIORITY:=4}"
    : "${NTFY_DEFAULT_TAGS:=rss,white_check_mark}"
    : "${NTFY_BIND_HOST:=}"
    : "${NTFY_MANAGED_NGINX_FILE:=}"
    : "${NTFY_MANAGED_NGINX_LINK:=}"

    NGINX_SITE_FILE="/etc/nginx/sites-available/${SERVICE_NAME}_${PUBLIC_PORT}.conf"
    NGINX_SITE_LINK="/etc/nginx/sites-enabled/${SERVICE_NAME}_${PUBLIC_PORT}.conf"

    detect_compose_bind_host

    # 兼容旧版脚本：若旧版已经创建了当前 ntfy_<port>.conf，则把它认作本脚本旧配置。
    if [ -z "${NTFY_MANAGED_NGINX_FILE:-}" ] && [ -f "$NGINX_SITE_FILE" ]; then
        NTFY_MANAGED_NGINX_FILE="$NGINX_SITE_FILE"
        NTFY_MANAGED_NGINX_LINK="$NGINX_SITE_LINK"
    fi
}

save_state() {
    cat > "$NTFY_STATE_FILE" <<EOF_STATE
NTFY_ROOT=${NTFY_ROOT@Q}
NTFY_CACHE_DIR=${NTFY_CACHE_DIR@Q}
NTFY_ETC_DIR=${NTFY_ETC_DIR@Q}
NTFY_LIB_DIR=${NTFY_LIB_DIR@Q}
NTFY_ATTACH_DIR=${NTFY_ATTACH_DIR@Q}
NTFY_COMPOSE_FILE=${NTFY_COMPOSE_FILE@Q}
NTFY_SERVER_FILE=${NTFY_SERVER_FILE@Q}
INTERNAL_PORT=${INTERNAL_PORT@Q}
PUBLIC_PORT=${PUBLIC_PORT@Q}
DOMAIN=${DOMAIN@Q}
NTFY_BASE_URL=${NTFY_BASE_URL@Q}
NTFY_ENABLE_AUTH=${NTFY_ENABLE_AUTH@Q}
NTFY_ADMIN_USER=${NTFY_ADMIN_USER@Q}
NTFY_ADMIN_PASS=${NTFY_ADMIN_PASS@Q}
NTFY_DEFAULT_TOPIC=${NTFY_DEFAULT_TOPIC@Q}
NTFY_DEFAULT_PRIORITY=${NTFY_DEFAULT_PRIORITY@Q}
NTFY_DEFAULT_TAGS=${NTFY_DEFAULT_TAGS@Q}
NTFY_BIND_HOST=${NTFY_BIND_HOST@Q}
NTFY_MANAGED_NGINX_FILE=${NTFY_MANAGED_NGINX_FILE@Q}
NTFY_MANAGED_NGINX_LINK=${NTFY_MANAGED_NGINX_LINK@Q}
EOF_STATE
    chmod 600 "$NTFY_STATE_FILE" 2>/dev/null || true
}

get_host_ip() {
    hostname -I 2>/dev/null | awk '{print $1}'
}

wait_for_port() {
    local port="$1"
    local tries="${2:-15}"
    local i
    for i in $(seq 1 "$tries"); do
        if ss -lnt 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_ntfy_health() {
    # 端口监听 != ntfy 已可用；必须等健康接口真正返回 healthy=true。
    local tries="${1:-45}"
    local i body
    for i in $(seq 1 "$tries"); do
        body="$(curl -fsS --max-time 3 "http://127.0.0.1:${INTERNAL_PORT}/v1/health" 2>/dev/null || true)"
        if printf '%s' "$body" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_proxy_health() {
    # 从本机穿过 Nginx 反代检查，不依赖公网 NAT 回环。
    local tries="${1:-30}"
    local i body scheme="http"
    if [[ "${NTFY_BASE_URL:-}" == https://* ]]; then
        scheme="https"
    fi
    for i in $(seq 1 "$tries"); do
        if [ -n "${DOMAIN:-}" ]; then
            body="$(curl -kfsS --max-time 4 \
                --resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1" \
                "${scheme}://${DOMAIN}:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
        else
            body="$(curl -fsS --max-time 4 \
                "http://127.0.0.1:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
        fi
        if printf '%s' "$body" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

get_local_ws_code() {
    # 返回本机经 Nginx 到 ntfy 的 WebSocket 握手 HTTP 状态码。
    local scheme="http"
    local -a args
    if [[ "${NTFY_BASE_URL:-}" == https://* ]]; then
        scheme="https"
    fi

    args=(-k -sS --http1.1 --max-time 4 -o /dev/null -w '%{http_code}'
          -H 'Connection: Upgrade'
          -H 'Upgrade: websocket'
          -H 'Sec-WebSocket-Version: 13'
          -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==')

    if [ "${NTFY_ENABLE_AUTH:-false}" = "true" ] && [ -n "${NTFY_ADMIN_USER:-}" ] && [ -n "${NTFY_ADMIN_PASS:-}" ]; then
        args+=(-u "${NTFY_ADMIN_USER}:${NTFY_ADMIN_PASS}")
    fi

    if [ -n "${DOMAIN:-}" ]; then
        args+=(--resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1"
              "${scheme}://${DOMAIN}:${PUBLIC_PORT}/${NTFY_DEFAULT_TOPIC}/ws")
    else
        args+=("http://127.0.0.1:${PUBLIC_PORT}/${NTFY_DEFAULT_TOPIC}/ws")
    fi

    curl "${args[@]}" 2>/dev/null || true
}

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        return 1
    fi
}

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    info "安装依赖：Docker / Docker Compose / Nginx / curl / ca-certificates"

    apt-get update
    apt-get install -y curl ca-certificates gnupg lsb-release openssl

    # 不盲目重装/重启 Nginx，避免影响服务器上的其他站点。
    if ! command -v nginx >/dev/null 2>&1; then
        apt-get install -y nginx
    else
        ok "nginx 已安装，跳过重装"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        warn "未检测到 Docker，使用系统仓库安装 docker.io"
        apt-get install -y docker.io
    fi

    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
        warn "未检测到 Docker Compose，尝试安装 docker-compose-plugin / docker-compose"
        apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
    fi

    systemctl enable --now docker

    # 无论 Nginx 当前是否已运行，都确保开机自启；enable 不会中断现有连接。
    systemctl enable nginx >/dev/null 2>&1 || warn "无法设置 nginx 开机自启，请手动执行：systemctl enable nginx"
    if systemctl is-active --quiet nginx 2>/dev/null; then
        ok "nginx 已在运行；不执行 restart"
    else
        # Nginx 未运行时也必须先检查整个配置，避免启动一个有错误的全局配置。
        if nginx -t >/tmp/ntfy_nginx_test.out 2>&1; then
            systemctl start nginx
            ok "nginx 已启动并设置开机自启"
        else
            warn "nginx 当前未运行，且 nginx -t 未通过；为避免影响其他站点，本脚本不会强制启动"
            sed 's/^/  /' /tmp/ntfy_nginx_test.out 2>/dev/null || true
        fi
    fi
    ok "依赖安装完成"
}

normalize_bool() {
    local v="${1:-}"
    case "$v" in
        y|Y|yes|YES|Yes|true|TRUE|1|开启|是) echo "true" ;;
        n|N|no|NO|No|false|FALSE|0|关闭|否|DELETE|delete|删除|清空) echo "false" ;;
        *) echo "$v" ;;
    esac
}

is_delete_input() {
    case "${1:-}" in
        DELETE|delete|Delete|删除|清空|移除) return 0 ;;
        *) return 1 ;;
    esac
}

apply_text_input() {
    # 用法：apply_text_input 变量名 输入值
    # 留空=保持；输入 DELETE/删除/清空=清空该配置；其它内容=设置新值
    local var_name="$1"
    local input_value="${2:-}"
    if is_delete_input "$input_value"; then
        printf -v "$var_name" '%s' ""
    elif [ -n "$input_value" ]; then
        printf -v "$var_name" '%s' "$input_value"
    fi
}

apply_port_input() {
    # 端口不能真正清空；输入 DELETE/删除/清空=恢复默认端口
    local var_name="$1"
    local input_value="${2:-}"
    local default_value="$3"
    if is_delete_input "$input_value"; then
        printf -v "$var_name" '%s' "$default_value"
    elif [ -n "$input_value" ]; then
        printf -v "$var_name" '%s' "$input_value"
    fi
}

validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        err "端口无效：${port}，请输入 1-65535 之间的数字"
        return 1
    fi
}

open_firewall_port() {
    local port="$1"
    validate_port "$port" || return 1

    info "尝试自动放行防火墙端口：${port}/tcp"

    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qi "Status: active"; then
            ufw allow "${port}/tcp" >/dev/null 2>&1 || warn "ufw 放行 ${port}/tcp 失败，请手动检查"
            ok "ufw 已放行 ${port}/tcp"
            return 0
        fi
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || warn "firewalld 永久放行 ${port}/tcp 失败"
            firewall-cmd --reload >/dev/null 2>&1 || warn "firewalld reload 失败"
            ok "firewalld 已放行 ${port}/tcp"
            return 0
        fi
    fi

    if command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
            iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || warn "iptables 放行 ${port}/tcp 失败，请手动检查"
        fi
        ok "iptables 当前会话已放行 ${port}/tcp（如需持久化，请确认系统已安装 iptables-persistent）"
        return 0
    fi

    warn "未检测到 ufw/firewalld/iptables，若云厂商安全组或系统防火墙拦截，请手动放行 ${port}/tcp"
}

close_firewall_port() {
    local port="$1"
    validate_port "$port" || return 0

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
    fi
}

# 修复旧版 domain.sh 等脚本破坏的 Docker iptables NAT 链
repair_docker_iptables() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 0
    fi
    if ! iptables -t nat -L DOCKER >/dev/null 2>&1; then
        info "检测到 Docker NAT 链缺失，正在重建..."
        systemctl restart docker 2>/dev/null || true
        sleep 3
        ok "Docker iptables 规则已重建"
    fi
}

refresh_base_url() {
    if [ -n "${DOMAIN:-}" ]; then
        if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]; then
            NTFY_BASE_URL="https://${DOMAIN}:${PUBLIC_PORT}"
        else
            NTFY_BASE_URL="http://${DOMAIN}:${PUBLIC_PORT}"
        fi
    else
        local ip
        ip="$(get_host_ip || true)"
        NTFY_BASE_URL="http://${ip:-服务器IP}:${PUBLIC_PORT}"
    fi
}

detect_compose_bind_host() {
    # 新安装默认 127.0.0.1；若已有 Compose，则保留原绑定，避免升级时突然改变访问方式。
    if [ -n "${NTFY_BIND_HOST:-}" ]; then
        return 0
    fi

    NTFY_BIND_HOST="127.0.0.1"
    if [ -f "${NTFY_COMPOSE_FILE:-}" ]; then
        local bind_line
        bind_line="$(grep -E '^[[:space:]]*-[[:space:]]*"?((0\.0\.0\.0|127\.0\.0\.1):)?[0-9]+:80"?[[:space:]]*$' "$NTFY_COMPOSE_FILE" 2>/dev/null | head -n 1 || true)"
        case "$bind_line" in
            *127.0.0.1:*) NTFY_BIND_HOST="127.0.0.1" ;;
            *0.0.0.0:*) NTFY_BIND_HOST="0.0.0.0" ;;
            "") ;;
            *) NTFY_BIND_HOST="0.0.0.0" ;;
        esac
    fi
}

is_ntfy_owned_nginx_path() {
    local path="${1:-}"
    [ -n "$path" ] || return 1
    case "$path" in
        /etc/nginx/sites-available/ntfy_*.conf|/etc/nginx/sites-enabled/ntfy_*.conf) return 0 ;;
        *) return 1 ;;
    esac
}

is_ntfy_managed_file() {
    local file="${1:-}"
    [ -f "$file" ] || return 1
    grep -Fq "$NGINX_MANAGED_MARKER" "$file" 2>/dev/null && return 0
    # 兼容旧版：只承认 ntfy_<port>.conf 这个专用命名，不承认任何其它站点配置。
    is_ntfy_owned_nginx_path "$file"
}

nginx_file_matches_endpoint() {
    local file="$1"
    [ -f "$file" ] || return 1

    grep -Eq "^[[:space:]]*listen[[:space:]]+([^;]*:)?${PUBLIC_PORT}([[:space:]]|;)" "$file" 2>/dev/null || return 1
    if [ -n "${DOMAIN:-}" ]; then
        grep -E '^[[:space:]]*server_name[[:space:]]+' "$file" 2>/dev/null | grep -Fq "$DOMAIN" || return 1
    fi
    return 0
}

get_effective_nginx_configs() {
    # 只扫描真正会被 nginx include 的常见 enabled 目录；只读，不修改。
    local file
    for file in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [ -f "$file" ] || continue
        if nginx_file_matches_endpoint "$file"; then
            printf '%s\n' "$file"
        fi
    done
}

get_foreign_nginx_configs() {
    local file real_file current_real managed_real
    current_real="$(readlink -f "$NGINX_SITE_FILE" 2>/dev/null || printf '%s' "$NGINX_SITE_FILE")"
    managed_real=""
    if [ -n "${NTFY_MANAGED_NGINX_FILE:-}" ]; then
        managed_real="$(readlink -f "$NTFY_MANAGED_NGINX_FILE" 2>/dev/null || printf '%s' "$NTFY_MANAGED_NGINX_FILE")"
    fi

    while IFS= read -r file; do
        [ -n "$file" ] || continue
        real_file="$(readlink -f "$file" 2>/dev/null || printf '%s' "$file")"
        if [ "$real_file" = "$current_real" ] || { [ -n "$managed_real" ] && [ "$real_file" = "$managed_real" ]; }; then
            continue
        fi
        printf '%s\n' "$file"
    done < <(get_effective_nginx_configs)
}

safe_remove_managed_nginx_config() {
    local file="${1:-}"
    local link="${2:-}"
    [ -n "$file" ] || return 0

    if [ -e "$file" ] && ! is_ntfy_managed_file "$file"; then
        warn "拒绝删除非 ntfy 自管配置：${file}"
        return 1
    fi

    if [ -n "$link" ] && [ -L "$link" ]; then
        local target
        target="$(readlink -f "$link" 2>/dev/null || true)"
        if [ -z "$target" ] || [ "$target" = "$(readlink -f "$file" 2>/dev/null || printf '%s' "$file")" ]; then
            rm -f "$link"
        else
            warn "链接 ${link} 已指向其它文件，未删除"
        fi
    fi
    [ -e "$file" ] && rm -f "$file"
    return 0
}

show_effective_nginx_configs() {
    local configs file real_file own="false"
    configs="$(get_effective_nginx_configs || true)"
    if [ -z "$configs" ]; then
        echo "  实际生效：未发现匹配 ${DOMAIN:-_}:${PUBLIC_PORT} 的 enabled 配置"
        return 1
    fi

    echo "  实际生效："
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        real_file="$(readlink -f "$file" 2>/dev/null || printf '%s' "$file")"
        echo "    - ${file} -> ${real_file}"
        if [ "$real_file" = "$(readlink -f "$NGINX_SITE_FILE" 2>/dev/null || printf '%s' "$NGINX_SITE_FILE")" ]; then
            own="true"
        elif [ -n "${NTFY_MANAGED_NGINX_FILE:-}" ] && [ "$real_file" = "$(readlink -f "$NTFY_MANAGED_NGINX_FILE" 2>/dev/null || printf '%s' "$NTFY_MANAGED_NGINX_FILE")" ]; then
            own="true"
        fi
    done <<< "$configs"

    if [ "$own" = "true" ]; then
        green "  [OK] 当前端点包含 ntfy.sh 自管 Nginx 配置"
    else
        yellow "  [WARN] 当前端点由外部 Nginx 配置接管；ntfy.sh 只检测，不会覆盖/删除它"
    fi
    return 0
}

prompt_value() {
    local prompt="$1" default="$2" var_name="$3" input
    if [ -n "$default" ]; then
        stty sane 2>/dev/null || true
        read -e -r -p "$prompt [$default]: " input
    else
        stty sane 2>/dev/null || true
        read -e -r -p "$prompt: " input
    fi
    if [ -z "${input:-}" ] && [ -n "$default" ]; then
        printf -v "$var_name" '%s' "$default"
    elif [ -n "${input:-}" ]; then
        printf -v "$var_name" '%s' "$input"
    else
        return 1
    fi
    return 0
}

prompt_required() {
    local prompt="$1" var_name="$2" input
    while true; do
        stty sane 2>/dev/null || true
        read -e -r -p "$prompt: " input
        if [ -n "${input:-}" ]; then
            printf -v "$var_name" '%s' "$input"
            return 0
        fi
        err "不能为空，请重新输入"
    done
}

prompt_port() {
    local prompt="$1" default="$2" var_name="$3" input
    while true; do
        if [ -n "$default" ]; then
            stty sane 2>/dev/null || true
            read -e -r -p "$prompt [$default]: " input
        else
            stty sane 2>/dev/null || true
            read -e -r -p "$prompt: " input
        fi
        if [ -z "${input:-}" ] && [ -n "$default" ]; then
            printf -v "$var_name" '%s' "$default"
            return 0
        fi
        if [ -n "${input:-}" ]; then
            if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le 65535 ]; then
                printf -v "$var_name" '%s' "$input"
                return 0
            fi
            err "端口无效，请输入 1-65535 之间的数字"
        fi
    done
}

prompt_basic_config() {
    load_state
    echo "ntfy 基础配置"
    echo "  回车=使用当前值（括号内显示），无默认值时不能留空"
    echo

    stty sane 2>/dev/null || true
    prompt_value "域名（留空用 IP）" "${DOMAIN:-}" DOMAIN

    prompt_port "Nginx 外部端口" "${PUBLIC_PORT}" PUBLIC_PORT

    prompt_port "容器内部映射端口" "${INTERNAL_PORT}" INTERNAL_PORT

    prompt_value "默认推送 Topic" "${NTFY_DEFAULT_TOPIC}" NTFY_DEFAULT_TOPIC

    prompt_value "默认优先级 1-5" "${NTFY_DEFAULT_PRIORITY}" NTFY_DEFAULT_PRIORITY

    prompt_value "默认 Tags（逗号分隔）" "${NTFY_DEFAULT_TAGS}" NTFY_DEFAULT_TAGS

    local auth_default
    if [ "${NTFY_ENABLE_AUTH}" = "true" ]; then auth_default="yes"; else auth_default="no"; fi
    prompt_value "开启登录认证（yes/no）" "${auth_default}" NTFY_ENABLE_AUTH_INPUT
    NTFY_ENABLE_AUTH="$(normalize_bool "${NTFY_ENABLE_AUTH_INPUT:-$auth_default}")"

    if [ "${NTFY_ENABLE_AUTH}" = "true" ]; then
        prompt_value "管理员用户名" "${NTFY_ADMIN_USER}" NTFY_ADMIN_USER

        local pass_display input_pass
        if [ -n "${NTFY_ADMIN_PASS:-}" ]; then
            pass_display="********"
        else
            pass_display=""
        fi
        stty sane 2>/dev/null || true
        read -e -r -p "管理员密码（回车=自动生成，输入=设置密码）[${pass_display:-自动生成}]: " input_pass
        if [ -z "${input_pass:-}" ] && [ -z "${NTFY_ADMIN_PASS:-}" ]; then
            NTFY_ADMIN_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
            echo "  已自动生成密码: $NTFY_ADMIN_PASS"
        elif [ -n "${input_pass:-}" ]; then
            NTFY_ADMIN_PASS="$input_pass"
        fi
        # else keep existing
    else
        NTFY_ADMIN_USER="${NTFY_ADMIN_USER:-admin}"
        NTFY_ADMIN_PASS=""
    fi

    refresh_base_url
    save_state
    ok "配置已保存：${NTFY_STATE_FILE}"
}
write_server_config() {
    mkdir -p "$NTFY_ETC_DIR" "$NTFY_CACHE_DIR" "$NTFY_LIB_DIR" "$NTFY_ATTACH_DIR"
    refresh_base_url

    if [ "${NTFY_ENABLE_AUTH}" = "true" ]; then
        cat > "$NTFY_SERVER_FILE" <<EOF_SERVER_AUTH
base-url: "${NTFY_BASE_URL}"
listen-http: ":80"
behind-proxy: true
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/auth.db"
auth-default-access: "deny-all"
enable-login: true
attachment-cache-dir: "/var/lib/ntfy/attachments"
attachment-total-size-limit: "1G"
attachment-file-size-limit: "20M"
attachment-expiry-duration: "24h"
EOF_SERVER_AUTH
    else
        cat > "$NTFY_SERVER_FILE" <<EOF_SERVER_OPEN
base-url: "${NTFY_BASE_URL}"
listen-http: ":80"
behind-proxy: true
cache-file: "/var/cache/ntfy/cache.db"
auth-default-access: "read-write"
enable-login: false
attachment-cache-dir: "/var/lib/ntfy/attachments"
attachment-total-size-limit: "1G"
attachment-file-size-limit: "20M"
attachment-expiry-duration: "24h"
EOF_SERVER_OPEN
    fi

    ok "ntfy server.yml 已写入：${NTFY_SERVER_FILE}"
}

write_compose() {
    mkdir -p "$NTFY_ROOT" "$NTFY_CACHE_DIR" "$NTFY_ETC_DIR" "$NTFY_LIB_DIR" "$NTFY_ATTACH_DIR"
    detect_compose_bind_host
    cat > "$NTFY_COMPOSE_FILE" <<EOF_COMPOSE
services:
  ntfy:
    image: binwiederhier/ntfy:latest
    container_name: ${CONTAINER_NAME}
    command:
      - serve
    restart: unless-stopped
    ports:
      - "${NTFY_BIND_HOST}:${INTERNAL_PORT}:80"
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - ./cache:/var/cache/ntfy
      - ./etc:/etc/ntfy
      - ./lib:/var/lib/ntfy
EOF_COMPOSE
    ok "Docker Compose 已写入：${NTFY_COMPOSE_FILE}（后端绑定 ${NTFY_BIND_HOST}:${INTERNAL_PORT}）"
}

start_ntfy() {
    local cmd
    cmd="$(compose_cmd)"
    info "启动 ntfy 容器"
    # 先修复 Docker iptables（旧版 domain.sh 等脚本可能已破坏）
    repair_docker_iptables
    (cd "$NTFY_ROOT" && $cmd up -d)

    if wait_for_port "$INTERNAL_PORT" 30; then
        ok "ntfy 已监听宿主机端口 ${INTERNAL_PORT}"
    else
        warn "暂未检测到 ${INTERNAL_PORT} 端口监听，请执行：cd ${NTFY_ROOT} && ${cmd} logs --tail=100 ntfy"
    fi
}

ensure_admin_user() {
    load_state
    if [ "${NTFY_ENABLE_AUTH}" != "true" ]; then
        return 0
    fi

    if [ -z "${NTFY_ADMIN_USER:-}" ] || [ -z "${NTFY_ADMIN_PASS:-}" ]; then
        warn "未设置管理员账号或密码，跳过用户创建"
        return 0
    fi

    info "创建/更新 ntfy 管理员账号：${NTFY_ADMIN_USER}"
    # ntfy user add 是交互式密码输入；这里通过 printf 喂两次密码。
    if docker exec -i "$CONTAINER_NAME" ntfy user add --role=admin "$NTFY_ADMIN_USER" >/tmp/ntfy_user_add.out 2>&1 <<EOF_PASS
${NTFY_ADMIN_PASS}
${NTFY_ADMIN_PASS}
EOF_PASS
    then
        ok "管理员账号已创建：${NTFY_ADMIN_USER}"
    else
        if grep -qiE "already exists|exists|duplicate" /tmp/ntfy_user_add.out 2>/dev/null; then
            if docker exec -i "$CONTAINER_NAME" ntfy user change-pass "$NTFY_ADMIN_USER" >/tmp/ntfy_user_pass.out 2>&1 <<EOF_PASS2
${NTFY_ADMIN_PASS}
${NTFY_ADMIN_PASS}
EOF_PASS2
            then
                ok "管理员密码已更新：${NTFY_ADMIN_USER}"
            else
                warn "账号已存在，但自动更新密码失败。你可以手动执行：docker exec -it ${CONTAINER_NAME} ntfy user change-pass ${NTFY_ADMIN_USER}"
                cat /tmp/ntfy_user_pass.out 2>/dev/null || true
            fi
        else
            warn "自动创建管理员失败。你可以手动执行：docker exec -it ${CONTAINER_NAME} ntfy user add --role=admin ${NTFY_ADMIN_USER}"
            cat /tmp/ntfy_user_add.out 2>/dev/null || true
        fi
    fi
}

write_nginx_http() {
    cat > "$NGINX_SITE_FILE" <<EOF_NGINX_HTTP
${NGINX_MANAGED_MARKER}
# This file is owned by ntfy.sh. Other Nginx vhosts are never modified by this script.
server {
    listen ${PUBLIC_PORT};
    listen [::]:${PUBLIC_PORT};
    server_name ${DOMAIN:-_};

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:${INTERNAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_redirect off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
    }
}
EOF_NGINX_HTTP
}

write_nginx_https() {
    local cert_dir="/etc/letsencrypt/live/${DOMAIN}"
    cat > "$NGINX_SITE_FILE" <<EOF_NGINX_HTTPS
${NGINX_MANAGED_MARKER}
# This file is owned by ntfy.sh. Other Nginx vhosts are never modified by this script.
server {
    listen ${PUBLIC_PORT} ssl;
    listen [::]:${PUBLIC_PORT} ssl;
    http2 on;
    server_name ${DOMAIN};

    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:${INTERNAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_redirect off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
    }
}
EOF_NGINX_HTTPS
}

configure_nginx() {
    load_state
    NGINX_SITE_FILE="/etc/nginx/sites-available/${SERVICE_NAME}_${PUBLIC_PORT}.conf"
    NGINX_SITE_LINK="/etc/nginx/sites-enabled/${SERVICE_NAME}_${PUBLIC_PORT}.conf"

    info "安全配置 Nginx 反向代理"
    systemctl enable nginx >/dev/null 2>&1 || warn "无法设置 nginx 开机自启，请手动执行：systemctl enable nginx"

    # 先识别是否已有其它配置接管相同 域名+端口。发现后绝不覆盖、绝不删除。
    local foreign_configs
    foreign_configs="$(get_foreign_nginx_configs || true)"
    if [ -n "$foreign_configs" ]; then
        warn "检测到相同端点已由其它 Nginx 配置接管："
        while IFS= read -r file; do
            [ -n "$file" ] && echo "  - ${file} -> $(readlink -f "$file" 2>/dev/null || printf '%s' "$file")"
        done <<< "$foreign_configs"
        warn "为避免影响其它 Nginx 服务，本脚本不会覆盖、删除或 reload 这些配置。"
        warn "若该外部配置本来就是给 ntfy 使用，请保持它；菜单 [4] 会实际检查 HTTP 与 WebSocket。"

        refresh_base_url
        save_state
        write_server_config
        if [ -f "$NTFY_COMPOSE_FILE" ]; then
            local cmd_external
            cmd_external="$(compose_cmd || true)"
            if [ -n "${cmd_external:-}" ]; then
                (cd "$NTFY_ROOT" && $cmd_external restart ntfy) || true
            fi
        fi
        open_firewall_port "$PUBLIC_PORT" || true
        return 0
    fi

    # 如果端口被非 Nginx 进程占用，也不强抢。
    if ss -lntp 2>/dev/null | grep -E ":${PUBLIC_PORT}\b" | grep -vq 'nginx'; then
        err "端口 ${PUBLIC_PORT} 已被非 Nginx 进程占用；为避免影响其它服务，停止写入反代配置。"
        ss -lntp 2>/dev/null | grep -E ":${PUBLIC_PORT}\b" || true
        return 1
    fi

    # 目标 ntfy_<port>.conf 若存在但不像 ntfy 自管文件，则拒绝覆盖。
    if [ -e "$NGINX_SITE_FILE" ] && ! is_ntfy_managed_file "$NGINX_SITE_FILE"; then
        err "目标文件已存在但不属于 ntfy.sh：${NGINX_SITE_FILE}"
        err "为避免覆盖其它配置，本脚本已停止。"
        return 1
    fi

    local backup_file="" old_link_target="" had_link="false"
    if [ -f "$NGINX_SITE_FILE" ]; then
        backup_file="$(mktemp /tmp/ntfy_nginx_backup.XXXXXX)"
        cp -a "$NGINX_SITE_FILE" "$backup_file"
    fi
    if [ -L "$NGINX_SITE_LINK" ]; then
        had_link="true"
        old_link_target="$(readlink "$NGINX_SITE_LINK" 2>/dev/null || true)"
    fi

    if [ -n "${DOMAIN:-}" ] && [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]; then
        write_nginx_https
        NTFY_BASE_URL="https://${DOMAIN}:${PUBLIC_PORT}"
        ok "检测到证书，准备使用 ${NTFY_BASE_URL}"
    else
        write_nginx_http
        if [ -n "${DOMAIN:-}" ]; then
            NTFY_BASE_URL="http://${DOMAIN}:${PUBLIC_PORT}"
            warn "未找到 /etc/letsencrypt/live/${DOMAIN}/ 证书，准备使用 ${NTFY_BASE_URL}"
        else
            local ip
            ip="$(get_host_ip || true)"
            NTFY_BASE_URL="http://${ip:-服务器IP}:${PUBLIC_PORT}"
            warn "未填写域名，准备使用 ${NTFY_BASE_URL}"
        fi
    fi

    ln -sfn "$NGINX_SITE_FILE" "$NGINX_SITE_LINK"

    # 任何 Nginx 修改都必须先通过全局语法检查；失败立即回滚 ntfy 自己的文件。
    if ! nginx -t >/tmp/ntfy_nginx_test.out 2>&1; then
        red "[FAIL] nginx -t 未通过，已取消本次 ntfy 反代修改："
        sed 's/^/  /' /tmp/ntfy_nginx_test.out 2>/dev/null || true
        if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
            cp -a "$backup_file" "$NGINX_SITE_FILE"
        else
            rm -f "$NGINX_SITE_FILE"
        fi
        if [ "$had_link" = "true" ]; then
            ln -sfn "$old_link_target" "$NGINX_SITE_LINK"
        else
            rm -f "$NGINX_SITE_LINK"
        fi
        rm -f "$backup_file" 2>/dev/null || true
        return 1
    fi

    # 新配置通过后，才清理“状态文件记录的上一份 ntfy 自管配置”；不会使用 ntfy_*.conf 通配删除。
    local previous_file="${NTFY_MANAGED_NGINX_FILE:-}"
    local previous_link="${NTFY_MANAGED_NGINX_LINK:-}"
    if [ -n "$previous_file" ] && [ "$previous_file" != "$NGINX_SITE_FILE" ]; then
        safe_remove_managed_nginx_config "$previous_file" "$previous_link" || true
        if ! nginx -t >/tmp/ntfy_nginx_test.out 2>&1; then
            warn "清理旧 ntfy 配置后 nginx -t 出现异常，请检查；未执行 reload。"
            sed 's/^/  /' /tmp/ntfy_nginx_test.out 2>/dev/null || true
            return 1
        fi
    fi

    NTFY_MANAGED_NGINX_FILE="$NGINX_SITE_FILE"
    NTFY_MANAGED_NGINX_LINK="$NGINX_SITE_LINK"
    save_state
    write_server_config

    # 只在 ntfy 自管配置实际变化且 nginx -t 成功后 reload；永不 restart Nginx。
    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx
        ok "Nginx 已安全 reload（未 restart，不会主动中断其它站点）"
    else
        if nginx -t >/dev/null 2>&1; then
            systemctl start nginx
            ok "Nginx 原先未运行，配置检查通过后已启动"
        else
            err "Nginx 未运行且配置检查失败，未启动"
            return 1
        fi
    fi

    rm -f "$backup_file" 2>/dev/null || true
    open_firewall_port "$PUBLIC_PORT" || true

    # base-url 变化后只重启 ntfy 容器，不操作 Nginx。
    if [ -f "$NTFY_COMPOSE_FILE" ]; then
        local cmd
        cmd="$(compose_cmd || true)"
        if [ -n "${cmd:-}" ]; then
            (cd "$NTFY_ROOT" && $cmd restart ntfy) || true
        fi
    fi

    if wait_for_port "$PUBLIC_PORT" 10; then
        ok "ntfy 自管反代已生效，端口 ${PUBLIC_PORT} 正在监听"
    else
        warn "端口 ${PUBLIC_PORT} 暂未监听，请运行菜单 [4] 查看实际状态"
    fi
}

install_boot_guard() {
    load_state
    info "安装/刷新 ntfy 开机自愈服务"

    cat > "$NTFY_BOOT_GUARD_SCRIPT" <<'EOF_BOOT_GUARD'
#!/usr/bin/env bash
set -u

STATE_FILE="/root/.ntfy_install.conf"
LOG_TAG="ntfy-boot-guard"

log() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*"
    logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true
}

[ -f "$STATE_FILE" ] || { log "state file missing: $STATE_FILE"; exit 1; }
# shellcheck disable=SC1090
. "$STATE_FILE"

: "${NTFY_ROOT:=/root/ntfy}"
: "${NTFY_COMPOSE_FILE:=${NTFY_ROOT}/docker-compose.yml}"
: "${INTERNAL_PORT:=8083}"
: "${PUBLIC_PORT:=8183}"
: "${DOMAIN:=}"
: "${NTFY_BASE_URL:=}"
: "${NTFY_ENABLE_AUTH:=true}"
: "${NTFY_ADMIN_USER:=admin}"
: "${NTFY_ADMIN_PASS:=}"
: "${NTFY_DEFAULT_TOPIC:=let-rss}"

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        return 1
    fi
}

wait_internal_health() {
    local i body
    for i in $(seq 1 60); do
        body="$(curl -fsS --max-time 3 "http://127.0.0.1:${INTERNAL_PORT}/v1/health" 2>/dev/null || true)"
        if printf '%s' "$body" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_proxy_health() {
    local i body scheme="http"
    [[ "${NTFY_BASE_URL:-}" == https://* ]] && scheme="https"
    for i in $(seq 1 30); do
        if [ -n "${DOMAIN:-}" ]; then
            body="$(curl -kfsS --max-time 4 --resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1" \
                "${scheme}://${DOMAIN}:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
        else
            body="$(curl -fsS --max-time 4 "http://127.0.0.1:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
        fi
        if printf '%s' "$body" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ws_code() {
    local scheme="http"
    local -a args
    [[ "${NTFY_BASE_URL:-}" == https://* ]] && scheme="https"
    args=(-k -sS --http1.1 --max-time 4 -o /dev/null -w '%{http_code}'
          -H 'Connection: Upgrade'
          -H 'Upgrade: websocket'
          -H 'Sec-WebSocket-Version: 13'
          -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==')
    if [ "${NTFY_ENABLE_AUTH:-false}" = "true" ] && [ -n "${NTFY_ADMIN_USER:-}" ] && [ -n "${NTFY_ADMIN_PASS:-}" ]; then
        args+=(-u "${NTFY_ADMIN_USER}:${NTFY_ADMIN_PASS}")
    fi
    if [ -n "${DOMAIN:-}" ]; then
        args+=(--resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1"
              "${scheme}://${DOMAIN}:${PUBLIC_PORT}/${NTFY_DEFAULT_TOPIC}/ws")
    else
        args+=("http://127.0.0.1:${PUBLIC_PORT}/${NTFY_DEFAULT_TOPIC}/ws")
    fi
    curl "${args[@]}" 2>/dev/null || true
}

# systemd 已声明 After=network-online/docker/nginx，这里再做运行态兜底。
for _ in $(seq 1 30); do
    systemctl is-active --quiet docker 2>/dev/null && break
    sleep 1
done
if ! systemctl is-active --quiet docker 2>/dev/null; then
    systemctl start docker 2>/dev/null || true
    sleep 3
fi

cmd="$(compose_cmd || true)"
[ -n "$cmd" ] || { log "docker compose unavailable"; exit 1; }
[ -f "$NTFY_COMPOSE_FILE" ] || { log "compose file missing: $NTFY_COMPOSE_FILE"; exit 1; }

cd "$NTFY_ROOT" || exit 1
$cmd up -d ntfy >/dev/null 2>&1 || true

if ! wait_internal_health; then
    log "first start unhealthy; force recreating ntfy container"
    $cmd stop ntfy >/dev/null 2>&1 || true
    $cmd up -d --force-recreate ntfy >/dev/null 2>&1 || true
    wait_internal_health || { log "internal health failed after recovery"; exit 1; }
fi

if ! systemctl is-active --quiet nginx 2>/dev/null; then
    if nginx -t >/dev/null 2>&1; then
        systemctl start nginx >/dev/null 2>&1 || true
    fi
fi

wait_proxy_health || { log "nginx proxy health failed"; exit 1; }
code="$(ws_code)"
if [ "$code" != "101" ]; then
    log "websocket handshake=${code:-000}; retrying ntfy once"
    $cmd restart ntfy >/dev/null 2>&1 || true
    wait_internal_health || { log "retry internal health failed"; exit 1; }
    wait_proxy_health || { log "retry proxy health failed"; exit 1; }
    code="$(ws_code)"
fi

if [ "$code" = "101" ]; then
    log "ntfy boot recovery OK: internal/proxy/websocket all healthy"
    exit 0
fi

log "websocket still unhealthy after recovery: HTTP ${code:-000}"
exit 1
EOF_BOOT_GUARD
    chmod 700 "$NTFY_BOOT_GUARD_SCRIPT"

    cat > "$NTFY_BOOT_GUARD_SERVICE" <<EOF_BOOT_SERVICE
[Unit]
Description=ntfy boot health recovery
Wants=network-online.target docker.service nginx.service
After=network-online.target docker.service nginx.service
StartLimitIntervalSec=180
StartLimitBurst=4

[Service]
Type=oneshot
ExecStart=${NTFY_BOOT_GUARD_SCRIPT}
Restart=on-failure
RestartSec=15s
TimeoutStartSec=360

[Install]
WantedBy=multi-user.target
EOF_BOOT_SERVICE

    systemctl daemon-reload
    systemctl enable ntfy-boot-guard.service >/dev/null 2>&1
    systemctl reset-failed ntfy-boot-guard.service >/dev/null 2>&1 || true
    if systemctl start ntfy-boot-guard.service; then
        ok "开机自愈已启用，并已完成一次即时健康检查：ntfy-boot-guard.service"
    else
        warn "开机自愈已启用，但即时健康检查未完全通过；可查看下面日志定位"
    fi
    echo "  查看本次自愈日志：journalctl -u ntfy-boot-guard.service -b --no-pager"
}

remove_boot_guard() {
    systemctl disable --now ntfy-boot-guard.service >/dev/null 2>&1 || true
    rm -f "$NTFY_BOOT_GUARD_SERVICE" "$NTFY_BOOT_GUARD_SCRIPT"
    systemctl daemon-reload >/dev/null 2>&1 || true
}

install_ntfy_all() {
    load_state
    install_dependencies
    prompt_basic_config
    write_server_config
    write_compose
    start_ntfy
    ensure_admin_user
    configure_nginx
    install_boot_guard
}

restart_ntfy() {
    load_state
    local cmd ws_code
    cmd="$(compose_cmd)"

    info "重启 ntfy，并等待应用/反代/WebSocket 真正恢复"
    repair_docker_iptables
    (cd "$NTFY_ROOT" && $cmd restart ntfy)

    if ! wait_for_port "$INTERNAL_PORT" 30; then
        warn "第一次重启后端口仍未监听，准备执行一次强制重建恢复"
    elif ! wait_for_ntfy_health 45; then
        warn "第一次重启后端口已监听，但 /v1/health 未恢复，准备执行一次强制重建恢复"
    elif ! wait_for_proxy_health 30; then
        warn "ntfy 本体已健康，但 Nginx 反代尚未恢复，准备执行一次强制重建恢复"
    else
        ws_code="$(get_local_ws_code)"
        if [ "$ws_code" = "101" ]; then
            ok "ntfy 重启完成：内部健康、Nginx 反代、WebSocket 订阅均正常"
            return 0
        fi
        warn "第一次重启后 WebSocket 握手为 HTTP ${ws_code:-000}，自动执行一次干净重建"
    fi

    # 第二阶段：不动 Nginx，只强制重建 ntfy 容器。持久化目录均为 bind mount，不会丢订阅/账号数据。
    (cd "$NTFY_ROOT" && $cmd stop ntfy) || true
    sleep 2
    (cd "$NTFY_ROOT" && $cmd up -d --force-recreate ntfy) || true

    if ! wait_for_port "$INTERNAL_PORT" 30 || ! wait_for_ntfy_health 60; then
        err "ntfy 强制重建后仍未健康"
        echo "最近日志："
        (cd "$NTFY_ROOT" && $cmd logs --tail=80 ntfy) || true
        return 1
    fi

    if ! wait_for_proxy_health 30; then
        err "ntfy 已健康，但 Nginx -> ntfy 反代检查失败"
        echo "建议立即运行菜单 [4] 查看 Nginx/端口状态。"
        return 1
    fi

    ws_code="$(get_local_ws_code)"
    if [ "$ws_code" = "101" ]; then
        ok "ntfy 已自动恢复：内部健康、Nginx 反代、WebSocket 订阅均正常"
        return 0
    fi

    err "ntfy 本体和反代已健康，但 WebSocket 仍异常：HTTP ${ws_code:-000}"
    echo "建议立即运行菜单 [4]；脚本不会重启 Nginx，以免影响其它站点。"
    return 1
}

show_status() {
    load_state
    local cmd internal_health proxy_health public_health ws_code
    local nginx_active="false" nginx_enabled="false" nginx_config_ok="false"
    local internal_listen="false" public_listen="false"
    local scheme="http" effective_configs="" foreign_configs=""
    cmd="$(compose_cmd || true)"

    effective_configs="$(get_effective_nginx_configs || true)"
    foreign_configs="$(get_foreign_nginx_configs || true)"

    echo "ntfy 状态"
    echo "  安装目录：${NTFY_ROOT}"
    echo "  缓存目录：${NTFY_CACHE_DIR}"
    echo "  配置目录：${NTFY_ETC_DIR}"
    echo "  数据目录：${NTFY_LIB_DIR}"
    echo "  Compose：${NTFY_COMPOSE_FILE}"
    echo "  状态配置：${NTFY_STATE_FILE}"
    echo "  server.yml：${NTFY_SERVER_FILE}"
    echo "  域名：${DOMAIN:-未设置}"
    echo "  内部映射端口：${NTFY_BIND_HOST}:${INTERNAL_PORT}"
    echo "  外部端口：${PUBLIC_PORT}"
    echo "  访问地址：${NTFY_BASE_URL:-未生成}"
    echo "  默认 Topic：${NTFY_DEFAULT_TOPIC}"
    echo "  登录认证：${NTFY_ENABLE_AUTH}"
    echo "  管理员账号：${NTFY_ADMIN_USER:-未设置}"
    echo "  Nginx 自管目标：${NGINX_SITE_FILE}"
    if [ -n "${NTFY_MANAGED_NGINX_FILE:-}" ]; then
        echo "  Nginx 状态记录：${NTFY_MANAGED_NGINX_FILE}"
    else
        echo "  Nginx 状态记录：未记录自管文件"
    fi
    echo

    echo "实际 Nginx 配置："
    show_effective_nginx_configs || true
    if [ -n "$foreign_configs" ]; then
        yellow "  [INFO] 检测到外部配置接管此端点；安装/重写/卸载均不会修改它。"
    fi

    echo
    echo "容器状态："
    if [ -n "$cmd" ] && [ -f "$NTFY_COMPOSE_FILE" ]; then
        (cd "$NTFY_ROOT" && $cmd ps) || true
    else
        warn "未检测到 Compose 文件或 Docker Compose"
    fi

    echo
    echo "实际健康检查："

    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\])${INTERNAL_PORT}$"; then
        internal_listen="true"
        green "  [OK] ntfy 内部端口 ${INTERNAL_PORT}：已监听"
    else
        red "  [FAIL] ntfy 内部端口 ${INTERNAL_PORT}：未监听"
    fi

    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\])${PUBLIC_PORT}$"; then
        public_listen="true"
        green "  [OK] Nginx 外部端口 ${PUBLIC_PORT}：已监听"
    else
        red "  [FAIL] Nginx 外部端口 ${PUBLIC_PORT}：未监听"
    fi

    internal_health="$(curl -fsS --max-time 5 "http://127.0.0.1:${INTERNAL_PORT}/v1/health" 2>/dev/null || true)"
    if printf '%s' "$internal_health" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
        green "  [OK] ntfy /v1/health：healthy=true"
    else
        red "  [FAIL] ntfy /v1/health：无正常响应"
    fi

    if systemctl is-active --quiet nginx 2>/dev/null; then
        nginx_active="true"
        green "  [OK] Nginx 服务：active"
    else
        red "  [FAIL] Nginx 服务：inactive/failed"
    fi

    if systemctl is-enabled --quiet nginx 2>/dev/null; then
        nginx_enabled="true"
        green "  [OK] Nginx 开机自启：enabled"
    else
        yellow "  [WARN] Nginx 开机自启：disabled/unknown（服务器重启后可能再次失联）"
    fi

    if systemctl is-enabled --quiet ntfy-boot-guard.service 2>/dev/null; then
        local guard_result
        guard_result="$(systemctl show ntfy-boot-guard.service -p Result --value 2>/dev/null || true)"
        if [ -z "$guard_result" ] || [ "$guard_result" = "success" ]; then
            green "  [OK] ntfy 开机自愈：enabled（最近结果 ${guard_result:-success}）"
        else
            yellow "  [WARN] ntfy 开机自愈：enabled，但最近结果 ${guard_result}"
            echo "       日志：journalctl -u ntfy-boot-guard.service -b --no-pager"
        fi
    else
        yellow "  [WARN] ntfy 开机自愈：未启用（可执行菜单 [7]）"
    fi

    if nginx -t >/tmp/ntfy_nginx_test.out 2>&1; then
        nginx_config_ok="true"
        green "  [OK] Nginx 配置：nginx -t 通过"
    else
        red "  [FAIL] Nginx 配置：nginx -t 失败"
        sed 's/^/         /' /tmp/ntfy_nginx_test.out 2>/dev/null || true
    fi

    proxy_health=""
    if [ -n "${DOMAIN:-}" ]; then
        if [[ "${NTFY_BASE_URL:-}" == https://* ]]; then
            scheme="https"
        fi
        proxy_health="$(curl -kfsS --max-time 6 \
            --resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1" \
            "${scheme}://${DOMAIN}:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
    else
        proxy_health="$(curl -fsS --max-time 6 \
            "http://127.0.0.1:${PUBLIC_PORT}/v1/health" 2>/dev/null || true)"
    fi

    if printf '%s' "$proxy_health" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
        green "  [OK] Nginx -> ntfy 反代健康：正常"
    else
        red "  [FAIL] Nginx -> ntfy 反代健康：失败"
    fi

    public_health=""
    if [ -n "${NTFY_BASE_URL:-}" ]; then
        public_health="$(curl -kfsS --max-time 8 "${NTFY_BASE_URL}/v1/health" 2>/dev/null || true)"
    fi
    if printf '%s' "$public_health" | grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true'; then
        green "  [OK] 公网访问地址 /v1/health：正常"
    else
        yellow "  [WARN] 公网访问地址 /v1/health：本机访问失败（若不支持 NAT 回环可忽略）"
    fi

    ws_code=""
    if [ -n "${DOMAIN:-}" ] && [ -n "${NTFY_DEFAULT_TOPIC:-}" ] && [ -n "${NTFY_ADMIN_USER:-}" ] && [ -n "${NTFY_ADMIN_PASS:-}" ]; then
        ws_code="$(curl -k -sS --http1.1 --max-time 3 -o /dev/null -w '%{http_code}' \
            --resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1" \
            -u "${NTFY_ADMIN_USER}:${NTFY_ADMIN_PASS}" \
            -H 'Connection: Upgrade' \
            -H 'Upgrade: websocket' \
            -H 'Sec-WebSocket-Version: 13' \
            -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
            "${scheme}://${DOMAIN}:${PUBLIC_PORT}/${NTFY_DEFAULT_TOPIC}/ws" 2>/dev/null || true)"
        case "$ws_code" in
            101) green "  [OK] WebSocket 订阅握手：HTTP 101（正常）" ;;
            401|403) red "  [FAIL] WebSocket 订阅握手：HTTP ${ws_code}（认证/Topic 权限问题）" ;;
            000|"") red "  [FAIL] WebSocket 订阅握手：无法连接" ;;
            400)
                red "  [FAIL] WebSocket 订阅握手：HTTP 400"
                yellow "       提示：若普通 /v1/health 正常，优先检查上面列出的实际 Nginx 配置是否转发 Upgrade/Connection。"
                ;;
            *) red "  [FAIL] WebSocket 订阅握手：HTTP ${ws_code}" ;;
        esac
    else
        yellow "  [WARN] WebSocket 订阅握手：缺少域名/Topic/管理员凭据，跳过"
    fi

    echo
    echo "端口监听明细："
    ss -lntp 2>/dev/null | grep -E ":(${INTERNAL_PORT}|${PUBLIC_PORT})\b" || true

    echo
    echo "综合判断："
    if [ "$internal_listen" != "true" ]; then
        red "  ntfy 容器/内部服务异常。"
        echo "  建议查看：cd ${NTFY_ROOT} && ${cmd:-docker compose} logs --tail=100 ntfy"
    elif [ "$nginx_active" != "true" ] || [ "$public_listen" != "true" ]; then
        red "  ntfy 本体正常，但 Nginx/外部端口异常，订阅会失联。"
        echo "  本脚本状态查询不会自动操作 Nginx。先执行 nginx -t；若通过且 Nginx 未运行，可执行 systemctl start nginx。"
    elif [ "$nginx_config_ok" != "true" ]; then
        red "  Nginx 正在运行，但全局配置检查失败；不要 reload/restart，先修正 nginx -t 报错。"
    elif [ "$ws_code" = "401" ] || [ "$ws_code" = "403" ]; then
        red "  HTTP 链路正常，但 WebSocket 被认证/权限拒绝。"
        echo "  查看 ACL：docker exec -it ${CONTAINER_NAME} ntfy access"
    elif [ "$nginx_enabled" != "true" ]; then
        yellow "  当前链路可能正常，但 Nginx 未设置开机自启；服务器重启后可能再次失联。"
        echo "  修复：systemctl enable nginx"
    elif [ "$ws_code" = "101" ]; then
        green "  ntfy、Nginx、WebSocket 订阅链路均正常，且 Nginx 已设置开机自启。"
        if [ -n "$foreign_configs" ]; then
            yellow "  说明：当前反代由外部 Nginx 配置提供；ntfy.sh 将保持只读检测，不会改动它。"
        fi
    else
        yellow "  基础服务已运行，但订阅链路未完全确认；可根据上面的 FAIL/WARN 定位。"
    fi
}

reset_admin_user() {
    load_state
    warn "该操作只更新 ntfy 管理员账号，不修改任何 Nginx 配置。"
    echo
    NTFY_ENABLE_AUTH="true"
    stty sane 2>/dev/null || true
    read -e -r -p "请输入管理员用户名 [${NTFY_ADMIN_USER}]: " input_user
    if [ -n "${input_user:-}" ]; then
        NTFY_ADMIN_USER="$input_user"
    fi
    read -r -s -p "请输入新的管理员密码（回车=自动生成）: " input_pass
    echo
    if [ -n "${input_pass:-}" ]; then
        NTFY_ADMIN_PASS="$input_pass"
    else
        NTFY_ADMIN_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
        echo "  已自动生成密码: $NTFY_ADMIN_PASS"
    fi

    stty sane 2>/dev/null || true
    read -e -r -p "输入 RESET 确认重置/更新 ntfy 登录账号: " confirm_text
    if [ "${confirm_text:-}" != "RESET" ]; then
        warn "已取消重置"
        return 0
    fi

    save_state
    write_server_config
    repair_docker_iptables
    start_ntfy
    ensure_admin_user
    restart_ntfy

    ok "ntfy 登录账号已设置；未修改 Nginx"
    echo "访问地址：${NTFY_BASE_URL}"
    echo "管理员账号：${NTFY_ADMIN_USER}"
    echo "管理员密码：${NTFY_ADMIN_PASS}"
}

uninstall_ntfy() {
    load_state
    warn "该操作会停止并删除 ntfy 容器。"
    warn "Nginx 只删除 ntfy.sh 自己管理的配置；外部站点配置绝不会自动删除。"
    warn "默认不会删除数据目录：${NTFY_ROOT}"
    stty sane 2>/dev/null || true
    read -e -r -p "输入 YES 确认卸载 ntfy: " confirm_text
    if [ "${confirm_text:-}" != "YES" ]; then
        warn "已取消卸载"
        return 0
    fi

    local cmd removed_nginx="false" foreign_configs
    remove_boot_guard
    cmd="$(compose_cmd || true)"
    foreign_configs="$(get_foreign_nginx_configs || true)"

    if [ -n "${cmd:-}" ] && [ -f "$NTFY_COMPOSE_FILE" ]; then
        (cd "$NTFY_ROOT" && $cmd down) || true
    fi

    if [ -n "${NTFY_MANAGED_NGINX_FILE:-}" ] && [ -e "$NTFY_MANAGED_NGINX_FILE" ]; then
        if safe_remove_managed_nginx_config "$NTFY_MANAGED_NGINX_FILE" "${NTFY_MANAGED_NGINX_LINK:-}"; then
            removed_nginx="true"
            ok "已删除 ntfy.sh 自管 Nginx 配置"
        fi
    elif [ -e "$NGINX_SITE_FILE" ] && is_ntfy_managed_file "$NGINX_SITE_FILE"; then
        if safe_remove_managed_nginx_config "$NGINX_SITE_FILE" "$NGINX_SITE_LINK"; then
            removed_nginx="true"
            ok "已删除 ntfy.sh 自管 Nginx 配置"
        fi
    fi

    if [ "$removed_nginx" = "true" ]; then
        if nginx -t >/tmp/ntfy_nginx_test.out 2>&1; then
            if systemctl is-active --quiet nginx 2>/dev/null; then
                systemctl reload nginx || warn "Nginx reload 失败，请手动检查；未执行 restart"
            fi
        else
            warn "删除 ntfy 自管配置后 nginx -t 未通过，因此未 reload："
            sed 's/^/  /' /tmp/ntfy_nginx_test.out 2>/dev/null || true
        fi
    fi

    if [ -n "$foreign_configs" ]; then
        warn "检测到外部 Nginx 配置仍匹配 ${DOMAIN:-_}:${PUBLIC_PORT}，本脚本按安全策略保留："
        while IFS= read -r file; do
            [ -n "$file" ] && echo "  - ${file}"
        done <<< "$foreign_configs"
        warn "如果这些文件专门用于 ntfy，请由你确认用途后手动处理。"
    fi

    stty sane 2>/dev/null || true
    read -e -r -p "是否同时删除 ntfy 数据目录 ${NTFY_ROOT} ? 输入 DELETE 确认删除: " delete_text
    if [ "${delete_text:-}" = "DELETE" ]; then
        rm -rf "$NTFY_ROOT"
        ok "ntfy 数据目录已删除"
    else
        warn "保留数据目录：${NTFY_ROOT}"
    fi

    stty sane 2>/dev/null || true
    read -e -r -p "是否同时移除防火墙端口 ${PUBLIC_PORT}/tcp ? 输入 CLOSE 确认移除: " close_text
    if [ "${close_text:-}" = "CLOSE" ]; then
        close_firewall_port "$PUBLIC_PORT"
        ok "已尝试移除防火墙端口 ${PUBLIC_PORT}/tcp"
    fi

    rm -f "$NTFY_STATE_FILE"
    ok "ntfy 已卸载"
}

show_menu() {
    clear
    printf "\n"
    printf "${BOLD}${BLUE}=========================================================================${NC}\n"
    printf "${BOLD}${WHITE}                   ntfy 安装 / 反代 / 配置菜单                           ${NC}\n"
    printf "${BOLD}${BLUE}=========================================================================${NC}\n"
    printf "${BOLD}${GREEN} [1] 一键安装 / 重装 ntfy${NC}        ${WHITE}Docker 部署 + Nginx 反代 + 复用证书路径${NC}\n"
    printf "${BOLD}${CYAN}  [2] 安全配置 Nginx 反代${NC}        ${WHITE}只管理 ntfy 自有配置；外部配置只检测不覆盖${NC}\n"
    printf "${BOLD}${CYAN}  [3] 重启 ntfy${NC}                  ${WHITE}仅重启容器，不 reload/restart Nginx${NC}\n"
    printf "${BOLD}${YELLOW} [4] 查看状态${NC}                   ${WHITE}检查容器、Nginx、健康接口与 WebSocket${NC}\n"
    printf "${BOLD}${MAGENTA} [5] 设置/重置登录账号${NC}         ${WHITE}创建或更新 ntfy 管理员账号${NC}\n"
    printf "${BOLD}${RED}   [6] 卸载 ntfy${NC}                 ${YELLOW}仅删除自管反代；外部 Nginx 配置保留${NC}\n"
    printf "${BOLD}${GREEN} [7] 安装/刷新开机自愈${NC}          ${WHITE}首轮启动异常时自动健康检查并恢复${NC}\n"
    printf "${BOLD}${RED}   [0] 退出${NC}\n"
    printf "${BOLD}${BLUE}-------------------------------------------------------------------------${NC}\n"
    printf "${BOLD}${YELLOW} ★ 默认外部端口：${NC}${GREEN}${PUBLIC_PORT}${NC}${WHITE}，避免与你现有 asset_manager / gotify 端口冲突${NC}\n"
    printf "${BOLD}${YELLOW} ★ 证书路径：${NC}${GREEN}/etc/letsencrypt/live/域名/fullchain.pem${NC}\n"
    printf "${BOLD}${YELLOW} ★ 默认 Topic：${NC}${GREEN}${NTFY_DEFAULT_TOPIC}${NC}${WHITE}，客户端订阅同名 Topic 接收消息${NC}\n"
    printf "${BOLD}${YELLOW} ★ 输入提示：${NC}${GREEN}DELETE/删除/清空${NC}${WHITE} 可清空配置，端口会恢复默认值${NC}\n"
    printf "${BOLD}${YELLOW} ★ Nginx 安全策略：${NC}${WHITE}其它站点只检测，不覆盖、不删除；配置变更只 reload，永不 restart${NC}\n"
    printf "${BOLD}${BLUE}=========================================================================${NC}\n"
    printf "\n"
}

main() {
    require_root
    load_state
    while true; do
        show_menu
        stty sane 2>/dev/null || true
        read -e -r -p "请输入菜单编号: " choice
        echo
        case "${choice:-}" in
            1) install_ntfy_all ;;
            2) prompt_basic_config; configure_nginx; install_boot_guard ;;
            3) restart_ntfy ;;
            4) show_status ;;
            5) reset_admin_user ;;
            6) uninstall_ntfy ;;
            7) install_boot_guard ;;
            0) exit 0 ;;
            *) warn "无效选项" ;;
        esac
        echo
        stty sane 2>/dev/null || true
        read -e -r -p "按回车继续..." _
    done
}

main "$@"
