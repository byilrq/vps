#!/bin/bash
# NodeSeek keyword monitor manager (ntfy only)
# 仅保留本管理脚本 node.sh：菜单 2 同时负责首次安装及升级，无需 install.sh。
# node.sh 安装在 /root/node.sh；程序数据在 /root/node/。
# 本项目独立使用 Python Web 服务，不创建也不修改 Nginx 配置。
# systemd handles startup/restart; node.py run-all handles monitor + web

set -u

export LANG=C.UTF-8
export LC_ALL=C.UTF-8
# 保留服务器实际本地时区，Python 发送前会自动转换为 Asia/Shanghai。

# 如果从 ZIP 解压目录直接执行 node.sh，自动安装同目录的 node.py、push.py。
# 已安装后从 /root/node.sh 启动，直接操作 /root/node 中的现有程序。
BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORK_DIR="/root/node"
CONFIG_FILE="$WORK_DIR/node_config.txt"
PYTHON_SCRIPT="$WORK_DIR/node.py"
PUSH_SCRIPT="$WORK_DIR/push.py"
SCRIPT_PATH="/root/node.sh"
SERVICE_NAME="node"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
# 只清理由本项目明确标记的防火墙规则，不动其他服务的放行规则。
FIREWALL_TAG="node-monitor-8168"

CRON_LOG="$WORK_DIR/node_cron.log"
PID_FILE="$WORK_DIR/.node_python.pid"
WEB_PID_FILE="$WORK_DIR/.node_keyword_web.pid"
LAST_NODE_TXT="$WORK_DIR/last_node.txt"

DEFAULT_NS_URL="https://rss.nodeseek.com/?sortBy=postTime"
DEFAULT_INTERVAL_SEC="15"
DEFAULT_WEB_PORT="8168"
DEFAULT_WEB_PIN="0819"

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
BLUE="\033[34m"; PURPLE="\033[35m"; CYAN="\033[36m"; WHITE="\033[37m"
BOLD="\033[1m"; PLAIN="\033[0m"

ensure_runtime_files() {
    mkdir -p "$WORK_DIR"
    touch "$CRON_LOG"
}

# ==================== 防火墙配置（仅操作本项目端口） ====================
setup_firewall() {
    local port="$DEFAULT_WEB_PORT" chain
    echo -e "${BLUE}检查 TCP/$port 防火墙规则...${PLAIN}"

    # iptables 的新规则使用唯一 comment 标签；已有无标签规则视为共享规则，不覆盖。
    if command -v iptables >/dev/null 2>&1; then
        for chain in INPUT HY2_INPUT; do
            iptables -L "$chain" -n >/dev/null 2>&1 || continue
            if iptables -C "$chain" -p tcp --dport "$port" -m comment --comment "$FIREWALL_TAG" -j ACCEPT >/dev/null 2>&1; then
                echo "iptables/$chain: 本项目规则已经存在"
            elif iptables -C "$chain" -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                echo "iptables/$chain: 已允许 $port（保留已有规则）"
            elif iptables -I "$chain" -p tcp --dport "$port" -m comment --comment "$FIREWALL_TAG" -j ACCEPT >/dev/null 2>&1; then
                echo "iptables/$chain: 已添加本项目专用放行规则"
            else
                echo -e "${YELLOW}iptables/$chain: 规则添加失败，请手动确认${PLAIN}"
            fi
        done
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        if ufw status | grep -E "(^|[[:space:]])${port}/tcp([[:space:]]|$)" | grep -q 'ALLOW'; then
            echo "ufw: TCP/$port 已允许，保留现有规则"
        elif ufw allow "$port/tcp" comment "$FIREWALL_TAG" >/dev/null 2>&1; then
            echo "ufw: 已添加标记为 $FIREWALL_TAG 的规则"
        else
            echo -e "${YELLOW}ufw: 未能添加带标记规则，请手动确认${PLAIN}"
        fi
    fi

    # firewalld 采用端口级共享规则，不记录归属；卸载时不回收未知归属的放行。
    if command -v firewall-cmd >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 \
         && systemctl is-active --quiet firewalld; then
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            echo "firewalld: TCP/$port 已允许"
        elif firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1 || true
            echo "firewalld: TCP/$port 已开放（卸载时为安全起见不自动删除）"
        else
            echo -e "${YELLOW}firewalld: 端口开放失败，请手动确认${PLAIN}"
        fi
    fi
    echo -e "${GREEN}✔ 防火墙检查完成${PLAIN}"
}

remove_owned_firewall_rules() {
    local chain port="$DEFAULT_WEB_PORT" count=0 line rule_no
    # 仅移除带本项目标记的 iptables 规则，不能碰其他站点/程序的规则。
    if command -v iptables >/dev/null 2>&1; then
        for chain in INPUT HY2_INPUT; do
            while [ "$count" -lt 20 ] && iptables -C "$chain" -p tcp --dport "$port" \
                -m comment --comment "$FIREWALL_TAG" -j ACCEPT >/dev/null 2>&1; do
                iptables -D "$chain" -p tcp --dport "$port" \
                    -m comment --comment "$FIREWALL_TAG" -j ACCEPT >/dev/null 2>&1 || break
                count=$((count + 1))
            done
        done
        if [ "$count" -gt 0 ] && command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
    fi
    # ufw 必须找到具有相同 comment 的编号规则才删除，避免误删其他 8168/tcp 规则。
    if command -v ufw >/dev/null 2>&1; then
        for _ in 1 2 3 4; do
            line="$(ufw status numbered 2>/dev/null | grep -F "$FIREWALL_TAG" \
                | grep -E "(^|[[:space:]])${port}/tcp([[:space:]]|$)" | head -n 1 || true)"
            [ -n "$line" ] || break
            rule_no="$(printf '%s\n' "$line" | sed -n 's/^[[:space:]]*\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p')"
            [ -n "$rule_no" ] || break
            ufw --force delete "$rule_no" >/dev/null 2>&1 || break
        done
    fi
    # 不调整 firewalld/无标记 iptables/旧 ufw 规则，以免影响其他服务。
}

# ==================== Let's Encrypt 证书处理 ====================
find_cert_name_by_domain() {
    local cert_domain="$1"
    local d=""
    if [ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${cert_domain}/privkey.pem" ]; then
        echo "$cert_domain"
        return 0
    fi
    for d in /etc/letsencrypt/live/"${cert_domain}"*; do
        [ -d "$d" ] || continue
        if [ -f "$d/fullchain.pem" ] && [ -f "$d/privkey.pem" ]; then
            basename "$d"
            return 0
        fi
    done
    return 1
}

get_cert_paths() {
    local cert_domain="$1"
    local cert_name=""
    cert_name="$(find_cert_name_by_domain "$cert_domain" 2>/dev/null || true)"
    [ -n "$cert_name" ] || return 1
    [ -f "/etc/letsencrypt/live/${cert_name}/fullchain.pem" ] || return 1
    [ -f "/etc/letsencrypt/live/${cert_name}/privkey.pem" ] || return 1
    echo "${cert_name}|/etc/letsencrypt/live/${cert_name}/fullchain.pem|/etc/letsencrypt/live/${cert_name}/privkey.pem"
}

cert_files_exist() {
    get_cert_paths "$1" >/dev/null 2>&1
}

cert_is_valid() {
    local cert_domain="$1"
    local cert_info="" cert_file=""
    cert_info="$(get_cert_paths "$cert_domain" 2>/dev/null || true)"
    [ -n "$cert_info" ] || return 1
    cert_file="$(echo "$cert_info" | cut -d'|' -f2)"
    [ -f "$cert_file" ] || return 1
    openssl x509 -checkend 0 -noout -in "$cert_file" >/dev/null 2>&1 || return 1
    if openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | grep -qw "DNS:${cert_domain}"; then
        return 0
    fi
    openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -Eq "CN[[:space:]]*=[[:space:]]*${cert_domain}([,/]|$)"
}

cert_key_matches() {
    local cert_domain="$1"
    local cert_info="" cert_file="" key_file="" cert_pub="" key_pub=""
    cert_info="$(get_cert_paths "$cert_domain" 2>/dev/null || true)"
    [ -n "$cert_info" ] || return 1
    cert_file="$(echo "$cert_info" | cut -d'|' -f2)"
    key_file="$(echo "$cert_info" | cut -d'|' -f3)"
    [ -f "$cert_file" ] && [ -f "$key_file" ] || return 1
    cert_pub="$(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform pem 2>/dev/null || true)"
    key_pub="$(openssl pkey -in "$key_file" -pubout -outform pem 2>/dev/null || true)"
    [ -n "$cert_pub" ] && [ -n "$key_pub" ] && [ "$cert_pub" = "$key_pub" ]
}

show_local_cert_info() {
    local cert_domain="$1"
    local cert_info="" cert_file=""
    cert_info="$(get_cert_paths "$cert_domain" 2>/dev/null || true)"
    cert_file="$(echo "$cert_info" | cut -d'|' -f2)"
    if [ -f "$cert_file" ]; then
        echo "域名: ${cert_domain}"
        openssl x509 -noout -subject -issuer -dates -in "$cert_file" 2>/dev/null || true
    fi
}

prepare_web_cert_for_domain() {
    local cert_domain="$1"
    echo "检查域名证书：${cert_domain}"

    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        echo "检测到有效 Let's Encrypt 证书，直接复用。"
        show_local_cert_info "$cert_domain"
        return 0
    fi

    echo "❌ 证书文件不存在或无效，请先使用 certbot 为 ${cert_domain} 申请证书。"
    echo "   证书路径：/etc/letsencrypt/live/${cert_domain}/fullchain.pem"
    echo "   申请命令：certbot certonly --standalone -d ${cert_domain}"
    return 1
}
chmod_if_needed() {
    local file="$1"
    [ -f "$file" ] || return 0
    chmod 755 "$file" 2>/dev/null || true
}

normalize_text_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    if grep -q $'\r' "$file" 2>/dev/null; then
        sed -i 's/\r$//' "$file" 2>/dev/null || true
    fi
}

ensure_permissions() {
    ensure_runtime_files
    normalize_text_file "$SCRIPT_PATH"
    normalize_text_file "$PYTHON_SCRIPT"
    normalize_text_file "$PUSH_SCRIPT"
    chmod_if_needed "$SCRIPT_PATH"
    chmod_if_needed "$PYTHON_SCRIPT"
    chmod_if_needed "$PUSH_SCRIPT"
}

python_ready() {
    command -v python3 >/dev/null 2>&1
}

have_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

escape_config_value() {
    local value="${1:-}"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\r'/}
    value=${value//$'\n'/ }
    printf '%s' "$value"
}

read_config() {
    if [ ! -s "$CONFIG_FILE" ]; then
        return 1
    fi
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    NTFY_URL="${NTFY_URL:-http://127.0.0.1:8083}"
    NTFY_USERNAME="${NTFY_USERNAME:-}"
    NTFY_PASSWORD="${NTFY_PASSWORD:-}"
    NTFY_TOPIC="${NTFY_TOPIC:-node}"
    NTFY_PRIORITY="${NTFY_PRIORITY:-3}"
    NS_URL="${NS_URL:-$DEFAULT_NS_URL}"
    KEYWORDS="${KEYWORDS:-}"
    INTERVAL_SEC="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    DEBUG_LOG="${DEBUG_LOG:-0}"
    WEB_HOST="${WEB_HOST:-0.0.0.0}"
    WEB_PORT="${WEB_PORT:-$DEFAULT_WEB_PORT}"
    WEB_PIN="$DEFAULT_WEB_PIN"
    WEB_DOMAIN="${WEB_DOMAIN:-}"
    return 0
}

init_default_vars() {
    NTFY_URL="${NTFY_URL:-http://127.0.0.1:8083}"
    NTFY_USERNAME="${NTFY_USERNAME:-}"
    NTFY_PASSWORD="${NTFY_PASSWORD:-}"
    NTFY_TOPIC="${NTFY_TOPIC:-node}"
    NTFY_PRIORITY="${NTFY_PRIORITY:-3}"
    NS_URL="${NS_URL:-$DEFAULT_NS_URL}"
    INTERVAL_SEC="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    DEBUG_LOG="${DEBUG_LOG:-0}"
    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    WEB_PIN="$DEFAULT_WEB_PIN"
    WEB_DOMAIN="${WEB_DOMAIN:-}"
}


write_config() {
    ensure_runtime_files
    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    cat > "$CONFIG_FILE" <<CFGEOF
NTFY_URL="$(escape_config_value "${NTFY_URL:-http://127.0.0.1:8083}")"
NTFY_USERNAME="$(escape_config_value "${NTFY_USERNAME:-}")"
NTFY_PASSWORD="$(escape_config_value "${NTFY_PASSWORD:-}")"
NTFY_TOPIC="$(escape_config_value "${NTFY_TOPIC:-node}")"
NTFY_PRIORITY="$(escape_config_value "${NTFY_PRIORITY:-3}")"
NS_URL="$(escape_config_value "${NS_URL:-$DEFAULT_NS_URL}")"
KEYWORDS="$(escape_config_value "${KEYWORDS:-}")"
INTERVAL_SEC="$(escape_config_value "${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}")"
DEBUG_LOG="$(escape_config_value "${DEBUG_LOG:-0}")"
WEB_HOST="0.0.0.0"
WEB_PORT="$DEFAULT_WEB_PORT"
WEB_PIN="$DEFAULT_WEB_PIN"
WEB_DOMAIN="$(escape_config_value "${WEB_DOMAIN:-}")"
CFGEOF
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    echo -e "${GREEN}✅ 配置已保存到 $CONFIG_FILE${PLAIN}"
    echo -e "${GREEN}✅ 网页端口固定为 $DEFAULT_WEB_PORT${PLAIN}"
}

ensure_config_exists() {
    if [ -s "$CONFIG_FILE" ]; then
        return 0
    fi
    init_default_vars
    write_config >/dev/null
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}❌ 请使用 root 用户执行安装、更新或卸载。${PLAIN}"
        return 1
    fi
}

# 兼容本包和最初 node.zip 的两种管理脚本头部标识，避免拒绝升级原版。
manager_is_ours() {
    local file="$1"
    [ -f "$file" ] || return 1
    head -n 8 "$file" | grep -Eq '^# (NodeSeek keyword monitor manager|node Python monitor simple manager)'
}

validate_program_pair() {
    local dir="$1"
    if [ ! -s "$dir/node.py" ] || [ ! -s "$dir/push.py" ]; then
        echo -e "${RED}❌ 缺少 node.py 或 push.py，请将 3 个程序文件一起解压后重试。${PLAIN}"
        return 1
    fi
    if ! python_ready; then
        echo -e "${RED}❌ 未安装 python3，请先执行菜单 1。${PLAIN}"
        return 1
    fi
    if ! python3 -m py_compile "$dir/node.py" "$dir/push.py"; then
        echo -e "${RED}❌ Python 程序存在语法错误，停止部署。${PLAIN}"
        return 1
    fi
    if ! grep -q 'INLINE_SKIN_CSS' "$dir/node.py"; then
        echo -e "${RED}❌ 检测到旧 node.py：没有内嵌 CSS，停止部署。${PLAIN}"
        return 1
    fi
}

validate_local_programs() {
    validate_program_pair "$WORK_DIR"
}

# 直接用 node.sh 一体化首次部署/更新，不需要额外 install.sh。
copy_programs_from_bundle() {
    local source_dir="$BUNDLE_DIR" backup_dir stamp name
    # 已安装脚本 /root/node.sh 不带附件时：使用当前 /root/node 中的程序。
    if [ "$source_dir/node.sh" = "$SCRIPT_PATH" ]; then
        return 0
    fi
    if [ "$source_dir" = "$WORK_DIR" ]; then
        # 用户将新包直接解压到现有项目目录时，也同步更新管理脚本。
        validate_program_pair "$source_dir" || return 1
        bash -n "$source_dir/node.sh" || return 1
        if [ -f "$SCRIPT_PATH" ] && ! manager_is_ours "$SCRIPT_PATH"; then
            echo -e "${RED}❌ $SCRIPT_PATH 已被其他程序占用，拒绝覆盖。${PLAIN}"
            return 1
        fi
        install -m 0755 "$source_dir/node.sh" "$SCRIPT_PATH" || return 1
        return 0
    fi
    [ -f "$source_dir/node.sh" ] || {
        echo -e "${RED}❌ 当前目录缺少 node.sh；请在 ZIP 解压后的 node 目录执行。${PLAIN}"
        return 1
    }
    validate_program_pair "$source_dir" || return 1
    bash -n "$source_dir/node.sh" || return 1
    if [ -L "$WORK_DIR" ]; then
        echo -e "${RED}❌ $WORK_DIR 是符号链接，为防止覆盖其他目录已取消部署。${PLAIN}"
        return 1
    fi
    if [ -f "$SCRIPT_PATH" ] && ! manager_is_ours "$SCRIPT_PATH"; then
        echo -e "${RED}❌ $SCRIPT_PATH 已被其他程序使用，拒绝覆盖。${PLAIN}"
        return 1
    fi
    if [ -f "$SERVICE_FILE" ] && ! service_is_ours; then
        echo -e "${RED}❌ $SERVICE_FILE 属于其他服务，拒绝安装覆盖。${PLAIN}"
        return 1
    fi
    ensure_runtime_files
    stamp="$(date '+%Y%m%d_%H%M%S')_$$"
    backup_dir="$WORK_DIR/upgrade_backups/$stamp"
    mkdir -p "$backup_dir" || return 1
    for name in node.py push.py node_config.txt; do
        [ -f "$WORK_DIR/$name" ] && cp -p "$WORK_DIR/$name" "$backup_dir/$name"
    done
    [ -f "$SCRIPT_PATH" ] && cp -p "$SCRIPT_PATH" "$backup_dir/node.sh"
    # 已经校验来源完整；仅替换本程序文件，不覆盖配置和历史数据。
    install -m 0755 "$source_dir/node.py" "$PYTHON_SCRIPT" || return 1
    install -m 0755 "$source_dir/push.py" "$PUSH_SCRIPT" || return 1
    if [ "$source_dir/node.sh" != "$SCRIPT_PATH" ]; then
        install -m 0755 "$source_dir/node.sh" "$SCRIPT_PATH" || return 1
    fi
    echo -e "${GREEN}✔ 新版文件已部署：$SCRIPT_PATH、$WORK_DIR/{node.py,push.py}${PLAIN}"
    echo "升级前旧文件备份：$backup_dir"
}

install_dependencies() {
    echo -e "${BLUE}开始安装/检查依赖...${PLAIN}"
    if command -v apt-get >/dev/null 2>&1; then
        local pkgs="python3 python3-requests curl wget ca-certificates"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y $pkgs
    else
        echo -e "${YELLOW}⚠️ 当前系统未检测到 apt-get，请手动安装 python3 / curl 或 wget。${PLAIN}"
    fi
    # 不升级全局 pip：共享服务器上的其他 Python/Nginx 站点可能使用它。
    # node.py 自带 urllib 回退，缺少 requests 也可以运行。
    ensure_runtime_files
    ensure_permissions
    echo -e "${GREEN}✅ 依赖检查/安装完成（不安装或修改 Nginx）${PLAIN}"
}

service_unit_content() {
    cat <<EOF
[Unit]
Description=node monitor and keyword web service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
Environment=NODE_WORK_DIR=$WORK_DIR
ExecStart=/usr/bin/python3 $PYTHON_SCRIPT run-all
Restart=always
RestartSec=2
KillSignal=SIGTERM
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF
}

cleanup_old_cron() {
    local entries
    command -v crontab >/dev/null 2>&1 || return 0
    entries="$(crontab -l 2>/dev/null)" || return 0
    if printf '%s\n' "$entries" | grep -Eq '(/root/node/node\.sh|/root/node\.sh) -cron'; then
        printf '%s\n' "$entries" | grep -Ev '(/root/node/node\.sh|/root/node\.sh) -cron' | crontab - || return 1
    fi
}

service_is_ours() {
    [ -f "$SERVICE_FILE" ] || return 1
    grep -Fqx "WorkingDirectory=$WORK_DIR" "$SERVICE_FILE" &&
        grep -Fqx "ExecStart=/usr/bin/python3 $PYTHON_SCRIPT run-all" "$SERVICE_FILE"
}

install_service() {
    if [ -e "$SERVICE_FILE" ] && ! service_is_ours; then
        echo -e "${RED}❌ $SERVICE_FILE 已存在但不是 Node 监控服务，拒绝覆盖。${PLAIN}"
        return 1
    fi
    if ! have_systemd; then
        echo -e "${RED}❌ 当前环境未检测到 systemd，无法安装服务。${PLAIN}"
        return 1
    fi
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo -e "${RED}❌ 未找到 $PYTHON_SCRIPT，请先执行菜单 2 部署。${PLAIN}"
        return 1
    fi
    service_unit_content > "$SERVICE_FILE"
    chmod 644 "$SERVICE_FILE" 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || return 1
    echo -e "${GREEN}✅ systemd 服务已创建/更新：$SERVICE_FILE${PLAIN}"
}

restart_service() {
    if ! service_is_ours; then
        echo -e "${RED}❌ $SERVICE_FILE 不是本项目服务，请先执行菜单 2。${PLAIN}"
        return 1
    fi
    systemctl restart "$SERVICE_NAME" 2>/dev/null || {
        install_service || return 1
        systemctl restart "$SERVICE_NAME"
    }
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}✔ node 服务已重启${PLAIN}"
        return 0
    fi
    echo -e "${RED}❌ node 服务启动失败，请查看：journalctl -u $SERVICE_NAME -n 100 --no-pager${PLAIN}"
    return 1
}

restart_node_service() {
    echo -e "${BLUE}正在重启整个 node 系统...${PLAIN}"
    if have_systemd; then
        if ! service_is_ours; then
            echo -e "${RED}❌ $SERVICE_FILE 不属于本项目，拒绝重启同名服务。${PLAIN}"
            return 1
        fi
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}✅ node 系统已成功重启${PLAIN}"
            return 0
        else
            echo -e "${RED}❌ node 系统重启失败${PLAIN}"
            return 1
        fi
    else
        stop_running
        sleep 1
        if [ -f "$PYTHON_SCRIPT" ]; then
            nohup python3 "$PYTHON_SCRIPT" run-all >> "$WORK_DIR/node.log" 2>&1 &
            echo -e "${GREEN}✅ 已在后台启动 node（无 systemd）${PLAIN}"
        else
            echo -e "${RED}❌ 缺少 node.py，请先部署${PLAIN}"
            return 1
        fi
    fi
}

deploy_from_local() {
    # 若从解压目录启动，则把同目录程序部署至 /root/node 并更新 /root/node.sh。
    require_root || return 1
    copy_programs_from_bundle || return 1
    ensure_runtime_files
    validate_local_programs || return 1
    ensure_config_exists
    read_config || return 1
    init_default_vars
    # 升级旧版配置：覆盖历史 8068 端口，保留 ntfy 和监控设置，移除 TG 字段。
    WEB_PORT="$DEFAULT_WEB_PORT"
    write_config
    cleanup_old_cron >/dev/null 2>&1 || true
    ensure_permissions
    install_service || return 1
    setup_firewall
    restart_service
}

# 只识别 python[3] /root/node/node.py <run|run-all|keyword-web>，防止误杀其他 node/nginx 进程。
owned_python_pids() {
    local cmdfile pid i
    local -a argv=()
    for cmdfile in /proc/[0-9]*/cmdline; do
        [ -r "$cmdfile" ] || continue
        argv=()
        mapfile -d '' -t argv < "$cmdfile" 2>/dev/null || continue
        [ "${#argv[@]}" -ge 3 ] || continue
        case "${argv[0]##*/}" in python|python[0-9]|python[0-9].*|pypy*) ;; *) continue ;; esac
        for ((i=1; i<${#argv[@]}-1; i++)); do
            if [ "${argv[i]}" = "$PYTHON_SCRIPT" ]; then
                case "${argv[i+1]}" in run|run-all|keyword-web)
                    pid="${cmdfile#/proc/}"
                    echo "${pid%/cmdline}"
                    ;;
                esac
                break
            fi
        done
    done
}

stop_owned_python_processes() {
    local pid
    local -a pids=()
    mapfile -t pids < <(owned_python_pids)
    for pid in "${pids[@]}"; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    # 最多等 3 秒，只针对再次验证为本项目的进程强制退出。
    local tries
    for tries in 1 2 3; do
        mapfile -t pids < <(owned_python_pids)
        [ "${#pids[@]}" -eq 0 ] && return 0
        sleep 1
    done
    mapfile -t pids < <(owned_python_pids)
    for pid in "${pids[@]}"; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        kill -KILL "$pid" 2>/dev/null || true
    done
}

stop_running() {
    if have_systemd && service_is_ours; then
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    stop_owned_python_processes
    rm -f "$PID_FILE" "$WEB_PID_FILE"
    echo -e "${GREEN}✔ Node 监控服务已停止${PLAIN}"
}

uninstall_service_only() {
    require_root || return 1
    if [ -e "$SERVICE_FILE" ] && ! service_is_ours; then
        echo -e "${RED}❌ $SERVICE_FILE 不属于 Node 监控，拒绝删除。${PLAIN}"
        return 1
    fi
    stop_running
    if [ -f "$SERVICE_FILE" ]; then
        if have_systemd; then
            systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        fi
        rm -f -- "$SERVICE_FILE" || return 1
        if have_systemd; then
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
        fi
    fi
    cleanup_old_cron || true
    echo -e "${GREEN}✔ 仅服务已卸载，程序、配置与数据仍保留在 $WORK_DIR${PLAIN}"
}

uninstall_everything() {
    require_root || return 1
    if [ -e "$SERVICE_FILE" ] && ! service_is_ours; then
        echo -e "${RED}❌ 检测到同名但非本项目的 $SERVICE_FILE，为避免误伤已取消卸载。${PLAIN}"
        return 1
    fi
    # 保护其他用户可能共享的目录，拒绝通过符号链接递归清理。
    if [ -L "$WORK_DIR" ]; then
        echo -e "${RED}❌ $WORK_DIR 是符号链接，已取消卸载，请手工确认链接目标。${PLAIN}"
        return 1
    fi
    # 避免误删误命名的目录；本项目专用目录必须包含至少一种已知程序/配置/状态文件。
    if [ -d "$WORK_DIR" ] &&
       [ ! -f "$PYTHON_SCRIPT" ] && [ ! -f "$PUSH_SCRIPT" ] &&
       [ ! -f "$CONFIG_FILE" ] && [ ! -f "$WORK_DIR/keywords.json" ] &&
       [ ! -f "$WORK_DIR/node_state.json" ] && [ ! -f "$CRON_LOG" ]; then
        echo -e "${RED}❌ $WORK_DIR 不包含可识别的 Node 文件，拒绝删除未知目录。${PLAIN}"
        return 1
    fi
    if [[ "$WORK_DIR" != */node || "$WORK_DIR" = /node || "$WORK_DIR" = / ]]; then
        echo -e "${RED}❌ 工作目录路径异常，已取消卸载。${PLAIN}"
        return 1
    fi
    if command -v findmnt >/dev/null 2>&1 && [ -d "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ]; then
        # 工作目录自身或其子目录有挂载点时停止，防止跨挂载点清理外部数据。
        if findmnt -rn -o TARGET 2>/dev/null | grep -Fxq "$WORK_DIR" ||
           findmnt -rn -o TARGET 2>/dev/null | grep -Fq "$WORK_DIR/"; then
            echo -e "${RED}❌ $WORK_DIR 内存在挂载点，已拒绝递归删除。请先排查挂载。${PLAIN}"
            return 1
        fi
    fi
    echo -e "${RED}${BOLD}===== 彻底卸载 Node 监控（不可恢复）=====${PLAIN}"
    echo "将停止并移除：node.service、Node 监控专属进程、旧 Cron 项"
    echo "将永久删除：$WORK_DIR（包括关键词、配置、历史日志、缓存、升级备份）"
    echo "将永久删除：$SCRIPT_PATH（仅在确认其属于本项目时）"
    echo "防火墙：仅清理带 ${FIREWALL_TAG} 标记的规则，其他规则保留"
    echo "不会操作：Nginx 服务、网站配置、其他站点、证书、Python 或系统依赖"
    echo -e "${YELLOW}如需要保留关键词/配置，请先自行备份 $WORK_DIR。${PLAIN}"
    local confirmation
    read -erp '确认彻底删除，请输入 DELETE（其他输入取消）: ' confirmation || return 1
    if [ "$confirmation" != 'DELETE' ]; then
        echo "已取消卸载，未修改任何文件。"
        return 1
    fi
    uninstall_service_only || return 1
    remove_owned_firewall_rules
    # 不执行 systemctl stop/restart nginx、nginx -s reload、apt purge 等全局操作。
    if [ -L "$WORK_DIR" ] || [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR" || return 1
        echo -e "${GREEN}✔ 项目目录与数据已清理${PLAIN}"
    fi
    if [ -f "$SCRIPT_PATH" ] && manager_is_ours "$SCRIPT_PATH"; then
        rm -f -- "$SCRIPT_PATH" || return 1
        echo -e "${GREEN}✔ 管理脚本已删除${PLAIN}"
    elif [ -e "$SCRIPT_PATH" ]; then
        echo -e "${YELLOW}⚠️ $SCRIPT_PATH 不是本项目脚本，已保留${PLAIN}"
    fi
    echo -e "${GREEN}✅ Node 监控系统已彻底卸载，其他 Nginx 网站/用户未被操作${PLAIN}"
    return 0
}

run_py() {
    if ! python_ready; then
        echo -e "${RED}❌ 未检测到 python3，请先安装依赖。${PLAIN}"
        return 1
    fi
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo -e "${RED}❌ 未找到 $PYTHON_SCRIPT，请先执行菜单 2 部署。${PLAIN}"
        return 1
    fi
    ensure_permissions
    python3 "$PYTHON_SCRIPT" "$@"
}

configure_params() {
    ensure_runtime_files
    read_config || true
    init_default_vars

    echo -e "${BLUE}======================================${PLAIN}"
    echo -e "${PURPLE} node 参数配置 (仅 ntfy) ${PLAIN}"
    echo -e "${BLUE}======================================${PLAIN}"
    echo "工作目录：$WORK_DIR"
    echo "网页端口：$DEFAULT_WEB_PORT（固定）"
    echo "服务器本地时间：$(date '+%Y-%m-%d %H:%M:%S %Z %z')"
    echo "上海时间：$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S %Z %z')"
    echo "推送规则：上海时间 22:30-次日08:00 优先级1，其余时段使用设定的 Priority。"
    echo "所有输入支持 Backspace / Delete / 左右方向键编辑。"
    echo "按 Enter 保持当前值；需要清空可选值时，输入一个减号 - 。"
    echo

    local new_ntfy_url new_ntfy_username new_ntfy_password new_ntfy_topic new_ntfy_priority
    echo "===== ntfy 配置 ====="
    read -erp "请输入 ntfy 地址 [当前: ${NTFY_URL:-http://127.0.0.1:8083}]: " new_ntfy_url
    [[ -z "$new_ntfy_url" ]] && new_ntfy_url="${NTFY_URL:-http://127.0.0.1:8083}"
    read -erp "请输入 ntfy 用户名 [当前: ${NTFY_USERNAME:-空}，清空输入-]: " new_ntfy_username
    [[ -z "$new_ntfy_username" ]] && new_ntfy_username="${NTFY_USERNAME:-}"
    [[ "$new_ntfy_username" == "-" ]] && new_ntfy_username=""
    read -erp "请输入 ntfy 密码 [回车保持已有值，清空输入-]: " new_ntfy_password
    [[ -z "$new_ntfy_password" ]] && new_ntfy_password="${NTFY_PASSWORD:-}"
    [[ "$new_ntfy_password" == "-" ]] && new_ntfy_password=""
    read -erp "请输入 ntfy Topic [当前: ${NTFY_TOPIC:-node}]: " new_ntfy_topic
    [[ -z "$new_ntfy_topic" ]] && new_ntfy_topic="${NTFY_TOPIC:-node}"
    read -erp "请输入 ntfy Priority 1-5 [当前: ${NTFY_PRIORITY:-3}]: " new_ntfy_priority
    [[ -z "$new_ntfy_priority" ]] && new_ntfy_priority="${NTFY_PRIORITY:-3}"
    if [[ ! "$new_ntfy_priority" =~ ^[1-5]$ ]]; then
        echo "无效 ntfy 优先级，保持原设置。"
        new_ntfy_priority="${NTFY_PRIORITY:-3}"
    fi
    NTFY_URL="$new_ntfy_url"
    NTFY_USERNAME="$new_ntfy_username"
    NTFY_PASSWORD="$new_ntfy_password"
    NTFY_TOPIC="$new_ntfy_topic"
    NTFY_PRIORITY="$new_ntfy_priority"

    local new_url new_interval new_debug new_web_domain
    read -erp "请输入要监控的 RSS URL [当前: ${NS_URL:-$DEFAULT_NS_URL}]: " new_url
    [[ -z "$new_url" ]] && new_url="${NS_URL:-$DEFAULT_NS_URL}"
    NS_URL="$new_url"

    read -erp "请输入监控间隔秒数 [当前: ${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}]（最低15）: " new_interval
    [[ -z "$new_interval" ]] && new_interval="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    if ! [[ "$new_interval" =~ ^[0-9]+$ ]] || (( 10#$new_interval < 15 )); then
        echo "无效的间隔，保持原设置。"
        new_interval="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    fi
    INTERVAL_SEC="$new_interval"

    read -erp "是否开启 Debug 日志？[当前: ${DEBUG_LOG:-0}] (0/1): " new_debug
    [[ -z "$new_debug" ]] && new_debug="${DEBUG_LOG:-0}"
    [[ "$new_debug" != "1" ]] && new_debug="0"
    DEBUG_LOG="$new_debug"

    echo "关键词网页 PIN: $DEFAULT_WEB_PIN（固定，仅用于 Web 端保存关键词）"
    echo "域名可选：不填写则使用 HTTP；填写域名且有有效证书，则启用 HTTPS。"
    read -erp "关键词网页域名 [当前: ${WEB_DOMAIN:-空}，清空输入-]: " new_web_domain
    [[ -z "$new_web_domain" ]] && new_web_domain="${WEB_DOMAIN:-}"
    [[ "$new_web_domain" == "-" ]] && new_web_domain=""
    WEB_DOMAIN="$new_web_domain"

    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    write_config
    echo "设置已保存，若服务正在运行，请在菜单 5 重启服务使配置生效。"
}

show_status() {
    echo -e "${BLUE}======================================${PLAIN}"
    echo -e "${PURPLE} node 运行状态 ${PLAIN}"
    echo -e "${BLUE}======================================${PLAIN}"
    echo "管理脚本: $SCRIPT_PATH"
    echo "工作目录: $WORK_DIR"
    echo "Python文件: $PYTHON_SCRIPT"
    echo "配置文件: $CONFIG_FILE"
    echo "网页端口: $DEFAULT_WEB_PORT"
    echo "服务器本地时间: $(date '+%Y-%m-%d %H:%M:%S %Z %z')"
    echo "上海时间: $(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S %Z %z')"
    echo "推送时间规则: 上海时间22:30-08:00优先级1；其他时段按照 NTFY_PRIORITY"

    echo
    if have_systemd; then
        if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
            echo -e "开机自启: ${GREEN}已启用${PLAIN}"
        else
            echo -e "开机自启: ${YELLOW}未启用${PLAIN}"
        fi
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "服务状态: ${GREEN}RUNNING${PLAIN}"
        else
            echo -e "服务状态: ${RED}STOPPED${PLAIN}"
        fi
        echo "服务文件: $SERVICE_FILE"
        echo "启动命令: /usr/bin/python3 $PYTHON_SCRIPT run-all"
    else
        echo -e "systemd: ${YELLOW}未检测到${PLAIN}"
    fi

    echo
    if [ -f "$PYTHON_SCRIPT" ]; then
        echo -e "node.py: ${GREEN}已部署${PLAIN}"
        run_py status 2>/dev/null || true
        run_py keyword-web-status 2>/dev/null || true
    else
        echo -e "node.py: ${RED}未部署${PLAIN}"
    fi

    echo
    if [ -f "$LAST_NODE_TXT" ]; then
        echo "缓存文件: $LAST_NODE_TXT"
        echo "最近修改: $(date -r "$LAST_NODE_TXT" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 未知)"
    else
        echo "缓存文件: 不存在"
    fi

    echo
    echo "最近 systemd 日志（最后 20 行）："
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || echo "（无日志或无权限）"
    echo -e "${BLUE}======================================${PLAIN}"
}

run_push() {
    if ! python_ready; then
        echo -e "${RED}❌ 未检测到 python3，请先安装依赖。${PLAIN}"
        return 1
    fi
    if [ ! -f "$PUSH_SCRIPT" ]; then
        echo -e "${RED}❌ 未找到 $PUSH_SCRIPT，请先执行菜单 2 部署。${PLAIN}"
        return 1
    fi
    ensure_permissions
    python3 "$PUSH_SCRIPT" "$@"
}

test_notification() {
    run_push test
}

update_node_domain() {
    echo -e "${BLUE}=============== 更新 Web 管理端域名 ===============${PLAIN}"
    if [ -e "$SERVICE_FILE" ] && ! service_is_ours; then
        echo -e "${RED}❌ 检测到同名非本项目的服务，拒绝修改并重启。${PLAIN}"
        return 1
    fi

    # 确保配置文件存在
    ensure_runtime_files
    read_config || true
    init_default_vars

    local current_domain="${WEB_DOMAIN:-}"
    if [ -z "$current_domain" ]; then
        echo "当前未配置域名（使用 HTTP）"
    else
        echo "当前域名: $current_domain"
    fi

    local new_domain=""
    read -erp "请输入新域名（留空则关闭 HTTPS 并回退到 HTTP）: " new_domain
    new_domain="$(echo "$new_domain" | tr -d '[:space:]')"
    if [ -n "$new_domain" ] && [[ ! "$new_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
        echo -e "${RED}❌ 域名包含非法字符，未修改配置。${PLAIN}"
        return 1
    fi

    if [ "$new_domain" = "$current_domain" ]; then
        echo "新域名与当前域名相同，无需更新。"
        return 0
    fi

    # 准备证书（如果输入了域名）
    if [ -n "$new_domain" ]; then
        echo "准备新域名的 SSL 证书..."
        if ! prepare_web_cert_for_domain "$new_domain"; then
            echo -e "${RED}❌ 新域名证书准备失败，已停止域名更新。${PLAIN}"
            return 1
        fi
    fi

    # 备份当前配置
    local bak_suffix=".bak.$(date '+%Y%m%d_%H%M%S')"
    cp -a "$CONFIG_FILE" "${CONFIG_FILE}${bak_suffix}"

    # 使用统一写入函数转义配置，并确保旧端口同步迁移。
    WEB_DOMAIN="$new_domain"
    write_config
    echo -e "${GREEN}✅ 已更新 $CONFIG_FILE 中的 WEB_DOMAIN 字段。${PLAIN}"

    # 重启服务
    echo "重启 node 服务以应用新域名..."
    if have_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        restart_service
    else
        echo "停止旧进程..."
        stop_running
        echo "启动新服务..."
        if have_systemd; then
            install_service || return 1
            systemctl start "$SERVICE_NAME"
        else
            # 无 systemd 则直接后台运行
            nohup python3 "$PYTHON_SCRIPT" run-all >> "$WORK_DIR/node.log" 2>&1 &
        fi
    fi

    sleep 2

    # 检查 HTTPS 是否可访问（如果配置了域名）
    if [ -n "$new_domain" ]; then
        echo "测试 HTTPS 连接（端口 $DEFAULT_WEB_PORT）..."
        if command -v curl >/dev/null 2>&1; then
            if curl -ksS --max-time 5 "https://${new_domain}:${DEFAULT_WEB_PORT}/" >/dev/null 2>&1; then
                echo -e "${GREEN}✅ HTTPS 服务已正常响应。${PLAIN}"
            else
                echo -e "${YELLOW}⚠️ HTTPS 服务未响应，请检查 node.py 日志和证书权限。${PLAIN}"
                echo "   日志位置：$WORK_DIR/node.log"
            fi
        else
            echo "未检测到 curl，请手动访问 https://${new_domain}:${DEFAULT_WEB_PORT}/ 验证。"
        fi
    else
        echo -e "${GREEN}✅ 已关闭 HTTPS，回退到 HTTP 端口 $DEFAULT_WEB_PORT。${PLAIN}"
    fi

    echo "============================================="
    echo -e "${GREEN}✅ Web 管理端域名已更新为：${new_domain:-未配置}${PLAIN}"
    if [ -n "$new_domain" ]; then
        echo "证书来源：/etc/letsencrypt/live/${new_domain}"
        echo "访问地址：https://${new_domain}:${DEFAULT_WEB_PORT}/keywords"
        echo "管理 PIN：${WEB_PIN}"
    fi
    echo "旧配置备份：${CONFIG_FILE}${bak_suffix}"
    echo "============================================="
}

dispatch_cli() {
    if [[ "${1:-}" == "-deps" ]]; then
        install_dependencies
        return $?
    fi
    if [[ "${1:-}" == "-deploy" || "${1:-}" == "-install" ]]; then
        deploy_from_local
        return $?
    fi
    if [[ "${1:-}" == "-config" ]]; then
        configure_params
        return $?
    fi
    if [[ "${1:-}" == "-stop" ]]; then
        stop_running
        return $?
    fi
    if [[ "${1:-}" == "-status" ]]; then
        show_status
        return $?
    fi
    if [[ "${1:-}" == "-uninstall" ]]; then
        uninstall_everything
        return $?
    fi
    if [[ "${1:-}" == "-service-remove" ]]; then
        uninstall_service_only
        return $?
    fi
    if [[ "${1:-}" == "-restart" || "${1:-}" == "-start" ]]; then
        restart_node_service
        return $?
    fi
    if [[ "${1:-}" == "-test" ]]; then
        test_notification
        return $?
    fi
    echo "未知参数：${1:-}；请直接运行 bash node.sh 打开管理菜单。"
    return 2
}

main_menu() {
    while true; do
        clear
        echo -e "${CYAN}┌────────────────────────────────────────────────┐${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${BOLD}${PURPLE}node 关键词监控管理面板${PLAIN}              ${CYAN}│${PLAIN}"
        echo -e "${CYAN}├────────────────────────────────────────────────┤${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${GREEN}1${PLAIN}）安装依赖                              ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${GREEN}2${PLAIN}）本地部署 / 更新系统                   ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${YELLOW}3${PLAIN}）配置参数                              ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${BLUE}4${PLAIN}）查看状态                              ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${PURPLE}5${PLAIN}）重启服务                              ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${CYAN}6${PLAIN}）推送测试消息                          ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${YELLOW}7${PLAIN}）更新域名 / HTTPS                      ${CYAN}│${PLAIN}"
        echo -e "${CYAN}├────────────────────────────────────────────────┤${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${RED}8${PLAIN}）${RED}彻底卸载 Node 监控系统${PLAIN}             ${CYAN}│${PLAIN}"
        echo -e "${CYAN}│${PLAIN}  ${WHITE}0${PLAIN}）退出                                ${CYAN}│${PLAIN}"
        echo -e "${CYAN}└────────────────────────────────────────────────┘${PLAIN}"
        read -erp "  请选择操作 [0-8]: " choice
        echo
        case "$choice" in
            1) install_dependencies ;;
            2) deploy_from_local ;;
            3) configure_params ;;
            4) show_status ;;
            5) restart_node_service ;;
            6) test_notification ;;
            7) update_node_domain ;;
            8) if uninstall_everything; then exit 0; fi ;;
            0) exit 0 ;;
            *) echo -e "${RED}  无效选项，请重新选择${PLAIN}" ;;
        esac
        echo
        read -erp "  按 Enter 返回菜单..."
    done
}

# 通过 source 加载时不自动启动菜单，便于对删除范围进行隔离验证。
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [ "$#" -gt 0 ]; then
        dispatch_cli "$@"
        exit $?
    fi
    main_menu
fi
