#!/bin/bash
# node Python monitor simple manager
# node.sh lives at /root/node.sh
# node.py is downloaded from GitHub to /root/node/node.py
# systemd handles startup and restart; node.py run-all handles monitor + keyword web

set -u

export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export TZ='Asia/Shanghai'

WORK_DIR="/root/node"
CONFIG_FILE="$WORK_DIR/node_config.txt"
PYTHON_SCRIPT="$WORK_DIR/node.py"
SCRIPT_PATH="/root/node.sh"
SERVICE_NAME="node"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_NODE_PY_URL="https://raw.githubusercontent.com/byilrq/vps/main/node/node.py"
https://github.com/byilrq/vps/blob/main/node/node.py

CRON_LOG="$WORK_DIR/node_cron.log"
BOOT_LOG="$WORK_DIR/node_boot.log"
WEB_LOG="$WORK_DIR/node_web.log"
PID_FILE="$WORK_DIR/.node_python.pid"
WEB_PID_FILE="$WORK_DIR/.node_keyword_web.pid"
LAST_NODE_TXT="$WORK_DIR/last_node.txt"

DEFAULT_NS_URL="https://rss.nodeseek.com/?sortBy=postTime"
DEFAULT_INTERVAL_SEC="15"
DEFAULT_WEB_PORT="2068"
DEFAULT_WEB_PIN="0819"

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
BLUE="\033[34m"; PURPLE="\033[35m"; WHITE="\033[37m"; PLAIN="\033[0m"

ensure_runtime_files() {
    mkdir -p "$WORK_DIR"
    touch "$CRON_LOG" "$BOOT_LOG" "$WEB_LOG"
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
    chmod_if_needed "$SCRIPT_PATH"
    chmod_if_needed "$PYTHON_SCRIPT"
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
    TG_BOT_TOKEN="${TG_BOT_TOKEN:-}"
    TG_PUSH_CHAT_ID="${TG_PUSH_CHAT_ID:-}"
    PUSH_CHANNEL="${PUSH_CHANNEL:-tg}"
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
    WEB_PIN="${WEB_PIN:-$DEFAULT_WEB_PIN}"
    WEB_DOMAIN="${WEB_DOMAIN:-}"
    return 0
}

init_default_vars() {
    TG_BOT_TOKEN="${TG_BOT_TOKEN:-}"
    TG_PUSH_CHAT_ID="${TG_PUSH_CHAT_ID:-}"
    PUSH_CHANNEL="${PUSH_CHANNEL:-tg}"
    NTFY_URL="${NTFY_URL:-http://127.0.0.1:8083}"
    NTFY_USERNAME="${NTFY_USERNAME:-}"
    NTFY_PASSWORD="${NTFY_PASSWORD:-}"
    NTFY_TOPIC="${NTFY_TOPIC:-node}"
    NTFY_PRIORITY="${NTFY_PRIORITY:-3}"
    NS_URL="${NS_URL:-$DEFAULT_NS_URL}"
    KEYWORDS="${KEYWORDS:-}"
    INTERVAL_SEC="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    DEBUG_LOG="${DEBUG_LOG:-0}"
    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    WEB_PIN="${WEB_PIN:-$DEFAULT_WEB_PIN}"
    WEB_DOMAIN="${WEB_DOMAIN:-}"
}

write_config() {
    ensure_runtime_files
    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    cat > "$CONFIG_FILE" <<CFGEOF
TG_BOT_TOKEN="$(escape_config_value "${TG_BOT_TOKEN:-}")"
TG_PUSH_CHAT_ID="$(escape_config_value "${TG_PUSH_CHAT_ID:-}")"
PUSH_CHANNEL="$(escape_config_value "${PUSH_CHANNEL:-tg}")"
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
WEB_PIN="$(escape_config_value "${WEB_PIN:-$DEFAULT_WEB_PIN}")"
WEB_DOMAIN="$(escape_config_value "${WEB_DOMAIN:-}")"
CFGEOF
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    echo -e "${GREEN}✅ 配置已保存到 $CONFIG_FILE${PLAIN}"
    echo -e "${GREEN}✅ 网页端口固定为 $DEFAULT_WEB_PORT${PLAIN}"
}

ensure_config_exists() {
    if read_config; then
        init_default_vars
        INTERVAL_SEC="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
        if ! [[ "$INTERVAL_SEC" =~ ^[0-9]+$ ]] || (( INTERVAL_SEC < 15 )); then
            INTERVAL_SEC="$DEFAULT_INTERVAL_SEC"
        fi
        WEB_HOST="0.0.0.0"
        WEB_PORT="$DEFAULT_WEB_PORT"
        write_config >/dev/null
        return 0
    fi
    init_default_vars
    write_config >/dev/null
}

download_node_py() {
    ensure_runtime_files
    local tmp_file="$WORK_DIR/node.py.tmp"
    echo -e "${BLUE}正在从 GitHub 下载 node.py...${PLAIN}"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$GITHUB_NODE_PY_URL" -o "$tmp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tmp_file" "$GITHUB_NODE_PY_URL"
    else
        echo -e "${RED}❌ 未检测到 curl 或 wget，请先执行菜单 1 安装依赖。${PLAIN}"
        return 1
    fi

    if [ ! -s "$tmp_file" ]; then
        rm -f "$tmp_file"
        echo -e "${RED}❌ node.py 下载失败或文件为空。${PLAIN}"
        return 1
    fi
    if ! grep -q "def main" "$tmp_file" || ! grep -q "run-all" "$tmp_file"; then
        rm -f "$tmp_file"
        echo -e "${RED}❌ 下载的 node.py 看起来不完整，已取消部署。${PLAIN}"
        return 1
    fi

    if [ -f "$PYTHON_SCRIPT" ]; then
        cp -f "$PYTHON_SCRIPT" "$PYTHON_SCRIPT.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    fi
    mv -f "$tmp_file" "$PYTHON_SCRIPT"
    chmod 755 "$PYTHON_SCRIPT" 2>/dev/null || true
    echo -e "${GREEN}✅ node.py 已更新到 $PYTHON_SCRIPT${PLAIN}"
}

install_dependencies() {
    echo -e "${BLUE}开始安装/检查依赖...${PLAIN}"
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y python3 python3-pip curl wget ca-certificates
    else
        echo -e "${YELLOW}⚠️ 当前系统未检测到 apt-get，请手动安装 python3 / pip / curl 或 wget。${PLAIN}"
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
        python3 -m pip install requests >/dev/null 2>&1 || true
    fi
    ensure_runtime_files
    ensure_permissions
    echo -e "${GREEN}✅ 依赖检查/安装完成${PLAIN}"
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
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
}

cleanup_old_cron() {
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -Ev '(/root/node/node\.sh|/root/node\.sh) -cron' | crontab - 2>/dev/null || true
    fi
}

install_service() {
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
    install_service || return 1
    systemctl restart "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}✔ node 服务已启动/重启，并已设置开机自启${PLAIN}"
        return 0
    fi
    echo -e "${RED}❌ node 服务启动失败，请查看：journalctl -u $SERVICE_NAME -n 100 --no-pager${PLAIN}"
    return 1
}

deploy_from_github() {
    ensure_runtime_files
    download_node_py || return 1
    ensure_config_exists
    cleanup_old_cron >/dev/null 2>&1 || true
    restart_service
}

stop_running() {
    if have_systemd; then
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    pkill -f "python3 $PYTHON_SCRIPT run-all" 2>/dev/null || true
    pkill -f "python3 $PYTHON_SCRIPT run" 2>/dev/null || true
    pkill -f "python3 $PYTHON_SCRIPT keyword-web" 2>/dev/null || true
    pkill -f "node.py run-all" 2>/dev/null || true
    rm -f "$PID_FILE" "$WEB_PID_FILE"
    echo -e "${GREEN}✔ node 服务已停止${PLAIN}"
}

uninstall_service() {
    stop_running >/dev/null 2>&1 || true
    if have_systemd; then
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    cleanup_old_cron >/dev/null 2>&1 || true
    echo -e "${GREEN}✔ node systemd 服务已卸载，配置和数据仍保留在 $WORK_DIR${PLAIN}"
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
    echo -e "${PURPLE} node 参数配置 ${PLAIN}"
    echo -e "${BLUE}======================================${PLAIN}"
    echo "工作目录：$WORK_DIR"
    echo "网页端口：$DEFAULT_WEB_PORT（固定）"
    echo "提示：按 Enter 保留当前配置，输入新值将覆盖原配置。"
    echo

    echo "请选择推送渠道："
    echo "1) Telegram"
    echo "2) ntfy"
    echo "当前: ${PUSH_CHANNEL:-tg}"
    read -rp "选择 (1-2) [回车保持当前]: " push_choice
    if [[ -n "$push_choice" ]]; then
        case "$push_choice" in
            1) PUSH_CHANNEL="tg" ;;
            2) PUSH_CHANNEL="ntfy" ;;
            *) PUSH_CHANNEL="${PUSH_CHANNEL:-tg}" ;;
        esac
    fi
    [[ "$PUSH_CHANNEL" != "ntfy" ]] && PUSH_CHANNEL="tg"

    if [[ "$PUSH_CHANNEL" == "tg" ]]; then
        if [ -n "${TG_BOT_TOKEN:-}" ]; then
            local token_display="${TG_BOT_TOKEN:0:10}...${TG_BOT_TOKEN: -4}"
            read -rp "请输入 Telegram Bot Token [当前: $token_display]: " new_bot_token
            [[ -z "$new_bot_token" ]] && new_bot_token="$TG_BOT_TOKEN"
        else
            read -rp "请输入 Telegram Bot Token: " new_bot_token
            while [[ -z "$new_bot_token" ]]; do
                echo "❌ Bot Token 不能为空，请重新输入。"
                read -rp "请输入 Telegram Bot Token: " new_bot_token
            done
        fi
        if [ -n "${TG_PUSH_CHAT_ID:-}" ]; then
            read -rp "请输入个人推送 Chat ID [当前: $TG_PUSH_CHAT_ID]: " new_chat_id
            [[ -z "$new_chat_id" ]] && new_chat_id="$TG_PUSH_CHAT_ID"
        else
            read -rp "请输入个人推送 Chat ID（不知道可先填0，稍后再改）: " new_chat_id
            [[ -z "$new_chat_id" ]] && new_chat_id="0"
        fi
        TG_BOT_TOKEN="$new_bot_token"
        TG_PUSH_CHAT_ID="$new_chat_id"
    fi

    if [[ "$PUSH_CHANNEL" == "ntfy" ]]; then
        echo
        echo "===== ntfy 配置 ====="
        read -rp "请输入 ntfy 地址 [当前: ${NTFY_URL:-http://127.0.0.1:8083}]: " new_ntfy_url
        [[ -z "$new_ntfy_url" ]] && new_ntfy_url="${NTFY_URL:-http://127.0.0.1:8083}"
        read -rp "请输入 ntfy 用户名 [当前: ${NTFY_USERNAME:-空}]: " new_ntfy_username
        [[ -z "$new_ntfy_username" ]] && new_ntfy_username="${NTFY_USERNAME:-}"
        read -rp "请输入 ntfy 密码 [当前已设置则回车保持]: " new_ntfy_password
        [[ -z "$new_ntfy_password" ]] && new_ntfy_password="${NTFY_PASSWORD:-}"
        read -rp "请输入 ntfy Topic [当前: ${NTFY_TOPIC:-node}]: " new_ntfy_topic
        [[ -z "$new_ntfy_topic" ]] && new_ntfy_topic="${NTFY_TOPIC:-node}"
        read -rp "请输入 ntfy Priority 1-5 [当前: ${NTFY_PRIORITY:-3}]: " new_ntfy_priority
        [[ -z "$new_ntfy_priority" ]] && new_ntfy_priority="${NTFY_PRIORITY:-3}"
        [[ ! "$new_ntfy_priority" =~ ^[1-5]$ ]] && new_ntfy_priority="3"
        NTFY_URL="$new_ntfy_url"
        NTFY_USERNAME="$new_ntfy_username"
        NTFY_PASSWORD="$new_ntfy_password"
        NTFY_TOPIC="$new_ntfy_topic"
        NTFY_PRIORITY="$new_ntfy_priority"
    fi

    read -rp "请输入要监控的 RSS URL [当前: ${NS_URL:-$DEFAULT_NS_URL}]: " new_url
    [[ -z "$new_url" ]] && new_url="${NS_URL:-$DEFAULT_NS_URL}"
    NS_URL="$new_url"

    read -rp "请输入监控间隔秒数 [当前: ${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}]（默认15，最低15）: " new_interval
    [[ -z "$new_interval" ]] && new_interval="${INTERVAL_SEC:-$DEFAULT_INTERVAL_SEC}"
    if ! [[ "$new_interval" =~ ^[0-9]+$ ]] || (( new_interval < 15 )); then
        new_interval="$DEFAULT_INTERVAL_SEC"
    fi
    INTERVAL_SEC="$new_interval"

    read -rp "是否开启 Debug 日志？[当前: ${DEBUG_LOG:-0}] (0/1): " new_debug
    [[ -z "$new_debug" ]] && new_debug="${DEBUG_LOG:-0}"
    [[ "$new_debug" != "1" ]] && new_debug="0"
    DEBUG_LOG="$new_debug"

    echo
    echo "当前关键词：${KEYWORDS:-未设置}"
    echo "支持写法：单关键词（抽奖）或 AND（车&box / a&b&c）"
    read -rp "是否需要重置关键词？(Y/N): " reset_kw
    if [[ "$reset_kw" =~ ^[Yy]$ ]]; then
        read -rp "输入关键词（多个可用空格或逗号，留空=清空）: " new_keywords
        new_keywords=${new_keywords//,/ }
        new_keywords=$(echo "$new_keywords" | xargs 2>/dev/null || true)
        KEYWORDS="$new_keywords"
    fi

    read -rp "关键词网页 PIN [当前: ${WEB_PIN:-$DEFAULT_WEB_PIN}]（4位数字）: " new_web_pin
    [[ -z "$new_web_pin" ]] && new_web_pin="${WEB_PIN:-$DEFAULT_WEB_PIN}"
    [[ ! "$new_web_pin" =~ ^[0-9]{4}$ ]] && new_web_pin="$DEFAULT_WEB_PIN"
    WEB_PIN="$new_web_pin"

    echo
    echo "域名可选：留空=HTTP 2068；填写域名则 node.py 会继续使用 /etc/letsencrypt/live/<域名>/fullchain.pem 和 privkey.pem。"
    read -rp "关键词网页域名 [当前: ${WEB_DOMAIN:-空}]: " new_web_domain
    [[ -z "$new_web_domain" ]] && new_web_domain="${WEB_DOMAIN:-}"
    WEB_DOMAIN="$new_web_domain"

    WEB_HOST="0.0.0.0"
    WEB_PORT="$DEFAULT_WEB_PORT"
    write_config
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

test_notification() {
    run_py test
}

if [[ "${1:-}" == "-deps" ]]; then
    install_dependencies
    exit $?
fi
if [[ "${1:-}" == "-deploy" || "${1:-}" == "-install" ]]; then
    deploy_from_github
    exit $?
fi
if [[ "${1:-}" == "-config" ]]; then
    configure_params
    exit $?
fi
if [[ "${1:-}" == "-stop" ]]; then
    stop_running
    exit $?
fi
if [[ "${1:-}" == "-status" ]]; then
    show_status
    exit $?
fi
if [[ "${1:-}" == "-uninstall" || "${1:-}" == "-service-remove" ]]; then
    uninstall_service
    exit $?
fi
if [[ "${1:-}" == "-restart" || "${1:-}" == "-start" ]]; then
    restart_service
    exit $?
fi
if [[ "${1:-}" == "-test" ]]; then
    test_notification
    exit $?
fi

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}======================================${PLAIN}"
        echo -e "${PURPLE} node Python 监控管理菜单 ${PLAIN}"
        echo -e "${BLUE}======================================${PLAIN}"
        echo -e "${GREEN}1.${PLAIN} 安装依赖"
        echo -e "${GREEN}2.${PLAIN} 安装 / 部署（仅 HTTP 2068）"
        echo -e "${GREEN}3.${PLAIN} 配置参数"
        echo -e "${GREEN}4.${PLAIN} 停止运行"
        echo -e "${GREEN}5.${PLAIN} 查看运行情况"
        echo -e "${GREEN}6.${PLAIN} 卸载服务"
        echo -e "${GREEN}7.${PLAIN} 重启服务"
        echo -e "${GREEN}8.${PLAIN} 推送测试消息"
        echo -e "${WHITE}0.${PLAIN} 退出"
        echo -e "${BLUE}======================================${PLAIN}"
        read -rp "请选择操作 [0-8]: " choice
        echo
        case "$choice" in
            1) install_dependencies ;;
            2) deploy_from_github ;;
            3) configure_params ;;
            4) stop_running ;;
            5) show_status ;;
            6) uninstall_service ;;
            7) restart_service ;;
            8) test_notification ;;
            0) exit 0 ;;
            *) echo "无效选项" ;;
        esac
        echo
        read -rp "按 Enter 返回菜单..."
    done
}

main_menu
