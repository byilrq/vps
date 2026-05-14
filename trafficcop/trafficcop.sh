#!/bin/bash
# ============================================
# TrafficCop - 流量周期统计 + 超限处理（TC限速/关机）
# 版本：1.0.87（减少日志噪音；用 LAST_PERIOD_RESET 替代 traffic_period.dat）
# 路径：/root/TrafficCop/trafficcop.sh
# 依赖：vnstat / bc / iproute2 / cron
# ============================================

# 设置 PATH 确保 cron 环境能找到所有命令
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TZ='Asia/Shanghai'

WORK_DIR="/root/TrafficCop"
CONFIG_FILE="$WORK_DIR/traffic_config.txt"
LOG_FILE="$WORK_DIR/traffic.log"
LOCK_FILE="$WORK_DIR/traffic.lock"
OFFSET_FILE="$WORK_DIR/traffic_offset.dat"
STATE_FILE="$WORK_DIR/limit_state.dat"

# 保留 SCRIPT_PATH（修复你之前写成 traffic.sh 导致 cron 失效的问题）
SCRIPT_PATH="$WORK_DIR/trafficcop.sh"

mkdir -p "$WORK_DIR"

# 运行模式：interactive / cron
RUN_MODE="interactive"
LOG_VERBOSE=1

# ============================================
# 日志横幅（仅交互模式输出，避免 cron 每分钟刷屏）
# ============================================
log_banner() {
    echo "-----------------------------------------------------" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') 当前版本：1.0.87（减少日志噪音；LAST_PERIOD_RESET 替代 traffic_period.dat）" | tee -a "$LOG_FILE"
}

# ============================================
# 统一日志输出（按模式控制）
# ============================================
log_info() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_info_quiet() { [ "$LOG_VERBOSE" = "1" ] && log_info "$@"; }

# ============================================
# 防止重复运行（交互模式用互杀兜底；cron 模式用 flock 静默互斥）
# ============================================
kill_other_instances() {
    local current_pid=$$
    for pid in $(pgrep -f "$(basename "$0")"); do
        if [ "$pid" != "$current_pid" ]; then
            log_info "终止其他实例 PID: $pid"
            kill "$pid" 2>/dev/null
        fi
    done
}

# ============================================
# 文件迁移（兼容旧版本脚本/文件名/旧 cron）
# ============================================
migrate_files() {
    mkdir -p "$WORK_DIR"

    # 旧文件迁移（如果有）
    for file in /root/traffic_monitor_config.txt /root/traffic_monitor.log /root/.traffic_monitor_packages_installed; do
        [ -f "$file" ] && mv "$file" "$WORK_DIR/"
    done

    # 如果旧 cron 指向 traffic.sh 或 traffic_monitor.sh，统一清理/替换
    if crontab -l 2>/dev/null | grep -q "/root/traffic_monitor.sh"; then
        (crontab -l 2>/dev/null | sed "s|/root/traffic_monitor.sh|$SCRIPT_PATH|g") | crontab -
    fi
}

# ============================================
# 安装必要软件包
# ============================================
check_and_install_packages() {
    local packages=("vnstat" "jq" "bc" "iproute2" "cron")
    for package in "${packages[@]}"; do
        dpkg -s "$package" >/dev/null 2>&1 || {
            apt-get update && apt-get install -y "$package"
        }
    done

    local main_interface
    main_interface=$(ip route | awk '/default/ {print $5; exit}')
    log_info "主要网络接口: ${main_interface:-未知}"
}

# ============================================
# 配置文件 KV 更新（替代写整个文件，避免 --run 模式误覆盖）
# ============================================
set_config_kv() {
    local key="$1"
    local value="$2"
    mkdir -p "$WORK_DIR"
    touch "$CONFIG_FILE"

    if grep -qE "^${key}=" "$CONFIG_FILE"; then
        # 用 | 作为分隔符，避免 value 含 /
        sed -i "s|^${key}=.*|${key}=${value}|" "$CONFIG_FILE"
    else
        echo "${key}=${value}" >> "$CONFIG_FILE"
    fi
}

# ============================================
# 读配置（只解析 KEY=VALUE 行；cron 模式不打印“已加载配置”）
# 新增参数：LAST_PERIOD_RESET=YYYY-MM-DD
# ============================================
read_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_info "配置文件不存在：$CONFIG_FILE"
        return 1
    fi

    unset TRAFFIC_MODE TRAFFIC_PERIOD TRAFFIC_LIMIT TRAFFIC_TOLERANCE PERIOD_START_DAY LIMIT_SPEED MAIN_INTERFACE LIMIT_MODE LAST_PERIOD_RESET

    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_FILE" | sed 's/\r$//') 2>/dev/null || {
        log_info "配置加载失败（可能包含非法行）：$CONFIG_FILE"
        return 1
    }

    TRAFFIC_MODE=${TRAFFIC_MODE:-total}
    TRAFFIC_PERIOD=${TRAFFIC_PERIOD:-monthly}
    TRAFFIC_LIMIT=${TRAFFIC_LIMIT:-0}
    TRAFFIC_TOLERANCE=${TRAFFIC_TOLERANCE:-0}
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}
    LIMIT_SPEED=${LIMIT_SPEED:-20}
    LIMIT_MODE=${LIMIT_MODE:-tc}
    LAST_PERIOD_RESET=${LAST_PERIOD_RESET:-}

    # PERIOD_START_DAY 防呆
    if ! [[ "$PERIOD_START_DAY" =~ ^([1-9]|[12][0-9]|3[01])$ ]]; then
        PERIOD_START_DAY=1
    fi

    # 主接口兜底
    if [ -z "$MAIN_INTERFACE" ]; then
        MAIN_INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
        [ -z "$MAIN_INTERFACE" ] && MAIN_INTERFACE=$(ip link | awk -F': ' '/state UP/ {print $2; exit}')
    fi

    if [ -z "$MAIN_INTERFACE" ] || ! ip link show "$MAIN_INTERFACE" >/dev/null 2>&1; then
        log_info "主接口无效/不存在：MAIN_INTERFACE=$MAIN_INTERFACE（请检查配置）"
        return 1
    fi

    # 仅交互模式输出一次配置摘要
    log_info_quiet "已加载配置：MODE=$TRAFFIC_MODE PERIOD=$TRAFFIC_PERIOD START_DAY=$PERIOD_START_DAY IFACE=$MAIN_INTERFACE LIMIT=$TRAFFIC_LIMIT TOL=$TRAFFIC_TOLERANCE LIMIT_MODE=$LIMIT_MODE LAST_PERIOD_RESET=${LAST_PERIOD_RESET:-空}"
    return 0
}

# ============================================
# 写配置（只在交互模式调用；包含 LAST_PERIOD_RESET）
# ============================================
write_config() {
    mkdir -p "$WORK_DIR"
    cat > "$CONFIG_FILE" <<EOF
TRAFFIC_MODE=$TRAFFIC_MODE
TRAFFIC_PERIOD=$TRAFFIC_PERIOD
TRAFFIC_LIMIT=$TRAFFIC_LIMIT
TRAFFIC_TOLERANCE=$TRAFFIC_TOLERANCE
PERIOD_START_DAY=${PERIOD_START_DAY:-1}
LIMIT_SPEED=${LIMIT_SPEED:-20}
MAIN_INTERFACE=$MAIN_INTERFACE
LIMIT_MODE=$LIMIT_MODE
LAST_PERIOD_RESET=${LAST_PERIOD_RESET:-}
EOF
}

# ============================================
# 获取主要接口（交互选择）
# ============================================
get_main_interface() {
    local iface
    iface=$(ip route | awk '/default/ {print $5; exit}')
    [ -z "$iface" ] && iface=$(ip link | awk -F': ' '/state UP/ {print $2; exit}')
    while true; do
        read -p "检测到主要接口: ${iface:-无}，直接回车使用或输入新接口: " input
        input=${input:-$iface}
        ip link show "$input" >/dev/null 2>&1 && { echo "$input"; return; }
        echo "接口无效，请重新输入"
    done
}

# ============================================
# 初始配置（交互）- 修复版
# 关键修复：vnstat oneline 解析更稳 + 自动 --add 兜底
# ============================================
initial_config() {
    MAIN_INTERFACE=$(get_main_interface)

    while :; do
        echo "1. 出站  2. 进站  3. 总和  4. 出入较大者"
        read -p "选择流量统计模式 (1-4): " c
        case $c in
            1) TRAFFIC_MODE=out; break ;;
            2) TRAFFIC_MODE=in; break ;;
            3) TRAFFIC_MODE=total; break ;;
            4) TRAFFIC_MODE=max; break ;;
        esac
    done

    read -p "统计周期 (m/q/y，默认为m): " p
    TRAFFIC_PERIOD=${p:-monthly}
    TRAFFIC_PERIOD=$(echo "$TRAFFIC_PERIOD" | cut -c1)
    [ "$TRAFFIC_PERIOD" = "q" ] && TRAFFIC_PERIOD=quarterly
    [ "$TRAFFIC_PERIOD" = "y" ] && TRAFFIC_PERIOD=yearly
    [ "$TRAFFIC_PERIOD" != "quarterly" ] && [ "$TRAFFIC_PERIOD" != "yearly" ] && TRAFFIC_PERIOD=monthly

    read -p "周期起始日 (1-31，默认为1): " PERIOD_START_DAY
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}
    [[ ! $PERIOD_START_DAY =~ ^[1-9]$|^[12][0-9]$|^3[01]$ ]] && PERIOD_START_DAY=1

    while :; do
        read -p "流量限制 (GB): " TRAFFIC_LIMIT
        [[ $TRAFFIC_LIMIT =~ ^[0-9]+(\.[0-9]*)?$ ]] && break
    done

    while :; do
        read -p "容错范围 (GB): " TRAFFIC_TOLERANCE
        [[ $TRAFFIC_TOLERANCE =~ ^[0-9]+(\.[0-9]*)?$ ]] && break
    done

    while :; do
        echo "1. TC限速  2. 关机"
        read -p "限制模式 (1-2): " m
        case $m in
            1)
                LIMIT_MODE=tc
                read -p "限速值 kbit/s (默认20): " LIMIT_SPEED
                LIMIT_SPEED=${LIMIT_SPEED:-20}
                break
                ;;
            2)
                LIMIT_MODE=shutdown
                break
                ;;
        esac
    done

    # ====== 关键：本次配置属于哪个周期（先算出来）======
    local period_start
    period_start=$(get_period_start_date)

    # 新增字段：LAST_PERIOD_RESET（先写入当前周期起点，避免后续 save_offset_on_new_period 覆盖）
    LAST_PERIOD_RESET="$period_start"

    # 先把配置写入（包括 LAST_PERIOD_RESET）
    write_config

    # ====== 去掉“手动修正本周期流量”逻辑：offset 直接从 0 开始 ======
    echo 0 > "$OFFSET_FILE" || { echo "写入 OFFSET_FILE 失败：$OFFSET_FILE"; return 1; }

    log_info "初始化：已移除手动基准设置，OFFSET_FILE=0（本周期从 0GB 开始统计）"
    log_info "初始化：LAST_PERIOD_RESET=$period_start（防止新周期检测覆盖 offset）"
    return 0
}



# ============================================
# 计算当前周期起始日（monthly/quarterly/yearly）
# ============================================
get_period_start_date() {
    _last_day_of_month() { date -d "$1-$2-01 +1 month -1 day" +%d 2>/dev/null; }

    local y m d
    y=$(date +%Y); m=$(date +%m); d=$(date +%d)

    local mm=$((10#$m))
    local dd=$((10#$d))

    local sd="$PERIOD_START_DAY"
    if ! [[ "$sd" =~ ^([1-9]|[12][0-9]|3[01])$ ]]; then sd=1; fi

    case "$TRAFFIC_PERIOD" in
        monthly)
            if (( dd < sd )); then
                local py pm last_prev
                py=$(date -d "$y-$m-01 -1 day" +%Y)
                pm=$(date -d "$y-$m-01 -1 day" +%m)
                last_prev=$(_last_day_of_month "$py" "$pm")
                (( sd > 10#$last_prev )) && sd=$((10#$last_prev))
                date -d "$py-$pm-$(printf "%02d" "$sd")" +%Y-%m-%d
            else
                local last_cur
                last_cur=$(_last_day_of_month "$y" "$m")
                (( sd > 10#$last_cur )) && sd=$((10#$last_cur))
                date -d "$y-$m-$(printf "%02d" "$sd")" +%Y-%m-%d
            fi
            ;;
        quarterly)
            local qstart=$(( ( (mm-1)/3 )*3 + 1 ))
            local qs_month; qs_month=$(printf "%02d" "$qstart")

            if (( mm == qstart && dd < sd )); then
                local qy qm last_qm
                qy=$(date -d "$y-$qs_month-01 -3 months" +%Y)
                qm=$(date -d "$y-$qs_month-01 -3 months" +%m)
                last_qm=$(_last_day_of_month "$qy" "$qm")
                (( sd > 10#$last_qm )) && sd=$((10#$last_qm))
                date -d "$qy-$qm-$(printf "%02d" "$sd")" +%Y-%m-%d
            else
                local last_qs
                last_qs=$(_last_day_of_month "$y" "$qs_month")
                (( sd > 10#$last_qs )) && sd=$((10#$last_qs))
                date -d "$y-$qs_month-$(printf "%02d" "$sd")" +%Y-%m-%d
            fi
            ;;
        yearly)
            if (( mm == 1 && dd < sd )); then
                date -d "$((y-1))-01-$(printf "%02d" "$sd")" +%Y-%m-%d
            else
                date -d "$y-01-$(printf "%02d" "$sd")" +%Y-%m-%d
            fi
            ;;
        *)
            date -d "$y-$m-$(printf "%02d" "$sd")" +%Y-%m-%d
            ;;
    esac
}

# ============================================
# 新周期检测：用 LAST_PERIOD_RESET 替代 traffic_period.dat
# period_start 变化时：更新 OFFSET + 写回 LAST_PERIOD_RESET + 清除限速
# ============================================
save_offset_on_new_period() {
    local period_start last_mark line total_bytes rx tx

    period_start=$(get_period_start_date)
    last_mark="${LAST_PERIOD_RESET:-}"

    if [ "$last_mark" != "$period_start" ]; then
        vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1
        line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>/dev/null || echo "")

        # vnstat 输出异常：不写入 LAST_PERIOD_RESET，稍后 cron 再试
        if [ -z "$line" ] || ! echo "$line" | grep -q ';'; then
            [ "$RUN_MODE" = "interactive" ] && log_info "新周期检测到但 vnstat 输出无效，稍后重试（不更新 LAST_PERIOD_RESET）"
            return 0
        fi

        # all-time 字段：in=13 out=14 total=15
        total_bytes=0
        case $TRAFFIC_MODE in
            out)   total_bytes=$(echo "$line" | cut -d';' -f14) ;;
            in)    total_bytes=$(echo "$line" | cut -d';' -f13) ;;
            total) total_bytes=$(echo "$line" | cut -d';' -f15) ;;
            max)
                rx=$(echo "$line" | cut -d';' -f13); tx=$(echo "$line" | cut -d';' -f14)
                rx=${rx:-0}; tx=${tx:-0}
                [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
                [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
                total_bytes=$((rx > tx ? rx : tx))
                ;;
            *) total_bytes=$(echo "$line" | cut -d';' -f15) ;;
        esac

        total_bytes=${total_bytes:-0}
        if ! [[ "$total_bytes" =~ ^[0-9]+$ ]]; then
            [ "$RUN_MODE" = "interactive" ] && log_info "新周期基准异常(total_bytes=$total_bytes)，稍后重试（不更新 LAST_PERIOD_RESET）"
            return 0
        fi

        # 写 offset（新周期从 0 开始）
        echo "$total_bytes" > "$OFFSET_FILE"

        # 写回配置：LAST_PERIOD_RESET
        LAST_PERIOD_RESET="$period_start"
        set_config_kv "LAST_PERIOD_RESET" "$LAST_PERIOD_RESET"

        # 关键日志：只记录新周期
        log_info "进入新周期：${last_mark:-空} -> $period_start，写入 OFFSET_FILE=$total_bytes，并清除限速/关机"

        tc qdisc del dev "$MAIN_INTERFACE" root 2>/dev/null
        shutdown -c 2>/dev/null
        echo "normal" > "$STATE_FILE" 2>/dev/null || true
    fi
}

# ============================================
# 读取本周期用量（GB）：all-time(raw) - offset，输出 3 位小数
# ============================================
get_traffic_usage() {
    local offset raw_bytes real_bytes line rx tx

    offset=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)
    [[ "$offset" =~ ^-?[0-9]+$ ]] || offset=0

    vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1
    line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>/dev/null || echo "")

    if [ -z "$line" ] || ! echo "$line" | grep -q ';'; then
        printf "0.000"
        return 0
    fi

    raw_bytes=0
    case $TRAFFIC_MODE in
        out)   raw_bytes=$(echo "$line" | cut -d';' -f14) ;;
        in)    raw_bytes=$(echo "$line" | cut -d';' -f13) ;;
        total) raw_bytes=$(echo "$line" | cut -d';' -f15) ;;
        max)
            rx=$(echo "$line" | cut -d';' -f13); tx=$(echo "$line" | cut -d';' -f14)
            rx=${rx:-0}; tx=${tx:-0}
            [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
            [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
            raw_bytes=$((rx > tx ? rx : tx))
            ;;
        *) raw_bytes=$(echo "$line" | cut -d';' -f15) ;;
    esac

    raw_bytes=${raw_bytes:-0}
    [[ "$raw_bytes" =~ ^[0-9]+$ ]] || raw_bytes=0

    real_bytes=$((raw_bytes - offset))
    [ "$real_bytes" -lt 0 ] && real_bytes=0

    printf "%.3f" "$(echo "scale=6; $real_bytes/1024/1024/1024" | bc 2>/dev/null || echo 0)"
}

# ============================================
# 超限处理：仅在状态变化时记录日志（limited <-> normal）
# ============================================
check_and_limit_traffic() {
    local usage threshold prev_state new_state

    usage=$(get_traffic_usage)
    threshold=$(echo "$TRAFFIC_LIMIT - $TRAFFIC_TOLERANCE" | bc 2>/dev/null || echo 0)

    prev_state=$(cat "$STATE_FILE" 2>/dev/null || echo "normal")
    new_state="$prev_state"

    if (( $(echo "$usage > $threshold" | bc -l 2>/dev/null || echo 0) )); then
        new_state="limited"
        if [ "$prev_state" != "limited" ]; then
            if [ "$LIMIT_MODE" = "tc" ]; then
                tc qdisc add dev "$MAIN_INTERFACE" root tbf rate ${LIMIT_SPEED}kbit burst 32kbit latency 400ms 2>/dev/null || \
                tc qdisc change dev "$MAIN_INTERFACE" root tbf rate ${LIMIT_SPEED}kbit burst 32kbit latency 400ms
                log_info "流量超限：已用 ${usage}GB > 阈值 ${threshold}GB，开始限速 ${LIMIT_SPEED}kbit"
            else
                log_info "流量超限：已用 ${usage}GB > 阈值 ${threshold}GB，60秒后关机"
                shutdown -h +1 "流量超限自动关机"
            fi
        fi
    else
        new_state="normal"
        if [ "$prev_state" != "normal" ]; then
            tc qdisc del dev "$MAIN_INTERFACE" root 2>/dev/null
            shutdown -c 2>/dev/null
            log_info "流量恢复：已用 ${usage}GB <= 阈值 ${threshold}GB，解除限速/取消关机"
        fi
    fi

    echo "$new_state" > "$STATE_FILE" 2>/dev/null || true
}

# ============================================
# 设置 cron：每分钟执行 $SCRIPT_PATH --run（保留 SCRIPT_PATH）
# ============================================
setup_crontab() {
    (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH --run" | grep -v "/root/TrafficCop/traffic.sh --run" ; echo "* * * * * $SCRIPT_PATH --run") | crontab -
}

# ============================================
# 主流程：--run 为 cron 模式（静默+互斥）；否则交互配置模式
# ============================================
main() {
    cd "$WORK_DIR" || exit 1

    if [ "$1" = "--run" ]; then
        RUN_MODE="cron"
        LOG_VERBOSE=0

        exec 9>"$LOCK_FILE"
        flock -n 9 || exit 0

        read_config || exit 0
        save_offset_on_new_period
        check_and_limit_traffic
        exit 0
    fi

    RUN_MODE="interactive"
    LOG_VERBOSE=1

    log_banner
    kill_other_instances
    migrate_files
    check_and_install_packages

    if read_config; then
        echo "检测到已有配置，5秒内按任意键修改，否则保持"
        if read -t 5 -n 1; then
            initial_config
        fi
    else
        initial_config
    fi

    setup_crontab
    write_config

    # 首次部署也强制跑一次周期初始化（会写入 LAST_PERIOD_RESET）
    save_offset_on_new_period

    log_info "配置完成：已设置每分钟自动检查（cron）"
    log_info "当前本周期已用流量: $(get_traffic_usage) GB"
}

main "$@"
