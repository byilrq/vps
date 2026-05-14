#!/bin/bash
# ============================================
# 支持两种流量来源：
#   1) vnstat（本机网卡口径，支持 offset 校准；周期按 TrafficCop 配置）
#   2) bwh_api（KiwiVM 面板口径；周期按 data_next_reset 推算）
# ============================================

WORK_DIR="/root/TrafficCop"
mkdir -p "$WORK_DIR"

CONFIG_FILE="$WORK_DIR/push_config.txt"
CRON_LOG="$WORK_DIR/push_cron.log"
SCRIPT_PATH="$WORK_DIR/push.sh"

TRAFFIC_CONFIG="$WORK_DIR/traffic_config.txt"
OFFSET_FILE="$WORK_DIR/traffic_offset.dat"

BWH_API_ENDPOINT_DEFAULT="https://api.64clouds.com/v1/getServiceInfo"
PUSHPLUS_ENDPOINT_DEFAULT="https://www.pushplus.plus/send"
NTFY_URL_DEFAULT="http://127.0.0.1:8083"
NTFY_TOPIC_DEFAULT="traffic"
NTFY_PRIORITY_DEFAULT="1"

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"
PURPLE="\033[35m"; CYAN="\033[36m"; WHITE="\033[37m"; PLAIN="\033[0m"

cd "$WORK_DIR" || exit 1

trim_cron_log() {
    local file="$CRON_LOG"
    local max_lines=150
    [[ -f "$file" ]] || return 0

    local cnt
    cnt=$(wc -l < "$file" 2>/dev/null || echo 0)
    if (( cnt > max_lines )); then
        tail -n "$max_lines" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

log_cron() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') : $*" | tee -a "$CRON_LOG" >/dev/null
    trim_cron_log
}

check_running() {
    if pidof -x "$(basename "$0")" -o $$ >/dev/null 2>&1; then
        log_cron "已有实例运行，退出。"
        exit 1
    fi
}

read_config() {
    [ ! -s "$CONFIG_FILE" ] && return 1
    # shellcheck disable=SC1090
    source "$CONFIG_FILE" 2>/dev/null || return 1

    PUSH_CHANNEL=${PUSH_CHANNEL:-tg}              # tg / pushplus / ntfy
    TRAFFIC_SOURCE=${TRAFFIC_SOURCE:-vnstat}      # vnstat / bwh_api
    BWH_API_ENDPOINT=${BWH_API_ENDPOINT:-$BWH_API_ENDPOINT_DEFAULT}

    PUSHPLUS_ENDPOINT=${PUSHPLUS_ENDPOINT:-$PUSHPLUS_ENDPOINT_DEFAULT}
    PUSHPLUS_TEMPLATE=${PUSHPLUS_TEMPLATE:-html}

    NTFY_URL=${NTFY_URL:-$NTFY_URL_DEFAULT}
    NTFY_USERNAME=${NTFY_USERNAME:-}
    NTFY_PASSWORD=${NTFY_PASSWORD:-}
    NTFY_TOPIC=${NTFY_TOPIC:-$NTFY_TOPIC_DEFAULT}
    NTFY_PRIORITY=${NTFY_PRIORITY:-$NTFY_PRIORITY_DEFAULT}
    if ! [[ "$NTFY_PRIORITY" =~ ^[1-5]$ ]]; then
        NTFY_PRIORITY="$NTFY_PRIORITY_DEFAULT"
    fi

    [[ -z "$MACHINE_NAME" || -z "$DAILY_REPORT_TIME" || -z "$EXPIRE_DATE" ]] && return 1

    case "$PUSH_CHANNEL" in
        tg)
            [[ -z "$TG_BOT_TOKEN" || -z "$TG_CHAT_ID" ]] && return 1
            ;;
        pushplus)
            [[ -z "$PUSHPLUS_TOKEN" ]] && return 1
            ;;
        ntfy)
            [[ -z "$NTFY_URL" || -z "$NTFY_TOPIC" || -z "$NTFY_PRIORITY" ]] && return 1
            ;;
        *)
            return 1
            ;;
    esac

    if [[ "$TRAFFIC_SOURCE" == "bwh_api" ]]; then
        [[ -z "$BWH_VEID" || -z "$BWH_API_KEY" ]] && return 1
    fi

    return 0
}

write_config() {
    cat >"$CONFIG_FILE" <<EOF
# ===== 基本信息 =====
MACHINE_NAME="$MACHINE_NAME"
DAILY_REPORT_TIME="$DAILY_REPORT_TIME"
EXPIRE_DATE="$EXPIRE_DATE"

# ===== 推送渠道：tg / pushplus / ntfy =====
PUSH_CHANNEL="$PUSH_CHANNEL"

# ===== 流量来源：vnstat / bwh_api =====
TRAFFIC_SOURCE="$TRAFFIC_SOURCE"

# ===== Telegram（tg 需要）=====
TG_BOT_TOKEN="$TG_BOT_TOKEN"
TG_CHAT_ID="$TG_CHAT_ID"

# ===== PushPlus（pushplus 需要）=====
PUSHPLUS_TOKEN="$PUSHPLUS_TOKEN"
PUSHPLUS_TOPIC="$PUSHPLUS_TOPIC"
PUSHPLUS_TEMPLATE="$PUSHPLUS_TEMPLATE"
PUSHPLUS_ENDPOINT="$PUSHPLUS_ENDPOINT"

# ===== ntfy（ntfy 需要；默认本机内网推送）=====
NTFY_URL="${NTFY_URL:-$NTFY_URL_DEFAULT}"
NTFY_USERNAME="${NTFY_USERNAME:-}"
NTFY_PASSWORD="${NTFY_PASSWORD:-}"
NTFY_TOPIC="${NTFY_TOPIC:-$NTFY_TOPIC_DEFAULT}"
NTFY_PRIORITY="${NTFY_PRIORITY:-$NTFY_PRIORITY_DEFAULT}"

# ===== 搬瓦工 / KiwiVM API（仅 bwh_api 需要）=====
BWH_VEID="$BWH_VEID"
BWH_API_KEY="$BWH_API_KEY"
BWH_API_ENDPOINT="$BWH_API_ENDPOINT"
EOF
    log_cron "配置已保存到 $CONFIG_FILE"
}

read_traffic_config() {
    [ ! -s "$TRAFFIC_CONFIG" ] && return 1

    unset MAIN_INTERFACE TRAFFIC_MODE TRAFFIC_LIMIT TRAFFIC_TOLERANCE TRAFFIC_PERIOD PERIOD_START_DAY LIMIT_SPEED LIMIT_MODE
    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$TRAFFIC_CONFIG" | sed 's/\r$//') 2>/dev/null || return 1

    TRAFFIC_MODE=${TRAFFIC_MODE:-total}
    TRAFFIC_PERIOD=${TRAFFIC_PERIOD:-monthly}
    TRAFFIC_LIMIT=${TRAFFIC_LIMIT:-0}
    TRAFFIC_TOLERANCE=${TRAFFIC_TOLERANCE:-0}
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}
    MAIN_INTERFACE=${MAIN_INTERFACE:-eth0}

    [[ -z "$TRAFFIC_PERIOD" || -z "$PERIOD_START_DAY" ]] && return 1

    if [[ "${TRAFFIC_SOURCE:-vnstat}" == "vnstat" ]]; then
        [[ -z "$MAIN_INTERFACE" || -z "$TRAFFIC_MODE" || -z "$TRAFFIC_LIMIT" || -z "$TRAFFIC_TOLERANCE" ]] && return 1
        ip link show "$MAIN_INTERFACE" >/dev/null 2>&1 || return 1
    fi
    return 0
}

get_period_start_date() {
    local y m d
    y=$(date +%Y); m=$(date +%m); d=$(date +%d)
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}

    case $TRAFFIC_PERIOD in
        monthly)
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                date -d "$y-$m-$PERIOD_START_DAY -1 month" +%Y-%m-%d 2>/dev/null || date -d "$y-$m-$PERIOD_START_DAY" +%Y-%m-%d
            else
                date -d "$y-$m-$PERIOD_START_DAY" +%Y-%m-%d 2>/dev/null
            fi
            ;;
        quarterly)
            local qm
            qm=$(( ((10#$m-1)/3*3 +1) )); qm=$(printf "%02d" "$qm")
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                date -d "$y-$qm-$PERIOD_START_DAY -3 months" +%Y-%m-%d 2>/dev/null || date -d "$y-$qm-$PERIOD_START_DAY" +%Y-%m-%d
            else
                date -d "$y-$qm-$PERIOD_START_DAY" +%Y-%m-%d 2>/dev/null
            fi
            ;;
        yearly)
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                date -d "$((y-1))-01-$PERIOD_START_DAY" +%Y-%m-%d 2>/dev/null || date -d "$y-01-$PERIOD_START_DAY" +%Y-%m-%d
            else
                date -d "$y-01-$PERIOD_START_DAY" +%Y-%m-%d 2>/dev/null
            fi
            ;;
        *)
            date -d "$y-$m-${PERIOD_START_DAY:-1}" +%Y-%m-%d 2>/dev/null
            ;;
    esac
}

get_period_end_date() {
    local start="$1"
    case "$TRAFFIC_PERIOD" in
        monthly)   date -d "$start +1 month -1 day" +%Y-%m-%d 2>/dev/null ;;
        quarterly) date -d "$start +3 month -1 day" +%Y-%m-%d 2>/dev/null ;;
        yearly)    date -d "$start +1 year -1 day" +%Y-%m-%d 2>/dev/null ;;
        *)         date -d "$start +1 month -1 day" +%Y-%m-%d 2>/dev/null ;;
    esac
}

get_traffic_usage_vnstat() {
    local offset raw=0 line rx tx real

    offset=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)
    [[ "$offset" =~ ^-?[0-9]+$ ]] || offset=0

    vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1
    line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>/dev/null || echo "")
    [ -z "$line" ] && { printf "0.000"; return 0; }
    echo "$line" | grep -q ';' || { printf "0.000"; return 0; }

    case $TRAFFIC_MODE in
        out)   raw=$(echo "$line" | cut -d';' -f14) ;;
        in)    raw=$(echo "$line" | cut -d';' -f13) ;;
        total) raw=$(echo "$line" | cut -d';' -f15) ;;
        max)
            rx=$(echo "$line" | cut -d';' -f13); tx=$(echo "$line" | cut -d';' -f14)
            rx=${rx:-0}; tx=${tx:-0}
            [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
            [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
            raw=$(( rx > tx ? rx : tx ))
            ;;
        *) raw=0 ;;
    esac

    raw=${raw:-0}
    [[ "$raw" =~ ^[0-9]+$ ]] || raw=0

    real=$((raw - offset))
    (( real < 0 )) && real=0

    printf "%.3f" "$(echo "scale=6; $real/1024/1024/1024" | bc 2>/dev/null || echo 0)"
}

get_bwh_info() {
    local json err used_bytes plan_bytes next_reset

    json=$(curl -fsS -G "$BWH_API_ENDPOINT" \
        --data-urlencode "veid=$BWH_VEID" \
        --data-urlencode "api_key=$BWH_API_KEY" 2>/dev/null) || return 1

    err=$(echo "$json" | jq -r '.error // 1' 2>/dev/null)
    [[ "$err" == "0" ]] || return 1

    used_bytes=$(echo "$json" | jq -r '.data_counter // empty' 2>/dev/null)
    plan_bytes=$(echo "$json" | jq -r '.plan_monthly_data // empty' 2>/dev/null)
    next_reset=$(echo "$json" | jq -r '.data_next_reset // empty' 2>/dev/null)

    [[ "$used_bytes" =~ ^[0-9]+$ ]] || return 1
    [[ "$plan_bytes" =~ ^[0-9]+$ ]] || plan_bytes=0
    [[ "$next_reset" =~ ^[0-9]+$ ]] || next_reset=0

    local used_gb plan_gb
    used_gb=$(awk "BEGIN{printf \"%.3f\", $used_bytes/1024/1024/1024}")
    plan_gb=$(awk "BEGIN{printf \"%.3f\", $plan_bytes/1024/1024/1024}")

    echo "$used_gb $plan_gb $next_reset $used_bytes $plan_bytes"
    return 0
}

get_bwh_cycle_dates() {
    local next_reset_ts="$1"
    [[ "$next_reset_ts" =~ ^[0-9]+$ ]] || return 1
    (( next_reset_ts > 0 )) || return 1

    local reset_date start_date end_date
    reset_date=$(date -d @"$next_reset_ts" +%Y-%m-%d 2>/dev/null) || return 1

    start_date=$(date -d "$reset_date -1 month" +%Y-%m-%d 2>/dev/null) || return 1
    end_date=$(date -d "$reset_date -1 day" +%Y-%m-%d 2>/dev/null) || return 1

    echo "$start_date $end_date"
    return 0
}

# 重要修复：
# Telegram 的 parse_mode=HTML 不支持 <br>，只用 \n 换行 + 少量合法标签（b/i/u/s/code/pre/a）
build_report() {
    local today expire_ts today_ts diff_days remain_emoji
    local disk_used disk_total disk_pct disk_line
    local start end usage limit

    today=$(date +%Y-%m-%d)

    expire_ts=$(date -d "${EXPIRE_DATE//./-}" +%s 2>/dev/null)
    today_ts=$(date -d "$today" +%s 2>/dev/null)
    diff_days=$(( (expire_ts - today_ts) / 86400 ))

    remain_emoji="🟢"
    if (( diff_days <= 0 )); then
        remain_emoji="🏴‍☠️"; diff_days="已到期"
    elif (( diff_days <= 30 )); then
        remain_emoji="🔴"
    elif (( diff_days <= 60 )); then
        remain_emoji="🟡"
    fi

    disk_used=$(df -hP / 2>/dev/null | awk 'NR==2{print $3}')
    disk_total=$(df -hP / 2>/dev/null | awk 'NR==2{print $2}')
    disk_pct=$(df -hP / 2>/dev/null | awk 'NR==2{print $5}')
    if [[ -n "$disk_used" && -n "$disk_total" && -n "$disk_pct" ]]; then
        disk_line="${disk_used}/${disk_total} (${disk_pct})"
    else
        disk_line="未知"
    fi

    # 周期兜底
    if read_traffic_config; then
        start=$(get_period_start_date)
        end=$(get_period_end_date "$start")
    else
        start="未知"; end="未知"
    fi

    if [[ "$TRAFFIC_SOURCE" == "bwh_api" ]]; then
        local info used_gb plan_gb next_reset cy
        info=$(get_bwh_info) || return 1
        used_gb=$(echo "$info" | awk '{print $1}')
        plan_gb=$(echo "$info" | awk '{print $2}')
        next_reset=$(echo "$info" | awk '{print $3}')

        cy=$(get_bwh_cycle_dates "$next_reset" 2>/dev/null) && {
            start=$(echo "$cy" | awk '{print $1}')
            end=$(echo "$cy" | awk '{print $2}')
        }

        usage="$used_gb"
        limit="${plan_gb} GB"
    else
        read_traffic_config || return 1
        usage=$(get_traffic_usage_vnstat)
        limit="${TRAFFIC_LIMIT} GB"
    fi

    local title="🎯 [${MACHINE_NAME}] 流量统计"

    # 纯文本（用于终端显示、PushPlus 也可用）
    local text_plain="${title}

🕒日期：${today}
${remain_emoji}剩余：${diff_days}天
🔄周期：${start} 到 ${end}
⌛已用：${usage} GB
🌐套餐：${limit}
💾空间：${disk_line}
"

    # Telegram-safe HTML：只保留<b>，不用<br>，用换行符
    local text_tg_html="<b>${title}</b>
🕒日期：${today}
${remain_emoji}剩余：${diff_days}天
🔄周期：${start} 到 ${end}
⌛已用：${usage} GB
🌐套餐：${limit}
💾空间：${disk_line}
"

    # PushPlus HTML：使用<br>
    local text_pp_html="<b>${title}</b><br><br>
🕒日期：${today}<br>
${remain_emoji}剩余：${diff_days}天<br>
🔄周期：${start} 到 ${end}<br>
⌛已用：${usage} GB<br>
🌐套餐：${limit}<br>
💾空间：${disk_line}
"

    # 用分隔符输出三段，避免 sed 取行断裂
    printf "%s\n__SPLIT__\n%s\n__SPLIT__\n%s\n__SPLIT__\n%s\n" \
        "$title" "$text_plain" "$text_tg_html" "$text_pp_html"
}


is_delete_input() {
    case "${1:-}" in
        DELETE|delete|DEL|del|删除|清空) return 0 ;;
        *) return 1 ;;
    esac
}

read_input() {
    local __var="$1"
    local __prompt="${2:-}"
    if [ -t 0 ]; then
        # -e enables readline editing: arrows, Backspace, Ctrl+A/E, etc.
        IFS= read -e -r -p "$__prompt" "$__var"
    else
        IFS= read -r "$__var"
    fi
}

get_ntfy_effective_priority() {
    local base_priority expire_ts today_ts remain_days

    base_priority="${NTFY_PRIORITY:-$NTFY_PRIORITY_DEFAULT}"
    if ! [[ "$base_priority" =~ ^[1-5]$ ]]; then
        base_priority="$NTFY_PRIORITY_DEFAULT"
    fi

    # VPS 剩余时间小于 30 天时，ntfy 使用高优先级 4；否则沿用配置/默认优先级。
    if [[ -n "${EXPIRE_DATE:-}" ]]; then
        expire_ts=$(date -d "${EXPIRE_DATE//./-}" +%s 2>/dev/null || echo "")
        today_ts=$(date -d "$(date +%Y-%m-%d)" +%s 2>/dev/null || echo "")
        if [[ "$expire_ts" =~ ^[0-9]+$ && "$today_ts" =~ ^[0-9]+$ ]]; then
            remain_days=$(( (expire_ts - today_ts) / 86400 ))
            if (( remain_days < 30 )); then
                echo "4"
                return 0
            fi
        fi
    fi

    echo "$base_priority"
}

ntfy_send() {
    local content="$1"
    local url topic priority endpoint resp http_code

    url="${NTFY_URL:-$NTFY_URL_DEFAULT}"
    topic="${NTFY_TOPIC:-$NTFY_TOPIC_DEFAULT}"
    priority=$(get_ntfy_effective_priority)

    if [[ -z "$url" || -z "$topic" ]]; then
        log_cron "ntfy 发送失败：NTFY_URL 或 NTFY_TOPIC 为空"
        return 1
    fi

    endpoint="${url%/}/${topic}"
    local auth_arg=()
    if [[ -n "${NTFY_USERNAME:-}" || -n "${NTFY_PASSWORD:-}" ]]; then
        auth_arg=(-u "${NTFY_USERNAME:-}:${NTFY_PASSWORD:-}")
    fi

    resp=$(printf '%s' "$content" | curl -sS -w "\nHTTP_CODE:%{http_code}\n" -X POST "$endpoint" \
        "${auth_arg[@]}" \
        -H "Priority: ${priority}" \
        --data-binary @- \
        --connect-timeout 8 --max-time 15)

    http_code=$(echo "$resp" | awk -F: '/HTTP_CODE:/{print $2}' | tail -n 1)
    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        return 0
    fi

    log_cron "ntfy 发送失败：HTTP=${http_code} resp=$(echo "$resp" | sed '/HTTP_CODE:/d' | tr '\n' ' ' | cut -c1-1200)"
    return 1
}


tg_send() {
    local html="$1"
    local resp http_code ok

    resp=$(curl -sS -w "\nHTTP_CODE:%{http_code}\n" -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT_ID}" \
        --data-urlencode "text=${html}" \
        -d "parse_mode=HTML" \
        -d "disable_web_page_preview=true" \
        --connect-timeout 8 --max-time 15)

    http_code=$(echo "$resp" | awk -F: '/HTTP_CODE:/{print $2}' | tail -n 1)
    ok=$(echo "$resp" | sed '/HTTP_CODE:/d' | jq -r '.ok // empty' 2>/dev/null)

    if [[ "$http_code" == "200" && "$ok" == "true" ]]; then
        return 0
    fi

    log_cron "Telegram 发送失败：resp=$(echo "$resp" | sed '/HTTP_CODE:/d' | tr '\n' ' ' | cut -c1-1200)"
    return 1
}

pushplus_send() {
    local title="$1"
    local content="$2"
    local resp http_code code

    local topic_arg=()
    [[ -n "$PUSHPLUS_TOPIC" ]] && topic_arg=(-d "topic=${PUSHPLUS_TOPIC}")

    resp=$(curl -sS -w "\nHTTP_CODE:%{http_code}\n" -X POST "$PUSHPLUS_ENDPOINT" \
        -d "token=${PUSHPLUS_TOKEN}" \
        "${topic_arg[@]}" \
        --data-urlencode "title=${title}" \
        --data-urlencode "content=${content}" \
        -d "template=${PUSHPLUS_TEMPLATE}" \
        --connect-timeout 8 --max-time 15)

    http_code=$(echo "$resp" | awk -F: '/HTTP_CODE:/{print $2}' | tail -n 1)
    code=$(echo "$resp" | sed '/HTTP_CODE:/d' | jq -r '.code // empty' 2>/dev/null)

    if [[ "$http_code" == "200" && "$code" == "200" ]]; then
        return 0
    fi

    log_cron "PushPlus 发送失败：resp=$(echo "$resp" | sed '/HTTP_CODE:/d' | tr '\n' ' ' | cut -c1-1200)"
    return 1
}

test_push() {
    local title="🖥️ [${MACHINE_NAME}] 测试消息"
    local plain="${title}\n\n这是一条测试消息，如果您收到此推送，说明配置正常！"
    local tg_html="<b>${title}</b>
这是一条测试消息，如果您收到此推送，说明配置正常！"
    local pp_html="<b>${title}</b><br><br>这是一条测试消息，如果您收到此推送，说明配置正常！"

    case "$PUSH_CHANNEL" in
        tg)
            tg_send "$tg_html" && log_cron "Telegram 测试推送成功" || log_cron "Telegram 测试推送失败"
            ;;
        pushplus)
            pushplus_send "$title" "$pp_html" && log_cron "PushPlus 测试推送成功" || log_cron "PushPlus 测试推送失败"
            ;;
        ntfy)
            ntfy_send "$(printf "%b" "$plain")" && log_cron "ntfy 测试推送成功" || log_cron "ntfy 测试推送失败"
            ;;
    esac

    echo -e "$plain"
}


daily_report() {
    local out title plain tg_html pp_html
    out=$(build_report) || { log_cron "生成报告失败（流量来源/配置/依赖异常）"; return 1; }

    title=$(echo "$out" | awk 'BEGIN{RS="__SPLIT__"; ORS=""} NR==1{print}' | sed 's/\n$//')
    plain=$(echo "$out" | awk 'BEGIN{RS="__SPLIT__"; ORS=""} NR==2{print}' | sed 's/\n$//')
    tg_html=$(echo "$out" | awk 'BEGIN{RS="__SPLIT__"; ORS=""} NR==3{print}' | sed 's/\n$//')
    pp_html=$(echo "$out" | awk 'BEGIN{RS="__SPLIT__"; ORS=""} NR==4{print}' | sed 's/\n$//')

    case "$PUSH_CHANNEL" in
        tg)
            if tg_send "$tg_html"; then
                log_cron "Telegram 推送成功"
            else
                log_cron "Telegram 推送失败"
            fi
            ;;
        pushplus)
            if pushplus_send "$title" "$pp_html"; then
                log_cron "PushPlus 推送成功"
            else
                log_cron "PushPlus 推送失败"
            fi
            ;;
        ntfy)
            if ntfy_send "$plain"; then
                log_cron "ntfy 推送成功"
            else
                log_cron "ntfy 推送失败"
            fi
            ;;
    esac

    echo -e "$plain"
}




flow_setting() {
    echo "（仅 vnstat 模式可用）请输入本周期实际已用流量（GiB）:"
    read_input real_gb
    [[ ! $real_gb =~ ^[0-9]+(\.[0-9]+)?$ ]] && { echo "输入无效"; return; }
    read_traffic_config || { echo "无法读取 TrafficCop 配置"; return; }

    vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1
    local line raw rx tx
    line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>/dev/null || echo "")
    [ -z "$line" ] && { echo "vnstat 无输出"; return; }
    echo "$line" | grep -q ';' || { echo "vnstat 输出无效：$line"; return; }

    case $TRAFFIC_MODE in
        out)   raw=$(echo "$line" | cut -d';' -f14) ;;
        in)    raw=$(echo "$line" | cut -d';' -f13) ;;
        total) raw=$(echo "$line" | cut -d';' -f15) ;;
        max)
            rx=$(echo "$line" | cut -d';' -f13)
            tx=$(echo "$line" | cut -d';' -f14)
            rx=${rx:-0}; tx=${tx:-0}
            [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
            [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
            raw=$(( rx > tx ? rx : tx ))
            ;;
        *) raw=0 ;;
    esac
    raw=${raw:-0}
    [[ "$raw" =~ ^[0-9]+$ ]] || raw=0

    local target_bytes new_offset
    target_bytes=$(echo "$real_gb * 1024*1024*1024" | bc 2>/dev/null | cut -d. -f1)
    target_bytes=${target_bytes:-0}
    [[ "$target_bytes" =~ ^[0-9]+$ ]] || target_bytes=0

    new_offset=$((raw - target_bytes))
    echo "$new_offset" > "$OFFSET_FILE"
    echo "已修正 offset → $new_offset（当前显示 ≈${real_gb} GiB）"
}

initial_config() {
    echo "======================================"
    echo "     修改 Push（TG / PushPlus / ntfy）配置"
    echo "======================================"
    echo

    echo "请输入机器名称 [当前: ${MACHINE_NAME:-未设置}]: "
    read_input new_name
    [[ -z "$new_name" ]] && new_name="${MACHINE_NAME:-$(hostname)}"
    while [ -z "$new_name" ]; do read_input new_name; done

    echo "请输入每日报告时间 (HH:MM) [当前: ${DAILY_REPORT_TIME:-01:00}]: "
    read_input new_time
    [[ -z "$new_time" ]] && new_time="${DAILY_REPORT_TIME:-01:00}"
    while ! [[ $new_time =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]]; do
        echo "格式错误！请重新输入 (HH:MM): "
        read_input new_time
    done

    echo "请输入 VPS 到期日期 (YYYY.MM.DD) [当前: ${EXPIRE_DATE:-未设置}]: "
    read_input new_expire
    [[ -z "$new_expire" ]] && new_expire="$EXPIRE_DATE"
    while ! [[ $new_expire =~ ^[0-9]{4}\.[0-1][0-9]\.[0-3][0-9]$ ]]; do
        echo "格式错误！请重新输入 (YYYY.MM.DD): "
        read_input new_expire
    done

    echo
    echo "请选择推送渠道："
    echo "1) Telegram"
    echo "2) PushPlus"
    echo "3) ntfy"
    echo "当前: ${PUSH_CHANNEL:-tg}"
    read_input ch "选择 (1-3) [回车保持当前]: "
    if [[ -n "$ch" ]]; then
        case "$ch" in
            1) PUSH_CHANNEL="tg" ;;
            2) PUSH_CHANNEL="pushplus" ;;
            3) PUSH_CHANNEL="ntfy" ;;
            *) echo "无效选择，保持当前：${PUSH_CHANNEL:-tg}" ;;
        esac
    else
        PUSH_CHANNEL=${PUSH_CHANNEL:-tg}
    fi

    if [[ "$PUSH_CHANNEL" == "both" ]]; then
        PUSH_CHANNEL="tg"
    fi

    if [[ "$PUSH_CHANNEL" == "tg" ]]; then
        echo
        echo "===== Telegram 配置 ====="
        if [ -n "$TG_BOT_TOKEN" ]; then
            local tshow="${TG_BOT_TOKEN:0:8}...${TG_BOT_TOKEN: -4}"
            echo "请输入 Bot Token [当前: $tshow]: "
        else
            echo "请输入 Bot Token: "
        fi
        read_input new_token
        [[ -z "$new_token" && -n "$TG_BOT_TOKEN" ]] && new_token="$TG_BOT_TOKEN"
        while [ -z "$new_token" ]; do echo "不能为空！"; read_input new_token; done

        if [ -n "$TG_CHAT_ID" ]; then
            echo "请输入 Chat ID [当前: $TG_CHAT_ID]: "
        else
            echo "请输入 Chat ID: "
        fi
        read_input new_chat
        [[ -z "$new_chat" && -n "$TG_CHAT_ID" ]] && new_chat="$TG_CHAT_ID"
        while [ -z "$new_chat" ]; do echo "不能为空！"; read_input new_chat; done

        TG_BOT_TOKEN="$new_token"
        TG_CHAT_ID="$new_chat"
    fi

    if [[ "$PUSH_CHANNEL" == "pushplus" ]]; then
        echo
        echo "===== PushPlus 配置 ====="
        if [[ -n "$PUSHPLUS_TOKEN" ]]; then
            local pshow="${PUSHPLUS_TOKEN:0:6}...${PUSHPLUS_TOKEN: -4}"
            echo "请输入 PushPlus Token [当前: $pshow]（回车保持）: "
        else
            echo "请输入 PushPlus Token: "
        fi
        read_input new_ptoken
        [[ -z "$new_ptoken" && -n "$PUSHPLUS_TOKEN" ]] && new_ptoken="$PUSHPLUS_TOKEN"
        while [ -z "$new_ptoken" ]; do echo "不能为空！"; read_input new_ptoken; done

        echo "请输入 PushPlus Topic（可选，回车跳过）[当前: ${PUSHPLUS_TOPIC:-空}]: "
        read_input new_topic
        [[ -z "$new_topic" ]] && new_topic="$PUSHPLUS_TOPIC"

        echo "PushPlus Template（默认 html）[当前: ${PUSHPLUS_TEMPLATE:-html}]："
        read_input new_tpl
        [[ -z "$new_tpl" ]] && new_tpl="${PUSHPLUS_TEMPLATE:-html}"

        PUSHPLUS_TOKEN="$new_ptoken"
        PUSHPLUS_TOPIC="$new_topic"
        PUSHPLUS_TEMPLATE="$new_tpl"
        PUSHPLUS_ENDPOINT="$PUSHPLUS_ENDPOINT_DEFAULT"
    fi



    if [[ "$PUSH_CHANNEL" == "ntfy" ]]; then
        echo
        echo "===== ntfy 配置 ====="

        local current_ntfy_url="${NTFY_URL:-$NTFY_URL_DEFAULT}"
        read_input new_ntfy_url "请输入 ntfy 地址 [当前: ${current_ntfy_url}]: "
        if [[ -z "$new_ntfy_url" ]]; then
            new_ntfy_url="$current_ntfy_url"
        elif is_delete_input "$new_ntfy_url"; then
            new_ntfy_url="$NTFY_URL_DEFAULT"
        fi
        [[ -z "$new_ntfy_url" ]] && new_ntfy_url="$NTFY_URL_DEFAULT"

        local current_ntfy_user="${NTFY_USERNAME:-}"
        if [[ -n "$current_ntfy_user" ]]; then
            read_input new_ntfy_user "请输入 ntfy 用户名 [当前: ${current_ntfy_user}]: "
        else
            read_input new_ntfy_user "请输入 ntfy 用户名: "
        fi
        if [[ -z "$new_ntfy_user" ]]; then
            new_ntfy_user="$current_ntfy_user"
        elif is_delete_input "$new_ntfy_user"; then
            new_ntfy_user=""
        fi

        local current_ntfy_pass="${NTFY_PASSWORD:-}"
        if [[ -n "$current_ntfy_pass" ]]; then
            read_input new_ntfy_pass "请输入 ntfy 密码 [当前: 已设置]: "
        else
            read_input new_ntfy_pass "请输入 ntfy 密码: "
        fi
        if [[ -z "$new_ntfy_pass" ]]; then
            new_ntfy_pass="$current_ntfy_pass"
        elif is_delete_input "$new_ntfy_pass"; then
            new_ntfy_pass=""
        fi

        local current_ntfy_topic="${NTFY_TOPIC:-$NTFY_TOPIC_DEFAULT}"
        read_input new_ntfy_topic "请输入 ntfy Topic [当前: ${current_ntfy_topic}]: "
        if [[ -z "$new_ntfy_topic" ]]; then
            new_ntfy_topic="$current_ntfy_topic"
        elif is_delete_input "$new_ntfy_topic"; then
            new_ntfy_topic="$NTFY_TOPIC_DEFAULT"
        fi
        [[ -z "$new_ntfy_topic" ]] && new_ntfy_topic="$NTFY_TOPIC_DEFAULT"

        local current_ntfy_priority="${NTFY_PRIORITY:-$NTFY_PRIORITY_DEFAULT}"
        read_input new_ntfy_priority "请输入 ntfy Priority 1-5 [当前: ${current_ntfy_priority}]: "
        if [[ -z "$new_ntfy_priority" ]]; then
            new_ntfy_priority="$current_ntfy_priority"
        elif is_delete_input "$new_ntfy_priority"; then
            new_ntfy_priority="$NTFY_PRIORITY_DEFAULT"
        fi
        if ! [[ "$new_ntfy_priority" =~ ^[1-5]$ ]]; then
            echo "Priority 输入无效，已使用默认 ${NTFY_PRIORITY_DEFAULT}"
            new_ntfy_priority="$NTFY_PRIORITY_DEFAULT"
        fi

        NTFY_URL="$new_ntfy_url"
        NTFY_USERNAME="$new_ntfy_user"
        NTFY_PASSWORD="$new_ntfy_pass"
        NTFY_TOPIC="$new_ntfy_topic"
        NTFY_PRIORITY="$new_ntfy_priority"
    fi
    echo
    echo "请选择流量来源："
    echo "1) vnstat（本机网卡口径，可 offset 校准）"
    echo "2) bwh_api（KiwiVM 面板口径，按 data_next_reset 推算周期）"
    echo "当前: ${TRAFFIC_SOURCE:-vnstat}"
    read_input src_choice "选择 (1-2) [回车保持当前]: "
    if [[ -n "$src_choice" ]]; then
        case "$src_choice" in
            1) TRAFFIC_SOURCE="vnstat" ;;
            2) TRAFFIC_SOURCE="bwh_api" ;;
            *) echo "无效选择，保持当前：${TRAFFIC_SOURCE:-vnstat}" ;;
        esac
    else
        TRAFFIC_SOURCE=${TRAFFIC_SOURCE:-vnstat}
    fi

    BWH_API_ENDPOINT=${BWH_API_ENDPOINT:-$BWH_API_ENDPOINT_DEFAULT}
    if [[ "$TRAFFIC_SOURCE" == "bwh_api" ]]; then
        echo
        echo "===== 搬瓦工 / KiwiVM API 配置（bwh_api 必填）====="
        if [[ -n "$BWH_VEID" ]]; then
            echo "请输入 VEID [当前: $BWH_VEID]: "
        else
            echo "请输入 VEID: "
        fi
        read_input new_veid
        [[ -z "$new_veid" && -n "$BWH_VEID" ]] && new_veid="$BWH_VEID"
        while ! [[ "$new_veid" =~ ^[0-9]+$ ]]; do
            echo "VEID 必须为数字，请重新输入："
            read_input new_veid
        done

        if [[ -n "$BWH_API_KEY" ]]; then
            local kshow="${BWH_API_KEY:0:6}...${BWH_API_KEY: -4}"
            echo "请输入 API_KEY [当前: $kshow]（回车保持不变）: "
        else
            echo "请输入 API_KEY: "
        fi
        read_input new_key
        [[ -z "$new_key" && -n "$BWH_API_KEY" ]] && new_key="$BWH_API_KEY"
        while [ -z "$new_key" ]; do
            echo "API_KEY 不能为空，请重新输入："
            read_input new_key
        done

        echo "API Endpoint [当前: ${BWH_API_ENDPOINT}]（一般无需修改，回车保持）: "
        read_input new_ep
        [[ -z "$new_ep" ]] && new_ep="$BWH_API_ENDPOINT"

        BWH_VEID="$new_veid"
        BWH_API_KEY="$new_key"
        BWH_API_ENDPOINT="$new_ep"

        echo
        echo "正在测试 KiwiVM API..."
        if get_bwh_info >/dev/null 2>&1; then
            echo "API 测试成功。"
        else
            echo "API 测试失败：请检查 VEID/API_KEY 是否正确、网络是否可访问。"
            echo "你仍可保存配置，但推送会失败。"
        fi
    fi

    NTFY_URL="${NTFY_URL:-$NTFY_URL_DEFAULT}"
    NTFY_USERNAME="${NTFY_USERNAME:-}"
    NTFY_PASSWORD="${NTFY_PASSWORD:-}"
    NTFY_TOPIC="${NTFY_TOPIC:-$NTFY_TOPIC_DEFAULT}"
    NTFY_PRIORITY="${NTFY_PRIORITY:-$NTFY_PRIORITY_DEFAULT}"

    MACHINE_NAME="$new_name"
    DAILY_REPORT_TIME="$new_time"
    EXPIRE_DATE="$new_expire"

    write_config
    setup_cron
    echo "配置已更新成功！"
}

setup_cron() {
    if ! read_config >/dev/null 2>&1; then
        log_cron "配置不完整，无法设置 cron。"
        return 1
    fi

    if ! [[ "$DAILY_REPORT_TIME" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
        log_cron "报告时间格式错误：$DAILY_REPORT_TIME，无法设置 cron。"
        return 1
    fi

    local hh mm entry
    hh="${DAILY_REPORT_TIME%%:*}"
    mm="${DAILY_REPORT_TIME##*:}"

    # 去掉前导 0，避免某些 cron 实现把 08/09 当作异常八进制。
    hh=$((10#$hh))
    mm=$((10#$mm))

    entry="$mm $hh * * * $SCRIPT_PATH -cron"

    (
        crontab -l 2>/dev/null | grep -Fv "$SCRIPT_PATH -cron"
        echo "$entry"
    ) | crontab -

    log_cron "✅ Crontab 已更新：每天 ${DAILY_REPORT_TIME} 按系统时区执行推送。"
}

stop_service() {
    crontab -l 2>/dev/null | grep -Fv "$SCRIPT_PATH -cron" | crontab -
    log_cron "定时任务已移除"
    exit 0
}

main() {
    check_running

    echo "----------------------------------------------" | tee -a "$CRON_LOG" >/dev/null
    log_cron "启动 Push 通知脚本"

    if [[ "$*" == *"-cron"* ]]; then
        if ! read_config; then
            log_cron "配置不完整，跳过 cron 执行。"
            exit 1
        fi

        log_cron "cron 触发，开始发送每日报告。"
        daily_report
        exit 0
    fi

    read_config >/dev/null 2>&1 || echo "首次运行请先选择 1 配置"
    setup_cron

    while true; do
        clear
        echo -e "${BLUE}======================================${PLAIN}"
        echo -e "${PURPLE}     Push（TG / PushPlus / ntfy）管理菜单${PLAIN}"
        echo -e "${BLUE}======================================${PLAIN}"
        echo -e "${GREEN}1.${PLAIN} 修改${PURPLE}推送配置${PLAIN}"
        echo -e "${GREEN}2.${PLAIN} 发送${YELLOW}每日报告${PLAIN}"
        echo -e "${GREEN}3.${PLAIN} 发送${CYAN}测试消息${PLAIN}"
        echo -e "${RED}4.${PLAIN} 移除定时任务${PLAIN}"
        echo -e "${WHITE}0.${PLAIN} 退出${PLAIN}"
        echo -e "${BLUE}======================================${PLAIN}"
        read_input choice "请选择操作 [0-4]: "
        echo
        case "$choice" in
            1) initial_config ;;
            2) daily_report ;;
            3) test_push ;;
            4) stop_service ;;
            0) exit 0 ;;
            *) echo "无效选项，请重新输入" ;;
        esac
        read_input _ "按 Enter 返回菜单..."
    done
}

main "$@"
