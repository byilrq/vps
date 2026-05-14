#!/bin/bash
# TrafficCop 管理器 - 交互式管理工具
# 版本 1.1（合并推送：push.sh，支持 TG / PushPlus / ntfy）

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 基础目录
WORK_DIR="/root/TrafficCop"
REPO_URL="https://raw.githubusercontent.com/byilrq/vps/main/trafficcop"

# 检查root权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}此脚本必须以root权限运行${NC}"
        exit 1
    fi
}

# 创建工作目录
create_work_dir() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1
}

# 下载脚本
install_script() {
    local script_name="$1"
    echo -e "${YELLOW}正在下载 $script_name...${NC}"
    if ! curl -fsSL "$REPO_URL/$script_name" -o "$WORK_DIR/$script_name"; then
        echo -e "${RED}下载失败：$script_name${NC}"
        return 1
    fi
    chmod +x "$WORK_DIR/$script_name"
    return 0
}

# 运行脚本
run_script() {
    local script_path="$1"
    bash "$script_path"
}

show_existing_traffic_config() {
    local cfg="$WORK_DIR/traffic_config.txt"
    [ -s "$cfg" ] || return 0

    echo -e "${CYAN}检测到已有流量监控配置：${NC}$cfg"
    # 只读取 KEY=VALUE，避免配置中混入非 shell 内容。
    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$cfg" | sed 's/\r$//') 2>/dev/null || true

    echo "--------------------------------------"
    echo "接口 MAIN_INTERFACE : ${MAIN_INTERFACE:-未设置}"
    echo "统计模式 TRAFFIC_MODE : ${TRAFFIC_MODE:-未设置}  (out/in/total/max)"
    echo "统计周期 TRAFFIC_PERIOD: ${TRAFFIC_PERIOD:-未设置}  (monthly/quarterly/yearly)"
    echo "周期起始 PERIOD_START_DAY: ${PERIOD_START_DAY:-未设置}"
    echo "流量限制 TRAFFIC_LIMIT: ${TRAFFIC_LIMIT:-未设置} GB"
    echo "容错范围 TRAFFIC_TOLERANCE: ${TRAFFIC_TOLERANCE:-未设置} GB"
    echo "限制模式 LIMIT_MODE: ${LIMIT_MODE:-未设置}"
    echo "限速值 LIMIT_SPEED: ${LIMIT_SPEED:-未设置} kbit/s"
    echo "--------------------------------------"
    echo -e "${YELLOW}如果 trafficcop.sh 提示输入，直接回车通常表示保持当前/默认值。${NC}"
}

# 安装流量监控
install_monitor() {
    echo -e "${CYAN}正在安装/管理流量监控功能...${NC}"
    create_work_dir
    show_existing_traffic_config

    if [ ! -x "$WORK_DIR/trafficcop.sh" ]; then
        install_script "trafficcop.sh" || { read -p "按回车键继续..."; return; }
    else
        echo -e "${GREEN}检测到本地 trafficcop.sh，直接运行本地版本，避免覆盖已有修改。${NC}"
    fi

    run_script "$WORK_DIR/trafficcop.sh"
    echo -e "${GREEN}流量监控功能执行完毕！${NC}"
    read -p "按回车键继续..."
}

# 安装/管理推送（合并版 push.sh：TG / PushPlus / ntfy）
install_push_manager() {
    echo -e "${CYAN}正在安装/管理 推送功能（push.sh：TG / PushPlus / ntfy 合并版，按配置时间写入 cron）...${NC}"
    create_work_dir

    if [ ! -x "$WORK_DIR/push.sh" ]; then
        install_script "push.sh" || { read -p "按回车键继续..."; return; }
    else
        echo -e "${GREEN}检测到本地 push.sh，直接运行本地版本，避免从远程下载旧版覆盖。${NC}"
    fi

    run_script "$WORK_DIR/push.sh"
    echo -e "${GREEN}push.sh 执行完毕！${NC}"
    read -p "按回车键继续..."
}

# 查看当前配置
view_config() {
    echo -e "${CYAN}查看当前配置${NC}"
    echo "1) 流量监控配置（traffic_config.txt）"
    echo "2) 推送配置（push_config.txt）"
    echo "3) cron任务配置（push.sh 按配置时间直接触发）"
    echo "0) 返回主菜单"

    read -p "请选择要查看的配置类型 [0-3]: " config_choice

    case $config_choice in
        1)
            if [ -f "$WORK_DIR/traffic_config.txt" ]; then
                cat "$WORK_DIR/traffic_config.txt"
            else
                echo -e "${RED}流量监控配置不存在：$WORK_DIR/traffic_config.txt${NC}"
            fi
            ;;
        2)
            if [ -f "$WORK_DIR/push_config.txt" ]; then
                cat "$WORK_DIR/push_config.txt"
            else
                echo -e "${RED}推送配置不存在：$WORK_DIR/push_config.txt${NC}"
            fi
            ;;
        3)
            echo -e "${CYAN}当前 cron 任务列表${NC}"
            echo "--------------------------------------"
            if crontab -l >/dev/null 2>&1; then
                crontab -l | grep -E "TrafficCop|trafficcop|traffic_monitor|push\.sh|push_cron|pushplus|tg_push|tg_notifier" --color=always || echo "（未发现相关任务）"
            else
                echo -e "${RED}未找到当前用户的 crontab 任务${NC}"
            fi
            echo "--------------------------------------"
            echo ""
            echo "如需查看系统级任务，可执行："
            echo "  cat /etc/crontab"
            echo "  ls /etc/cron.d/"
            echo "  cat /var/spool/cron/root"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效的选择${NC}"
            ;;
    esac

    read -p "按回车键继续..."
}

# 停止所有服务
stop_all_services() {
    echo -e "${CYAN}正在停止所有TrafficCop服务...${NC}"

    # 停止流量监控进程
    pkill -f "trafficcop.sh" 2>/dev/null
    pkill -f "traffic_monitor.sh" 2>/dev/null
    echo "✓ 流量监控进程已停止"

    # 停止推送进程
    pkill -f "push.sh" 2>/dev/null
    pkill -f "tg_push.sh" 2>/dev/null
    pkill -f "pushplus.sh" 2>/dev/null
    echo "✓ 推送进程已停止"

    # 移除cron任务（包含 push.sh / traffic 相关，兼容旧脚本残留）
    crontab -l 2>/dev/null | grep -vE "trafficcop\.sh|traffic_monitor\.sh|push\.sh -cron|tg_push\.sh -cron|pushplus\.sh -cron|tg_notifier|pushplus_notifier" | crontab - 2>/dev/null
    echo "✓ 定时任务已清理"

    # 清除TC规则
    local interface
    interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -n "$interface" ]; then
        tc qdisc del dev "$interface" root 2>/dev/null
        echo "✓ TC限速规则已清除"
    fi

    # 取消关机计划
    shutdown -c 2>/dev/null
    echo "✓ 关机计划已取消"

    echo -e "${GREEN}所有服务已停止！${NC}"
    read -p "按回车键继续..."
}

# 更新所有脚本
update_all_scripts() {
    echo -e "${CYAN}正在更新所有脚本到最新版本...${NC}"

    # 仅更新通用脚本；push.sh 通常包含本地定制，不在这里自动覆盖
    local scripts=("trafficcop.sh" "node.sh")

    for script in "${scripts[@]}"; do
        if curl -fsSL "$REPO_URL/$script" -o "$WORK_DIR/$script.new" 2>/dev/null; then
            mv "$WORK_DIR/$script.new" "$WORK_DIR/$script"
            chmod +x "$WORK_DIR/$script"
            echo -e "${GREEN}✓ $script 已更新${NC}"
        else
            echo -e "${YELLOW}! $script 更新失败或不存在${NC}"
        fi
    done

    echo -e "${YELLOW}! push.sh 未自动更新，避免覆盖按配置时间写入 cron 的本地版本。${NC}"
    echo -e "${GREEN}脚本更新完成！${NC}"
    read -p "按回车键继续..."
}

# ============================================
# 读取当前总流量（与 trafficcop.sh 口径一致：all-time 字段 13/14/15）
# ============================================
# ============================================
# Traffic_all 扩展版：
# - 默认走 vnstat（保持原逻辑）
# - 若 push_config.txt 中 TRAFFIC_SOURCE="bwh_api"，则读取 KiwiVM API 的 data_counter
# ============================================

# --- 读取 push_config.txt（仅解析 KEY=VALUE） ---
_read_push_config_kv() {
    local push_cfg="$WORK_DIR/push_config.txt"
    [ -s "$push_cfg" ] || return 1
    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$push_cfg" | sed 's/\r$//') 2>/dev/null || return 1
    return 0
}

# --- KiwiVM API：输出 used_bytes plan_bytes next_reset ---
_get_bwh_info_bytes() {
    local endpoint="$1" veid="$2" api_key="$3"
    local json err used_bytes plan_bytes next_reset

    json=$(curl -fsS -G "$endpoint" \
        --data-urlencode "veid=$veid" \
        --data-urlencode "api_key=$api_key" 2>/dev/null) || return 1

    err=$(echo "$json" | jq -r '.error // 1' 2>/dev/null)
    [[ "$err" == "0" ]] || return 1

    used_bytes=$(echo "$json" | jq -r '.data_counter // empty' 2>/dev/null)
    plan_bytes=$(echo "$json" | jq -r '.plan_monthly_data // empty' 2>/dev/null)
    next_reset=$(echo "$json" | jq -r '.data_next_reset // empty' 2>/dev/null)

    [[ "$used_bytes" =~ ^[0-9]+$ ]] || return 1
    [[ "$plan_bytes" =~ ^[0-9]+$ ]] || plan_bytes=0
    [[ "$next_reset" =~ ^[0-9]+$ ]] || next_reset=0

    echo "$used_bytes $plan_bytes $next_reset"
    return 0
}

Traffic_all() {
    local push_cfg="$WORK_DIR/push_config.txt"

    # 1) 先看 push_config 的流量来源（缺失则默认 vnstat）
    local TRAFFIC_SOURCE="vnstat"
    local BWH_VEID="" BWH_API_KEY="" BWH_API_ENDPOINT=""
    local BWH_API_ENDPOINT_DEFAULT="https://api.64clouds.com/v1/getServiceInfo"

    if _read_push_config_kv; then
        TRAFFIC_SOURCE=${TRAFFIC_SOURCE:-vnstat}
        BWH_VEID=${BWH_VEID:-}
        BWH_API_KEY=${BWH_API_KEY:-}
        BWH_API_ENDPOINT=${BWH_API_ENDPOINT:-$BWH_API_ENDPOINT_DEFAULT}
    else
        TRAFFIC_SOURCE="vnstat"
    fi

    # 2) bwh_api 路径：不依赖 traffic_config.txt，不走 offset
    if [[ "$TRAFFIC_SOURCE" == "bwh_api" ]]; then
        if [[ -z "$BWH_VEID" || -z "$BWH_API_KEY" ]]; then
            echo -e "${RED}push_config.txt 未配置 BWH_VEID / BWH_API_KEY，无法读取 bwh_api 流量。${NC}"
            echo -e "${YELLOW}请在 push.sh 菜单 1 的“修改推送配置”中完成 bwh_api 配置后再试。${NC}"
            return 1
        fi

        local info used_bytes plan_bytes next_reset
        info=$(_get_bwh_info_bytes "$BWH_API_ENDPOINT" "$BWH_VEID" "$BWH_API_KEY") || {
            echo -e "${RED}KiwiVM API 调用失败：请检查网络、VEID/API_KEY、Endpoint。${NC}"
            return 1
        }

        used_bytes=$(echo "$info" | awk '{print $1}')
        plan_bytes=$(echo "$info" | awk '{print $2}')
        next_reset=$(echo "$info" | awk '{print $3}')

        # bytes -> GB（GiB）
        local used_gb plan_gb
        used_gb=$(awk "BEGIN{printf \"%.3f\", $used_bytes/1024/1024/1024}")
        plan_gb=$(awk "BEGIN{printf \"%.3f\", $plan_bytes/1024/1024/1024}")

        echo "$(date '+%Y-%m-%d %H:%M:%S') 流量来源: bwh_api（KiwiVM）"
        echo "$(date '+%Y-%m-%d %H:%M:%S') 当前流量使用: ${used_gb} GB"
        echo "$(date '+%Y-%m-%d %H:%M:%S') 套餐总量: ${plan_gb} GB"
        echo "$(date '+%Y-%m-%d %H:%M:%S') DEBUG: used_bytes=${used_bytes} plan_bytes=${plan_bytes} next_reset=${next_reset} veid=${BWH_VEID}"
        return 0
    fi

    # 3) vnstat 路径：保持你原来的逻辑（依赖 traffic_config.txt + offset）
    local config_file="$WORK_DIR/traffic_config.txt"
    local offset_file="$WORK_DIR/traffic_offset.dat"

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}找不到流量监控配置文件：$config_file${NC}"
        echo -e "请先运行一次 ${YELLOW}流量监控安装/配置（菜单 1）${NC}"
        return 1
    fi

    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$config_file" | sed 's/\r$//') 2>/dev/null || {
        echo -e "${RED}配置加载失败（可能包含非法行）：$config_file${NC}"
        return 1
    }

    TRAFFIC_MODE=${TRAFFIC_MODE:-total}
    TRAFFIC_PERIOD=${TRAFFIC_PERIOD:-monthly}
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}
    MAIN_INTERFACE=${MAIN_INTERFACE:-eth0}

    local offset
    offset=$(cat "$offset_file" 2>/dev/null || echo 0)
    [[ "$offset" =~ ^-?[0-9]+$ ]] || offset=0

    vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1

    local line raw_bytes rx tx
    line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>/dev/null || echo "")

    if [ -z "$line" ] || ! echo "$line" | grep -q ';'; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') vnstat 输出无效（接口：$MAIN_INTERFACE），暂按 0GB 处理。"
        raw_bytes=0
    else
        case "$TRAFFIC_MODE" in
            out)   raw_bytes=$(echo "$line" | cut -d';' -f14) ;;
            in)    raw_bytes=$(echo "$line" | cut -d';' -f13) ;;
            total) raw_bytes=$(echo "$line" | cut -d';' -f15) ;;
            max)
                rx=$(echo "$line" | cut -d';' -f13)
                tx=$(echo "$line" | cut -d';' -f14)
                rx=${rx:-0}; tx=${tx:-0}
                [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
                [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
                raw_bytes=$((rx > tx ? rx : tx))
                ;;
            *) raw_bytes=0 ;;
        esac
    fi

    [[ "$raw_bytes" =~ ^[0-9]+$ ]] || raw_bytes=0

    local real_bytes=$((raw_bytes - offset))
    [ "$real_bytes" -lt 0 ] && real_bytes=0

    local usage_gb
    usage_gb=$(echo "$real_bytes/1024/1024/1024" | bc -l 2>/dev/null)
    usage_gb=$(printf "%.3f" "${usage_gb:-0}")
    [[ "$usage_gb" == .* ]] && usage_gb="0$usage_gb"

    # 周期起始（简化版）
    local y m d period_start
    y=$(date +%Y); m=$(date +%m); d=$(date +%d)
    PERIOD_START_DAY=${PERIOD_START_DAY:-1}

    case "$TRAFFIC_PERIOD" in
        monthly)
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                period_start=$(date -d "$y-$m-$PERIOD_START_DAY -1 month" +%Y-%m-%d 2>/dev/null || \
                               date -d "$y-$m-$PERIOD_START_DAY" +%Y-%m-%d)
            else
                period_start=$(date -d "$y-$m-$PERIOD_START_DAY" +%Y-%m-%d)
            fi
            ;;
        quarterly)
            local mm qm
            mm=$((10#$m))
            qm=$(( ((mm-1)/3*3 +1) ))
            qm=$(printf "%02d" "$qm")
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                period_start=$(date -d "$y-$qm-$PERIOD_START_DAY -3 months" +%Y-%m-%d)
            else
                period_start=$(date -d "$y-$qm-$PERIOD_START_DAY" +%Y-%m-%d)
            fi
            ;;
        yearly)
            if [ "$d" -lt "$PERIOD_START_DAY" ]; then
                period_start=$(date -d "$((y-1))-01-$PERIOD_START_DAY" +%Y-%m-%d)
            else
                period_start=$(date -d "$y-01-$PERIOD_START_DAY" +%Y-%m-%d)
            fi
            ;;
        *) period_start=$(date -d "$y-$m-${PERIOD_START_DAY:-1}" +%Y-%m-%d) ;;
    esac

    echo "$(date '+%Y-%m-%d %H:%M:%S') 流量来源: vnstat（本机口径）"
    echo "$(date '+%Y-%m-%d %H:%M:%S') 当前周期: ${period_start} 起（按 $TRAFFIC_PERIOD 统计）"
    echo "$(date '+%Y-%m-%d %H:%M:%S') 统计模式: $TRAFFIC_MODE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') 当前流量使用: $usage_gb GB"
    echo "$(date '+%Y-%m-%d %H:%M:%S') DEBUG: raw_bytes(all-time)=$raw_bytes offset=$offset real_bytes=$real_bytes iface=$MAIN_INTERFACE"
}


# ======================================================
# 手动设置已用流量（管理脚本版本，口径与 trafficcop.sh 一致）
# ======================================================
flow_setting() {
    local push_cfg="$WORK_DIR/push_config.txt"
    local current_source="vnstat"
    if [ -s "$push_cfg" ]; then
        # shellcheck disable=SC1090
        source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$push_cfg" | sed 's/\r$//') 2>/dev/null || true
        current_source="${TRAFFIC_SOURCE:-vnstat}"
    fi

    if [[ "$current_source" == "bwh_api" ]]; then
        echo "当前为 bwh_api 模式，流量来自 KiwiVM 面板，不需要 vnstat offset 补偿。"
        echo "如需改回本机 vnstat 口径，请到菜单 2 → 修改推送配置 → 流量来源 选择 vnstat。"
        return 0
    fi

    echo "================ 手动修正本周期流量 ================"
    echo "用于在运行一段时间后，调整当前周期已用流量（比如对齐运营商面板）。"
    echo "注意：这里输入的是【本周期应当已经使用的总量】，不是要增加的差值。"
    echo "===================================================="
    echo
    echo "请输入当前本周期实际已使用流量(GB)："
    read -r real_gb

    if ! [[ "$real_gb" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "输入无效，请输入数字，例如 30 或 12.5"
        return 1
    fi

    local config_file="$WORK_DIR/traffic_config.txt"
    local offset_file="$WORK_DIR/traffic_offset.dat"
    local log_file="$WORK_DIR/traffic.log"

    if [ ! -f "$config_file" ]; then
        echo "错误：找不到配置文件 $config_file，请先在菜单[1]完成流量监控安装/配置。"
        return 1
    fi

    # shellcheck disable=SC1090
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$config_file" | sed 's/\r$//') 2>/dev/null || {
        echo "错误：配置加载失败（可能包含非法行）：$config_file"
        return 1
    }

    TRAFFIC_MODE=${TRAFFIC_MODE:-total}
    MAIN_INTERFACE=${MAIN_INTERFACE:-eth0}

    if [ -z "$MAIN_INTERFACE" ] || [ -z "$TRAFFIC_MODE" ]; then
        echo "错误：未能获取 MAIN_INTERFACE / TRAFFIC_MODE，请先在菜单[1]完成配置。"
        return 1
    fi

    vnstat -u -i "$MAIN_INTERFACE" >/dev/null 2>&1

    local line raw_bytes rx tx target_bytes new_offset
    line=$(vnstat -i "$MAIN_INTERFACE" --oneline b 2>&1 || echo "")

    if echo "$line" | grep -qiE "Not enough data available yet|No data\. Timestamp of last update is same"; then
        raw_bytes=0
    else
        if [ -z "$line" ] || ! echo "$line" | grep -q ';'; then
            echo "vnstat 输出无效，无法计算 raw_bytes：$line"
            echo "$(date '+%Y-%m-%d %H:%M:%S') flow_setting：vnstat 输出无效($line)，放弃修改 OFFSET_FILE" | tee -a "$log_file"
            return 1
        fi

        raw_bytes=0
        case "$TRAFFIC_MODE" in
            out)   raw_bytes=$(echo "$line" | cut -d';' -f14) ;;
            in)    raw_bytes=$(echo "$line" | cut -d';' -f13) ;;
            total) raw_bytes=$(echo "$line" | cut -d';' -f15) ;;
            max)
                rx=$(echo "$line" | cut -d';' -f13)
                tx=$(echo "$line" | cut -d';' -f14)
                rx=${rx:-0}; tx=${tx:-0}
                [[ "$rx" =~ ^[0-9]+$ ]] || rx=0
                [[ "$tx" =~ ^[0-9]+$ ]] || tx=0
                raw_bytes=$((rx > tx ? rx : tx))
                ;;
            *) raw_bytes=$(echo "$line" | cut -d';' -f15) ;;
        esac
    fi

    raw_bytes=${raw_bytes:-0}
    if ! [[ "$raw_bytes" =~ ^[0-9]+$ ]]; then
        echo "vnstat 返回的累计流量不是纯数字(raw_bytes=$raw_bytes)，放弃修改。"
        echo "$(date '+%Y-%m-%d %H:%M:%S') flow_setting：raw_bytes 异常($raw_bytes)，放弃修改 OFFSET_FILE" | tee -a "$log_file"
        return 1
    fi

    target_bytes=$(echo "$real_gb * 1024 * 1024 * 1024" | bc 2>/dev/null | cut -d'.' -f1)
    target_bytes=${target_bytes:-0}
    [[ "$target_bytes" =~ ^[0-9]+$ ]] || target_bytes=0

    new_offset=$((raw_bytes - target_bytes))
    echo "$new_offset" > "$offset_file"

    echo "--------------------------------------"
    echo "当前累计流量 raw_bytes(all-time): $raw_bytes bytes"
    echo "设定本周期使用量            : $real_gb GB"
    echo "目标字节 target_bytes        : $target_bytes bytes"
    echo "新的 offset                 : $new_offset"
    echo "（后续统计：已用 = 当前累计 - offset，将从 ${real_gb}GB 附近开始往上增长）"
    echo "--------------------------------------"
    echo "$(date '+%Y-%m-%d %H:%M:%S') flow_setting：手动设置 OFFSET_FILE=$new_offset（对应本周期已用 $real_gb GB）" | tee -a "$log_file"
    return 0
}


# ======================================================
# 安装 / 管理 node 监控通知
# ======================================================
install_node() {
    echo -e "${CYAN}正在安装 node 监控脚本...${NC}"

    local file="node.sh"
    local url="$REPO_URL/$file"
    local dest="$WORK_DIR/$file"

    echo -e "${BLUE}➡ 下载 node.sh ...${NC}"
    if ! curl -fsSL "$url" -o "$dest"; then
        echo -e "${RED}❌ 下载失败，请检查网络或 GitHub 链接。${NC}"
        read -p "按回车继续..."
        return
    fi

    chmod +x "$dest"
    echo -e "${GREEN}✔ node.sh 安装完成${NC}"

    echo -e "${CYAN}➡ 运行 node 配置管理...${NC}"
    bash "$dest"

    echo -e "${GREEN}✔ node 监控功能已启动！${NC}"
    read -p "按回车继续..."
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}        TrafficCop 管理工具              ${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${PURPLE}====================================${NC}"
    echo ""
    echo -e "${YELLOW}1) 安装/管理流量监控${NC}"
    echo -e "${YELLOW}2) 安装/管理推送通知${NC}"
    echo -e "${YELLOW}3) 查看配置${NC}"
    echo -e "${YELLOW}4) 实时流量${NC}"
    echo -e "${YELLOW}5) 补偿流量${NC}"
    echo -e "${RED}6) 停止服务${NC}"
    echo -e "${BLUE}7) 更新脚本${NC}"
    echo -e "${YELLOW}0) 退出${NC}"
    echo -e "${PURPLE}====================================${NC}"
    echo ""
}

# 主函数
main() {
    check_root
    create_work_dir

    while true; do
        show_main_menu
        read -p "请选择操作 [0-7]: " choice

        case $choice in
            1)
                install_monitor
                ;;
            2)
                install_push_manager
                ;;
            3)
                view_config
                ;;
            4)
                Traffic_all
                read -p "按回车键继续..."
                ;;
            5)
                flow_setting
                read -p "按回车键继续..."
                ;;
            6)
                stop_all_services
                ;;
            7)
                update_all_scripts
                ;;
            0)
                echo -e "${GREEN}感谢使用TrafficCop管理工具！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入${NC}"
                sleep 1
                ;;
        esac
    done
}

# 启动主程序
main "$@"
