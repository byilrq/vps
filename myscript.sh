#!/bin/bash

# ---------- 0. 权限与系统检测 (最优先执行) ----------
# 必须先确保是 Root 用户和支持的系统，否则后续安装依赖会报错

if [ "$(id -u)" != "0" ]; then
  echo -e "\033[31m[×] 错误：此脚本必须以 root 权限运行\033[0m"
  exit 1
fi
# ---------- 修复对齐问题  ----------
# 强制使用 UTF-8 环境，确保脚本将中文字符识别为单个字符而不是多个字节
# 解决在部分 LANG=C 的最小化 VPS 上，中文字符宽度计算错误导致无法对齐的问题
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# 检测是否为 Debian/Ubuntu 系系统
if [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
  echo -e "\033[31m[×] 错误：本脚本基于 apt/dpkg 包管理，仅支持 Debian/Ubuntu 系列系统。\033[0m"
  echo -e "\033[33m检测到当前可能为 CentOS/RedHat/AlmaLinux，请勿运行以免损坏系统。\033[0m"
  exit 1
fi

# ---------- 配色定义 ----------
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'
GRAY='\033[90m'

# ---------- [新增] Ctrl+C 信号捕获与跳过暂停 ----------
# 定义全局变量
SKIP_PAUSE=false
CTRL_C_PRESSED=false

trap_ctrl_c() {
  echo -e "\n${YELLOW}[!] 用户触发中断 (Ctrl+C)，正在返回主菜单...${RESET}"
  SKIP_PAUSE=true
  CTRL_C_PRESSED=true
  # 这里不 exit，而是让当前执行的命令中断后，通过检测变量状态退出特定循环
}
trap trap_ctrl_c SIGINT

# ---------- [新增] APT 锁检测函数 (修复死循环版) ----------
check_apt_lock() {
  # 检测三个常见的锁文件
  local lock_files=("/var/lib/dpkg/lock" "/var/lib/dpkg/lock-frontend" "/var/lib/apt/lists/lock")
  local locked=false
  local pids=""

  # 检查是否有锁
  for lock in "${lock_files[@]}"; do
    if fuser "$lock" >/dev/null 2>&1; then
      locked=true
      # 获取占用进程PID
      local pid
      pid=$(fuser "$lock" 2>/dev/null | awk '{print $1}')
      pids="$pids $pid"
    fi
  done

  if [ "$locked" = true ]; then
    echo -e "${RED}[!] 检测到 APT/DPKG 锁被占用 (PID: $pids)${RESET}"
    echo -e "${YELLOW}可能有系统自动更新正在后台运行。${RESET}"
    echo -e "请选择操作："
    echo -e "  1. 等待锁释放 (推荐)"
    echo -e "  2. 强制杀掉占用进程 (可能导致数据库损坏)"
    echo -e "  3. 取消当前操作"

    read -p "请输入选项 [1-3]: " lock_choice
    case $lock_choice in
    1)
      echo -e "${CYAN}>>> 正在等待锁释放 (按 Ctrl+C 可取消)...${RESET}"
      # 重置中断标记，防止之前的 Ctrl+C 影响本次等待
      CTRL_C_PRESSED=false

      while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        # 核心修复：如果在等待期间按了 Ctrl+C，则跳出循环并返回失败
        if [ "$CTRL_C_PRESSED" = true ]; then
          echo -e "\n${YELLOW}>>> 用户取消等待，操作终止。${RESET}"
          return 1
        fi

        echo -n "."
        sleep 2
      done

      # 如果是因为 Ctrl+C 退出循环的，这里需要再次确认（虽然上面 return 1 已经处理，双重保险）
      if [ "$CTRL_C_PRESSED" = true ]; then return 1; fi

      echo -e "\n${GREEN}[√] 锁已释放${RESET}"
      ;;
    2)
      echo -e "${RED}>>> 正在强制终止占用进程...${RESET}"
      for pid in $pids; do
        kill -9 "$pid" 2>/dev/null
      done
      # 清理锁文件
      rm -f /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock
      dpkg --configure -a >/dev/null 2>&1 # 尝试修复
      echo -e "${GREEN}[√] 已强制解锁${RESET}"
      ;;
    *)
      echo -e "${YELLOW}操作已取消${RESET}"
      return 1
      ;;
    esac
  fi
  return 0
}

# ---------- 1. 基础依赖检查 ----------
check_dependencies() {
  # A. 定义需要检测的【命令】列表
  local commands=("curl" "wget" "grep" "awk" "sed" "ip" "ss" "lsof")
  local install_needed=false
  local missing_cmds=""

  # 检查命令是否存在
  for cmd in "${commands[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      install_needed=true
      missing_cmds="$missing_cmds $cmd"
    fi
  done

  if [ "$install_needed" = true ]; then
    echo -e "\033[36m>>> 检测到缺失工具 ($missing_cmds)，正在安装...\033[0m"
    check_apt_lock || exit 1

    apt-get update -y

    local packages=("curl" "wget" "grep" "gawk" "sed" "iproute2" "lsof")

    export DEBIAN_FRONTEND=noninteractive
    # 安装正确的软件包列表
    apt-get install -y "${packages[@]}"

    # C. 二次验证 (依然检查命令)
    for cmd in "${commands[@]}"; do
      if ! command -v "$cmd" &>/dev/null; then
        echo -e "\033[31m[×] 错误：命令 $cmd 依然无法找到。\033[0m"
        echo -e "\033[33m可能软件包安装失败，请手动执行: apt-get install -y iproute2 gawk lsof curl wget\033[0m"
        exit 1
      fi
    done
    echo -e "\033[32m[√] 依赖安装完成\033[0m"
  fi
}

check_dependencies

# ---------- 2. Trap 自动清理机制 ----------
# 创建一个专属的临时目录，所有临时文件都放在这里
TEMP_DIR=$(mktemp -d)
# 定义缓存文件路径
CACHE_FILE="${TEMP_DIR}/sys_info_cache"

# 定义清理函数
on_exit() {
  # 确保变量不为空且目录确实存在
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}

# 捕获 EXIT 信号 (包括正常退出、错误退出)
# 注意：Ctrl+C(SIGINT) 由上面的 trap_ctrl_c 处理
trap on_exit EXIT

# ---------- 配置变量 (放到依赖检查之后) ----------
# 此时 curl 已确保安装
COUNT=$(curl -s --connect-timeout 2 https://sh.cici.one/count.php 2>/dev/null || echo "N/A")
SCRIPT_URL="bash <(curl -sL sh.cici.one)"

# ---------- 基础函数 ----------
get_debian_version() {
  [ -f /etc/debian_version ] && cat /etc/debian_version || echo "0"
}

get_debian_major_version() {
  [ -f /etc/debian_version ] && cut -d'.' -f1 </etc/debian_version || echo "0"
}

# ---------- 信息显示函数 ----------
display_info() {
  local title="$1"
  local items=("${@:2}")

  echo -e "${BOLD}${CYAN}${title}${RESET}"

  # ---- 计算最长标签显示宽度（中文=2宽度，英文=1宽度）----
  local max_label_width=0
  for item in "${items[@]}"; do
    IFS='|' read -r label _ <<<"$item"
    # 去除颜色码
    local clean_label
    clean_label=$(echo -e "$label" | sed -E "s/\x1B\[[0-9;]*[mK]//g")
    # 计算宽度（中文算2）
    local width=0
    for ((i = 0; i < ${#clean_label}; i++)); do
      local c="${clean_label:i:1}"
      [[ "$c" =~ [\x00-\x7F] ]] && ((width += 1)) || ((width += 2))
    done
    ((width > max_label_width)) && max_label_width=$width
  done

  # ---- 输出对齐 ----
  for item in "${items[@]}"; do
    IFS='|' read -r label value <<<"$item"

    # 去除颜色计算实际宽度
    local clean_label
    clean_label=$(echo -e "$label" | sed -E "s/\x1B\[[0-9;]*[mK]//g")
    local width=0
    for ((i = 0; i < ${#clean_label}; i++)); do
      local c="${clean_label:i:1}"
      [[ "$c" =~ [\x00-\x7F] ]] && ((width += 1)) || ((width += 2))
    done

    local padding=$((max_label_width - width))
    local spaces=""
    for ((i = 0; i < padding; i++)); do
      spaces+=" "
    done

    echo -e "  ${YELLOW}${label}:${RESET}${spaces} ${value}"
  done
  echo -e "${CYAN}--------------------------------------------------${RESET}"
}

# ---------- 虚拟化检测函数 ----------
detect_virtualization() {
  local virt_type="未知"
  # 检测容器环境
  if [ -f /.dockerenv ]; then
    virt_type="Docker容器"
  elif grep -q "docker" /proc/1/cgroup 2>/dev/null; then
    virt_type="Docker容器"
  elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
    virt_type="LXC容器"
  elif command -v systemd-detect-virt >/dev/null 2>&1; then
    local sdv
    sdv=$(systemd-detect-virt 2>/dev/null || echo "none")
    case $sdv in
    kvm) virt_type="KVM虚拟机" ;;
    qemu) virt_type="QEMU虚拟机" ;;
    vmware) virt_type="VMware虚拟机" ;;
    microsoft) virt_type="Hyper-V虚拟机" ;;
    oracle) virt_type="VirtualBox虚拟机" ;;
    xen) virt_type="Xen虚拟机" ;;
    lxc | lxc-libvirt) virt_type="LXC容器" ;;
    docker) virt_type="Docker容器" ;;
    podman) virt_type="Podman容器" ;;
    none) virt_type="物理机/未知" ;;
    *) virt_type="$sdv" ;;
    esac
  elif [ -f /proc/cpuinfo ] && grep -q "hypervisor" /proc/cpuinfo; then
    virt_type="虚拟化环境"
  elif command -v dmidecode >/dev/null 2>&1; then
    local bios_vendor
    bios_vendor=$(dmidecode -s system-manufacturer 2>/dev/null | head -1)
    case $bios_vendor in
    *[Vv][Mm][Ww]are*) virt_type="VMware虚拟机" ;;
    *[Qq][Ee][Mm][Uu]*) virt_type="QEMU虚拟机" ;;
    *[Mm]icrosoft*) virt_type="Hyper-V虚拟机" ;;
    *[Oo]racle*) virt_type="VirtualBox虚拟机" ;;
    *[Xx]en*) virt_type="Xen虚拟机" ;;
    *[Kk][Vv][Mm]*) virt_type="KVM虚拟机" ;;
    esac
  fi

  echo "$virt_type"
}

# ---------- 并行执行函数 ----------
run_parallel() {
  local funcs=("$@")
  local pids=()
  local outfiles=()

  for i in "${!funcs[@]}"; do
    outfiles[$i]="${TEMP_DIR}/parallel_result_$i"
    ${funcs[$i]} >"${outfiles[$i]}" 2>/dev/null &
    pids[$i]=$!
  done

  # 等待并读结果
  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" 2>/dev/null
  done

  for i in "${!outfiles[@]}"; do
    if [ -f "${outfiles[$i]}" ]; then
      cat "${outfiles[$i]}"
      rm -f "${outfiles[$i]}"
    fi
  done
}

# ---------- 网络检测函数（用于并行执行） ----------
get_ipv4_public() {
  curl -s -4 --connect-timeout 2 ifconfig.co 2>/dev/null || echo "N/A"
}

get_ipv6_public() {
  curl -s -6 --connect-timeout 2 ifconfig.co 2>/dev/null || echo "N/A"
}

get_isp_info() {
  local ip=$1
  if [ -n "$ip" ] && [ "$ip" != "N/A" ]; then
    curl -s -4 --connect-timeout 2 "ipinfo.io/$ip/org" 2>/dev/null | head -1 || echo "未知"
  else
    echo "未知"
  fi
}

get_location_info() {
  local ip=$1
  if [ -n "$ip" ] && [ "$ip" != "N/A" ]; then
    local city country
    city=$(curl -s -4 --connect-timeout 2 "ipinfo.io/$ip/city" 2>/dev/null || echo "未知")
    country=$(curl -s -4 --connect-timeout 2 "ipinfo.io/$ip/country" 2>/dev/null || echo "未知")
    echo "$city, $country"
  else
    echo "未知"
  fi
}

# ---------- 系统信息显示 (优化版: 增加静态信息缓存) ----------
display_system_info() {
  clear
  echo -e "${BOLD}${CYAN}"
  echo "=================================================="
  echo "             🚀 极光VPS系统管理工具"
  echo "=================================================="
  echo -e "${RESET}${CYAN}作者: FMSO ${YELLOW}|${CYAN} 版本: v2025-11-27 ${YELLOW}|${CYAN} 调用: ${COUNT}次"
  echo -e "地址: ${SCRIPT_URL}"
  echo -e "==================================================${RESET}"

  # 1. 缓存文件定义
  # 注意: CACHE_FILE 在脚本开头定义，这里直接使用
  # 我们增加一个专门存储硬件静态信息的缓存，避免每次都 grep cpuinfo
  local HW_CACHE="${TEMP_DIR}/hardware_cache"

  local CACHE_HIT=false
  if [ -f "$CACHE_FILE" ]; then
    source "$CACHE_FILE"
    CACHE_HIT=true
  else
    echo -e "${CYAN}正在初始化系统信息 (首次运行需检测网络)...${RESET}"
  fi

  # 2. 网络信息获取逻辑 (如果无缓存则获取并写入)
  if [ "$CACHE_HIT" = false ]; then
    tmp4="${TEMP_DIR}/get_ipv4"
    tmp6="${TEMP_DIR}/get_ipv6"
    get_ipv4_public >"$tmp4" 2>/dev/null &
    pid4=$!
    get_ipv6_public >"$tmp6" 2>/dev/null &
    pid6=$!
  fi

  # 3. 获取静态系统信息 (优先读取硬件缓存)
  if [ -f "$HW_CACHE" ]; then
    source "$HW_CACHE"
  else
    # 动态获取并生成缓存
    if command -v lsb_release >/dev/null 2>&1; then
      os_name=$(lsb_release -d | cut -f2-)
    else
      os_name=$(grep "PRETTY_NAME" /etc/os-release | cut -d'"' -f2 2>/dev/null || uname -s)
    fi

    sys_ver=$(get_debian_version)
    kernel_ver=$(uname -r)
    arch_info=$(uname -m)
    virt_type=$(detect_virtualization)
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs || echo "未知")
    cpu_count=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "1")

    # 写入硬件缓存
    cat >"$HW_CACHE" <<EOF
os_name="$os_name"
sys_ver="$sys_ver"
kernel_ver="$kernel_ver"
arch_info="$arch_info"
virt_type="$virt_type"
cpu_model="$cpu_model"
cpu_count="$cpu_count"
EOF
  fi

  # 动态信息 (必须实时获取)
  if uptime -p >/dev/null 2>&1; then
    uptime_info=$(uptime -p | sed 's/up //')
  else
    uptime_info=$(uptime | sed -E 's/^.* up +//; s/, *[0-9]+ users.*//; s/, *load average.*//')
  fi
  boot_time=$(who -b | awk '{print $3 " " $4}')
  load_info=$(uptime | awk -F'load average:' '{print $2}' | xargs)
  current_user=$(whoami)
  hostname_info=$(hostname)

  system_items=(
    "操作系统|$os_name"
    "系统版本|$sys_ver"
    "内核版本|$kernel_ver"
    "系统架构|$arch_info"
    "虚拟化类型|$virt_type"
    "登录用户|$current_user"
    "主机名|$hostname_info"
    "运行时间|$uptime_info"
    "启动时间|$boot_time"
    "系统负载|$load_info"
  )
  display_info "🖥️ 系统信息" "${system_items[@]}"

  # ---------- CPU 信息获取逻辑 (极速响应版 + 完整Steal功能) ----------
  # 优化原理：首次运行微小延迟初始化，后续刷新直接对比上一次的数据，实现 0 延迟。

  # 1. 定义读取 CPU 统计的函数
  get_cpu_stat() {
    local line
    read -r line </proc/stat
    # 格式: cpu user nice system idle iowait irq softirq steal guest guest_nice
    # [修复]: awk 中 system 是保留关键字，改为 sys
    echo "$line" | awk '{
      us=$2; ni=$3; sys=$4; id=$5; wa=$6; hi=$7; si=$8; st=$9; gu=$10; gn=$11;

      # 容错处理：如果 guest 为空则设为 0
      if(gu=="") gu=0; if(gn=="") gn=0;

      # 计算总 tick
      total = us + ni + sys + id + wa + hi + si + st + gu + gn;
      idle_sum = id + wa;
      print total, idle_sum, st
    }'
  }

  # 2. 获取当前时刻 CPU 状态
  read -r cur_total cur_idle cur_steal <<<$(get_cpu_stat)

  # 3. 判断是否有上一次的缓存数据
  if [ -z "$PREV_CPU_TOTAL" ]; then
    # [首次运行]：由于没有历史数据，为了避免显示 N/A，进行一次极短的采样 (0.1s)
    sleep 0.1
    read -r next_total next_idle next_steal <<<$(get_cpu_stat)

    # 计算差值
    diff_total=$((next_total - cur_total))
    diff_idle=$((next_idle - cur_idle))
    diff_steal=$((next_steal - cur_steal))

    # 更新“当前”为刚才采样的“下一刻”，以便保存到缓存
    cur_total=$next_total
    cur_idle=$next_idle
    cur_steal=$next_steal
  else
    # [后续刷新]：直接对比“当前”与“上一次菜单显示时”的数据
    diff_total=$((cur_total - PREV_CPU_TOTAL))
    diff_idle=$((cur_idle - PREV_CPU_IDLE))
    diff_steal=$((cur_steal - PREV_CPU_STEAL))
  fi

  # 4. 保存当前状态到全局变量（供下一次对比使用）
  PREV_CPU_TOTAL=$cur_total
  PREV_CPU_IDLE=$cur_idle
  PREV_CPU_STEAL=$cur_steal

  # 5. 计算百分比 (防止分母为 0)
  if [ "$diff_total" -gt 0 ]; then
    # 使用 awk 进行浮点运算
    cpu_usage=$(awk -v i="$diff_idle" -v t="$diff_total" 'BEGIN {printf "%.1f%%", 100 - (i/t)*100}')
    cpu_st=$(awk -v s="$diff_steal" -v t="$diff_total" 'BEGIN {printf "%.1f", (s/t)*100}')
  else
    cpu_usage="0.0%"
    cpu_st="0.0"
  fi

  # 6. Steal 状态高亮 (保留原有逻辑)
  st_int=$(echo "$cpu_st" | awk -F. '{print $1}')
  if [ "$st_int" -ge 10 ]; then
    st_display="${RED}${cpu_st}% (严重抢占)${RESET}"
  elif [ "$st_int" -gt 0 ]; then
    st_display="${YELLOW}${cpu_st}% (轻微争抢)${RESET}"
  else
    st_display="${GREEN}${cpu_st}% (良好)${RESET}"
  fi
  # --------------------------------------------

  mem_info=$(free -h | awk '/Mem:/ {print $2, $3}' 2>/dev/null)
  mem_total=$(echo $mem_info | awk '{print $1}')
  mem_used=$(echo $mem_info | awk '{print $2}')
  mem_percent=$(free 2>/dev/null | awk '/Mem:/ {used=$3; total=$2; if(total>0) printf "%.1f%%", used/total*100}')

  swap_info=$(free -h | awk '/Swap:/ {print $2, $3}' 2>/dev/null)
  swap_total=$(echo $swap_info | awk '{print $1}')
  swap_used=$(echo $swap_info | awk '{print $2}')
  if [ -z "$swap_total" ] || [ "$swap_total" = "0B" ]; then
    swap_display="${RED}未检测到SWAP分区${RESET}"
  else
    swap_percent=$(free 2>/dev/null | awk '/Swap:/ {used=$3; total=$2; if(total>0) printf "%.1f%%", used/total*100}')
    swap_display="$swap_used / $swap_total ($swap_percent)"
  fi

  hardware_items=(
    "CPU型号|$cpu_model"
    "CPU核心|${cpu_count} 核心"
    "CPU使用率|$cpu_usage"
    "CPU窃取|$st_display"
    "内存使用|$mem_used / $mem_total ($mem_percent)"
    "SWAP使用|$swap_display"
  )
  display_info "⚙️ 硬件资源" "${hardware_items[@]}"

  # 4. 处理网络请求结果 (仅无缓存时)
  if [ "$CACHE_HIT" = false ]; then
    wait $pid4 2>/dev/null
    wait $pid6 2>/dev/null
    ipv4_public=$(cat "$tmp4" 2>/dev/null || echo "N/A")
    ipv6_public=$(cat "$tmp6" 2>/dev/null || echo "N/A")

    # 并行获取 ISP / 位置信息
    tmp_isp="${TEMP_DIR}/isp"
    tmp_loc="${TEMP_DIR}/loc"
    get_isp_info "$ipv4_public" >"$tmp_isp" 2>/dev/null &
    pid_isp=$!
    get_location_info "$ipv4_public" >"$tmp_loc" 2>/dev/null &
    pid_loc=$!
  fi

  ipv4_local=$(hostname -I 2>/dev/null | awk '{print $1}')
  ipv6_local=$(ip -6 addr show 2>/dev/null | grep -oP 'inet6 \K[^\s/]+' | grep -v '^::1$' | head -1)

  current_time=$(date '+%Y-%m-%d %H:%M:%S')
  timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || date '+%Z')

  # 优化默认网卡获取逻辑
  default_interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
  if [ -n "$default_interface" ]; then
    mac_address=$(ip link show "$default_interface" 2>/dev/null | awk '/link\/ether/ {print $2; exit}' || echo "未知")
    rx=$(cat /sys/class/net/"$default_interface"/statistics/rx_bytes 2>/dev/null || echo 0)
    tx=$(cat /sys/class/net/"$default_interface"/statistics/tx_bytes 2>/dev/null || echo 0)
    rx_h=$(awk -v b=$rx 'BEGIN{printf "%.2f GB", b/1024/1024/1024}')
    tx_h=$(awk -v b=$tx 'BEGIN{printf "%.2f GB", b/1024/1024/1024}')
  else
    default_interface="未知"
    mac_address="未知"
    rx_h="0 GB"
    tx_h="0 GB"
  fi

  # 5. 获取 ISP/Loc 结果并写入缓存
  if [ "$CACHE_HIT" = false ]; then
    wait $pid_isp 2>/dev/null
    wait $pid_loc 2>/dev/null
    isp_info=$(cat "$tmp_isp" 2>/dev/null || echo "未知")
    location_info=$(cat "$tmp_loc" 2>/dev/null || echo "未知")

    # 写入网络信息缓存
    cat >"$CACHE_FILE" <<EOF
ipv4_public="$ipv4_public"
ipv6_public="$ipv6_public"
isp_info="$isp_info"
location_info="$location_info"
EOF
  fi

  # DNS 信息
  dns_servers=$(grep -oP 'nameserver\s+\K\S+' /etc/resolv.conf 2>/dev/null | head -3 | tr '\n' ',' | sed 's/,$//')
  if [ -z "$dns_servers" ]; then dns_servers="未配置"; fi

  # 处理 IP 显示
  display_ipv4_pub=$ipv4_public
  display_ipv6_pub=$ipv6_public
  [ "$ipv4_public" = "N/A" ] && display_ipv4_pub=$(echo -e "${RED}❌ 无法获取${RESET}")
  [ "$ipv6_public" = "N/A" ] && display_ipv6_pub=$(echo -e "${RED}❌ 无法获取${RESET}")

  network_items=(
    "运营商|$isp_info"
    "地理位置|$location_info"
    "系统时间|$current_time"
    "时区信息|$timezone"
    "默认网卡|${default_interface:-未知}"
    "MAC地址|$mac_address"
    "公网IPv4|$display_ipv4_pub"
    "内网IPv4|${ipv4_local:-未检测到}"
    "公网IPv6|$display_ipv6_pub"
    "内网IPv6|${ipv6_local:-未检测到}"
    "DNS服务器|$dns_servers"
    "入站流量|$rx_h"
    "出站流量|$tx_h"
  )
  display_info "🌐 网络信息" "${network_items[@]}"
  echo -e "${CYAN}--------------------------------------------------${RESET}"

  # 磁盘信息
  echo -e "${BOLD}${CYAN}💽 磁盘使用情况${RESET}"
  df -h 2>/dev/null | grep -vE 'tmpfs|udev' | awk 'NR==1{printf "  %-18s %-8s %-8s %-8s %-10s\n", $1, $2, $3, $4, $6}
    NR>1{printf "  %-18s %-8s %-8s %-8s %-10s\n", $1, $2, $3, $4, $6}'
  echo -e "${CYAN}--------------------------------------------------${RESET}"

  # 服务状态 (保持原有逻辑)
  echo -e "${BOLD}${CYAN}🔧 系统服务状态${RESET}"
  services=("ssh" "nginx" "apache2" "mysql" "mariadb" "docker" "ufw" "fail2ban")
  for service in "${services[@]}"; do
    if systemctl list-unit-files --type=service 2>/dev/null | grep -qE "^${service}"; then
      status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")

      if [ "$service" == "ufw" ]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
          status="active"
        else
          status="inactive"
        fi
      fi

      version_info=""
      case $service in
      ssh) version=$(ssh -V 2>&1 | awk '{print $1}' | sed 's/^OpenSSH_//') ;;
      nginx) version=$(nginx -v 2>&1 | awk -F'/' '{print $2}' | awk '{print $1}') ;;
      apache2) version=$(apache2ctl -v 2>&1 | grep 'Server version' | awk -F'/' '{print $2}' | awk '{print $1}') ;;
      mysql) version=$(mysql --version 2>&1 | awk '{print $5}' | sed 's/,//') ;;
      mariadb) version=$(mariadb --version 2>&1 | awk '{print $5}' | sed 's/,//') ;;
      docker) version=$(docker --version 2>&1 | awk '{print $3}' | sed 's/,//') ;;
      ufw) version=$(ufw --version 2>&1 | awk '{print $2}') ;;
      fail2ban) version=$(fail2ban-client --version 2>&1 | awk '{print $3}') ;;
      *) version="N/A" ;;
      esac
      version=$(echo "$version" | tr -d '\n')
      version_info="(v$version)"

      if [ "$status" = "active" ]; then
        port_info=""
        if [ "$service" = "ssh" ]; then
          CURRENT_PORT=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
          CURRENT_PORT=${CURRENT_PORT:-22}
          port_info="(端口: ${CURRENT_PORT})"
        fi
        printf "  ${GREEN}✅ %-10s${RESET} ${GREEN}%s${RESET}\n" "$service:" "运行中 $version_info $port_info"
      else
        printf "  ${YELLOW}⚠️  %-10s${RESET} %s\n" "$service:" "已启用但未运行 $version_info"
      fi
    else
      printf "  ${GRAY}🔘 %-10s${RESET} %s\n" "$service:" "未启用/未安装"
    fi
  done
  echo -e "${CYAN}--------------------------------------------------${RESET}"

  # BBR状态
  bbr_status="未启用"
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    bbr_status="已启用"
  fi
  if lsmod | grep -q bbr; then
    bbr_status="$bbr_status（模块已加载）"
  else
    bbr_status="$bbr_status（模块未加载）"
  fi
  qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk -F'= ' '{print $2}')
  acceleration_items=("BBR状态|$bbr_status" "BBR调度算法|${qdisc:-未设置}")
  display_info "🚀 网络加速状态" "${acceleration_items[@]}"

  echo -e "${BOLD}${CYAN}==================================================${RESET}\n"
}

# ---------- 菜单 ----------
show_menu() {
  display_system_info
  echo -e "${BOLD}${GREEN}🧭 系统管理工具菜单${RESET}"
  echo -e "${CYAN}==================================================${RESET}"
  echo -e "${YELLOW}  1.${RESET} 系统升级与缓存清理"
  echo -e "${YELLOW}  2.${RESET} 开启 BBR 加速"
  echo -e "${YELLOW}  3.${RESET} 开启 Swap 交换文件"
  echo -e "${YELLOW}  4.${RESET} 清理多余内核"
  echo -e "${YELLOW}  5.${RESET} SSH端口号检测和修改"
  echo -e "${YELLOW}  6.${RESET} DNS检测和修改"
  echo -e "${YELLOW}  7.${RESET} IPv6 开启与关闭"
  echo -e "${YELLOW}  8.${RESET} 常用软件安装 (Docker/面板)"
  echo -e "${YELLOW}  9.${RESET} 流媒体解锁测试"
  echo -e "${YELLOW} 10.${RESET} 网络质量测试"
  echo -e "${YELLOW} 11.${RESET} 融合怪全面测试"
  echo -e "${YELLOW} 12.${RESET} 服务器性能测试"
  echo -e "${YELLOW} 13.${RESET} 系统清理"
  echo -e "${YELLOW} 14.${RESET} Fail2Ban 防爆破管理"
  echo -e "${YELLOW} 15.${RESET} 防火墙管理 (UFW)"
  echo -e "${YELLOW} 16.${RESET} 系统时区设置"
  echo -e "${YELLOW} 17.${RESET} 端口占用情况速查"
  echo -e "${YELLOW} 18.${RESET} 计划任务管理 (Crontab)"
  echo -e "${YELLOW} 19.${RESET} 修改主机名 (Hostname)"
  echo -e "${YELLOW}  0.${RESET} 退出脚本"
  echo -e "${CYAN}==================================================${RESET}"
}

# ---------- 通用依赖安装 (整合APT锁检测) ----------
install_deps() {
  for dep in "$@"; do
    if ! command -v "$dep" &>/dev/null; then
      echo -e "${BLUE}[→] 安装依赖: ${dep}${RESET}"
      check_apt_lock || return 1
      apt install -y "$dep" >/dev/null 2>&1
    fi
  done
}

# ---------- 通用清理 ----------
cleanup() {
  [ -d "$1" ] && rm -rf "$1" && echo -e "${GREEN}[√] 清理临时目录: $1${RESET}"
}

# ---------- UFW 防火墙管理 (深度修复: 状态全显 + 禁Ping智能兜底 + 交互优化) ----------
manage_ufw() {
  # [辅助] 检测安装
  check_ufw_installed() {
    if ! command -v ufw >/dev/null 2>&1; then return 1; else return 0; fi
  }

  # [辅助] 获取真实 SSH 端口
  get_actual_ssh_port() {
    local port=""
    local pid=$(pidof sshd | awk '{print $1}')
    if [ -n "$pid" ]; then
      port=$(ss -tlnp | grep "pid=$pid," | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
    fi
    if [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; then
      port=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    fi
    echo "${port:-22}"
  }

  # [辅助] 检查 Limit
  check_port_limit() {
    local port=$1
    if ufw status | grep -E "^$port(/tcp)? +LIMIT" >/dev/null 2>&1; then return 0; else return 1; fi
  }

  # [辅助] Ping 状态检测 (基于 DROP 关键字)
  check_ping_status() {
    # 只要检测到 explicit DROP 规则，就视为已禁用 (返回 1/False)
    # 没有 DROP 规则，视为允许 (返回 0/True)
    if grep -q "icmp-type.*echo-request.*DROP" /etc/ufw/before.rules 2>/dev/null; then
      return 1 
    else
      return 0 
    fi
  }

  # [辅助] 智能修改 Ping 规则 (核心修复逻辑)
  modify_ping_rule() {
    local action=$1; local file=$2; local proto=$3
    local type_flag="icmp-type"
    [ "$proto" == "icmpv6" ] && type_flag="icmpv6-type"
    
    local target="ACCEPT"
    [ "$action" == "drop" ] && target="DROP"
    
    if grep -q "$type_flag.*echo-request" "$file"; then
       sed -i -E "s/($type_flag.*echo-request.*-j) [A-Z]+/\1 $target/g" "$file"
       return 0
    else
       if [ "$action" == "drop" ]; then
          local chain="ufw-before-input"
          [ "$proto" == "icmpv6" ] && chain="ufw6-before-input"
          local new_rule="-A $chain -p $proto --$type_flag echo-request -j DROP"
          if ! grep -q "$new_rule" "$file"; then
             sed -i "/^# ok icmp codes/i $new_rule" "$file" 2>/dev/null || sed -i "/^COMMIT/i $new_rule" "$file"
          fi
       else
          return 0
       fi
    fi
  }

  # --- 入口安装检测 ---
  if ! check_ufw_installed; then
    echo -e "${YELLOW}[!] 未检测到 UFW 防火墙。${RESET}"
    read -p "是否立即安装 UFW? [y/N]: " install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
      check_apt_lock || return 1
      apt-get update && apt-get install -y ufw
      hash -r 2>/dev/null
    else
      return 0
    fi
  fi

  while true; do
    if ! check_ufw_installed; then echo -e "${RED}UFW 丢失${RESET}"; sleep 2; return 0; fi

    # --- 状态检测逻辑 ---
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      is_active=true; ufw_status="${GREEN}运行中 (Active)${RESET}"
      # 获取默认策略
      default_incoming=$(ufw status verbose | grep "Default:" | awk '{print $2}')
      if [ "$default_incoming" == "deny" ]; then
         policy_display="${GREEN}拒绝入站 (Safe)${RESET}"
      else
         policy_display="${RED}允许入站 (Risk)${RESET}"
      fi
    else
      is_active=false; ufw_status="${RED}已关闭 (Inactive)${RESET}"
      policy_display="${GRAY}未生效${RESET}"
    fi

    ssh_port=$(get_actual_ssh_port)
    if [ "$is_active" = true ]; then
      if check_port_limit "$ssh_port"; then
        limit_display="${GREEN}●${RESET} 关闭 SSH 智能防爆破 (当前: Limit模式)"
        limit_is_on=true
      else
        limit_display="${GRAY}○${RESET} 开启 SSH 智能防爆破 (当前: Allow模式)"
        limit_is_on=false
      fi
    else
      limit_display="${GRAY}○${RESET} 开启 SSH 智能防爆破 (需先开启防火墙)"
      limit_is_on=false
    fi

    # Ping 状态显示逻辑
    if check_ping_status; then
        ping_display="${GREEN}已允许${RESET}"
    else
        ping_display="${RED}已禁止${RESET}"
    fi

    if [ -f /usr/local/bin/ufw-docker ]; then
        docker_tool_display="${GREEN}已安装${RESET}"
    else
        docker_tool_display="${GRAY}未安装${RESET}"
    fi

    # --- 菜单显示 ---
    clear
    echo -e "${BOLD}${CYAN}🛡️  UFW 防火墙高级管理${RESET}"
    echo -e "${CYAN}==================================================${RESET}"
    echo -e "当前状态: $ufw_status  |  默认策略: $policy_display"
    echo -e "SSH 端口: ${YELLOW}$ssh_port${RESET}"
    echo -e "${CYAN}--------------------------------------------------${RESET}"

    if [ "$is_active" = true ]; then
      echo -e "${YELLOW}  1.${RESET} 重载配置 (Reload) ${GREEN}[自动保活SSH]${RESET}"
      echo -e "${YELLOW}  2.${RESET} 关闭防火墙 (Disable)"
      echo -e "${YELLOW}  3.${RESET} 查看规则列表 (含编号)"
    else
      echo -e "${YELLOW}  1.${RESET} 开启防火墙 (Enable)"
      echo -e "${GRAY}  2. 关闭防火墙 (当前已关闭)${RESET}"
      echo -e "${GRAY}  3. 查看规则列表 (需开启)${RESET}"
    fi

    echo -e "${CYAN}--- 规则管理 ---${RESET}"
    echo -e "${YELLOW}  4.${RESET} 放行端口 (Allow Port)"
    echo -e "${YELLOW}  5.${RESET} 放行应用 (Allow App)"
    if [ "$is_active" = true ]; then
      echo -e "${YELLOW}  6.${RESET} 删除规则 (Delete Rule) ${GREEN}[安全交互]${RESET}"
    else
      echo -e "${GRAY}  6. 删除规则 (需开启)${RESET}"
    fi

    echo -e "${CYAN}--- 安全策略 ---${RESET}"
    echo -e "${YELLOW}  7.${RESET} 封禁 IP (Deny IP)"
    echo -e "${YELLOW}  8.${RESET} 信任 IP (Allow IP)"
    if [ "$is_active" = true ]; then
      echo -e "${YELLOW}  9.${RESET} $limit_display"
    else
      echo -e "${GRAY}  9. $limit_display${RESET}"
    fi

    echo -e "${CYAN}--- 高级功能 ---${RESET}"
    echo -e "${YELLOW} 12.${RESET} Docker 防火墙修复 (UFW-Docker) [${docker_tool_display}]"
    echo -e "${YELLOW} 13.${RESET} ICMP(Ping) 控制 (当前: ${ping_display})"
    echo -e "${YELLOW} 14.${RESET} 调整日志级别 (Log Level)"
    echo -e "${YELLOW} 15.${RESET} 备份与恢复配置 (Backup/Restore)"
    
    echo -e "${CYAN}--- 系统 ---${RESET}"
    echo -e "${YELLOW} 10.${RESET} 重置防火墙 (Reset) ${RED}[慎用]${RESET}"
    echo -e "${YELLOW} 11.${RESET} ${RED}卸载 UFW 防火墙${RESET}"
    echo -e "${YELLOW}  0.${RESET} 返回主菜单"
    echo -e "${CYAN}==================================================${RESET}"

    read -p "请输入选项: " u_choice

    case $u_choice in
    1)
      local r_port=$(get_actual_ssh_port)
      ufw allow "$r_port/tcp" comment "SSH-Anti-Lockout" >/dev/null 2>&1
      if [ "$is_active" = true ]; then
        ufw reload; echo -e "${GREEN}[√] 重载完成${RESET}"
      else
        ufw --force enable; echo -e "${GREEN}[√] 防火墙已开启${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    2)
      if [ "$is_active" = false ]; then echo -e "${YELLOW}已关闭${RESET}"; else ufw disable; echo -e "${YELLOW}[!] 已关闭${RESET}"; fi
      read -p "按 Enter 继续..."
      ;;
    3)
      if [ "$is_active" = false ]; then echo -e "${RED}需开启${RESET}"; else ufw status numbered; fi
      read -p "按 Enter 继续..."
      ;;
    4)
      # [UX优化] 端口智能输入
      read -p "端口/范围 (例如 80 或 80/tcp) [0 返回]: " port
      [ "$port" == "0" ] || [ -z "$port" ] && continue
      
      # 检测用户是否已经输入了协议 (如 80/tcp)
      if [[ "$port" == *"/"* ]]; then
        arg="" # 如果带斜杠，直接作为参数
        echo -e "${GRAY}检测到已包含协议，跳过协议选择...${RESET}"
      else
        read -p "协议 (1:TCP 2:UDP 3:All): " pidx
        arg="/tcp"; [ "$pidx" == "2" ] && arg="/udp"; [ "$pidx" == "3" ] && arg=""
        port="${port}${arg}"
      fi
      
      read -p "备注: " cmt; [ -z "$cmt" ] && cmt="Manual"
      ufw allow "$port" comment "$cmt"
      echo -e "${GREEN}[√] 添加成功: $port${RESET}"
      read -p "按 Enter 继续..."
      ;;
    5)
      ufw app list
      read -p "应用名 [0 返回]: " app; [ "$app" != "0" ] && [ -n "$app" ] && ufw allow "$app"
      read -p "按 Enter 继续..."
      ;;
    6)
      [ "$is_active" = false ] && { echo -e "${RED}需开启${RESET}"; read -p "..."; continue; }
      # [UX优化] 先展示列表
      echo -e "${CYAN}>>> 当前规则列表:${RESET}"
      ufw status numbered
      echo -e "${CYAN}--------------------------${RESET}"
      
      read -p "请输入要删除的规则编号 [0 返回]: " n
      if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ne 0 ]; then
         # [UX优化] 获取规则内容用于回显，防止误删
         rule_content=$(ufw status numbered | grep -E "\[\s*$n\]")
         
         if [ -n "$rule_content" ]; then
             echo -e "\n${YELLOW}即将删除以下规则:${RESET}"
             echo -e "${CYAN}${rule_content}${RESET}"
             read -p "请再次确认删除? [y/N]: " confirm_del
             if [[ "$confirm_del" =~ ^[Yy]$ ]]; then
                 echo "y" | ufw delete "$n" >/dev/null 2>&1
                 echo -e "${GREEN}[√] 规则已删除${RESET}"
                 echo -e "${GRAY}提示: 后续规则编号已自动前移${RESET}"
             else
                 echo -e "${YELLOW}已取消删除${RESET}"
             fi
         else
             echo -e "${RED}[!] 找不到编号为 $n 的规则${RESET}"
         fi
      fi
      read -p "按 Enter 继续..."
      ;;
    7)
      read -p "封禁 IP [0 返回]: " ip; [ "$ip" != "0" ] && [ -n "$ip" ] && ufw deny from "$ip" && echo -e "${GREEN}[√] 已封禁${RESET}"
      read -p "按 Enter 继续..."
      ;;
    8)
      read -p "信任 IP [0 返回]: " ip; [ "$ip" != "0" ] && [ -n "$ip" ] && ufw allow from "$ip" && echo -e "${GREEN}[√] 已信任${RESET}"
      read -p "按 Enter 继续..."
      ;;
    9)
      [ "$is_active" = false ] && { echo -e "${RED}需开启${RESET}"; read -p "..."; continue; }
      if [ "$limit_is_on" = true ]; then
        read -p "确认关闭 Limit (回退为 Allow)? [y/N]: " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
          ufw delete limit "$ssh_port/tcp" >/dev/null 2>&1
          ufw allow "$ssh_port/tcp" comment "SSH-Allow" >/dev/null 2>&1
          echo -e "${GREEN}[√] 已恢复普通放行${RESET}"
        fi
      else
        read -p "确认开启 Limit (30s/6次)? [y/N]: " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
          ufw delete allow "$ssh_port/tcp" >/dev/null 2>&1
          ufw limit "$ssh_port/tcp" comment "SSH-Limit"
          echo -e "${GREEN}[√] Limit 已开启${RESET}"
        fi
      fi
      read -p "按 Enter 继续..."
      ;;
    10)
      # [UX优化] 增加对 Docker/自定义规则丢失的明确警告
      echo -e "${RED}>>> 危险警告：重置将删除所有规则！${RESET}"
      echo -e "${YELLOW}注意: 这将清除所有 UFW-Docker 规则和自定义端口，仅自动尝试放行 SSH。${RESET}"
      read -p "确认执行重置? [y/N]: " c
      if [[ "$c" =~ ^[Yy]$ ]]; then
        ufw --force reset
        ufw default deny incoming; ufw default allow outgoing
        local rp=$(get_actual_ssh_port)
        ufw allow "$rp/tcp" comment "SSH-Anti-Lockout"
        ufw --force enable
        echo -e "${GREEN}[√] 重置完成${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    11)
      read -p "确认卸载 UFW? [y/N]: " c
      if [[ "$c" =~ ^[Yy]$ ]]; then
        ufw disable; apt-get purge -y ufw; rm -rf /etc/ufw; hash -r
        # 清理 docker 工具
        [ -f /usr/local/bin/ufw-docker ] && rm -f /usr/local/bin/ufw-docker
        echo -e "${GREEN}[√] 已卸载${RESET}"; SKIP_PAUSE=true; return 0
      fi
      ;;
    12)
      echo -e "${CYAN}>>> Docker 防火墙修复 (UFW-Docker)${RESET}"
      if [ ! -f /usr/local/bin/ufw-docker ]; then
        echo -e "${YELLOW}正在下载工具...${RESET}"
        wget -O /usr/local/bin/ufw-docker https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
        chmod +x /usr/local/bin/ufw-docker
      fi
      echo -e "\n  1. 自动修复 (Install & Reload)"
      echo -e "  2. 检查状态"
      read -p "选项: " d_opt
      case $d_opt in
        1) ufw-docker install; ufw reload; echo -e "${GREEN}[√] 修复完成${RESET}" ;;
        2) ufw-docker check ;;
      esac
      read -p "按 Enter 继续..."
      ;;
    13)
      if check_ping_status; then
         # 当前状态: 允许 -> 设为禁止
         echo -e "${CYAN}当前状态: ${GREEN}允许 Ping${RESET}"
         read -p "是否【禁止】 Ping (隐藏服务器)? [y/N]: " c
         if [[ "$c" =~ ^[Yy]$ ]]; then
            cp /etc/ufw/before.rules /etc/ufw/before.rules.bak 2>/dev/null
            if [ -f /etc/ufw/before.rules ]; then modify_ping_rule "drop" "/etc/ufw/before.rules" "icmp"; fi
            if [ -f /etc/ufw/before6.rules ]; then modify_ping_rule "drop" "/etc/ufw/before6.rules" "icmpv6"; fi
            ufw reload >/dev/null
            echo -e "${YELLOW}[!] 已禁止 Ping (双栈生效)${RESET}"
         fi
      else
         # 当前状态: 禁止 -> 设为允许
         echo -e "${CYAN}当前状态: ${YELLOW}已禁止 Ping${RESET}"
         read -p "是否【允许】 Ping (恢复默认)? [y/N]: " c
         if [[ "$c" =~ ^[Yy]$ ]]; then
            if [ -f /etc/ufw/before.rules ]; then modify_ping_rule "accept" "/etc/ufw/before.rules" "icmp"; fi
            if [ -f /etc/ufw/before6.rules ]; then modify_ping_rule "accept" "/etc/ufw/before6.rules" "icmpv6"; fi
            ufw reload >/dev/null
            echo -e "${GREEN}[√] 已允许 Ping (恢复默认)${RESET}"
         fi
      fi
      read -p "按 Enter 继续..."
      ;;
    14)
      echo -e "当前: $(grep "LOGLEVEL" /etc/ufw/ufw.conf | cut -d= -f2)"
      echo -e "可选: off, low, medium, high"
      read -p "输入级别 [0 返回]: " lvl
      if [ "$lvl" != "0" ] && [ -n "$lvl" ]; then
         ufw logging "$lvl"
         echo -e "${GREEN}[√] 已设置${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    15)
      echo -e "  1. 备份配置\n  2. 恢复配置"
      read -p "选项: " bk_opt
      case $bk_opt in
        1)
           bk_file="/root/ufw_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
           tar -czf "$bk_file" /etc/ufw /lib/ufw/user* 2>/dev/null
           echo -e "${GREEN}[√] 备份至: $bk_file${RESET}"
           ;;
        2)
           read -p "备份路径: " r_file
           if [ -f "$r_file" ]; then
              tar -xzf "$r_file" -C /; ufw reload; echo -e "${GREEN}[√] 恢复成功${RESET}"
           else
              echo -e "${RED}文件不存在${RESET}"
           fi
           ;;
      esac
      read -p "按 Enter 继续..."
      ;;
    0) SKIP_PAUSE=true; break ;;
    *) echo -e "${RED}无效选项${RESET}"; sleep 1 ;;
    esac
  done
}

# ---------- 各功能 (整合APT锁检测) ----------
system_upgrade() {
  echo -e "${CYAN}>>> 准备进行系统升级与缓存清理${RESET}"
  echo -e "${YELLOW}注意: 这将运行 apt update & upgrade，可能需要一些时间。${RESET}"
  read -p "确认继续吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  # ------------------

  echo -e "${CYAN}>>> 系统升级与清理开始...${RESET}"
  check_apt_lock || return 1
  export DEBIAN_FRONTEND=noninteractive
  apt update -y && apt upgrade -y && apt autoremove -y && apt autoclean -y
  echo -e "${GREEN}[√] 系统升级与清理完成${RESET}"
}

enable_bbr() {
  echo -e "${CYAN}>>> 正在配置 BBR 加速...${RESET}"
  ver_major=$(get_debian_major_version)
  ver_full=$(get_debian_version)
  echo -e "检测到 Debian ${YELLOW}${ver_full}${RESET} (主版本号: ${ver_major})"

  # 让用户选择队列规则
  echo -e "\n${CYAN}请选择队列规则：${RESET}"
  echo -e "${GREEN}  1${RESET}) BBR + FQ (兼容性好，适用于大多数场景)"
  echo -e "${GREEN}  2${RESET}) BBR + CAKE (性能更优，需要内核4.19+支持)"
  echo -e "${YELLOW}  0.${RESET} 返回上一级"
  echo -ne "\n${YELLOW}请输入选择 [0-2]: ${RESET}"
  read -r qdisc_choice

  case "$qdisc_choice" in
  1)
    qdisc="fq"
    echo -e "${GREEN}已选择 BBR + FQ${RESET}"
    ;;
  2)
    qdisc="cake"
    echo -e "${GREEN}已选择 BBR + CAKE${RESET}"

    # 检查内核版本是否支持CAKE
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

    if [ "$kernel_major" -lt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 19 ]; }; then
      echo -e "${YELLOW}[!] 警告: 当前内核版本 $(uname -r) 可能不完全支持CAKE${RESET}"
      echo -e "${YELLOW}[!] 建议使用内核4.19或更高版本以获得最佳性能${RESET}"
      echo -ne "${YELLOW}是否继续使用CAKE? [y/N]: ${RESET}"
      read -r continue_choice
      if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}已回退使用 FQ${RESET}"
        qdisc="fq"
      fi
    fi
    ;;
  0)
    # [优化] 取消操作时，不暂停
    SKIP_PAUSE=true
    return 0
    ;;
  *)
    echo -e "${YELLOW}无效选择，使用默认值 BBR + FQ${RESET}"
    qdisc="fq"
    ;;
  esac

  # ---------- [修复核心] 配置文件路径逻辑 ----------
  # 修复 Debian 13 下 sed 报错 "No space left on device" 的问题
  # 不再去猜测 sysctl.d/sysctl.conf，而是直接使用独立的优先级配置文件 99-bbr.conf

  if [ -d "/etc/sysctl.d" ]; then
    cfg_file="/etc/sysctl.d/99-bbr.conf"
  else
    cfg_file="/etc/sysctl.conf"
  fi

  # 1. 确保目录存在
  mkdir -p /etc/sysctl.d

  # 2. 确保文件存在（解决 sed 在空文件或不存在文件上 -i 操作时的异常）
  if [ ! -f "$cfg_file" ]; then
    touch "$cfg_file"
  fi

  # 3. 移除可能存在的旧配置 (在独立文件中操作更安全)
  # 增加 2>/dev/null 屏蔽非致命错误
  sed -i '/net.core.default_qdisc/d' "$cfg_file" 2>/dev/null
  sed -i '/net.ipv4.tcp_congestion_control/d' "$cfg_file" 2>/dev/null

  # 4. 同时清理主配置文件，防止冲突 (可选，增强稳健性)
  if [ "$cfg_file" != "/etc/sysctl.conf" ] && [ -f "/etc/sysctl.conf" ]; then
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null
  fi

  # 添加新配置
  echo "net.core.default_qdisc=$qdisc" >>"$cfg_file"
  echo "net.ipv4.tcp_congestion_control=bbr" >>"$cfg_file"

  echo -e "\n${CYAN}应用网络配置...${RESET}"
  # 优先加载我们刚写的文件，然后刷新系统
  if sysctl -p "$cfg_file" >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1
  else
    # 回退方案
    sysctl -p >/dev/null 2>&1
  fi

  # 加载BBR模块
  modprobe tcp_bbr 2>/dev/null
  if lsmod | grep -q bbr; then
    echo -e "${GREEN}[√] BBR 模块加载成功${RESET}"
  else
    echo -e "${YELLOW}[!] BBR 模块未加载，可能需要重启系统${RESET}"
  fi

  # 显示最终配置
  echo -e "\n${CYAN}最终配置状态：${RESET}"
  sysctl net.ipv4.tcp_congestion_control
  sysctl net.core.default_qdisc

  echo -e "\n${GREEN}[√] BBR 配置完成 - 使用 ${qdisc^^} 队列规则${RESET}"

  # 显示重启建议
  if ! lsmod | grep -q bbr; then
    echo -e "\n${YELLOW}[!] 建议重启系统以使BBR完全生效${RESET}"
  fi
}

enable_swap() {
  echo -e "${CYAN}>>> 开启 Swap 交换文件${RESET}"

  # 检测旧SWAP文件
  if [ -f "/swapfile" ]; then
    # 获取旧SWAP文件大小
    old_size=$(ls -lh /swapfile | awk '{print $5}')
    echo -e "${YELLOW}[!] 检测到旧 Swap 文件，大小: ${old_size}${RESET}"

    # 确认是否删除
    read -p "是否删除旧 Swap 文件? [Y/n]: " confirm
    case $confirm in
    [yY] | [yY][eE][sS] | "")
      echo -e "${CYAN}>>> 移除旧 Swap 文件...${RESET}"
      swapoff /swapfile 2>/dev/null
      sed -i '/\/swapfile/d' /etc/fstab
      rm -f /swapfile
      echo -e "${GREEN}[√] 旧 Swap 文件已移除${RESET}"
      ;;
    [nN] | [nN][oO])
      echo -e "${YELLOW}[!] 已取消操作，退出脚本${RESET}"
      SKIP_PAUSE=true
      return 1
      ;;
    *)
      echo -e "${RED}[!] 无效输入，退出脚本${RESET}"
      SKIP_PAUSE=true
      return 1
      ;;
    esac
  fi

  # 创建新SWAP
  read -p "请输入 swap 大小 (MB) (输入 0 退出): " size
  if [ "$size" == "0" ]; then
    SKIP_PAUSE=true
    return 0
  fi

  if ! [[ "$size" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}[!] 输入错误，请输入数字${RESET}"
    return 1
  fi

  echo -e "${CYAN}>>> 创建新的 Swap 文件 (${size}MB)...${RESET}"
  dd if=/dev/zero of=/swapfile bs=1M count=$size status=progress
  chmod 600 /swapfile
  mkswap /swapfile && swapon /swapfile
  echo "/swapfile none swap sw 0 0" >>/etc/fstab
  sysctl -w vm.swappiness=10 >/dev/null
  echo -e "${GREEN}[√] Swap 已启用 (${size}MB)${RESET}"
  free -h | grep -E "Mem:|Swap:"
}

clean_kernels() {
  echo -e "${CYAN}>>> 扫描可清理内核...${RESET}"

  # 1. 优先清理残留配置 (rc 状态)
  local rc_kernels=$(dpkg -l | grep "^rc" | grep "linux-" | awk '{print $2}')
  if [ -n "$rc_kernels" ]; then
    echo -e "${YELLOW}发现已卸载内核的残留配置，正在自动清理...${RESET}"
    check_apt_lock || return 1
    echo "$rc_kernels" | xargs apt-get -y purge
  fi

  # 2. 扫描已安装的旧内核
  local current_ver=$(uname -r)
  echo -e "当前运行内核: ${GREEN}$current_ver${RESET}"

  # 查找旧内核
  local old_kernels=$(dpkg -l | grep "^ii" | awk '{print $2}' | grep -E "^linux-(image|headers)-[0-9]+" | grep -v "$current_ver")

  if [ -z "$old_kernels" ]; then
    echo -e "${GREEN}[√] 未发现可清理的旧内核 (已安装且非当前运行)${RESET}"
    return 0
  fi

  echo -e "${YELLOW}发现以下旧内核版本:${RESET}"
  echo "$old_kernels"
  echo -e "${RED}警告: 请确保当前系统已通过当前内核成功启动。删除旧内核可能导致回滚失败。${RESET}"

  echo -e "${CYAN}请选择操作:${RESET}"
  echo -e "  ${GREEN}1${RESET}) 确认清理上述所有旧内核"
  echo -e "  ${YELLOW}0.${RESET} 取消/返回"

  read -p "请输入选项 [0-1]: " k_choice

  case "$k_choice" in
  1)
    check_apt_lock || return 1
    echo -e "${CYAN}正在清理旧内核...${RESET}"
    echo "$old_kernels" | xargs apt-get -y purge
    apt-get -y autoremove
    update-grub
    echo -e "${GREEN}[√] 内核清理完成${RESET}"
    ;;
  *)
    echo -e "${YELLOW}已取消清理操作${RESET}"
    SKIP_PAUSE=true
    ;;
  esac
}

# ---------- 修改 SSH 端口 (增强版: 增加恢复默认提示) ----------
change_ssh_port() {
  echo -e "${CYAN}>>> 正在修改 SSH 端口...${RESET}"

  local CURRENT_PORT=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
  if [[ -z "$CURRENT_PORT" ]]; then CURRENT_PORT="22"; fi
  echo -e "${CYAN}当前SSH端口: ${YELLOW}$CURRENT_PORT${RESET}"

  while true; do
    while true; do
      # --- [增强] 提示文本优化 ---
      echo -ne "${CYAN}请输入新的SSH端口号 (输入 22 恢复默认, 0 退出): ${RESET}"
      read -r NEW_PORT

      if [ "$NEW_PORT" == "0" ]; then
        SKIP_PAUSE=true
        return 0
      fi

      if [[ ! $NEW_PORT =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误：端口号必须是数字${RESET}"
        continue
      fi

      if [[ $NEW_PORT -eq $CURRENT_PORT ]]; then
        echo -e "${YELLOW}[!] 新端口与当前端口相同，无需修改${RESET}"
        return 1
      fi

      if ss -tuln | grep -q ":${NEW_PORT} "; then
        echo -e "${YELLOW}[!] 警告: 端口 $NEW_PORT 已被其他服务使用${RESET}"
        echo -ne "${YELLOW}是否继续？(y/N): ${RESET}"
        read -r FORCE_CONTINUE
        if [[ ! $FORCE_CONTINUE =~ ^[Yy]$ ]]; then continue; fi
      fi
      break
    done

    # --- [增强] 确认逻辑区分 ---
    if [ "$NEW_PORT" == "22" ]; then
      echo -e "\n${CYAN}即将恢复默认 SSH 端口 (22)${RESET}"
    else
      echo -e "\n${CYAN}即将修改SSH端口: ${YELLOW}$CURRENT_PORT -> $NEW_PORT${RESET}"
    fi

    echo -ne "${YELLOW}确认修改？(y/N): ${RESET}"
    read -r CONFIRM
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
      echo -e "${YELLOW}[!] 操作已取消，请重新输入端口号${RESET}"
      continue
    else
      break
    fi
  done

  local backup_file="/etc/ssh/sshd_config.backup.$(date +%Y%m%d%H%M%S)"
  cp /etc/ssh/sshd_config "$backup_file"
  echo -e "${GREEN}[√] 已备份SSH配置文件: $backup_file${RESET}"

  if grep -E "^#? *Port " /etc/ssh/sshd_config >/dev/null; then
    sed -i -E "s/^#? *Port [0-9]+/Port $NEW_PORT/" /etc/ssh/sshd_config
  else
    echo "Port $NEW_PORT" >>/etc/ssh/sshd_config
  fi
  echo -e "${GREEN}[√] SSH配置已更新${RESET}"

  local firewall_configured=false
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
    echo -e "${CYAN}检测到 UFW 防火墙正在运行，正在放行端口...${RESET}"
    ufw allow "$NEW_PORT/tcp"
    echo -e "${GREEN}[√] 已添加 UFW 规则: allow $NEW_PORT/tcp${RESET}"
    firewall_configured=true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --zone=public --add-port=$NEW_PORT/tcp --permanent >/dev/null
    firewall-cmd --reload >/dev/null
    echo -e "${GREEN}[√] 已添加 Firewalld 规则${RESET}"
    firewall_configured=true
  fi
  if [ "$firewall_configured" = false ] && command -v iptables >/dev/null 2>&1; then
    if iptables -L INPUT | grep -qE "DROP|REJECT"; then
      iptables -I INPUT -p tcp --dport $NEW_PORT -j ACCEPT
      echo -e "${GREEN}[√] 已添加 iptables 临时规则${RESET}"
    fi
  fi

  if [ "$firewall_configured" = false ]; then
    echo -e "${YELLOW}======================================================${RESET}"
    echo -e "${RED}[!] 警告：未检测到受支持的防火墙 (ufw/firewalld)${RESET}"
    echo -e "${YELLOW}请务必手动放行端口 ${NEW_PORT}，否则无法连接！${RESET}"
    echo -e "${YELLOW}======================================================${RESET}"
    read -p "我已确认防火墙设置无误 [按回车继续]"
  fi

  echo -e "\n${CYAN}是否立即重启SSH服务以使更改生效？${RESET}"
  echo -ne "${YELLOW}请输入选择 (Y/n): ${RESET}"
  read -r RESTART_SSH

  if [[ $RESTART_SSH =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}[!] 请稍后手动执行: systemctl restart ssh${RESET}"
    return 0
  else
    echo -e "${CYAN}正在重启SSH服务...${RESET}"
    if sshd -t; then
      systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
      sleep 2
      if systemctl is-active --quiet ssh || service ssh status >/dev/null 2>&1; then
        echo -e "${GREEN}[√] SSH服务重启成功${RESET}"
        rm -f "$backup_file"
        echo -e "\n${GREEN}端口已修改为 $NEW_PORT${RESET}"
        echo -e "${YELLOW}请新开窗口测试: ssh -p $NEW_PORT root@<IP>${RESET}"
      else
        echo -e "${RED}[!] 警告：SSH启动失败，正在还原备份...${RESET}"
        cp "$backup_file" /etc/ssh/sshd_config
        systemctl restart ssh
        return 1
      fi
    else
      echo -e "${RED}[!] 错误：SSH配置语法检查失败，已还原备份${RESET}"
      cp "$backup_file" /etc/ssh/sshd_config
      return 1
    fi
  fi
}

modify_dns() {
  echo -e "${CYAN}>>> 修改系统DNS地址...${RESET}"

  # 检查权限
  if [ $EUID -ne 0 ]; then
    echo -e "${RED}错误: 此功能需要root权限执行${RESET}"
    return 1
  fi

  # 常用DNS服务器列表
  common_dns=(
    # IPv4
    "8.8.8.8|Google Public DNS (IPv4)"
    "8.8.4.4|Google Public DNS 备用 (IPv4)"
    "1.1.1.1|Cloudflare DNS (IPv4)"
    "1.0.0.1|Cloudflare DNS 备用 (IPv4)"
    "208.67.222.222|OpenDNS (IPv4)"
    "208.67.220.220|OpenDNS 备用 (IPv4)"
    "9.9.9.9|Quad9 DNS (IPv4)"
    "149.112.112.112|Quad9 DNS 备用 (IPv4)"
    "94.140.14.14|AdGuard DNS (IPv4)"
    "94.140.15.15|AdGuard DNS 备用 (IPv4)"
    "223.5.5.5|阿里 AliDNS (IPv4)"
    "223.6.6.6|阿里 AliDNS 备用 (IPv4)"
    "119.29.29.29|腾讯 DNSPod (IPv4)"
    "180.76.76.76|百度 BaiduDNS (IPv4)"
    # IPv6
    "2001:4860:4860::8888|Google Public DNS (IPv6)"
    "2001:4860:4860::8844|Google Public DNS 备用 (IPv6)"
    "2606:4700:4700::1111|Cloudflare DNS (IPv6)"
    "2606:4700:4700::1001|Cloudflare DNS 备用 (IPv6)"
    "2620:119:35::35|OpenDNS (IPv6)"
    "2620:119:53::53|OpenDNS 备用 (IPv6)"
    "2620:fe::fe|Quad9 DNS (IPv6)"
    "2a10:50c0::ad1:ff|AdGuard DNS (IPv6)"
    "2400:3200::1|阿里 AliDNS (IPv6)"
    "2400:da00::6666|百度 BaiduDNS (IPv6)"
  )

  # 全局变量，用于接收子函数返回的 IP 列表
  SELECTED_IPS=()

  # 显示当前DNS配置
  echo -e "${YELLOW}当前DNS配置:${RESET}"
  if [ -f /etc/resolv.conf ]; then
    grep -E '^nameserver' /etc/resolv.conf | while read line; do
      echo -e "  ${GREEN}✓${RESET} $line"
    done
  fi

  # 使用循环包裹菜单，实现子菜单返回上一级
  while true; do
    # 每次循环清空选择
    SELECTED_IPS=()

    echo -e "\n${CYAN}请选择操作方式:${RESET}"
    echo -e "  ${GREEN}1${RESET}) 自动测试并手动选择 (支持多选，含IPv6)"
    echo -e "  ${GREEN}2${RESET}) 手动输入DNS地址 (支持连续输入，含IPv6)"
    echo -e "  ${GREEN}3${RESET}) 从常用DNS列表选择 (支持多选，含IPv6)"
    echo -e "  ${YELLOW}0.${RESET} 取消操作/返回"

    read -p "请输入选择 [0-3]: " choice

    case $choice in
    1)
      auto_test_dns
      ;;
    2)
      manual_input_dns
      ;;
    3)
      select_from_list
      ;;
    0)
      echo -e "${YELLOW}已取消DNS修改操作${RESET}"
      SKIP_PAUSE=true
      return 0
      ;;
    *)
      echo -e "${RED}无效选择，请重新输入${RESET}"
      continue
      ;;
    esac

    # 检查是否有选中的 IP
    if [ ${#SELECTED_IPS[@]} -eq 0 ]; then
      echo -e "${YELLOW}未选择任何 DNS，返回上一级菜单...${RESET}"
      continue # 继续循环
    fi

    # 如果选择了IP，则跳出循环，继续执行应用逻辑
    break
  done

  # === 数组去重 ===
  SELECTED_IPS=($(printf "%s\n" "${SELECTED_IPS[@]}" | awk '!a[$0]++'))

  echo -e "\n${CYAN}准备应用新的 DNS 配置: ${SELECTED_IPS[*]}${RESET}"

  # --- 1. 备份配置 ---
  local backup_file="/etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)"
  local backup_systemd=""

  # 尝试备份
  if cp -P /etc/resolv.conf "$backup_file" 2>/dev/null; then
    echo -e "${GREEN}[√] 已备份原配置到: $backup_file${RESET}"
  else
    touch "$backup_file"
    echo -e "${YELLOW}[!] 原配置不存在或无法备份，将创建新配置...${RESET}"
  fi

  # 如果存在 systemd-resolved，也备份它的配置
  if [ -f /etc/systemd/resolved.conf ]; then
    backup_systemd="/etc/systemd/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/systemd/resolved.conf "$backup_systemd" 2>/dev/null
  fi

  # --- 2. 写入新配置 (先清理后应用) ---
  write_dns_config "${SELECTED_IPS[@]}"

  # --- 3. 验证与回滚 ---
  if verify_dns_config; then
    echo -e "${GREEN}[√] DNS修改成功且验证通过${RESET}"
    echo -e "${YELLOW}新的DNS配置:${RESET}"
    grep -E '^nameserver' /etc/resolv.conf | while read line; do
      echo -e "  ${GREEN}✓${RESET} $line"
    done

    # 验证成功，删除备份文件
    echo -e "${CYAN}>>> 正在清理备份文件...${RESET}"
    [ -f "$backup_file" ] && rm -f "$backup_file"
    [ -n "$backup_systemd" ] && [ -f "$backup_systemd" ] && rm -f "$backup_systemd"
    echo -e "${GREEN}[√] 备份文件已删除${RESET}"

  else
    echo -e "${RED}[×] DNS配置验证失败，正在还原配置...${RESET}"

    # 还原 resolv.conf
    if [ -f "$backup_file" ]; then
      chattr -i /etc/resolv.conf 2>/dev/null
      rm -f /etc/resolv.conf
      cp -P "$backup_file" /etc/resolv.conf 2>/dev/null || cp "$backup_file" /etc/resolv.conf
      echo -e "${YELLOW}[!] 已还原 /etc/resolv.conf${RESET}"
    fi

    # 还原 systemd-resolved
    if [ -n "$backup_systemd" ] && [ -f "$backup_systemd" ]; then
      cp "$backup_systemd" /etc/systemd/resolved.conf
      systemctl restart systemd-resolved 2>/dev/null
      echo -e "${YELLOW}[!] 已还原 /etc/systemd/resolved.conf${RESET}"
    fi

    return 1
  fi
}

auto_test_dns() {
  echo -e "${CYAN}>>> 正在测试常用DNS速度 (含IPv6)...${RESET}"

  # 测试的DNS服务器 (混合v4和v6)
  local test_dns=(
    "8.8.8.8|Google IPv4"
    "1.1.1.1|Cloudflare IPv4"
    "208.67.222.222|OpenDNS IPv4"
    "9.9.9.9|Quad9 IPv4"
    "223.5.5.5|AliDNS IPv4"
    "119.29.29.29|DNSPod IPv4"
    "2001:4860:4860::8888|Google IPv6"
    "2606:4700:4700::1111|Cloudflare IPv6"
    "2400:3200::1|AliDNS IPv6"
  )

  declare -a dns_results
  local count=0

  for dns_info in "${test_dns[@]}"; do
    IFS='|' read -r dns_ip dns_name <<<"$dns_info"
    echo -ne "  测试 ${YELLOW}$dns_name${RESET} ($dns_ip)... "

    # 判断IPv4还是IPv6选择ping命令
    local ping_cmd="ping"
    if [[ "$dns_ip" == *":"* ]]; then
      # IPv6
      if command -v ping6 &>/dev/null; then
        ping_cmd="ping6"
      else
        ping_cmd="ping -6"
      fi
    fi

    # 使用ping测试延迟
    # 增加 LC_ALL=C 确保 grep 'avg' 能匹配到英文输出
    if ping_result=$(LC_ALL=C $ping_cmd -c 2 -W 2 "$dns_ip" 2>/dev/null | grep -i 'avg'); then
      avg_latency=$(echo "$ping_result" | awk -F'/' '{print $5}')
      echo -e "${GREEN}${avg_latency}ms${RESET}"
      dns_results[$count]="$avg_latency|$dns_ip|$dns_name"
    else
      echo -e "${RED}超时/不可达${RESET}"
      dns_results[$count]="9999|$dns_ip|$dns_name"
    fi

    count=$((count + 1))
  done

  # Separate results
  local v4_list=()
  local v6_list=()
  for res in "${dns_results[@]}"; do
    IFS='|' read -r lat ip nm <<<"$res"
    if [[ "$ip" == *":"* ]]; then
      v6_list+=("$res")
    else
      v4_list+=("$res")
    fi
  done

  # Sort
  local sorted_v4=()
  local sorted_v6=()
  if [ ${#v4_list[@]} -gt 0 ]; then
    IFS=$'\n' sorted_v4=($(printf "%s\n" "${v4_list[@]}" | sort -n -t'|' -k1))
    unset IFS
  fi
  if [ ${#v6_list[@]} -gt 0 ]; then
    IFS=$'\n' sorted_v6=($(printf "%s\n" "${v6_list[@]}" | sort -n -t'|' -k1))
    unset IFS
  fi

  local valid_options=()
  local display_index=1

  # Display IPv4
  echo -e "\n${CYAN}IPv4 DNS 延迟排名:${RESET}"
  local v4_count=0
  for item in "${sorted_v4[@]}"; do
    IFS='|' read -r latency ip name <<<"$item"
    if [ "$latency" != "9999" ]; then
      echo -e "  ${GREEN}${display_index}${RESET}. ${BOLD}$name${RESET} ($ip) - ${YELLOW}${latency}ms${RESET}"
      valid_options[$display_index]="$ip"
      display_index=$((display_index + 1))
      v4_count=$((v4_count + 1))
    fi
  done
  [ $v4_count -eq 0 ] && echo -e "  ${GRAY}无可用 IPv4 结果${RESET}"

  # Display IPv6
  echo -e "\n${CYAN}IPv6 DNS 延迟排名:${RESET}"
  local v6_count=0
  for item in "${sorted_v6[@]}"; do
    IFS='|' read -r latency ip name <<<"$item"
    if [ "$latency" != "9999" ]; then
      echo -e "  ${GREEN}${display_index}${RESET}. ${BOLD}$name${RESET} ($ip) - ${YELLOW}${latency}ms${RESET}"
      valid_options[$display_index]="$ip"
      display_index=$((display_index + 1))
      v6_count=$((v6_count + 1))
    fi
  done
  [ $v6_count -eq 0 ] && echo -e "  ${GRAY}无可用 IPv6 结果${RESET}"

  # Check if any valid
  if [ ${#valid_options[@]} -eq 0 ]; then
    echo -e "${RED}所有DNS测试均超时，请检查网络连接${RESET}"
    return 1
  fi

  echo -e "\n${YELLOW}提示：可以输入多个编号进行组合（例如：1 3）(输入 0 退出)${RESET}"
  read -p "请输入要使用的DNS编号 (用空格分隔): " user_choices

  # 处理用户输入
  for choice in $user_choices; do
    if [ "$choice" == "0" ]; then return 0; fi
    if [ -n "${valid_options[$choice]}" ]; then
      SELECTED_IPS+=("${valid_options[$choice]}")
    fi
  done
}

manual_input_dns() {
  echo -e "${CYAN}>>> 手动输入DNS地址${RESET}"
  echo -e "${YELLOW}提示：支持输入多个IP地址(IPv4/IPv6)，用空格分隔 (输入 0 返回)${RESET}" # [修改] 提示文本

  read -p "请输入DNS服务器地址: " input_dns
  if [ "$input_dns" == "0" ]; then return 0; fi

  for ip in $input_dns; do
    if validate_ip "$ip"; then
      SELECTED_IPS+=("$ip")
    else
      echo -e "${RED}忽略无效的IP地址格式: $ip${RESET}"
    fi
  done
}

select_from_list() {
  echo -e "${CYAN}>>> 从常用DNS列表选择${RESET}"

  echo -e "${YELLOW}常用DNS服务器列表:${RESET}"
  for i in "${!common_dns[@]}"; do
    IFS='|' read -r ip name <<<"${common_dns[$i]}"
    echo -e "  ${GREEN}$((i + 1))${RESET}) $name - ${YELLOW}$ip${RESET}"
  done

  echo -e "\n${YELLOW}提示：可以输入多个编号进行组合（例如：1 2）(输入 0 退出)${RESET}"
  read -p "请选择DNS服务器编号 [用空格分隔]: " user_choices

  for choice in $user_choices; do
    if [ "$choice" == "0" ]; then return 0; fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#common_dns[@]}" ]; then
      index=$((choice - 1))
      IFS='|' read -r selected_ip selected_name <<<"${common_dns[$index]}"
      SELECTED_IPS+=("$selected_ip")
    else
      echo -e "${RED}忽略无效选择: $choice${RESET}"
    fi
  done
}

# 辅助函数 (支持IPv4和IPv6)
validate_ip() {
  local ip=$1
  # IPv4 check
  if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 0
  # IPv6 check (simplified regex)
  elif [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    return 0
  else
    return 1
  fi
}

write_dns_config() {
  local dns_list=("$@")

  echo -e "${CYAN}正在重写 /etc/resolv.conf 以确保无多余DNS残留...${RESET}"

  # 1. 强制覆盖 /etc/resolv.conf
  # 尝试解锁文件
  chattr -i /etc/resolv.conf 2>/dev/null

  # [核心操作] 强制删除原文件/软链接
  rm -f /etc/resolv.conf

  # 创建新文件
  touch /etc/resolv.conf
  chmod 644 /etc/resolv.conf

  # 写入文件头
  cat >/etc/resolv.conf <<EOF
# Generated by VPS Management Script
# Last update: $(date)
EOF

  # 循环写入所有选中的 IP
  for ip in "${dns_list[@]}"; do
    echo "nameserver $ip" >>/etc/resolv.conf
  done

  echo -e "${GREEN}[√] /etc/resolv.conf 已重写为静态文件${RESET}"

  # 2. 如果检测到 systemd-resolved，也同步修改其配置
  if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    echo -e "${CYAN}检测到 systemd-resolved，正在同步 Global 配置...${RESET}"

    local dns_string="${dns_list[*]}"

    # 彻底清理旧配置
    sed -i '/^DNS=/d' /etc/systemd/resolved.conf
    sed -i '/^#DNS=/d' /etc/systemd/resolved.conf
    sed -i '/^FallbackDNS=/d' /etc/systemd/resolved.conf
    sed -i '/^#FallbackDNS=/d' /etc/systemd/resolved.conf

    # 插入新配置
    if grep -q "\[Resolve\]" /etc/systemd/resolved.conf; then
      sed -i "/\[Resolve\]/a DNS=$dns_string" /etc/systemd/resolved.conf
      sed -i "/\[Resolve\]/a FallbackDNS=8.8.8.8 1.1.1.1" /etc/systemd/resolved.conf
    else
      echo "[Resolve]" >>/etc/systemd/resolved.conf
      echo "DNS=$dns_string" >>/etc/systemd/resolved.conf
      echo "FallbackDNS=8.8.8.8 1.1.1.1" >>/etc/systemd/resolved.conf
    fi

    systemctl restart systemd-resolved
    echo -e "${GREEN}[√] systemd-resolved 全局配置已更新${RESET}"
  fi

  # 3. 询问锁定
  echo -e "${YELLOW}是否锁定 DNS 配置文件以防止系统重启或 DHCP 再次修改?${RESET}"
  read -p "锁定 /etc/resolv.conf? [y/N]: " lock_choice
  if [[ "$lock_choice" =~ ^[Yy]$ ]]; then
    if command -v chattr >/dev/null 2>&1; then
      chattr +i /etc/resolv.conf
      echo -e "${GREEN}[√] 文件已锁定 (+i)${RESET}"
    else
      echo -e "${RED}[!] 错误：未找到 chattr 命令，无法锁定${RESET}"
    fi
  fi
}

verify_dns_config() {
  echo -e "\n${CYAN}>>> 验证DNS配置...${RESET}"

  if [ ! -f /etc/resolv.conf ]; then
    echo -e "${RED}错误: /etc/resolv.conf 文件不存在${RESET}"
    return 1
  fi

  local dns_servers=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}')
  if [ -z "$dns_servers" ]; then
    # 如果是 systemd-resolved，resolv.conf 可能是存根，需要检查 resolvectl
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
      echo -e "${GRAY}使用 systemd-resolved，尝试解析验证...${RESET}"
    else
      echo -e "${RED}错误: 未找到有效的DNS服务器配置${RESET}"
      return 1
    fi
  fi

  # 进行实际解析测试
  echo -ne "  正在测试解析 google.com ... "
  if nslookup -timeout=5 google.com >/dev/null 2>&1 || ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo -e "${GREEN}成功${RESET}"
    return 0
  else
    echo -e "${RED}失败${RESET}"
    return 1
  fi
}

manage_ipv6() {
  echo -e "${CYAN}>>> 管理 IPv6 配置...${RESET}"

  # 检测当前内核 IPv6 状态
  local ipv6_disabled_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
  local has_ipv6_addr=$(ip -6 addr show | grep -v "::1" | grep -q "inet6" && echo "yes" || echo "no")

  echo -ne "当前状态: "
  if [ "$ipv6_disabled_status" = "1" ]; then
    echo -e "${RED}已禁用${RESET}"
  else
    if [ "$has_ipv6_addr" = "yes" ]; then
      echo -e "${GREEN}已开启 (且检测到IPv6地址)${RESET}"
    else
      echo -e "${YELLOW}已开启 (但未检测到IPv6地址，可能网络不支持)${RESET}"
    fi
  fi

  echo -e "\n${CYAN}请选择操作:${RESET}"
  echo -e "  ${GREEN}1${RESET}) 开启 IPv6"
  echo -e "  ${GREEN}2${RESET}) 关闭 IPv6 (永久生效)"
  echo -e "  ${YELLOW}0.${RESET} 取消/返回"

  read -p "请输入选项 [0-2]: " ipv6_choice

  local ver_major=$(get_debian_major_version)
  local sysctl_conf="/etc/sysctl.conf"
  [ "$ver_major" -ge 13 ] && sysctl_conf="/etc/sysctl.d/sysctl.conf"

  if [ ! -f "$sysctl_conf" ]; then
    mkdir -p "$(dirname "$sysctl_conf")"
    touch "$sysctl_conf"
  fi

  local disable_conf="/etc/sysctl.d/99-ipv6-disable.conf"
  local grub_file="/etc/default/grub"

  case $ipv6_choice in
  1)
    echo -e "${CYAN}>>> 正在开启 IPv6...${RESET}"

    local reboot_required=false

    # 1. GRUB 配置清理
    if [ -f "$grub_file" ]; then
      if grep -q "ipv6.disable=1" "$grub_file"; then
        echo -e "${CYAN}发现 GRUB 内核禁用参数，正在移除...${RESET}"
        sed -i 's/ipv6.disable=1//g' "$grub_file"
        sed -i 's/  / /g' "$grub_file" # 清理空格
        update-grub
        echo -e "${GREEN}[√] GRUB 配置已更新${RESET}"
        reboot_required=true
      fi
    fi

    # 2. 删除专门的禁用配置文件
    if [ -f "$disable_conf" ]; then
      rm -f "$disable_conf"
      echo -e "${YELLOW}[-] 已删除禁用配置文件: $disable_conf${RESET}"
    fi

    # 3. 清理主配置文件中的禁用项
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$sysctl_conf"
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' "$sysctl_conf"
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' "$sysctl_conf"

    # 4. 尝试动态启用
    if [ -d "/proc/sys/net/ipv6" ]; then
      sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1
      sysctl -p >/dev/null 2>&1
      echo -e "${GREEN}[√] IPv6 参数已动态启用${RESET}"
    else
      echo -e "${YELLOW}[!] 检测到 IPv6 内核模块未加载${RESET}"
      reboot_required=true
    fi

    if [ "$reboot_required" = true ]; then
      echo -e "${RED}[!] 必须重启系统才能重新加载 IPv6 模块！${RESET}"
      read -p "是否立即重启? [y/N]: " restart_choice
      if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        reboot
      fi
    else
      echo -e "${GREEN}[√] IPv6 已开启${RESET}"
    fi
    ;;

  2)
    echo -e "${CYAN}>>> 正在关闭 IPv6...${RESET}"

    # 写入禁用配置到独立文件
    cat >"$disable_conf" <<EOF
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    echo -e "${GREEN}[+] 已创建禁用配置: $disable_conf${RESET}"
    sysctl -p "$disable_conf" >/dev/null

    # GRUB 禁用
    if [ -f "$grub_file" ]; then
      echo -e "${CYAN}正在修改 GRUB 配置以彻底禁用 IPv6...${RESET}"
      if ! grep -q "ipv6.disable=1" "$grub_file"; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1 /' "$grub_file"
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' "$grub_file"
        update-grub
        echo -e "${GREEN}[√] GRUB 配置已更新${RESET}"
      fi
    fi

    echo -e "${GREEN}[√] IPv6 已永久关闭${RESET}"
    echo -e "${YELLOW}注意: 建议重启系统以确保 GRUB 配置生效${RESET}"
    ;;

  0)
    SKIP_PAUSE=true
    return 0
    ;;

  *)
    echo -e "${RED}无效选项${RESET}"
    ;;
  esac
}

# ---------- [整合] 常用软件与Docker管理 (已修改: 拆分管理与增加确认) ----------

# 辅助: 确保 Docker 已安装 (增加确认逻辑)
ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] 检测到系统未安装 Docker 环境。${RESET}"
    read -p "是否立即安装 Docker? [y/N]: " install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
      do_install_docker
      # 安装后再次检测
      if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}[×] Docker 安装失败或已取消，无法继续部署容器。${RESET}"
        return 1
      fi
    else
      echo -e "${YELLOW}[!] 已取消操作，需要 Docker 环境才能继续。${RESET}"
      return 1
    fi
  fi
  # 确保 docker 服务运行
  systemctl start docker >/dev/null 2>&1
  return 0
}

install_xui() {
  echo -e "${CYAN}>>> 准备安装 X-UI 面板 (官方脚本)${RESET}"
  read -p "确认开始安装吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  install_deps "curl"
  bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh)
}

install_3xui() {
  echo -e "${CYAN}>>> 准备安装 3X-UI 面板 (官方脚本)${RESET}"
  read -p "确认开始安装吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  install_deps "curl"
  bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
}

# 独立安装 Docker 函数
do_install_docker() {
  if command -v docker >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Docker 已安装，无需重复操作。${RESET}"
    return 0
  fi

  echo -e "${CYAN}>>> 准备安装 Docker 环境 (官方源)...${RESET}"
  read -p "确认开始安装吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  install_deps "curl"
  check_apt_lock || return 1
  if curl -fsSL https://get.docker.com | sh; then
    echo -e "${GREEN}[√] Docker 安装完成${RESET}"
    systemctl enable --now docker
  else
    echo -e "${RED}[×] Docker 安装失败，请检查网络${RESET}"
  fi
}

# 独立卸载 Docker 函数
do_uninstall_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] 系统未安装 Docker。${RESET}"
    return 0
  fi

  echo -e "${RED}>>> 警告: 即将卸载 Docker 环境及所有容器数据/镜像!${RESET}"
  read -p "确认彻底卸载吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  echo -e "${CYAN}>>> 正在卸载 Docker...${RESET}"
  check_apt_lock || return 1
  apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
  rm -rf /var/lib/docker
  rm -rf /var/lib/containerd
  echo -e "${GREEN}[√] Docker 已卸载完成${RESET}"
}

install_portainer() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 Portainer CE (可视化管理)${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  echo -e "${CYAN}>>> 正在拉取并启动 Portainer...${RESET}"
  docker volume create portainer_data
  docker run -d \
    -p 8000:8000 \
    -p 9443:9443 \
    -p 9000:9000 \
    --name portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    portainer/portainer-ce:latest

  echo -e "${GREEN}[√] Portainer 已部署。${RESET}"
  echo -e "${YELLOW}访问地址 (HTTPS - 推荐): https://<IP>:9443${RESET}"
  echo -e "${YELLOW}访问地址 (HTTP): http://<IP>:9000${RESET}"
}

install_npm() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 Nginx Proxy Manager${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  local install_dir="/root/npm"
  mkdir -p "$install_dir"

  cat >"$install_dir/docker-compose.yml" <<EOF
services:
  app:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
EOF

  echo -e "${CYAN}正在启动容器...${RESET}"
  cd "$install_dir" && docker compose up -d

  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[√] NPM 已部署。${RESET}"
    echo -e "${YELLOW}管理后台: http://<IP>:81 (admin@example.com / changeme)${RESET}"
  else
    echo -e "${RED}[×] 启动失败。${RESET}"
  fi
}

install_filecodebox() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 FileCodeBox (文件快递柜)${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  local data_dir="/opt/filecodebox"
  mkdir -p "$data_dir"

  docker run -d \
    --name filecodebox \
    --restart=always \
    -p 12345:12345 \
    -v "$data_dir":/app/data \
    lanol/filecodebox:latest

  echo -e "${GREEN}[√] FileCodeBox 已部署。${RESET}"
  echo -e "${YELLOW}访问地址: http://<IP>:12345${RESET}"
}

install_1panel() {
  echo -e "${CYAN}>>> 准备安装 1Panel (现代化运维面板)${RESET}"
  echo -e "${GRAY}注意: 1Panel 安装脚本会自动管理 Docker 环境。${RESET}"
  read -p "确认开始安装吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  install_deps "curl"
  check_apt_lock || return 1
  bash -c "$(curl -sSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh)"
  rm -f quick_start.sh
}

install_n8n() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 n8n (自动化工作流)${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  docker volume create n8n_data
  docker run -d \
    --name n8n \
    --restart unless-stopped \
    --shm-size 2g \
    -p 5678:5678 \
    -e N8N_SECURE_COOKIE=false \
    -v n8n_data:/home/node/.n8n \
    n8nio/n8n:latest

  echo -e "${GREEN}[√] n8n 已部署。${RESET}"
  echo -e "${YELLOW}访问地址: http://<IP>:5678${RESET}"
}

install_uptime_kuma() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 Uptime Kuma (在线状态监控)${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  docker run -d \
    --restart=always \
    -p 3001:3001 \
    -v uptime-kuma:/app/data \
    --name uptime-kuma \
    louislam/uptime-kuma:1

  echo -e "${GREEN}[√] Uptime Kuma 已部署。${RESET}"
  echo -e "${YELLOW}访问地址: http://<IP>:3001${RESET}"
}

install_netdata() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 Netdata (实时性能监控)${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  docker run -d --name=netdata \
    -p 19999:19999 \
    -v netdataconfig:/etc/netdata \
    -v netdatalib:/var/lib/netdata \
    -v netdatacache:/var/cache/netdata \
    -v /etc/passwd:/host/etc/passwd:ro \
    -v /etc/group:/host/etc/group:ro \
    -v /proc:/host/proc:ro \
    -v /sys:/host/sys:ro \
    -v /etc/os-release:/host/etc/os-release:ro \
    --restart unless-stopped \
    --cap-add SYS_PTRACE \
    --security-opt apparmor=unconfined \
    netdata/netdata

  echo -e "${GREEN}[√] Netdata 已部署。${RESET}"
  echo -e "${YELLOW}访问地址: http://<IP>:19999${RESET}"
}

install_prom_grafana() {
  ensure_docker || return 1

  echo -e "${CYAN}>>> 准备安装 Prometheus + Grafana${RESET}"
  read -p "确认开始部署吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${RESET}"
    return 0
  fi

  local install_dir="/opt/monitoring"
  mkdir -p "$install_dir/prometheus"
  mkdir -p "$install_dir/grafana/provisioning/datasources"

  # 配置文件生成逻辑保持不变，此处省略详细生成过程以节省篇幅，实际运行时会执行
  cat >"$install_dir/prometheus/prometheus.yml" <<EOF
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

  cat >"$install_dir/grafana/provisioning/datasources/datasource.yml" <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

  cat >"$install_dir/docker-compose.yml" <<EOF
services:
  prometheus:
    image: prom/prometheus
    container_name: prometheus
    restart: unless-stopped
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - 9090:9090
    networks:
      - monitoring
  grafana:
    image: grafana/grafana
    container_name: grafana
    restart: unless-stopped
    ports:
      - 3000:3000
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    depends_on:
      - prometheus
    networks:
      - monitoring
volumes:
  grafana_data:
networks:
  monitoring:
EOF

  echo -e "${CYAN}正在启动监控容器...${RESET}"
  cd "$install_dir" && docker compose up -d

  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[√] 监控平台已部署。${RESET}"
    echo -e "${YELLOW}Grafana: http://<IP>:3000 (admin/admin)${RESET}"
  else
    echo -e "${RED}[×] 启动失败。${RESET}"
  fi
}

software_hub() {
  while true; do
    clear
    echo -e "${BOLD}${GREEN}📦 常用软件安装中心 (Docker/Panel)${RESET}"
    echo -e "${CYAN}==================================================${RESET}"

    # 简易检测 Docker 状态
    if command -v docker >/dev/null 2>&1; then
      echo -e "Docker状态: ${GREEN}已安装 $(docker --version | awk '{print $3}' | sed 's/,//')${RESET}"
    else
      echo -e "Docker状态: ${RED}未安装${RESET}"
    fi
    echo -e "${CYAN}--------------------------------------------------${RESET}"

    echo -e "${CYAN}--- 环境管理 ---${RESET}"
    echo -e "${YELLOW}  1.${RESET} 安装 Docker 环境"
    echo -e "${YELLOW}  2.${RESET} 卸载 Docker 环境"
    echo -e "${CYAN}--- 面板类 (Script) ---${RESET}"
    echo -e "${YELLOW}  3.${RESET} 安装 X-UI 面板"
    echo -e "${YELLOW}  4.${RESET} 安装 3X-UI 面板"
    echo -e "${CYAN}--- 容器类 (Docker) ---${RESET}"
    echo -e "${YELLOW}  5.${RESET} 安装 Portainer (可视化容器管理)"
    echo -e "${YELLOW}  6.${RESET} 安装 Nginx Proxy Manager (反代神器)"
    echo -e "${YELLOW}  7.${RESET} 安装 FileCodeBox (文件快递柜)"
    echo -e "${YELLOW}  8.${RESET} 安装 1Panel (现代化运维面板)"
    echo -e "${YELLOW}  9.${RESET} 安装 N8n (工作流自动化)"
    echo -e "${CYAN}--- 监控类 (Monitoring) ---${RESET}"
    echo -e "${YELLOW} 10.${RESET} 安装 Uptime Kuma (在线状态监控)"
    echo -e "${YELLOW} 11.${RESET} 安装 Netdata (实时性能监控)"
    echo -e "${YELLOW} 12.${RESET} 安装 Prometheus + Grafana (可视化平台)"
    echo -e "${YELLOW}  0.${RESET} 返回主菜单"
    echo -e "${CYAN}==================================================${RESET}"

    read -p "请输入选项: " sw_choice
    case $sw_choice in
    1) do_install_docker ;;
    2) do_uninstall_docker ;;
    3) install_xui ;;
    4) install_3xui ;;
    5) install_portainer ;;
    6) install_npm ;;
    7) install_filecodebox ;;
    8) install_1panel ;;
    9) install_n8n ;;
    10) install_uptime_kuma ;;
    11) install_netdata ;;
    12) install_prom_grafana ;;
    0)
      SKIP_PAUSE=true
      return 0
      ;;
    *) echo -e "${RED}无效选项${RESET}" ;;
    esac

    # 子菜单操作完后暂停，方便看日志
    if [ "$SKIP_PAUSE" = false ]; then
      echo -e ""
      read -p "按 Enter 继续..."
    else
      SKIP_PAUSE=false
    fi
  done
}

stream_test() {
  echo -e "${CYAN}>>> 准备运行流媒体解锁测试${RESET}"
  read -p "确认开始测试吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  # ------------------
  install_deps "curl"
  local temp
  temp=$(mktemp -d -p "$TEMP_DIR")
  echo -e "${CYAN}>>> 开始流媒体解锁测试...${RESET}"
  cd "$temp" && bash <(curl -Ls https://Check.Place) -I
  cd - >/dev/null
  echo -e "${GREEN}[√] 流媒体测试完成${RESET}"
}

net_test() {
  echo -e "${CYAN}>>> 准备运行网络质量测试${RESET}"
  read -p "确认开始测试吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  # ------------------
  install_deps "curl"
  local temp
  temp=$(mktemp -d -p "$TEMP_DIR")
  echo -e "${CYAN}>>> 开始网络质量测试...${RESET}"
  cd "$temp" && bash <(curl -Ls https://Check.Place) -N
  cd - >/dev/null
  echo -e "${GREEN}[√] 网络质量测试完成${RESET}"
}

full_test() {
  echo -e "${CYAN}>>> 准备运行融合怪全面测试${RESET}"
  read -p "确认开始测试吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  # ------------------
  install_deps "curl"
  local temp
  temp=$(mktemp -d -p "$TEMP_DIR")
  echo -e "${CYAN}>>> 开始融合怪全面测试...${RESET}"
  cd "$temp" && curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
  cd - >/dev/null
  echo -e "${GREEN}[√] 融合怪测试完成${RESET}"
}

benchmark() {
  echo -e "${CYAN}>>> 准备运行服务器性能测试${RESET}"
  read -p "确认开始测试吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  install_deps "curl"
  local temp
  temp=$(mktemp -d -p "$TEMP_DIR")
  echo -e "${CYAN}>>> 开始服务器性能测试...${RESET}"
  cd "$temp" && curl -sL yabs.sh -o yabs.sh && chmod +x yabs.sh && bash yabs.sh
  cd - >/dev/null
  echo -e "${GREEN}[√] 性能测试完成${RESET}"
}

# ---------- 系统清理 (保持完整逻辑，整合APT锁检测) ----------
system_cleanup() {
  echo -e "${CYAN}>>> 准备执行深度系统清理${RESET}"
  echo -e "${YELLOW}将清理: 日志、APT缓存、孤立包、临时文件等。${RESET}"
  read -p "确认执行清理吗? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}操作已取消${RESET}"
    SKIP_PAUSE=true
    return 0
  fi
  echo -e "${BOLD}${CYAN}>>> 正在执行深度系统清理...${RESET}"

  # 初始化总清理大小 (KB)
  total_freed_kb=0

  # 辅助函数：获取目录大小 (KB)
  get_dir_size_kb() {
    local path="$1"
    if [ -d "$path" ]; then
      du -sk "$path" 2>/dev/null | awk '{print $1}'
    else
      echo 0
    fi
  }

  # 辅助函数：格式化大小显示 (KB -> Human Readable)
  format_size() {
    local kb=$1
    if [ "$kb" -lt 1024 ]; then
      echo "${kb}KB"
    elif [ "$kb" -lt 1048576 ]; then
      awk -v k="$kb" 'BEGIN{printf "%.2fMB", k/1024}'
    else
      awk -v k="$kb" 'BEGIN{printf "%.2fGB", k/1024/1024}'
    fi
  }

  # --- 1. 系统缓存与APT清理  ---
  echo -e "${YELLOW}[1/6] 清理系统缓存与软件包...${RESET}"

  # 计算 APT 缓存大小
  apt_size=$(get_dir_size_kb "/var/cache/apt/archives")

  # 清理
  check_apt_lock || return 1
  apt-get autoremove -y >/dev/null 2>&1
  apt-get clean -y >/dev/null 2>&1

  # 其他系统缓存目录
  sys_dirs=("/var/tmp" "/var/crash")
  sys_cleaned=0
  for dir in "${sys_dirs[@]}"; do
    size=$(get_dir_size_kb "$dir")
    sys_cleaned=$((sys_cleaned + size))
    rm -rf "${dir:?}"/* 2>/dev/null
  done

  # 合计本项
  step1_total=$((apt_size + sys_cleaned))
  total_freed_kb=$((total_freed_kb + step1_total))
  echo -e "  ${GREEN}✓ APT及系统缓存已清理 (释放: $(format_size $step1_total))${RESET}"

  # --- 2. 残留配置清理  ---
  echo -e "${YELLOW}[2/6] 扫描已卸载软件的残留配置(RC)...${RESET}"
  rc_count=$(dpkg -l | grep "^rc" | wc -l)
  if [ "$rc_count" -gt 0 ]; then
    dpkg -l | grep "^rc" | awk '{print $2}' | xargs -r apt-get -y purge >/dev/null 2>&1
    echo -e "  ${GREEN}✓ 清理了 $rc_count 个残留配置${RESET}"
  else
    echo -e "  ${GRAY}✓ 无残留配置需清理${RESET}"
  fi

  # --- 3. 日志清理与截断  ---
  echo -e "${YELLOW}[3/6] 深度清理系统日志...${RESET}"
  log_freed=0

  # 3.1 截断大日志 (>50MB)
  large_logs=$(find /var/log -type f -name "*.log" -size +50M 2>/dev/null)
  if [ -n "$large_logs" ]; then
    large_logs_size=$(find /var/log -type f -name "*.log" -size +50M -print0 | xargs -0 du -ck 2>/dev/null | tail -1 | awk '{print $1}')
    find /var/log -type f -name "*.log" -size +50M -exec truncate -s 0 {} \; 2>/dev/null
    log_freed=$((log_freed + large_logs_size))
    echo -e "  ${GREEN}✓ 已截断过大的活动日志文件${RESET}"
  fi

  # 3.2 Systemd Journal
  if command -v journalctl >/dev/null 2>&1; then
    journalctl --vacuum-time=1d >/dev/null 2>&1
    echo -e "  ${GREEN}✓ Systemd 日志已优化 (保留最近1天)${RESET}"
  fi

  # 3.3 旧日志文件 (*.gz, *.old)
  old_logs_size=$(find /var/log -type f \( -name "*.gz" -o -name "*.old" -o -name "*.log.*" \) -print0 | xargs -0 du -ck 2>/dev/null | tail -1 | awk '{print $1}')
  if [ -n "$old_logs_size" ] && [ "$old_logs_size" -gt 0 ]; then
    find /var/log -type f \( -name "*.gz" -o -name "*.old" -o -name "*.log.*" \) -delete 2>/dev/null
    log_freed=$((log_freed + old_logs_size))
  fi

  # 3.4 清理/tmp (24小时前)
  tmp_size=$(find /tmp -type f -mtime +1 -print0 2>/dev/null | xargs -0 du -ck 2>/dev/null | tail -1 | awk '{print $1}')
  find /tmp -type f -mtime +1 -delete 2>/dev/null
  find /tmp -type d -empty -delete 2>/dev/null
  [ -n "$tmp_size" ] && log_freed=$((log_freed + tmp_size))

  total_freed_kb=$((total_freed_kb + log_freed))
  echo -e "  ${GREEN}✓ 日志与临时文件清理完成 (释放: $(format_size $log_freed))${RESET}"

  # --- 4. Snap清理  ---
  if command -v snap >/dev/null 2>&1; then
    echo -e "${YELLOW}[4/6] 正在清理 Snap 旧版本缓存...${RESET}"
    snap_before=$(get_dir_size_kb "/var/lib/snapd/snaps")
    snap set system refresh.retain=2 2>/dev/null
    snap list --all | awk '/disabled/{print $1, $3}' |
      while read snapname revision; do
        snap remove "$snapname" --revision="$revision" >/dev/null 2>&1
      done
    snap_after=$(get_dir_size_kb "/var/lib/snapd/snaps")
    snap_freed=$((snap_before - snap_after))
    if [ "$snap_freed" -lt 0 ]; then snap_freed=0; fi
    total_freed_kb=$((total_freed_kb + snap_freed))
    echo -e "  ${GREEN}✓ Snap 缓存清理完成 (释放: $(format_size $snap_freed))${RESET}"
  else
    echo -e "${YELLOW}[4/6] Snap 未安装，跳过${RESET}"
  fi

  # --- 5. 语言环境缓存  ---
  echo -e "${YELLOW}[5/6] 检查编程语言与开发缓存...${RESET}"
  lang_freed=0

  cache_checks=(
    "NPM|npm|$HOME/.npm"
    "Yarn|yarn|$HOME/.cache/yarn"
    "Pip|pip|$HOME/.cache/pip"
    "Go|go|$HOME/go/pkg/mod"
  )

  for check in "${cache_checks[@]}"; do
    IFS='|' read -r name cmd path <<<"$check"
    if command -v "$cmd" >/dev/null 2>&1 && [ -d "$path" ]; then
      size=$(get_dir_size_kb "$path")
      if [ "$size" -gt 0 ]; then
        lang_freed=$((lang_freed + size))
        rm -rf "${path:?}"/* 2>/dev/null
        echo -e "  ${GREEN}✓ 清理 $name 缓存 ($(format_size $size))${RESET}"
      fi
    fi
  done

  total_freed_kb=$((total_freed_kb + lang_freed))
  if [ "$lang_freed" -eq 0 ]; then
    echo -e "  ${GRAY}✓ 无开发环境缓存需清理${RESET}"
  fi

  # --- 6. 用户级缓存 ---
  echo -e "${YELLOW}[6/6] 清理用户缩略图缓存...${RESET}"
  user_freed=0
  for user_home in /home/*; do
    [ -d "$user_home" ] || continue
    cache_dir="$user_home/.cache"

    if [ -d "$cache_dir" ]; then
      s1=$(get_dir_size_kb "$cache_dir")
      user_freed=$((user_freed + s1))
      rm -rf "$cache_dir"/* 2>/dev/null
    fi
  done
  # root 的缓存
  if [ -d "/root/.cache" ]; then
    s_root=$(get_dir_size_kb "/root/.cache")
    user_freed=$((user_freed + s_root))
    rm -rf "/root/.cache"/* 2>/dev/null
  fi

  total_freed_kb=$((total_freed_kb + user_freed))
  echo -e "  ${GREEN}✓ 用户缓存清理完成 (释放: $(format_size $user_freed))${RESET}"

  # --- 总结报告 ---
  echo -e "${BOLD}${CYAN}--------------------------------------------------${RESET}"
  echo -e "${BOLD}${GREEN}🎉 系统清理全部完成！${RESET}"
  echo -e "${BOLD}共计释放空间: ${YELLOW}$(format_size $total_freed_kb)${RESET}"

  df -h / | tail -1 | awk -v G="${GREEN}" -v R="${RESET}" '{printf "%s当前磁盘剩余空间: %s (使用率: %s)%s\n", G, $4, $5, R}'
  echo -e "${BOLD}${CYAN}--------------------------------------------------${RESET}"
}

# ---------- Fail2Ban 管理 (逻辑闭环: 白名单子菜单 + 状态全显 + 交互优化) ----------
manage_fail2ban() {
  # [逻辑] 检测服务守护进程状态
  check_f2b_running() {
    if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active fail2ban >/dev/null 2>&1; then
      return 0
    else
      return 1
    fi
  }

  # [逻辑] 检测特定 Jail 运行状态
  check_jail_status() {
    local jail_name=$1
    if check_f2b_running; then
      if fail2ban-client status "$jail_name" >/dev/null 2>&1; then return 0; fi
    fi
    return 1
  }

  # [逻辑] 配置文件写入函数
  set_jail_config() {
    local jail=$1; local state=$2; local file="/etc/fail2ban/jail.local"
    [ ! -f "$file" ] && { cp /etc/fail2ban/jail.conf "$file" 2>/dev/null || touch "$file"; }
    # 确保段落存在
    if ! grep -q "^\[$jail\]" "$file"; then echo -e "\n[$jail]" >> "$file"; fi
    # 修改或添加 enabled
    local has_key=$(sed -n "/^\[$jail\]/,/^\[/p" "$file" | grep "enabled")
    if [ -n "$has_key" ]; then
      sed -i "/^\[$jail\]/,/^\[/{s/enabled[[:space:]]*=.*/enabled = $state/}" "$file"
    else
      sed -i "/^\[$jail\]/a enabled = $state" "$file"
    fi
  }

  # [逻辑] 补全缺失参数
  ensure_jail_params() {
    local jail=$1; local file="/etc/fail2ban/jail.local"
    case $jail in
      "sshd")
        if ! sed -n "/^\[sshd\]/,/^\[/p" "$file" | grep -q "logpath"; then
           sed -i "/^\[sshd\]/a logpath = /var/log/auth.log\nport = ssh\nmaxretry = 5\nbantime = 10m\nfilter = sshd" "$file"
        fi ;;
      "recidive")
        if ! sed -n "/^\[recidive\]/,/^\[/p" "$file" | grep -q "banaction"; then
           sed -i "/^\[recidive\]/a logpath = /var/log/fail2ban.log\nbanaction = iptables-allports\nbantime = 1w\nfindtime = 1d\nmaxretry = 3" "$file"
        fi ;;
    esac
  }

  while true; do
    clear
    
    # --- 状态检测逻辑 ---
    if check_f2b_running; then
      f2b_state="${GREEN}运行中 (Active)${RESET}"
      is_running=true
      
      # SSH 保护状态
      if check_jail_status "sshd"; then
        ssh_display="${GREEN}●${RESET} 关闭 SSH 保护"
        ssh_status="on"
      else
        ssh_display="${GRAY}○${RESET} 开启 SSH 保护"
        ssh_status="off"
      fi

      # 顽固监狱状态
      if check_jail_status "recidive"; then
        rec_display="${GREEN}●${RESET} 关闭 顽固监狱 (Recidive)"
        rec_status="on"
      else
        rec_display="${GRAY}○${RESET} 开启 顽固监狱 (Recidive)"
        rec_status="off"
      fi
    else
      f2b_state="${RED}未运行 / 未安装${RESET}"
      is_running=false
      ssh_display="${GRAY}○${RESET} 开启 SSH 保护 (需服务运行)"
      rec_display="${GRAY}○${RESET} 开启 顽固监狱 (需服务运行)"
    fi
    
    db_file="/var/lib/fail2ban/fail2ban.sqlite3"
    db_size="N/A"
    [ -f "$db_file" ] && db_size=$(ls -lh "$db_file" | awk '{print $5}')

    # --- 菜单显示 ---
    echo -e "${BOLD}${CYAN}🛡️  Fail2Ban 防爆破高级管理${RESET}"
    echo -e "${CYAN}==================================================${RESET}"
    echo -e "Fail2Ban状态: $f2b_state"
    echo -e "数据库占用: ${YELLOW}$db_size${RESET}"
    echo -e "${CYAN}--------------------------------------------------${RESET}"
    
    if [ "$is_running" = true ]; then echo -e "${GREEN}  1.${RESET} 重启 Fail2Ban 服务"; else echo -e "${YELLOW}  1.${RESET} 安装并启动 Fail2Ban"; fi
    echo -e "${YELLOW}  2.${RESET} 卸载 Fail2Ban"
    
    echo -e "${CYAN}--- 监控与操作 ---${RESET}"
    echo -e "${YELLOW}  3.${RESET} 查看 SSH 封禁列表"
    echo -e "${YELLOW}  4.${RESET} 手动封禁 IP (Ban IP) ${GREEN}[增强版]${RESET}"
    echo -e "${YELLOW}  5.${RESET} 手动解封 IP (Unban) ${GREEN}[列表回显]${RESET}"
    echo -e "${YELLOW}  6.${RESET} 白名单管理 (Whitelist) ${GREEN}[独立子菜单]${RESET}"
    echo -e "${YELLOW}  7.${RESET} 查看详细运行日志"
    
    echo -e "${CYAN}--- 策略与维护 ---${RESET}"
    if [ "$is_running" = true ]; then
      echo -e "${YELLOW}  8.${RESET} 修改 SSH 封禁策略 (次数/时长)"
      echo -e "${YELLOW}  9.${RESET} $rec_display"
      echo -e "${YELLOW} 10.${RESET} $ssh_display"
      echo -e "${YELLOW} 11.${RESET} 清理数据库 (当前: $db_size)"
    else
      echo -e "${GRAY}  8. 修改封禁策略 (需启动服务)${RESET}"
      echo -e "${GRAY}  9. $rec_display${RESET}"
      echo -e "${GRAY} 10. $ssh_display${RESET}"
      echo -e "${GRAY} 11. 清理数据库 (需启动服务)${RESET}"
    fi
    
    echo -e "${YELLOW}  0.${RESET} 返回主菜单"
    echo -e "${CYAN}==================================================${RESET}"

    read -p "请输入选项: " f_choice

    case $f_choice in
    1)
      if [ "$is_running" = true ]; then
        echo -e "${CYAN}正在重启服务...${RESET}"
        systemctl restart fail2ban; echo -e "${GREEN}[√] 服务已重启${RESET}"; sleep 2
      else
        check_apt_lock || return 1
        echo -e "${CYAN}正在安装 Fail2Ban...${RESET}"
        apt-get update && apt-get install -y fail2ban
        set_jail_config "sshd" "true"; ensure_jail_params "sshd"
        systemctl enable fail2ban; systemctl restart fail2ban
        echo -e "${GREEN}[√] 安装并启动成功${RESET}"; sleep 3
      fi
      ;;
    2)
      echo -e "${RED}警告: 即将卸载 Fail2Ban。${RESET}"
      read -p "确认? [y/N]: " c
      if [[ "$c" =~ ^[Yy]$ ]]; then
        systemctl stop fail2ban; systemctl disable fail2ban
        check_apt_lock || return 1
        apt-get purge -y fail2ban; rm -rf /etc/fail2ban /var/lib/fail2ban
        echo -e "${GREEN}[√] 卸载完成${RESET}"; SKIP_PAUSE=true; return 0
      fi
      ;;
    3)
      check_f2b_running || continue
      echo -e "${CYAN}SSH 监狱:${RESET}"; fail2ban-client status sshd 2>/dev/null || echo "未启动"
      if check_jail_status "recidive"; then echo -e "\n${CYAN}顽固监狱:${RESET}"; fail2ban-client status recidive; fi
      read -p "按 Enter 继续..."
      ;;
    4)
      check_f2b_running || continue
      read -p "封禁 IP [0 返回]: " ip
      [ "$ip" == "0" ] || [ -z "$ip" ] && continue
      echo -e "  1. 临时封禁 (Fail2Ban)\n  2. 永久封禁 (hosts.deny)"
      read -p "选择: " m
      case $m in
        1) fail2ban-client set sshd banip "$ip" && echo -e "${GREEN}[√] 已加入 Jail${RESET}" ;;
        2) echo "ALL: $ip" >> /etc/hosts.deny && echo -e "${GREEN}[√] 已加入黑名单${RESET}" ;;
      esac
      read -p "按 Enter 继续..."
      ;;
    5)
      check_f2b_running || continue
      # [UX优化] 先展示当前封禁列表，方便复制
      echo -e "${CYAN}>>> 当前被封禁的 IP (SSH):${RESET}"
      fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" | sed 's/Banned IP list://g' | xargs -n 5
      echo -e "${CYAN}--------------------------${RESET}"
      
      read -p "请输入要解封的 IP [0 返回]: " ip
      [ "$ip" != "0" ] && [ -n "$ip" ] && {
        fail2ban-client set sshd unbanip "$ip" 2>/dev/null
        fail2ban-client set recidive unbanip "$ip" 2>/dev/null
        [ -f /etc/hosts.deny ] && sed -i "/$ip/d" /etc/hosts.deny
        echo -e "${GREEN}[√] 已解封${RESET}"
      }
      read -p "按 Enter 继续..."
      ;;
    6)
      check_f2b_running || continue
      # --- 白名单子菜单循环 ---
      while true; do
        clear
        echo -e "${BOLD}${CYAN}📋 Fail2Ban 白名单管理${RESET}"
        echo -e "${CYAN}==================================================${RESET}"
        
        # 实时获取列表
        cur_runtime_list=$(fail2ban-client get sshd ignoreip 2>/dev/null)
        cur_file_list=$(grep "^ignoreip" /etc/fail2ban/jail.local | cut -d= -f2 | xargs)
        
        echo -e "当前生效(Runtime): ${GREEN}${cur_runtime_list:-无}${RESET}"
        echo -e "配置文件(Config):  ${YELLOW}${cur_file_list:-无}${RESET}"
        echo -e "${CYAN}--------------------------------------------------${RESET}"
        echo -e "${YELLOW}  1.${RESET} 添加 IP (Add IP) ${GRAY}[智能建议]${RESET}"
        echo -e "${YELLOW}  2.${RESET} 删除 IP (Remove IP)"
        echo -e "${YELLOW}  0.${RESET} 返回上一级"
        echo -e "${CYAN}==================================================${RESET}"
        
        read -p "请输入选项: " wl_choice
        case $wl_choice in
          1)
            # 智能获取建议 IP
            suggest_ip=$(echo "${SSH_CLIENT%% *}"); [ -z "$suggest_ip" ] && suggest_ip=$(echo "${SSH_CONNECTION%% *}")
            read -p "请输入要添加的 IP (默认 $suggest_ip): " add_ip
            [ -z "$add_ip" ] && add_ip="$suggest_ip"
            
            if [ -n "$add_ip" ]; then
                # 1. 运行时添加
                fail2ban-client set sshd addignoreip "$add_ip" >/dev/null 2>&1
                
                # 2. 写入配置文件 (持久化)
                if grep -q "ignoreip =" /etc/fail2ban/jail.local; then
                   # 防止重复添加
                   if ! grep "^ignoreip" /etc/fail2ban/jail.local | grep -q "$add_ip"; then
                       sed -i "/ignoreip =/s/$/ $add_ip/" /etc/fail2ban/jail.local
                   fi
                else
                   # 如果没有 ignoreip 行，插入一行
                   sed -i "/^\[DEFAULT\]/a ignoreip = 127.0.0.1/8 $add_ip" /etc/fail2ban/jail.local
                fi
                echo -e "${GREEN}[√] 添加成功: $add_ip${RESET}"
                sleep 1
            fi
            ;;
          2)
            read -p "请输入要删除的 IP: " del_ip
            if [ -n "$del_ip" ]; then
                # 1. 运行时删除
                fail2ban-client set sshd delignoreip "$del_ip" >/dev/null 2>&1
                
                # 2. 配置文件删除 (使用 sed 精确匹配空格+IP)
                if [ -f /etc/fail2ban/jail.local ]; then
                    sed -i "s/ $del_ip//g" /etc/fail2ban/jail.local
                fi
                echo -e "${GREEN}[√] 删除操作已执行: $del_ip${RESET}"
                sleep 1
            fi
            ;;
          0) break ;; # 退出子菜单
          *) echo -e "${RED}无效选项${RESET}"; sleep 1 ;;
        esac
      done
      ;;
    7)
      check_f2b_running || continue
      echo -e "${CYAN}>>> 最后 20 条日志:${RESET}"
      tail -n 20 /var/log/fail2ban.log 2>/dev/null
      echo -e "${CYAN}--------------------------------------------------${RESET}"
      read -p "是否进入实时监控模式 (按 Ctrl+C 退出)? [y/N]: " view_live
      if [[ "$view_live" =~ ^[Yy]$ ]]; then
        tail -f /var/log/fail2ban.log
      fi
      ;;
    8)
      check_f2b_running || continue
      read -p "最大失败次数 (5): " mr; read -p "封禁时长 (1h): " bt
      if [[ "$mr" =~ ^[0-9]+$ ]] && [ -n "$bt" ]; then
         sed -i '/^\[sshd\]/,/^\[/ { /maxretry/d; /bantime/d }' /etc/fail2ban/jail.local
         sed -i "/^\[sshd\]/a maxretry = $mr\nbantime = $bt" /etc/fail2ban/jail.local
         echo -e "${CYAN}正在应用策略...${RESET}"
         systemctl restart fail2ban; echo -e "${GREEN}[√] 已更新${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    9)
      check_f2b_running || continue
      if [ "$rec_status" == "on" ]; then
        read -p "确认关闭 顽固监狱 (Recidive)? [y/N]: " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
            set_jail_config "recidive" "false"; systemctl restart fail2ban; sleep 2; echo -e "${YELLOW}[!] 已关闭${RESET}"
        else
            echo -e "${YELLOW}操作已取消${RESET}"
        fi
      else
        set_jail_config "recidive" "true"; ensure_jail_params "recidive"
        systemctl restart fail2ban; sleep 2; echo -e "${GREEN}[√] 已开启${RESET}"
      fi
      ;;
    10)
      check_f2b_running || continue
      if [ "$ssh_status" == "on" ]; then
        read -p "确认关闭 SSH 保护? [y/N]: " c
        [[ "$c" =~ ^[Yy]$ ]] && { set_jail_config "sshd" "false"; systemctl restart fail2ban; sleep 2; echo -e "${YELLOW}[!] 已关闭${RESET}"; }
      else
        set_jail_config "sshd" "true"; ensure_jail_params "sshd"
        systemctl restart fail2ban; sleep 2; echo -e "${GREEN}[√] 已开启${RESET}"
      fi
      ;;
    11)
      if [ -f "$db_file" ]; then
        read -p "确认清理数据库? [y/N]: " c
        [[ "$c" =~ ^[Yy]$ ]] && { systemctl stop fail2ban; rm -f "$db_file"; systemctl start fail2ban; echo -e "${GREEN}[√] 完成${RESET}"; }
      else echo -e "${YELLOW}文件不存在${RESET}"; fi
      read -p "按 Enter 继续..."
      ;;
    0) SKIP_PAUSE=true; break ;;
    *) echo -e "${RED}无效选项${RESET}"; sleep 1 ;;
    esac
  done
}

# ---------- 系统时区设置 ----------
change_timezone() {
  echo -e "${CYAN}>>> 修改系统时区...${RESET}"

  while true; do
    current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone)
    current_time=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "当前时区: ${GREEN}$current_tz${RESET}"
    echo -e "当前时间: ${GREEN}$current_time${RESET}"

    echo -e "\n${CYAN}请选择目标时区:${RESET}"
    echo -e "  ${GREEN}1${RESET}) 亚洲/上海 (Beijing/Shanghai, UTC+8)"
    echo -e "  ${GREEN}2${RESET}) 亚洲/香港 (Hong Kong, UTC+8)"
    echo -e "  ${GREEN}3${RESET}) 亚洲/台北 (Taipei, UTC+8)"
    echo -e "  ${GREEN}4${RESET}) 亚洲/东京 (Tokyo, UTC+9)"
    echo -e "  ${GREEN}5${RESET}) 美国/纽约 (New York, UTC-5/UTC-4)"
    echo -e "  ${GREEN}6${RESET}) 欧洲/伦敦 (London, UTC+0/UTC+1)"
    echo -e "  ${GREEN}7${RESET}) 交互式选择 (Region -> City)"
    echo -e "  ${YELLOW}0.${RESET} 取消/返回"

    read -p "请输入选项 [0-7]: " tz_choice

    local target_tz=""

    case $tz_choice in
    1)
      target_tz="Asia/Shanghai"
      break
      ;;
    2)
      target_tz="Asia/Hong_Kong"
      break
      ;;
    3)
      target_tz="Asia/Taipei"
      break
      ;;
    4)
      target_tz="Asia/Tokyo"
      break
      ;;
    5)
      target_tz="America/New_York"
      break
      ;;
    6)
      target_tz="Europe/London"
      break
      ;;
    7)
      while true; do
        echo -e "\n${CYAN}>>> 区域选择 (输入 0 退出):${RESET}"
        regions=($(find /usr/share/zoneinfo -maxdepth 1 -type d | sed 's|/usr/share/zoneinfo/||' | grep -v "^\." | grep -v "^posix" | grep -v "^right" | grep -E "^[A-Z]" | sort))

        for i in "${!regions[@]}"; do
          printf "  ${GREEN}%-2d${RESET}) %s\n" "$((i + 1))" "${regions[$i]}"
        done
        echo -e "  ${YELLOW}0.${RESET} 返回上一级"

        read -p "请输入区域编号: " region_idx

        if [[ "$region_idx" == "0" ]]; then break; fi

        if [[ "$region_idx" =~ ^[0-9]+$ ]] && [ "$region_idx" -ge 1 ] && [ "$region_idx" -le "${#regions[@]}" ]; then
          selected_region="${regions[$((region_idx - 1))]}"
          echo -e "${YELLOW}已选择区域: $selected_region${RESET}"

          while true; do
            echo -e "\n${CYAN}>>> 城市选择 (输入 0 返回区域列表):${RESET}"
            cities=($(ls "/usr/share/zoneinfo/$selected_region" | grep -v "^posix" | grep -v "^right" | sort))

            local total_cities=${#cities[@]}
            local num_cols=3
            local rows=$(((total_cities + num_cols - 1) / num_cols))

            for ((r = 0; r < rows; r++)); do
              idx1=$r
              if [ $idx1 -lt $total_cities ]; then
                printf "${GREEN}%-3d${RESET}) %-20s" "$((idx1 + 1))" "${cities[$idx1]}"
              fi
              idx2=$((r + rows))
              if [ $idx2 -lt $total_cities ]; then
                printf "${GREEN}%-3d${RESET}) %-20s" "$((idx2 + 1))" "${cities[$idx2]}"
              fi
              idx3=$((r + rows * 2))
              if [ $idx3 -lt $total_cities ]; then
                printf "${GREEN}%-3d${RESET}) %-20s" "$((idx3 + 1))" "${cities[$idx3]}"
              fi
              echo ""
            done

            echo -e "  ${YELLOW}0.${RESET} 返回上一级"

            read -p "请输入城市编号: " city_idx

            if [[ "$city_idx" == "0" ]]; then break; fi

            if [[ "$city_idx" =~ ^[0-9]+$ ]] && [ "$city_idx" -ge 1 ] && [ "$city_idx" -le "${#cities[@]}" ]; then
              selected_city="${cities[$((city_idx - 1))]}"
              target_tz="$selected_region/$selected_city"
              break 2
            else
              echo -e "${RED}无效的城市编号${RESET}"
            fi
          done
        else
          echo -e "${RED}无效的区域编号${RESET}"
        fi
      done
      if [ -z "$target_tz" ]; then continue; fi
      ;;
    0)
      SKIP_PAUSE=true
      return 0
      ;;
    *)
      echo -e "${RED}无效选项${RESET}"
      continue
      ;;
    esac

    if [ -n "$target_tz" ]; then
      if [ -f "/usr/share/zoneinfo/$target_tz" ]; then
        if command -v timedatectl >/dev/null 2>&1; then
          timedatectl set-timezone "$target_tz"
        else
          ln -sf "/usr/share/zoneinfo/$target_tz" /etc/localtime
          echo "$target_tz" >/etc/timezone
        fi
        echo -e "${GREEN}[√] 时区已修改为: $target_tz${RESET}"
        echo -e "当前时间: $(date '+%Y-%m-%d %H:%M:%S')"
        hwclock --systohc 2>/dev/null
      else
        echo -e "${RED}[!] 错误: 未找到时区文件 /usr/share/zoneinfo/$target_tz${RESET}"
      fi
    fi
  done
}
# ... (change_timezone 函数结束的大括号 '}' 之后)

# ---------- 修改主机名 ----------
change_hostname() {
  while true; do
    clear
    echo -e "${CYAN}>>> 修改系统主机名 (Hostname)${RESET}"

    local current_hostname=$(hostname)
    echo -e "当前主机名: ${GREEN}${current_hostname}${RESET}"
    echo -e "${CYAN}--------------------------------------------------${RESET}"

    # --- 步骤 1: 输入阶段 (支持返回) ---
    echo -e "${GRAY}提示: 建议使用英文、数字和连字符(-)，例如: vps-hk-01${RESET}"
    read -p "请输入新的主机名 (输入 0 取消): " new_hostname

    # 返回主菜单逻辑
    if [ "$new_hostname" == "0" ]; then
      SKIP_PAUSE=true
      return 0
    fi

    # 空值检查 -> 返回重输
    if [ -z "$new_hostname" ]; then
      echo -e "${RED}[!] 错误：主机名不能为空，请重新输入。${RESET}"
      sleep 1
      continue
    fi

    # 格式检查 (简单正则) -> 返回重输
    if [[ ! "$new_hostname" =~ ^[a-zA-Z0-9.-]+$ ]]; then
      echo -e "${RED}[!] 错误：主机名包含非法字符，仅支持字母、数字、点和横杠。${RESET}"
      sleep 2
      continue
    fi

    # 一致性检查 -> 返回重输
    if [ "$new_hostname" == "$current_hostname" ]; then
      echo -e "${YELLOW}[!] 新主机名与当前一致，无需修改。${RESET}"
      read -p "按 Enter 返回..."
      return 0
    fi

    # --- 步骤 2: 确认阶段 (支持“反悔”返回上一步) ---
    echo -e "\n${CYAN}即将执行以下变更:${RESET}"
    echo -e "  旧主机名: ${RED}${current_hostname}${RESET}"
    echo -e "  新主机名: ${GREEN}${new_hostname}${RESET}"

    echo -e "\n${YELLOW}确认修改吗?${RESET}"
    echo -e "  [y] 确认修改"
    echo -e "  [n] 重新输入 (返回上一步)"
    echo -e "  [0] 取消并退出"

    read -p "请输入选项: " confirm_choice

    case $confirm_choice in
    [yY] | [yY][eE][sS])
      # 用户确认，跳出循环执行修改
      break
      ;;
    0)
      # 用户取消
      SKIP_PAUSE=true
      return 0
      ;;
    *)
      # 用户选 n 或其他，循环继续，回到“输入阶段”
      continue
      ;;
    esac
  done

  # --- 步骤 3: 执行阶段 ---
  echo -e "\n${CYAN}>>> 正在应用修改...${RESET}"

  # 3.1 修改主机名
  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "$new_hostname"
  else
    hostname "$new_hostname"
    [ -f /etc/hostname ] && echo "$new_hostname" >/etc/hostname
  fi

  # 3.2 同步修改 /etc/hosts
  if [ -f /etc/hosts ]; then
    if grep -q "$current_hostname" /etc/hosts; then
      sed -i "s/$current_hostname/$new_hostname/g" /etc/hosts
      echo -e "${GREEN}[√] 已更新 /etc/hosts 映射${RESET}"
    else
      # 如果找不到旧名，追加新的一行
      if ! grep -q "$new_hostname" /etc/hosts; then
        echo "127.0.1.1 $new_hostname" >>/etc/hosts
        echo -e "${GREEN}[√] 已添加 /etc/hosts 映射${RESET}"
      fi
    fi
  fi

  # --- 步骤 4: 结果验证 ---
  local verify_name=$(hostname)
  if [ "$verify_name" == "$new_hostname" ]; then
    echo -e "${GREEN}[√] 主机名修改成功!${RESET}"
    echo -e "${YELLOW}注意: 请重新连接 SSH (断开重连) 以使终端提示符更新。${RESET}"
  else
    echo -e "${RED}[!] 修改可能未完全生效，检测到的主机名为: $verify_name${RESET}"
  fi
}

# ---------- [增强] 端口占用速查 (终极兼容版: Awk纯逻辑+Bash渲染) ----------
show_port_usage() {
  # 依赖检查
  install_deps "ss" "awk"

  while true; do
    clear
    echo -e "${BOLD}${CYAN}🔌 端口占用情况速查 (TCP/UDP)${RESET}"
    echo -e "${CYAN}========================================================================${RESET}"
    echo -e "${YELLOW}Proto  Local Address             Port    PID/Process Name${RESET}"
    echo -e "${CYAN}------------------------------------------------------------------------${RESET}"

    # 核心逻辑变更：
    # 1. awk 不再处理任何颜色，只输出纯文本数据，中间用 '|' 分隔。
    # 2. while read 循环读取数据，由 Bash 进行颜色判断和格式化输出。
    # 3. 这种方式彻底避开了 awk 正则引擎对颜色代码的误判。

    ss -tulnp | sed '1d' | awk '{
            proto = $1
            local_addr = $5
            process_raw = $7

            # --- 提取端口和IP ---
            # 兼容 IPv4 和 IPv6 格式
            n = split(local_addr, a, ":")
            port = a[n]

            # 重组 IP (移除端口部分)
            ip = ""
            for(i=1; i<n; i++){
                ip = ip a[i]
                if(i < n-1) ip = ip ":"
            }

            # --- 清洗进程信息 ---
            # 原始: users:(("nginx",pid=1445,fd=6),...) -> 目标: nginx(1445)
            proc_info = "未知"
            idx = index(process_raw, "users:((\"")
            if (idx > 0) {
                raw_str = substr(process_raw, idx + 9)
                split(raw_str, p_arr, ",")
                p_name = p_arr[1]
                gsub(/"/, "", p_name) # 去掉引号

                # 提取PID
                p_pid = ""
                for(k in p_arr) {
                    if(index(p_arr[k], "pid=") > 0) {
                        split(p_arr[k], pid_arr, "=")
                        p_pid = pid_arr[2]
                        break
                    }
                }
                proc_info = p_name "(" p_pid ")"
            }

            # 输出纯文本，用竖线分隔，交给 Bash 处理
            print proto "|" ip "|" port "|" proc_info
        }' | sort -k3 -n | head -n 30 |
      while IFS='|' read -r proto ip port proc_info; do
        # --- Bash 渲染层 ---
        # 在 Bash 中判断颜色，绝对安全
        current_color=""

        if [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" == "[::1]" ]]; then
          current_color="${GREEN}"
        elif [[ "$ip" == "0.0.0.0" ]] || [[ "$ip" == "*" ]] || [[ "$ip" == "[::]" ]]; then
          current_color="${RED}"
        else
          current_color="${RESET}" # 普通IP不染色
        fi

        # 格式化输出
        # 技巧：将颜色代码放在 %-25s 的外部，这样 printf 计算宽度时只计算 IP 字符长度
        # 从而完美保证表格对齐，不会因为颜色代码导致错位。
        printf "%-6s ${current_color}%-25s${RESET} %-7s %s\n" "$proto" "$ip" "$port" "$proc_info"
      done

    echo -e "${CYAN}========================================================================${RESET}"
    echo -e "${YELLOW}功能菜单:${RESET}"
    echo -e "  ${GREEN}1${RESET}) 刷新列表 (Refresh)"
    echo -e "  ${GREEN}2${RESET}) 强制结束进程 (Kill PID)"
    echo -e "  ${YELLOW}0${RESET}) 返回主菜单"

    read -p "请输入选项: " choice
    case $choice in
    1)
      continue
      ;;
    2)
      # [修改] 增加提示文本 (输入 0 返回)
      read -p "请输入要结束的 PID (数字, 输入 0 返回): " kill_pid

      # [新增] 增加 0 返回逻辑
      if [ "$kill_pid" == "0" ]; then
        echo -e "${YELLOW}操作已取消${RESET}"
        read -p "按 Enter 继续..."
        continue
      fi

      if [[ "$kill_pid" =~ ^[0-9]+$ ]]; then
        # 二次确认
        # 使用 ps 命令验证 PID 是否存在
        proc_name=$(ps -p "$kill_pid" -o comm= 2>/dev/null)
        if [ -z "$proc_name" ]; then
          echo -e "${RED}[!] 找不到 PID 为 $kill_pid 的进程${RESET}"
        else
          echo -e "${YELLOW}警告: 即将结束进程: $proc_name (PID: $kill_pid)${RESET}"
          read -p "确认执行吗? [y/N]: " confirm_kill
          if [[ "$confirm_kill" =~ ^[Yy]$ ]]; then
            kill -9 "$kill_pid"
            echo -e "${GREEN}[√] 进程已结束${RESET}"
          else
            echo -e "${YELLOW}操作已取消${RESET}"
          fi
        fi
      else
        echo -e "${RED}[!] PID 必须是数字${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    0)
      SKIP_PAUSE=true
      return 0
      ;;
    *)
      echo -e "${RED}无效选项${RESET}"
      sleep 1
      ;;
    esac
  done
}

# ---------- 计划任务管理 (增强版: 增加脚本权限自动检测 + 向导退出逻辑) ----------
manage_crontab() {
  # --- 1. 入口检测 ---
  if ! command -v crontab >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] 未检测到 Crontab 服务。${RESET}"
    read -p "是否立即安装 Cron? [y/N]: " install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
      check_apt_lock || return 1
      apt-get update && apt-get install -y cron
      systemctl enable cron
      systemctl start cron
      echo -e "${GREEN}[√] Cron 安装成功${RESET}"
    else
      return 0
    fi
  fi

  if ! systemctl is-active cron >/dev/null 2>&1; then
    systemctl start cron 2>/dev/null
    sleep 1
  fi

  while true; do
    clear
    echo -e "${BOLD}${CYAN}⏰ 计划任务管理 (Crontab)${RESET}"
    echo -e "${CYAN}==================================================${RESET}"

    if command -v crontab >/dev/null 2>&1; then
      if systemctl is-active cron >/dev/null 2>&1; then
        cron_status="${GREEN}运行中 (Active)${RESET}"
      else
        cron_status="${RED}未运行 (Inactive)${RESET}"
      fi
      task_count=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l)
    else
      cron_status="${RED}未安装${RESET}"
      task_count="N/A"
    fi

    echo -e "服务状态: $cron_status | 当前任务数: ${GREEN}$task_count${RESET}"
    echo -e "${CYAN}--------------------------------------------------${RESET}"

    if [[ "$task_count" != "N/A" ]] && [ "$task_count" -gt 0 ]; then
      echo -e "${YELLOW}任务预览:${RESET}"
      crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | head -n 3 | awk '{print "  " $0}'
      if [ "$task_count" -gt 3 ]; then echo -e "  ${GRAY}... (还有 $((task_count - 3)) 条)${RESET}"; fi
      echo -e "${CYAN}--------------------------------------------------${RESET}"
    fi

    echo -e "${YELLOW}  1.${RESET} 查看完整任务列表"
    echo -e "${YELLOW}  2.${RESET} 添加: 每日凌晨 3 点自动重启 (快捷)"
    echo -e "${YELLOW}  3.${RESET} 添加: 每周一凌晨 4 点清理日志 (快捷)"
    echo -e "${YELLOW}  4.${RESET} 添加: 自定义计划任务 ${GREEN}[向导模式]${RESET}"
    echo -e "${CYAN}--- 管理 ---${RESET}"
    echo -e "${YELLOW}  5.${RESET} 编辑: 手动编辑文件 (vi/nano)"
    echo -e "${YELLOW}  6.${RESET} 删除: 删除指定任务 [便捷]"
    echo -e "${YELLOW}  7.${RESET} 清空: 删除所有任务"
    echo -e "${CYAN}--- 维护 ---${RESET}"
    echo -e "${YELLOW}  8.${RESET} 备份: 导出当前任务列表"
    echo -e "${YELLOW}  9.${RESET} 恢复: 从备份文件导入"
    echo -e "${YELLOW} 10.${RESET} 日志: 查看 Crontab 运行日志"
    echo -e "${CYAN}--- 危险区域 ---${RESET}"
    echo -e "${YELLOW} 11.${RESET} ${RED}卸载 Cron 服务${RESET}"
    echo -e "${YELLOW}  0.${RESET} 返回主菜单"
    echo -e "${CYAN}==================================================${RESET}"

    read -p "请输入选项: " c_choice

    if [[ "$task_count" == "N/A" ]] && [[ "$c_choice" != "0" ]] && [[ "$c_choice" != "11" ]]; then
      echo -e "${RED}[!] 服务缺失，请选择卸载或返回。${RESET}"
      read -p "Wait..."
      continue
    fi

    case $c_choice in
    1)
      echo -e "${CYAN}>>> 完整任务列表:${RESET}"
      [ "$task_count" -eq 0 ] && echo -e "${GRAY}(无任务)${RESET}" || crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | nl -w2 -s'. '
      read -p "按 Enter 继续..."
      ;;
    2)
      (
        crontab -l 2>/dev/null
        echo "0 3 * * * /sbin/reboot"
      ) | grep -v "^$" | sort -u | crontab -
      echo -e "${GREEN}[√] 已添加${RESET}"
      read -p "按 Enter 继续..."
      ;;
    3)
      cmd="apt-get autoremove -y && apt-get clean && journalctl --vacuum-time=3d"
      (
        crontab -l 2>/dev/null
        echo "0 4 * * 1 $cmd"
      ) | grep -v "^$" | sort -u | crontab -
      echo -e "${GREEN}[√] 已添加${RESET}"
      read -p "按 Enter 继续..."
      ;;
    4)
      echo -e "${CYAN}>>> 添加自定义任务 (向导模式)${RESET}"
      echo -e "  ${GREEN}1.${RESET} 每分钟 (* * * * *)"
      echo -e "  ${GREEN}2.${RESET} 每小时 (0 * * * *)"
      echo -e "  ${GREEN}3.${RESET} 每天 (0 0 * * *)"
      echo -e "  ${GREEN}4.${RESET} 每周 (0 0 * * 0)"
      echo -e "  ${GREEN}5.${RESET} 每月 (0 0 1 * *)"
      echo -e "  ${GREEN}6.${RESET} 重启时 (@reboot)"
      echo -e "  ${YELLOW}7.${RESET} 手动输入"
      echo -e "  ${YELLOW}0.${RESET} 返回"

      read -p "频率编号: " cron_type
      local cron_time=""

      # [修改] 重写辅助函数，支持 q 退出
      read_range() {
        local p="$1"
        local min="$2"
        local max="$3"
        local v
        while true; do
          read -p "$p ($min-$max) [q 退出]: " v
          # [新增] 退出检测
          if [[ "$v" == "q" ]]; then
            echo "QUIT"
            return 0
          fi

          if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$min" ] && [ "$v" -le "$max" ]; then
            echo "$v"
            return 0
          fi
          echo -e "${RED}无效输入，请输入 $min-$max 之间的数字或 q 退出${RESET}" >&2
        done
      }

      case $cron_type in
      1) cron_time="* * * * *" ;;
      2)
        m=$(read_range "第几分钟" 0 59)
        if [ "$m" == "QUIT" ]; then continue; fi # [新增] 检测退出
        cron_time="$m * * * *"
        ;;
      3)
        h=$(read_range "小时" 0 23)
        if [ "$h" == "QUIT" ]; then continue; fi
        m=$(read_range "分钟" 0 59)
        if [ "$m" == "QUIT" ]; then continue; fi
        cron_time="$m $h * * *"
        ;;
      4)
        w=$(read_range "星期(0-6)" 0 6)
        if [ "$w" == "QUIT" ]; then continue; fi
        h=$(read_range "小时" 0 23)
        if [ "$h" == "QUIT" ]; then continue; fi
        m=$(read_range "分钟" 0 59)
        if [ "$m" == "QUIT" ]; then continue; fi
        cron_time="$m $h * * $w"
        ;;
      5)
        d=$(read_range "日期(1-31)" 1 31)
        if [ "$d" == "QUIT" ]; then continue; fi
        h=$(read_range "小时" 0 23)
        if [ "$h" == "QUIT" ]; then continue; fi
        m=$(read_range "分钟" 0 59)
        if [ "$m" == "QUIT" ]; then continue; fi
        cron_time="$m $h $d * *"
        ;;
      6) cron_time="@reboot" ;;
      7)
        read -p "输入表达式 (输入 0 返回): " cron_time
        if [ "$cron_time" == "0" ]; then continue; fi
        ;;
      0) continue ;;
      *)
        echo -e "${RED}无效选择${RESET}"
        sleep 1
        continue
        ;;
      esac

      echo -e "时间: ${YELLOW}$cron_time${RESET}"
      read -p "请输入命令 (绝对路径, 输入 0 返回): " cron_cmd
      if [ "$cron_cmd" == "0" ] || [ -z "$cron_cmd" ]; then continue; fi

      # --- [增强] 脚本权限自动检测 ---
      # 简单提取第一个字段作为文件路径
      cmd_path=$(echo "$cron_cmd" | awk '{print $1}')
      if [ -f "$cmd_path" ]; then
        if [ ! -x "$cmd_path" ]; then
          echo -e "${YELLOW}警告: 脚本 $cmd_path 没有执行权限 (x)${RESET}"
          read -p "是否自动赋予执行权限? [y/N]: " chmod_confirm
          if [[ "$chmod_confirm" =~ ^[Yy]$ ]]; then
            chmod +x "$cmd_path"
            echo -e "${GREEN}[√] 已赋予 +x 权限${RESET}"
          else
            echo -e "${RED}[!] 任务可能无法运行，请注意。${RESET}"
          fi
        fi
      fi
      # ------------------------------

      echo -e "${CYAN}添加任务: ${GREEN}$cron_time $cron_cmd${RESET}"
      read -p "确认? [y/N]: " confirm_add
      if [[ "$confirm_add" =~ ^[Yy]$ ]]; then
        (
          crontab -l 2>/dev/null
          echo "$cron_time $cron_cmd"
        ) | grep -v "^$" | sort -u | crontab -
        echo -e "${GREEN}[√] 成功${RESET}"
      fi
      read -p "按 Enter 继续..."
      ;;
    5)
      if command -v nano >/dev/null; then export EDITOR=nano; else export EDITOR=vi; fi
      crontab -e
      ;;
    6)
      if [ "$task_count" -gt 0 ]; then
        local tmp="${TEMP_DIR}/cron.tmp"
        crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" >"$tmp"
        nl -w2 -s'. ' "$tmp"
        read -p "删除编号 (0返回): " dn
        if [[ "$dn" =~ ^[0-9]+$ ]] && [ "$dn" -gt 0 ]; then
          sed -i "${dn}d" "$tmp"
          crontab "$tmp"
          echo -e "${GREEN}[√] 删除成功${RESET}"
        fi
        rm -f "$tmp"
      else echo -e "${YELLOW}无任务${RESET}"; fi
      read -p "按 Enter 继续..."
      ;;
    7)
      read -p "确认清空? [y/N]: " c
      [[ "$c" =~ ^[Yy]$ ]] && crontab -r && echo -e "${GREEN}[√] 已清空${RESET}"
      read -p "按 Enter 继续..."
      ;;
    8)
      bf="/root/cron_bak_$(date +%Y%m%d).txt"
      crontab -l >"$bf" 2>/dev/null
      echo -e "${GREEN}[√] 备份至 $bf${RESET}"
      read -p "按 Enter 继续..."
      ;;
    9)
      read -p "备份文件路径: " rf
      [ -f "$rf" ] && crontab "$rf" && echo -e "${GREEN}[√] 恢复成功${RESET}" || echo -e "${RED}文件不存在${RESET}"
      read -p "按 Enter 继续..."
      ;;
    10)
      if [ -f /var/log/syslog ]; then
        grep "CRON" /var/log/syslog | tail -20
      elif [ -f /var/log/cron.log ]; then
        tail -20 /var/log/cron.log
      else journalctl -u cron -n 20 --no-pager 2>/dev/null; fi
      read -p "按 Enter 继续..."
      ;;
    11)
      read -p "⚠️  确定卸载 Cron 服务? [y/N]: " un_c
      if [[ "$un_c" =~ ^[Yy]$ ]]; then
        systemctl stop cron
        apt-get purge -y cron
        rm -rf /var/spool/cron/crontabs
        echo -e "${GREEN}[√] 已卸载${RESET}"
        SKIP_PAUSE=true
        return 0
      fi
      ;;
    0)
      SKIP_PAUSE=true
      return 0
      ;;
    *)
      echo -e "${RED}无效${RESET}"
      sleep 1
      ;;
    esac
  done
}

# ---------- 主循环 (更新菜单逻辑) ----------
while true; do
  show_menu

  SKIP_PAUSE=false

  read -p "请输入选项编号: " choice
  case $choice in
  1) system_upgrade ;;
  2) enable_bbr ;;
  3) enable_swap ;;
  4) clean_kernels ;;
  5) change_ssh_port ;;
  6) modify_dns ;;
  7) manage_ipv6 ;;
  8) software_hub ;;
  9) stream_test ;;
  10) net_test ;;
  11) full_test ;;
  12) benchmark ;;
  13) system_cleanup ;;
  14) manage_fail2ban ;;
  15) manage_ufw ;;
  16) change_timezone ;;
  17) show_port_usage ;;
  18) manage_crontab ;;
  19) change_hostname ;;
  0)
    echo -e "${GREEN}已退出脚本，再见！${RESET}"
    exit 0
    ;;
  *)
    echo -e "${RED}[×] 无效选项，请重新输入${RESET}"
    SKIP_PAUSE=true
    sleep 1
    ;;
  esac

  if [ "$SKIP_PAUSE" = false ]; then
    echo -e ""
    read -p "按 Enter 返回主菜单..."
  fi
done
