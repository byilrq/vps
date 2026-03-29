#!/bin/bash
#=============================================================================
# BBR v3 终极优化脚本 - 融合版
# 功能：结合 XanMod 官方内核的稳定性 + 专业队列算法调优
# 特点：安全性 + 性能 双优化
# 版本：2.0 Ultimate Edition
#=============================================================================

# 颜色定义
gl_hong='\033[31m'
gl_lv='\033[32m'
gl_huang='\033[33m'
gl_bai='\033[0m'
gl_kjlan='\033[96m'
gl_zi='\033[35m'

# GitHub 代理设置
gh_proxy="https://"

# 配置文件路径（使用独立文件，不破坏系统配置）
SYSCTL_CONF="/etc/sysctl.d/99-bbr-ultimate.conf"

#=============================================================================
# 工具函数
#=============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${gl_hong}错误: ${gl_bai}此脚本需要 root 权限运行！"
        echo "请使用: sudo bash $0"
        exit 1
    fi
}

break_end() {
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按任意键继续..."
    read -n 1 -s -r -p ""
    echo ""
}

install_package() {
    for package in "$@"; do
        if ! command -v "$package" &>/dev/null; then
            echo -e "${gl_huang}正在安装 $package...${gl_bai}"
            if command -v apt &>/dev/null; then
                apt update -y > /dev/null 2>&1
                apt install -y "$package" > /dev/null 2>&1
            else
                echo "错误: 不支持的包管理器"
                return 1
            fi
        fi
    done
}

check_disk_space() {
    local required_gb=$1
    local required_space_mb=$((required_gb * 1024))
    local available_space_mb=$(df -m / | awk 'NR==2 {print $4}')

    if [ "$available_space_mb" -lt "$required_space_mb" ]; then
        echo -e "${gl_huang}警告: ${gl_bai}磁盘空间不足！"
        echo "当前可用: $((available_space_mb/1024))G | 最低需求: ${required_gb}G"
        read -e -p "是否继续？(Y/N): " continue_choice
        case "$continue_choice" in
            [Yy]) return 0 ;;
            *) exit 1 ;;
        esac
    fi
}

check_swap() {
    local swap_total=$(free -m | awk 'NR==3{print $2}')
    
    if [ "$swap_total" -eq 0 ]; then
        echo -e "${gl_huang}检测到无虚拟内存，正在创建 1G SWAP...${gl_bai}"
        fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
        chmod 600 /swapfile
        mkswap /swapfile > /dev/null 2>&1
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${gl_lv}虚拟内存创建成功${gl_bai}"
    fi
}

add_swap() {
    local new_swap=$1  # 获取传入的参数（单位：MB）
    
    echo -e "${gl_kjlan}=== 调整虚拟内存 ===${gl_bai}"
    
    # 获取当前系统中所有的 swap 分区
    local swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')
    
    # 遍历并删除所有的 swap 分区
    for partition in $swap_partitions; do
        swapoff "$partition" 2>/dev/null
        wipefs -a "$partition" 2>/dev/null
        mkswap -f "$partition" 2>/dev/null
    done
    
    # 确保 /swapfile 不再被使用
    swapoff /swapfile 2>/dev/null
    
    # 删除旧的 /swapfile
    rm -f /swapfile
    
    echo "正在创建 ${new_swap}MB 虚拟内存..."
    
    # 创建新的 swap 分区
    fallocate -l ${new_swap}M /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=${new_swap}
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1
    swapon /swapfile
    
    # 更新 /etc/fstab
    sed -i '/\/swapfile/d' /etc/fstab
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    
    # Alpine Linux 特殊处理
    if [ -f /etc/alpine-release ]; then
        echo "nohup swapon /swapfile" > /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local 2>/dev/null
    fi
    
    echo -e "${gl_lv}虚拟内存大小已调整为 ${new_swap}MB${gl_bai}"
}

calculate_optimal_swap() {
    # 获取物理内存（MB）
    local mem_total=$(free -m | awk 'NR==2{print $2}')
    local recommended_swap
    local reason
    
    echo -e "${gl_kjlan}=== 智能计算虚拟内存大小 ===${gl_bai}"
    echo ""
    echo -e "检测到物理内存: ${gl_huang}${mem_total}MB${gl_bai}"
    echo ""
    echo "计算过程："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 根据内存大小计算推荐 SWAP
    if [ "$mem_total" -lt 512 ]; then
        # < 512MB: SWAP = 1GB（固定）
        recommended_swap=1024
        reason="内存极小（< 512MB），固定推荐 1GB"
        echo "→ 内存 < 512MB"
        echo "→ 推荐固定 1GB SWAP"
        
    elif [ "$mem_total" -lt 1024 ]; then
        # 512MB ~ 1GB: SWAP = 内存 × 2
        recommended_swap=$((mem_total * 2))
        reason="内存较小（512MB-1GB），推荐 2 倍内存"
        echo "→ 内存在 512MB - 1GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 2"
        echo "→ ${mem_total}MB × 2 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 2048 ]; then
        # 1GB ~ 2GB: SWAP = 内存 × 1.5
        recommended_swap=$((mem_total * 3 / 2))
        reason="内存适中（1-2GB），推荐 1.5 倍内存"
        echo "→ 内存在 1GB - 2GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 1.5"
        echo "→ ${mem_total}MB × 1.5 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 4096 ]; then
        # 2GB ~ 4GB: SWAP = 内存 × 1
        recommended_swap=$mem_total
        reason="内存充足（2-4GB），推荐与内存同大小"
        echo "→ 内存在 2GB - 4GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 1"
        echo "→ ${mem_total}MB × 1 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 8192 ]; then
        # 4GB ~ 8GB: SWAP = 4GB（固定）
        recommended_swap=4096
        reason="内存较多（4-8GB），固定推荐 4GB"
        echo "→ 内存在 4GB - 8GB 之间"
        echo "→ 固定推荐 4GB SWAP"
        
    else
        # >= 8GB: SWAP = 4GB（固定）
        recommended_swap=4096
        reason="内存充裕（≥ 8GB），固定推荐 4GB"
        echo "→ 内存 ≥ 8GB"
        echo "→ 固定推荐 4GB SWAP"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${gl_lv}计算结果：${gl_bai}"
    echo -e "  物理内存:   ${gl_huang}${mem_total}MB${gl_bai}"
    echo -e "  推荐 SWAP:  ${gl_huang}${recommended_swap}MB${gl_bai}"
    echo -e "  总可用内存: ${gl_huang}$((mem_total + recommended_swap))MB${gl_bai}"
    echo ""
    echo -e "${gl_zi}推荐理由: ${reason}${gl_bai}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 确认是否应用
    read -e -p "$(echo -e "${gl_huang}是否应用此配置？(Y/N): ${gl_bai}")" confirm
    
    case "$confirm" in
        [Yy])
            add_swap "$recommended_swap"
            return 0
            ;;
        *)
            echo "已取消"
            sleep 2
            return 1
            ;;
    esac
}

manage_swap() {
    while true; do
        clear
        echo -e "${gl_kjlan}=== 虚拟内存管理 ===${gl_bai}"
        
        local mem_total=$(free -m | awk 'NR==2{print $2}')
        local swap_used=$(free -m | awk 'NR==3{print $3}')
        local swap_total=$(free -m | awk 'NR==3{print $2}')
        local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')
        
        echo -e "物理内存:     ${gl_huang}${mem_total}MB${gl_bai}"
        echo -e "当前虚拟内存: ${gl_huang}$swap_info${gl_bai}"
        echo "------------------------------------------------"
        echo "1. 分配 1024M (1GB) - 固定配置"
        echo "2. 分配 2048M (2GB) - 固定配置"
        echo "3. 分配 4096M (4GB) - 固定配置"
        echo "4. 智能计算推荐值 - 自动计算最佳配置"
        echo "0. 返回主菜单"
        echo "------------------------------------------------"
        read -e -p "请输入选择: " choice
        
        case "$choice" in
            1)
                add_swap 1024
                break_end
                ;;
            2)
                add_swap 2048
                break_end
                ;;
            3)
                add_swap 4096
                break_end
                ;;
            4)
                calculate_optimal_swap
                if [ $? -eq 0 ]; then
                    break_end
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "无效选择"
                sleep 2
                ;;
        esac
    done
}

server_reboot() {
    read -e -p "$(echo -e "${gl_huang}提示: ${gl_bai}现在重启服务器使配置生效吗？(Y/N): ")" rboot
    case "$rboot" in
        [Yy])
            echo "正在重启..."
            reboot
            ;;
        *)
            echo "已取消，请稍后手动执行: reboot"
            ;;
    esac
}

#=============================================================================
# 配置冲突检测与清理（避免被其他 sysctl 覆盖）
#=============================================================================
check_and_clean_conflicts() {
    echo -e "${gl_kjlan}=== 检查 sysctl 配置冲突 ===${gl_bai}"
    local conflicts=()
    # 搜索 /etc/sysctl.d/ 下可能覆盖 tcp_rmem/tcp_wmem 的高序号文件
    for conf in /etc/sysctl.d/[0-9]*-*.conf /etc/sysctl.d/[0-9][0-9][0-9]-*.conf; do
        [ -f "$conf" ] || continue
        [ "$conf" = "$SYSCTL_CONF" ] && continue
        if grep -qE "(^|\s)net\.ipv4\.tcp_(rmem|wmem)" "$conf" 2>/dev/null; then
            base=$(basename "$conf")
            num=$(echo "$base" | sed -n 's/^\([0-9]\+\).*/\1/p')
            # 99 及以上优先生效，可能覆盖本脚本
            if [ -n "$num" ] && [ "$num" -ge 99 ]; then
                conflicts+=("$conf")
            fi
        fi
    done

    # 主配置文件直接设置也会覆盖
    local has_sysctl_conflict=0
    if [ -f /etc/sysctl.conf ] && grep -qE "(^|\s)net\.ipv4\.tcp_(rmem|wmem)" /etc/sysctl.conf 2>/dev/null; then
        has_sysctl_conflict=1
    fi

    if [ ${#conflicts[@]} -eq 0 ] && [ $has_sysctl_conflict -eq 0 ]; then
        echo -e "${gl_lv}✓ 未发现可能的覆盖配置${gl_bai}"
        return 0
    fi

    echo -e "${gl_huang}发现可能的覆盖配置：${gl_bai}"
    for f in "${conflicts[@]}"; do
        echo "  - $f"; grep -E "net\.ipv4\.tcp_(rmem|wmem)" "$f" | sed 's/^/      /'
    done
    [ $has_sysctl_conflict -eq 1 ] && echo "  - /etc/sysctl.conf (含 tcp_rmem/tcp_wmem)"

    read -e -p "是否自动禁用/注释这些覆盖配置？(Y/N): " ans
    case "$ans" in
        [Yy])
            # 注释 /etc/sysctl.conf 中相关行
            if [ $has_sysctl_conflict -eq 1 ]; then
                sed -i.bak '/^net\.ipv4\.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i.bak '/^net\.ipv4\.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i.bak '/^net\.core\.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i.bak '/^net\.core\.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
                echo -e "${gl_lv}✓ 已注释 /etc/sysctl.conf 中的相关配置${gl_bai}"
            fi
            # 将高优先级冲突文件重命名禁用
            for f in "${conflicts[@]}"; do
                mv "$f" "${f}.disabled.$(date +%Y%m%d_%H%M%S)" 2>/dev/null && \
                  echo -e "${gl_lv}✓ 已禁用: $(basename "$f")${gl_bai}"
            done
            ;;
        *)
            echo -e "${gl_huang}已跳过自动清理，可能导致新配置未完全生效${gl_bai}"
            ;;
    esac
}

#=============================================================================
# 立即生效与防分片函数（无需重启）
#=============================================================================

# 获取需应用 qdisc 的网卡（排除常见虚拟接口）
eligible_ifaces() {
    for d in /sys/class/net/*; do
        [ -e "$d" ] || continue
        dev=$(basename "$d")
        case "$dev" in
            lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
        esac
        echo "$dev"
    done
}

# tc fq 立即生效（无需重启）
apply_tc_fq_now() {
    if ! command -v tc >/dev/null 2>&1; then
        echo -e "${gl_huang}警告: 未检测到 tc（iproute2），跳过 fq 应用${gl_bai}"
        return 0
    fi
    local applied=0
    for dev in $(eligible_ifaces); do
        tc qdisc replace dev "$dev" root fq 2>/dev/null && applied=$((applied+1))
    done
    [ $applied -gt 0 ] && echo -e "${gl_lv}已对 $applied 个网卡应用 fq（即时生效）${gl_bai}" || echo -e "${gl_huang}未发现可应用 fq 的网卡${gl_bai}"
}

# MSS clamp（防分片）自动启用
apply_mss_clamp() {
    local action=$1  # enable|disable
    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${gl_huang}警告: 未检测到 iptables，跳过 MSS clamp${gl_bai}"
        return 0
    fi
    if [ "$action" = "enable" ]; then
        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
          || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
        iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
    fi
}

#=============================================================================
# BBR 配置函数（改进版 - 确保配置生效）
#=============================================================================

bbr_configure() {
    local qdisc=$1
    local description=$2
    
    echo -e "${gl_kjlan}=== 配置 BBR v3 + ${qdisc} ===${gl_bai}"
    
    # 步骤 1：清理冲突配置
    echo "正在检查配置冲突..."
    
    # 1.1 备份主配置文件（如果还没备份）
    if [ -f /etc/sysctl.conf ] && ! [ -f /etc/sysctl.conf.bak.original ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.original
        echo "已备份: /etc/sysctl.conf -> /etc/sysctl.conf.bak.original"
    fi
    
    # 1.2 注释掉 /etc/sysctl.conf 中的 TCP 缓冲区配置（避免覆盖）
    if [ -f /etc/sysctl.conf ]; then
        sed -i '/^net.ipv4.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.ipv4.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.core.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.core.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
        echo "已清理 /etc/sysctl.conf 中的冲突配置"
    fi
    
    # 1.3 删除可能存在的软链接
    if [ -L /etc/sysctl.d/99-sysctl.conf ]; then
        rm -f /etc/sysctl.d/99-sysctl.conf
        echo "已删除配置软链接"
    fi
    
    # 步骤 0.5：检查并清理可能覆盖的新旧配置冲突
    check_and_clean_conflicts

    # 步骤 2：创建独立配置文件
    echo "正在创建新配置..."
    cat > "$SYSCTL_CONF" << EOF
# BBR v3 Ultimate Configuration
# Generated on $(date)

# 队列调度算法
net.core.default_qdisc=${qdisc}

# 拥塞控制算法
net.ipv4.tcp_congestion_control=bbr

# TCP 缓冲区优化（16MB 上限，适合小内存 VPS）
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF

    # 步骤 3：应用配置（只加载此配置文件）
    echo "正在应用配置..."
    sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1
    
    # 步骤 3.5：立即应用 fq，并启用 MSS clamp（无需重启）
    echo "正在应用队列与防分片（无需重启）..."
    apply_tc_fq_now >/dev/null 2>&1
    apply_mss_clamp enable >/dev/null 2>&1

    # 步骤 4：验证配置是否真正生效
    local actual_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    local actual_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local actual_wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')
    local actual_rmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    
    echo ""
    echo -e "${gl_kjlan}=== 配置验证 ===${gl_bai}"
    
    # 验证队列算法
    if [ "$actual_qdisc" = "$qdisc" ]; then
        echo -e "队列算法: ${gl_lv}$actual_qdisc ✓${gl_bai}"
    else
        echo -e "队列算法: ${gl_huang}$actual_qdisc (期望: $qdisc) ⚠${gl_bai}"
    fi
    
    # 验证拥塞控制
    if [ "$actual_cc" = "bbr" ]; then
        echo -e "拥塞控制: ${gl_lv}$actual_cc ✓${gl_bai}"
    else
        echo -e "拥塞控制: ${gl_huang}$actual_cc (期望: bbr) ⚠${gl_bai}"
    fi
    
    # 验证发送缓冲区
    if [ "$actual_wmem" = "16777216" ]; then
        echo -e "发送缓冲区: ${gl_lv}16MB ✓${gl_bai}"
    else
        echo -e "发送缓冲区: ${gl_huang}$(echo "scale=2; $actual_wmem / 1048576" | bc)MB (期望: 16MB) ⚠${gl_bai}"
    fi
    
    # 验证接收缓冲区
    if [ "$actual_rmem" = "16777216" ]; then
        echo -e "接收缓冲区: ${gl_lv}16MB ✓${gl_bai}"
    else
        echo -e "接收缓冲区: ${gl_huang}$(echo "scale=2; $actual_rmem / 1048576" | bc)MB (期望: 16MB) ⚠${gl_bai}"
    fi
    
    echo ""
    
    # 最终判断
    if [ "$actual_qdisc" = "$qdisc" ] && [ "$actual_cc" = "bbr" ] && \
       [ "$actual_wmem" = "16777216" ] && [ "$actual_rmem" = "16777216" ]; then
        echo -e "${gl_lv}✅ BBR v3 + ${qdisc} 配置完成并已生效！${gl_bai}"
        echo -e "${gl_zi}优化说明: ${description}${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 配置已保存但部分参数未生效${gl_bai}"
        echo -e "${gl_huang}建议执行以下操作：${gl_bai}"
        echo "1. 检查是否有其他配置文件冲突"
        echo "2. 重启服务器使配置完全生效: reboot"
    fi
}

bbr_configure_2gb() {
    local qdisc=$1
    local description=$2
    
    echo -e "${gl_kjlan}=== 配置 BBR v3 + ${qdisc} (2GB+ 内存优化) ===${gl_bai}"
    
    # 步骤 1：清理冲突配置
    echo "正在检查配置冲突..."
    
    # 1.1 备份主配置文件（如果还没备份）
    if [ -f /etc/sysctl.conf ] && ! [ -f /etc/sysctl.conf.bak.original ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.original
        echo "已备份: /etc/sysctl.conf -> /etc/sysctl.conf.bak.original"
    fi
    
    # 1.2 注释掉 /etc/sysctl.conf 中的 TCP 缓冲区配置（避免覆盖）
    if [ -f /etc/sysctl.conf ]; then
        sed -i '/^net.ipv4.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.ipv4.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.core.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
        sed -i '/^net.core.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
        echo "已清理 /etc/sysctl.conf 中的冲突配置"
    fi
    
    # 1.3 删除可能存在的软链接
    if [ -L /etc/sysctl.d/99-sysctl.conf ]; then
        rm -f /etc/sysctl.d/99-sysctl.conf
        echo "已删除配置软链接"
    fi
    
    # 步骤 0.5：检查并清理可能覆盖的新旧配置冲突
    check_and_clean_conflicts

    # 步骤 2：创建独立配置文件（2GB 内存版本）
    echo "正在创建新配置..."
    cat > "$SYSCTL_CONF" << EOF
# BBR v3 Ultimate Configuration (2GB+ Memory)
# Generated on $(date)

# 队列调度算法
net.core.default_qdisc=${qdisc}

# 拥塞控制算法
net.ipv4.tcp_congestion_control=bbr

# TCP 缓冲区优化（32MB 上限，256KB 默认值，适合 2GB+ 内存 VPS）
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 262144 33554432
net.ipv4.tcp_wmem=4096 262144 33554432

# 高级优化（适合高带宽场景）
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=16384
net.ipv4.tcp_max_syn_backlog=8192
EOF

    # 步骤 3：应用配置（只加载此配置文件）
    echo "正在应用配置..."
    sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1
    
    # 步骤 3.5：立即应用 fq，并启用 MSS clamp（无需重启）
    echo "正在应用队列与防分片（无需重启）..."
    apply_tc_fq_now >/dev/null 2>&1
    apply_mss_clamp enable >/dev/null 2>&1

    # 步骤 4：验证配置是否真正生效
    local actual_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    local actual_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local actual_wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')
    local actual_rmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    
    echo ""
    echo -e "${gl_kjlan}=== 配置验证 ===${gl_bai}"
    
    # 验证队列算法
    if [ "$actual_qdisc" = "$qdisc" ]; then
        echo -e "队列算法: ${gl_lv}$actual_qdisc ✓${gl_bai}"
    else
        echo -e "队列算法: ${gl_huang}$actual_qdisc (期望: $qdisc) ⚠${gl_bai}"
    fi
    
    # 验证拥塞控制
    if [ "$actual_cc" = "bbr" ]; then
        echo -e "拥塞控制: ${gl_lv}$actual_cc ✓${gl_bai}"
    else
        echo -e "拥塞控制: ${gl_huang}$actual_cc (期望: bbr) ⚠${gl_bai}"
    fi
    
    # 验证发送缓冲区
    if [ "$actual_wmem" = "33554432" ]; then
        echo -e "发送缓冲区: ${gl_lv}32MB ✓${gl_bai}"
    else
        echo -e "发送缓冲区: ${gl_huang}$(echo "scale=2; $actual_wmem / 1048576" | bc)MB (期望: 32MB) ⚠${gl_bai}"
    fi
    
    # 验证接收缓冲区
    if [ "$actual_rmem" = "33554432" ]; then
        echo -e "接收缓冲区: ${gl_lv}32MB ✓${gl_bai}"
    else
        echo -e "接收缓冲区: ${gl_huang}$(echo "scale=2; $actual_rmem / 1048576" | bc)MB (期望: 32MB) ⚠${gl_bai}"
    fi
    
    echo ""
    
    # 最终判断
    if [ "$actual_qdisc" = "$qdisc" ] && [ "$actual_cc" = "bbr" ] && \
       [ "$actual_wmem" = "33554432" ] && [ "$actual_rmem" = "33554432" ]; then
        echo -e "${gl_lv}✅ BBR v3 + ${qdisc} (2GB配置) 完成并已生效！${gl_bai}"
        echo -e "${gl_zi}优化说明: ${description}${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 配置已保存但部分参数未生效${gl_bai}"
        echo -e "${gl_huang}建议执行以下操作：${gl_bai}"
        echo "1. 检查是否有其他配置文件冲突"
        echo "2. 重启服务器使配置完全生效: reboot"
    fi
}

#=============================================================================
# 状态检查函数
#=============================================================================

check_bbr_status() {
    echo -e "${gl_kjlan}=== 当前系统状态 ===${gl_bai}"
    echo "内核版本: $(uname -r)"
    
    if command -v sysctl &>/dev/null; then
        local congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
        local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
        echo "拥塞控制算法: $congestion"
        echo "队列调度算法: $qdisc"
        
        # 检查 BBR 版本
        if command -v modinfo &>/dev/null; then
            local bbr_version=$(modinfo tcp_bbr 2>/dev/null | awk '/^version:/ {print $2}')
            if [ -n "$bbr_version" ]; then
                if [ "$bbr_version" = "3" ]; then
                    echo -e "BBR 版本: ${gl_lv}v${bbr_version} ✓${gl_bai}"
                else
                    echo -e "BBR 版本: ${gl_huang}v${bbr_version} (不是 v3)${gl_bai}"
                fi
            fi
        fi
    fi
    
    if dpkg -l 2>/dev/null | grep -q 'linux-xanmod'; then
        echo -e "XanMod 内核: ${gl_lv}已安装 ✓${gl_bai}"
        return 0
    else
        echo -e "XanMod 内核: ${gl_huang}未安装${gl_bai}"
        return 1
    fi
}

#=============================================================================
# XanMod 内核安装（官方源）
#=============================================================================

install_xanmod_kernel() {
    clear
    echo -e "${gl_kjlan}=== 安装 XanMod 内核与 BBR v3 ===${gl_bai}"
    echo "视频教程: https://www.bilibili.com/video/BV14K421x7BS"
    echo "------------------------------------------------"
    echo "支持系统: Debian/Ubuntu (x86_64 & ARM64)"
    echo -e "${gl_huang}警告: 将升级 Linux 内核，请提前备份重要数据！${gl_bai}"
    echo "------------------------------------------------"
    read -e -p "确定继续安装吗？(Y/N): " choice

    case "$choice" in
        [Yy])
            ;;
        *)
            echo "已取消安装"
            return 1
            ;;
    esac
    
    # 检测 CPU 架构
    local cpu_arch=$(uname -m)
    
    # ARM 架构特殊处理
    if [ "$cpu_arch" = "aarch64" ]; then
        echo -e "${gl_kjlan}检测到 ARM64 架构，使用专用安装脚本${gl_bai}"
        bash <(curl -sL jhb.ovh/jb/bbrv3arm.sh)
        if [ $? -eq 0 ]; then
            echo -e "${gl_lv}ARM BBR v3 安装完成${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}安装失败${gl_bai}"
            return 1
        fi
    fi
    
    # x86_64 架构安装流程
    # 检查系统支持
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
            echo -e "${gl_hong}错误: 仅支持 Debian 和 Ubuntu 系统${gl_bai}"
            return 1
        fi
    else
        echo -e "${gl_hong}错误: 无法确定操作系统类型${gl_bai}"
        return 1
    fi
    
    # 环境准备
    check_disk_space 3
    check_swap
    install_package wget gnupg
    
    # 添加 XanMod GPG 密钥
    echo "正在添加 XanMod 仓库密钥..."
    wget -qO - ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/archive.key | \
        gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    
    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}密钥下载失败，尝试官方源...${gl_bai}"
        wget -qO - https://dl.xanmod.org/archive.key | \
            gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    fi
    
    # 添加 XanMod 仓库
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | \
        tee /etc/apt/sources.list.d/xanmod-release.list > /dev/null
    
    # 检测 CPU 架构版本
    echo "正在检测 CPU 支持的最优内核版本..."
    local version=$(wget -q ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/check_x86-64_psabi.sh && \
                   chmod +x check_x86-64_psabi.sh && \
                   ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')
    
    if [ -z "$version" ]; then
        echo -e "${gl_huang}自动检测失败，使用默认版本 v3${gl_bai}"
        version="3"
    fi
    
    echo -e "${gl_lv}将安装: linux-xanmod-x64v${version}${gl_bai}"
    
    # 安装 XanMod 内核
    apt update -y
    apt install -y linux-xanmod-x64v$version
    
    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}内核安装失败！${gl_bai}"
        rm -f /etc/apt/sources.list.d/xanmod-release.list
        rm -f check_x86-64_psabi.sh*
        return 1
    fi
    
    # 清理临时文件
    rm -f /etc/apt/sources.list.d/xanmod-release.list
    rm -f check_x86-64_psabi.sh*
    
    echo -e "${gl_lv}XanMod 内核安装成功！${gl_bai}"
    echo -e "${gl_huang}提示: 请先重启系统加载新内核，然后再配置 BBR${gl_bai}"
    return 0
}


#=============================================================================
# 详细状态显示
#=============================================================================

show_detailed_status() {
    clear
    echo -e "${gl_kjlan}=== 系统详细信息 ===${gl_bai}"
    echo ""
    
    echo "操作系统: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
    echo "内核版本: $(uname -r)"
    echo "CPU 架构: $(uname -m)"
    echo ""
    
    if command -v sysctl &>/dev/null; then
        echo "TCP 拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
        echo "队列调度算法: $(sysctl -n net.core.default_qdisc)"
        echo ""
        
        echo "可用拥塞控制算法:"
        sysctl net.ipv4.tcp_available_congestion_control
        echo ""
        
        # BBR 模块信息
        if command -v modinfo &>/dev/null; then
            local bbr_info=$(modinfo tcp_bbr 2>/dev/null)
            if [ -n "$bbr_info" ]; then
                echo "BBR 模块详情:"
                echo "$bbr_info" | grep -E "version|description"
            fi
        fi
    fi
    
    echo ""
    if dpkg -l 2>/dev/null | grep -q 'linux-xanmod'; then
        echo -e "${gl_lv}XanMod 内核已安装${gl_bai}"
        dpkg -l | grep linux-xanmod | head -3
    else
        echo -e "${gl_huang}XanMod 内核未安装${gl_bai}"
    fi
    
    echo ""
    if [ -f "$SYSCTL_CONF" ]; then
        echo -e "${gl_lv}BBR 配置文件存在: $SYSCTL_CONF${gl_bai}"
        echo "配置内容:"
        cat "$SYSCTL_CONF"
    else
        echo -e "${gl_huang}BBR 配置文件不存在${gl_bai}"
    fi
    
    echo ""
    break_end
}

#=============================================================================
# 主菜单
#=============================================================================

show_main_menu() {
    clear
    check_bbr_status
    local is_installed=$?
    
    echo ""
    echo -e "${gl_zi}╔════════════════════════════════════════════╗${gl_bai}"
    echo -e "${gl_zi}║   BBR v3 终极优化脚本 - Ultimate Edition  ║${gl_bai}"
    echo -e "${gl_zi}╚════════════════════════════════════════════╝${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}[内核管理]${gl_bai}"
    
    if [ $is_installed -eq 0 ]; then
        echo "1. 更新 XanMod 内核"
        echo "2. 卸载 XanMod 内核"
    else
        echo "1. 安装 XanMod 内核 + BBR v3"
    fi
    
    echo ""
    echo -e "${gl_kjlan}[BBR 配置]${gl_bai}"
    echo "3. 快速启用 BBR + FQ（≤1GB 内存）"
    echo "4. 快速启用 BBR + FQ（2GB+ 内存）"
    echo ""
    echo -e "${gl_kjlan}[系统工具]${gl_bai}"
    echo "5. 虚拟内存管理"
    echo ""
    echo -e "${gl_kjlan}[系统信息]${gl_bai}"
    echo "6. 查看详细状态"
    echo "7. 性能测试建议"
    echo ""
    echo "0. 退出脚本"
    echo "------------------------------------------------"
    read -e -p "请输入选择: " choice
    
    case $choice in
        1)
            if [ $is_installed -eq 0 ]; then
                # 更新内核
                update_xanmod_kernel
                if [ $? -eq 0 ]; then
                    server_reboot
                fi
            else
                install_xanmod_kernel
                if [ $? -eq 0 ]; then
                    server_reboot
                fi
            fi
            ;;
        2)
            if [ $is_installed -eq 0 ]; then
                uninstall_xanmod
            fi
            ;;
        3)
            bbr_configure "fq" "通用场景优化（≤1GB 内存，16MB 缓冲区）"
            break_end
            ;;
        4)
            bbr_configure_2gb "fq" "通用场景优化（2GB+ 内存，32MB 缓冲区）"
            break_end
            ;;
        5)
            manage_swap
            ;;
        6)
            show_detailed_status
            ;;
        7)
            show_performance_test
            ;;
        0)
            echo "退出脚本"
            exit 0
            ;;
        *)
            echo "无效选择"
            sleep 2
            ;;
    esac
}

update_xanmod_kernel() {
    clear
    echo -e "${gl_kjlan}=== 更新 XanMod 内核 ===${gl_bai}"
    echo "------------------------------------------------"
    
    # 获取当前内核版本
    local current_kernel=$(uname -r)
    echo -e "当前内核版本: ${gl_huang}${current_kernel}${gl_bai}"
    echo ""
    
    # 检测 CPU 架构
    local cpu_arch=$(uname -m)
    
    # ARM 架构提示
    if [ "$cpu_arch" = "aarch64" ]; then
        echo -e "${gl_huang}ARM64 架构暂不支持自动更新${gl_bai}"
        echo "建议卸载后重新安装以获取最新版本"
        break_end
        return 1
    fi
    
    # x86_64 架构更新流程
    echo "正在检查可用更新..."
    
    # 添加 XanMod 仓库（如果不存在）
    if [ ! -f /etc/apt/sources.list.d/xanmod-release.list ]; then
        echo "正在添加 XanMod 仓库..."
        
        # 添加密钥
        wget -qO - ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/archive.key | \
            gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes 2>/dev/null
        
        if [ $? -ne 0 ]; then
            wget -qO - https://dl.xanmod.org/archive.key | \
                gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes 2>/dev/null
        fi
        
        # 添加仓库
        echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | \
            tee /etc/apt/sources.list.d/xanmod-release.list > /dev/null
    fi
    
    # 更新软件包列表
    echo "正在更新软件包列表..."
    apt update -y > /dev/null 2>&1
    
    # 检查已安装的 XanMod 内核包
    local installed_packages=$(dpkg -l | grep 'linux-.*xanmod' | awk '{print $2}')
    
    if [ -z "$installed_packages" ]; then
        echo -e "${gl_hong}错误: 未检测到已安装的 XanMod 内核${gl_bai}"
        break_end
        return 1
    fi
    
    echo -e "已安装的内核包:"
    echo "$installed_packages" | while read pkg; do
        echo "  - $pkg"
    done
    echo ""
    
    # 检查是否有可用更新
    local upgradable=$(apt list --upgradable 2>/dev/null | grep xanmod)
    
    if [ -z "$upgradable" ]; then
        echo -e "${gl_lv}✅ 当前内核已是最新版本！${gl_bai}"
        break_end
        return 0
    fi
    
    echo -e "${gl_huang}发现可用更新:${gl_bai}"
    echo "$upgradable"
    echo ""
    
    read -e -p "确定更新 XanMod 内核吗？(Y/N): " confirm
    
    case "$confirm" in
        [Yy])
            echo ""
            echo "正在更新内核..."
            apt install --only-upgrade -y $(echo "$installed_packages" | tr '\n' ' ')
            
            if [ $? -eq 0 ]; then
                # 清理仓库文件（避免日常 apt update 时出错）
                rm -f /etc/apt/sources.list.d/xanmod-release.list
                
                echo ""
                echo -e "${gl_lv}✅ XanMod 内核更新成功！${gl_bai}"
                echo -e "${gl_huang}⚠️  请重启系统以加载新内核${gl_bai}"
                return 0
            else
                echo ""
                echo -e "${gl_hong}❌ 内核更新失败${gl_bai}"
                break_end
                return 1
            fi
            ;;
        *)
            echo "已取消更新"
            break_end
            return 1
            ;;
    esac
}

uninstall_xanmod() {
    echo -e "${gl_huang}警告: 即将卸载 XanMod 内核${gl_bai}"
    read -e -p "确定继续吗？(Y/N): " confirm
    
    case "$confirm" in
        [Yy])
            apt purge -y 'linux-*xanmod1*'
            update-grub
            rm -f "$SYSCTL_CONF"
            echo -e "${gl_lv}XanMod 内核已卸载${gl_bai}"
            server_reboot
            ;;
        *)
            echo "已取消"
            ;;
    esac
}

show_performance_test() {
    clear
    echo -e "${gl_kjlan}=== 性能测试建议 ===${gl_bai}"
    echo ""
    echo "1. 验证 BBR v3 版本:"
    echo "   modinfo tcp_bbr | grep version"
    echo ""
    echo "2. 检查当前配置:"
    echo "   sysctl net.ipv4.tcp_congestion_control"
    echo "   sysctl net.core.default_qdisc"
    echo ""
    echo "3. 带宽测试:"
    echo "   wget -O /dev/null http://cachefly.cachefly.net/10gb.test"
    echo ""
    echo "4. 延迟测试:"
    echo "   ping -c 100 8.8.8.8"
    echo ""
    echo "5. iperf3 测试:"
    echo "   iperf3 -c speedtest.example.com"
    echo ""
    break_end
}

#=============================================================================
# 脚本入口
#=============================================================================

main() {
    check_root
    
    # 命令行参数支持
    if [ "$1" = "-i" ] || [ "$1" = "--install" ]; then
        install_xanmod_kernel
        if [ $? -eq 0 ]; then
            echo ""
            echo "安装完成后，请重启并运行以下命令配置 BBR:"
            echo "sudo $0 --configure"
        fi
        exit 0
    elif [ "$1" = "-c" ] || [ "$1" = "--configure" ]; then
        configure_bbr_qdisc
        exit 0
    fi
    
    # 交互式菜单
    while true; do
        show_main_menu
    done
}

# 执行主函数
main "$@"
