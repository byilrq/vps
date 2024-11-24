manage_swap_cache() {
    echo "=== 硬盘缓存设置工具 ==="

    # 检查是否是 root 用户
    if [ "$EUID" -ne 0 ]; then
        echo "错误：请以 root 权限运行此脚本。"
        exit 1
    fi

    # 检测当前的 Swap 配置
    echo "检测当前 Swap 缓存配置..."
    current_swap=$(free -m | awk '/Swap:/ {print $2}')
    echo "当前 Swap 缓存大小为：${current_swap} MB"
    echo ""

    # 获取用户输入的缓存大小
    read -p "请输入要设置的 Swap 缓存大小（单位：MB，建议值 >= 512）： " size_mb

    # 验证输入是否为正整数
    if ! [[ "$size_mb" =~ ^[0-9]+$ ]] || [ "$size_mb" -lt 1 ]; then
        echo "错误：请输入有效的正整数（单位：MB）。"
        exit 1
    fi

    # 确认用户输入
    echo "准备设置 Swap 缓存大小为 ${size_mb} MB..."
    read -p "是否继续操作？(y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "操作已取消。"
        exit 0
    fi

    # 停用现有的 Swap 文件（如果存在）
    if swapon --show | grep -q "/swapfile"; then
        echo "检测到现有 Swap 文件，正在停用..."
        swapoff /swapfile
        echo "已停用现有 Swap 文件。"
        echo "正在删除旧的 Swap 文件..."
        rm -f /swapfile
    fi

    # 创建新的 Swap 文件
    echo "正在创建新的 Swap 文件 (${size_mb} MB)..."
    fallocate -l "${size_mb}M" /swapfile
    if [ $? -ne 0 ]; then
        echo "错误：无法创建 Swap 文件，请检查磁盘空间或权限。"
        exit 1
    fi

    # 设置权限和格式化
    chmod 600 /swapfile
    echo "正在格式化 Swap 文件..."
    mkswap /swapfile

    # 启用新的 Swap
    echo "正在启用 Swap 文件..."
    swapon /swapfile

    # 更新 /etc/fstab 以支持开机自动挂载
    if ! grep -q "^/swapfile" /etc/fstab; then
        echo "正在配置开机自动挂载..."
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi

    # 显示新的 Swap 配置
    echo "新的 Swap 文件已启用。当前 Swap 配置："
    swapon --show
    free -h

    echo "操作完成！新的 Swap 缓存大小为 ${size_mb} MB。"
}

