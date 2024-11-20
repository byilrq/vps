#!/bin/bash

# 创建或调整 Swap 缓存的函数
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
    read -p "请输入要设置的 Swap 缓存大小（单位：MB）： " size_mb

    # 验证输入是否为数字
    if ! [[ "$size_mb" =~ ^[0-9]+$ ]]; then
        echo "错误：请输入有效的数字。"
        exit 1
    fi

    # 转换为 GB 并显示计划操作
    size_gb=$(echo "$size_mb / 1024" | bc -l)
    printf "准备设置 Swap 缓存大小为 %.2f GB (%d MB)...\n" "$size_gb" "$size_mb"

    # 停用现有的 Swap（如果存在）
    if swapon --show | grep -q "/swapfile"; then
        echo "发现现有的 Swap 文件，正在停用..."
        sudo swapoff /swapfile
        echo "已停用现有 Swap 文件。"
    fi

    # 创建新的 Swap 文件
    echo "正在创建新的 Swap 文件..."
    sudo fallocate -l "${size_mb}M" /swapfile
    sudo chmod 600 /swapfile

    # 格式化为 Swap 并启用
    echo "正在格式化为 Swap 空间..."
    sudo mkswap /swapfile
    echo "正在启用 Swap 文件..."
    sudo swapon /swapfile

    # 显示当前的 Swap 配置
    echo "新的 Swap 文件已启用。当前 Swap 配置："
    swapon --show
    free -h

    # 更新 /etc/fstab 以支持开机自动挂载
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "正在配置开机自动挂载..."
        echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
        echo "已更新 /etc/fstab 文件。"
    fi

    echo "设置完成！新的 Swap 缓存大小为 ${size_mb} MB。"
}

# 调用函数
manage_swap_cache