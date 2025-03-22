#!/bin/bash

# 检查是否以 root 或 sudo 运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 或 sudo 权限运行此脚本"
    exit 1
fi

# 更新包列表并安装必要工具
echo "正在更新包列表并安装必要工具..."
apt update -y
apt install -y software-properties-common

# 添加 Ondrej PHP PPA
echo "添加 Ondrej PHP PPA..."
add-apt-repository ppa:ondrej/php -y
apt update -y

# 检查 PPA 是否添加成功
echo "检查 PPA 是否添加成功..."
apt-cache policy | grep ondrej

# 安装 Nginx
echo "安装 Nginx..."
apt install -y nginx
systemctl enable nginx
systemctl start nginx

# 安装 PHP 8.2 及所有指定扩展（包括 php8.2-curl）
echo "安装 PHP 8.2 及其扩展（包含 curl）..."
apt install -y \
    php8.2 \
    php8.2-cli \
    php8.2-fpm \
    php8.2-curl \
    php8.2-gmp \
    php8.2-gd \
    php8.2-mbstring \
    php8.2-pdo

# 检查 PHP 版本
echo "检查 PHP 版本..."
php -v

# 验证 cURL 扩展是否安装
echo "验证 cURL 扩展是否启用..."
php -m | grep curl || echo "cURL 未安装，请检查安装步骤！"

# 重启 Nginx 和 PHP-FPM 服务
echo "重启 Nginx 和 PHP-FPM 服务..."
systemctl restart nginx
systemctl restart php8.2-fpm

# 检查服务状态
echo "检查服务状态..."
systemctl status nginx --no-pager
systemctl status php8.2-fpm --no-pager

# 创建测试文件以验证 PHP 和 cURL
echo "创建 PHP 测试文件..."
echo "<?php phpinfo(); ?>" > /var/www/html/info.php
chown www-data:www-data /var/www/html/info.php
chmod 644 /var/www/html/info.php

echo "安装完成！"
echo "请访问 http://你的服务器IP/info.php 检查 PHP 环境。"
echo "cURL 扩展已包含在安装中，可在 phpinfo() 中确认。"