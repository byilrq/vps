#!/bin/bash

# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装 Nginx
echo "安装 Nginx..."
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# 安装 software-properties-common
echo "安装 software-properties-common..."
sudo apt install -y software-properties-common

# 添加 PHP PPA 并更新软件包列表
echo "添加 PHP PPA 并更新软件包列表..."
sudo add-apt-repository ppa:ondrej/php -y
sudo apt update

# 安装 PHP 8.2 和相关扩展
echo "安装 PHP 8.2 和扩展..."
sudo apt install -y php8.2 php8.2-cli php8.2-fpm php8.2-gmp php8.2-gd php8.2-mbstring php8.2-pdo php8.2-mysql

# 启用 GMP 扩展
echo "启用 GMP 扩展..."
sudo sed -i 's/;extension=gmp/extension=gmp/' /etc/php/8.2/cli/php.ini

# 启用 GD 扩展
echo "启用 GD 扩展..."
sudo sed -i 's/;extension=gd/extension=gd/' /etc/php/8.2/cli/php.ini

# 重启 PHP-FPM 服务
echo "重启 PHP-FPM 服务..."
sudo systemctl restart php8.2-fpm

# 完成提示
echo "安装完成！Nginx 和 PHP 8.2 已安装，并已启用 GMP 和 GD 扩展。"
