1.定时位置： unbutu：   /etc/cron.d/mdadm

30 0 * * * root /sbin/reboot

2.一键debian 12:

wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/vps/main/ddsys.sh && bash ddsys.sh -debian 12 -pwd 'password'

# 安装 Debian 11
bash install.sh -debian 11

# 安装 Ubuntu 22.04
bash install.sh -ubuntu 22.04

# 指定密码和 SSH 端口
bash install.sh -debian 11 -pwd MyPassword -port 2222

# 指定静态 IP
bash install.sh -ubuntu 22.04 --ip-addr 192.168.1.100 --ip-mask 255.255.255.0 --ip-gate 192.168.1.1

# 启用 BBR
bash install.sh -debian 11 --bbr

# 使用特定镜像
bash install.sh -ubuntu 22.04 -mirror https://mirrors.tuna.tsinghua.edu.cn/ubuntu

