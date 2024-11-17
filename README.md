参考文档：https://v2.hysteria.network/zh
```shell
wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/hy2/main/hy2/hysteria.sh && bash hysteria.sh
```
系统工具---安装BBR3
```shell
curl -sS -O https://kejilion.pro/kejilion.sh && chmod +x kejilion.sh && ./kejilion.sh
```

设置时区：上海
```shell
sudo timedatectl set-timezone Asia/Shanghai
```
验证时区是否设置完成：
```shell
timedatectl
```

定时位置： unbutu：   /etc/cron.d/mdadm
30 0 * * * root /sbin/reboot
