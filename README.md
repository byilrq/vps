自用魔改+ 系统大保健工具
```shell
curl -sS -O https://kejilion.pro/kejilion.sh && chmod +x kejilion.sh && ./kejilion.sh
```
定时位置： unbutu：   /etc/cron.d/mdadm
30 0 * * * root /sbin/reboot

如果 VPS 与 GitHub Release 连接不畅， 可以手动将 Hysteria 可执行文件传输到 VPS 上进行安装。

```shell
bash <(curl -fsSL https://get.hy2.sh/) --local /path/to/hysteria-linux-amd64
```
