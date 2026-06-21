1.定时采用mdadm文件，位置： unbutu：   /etc/cron.d/mdadm

30 0 * * * root /sbin/reboot

2.domain.sh 可以申请证书/etc/letsencrypt/live/，并可以自动更新证书。

3.ntfy.sh 实现消息推送的服务端设置。

如果安装那个程序后，一些网站打不开了就是nginx被破坏了，nginx由伪装站wow.sh脚本实现。其他脚本不重新安装nginx,只配置。

