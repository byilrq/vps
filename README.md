定时位置： unbutu：   /etc/cron.d/mdadm
30 0 * * * root /sbin/reboot

如果 VPS 与 GitHub Release 连接不畅， 可以手动将 H.sh 传输到root/上进行安装。

bbr3安装了效果明显，不要配置带宽设置

4837的线路上海电信基本要跑满，跑不满不行。落地点需要近一点。最好就是IIJ。

1. HyperSpeed
bash <(wget -qO- https://bench.im/hyperspeed)

2．回城测试
curl http://tutu.ovh/bash/returnroute/test.sh|bash

3. SuperTrace.sh
wget -qO- oldking.net/supertrace.sh | bash

4.流媒体解锁测试脚本
bash <(curl -L -s check.unlock.media)

5.三网回程延迟测试脚本
wget -qO- git.io/besttrace | bash

6.三网测速脚本
bash <(curl -Lso- https://git.io/superspeed_uxh)
