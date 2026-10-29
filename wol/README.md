# VPS WOL Web v1.6.2

基于用户现有 v1.6.0 `wol.py`、`wol.sh` 的最小改动版。

## 修复

原 v1.6.0 在验证 HMAC 前，首先要求 ACK 源 IPv6 与 Cloudflare AAAA 解析到的 AX6 本地目的地址完全相同。然而实际抓包显示，AX6 的出站 ACK 可能从另一个 IPv6 地址回复。这种情况下即使路由器已认证请求并送出 7 个 WOL 包，WEB 仍错误地显示失败。

v1.6.2 保留完整 nonce、HMAC-SHA256 签名、包数范围验证，并检查 ACK 源 UDP 端口等于中继 UDP/41996；**只有签名和 nonce 都正确的应答才视作成功**。对于已通过加密身份认证的 ACK，不再以其 IPv6 源地址必须等于 AAAA 为成功条件，以兼容路由器多个 IPv6 地址、NAT66 或源地址转换。未验证的 ACK 仍然不能让页面显示成功。

## 升级已有 VPS

把 ZIP 解压到 `/root/wol-v162`，执行：

```bash
bash /root/wol-v162/upgrade_vps.sh
```

升级脚本只更新 `/root/wol/wol.py`、`/root/wol.py`、`/root/wol.sh` 并重启 `wol-web` 服务。先备份旧版代码，失败时尝试自动回滚；**不碰** `config.json`、`wol6_secret`、WEB 账号/密码、日志历史、Nginx、systemd 配置和防火墙。

然后检查：

```bash
systemctl is-active wol-web
grep -m1 WOL_WEB_APP_VERSION /root/wol/wol.py
```

`active` 和 `1.6.2` 表示 VPS 程序已升级。随后在 WEB 点击一次 WOL，看到 `relay_ack=true` 且 `lan_packets_submitted` 大于 0，才能认定 AX6 已确认 LAN 提交；不能据此推定 NAS 已启动。

**尚未在真实 VPS 和 AX6 上执行。** 请依据完整升级手册逐项验收。
