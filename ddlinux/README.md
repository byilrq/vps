# DD 适用目标系统：**Debian 12 / 13**、**Ubuntu 22.04 / 24.04**。

> **危险操作**：本项目用于重装 VPS。安装引擎准备好引导后，还需人工重启；进入重装环境后，所选磁盘会被覆写，无法通过菜单撤销。务必事先备份并准备好服务商的 VNC / Rescue 救援方式。
>

```
VPS 首次安装只需：

```bash
mkdir -p /root/ddlinux
curl -fL --retry 3 \
  https://raw.githubusercontent.com/byilrq/vps/main/ddlinux/d.sh \
  -o /root/ddlinux/d.sh
bash /root/ddlinux/d.sh
```
## 5. 功能菜单

| 菜单 | 功能 | 安装方式 |
| --- | --- | --- |
| 1 → 1 | Debian 12 bookworm | Debian 官方 netboot + preseed |
| 1 → 2 | Debian 13 trixie | Debian 官方 netboot + preseed |
| 2 → 1 | Ubuntu 22.04 jammy | Alpine 临时系统 + Ubuntu 磁盘镜像 DD |
| 2 → 2 | Ubuntu 24.04 noble | Alpine 临时系统 + Ubuntu 磁盘镜像 DD |
| 3 | 清除重启前的 DD 安装引导 | 重新生成正常 GRUB 配置，不删除项目脚本 |
| 0 | 退出 | 不安装 |

## 6. 菜单默认配置与重要风险

| 选项 | 当前设置 |
| --- | --- |
| 默认 root 密码 | `123456`（继承原菜单，**极弱密码**） |
| SSH 端口 | `2222`，可输入自定义端口 |
| 主机名 | `debian`，可输入自定义主机名 |
| 网络 | 固定 DHCP |
| 磁盘 | 检测并选取，确认后执行 |
| 重装开始 | 需要用户手动 `reboot` |

**安全建议**：重装后立即使用 `passwd` 修改 `123456`，并限制 SSH 访问源。使用固定 DHCP 的前提是服务商网络确实提供 DHCP；静态 IP VPS 不要直接使用此默认菜单，否则重装后可能无法连接。

Ubuntu 默认镜像地址继承原引擎中的第三方地址（不是 Ubuntu 官方域名）：

```text
https://cloud-images.a.disk.re/Ubuntu/jammy-server-cloudimg-amd64.xz
https://cloud-images.a.disk.re/Ubuntu/noble-server-cloudimg-amd64.xz
```
ARM64 使用对应 `arm64` 文件名。

