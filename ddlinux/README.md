# DD 系统管理脚本（d.sh，GitHub 目录 ddlinux）

版本：local-v1.2（2026-10-31）  
适用目标系统：**Debian 12 / 13**、**Ubuntu 22.04 / 24.04**。

> **危险操作**：本项目用于重装 VPS。安装引擎准备好引导后，还需人工重启；进入重装环境后，所选磁盘会被覆写，无法通过菜单撤销。务必事先备份并准备好服务商的 VNC / Rescue 救援方式。
>
> **本地脚本不等于离线安装**：新系统镜像、引导内核、Debian 软件包、Alpine 临时系统等仍需要网络下载。

## 1. 目录结构

```text
ddlinux/
├── d.sh                         # 唯一中文管理入口，支持首次自动补齐
├── engine.sh                    # 本地重装引擎
├── ubuntuInit.sh                # Ubuntu DD 的本地初始化脚本
├── CloudInit/
│   ├── dhcp_interfaces.cfg
│   ├── ipv4_dhcp_ipv6_static_interfaces.cfg
│   ├── ipv4_static_interfaces.cfg
│   ├── ipv4_static_ipv6_dhcp_interfaces.cfg
│   ├── ipv4_static_ipv6_static_interfaces.cfg
│   └── ipv6_static_interfaces.cfg
├── SHA256SUMS                   # 完整清单，包含 d.sh、引擎和所有模板
└── README.md
```

**已删除**：`dd.sh` 旧入口、`ddlinux.sh` 专用初始化脚本、`-debian-dd` 高级参数、Debian 自定义镜像菜单。`d.sh --sync` 成功后还会清理安装目录中的旧版 `dd.sh` / `ddlinux.sh`。

## 2. 本地压缩包安装（不依赖 GitHub）

将发布 ZIP 上传到 VPS 的 `/root` 并解压，使目录为 `/root/ddlinux`：

```bash
cd /root
unzip ddlinux_fixed.zip
cd /root/ddlinux
bash d.sh --check
bash d.sh
```

若 `/root/ddlinux` 已经存在，建议将新压缩包解压到一个**新目录**，确保没有混用旧版 `SHA256SUMS`；确认后再替换原目录。

## 3. 首次只下载 d.sh：自动补齐全部文件

**先把本 ZIP 内的文件全部更新到你的 GitHub 仓库 `byilrq/vps` 的 `main/ddlinux/` 目录；删除 GitHub 上的旧 `dd.sh` / `ddlinux.sh`。** GitHub 当前若仍是旧版本，首次补齐会因缺少 `d.sh` 或清单不匹配而中止。

VPS 首次安装只需：

```bash
mkdir -p /root/ddlinux
curl -fL --retry 3 \
  https://raw.githubusercontent.com/byilrq/vps/main/ddlinux/d.sh \
  -o /root/ddlinux/d.sh
bash /root/ddlinux/d.sh
```

`d.sh` 检测到缺少 `engine.sh`、`ubuntuInit.sh`、`CloudInit/` 模板、`README.md` 或 `SHA256SUMS` 时，将自动从**同一个固定 GitHub 目录**下载完整包，校验全部 SHA256 和脚本语法，通过后才允许进入安装菜单。下载使用 HTTPS 且**不跳过证书验证**；如果文件缺失、下载中断、校验失败，会在重装前退出，原有本地文件不受下载失败影响。

脚本必须先保存为本地文件，**不要**使用 `curl URL | bash`：安装目录是通过真实的 `d.sh` 路径识别的。

## 4. 日常使用和维护

```bash
cd /root/ddlinux
bash d.sh            # 管理菜单；文件齐全时直接本地运行、不联网更新脚本
bash d.sh --check    # 离线检查，非 root 也可执行，不会修改系统
bash d.sh --sync     # 显式从 GitHub 下载完整最新版，校验后再替换本地文件
bash d.sh --help     # 帮助
```

- **本地优先**：完整且通过 SHA256 校验的包，不会每次下载远程管理脚本。
- **缺失自动补齐**：缺少包内文件或清单时，自动下载完整包并验证。
- **校验失败即停止**：如果已有文件被修改、哈希不一致或语法报错，不会静默覆盖；请核实后手动执行 `bash d.sh --sync`。
- **整包升级**：`--sync` 先下载到临时目录；全部校验成功后才替换，并对部署失败执行备份回滚；成功后删除旧版 `dd.sh` / `ddlinux.sh`。更新入口脚本后请重新运行 `bash d.sh`。
- **代码来源**：固定为 `https://raw.githubusercontent.com/byilrq/vps/main/ddlinux/`，没有其他远程脚本或原作者脚本回退。SHA256 用于文件一致性检查；请自行确认 GitHub 仓库及分支可信。

## 5. 功能菜单

| 菜单 | 功能 | 安装方式 |
| --- | --- | --- |
| 1 → 1 | Debian 12 bookworm | Debian 官方 netboot + preseed |
| 1 → 2 | Debian 13 trixie | Debian 官方 netboot + preseed |
| 2 → 1 | Ubuntu 22.04 jammy | Alpine 临时系统 + Ubuntu 磁盘镜像 DD |
| 2 → 2 | Ubuntu 24.04 noble | Alpine 临时系统 + Ubuntu 磁盘镜像 DD |
| 3 | 清除重启前的 DD 安装引导 | 重新生成正常 GRUB 配置，不删除项目脚本 |
| 0 | 退出 | 不安装 |

Debian 两个入口**不是**自定义镜像 DD。Ubuntu 保留“默认镜像源 / 手动输入镜像直链”选项，专用初始化文件仍为本地 `ubuntuInit.sh`。

原有针对不同**当前系统**（例如 CentOS、AlmaLinux、Fedora 等）的网络、依赖、引导兼容判断予以保留；这些发行版不作为可选**目标系统**。Alpine 作为 Ubuntu DD 的内存启动环境保留，不能删除。

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

ARM64 使用对应 `arm64` 文件名。**不要把 ZIP 内脚本校验与系统镜像可信度混为一谈**；请自行确认默认源或选用可信的镜像直链。

## 7. 高级引擎入口（不经中文菜单）

```text
bash engine.sh --check
bash engine.sh -debian 12 [其他选项]
bash engine.sh -debian 13 [其他选项]
bash engine.sh -ubuntu 22.04 [其他选项]
bash engine.sh -ubuntu 24.04 [其他选项]
```

常用选项：`-setdisk /dev/vda`、`-port 2222`、`-pwd PASSWORD`、`-hostname NAME`、`--network dhcp|static`、`-dd IMAGE_URL`（仅 Ubuntu）、`-filetype raw|xz|gz`、`--init-file /本地绝对路径/脚本.sh`（仅 DD 模式）。

**`-debian-dd` 已不受支持**；Debian 使用 `-dd` 也会提前拒绝。高级调用绕过中文菜单的 `yes` 确认，请谨慎使用。

## 8. 交付测试说明

可在非目标 VPS 的普通 Linux 环境安全执行：

```bash
bash d.sh --check
bash engine.sh --check
bash engine.sh --help
```

这些命令不会开始磁盘重装。实际安装涉及网络、GRUB 和磁盘，尚需在可救援的测试 VPS 环境完成端到端验证。

## 9. 关于 GitHub 地址变更

下载与更新唯一来源已改为 `https://github.com/byilrq/vps/tree/main/ddlinux`，脚本实际读取 `https://raw.githubusercontent.com/byilrq/vps/main/ddlinux/`。不要把 ZIP 上传到 `ddinstall/` 或仅上传 `d.sh`；须先上传 **所有文件（包括 SHA256SUMS）** 至新的 `ddlinux/` 目录，自动下载才能通过校验。

注意：目录 `ddlinux/` 是本项目的新目录名称，**并不意味着保留**旧文件 `ddlinux.sh`；该文件随 Debian 自定义镜像 DD 功能一并删除。引擎内部的 `ddinstall-assets` 是临时启动环境中的载荷目录标识，与 GitHub 下载地址无关，不应因仓库改名而单独替换。
