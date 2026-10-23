# DD 重装管理脚本：Debian / Ubuntu 本地精简版

版本：local-v1.0  

> **此程序用于重装 VPS。确认安装并重启进入安装环境后，选中的磁盘会被覆写，数据不可通过菜单恢复。**
>
> **“本地版”指管理脚本、安装引擎、初始化脚本和网络模板使用压缩包里的本地文件，不等于完全离线重装。系统镜像、安装内核、软件包等仍需联网下载。**

## 1. 本版保留的安装功能

| 菜单路径 | 安装目标 | 实际方式 |
| --- | --- | --- |
| 主菜单 1 → 1 | Debian 12 / bookworm | 原有官方 netboot + preseed 网络安装 |
| 主菜单 1 → 2 | Debian 13 / trixie | 原有官方 netboot + preseed 网络安装 |
| 主菜单 1 → 3 | 自定义 Debian 镜像 | 原有 Alpine 临时环境 + DD + 本地 `ddlinux.sh` |
| 主菜单 2 → 1 | Ubuntu 22.04 / jammy | 原有 Alpine 临时环境 + DD + 本地 `ubuntuInit.sh` |
| 主菜单 2 → 2 | Ubuntu 24.04 / noble | 原有 Alpine 临时环境 + DD + 本地 `ubuntuInit.sh` |
| 主菜单 3 | 撤销重启前的安装引导 | 重新生成正常 GRUB 引导；不删除本地源码 |
| 主菜单 0 | 退出 | 不开始新的安装 |

Debian 12 / 13 的官方安装入口仍是 netboot，不是硬盘镜像 DD。

**为什么还能看到 Alpine、CentOS 等名称？**

- Alpine 仅作为 DD 时运行在内存里的临时环境；它不是可选的目标系统。删除这一层会破坏原有 Debian / Ubuntu DD 流程。
- CentOS、Rocky、AlmaLinux、Fedora、Kali 等名称仍可能出现在“当前 VPS 原系统”的识别、依赖准备、网络读取和 GRUB 兼容代码中。保留这些代码是为了能从这些原系统重装成 Debian / Ubuntu，并不表示还能安装这些系统。
- ARM EFI 兼容分支可能下载引导二进制文件；它不属于远程管理脚本或远程初始化脚本。

## 2. 默认配置保持原样

| 配置 | 菜单默认值 |
| --- | --- |
| 登录用户 | root |
| root 密码 | `123456`，保留原菜单固定密码行为 |
| SSH 端口 | `2222`，可在菜单输入其他端口 |
| 主机名 | `debian`，可在菜单修改；Ubuntu 菜单也沿用此默认值 |
| 网络方式 | DHCP，保留原菜单逻辑 |
| Ubuntu 默认镜像 | 沿用原版内置的第三方镜像源 |

**`123456` 是弱密码。** 正式使用建议在服务商防火墙中先将 SSH 访问限制为自己的来源地址，安装后立即执行 `passwd` 修改密码。直接使用引擎的高级方式可通过 `-pwd` 设置自己的密码，不应省略该参数；直接调用引擎时，不套用菜单固定密码。

本版修复了原引擎切换到 Alpine 临时环境时覆盖菜单传入密码的逻辑：已传入的密码会继续保留。

菜单仍固定选择 DHCP；只有服务商网络实际支持 DHCP 才适合使用这一默认流程。引擎原有静态 IPv4 / IPv6 参数及模板链路仍保留，但本版没有重新设计静态网络交互菜单。

## 7. 镜像来源和格式

Ubuntu 默认源沿用原脚本的以下第三方地址模式，**不是将该域名认定为 Ubuntu 官方镜像站**：

```text
https://cloud-images.a.disk.re/Ubuntu/jammy-server-cloudimg-amd64.xz
https://cloud-images.a.disk.re/Ubuntu/noble-server-cloudimg-amd64.xz
```

ARM 分支使用对应 `arm64` 文件名。交付前未对这些在线镜像地址进行实时可用性或内容验证；运行时会检查可访问性。镜像应来自你信任的来源。

自定义 DD 镜像应是兼容原初始化流程的完整磁盘镜像：

| 文件形式 | 解码处理 |
| --- | --- |
| 未压缩 raw 磁盘镜像 | 原样传输 |
| `.xz` | xzcat |
| `.gz` | gunzip -dc |
| 带查询参数的 `.xz` / `.gz` 直链 | 去掉查询参数和片段后判断后缀 |

下载地址必须直接返回镜像内容，而不是登录页、分享页或 HTML 页面。URL 中含 `&`、`?` 等字符时，直接调用引擎必须给 URL 加引号。

## 8. 高级参数说明

普通使用直接运行 `bash install.sh`。下面仅说明保留或调整的入口，不是让你在未确认磁盘前复制执行。

| 参数 | 含义 |
| --- | --- |
| `-debian 12` / `-debian 13` | Debian 官方 netboot 安装 |
| `-ubuntu 22.04` / `-ubuntu 24.04` | Ubuntu DD |
| `-debian-dd -dd '镜像直链'` | 使用本地 `ddlinux.sh` 的 Debian DD |
| `-setdisk /dev/vda` | 明确目标磁盘，以机器实际情况为准 |
| `-port 2222` | 新系统 SSH 端口 |
| `-pwd '自己的密码'` | 新系统 root 密码；原模板对特殊字符的全面兼容未验证 |
| `-hostname my-vps` | 主机名 |
| `--network dhcp` / `--network static` | 网络方式 |
| `--ip-addr`、`--ip-mask`、`--ip-gate` | IPv4 地址、子网掩码、网关 |
| `--ip6-addr`、`--ip6-mask`、`--ip6-gate` | IPv6 地址、前缀、网关 |
| `-architecture amd64` / `-architecture arm64` | 架构选择，需与机器及镜像匹配 |
| `-filetype raw` / `xz` / `gz` | 无法从 URL 后缀推断时指定镜像压缩格式 |
| `--init-file /本地路径/脚本.sh` | 替换 DD 初始化脚本；不会远程下载 |

**直接调用 `engine.sh` 不经过菜单里的 `yes` 确认。** 不熟悉参数时不要绕过菜单。高级自定义脚本会在安装环境里获得写盘能力，必须先自行审查其内容。



