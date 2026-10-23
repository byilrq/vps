# DD 重装管理脚本：Debian / Ubuntu 本地精简版

版本：local-v1.0  
修改日期：2026-10-23  
修改依据：本次上传的 `ddinstall.zip`，不是重新下载的其他版本。

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

Debian 12 / 13 的官方安装入口仍是 netboot，不是硬盘镜像 DD。本版没有将已经可用的安装方式统一重写成另一种实现。

**为什么还能看到 Alpine、CentOS 等名称？**

- Alpine 仅作为 DD 时运行在内存里的临时环境；它不是可选的目标系统。删除这一层会破坏原有 Debian / Ubuntu DD 流程。
- CentOS、Rocky、AlmaLinux、Fedora、Kali 等名称仍可能出现在“当前 VPS 原系统”的识别、依赖准备、网络读取和 GRUB 兼容代码中。保留这些代码是为了能从这些原系统重装成 Debian / Ubuntu，并不表示还能安装这些系统。
- ARM EFI 兼容分支可能下载引导二进制文件；它不属于远程管理脚本或远程初始化脚本。

## 2. 实际裁剪内容

删除其他系统作为**安装目标**时使用的参数入口、镜像选择和专用安装分支，包括 Windows、Kali、CentOS、Rocky Linux、AlmaLinux、Fedora，以及 Alpine 独立系统安装。

同时删除 Windows 的 RDP / NTFS / 批处理初始化链路、其他发行版的 Kickstart 等专用安装配置、netboot.xyz 分支，以及远程初始化脚本和模板的回退下载。

没有按系统名称全局删除代码，也没有重写共享的磁盘、网络、BIOS / UEFI 和 GRUB 检测逻辑。六份原网络模板内容逐字节保留。

`engine.sh`：原版 **279,763 字节** → 本版 **210,851 字节**，减少 **68,912 字节，约 24.6%**。本版优先保留兼容逻辑，并未为了体积压缩成难以维护的单行脚本。

## 3. 本地化后的调用链

```text
install.sh
  └─ 同目录 engine.sh
       ├─ Debian 12 / 13：生成 preseed 配置
       └─ Debian / Ubuntu DD：
            读取同目录 ddlinux.sh 或 ubuntuInit.sh
            读取同目录 CloudInit/ 网络模板
            生成 DNS 和参数文件
            一起装入 initramfs
            重启后，从内存中的本地文件复制到 Alpine 临时系统
            下载系统镜像 → DD → 初始化目标系统
```

关键点：**初始化脚本和模板在重启前就装入 initramfs**，并不是重启后再从原系统磁盘路径读取。因此，不会因为原系统被覆写而丢失所需的本地文件。

本地文件缺失、为空或语法检查不通过时停止，不会悄悄改用 GitHub / Gitee 上的其他脚本。Debian 安装后的 `.bashrc` 也不再远程下载，而是使用目标系统自己的 `/etc/skel/.bashrc`。

原来的 `--initurl` 参数已移除。确需自定义初始化脚本时，使用 `--init-file /绝对路径/脚本.sh`；它只接受本地文件，并在重启前打包。

## 4. 文件结构

```text
ddinstall/
├── install.sh
├── engine.sh
├── ddlinux.sh
├── ubuntuInit.sh
├── README.md
├── SHA256SUMS
└── CloudInit/
    ├── dhcp_interfaces.cfg
    ├── ipv4_static_interfaces.cfg
    ├── ipv4_dhcp_ipv6_static_interfaces.cfg
    ├── ipv4_static_ipv6_dhcp_interfaces.cfg
    ├── ipv4_static_ipv6_static_interfaces.cfg
    └── ipv6_static_interfaces.cfg
```

整个目录应一起上传、移动或备份。不要只上传 `install.sh`，也不要删除 `CloudInit/`。压缩包不包含旧版备份、升级补丁、开发测试文件或其他系统安装脚本。

## 5. 上传、检查和运行

### 5.1 重装前准备

先备份数据，并准备 VPS 服务商提供的控制台 / VNC / 救援系统。核实目标磁盘，尤其是有数据盘的机器。

以 root 运行正式安装。当前系统需具备 Bash、awk、grep、sed、cut、wget、curl、lsblk、ip 等基础命令。引擎会沿用原逻辑联网准备进一步的依赖、临时交换空间及引导文件；**正式安装准备不是只读操作**。

### 5.2 解压到新目录，避免混用旧文件

将 `ddinstall_debian_ubuntu_local_v1.0.zip` 上传至 VPS 的 `/root/`。

```bash
mkdir -p /root/dd-local-v1.0
unzip /root/ddinstall_debian_ubuntu_local_v1.0.zip -d /root/dd-local-v1.0
cd /root/dd-local-v1.0/ddinstall
```

第一次使用建议采用一个未放置旧版脚本的新目录。若没有 `unzip`，先通过当前系统的软件包管理器安装。

### 5.3 先做无破坏性检查

```bash
sha256sum -c SHA256SUMS
bash install.sh --check
```

`sha256sum` 用于检查包内文件是否与交付版本一致。`--check` 仅检查本地脚本、模板和 Bash 语法，不安装依赖、不探测镜像地址、不写引导、不格式化磁盘，也不会重启。

`--check` 不需要 root；它不是实际重装成功的保证。自检通过的提示是：

```text
[OK] Local scripts and all 6 network templates are present; syntax passed.
```

### 5.4 打开管理菜单

```bash
bash install.sh
```

也可从其他工作目录运行：

```bash
bash /root/dd-local-v1.0/ddinstall/install.sh
```

脚本以自身所在目录定位其他文件，不依赖当前工作目录，也不固定要求安装在 `/root/ddinstall`。

按菜单选择系统、磁盘、端口和主机名，核对配置后输入小写 `yes`。只有确认后才进入安装引擎。

### 5.5 引导准备成功后，再手动重启

本版不会在菜单确认后自动重启。看到引擎成功结束及“安装引导已准备好”的提示，确认备份、密码、SSH 端口、服务商安全组规则后，再自行执行：

```bash
reboot
```

重启后才进入实际安装 / DD 环境。DD 完成后，初始化脚本沿用原有流程重启到新系统。

如果出现错误、`DO NOT REBOOT` 或引擎非零退出，**不要继续重启**。先处理错误，必要时用菜单 3 撤销安装引导；撤销也失败时应从服务商控制台修复。

## 6. 默认配置保持原样

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

无法从 URL 路径判断压缩格式的地址，可在高级调用中明确指定 `-filetype xz`、`-filetype gz` 或 `-filetype raw`。菜单没有新增压缩格式选择项；不要把无可识别后缀的压缩文件当作 raw 使用。

**QCOW2、ISO 不能直接作为 raw 镜像写盘，改后缀也不等于转换格式。** 自定义 raw 镜像仍需满足原有分区布局、CPU 架构和 cloud-init 初始化条件，不能据此认定任意 Debian / Ubuntu 镜像都兼容。优先使用你已经验证过的镜像。

镜像下载沿用原实现，没有新增镜像签名验证。`SHA256SUMS` 只校验本地交付包，不验证远端系统镜像。

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

查看帮助：

```bash
bash engine.sh --help
```

## 9. 撤销安装引导

在尚未重启进入 DD / 安装环境之前，重新打开菜单，选择：

```text
3) 清除 DD 参数
```

本版不会删除 `/root/ddinstall` 或当前源码目录，不会删除当前系统的 `/boot/vmlinuz`、`/boot/initrd.img` 或版本化内核文件。它会清理本引擎的自定义引导项、重设默认引导，再生成 GRUB 配置。

本版安装用引导文件使用独立名称：

```text
/boot/ddinstall-vmlinuz
/boot/ddinstall-initrd.img
```

写入时使用临时文件和重命名，不跟随同名符号链接覆写其他内核。撤销流程不会强制删除这些安装专用文件；确认正常引导恢复后，它们可以留在原系统中，不影响本地源码。

**撤销不是完整系统回滚。** 它不恢复安装准备阶段的软件包、临时交换空间等所有改动，也无法恢复已经开始被 DD 覆写的数据。

如果已在旧版本里生成安装引导，建议先撤销旧引导，再使用本版重新准备，不要混用新旧引导文件。

## 10. 其他保护性调整

- 本地文件不存在、模板为空、脚本语法错误时立即停止，不远程回退。
- 禁用的目标系统参数在原系统准备阶段之前拒绝。
- Debian 官方 preseed 中的 root 登录布尔值拼写修正为 `true`。
- HTTP 错误状态不再被当作有效镜像链接。
- 保留完整的 `gunzip -dc` 参数，避免只读取第一个单词。
- DD 下载 / 解压 / 写盘管道有任一阶段返回失败时，不继续执行后续初始化和正常重启流程。已经写入的部分磁盘数据仍不可恢复。
- initramfs 解包、打包、文件复制和关键 GRUB 操作失败时停止。
- 在网络补丁插入完成后才定位 `switch_root`，避免插入行号发生偏移。
- 检测到原版处理过的云服务商守护进程时，不再下载执行卸载脚本，而是停止并提示先按服务商方法处理。这类机器可能需要你先进行额外处理。

## 11. 本次验证范围与结果

交付前完成 **302 项静态检查、生成结果对照和隔离模拟检查，全部通过**。测试在临时目录中运行；网络访问、GRUB 命令、写盘管道等危险操作在相关测试里被替换成模拟实现。

| 验证类别 | 数量 | 结果 |
| --- | ---: | --- |
| Bash / BusyBox ash 语法 | 6 | 通过 |
| 自检、帮助、缺失文件及禁用参数拒绝 | 29 | 通过 |
| 支持的参数入口解析 | 9 | 通过 |
| 六份模板和关键函数保留对照 | 24 | 通过 |
| 五个菜单入口传参 | 5 | 通过 |
| Debian 常规分区生成结果与原版对照 | 64 | 通过 |
| Debian RAID 分区生成结果与原版对照 | 20 | 通过 |
| 网络栈 / DHCP / 静态 / 架构 / 镜像区域 / 初始化脚本选择 | 64 | 通过 |
| 本地文件打包、cpio 压缩解压、临时系统复制 | 8 | 通过 |
| Debian 12 / 13 preseed 核心配置与原版对照 | 24 | 通过 |
| DD 下载 / 解压 / 写盘失败中止模拟 | 8 | 通过 |
| 引导文件符号链接保护、GRUB 路径、压缩格式、撤销、非 root 自检等补充检查 | 41 | 通过 |

原版 preseed 在生成后会删除 Windows 专用段落；对照测试也应用原版的这一清理规则，避免把主动移除的 Windows 代码误判为 Debian 配置差异。

**没有执行真实 VPS 重装，没有实际格式化磁盘，没有真实 BIOS / UEFI 启动，也没有在新系统中实测 SSH 登录和 cloud-init 完成情况。** 因此，上述检查不能替代真实机器验证，更不能据此保证所有云厂商、网卡、镜像和分区布局都成功。

本版继续使用原有在线安装源及 Alpine 临时环境版本选择，并未将所有联网资源固定成离线快照。首次部署建议先在可重建的测试 VPS 上跑通所需路径，再用于重要机器。

## 12. 许可和交付说明

保留原脚本的 GPL 声明及作者署名。这是基于你上传文件制作的修改版本，不代表原作者的正式发布。

原始上传包 SHA-256：

```text
e568693a9229eb3f042479258937922c7077aaa5b3d162b65db6dc9cfe1d0aa2
```

本包仅包含最终运行文件、本文档及校验清单，不包含原版副本或开发修改脚本。
