# NodeSeek 关键词监控：一体化管理版（ntfy / 内嵌 CSS）

**文件只有 `node.sh`、`node.py`、`push.py`、`README.md`；没有 `install.sh`。** 管理脚本统一负责安装依赖、本地部署、更新、配置、状态、重启、测试和完整卸载，不从 GitHub 下载程序，也不依赖单独的 CSS 文件。

## 初次安装 / 更新

通过 WinSCP 将 `node_monitor_no_install_sh.zip` 上传到 VPS 的 `/root`，再从 SSH 执行：

```bash
cd /root
unzip -o node_monitor_no_install_sh.zip -d /root/node_update
cd /root/node_update/node
bash node.sh
```

在菜单中选择：

- **1 安装依赖**：仅需要 Python 和运行库；**不安装、卸载或重启 Nginx**。首次安装如缺少 Python，请先选 1。
- **2 本地部署 / 更新系统**：自动校验同目录 `node.py`、`push.py`，备份旧脚本和配置，复制到 `/root/node/`，管理脚本安装为 `/root/node.sh`，创建/更新项目自己的 `node.service`，启动监控。旧关键词、日志和设置保留。可通过 `bash node.sh -deploy` 直接执行。
- **3 配置参数**：仅支持 ntfy；默认端口 TCP **8168**；允许使用 Backspace、Delete 和方向键修改输入。

之后使用已安装的脚本：

```bash
bash /root/node.sh                # 打开菜单
bash /root/node.sh -config        # 编辑配置
bash /root/node.sh -restart       # 重启项目服务
bash /root/node.sh -status        # 查看状态
bash /root/node.sh -test          # ntfy 测试
```

如需更新到新的压缩包版本，请再次从新解压目录执行 `bash node.sh`，然后选择菜单 2。**仅在 `/root/node.sh` 中点菜单 2 而未引入新文件，不会自动下载新版本。**

## 菜单 8：彻底卸载

从 SSH 运行 `bash /root/node.sh`，选择 **8 彻底卸载 Node 监控系统**，然后阅读提示并输入大写 `DELETE` 确认。也可以运行 `bash /root/node.sh -uninstall`，同样必须确认。

确认后删除：

1. 本项目的 `node.service`（仅当服务文件明确属于 `/root/node/node.py` 时）。
2. 本项目 Python 进程和旧版 node Cron 计划任务；不会通过模糊进程名杀死其他 Python/Node 服务。
3. `/root/node/` **整个目录**，含 `node.py`、`push.py`、`node_config.txt`、关键词、日志、状态、缓存、历史升级备份等。删除后这些数据无法恢复。
4. `/root/node.sh` 管理脚本（仅在内容确认属于本项目时）。
5. 仅清理带有 `node-monitor-8168` 明确标记的防火墙规则。**旧版无标记规则和其他用户可能共享的端口规则不自动清理**。

### 多网站 / 多用户 Nginx 安全边界

**本项目 Web 由 `node.py` 自己监听 8168，不创建 Nginx 虚拟主机，也不依赖 Nginx 配置。** 卸载过程**不会**执行 `apt remove/purge nginx`、`systemctl stop/restart nginx`、`nginx -s reload`，不会删除 `/etc/nginx`、其他站点配置、网站目录、SSL 证书或共享依赖。即使该 VPS 还有多个 Nginx 网站/用户，也不会主动操作它们。

如果您曾手工为 Node 监控设置 **Nginx 反向代理**，该代理规则不由本项目管理，因此必须另行核查，不能直接删除共享的 Nginx 文件。如果原脚本曾添加不带项目标记的防火墙规则，请在确认 8168 未被其他服务使用后自行清理。

> 卸载时请先备份想保留的配置或关键词；解压至 `/root/node_update/` 的上传/临时文件、以及 `/root` 下的原始 ZIP 属于用户自放文件，不会自动清理。

## 其他功能

- 原 `node_skin.css` 样式已经完整写入 `node.py`；页面不再依赖外部 CSS。
- 默认 Web 端口固定 **8168**，HTTP：`http://IP:8168/`；如已配置有效域名和证书，则 HTTPS：`https://域名:8168/`。
- 仅保留 ntfy 推送，删除 Telegram。上海时间 **22:30（含）至次日 08:00（不含）** 自动使用 ntfy Priority 1，其余时间使用配置中的优先级 1–5。VPS 系统时区无需改为上海时区，但系统时钟需要准确。
- 原有关键词、补充关键词、RSS 日志、网页开关、关键词编辑和 PIN 等功能保留。

操作系统部署需要 systemd。若系统未安装 Python，请先在菜单执行 1，或手动安装 Python 3。
