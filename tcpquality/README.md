# TcpQuality · 上海三网 IPv4 专用版

修改自 [ibsgss/TcpQuality](https://github.com/ibsgss/TcpQuality)（GPL-3.0-only）。
此目录仅包含运行必需的脚本、测速辅助源码、GPL 许可证及本使用说明；不包含 CI、beta、无关项目文件。

## 启动方式

上传本目录到 `https://github.com/byilrq/vps/tree/main/tcpquality` 后，在 Linux VPS 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byilrq/vps/main/tcpquality/runTcpQuality.sh)
```

若无法使用 bash 进程替换，也可以先克隆或下载本目录，然后执行：

```bash
bash runTcpQuality.sh
```

启动菜单只问三项，各自 `y/n`，**直接回车为 `y`**：

1. 上海电信、联通、移动 IPv4 回程：路由、延迟和丢包。
2. 上海电信、联通、移动 IPv4 大包回程：TCP 大包的回程线路、延迟及丢包。
3. 上海电信、联通、移动 IPv4 单线程测速：上传和下载。

允许只开启任意一项或两项。三项均选择 `n` 则直接退出；不检测 IPv6、外省节点、教育网、国际互联或 AppleCDN。
测速用的上海目标来自上游 `getNodes` 服务；当该服务无法返回节点时，可能无法测试。大包回程依赖 `nexttrace-tiny`；若下载失败则会提示并跳过大包，不以普通回程冒充大包。

## 说明

- 默认使用临时 Debian rootfs 环境，需 Linux root。首次运行将下载运行环境、自动准备依赖及 nexttrace-tiny；运行完自动清理。预构建 rootfs 来源为原项目，不属于本目录代码文件。
- 测试进程共享宿主网络命名空间，探测的是运行脚本 VPS 的网络回程，不会改变业务路由。
- 默认不上传在线报告或参与排行榜；结果直接显示并保存为 VPS `/tmp/zstatic_nping_*.csv`。
- 使用 `--no-rootfs` 可直接在宿主运行（需自行满足 `curl`、`nmap/nping`、`traceroute` 等依赖及大包测试 `nexttrace-tiny`）；可能因缺依赖触发程序自动安装。
- 使用 `--debug` 可保留调试数据。
- 单线程测速可能产生较大数据流量；实际测速节点和链路可用性依赖上游服务。

## 文件

`runTcpQuality.sh`：唯一入口及三个测试选项；
`runTcpQuality-core.sh`：包含三个检测项目的原有测试实现及独立开关；
`runTcpQuality-rootfs.sh`：隔离环境运行器；
`tcpquality-tcpinfo.c`、`tcpquality-retrans-*.bt`：测速时 TCP 重传指标的辅助源文件；
`LICENSE`：GPL-3.0-only 许可证。

独立上传时应保持文件名及所在目录不变。新的 GitHub Raw 地址在文件上传到仓库前不会生效。
