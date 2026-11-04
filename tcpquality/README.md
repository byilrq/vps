# 上海三网 IPv4 专用版

修改自 [ibsgss/TcpQuality](https://github.com/ibsgss/TcpQuality)（GPL-3.0-only）。

## 启动方式
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byilrq/vps/main/tcpquality/runTcpQuality.sh)
```

启动菜单只问三项，各自 `y/n`，**直接回车为 `y`**：

1. 上海电信、联通、移动 IPv4 回程：路由、延迟和丢包。
2. 上海电信、联通、移动 IPv4 大包回程：TCP 大包的回程线路、延迟及丢包。
3. 上海电信、联通、移动 IPv4 单线程测速：上传和下载。

允许只开启任意一项或两项。三项均选择 `n` 则直接退出；不检测 IPv6、外省节点、教育网、国际互联或 AppleCDN。
测速用的上海目标来自上游 `getNodes` 服务；当该服务无法返回节点时，可能无法测试。大包回程依赖 `nexttrace-tiny`；若下载失败则会提示并跳过大包，不以普通回程冒充大包。

## 说明

- 单线程测速可能产生较大数据流量；实际测速节点和链路可用性依赖上游服务。

## 文件

`runTcpQuality.sh`：唯一入口及三个测试选项；
`runTcpQuality-core.sh`：包含三个检测项目的原有测试实现及独立开关；
`runTcpQuality-rootfs.sh`：隔离环境运行器；
`tcpquality-tcpinfo.c`、`tcpquality-retrans-*.bt`：测速时 TCP 重传指标的辅助源文件；
`LICENSE`：GPL-3.0-only 许可证。

独立上传时应保持文件名及所在目录不变。新的 GitHub Raw 地址在文件上传到仓库前不会生效。
