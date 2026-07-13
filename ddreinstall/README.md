# DD 系统安装工具

精简版 DD 系统安装脚本，支持 Debian 和 Ubuntu。

## 功能特性

- ✅ 支持 Debian 9-13 安装
- ✅ 支持 Ubuntu 18.04/20.04/22.04/24.04 安装
- ✅ 交互式菜单配置
- ✅ 支持自定义 SSH 用户名、密码、端口
- ✅ SSH 端口默认 2222
- ✅ 支持命令行参数
- ✅ 支持 Backspace 删除输入

## 文件说明

| 文件 | 说明 |
|------|------|
| `reinstall.sh` | 主程序（支持菜单交互和命令行参数） |
| `trans.sh` | 系统传输脚本（安装过程中使用） |
| `debian.cfg` | Debian 自动安装配置文件 |
| `initrd-network.sh` | 网络初始化脚本 |

## 使用方式

### 方式一：交互菜单（推荐）

```bash
sudo bash reinstall.sh
```

菜单流程：
1. 选择系统 (1=Debian / 2=Ubuntu / 0=退出)
2. 选择版本号
3. 输入 SSH 用户名（默认 root）
4. 输入 SSH 密码（必须）
5. 输入 SSH 端口（默认 2222）
6. 输入镜像 URL（必须）
7. 确认无误后开始安装

### 方式二：命令行参数

```bash
sudo bash reinstall.sh dd \
  --img="https://example.com/debian-12.img" \
  --username="root" \
  --password="your_password" \
  --ssh-port="2222"
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--img` | 镜像 URL（必须） | - |
| `--username` | SSH 用户名 | root |
| `--password` | SSH 密码（必须） | - |
| `--ssh-port` | SSH 端口 | 2222 |

## 系统要求

- Linux 系统（已测试 Debian/Ubuntu）
- 需要 root 权限
- 不支持 Live OS 环境
- 不支持容器虚拟化
- 需要关闭安全启动（Secure Boot）

## 支持的系统版本

### Debian
- Debian 9 (Stretch)
- Debian 10 (Buster)
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Debian 13 (Trixie)

### Ubuntu
- Ubuntu 18.04 (Bionic)
- Ubuntu 20.04 (Focal)
- Ubuntu 22.04 (Jammy)
- Ubuntu 24.04 (Noble)

## 注意事项

1. **备份重要数据**：安装过程会重新分区和格式化磁盘，请提前备份数据
2. **网络连接**：确保系统能正常访问镜像源和 GitHub
3. **镜像准备**：需要提供有效的系统镜像 URL（支持 raw/vhd/tar/gz/xz/zst 格式）
4. **密码安全**：SSH 密码仅用于安装过程中查看日志，镜像密码不会被修改
5. **重启系统**：安装完成后需要手动重启系统

## 故障排除

### 连接超时
- 检查网络连接
- 尝试使用国内镜像源
- 确保防火墙允许出站连接

### 密码错误
- 确保密码中没有特殊字符干扰 shell
- 使用单引号或双引号包装密码

### 安装失败
- 查看 SSH 登录后的安装日志
- 确认镜像文件格式正确
- 检查磁盘空间是否足够

## 原始项目

基于 [bin456789/reinstall](https://github.com/bin456789/reinstall) 精简而来

## 许可证

MIT License

## 更新日志

### v1.0 (2026-07-13)
- 精简为仅支持 Debian 和 Ubuntu 的 DD 安装
- 添加交互式菜单
- 支持 SSH 端口自定义（默认 2222）
- 集成所有必需文件
