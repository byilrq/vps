#!/bin/bash
# ============================================
# Debian 12 / PVE 一键安装 XanMod 内核 + 启用 BBR3 + 自动验证
# 作者：ChatGPT (byilrq 版)
# ============================================

set -e

echo ">>> 🧩 检查系统环境..."
if ! grep -q "bookworm" /etc/os-release; then
    echo "⚠️ 当前系统不是 Debian 12 (bookworm)，请确认后再执行。"
    exit 1
fi

echo ">>> 📦 安装必要依赖..."
apt update -y
apt install -y wget curl gnupg ca-certificates apt-transport-https lsb-release

echo ">>> 🔑 导入 XanMod 公钥..."
wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor | tee /usr/share/keyrings/xanmod-archive-keyring.gpg > /dev/null

echo ">>> 🧭 添加 XanMod 软件源..."
echo "deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main" | tee /etc/apt/sources.list.d/xanmod.list

echo ">>> 🧰 更新源并安装最新 XanMod 内核..."
apt update -y
apt install -y linux-xanmod-x64v3

echo ">>> ⚙️ 启用 FQ + BBR3..."
grep -q "tcp_congestion_control" /etc/sysctl.conf || {
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
}
sysctl -p

echo ">>> 🧪 检查内核模块支持..."
modprobe tcp_bbr 2>/dev/null || true
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.core.default_qdisc

echo ">>> ✅ 预配置完成，准备重启验证 BBR3..."
sleep 3

# 创建启动后自动检测文件
cat > /root/check_bbr3.sh <<'EOF'
#!/bin/bash
echo "=== 🚀 系统重启后检测结果 ==="
uname -r
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
echo "----------------------------------------"
if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
  if sysctl net.core.default_qdisc | grep -q "fq"; then
    echo "✅ 检测结果：BBR3 + FQ 已启用成功！"
  else
    echo "⚠️ BBR3 启用成功，但 FQ 队列未激活。"
  fi
else
  echo "❌ BBR3 启用失败，请检查内核模块是否加载。"
fi
echo "========================================"
rm -f /etc/profile.d/check_bbr3.sh
EOF

chmod +x /root/check_bbr3.sh
echo "/root/check_bbr3.sh" > /etc/profile.d/check_bbr3.sh

echo ">>> ♻️ 安装完成，系统将在 5 秒后自动重启..."
sleep 5
reboot
