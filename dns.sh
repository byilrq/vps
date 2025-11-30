sudo bash -c '

echo -e "\n🚀 开始执行【海外 VPS DNS 优化 + 永久锁死】\n"

# -----------------------------------------
# 1️⃣ 应急 DNS（强制网络立即恢复）
# -----------------------------------------
echo -e "📡 [1/6] 设置应急 DNS（1.1.1.1 + 8.8.8.8）……"
cat > /etc/resolv.conf << "EOF"
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

chattr +i /etc/resolv.conf 2>/dev/null || true
sleep 2
echo -e "✅ 应急 DNS 已生效！\n"


# -----------------------------------------
# 2️⃣ 修复 apt 并安装 systemd-resolved
# -----------------------------------------
echo -e "📦 [2/6] 安装 systemd-resolved……"
export DEBIAN_FRONTEND=noninteractive
apt-get clean >/dev/null 2>&1
apt update --fix-missing -qq >/dev/null 2>&1
apt install -y systemd-resolved libnss-resolve >/dev/null 2>&1 ||
apt install -y --reinstall systemd-resolved >/dev/null 2>&1


# -----------------------------------------
# 3️⃣ 写入最优海外 DNS 配置
# -----------------------------------------
echo -e "⚙️ [3/6] 写入 Cloudflare + Google DNS 配置……"
cat > /etc/systemd/resolved.conf << "EOF"
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
DNSSEC=no
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=yes
EOF


# -----------------------------------------
# 4️⃣ 启用 systemd 的 stub-resolv.conf
# -----------------------------------------
echo -e "🔧 [4/6] 切换为 127.0.0.53 本地 DNS……"
chattr -i /etc/resolv.conf 2>/dev/null || true
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null ||
cp -f /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null


# -----------------------------------------
# 5️⃣ 重启 resolved
# -----------------------------------------
echo -e "🔄 [5/6] 重启 systemd-resolved ……"
systemctl enable --now systemd-resolved >/dev/null 2>&1
sleep 2


# -----------------------------------------
# 6️⃣ DNS 测试并锁死 resolv.conf
# -----------------------------------------
echo -e "🔍 [6/6] 测试 DNS 解析……"
sleep 2

if dig +short cloudflare.com @127.0.0.53 | grep -q "[0-9]"; then
    echo -e "🎉 DNS 测试成功！准备锁死 resolv.conf……"

    chattr -i /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.53" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null && \
        echo -e "🔥 锁死成功！DNS 永久固定，不会再被云厂商修改。\n"
else
    echo -e "⚠️ DNS 测试失败，本次不锁死 resolv.conf。\n"
fi


# 显示当前 DNS 状态
echo -e "📡 当前 DNS 设置：\n"
resolvectl status 2>/dev/null | grep -A 2 "DNS Servers" || cat /etc/resolv.conf

echo -e "\n🧪 测试解析 cloudflare.com：\n"
dig +short cloudflare.com | head -5

echo -e "\n🎊 已完成！海外 VPS DNS = Cloudflare + Google，速度最优、重启不变！\n"

'
