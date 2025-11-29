sudo bash -c '

echo -e "\n🚀 开始执行【终极美化版 DNS 永久优化】\n"

# -----------------------------------------
# 1️⃣ 暴力写入应急 DNS，先把网络抢回来
# -----------------------------------------
echo -e "📡 [1/6] 正在写入应急公共 DNS（114+阿里+谷歌）……"
cat > /etc/resolv.conf << "EOF"
nameserver 114.114.114.114
nameserver 223.5.5.5
nameserver 8.8.8.8
EOF

chattr +i /etc/resolv.conf 2>/dev/null || true
sleep 2
echo -e "✅ 网络已抢救成功！\n"


# -----------------------------------------
# 2️⃣ 修复 apt 并安装 systemd-resolved
# -----------------------------------------
echo -e "📦 [2/6] 安装 systemd-resolved（提供本地 DNS 解析）……"
export DEBIAN_FRONTEND=noninteractive
apt-get clean >/dev/null 2>&1
apt update --fix-missing -qq >/dev/null 2>&1
apt install -y systemd-resolved libnss-resolve >/dev/null 2>&1 ||
apt install -y --reinstall systemd-resolved >/dev/null 2>&1


# -----------------------------------------
# 3️⃣ 写入最优公共 DNS 配置
# -----------------------------------------
echo -e "⚙️ [3/6] 写入最优公共 DNS（阿里 + 腾讯 + 114 + 百度 + fallback）……"
cat > /etc/systemd/resolved.conf << "EOF"
[Resolve]
DNS=223.5.5.5 119.29.29.29 114.114.114.114 180.76.76.76
FallbackDNS=8.8.8.8 1.1.1.1
DNSSEC=no
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=yes
EOF


# -----------------------------------------
# 4️⃣ 切换到 systemd 的 stub-resolv.conf
# -----------------------------------------
echo -e "🔧 [4/6] 切换到 systemd 的 127.0.0.53 本地 DNS 模式……"

chattr -i /etc/resolv.conf 2>/dev/null || true
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null ||
cp -f /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null


# -----------------------------------------
# 5️⃣ 重启 systemd-resolved
# -----------------------------------------
echo -e "🔄 [5/6] 重启 systemd-resolved ……"
systemctl enable --now systemd-resolved >/dev/null 2>&1
sleep 2


# -----------------------------------------
# 6️⃣ 测试解析并最终锁死 resolv.conf
# -----------------------------------------
echo -e "🔍 [6/6] 正在进行最终 DNS 测试……"
sleep 2

if dig +short baidu.com @127.0.0.53 | grep -q "[0-9]"; then
    echo -e "🎉 DNS 测试通过！"
    echo -e "🔒 正在锁死 /etc/resolv.conf……"

    chattr -i /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.53" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null && \
        echo -e "🔥 锁死成功！DNS 将永远指向 systemd-resolved，不会被云厂商改回！\n"
else
    echo -e "⚠️ DNS 测试失败，已不执行锁死。\n"
fi


# 显示当前 DNS 状态
echo -e "📡 当前 DNS 状态：\n"
resolvectl status 2>/dev/null | grep -A 2 "DNS Servers" || cat /etc/resolv.conf

echo -e "\n🧪 再次测试解析：\n"
dig +short baidu.com | head -5

echo -e "\n🎊 全部完成！DNS 将保持最快最稳定状态！\n"

'
