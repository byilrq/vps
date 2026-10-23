#!/bin/ash
#
# Alpine Linux use "ash" as the default shell.

exec >/dev/tty0 2>&1

# Delete the initial script itself to prevent to be executed in the new system.
rm -f /etc/local.d/ddlinuxConf.start /etc/local.d/ubuntuConf.start
rm -f /etc/runlevels/default/local

# Install necessary components.
apk update
apk add coreutils grep sed

# Get Debian/Ubuntu Linux configurations.
confFile='/root/alpine.config'
[ -s "$confFile" ] || { echo '[ERROR] Missing local DD configuration.' >&2; exit 1; }

# Read configs from initial file.
IncDisk=$(grep "IncDisk" $confFile | awk '{print $2}')
LinuxMirror=$(grep -w "LinuxMirror" $confFile | awk '{print $2}')
alpineVer=$(grep "alpineVer" $confFile | awk '{print $2}')
distYearsNum=$(grep "ubuntuDigital" $confFile | awk '{print $2}' | cut -d'.' -f 1)
TimeZone1=$(grep "TimeZone" $confFile | awk '{print $2}' | cut -d'/' -f 1)
TimeZone2=$(grep "TimeZone" $confFile | awk '{print $2}' | cut -d'/' -f 2)
tmpWORD=$(grep -w "tmpWORD" $confFile | awk '{print $2}')
sshPORT=$(grep "sshPORT" $confFile | awk '{print $2}')
networkAdapter=$(grep "networkAdapter" $confFile | awk '{print $2}')
IPv4=$(grep "IPv4" $confFile | awk '{print $2}')
MASK=$(grep "MASK" $confFile | awk '{print $2}')
ipPrefix=$(grep "ipPrefix" $confFile | awk '{print $2}')
actualIp4Prefix=$(grep "actualIp4Prefix" $confFile | awk '{print $2}')
GATE=$(grep "GATE" $confFile | awk '{print $2}')
ipDNS1=$(grep "ipDNS1" $confFile | awk '{print $2}')
ipDNS2=$(grep "ipDNS2" $confFile | awk '{print $2}')
iAddrNum=$(grep "iAddrNum" $confFile | awk '{print $2}')
writeIpsCmd=$(grep "writeIpsCmd" $confFile | awk '{print $2}')
ip6Addr=$(grep "ip6Addr" $confFile | awk '{print $2}')
ip6Mask=$(grep "ip6Mask" $confFile | awk '{print $2}')
actualIp6Prefix=$(grep "actualIp6Prefix" $confFile | awk '{print $2}')
ip6Gate=$(grep "ip6Gate" $confFile | awk '{print $2}')
ip6DNS1=$(grep "ip6DNS1" $confFile | awk '{print $2}')
ip6DNS2=$(grep "ip6DNS2" $confFile | awk '{print $2}')
i6AddrNum=$(grep "i6AddrNum" $confFile | awk '{print $2}')
writeIp6sCmd=$(grep "writeIp6sCmd" $confFile | awk '{print $2}')
setIPv6=$(grep "setIPv6" $confFile | awk '{print $2}')
HostName=$(grep "HostName" $confFile | awk '{print $2}')
DDURL=$(grep "DDURL" $confFile | awk '{print $2}')
DEC_CMD=$(sed -n 's/^DEC_CMD  //p' "$confFile")
targetLinuxMirror=$(grep "targetLinuxMirror" $confFile | awk '{print $2}')
targetLinuxSecurityMirror=$(grep "targetLinuxSecurityMirror" $confFile | awk '{print $2}')
setFail2banStatus=$(grep "setFail2banStatus" $confFile | awk '{print $2}')
serialConsolePropertiesForGrub=$(grep "serialConsolePropertiesForGrub" $confFile | sed -e 's/serialConsolePropertiesForGrub  //g')

# Reset configurations of repositories.
true >/etc/apk/repositories
setup-apkrepos $LinuxMirror/$alpineVer/main
setup-apkcache /var/cache/apk

# Add community mirror.
sed -i '$a\'$LinuxMirror'/'$alpineVer'/community' /etc/apk/repositories
# Add edge testing to the repositories
# sed -i '$a\'$LinuxMirror'/edge/testing' /etc/apk/repositories

# Synchronize time from hardware.
hwclock -s || true

# Install necessary components.
apk update
apk add hdparm multipath-tools util-linux wget xz

# Start dd.
set -o pipefail
if ! wget --no-check-certificate --report-speed=bits --tries=0 --timeout=10 --wait=5 -O- "$DDURL" | $DEC_CMD | dd of="$IncDisk" status=progress; then
    echo '[ERROR] Image download, decompression or disk write failed. Installation stopped; use the VPS console/rescue system.' >&2
    exit 1
fi
sync

# Get a valid loop device.
loopDevice=$(echo $(losetup -f))
loopDeviceNum=$(echo $(losetup -f) | cut -d'/' -f 3)

# Make a soft link between valid loop device and disk.
losetup $loopDevice $IncDisk

if [[ "$distYearsNum" -le "22" ]]; then
	# Get mapper partition.
	mapperDevice=$(kpartx -av $loopDevice | grep "$loopDeviceNum" | head -n 1 | awk '{print $3}')
	# Mount Ubuntu dd partition to /mnt .
	mount /dev/mapper/$mapperDevice /mnt
	# Disable IPv6.
	[[ "$setIPv6" == "0" ]] && {
		sed -ri 's/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 ipv6.disable=1"/g' /mnt/etc/default/grub
		sed -ri 's/ro net.ifnames=0 biosdevname=0/ro net.ifnames=0 biosdevname=0 ipv6.disable=1/g' /mnt/boot/grub/grub.cfg
	}
	# Add console, Ubuntu 20.04 is different from Ubuntu 22.04 .
	[[ ! $(grep "console=tty[0-9] console=ttyS[0-9]" /mnt/etc/default/grub.d/50-cloudimg-settings.cfg) ]] && {
		sed -ri 's/net.ifnames=0 biosdevname=0/net.ifnames=0 biosdevname=0 console=tty1 console=ttyS0/g' /mnt/etc/default/grub
		sed -ri 's/net.ifnames=0 biosdevname=0/net.ifnames=0 biosdevname=0 console=tty1 console=ttyS0/g' /mnt/boot/grub/grub.cfg
	}
	# Replace serial console parameters.
	[[ -n "$serialConsolePropertiesForGrub" && $(echo "$serialConsolePropertiesForGrub" | sed 's/[[:space:]]/#/g' | grep "ttyAMA[0-9]") ]] && {
		sed -ri 's/console=tty1/console=tty1 console=ttyAMA0/g' /mnt/etc/default/grub.d/50-cloudimg-settings.cfg
		[[ ! $(grep "console=tty[0-9] console=ttyS[0-9]" /mnt/etc/default/grub.d/50-cloudimg-settings.cfg) ]] && {
			sed -ri 's/console=tty1/console=tty1 console=ttyAMA0/g' /mnt/etc/default/grub
		}
		sed -ri 's/console=tty1/console=tty1 console=ttyAMA0/g' /mnt/boot/grub/grub.cfg
	}
else
	# In cloud images of Ubuntu 24.04 and above, the partition of main system files is in the first, the partition of "/grub/grub.cfg" is in the last.
	mapperDevice=$(kpartx -av $loopDevice | grep "$loopDeviceNum" | sort -rn | head -n 1 | awk '{print $3}')
	mount /dev/mapper/$mapperDevice /mnt
	[[ "$setIPv6" == "0" ]] && {
		sed -ri 's/ro net.ifnames=0 biosdevname=0/ro net.ifnames=0 biosdevname=0 ipv6.disable=1/g' /mnt/grub/grub.cfg
	}
	[[ -n "$serialConsolePropertiesForGrub" && $(echo "$serialConsolePropertiesForGrub" | sed 's/[[:space:]]/#/g' | grep "ttyAMA[0-9]") ]] && {
		sed -ri 's/console=tty1/console=tty1 console=ttyAMA0/g' /mnt/grub/grub.cfg
	}
	umount /mnt
	mapperDevice=$(kpartx -av $loopDevice | grep "$loopDeviceNum" | head -n 1 | awk '{print $3}')
	mount /dev/mapper/$mapperDevice /mnt
	[[ "$setIPv6" == "0" ]] && {
		sed -ri 's/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 ipv6.disable=1"/g' /mnt/etc/default/grub
	}
	[[ -n "$serialConsolePropertiesForGrub" && $(echo "$serialConsolePropertiesForGrub" | sed 's/[[:space:]]/#/g' | grep "ttyAMA[0-9]") ]] && {
		sed -ri 's/console=tty1/console=tty1 console=ttyAMA0/g' /mnt/etc/default/grub.d/50-cloudimg-settings.cfg
	}
fi

# Create NoCloud seed for cloud-init.
mkdir -p /mnt/var/lib/cloud/seed/nocloud

# meta-data：cloud-init 需要识别的元数据
cat > /mnt/var/lib/cloud/seed/nocloud/meta-data << EOF
instance-id: i-ddinstall-${HostName}
local-ipv4: ${IPv4}
local-hostname: ${HostName}
hostname: ${HostName}
EOF

# user-data：云初始化脚本
cat > /mnt/var/lib/cloud/seed/nocloud/user-data << 'EOFUSERDATA'
#!/bin/bash
set -e

# 设置密码（直接在这里设置，不依赖 yaml 解析）
echo 'root:tmpWORD' | chpasswd

# 设置主机名
hostnamectl set-hostname 'HostName' 2>/dev/null || hostname 'HostName'
sed -i "s/^127.0.1.1.*/127.0.1.1\tHostName/" /etc/hosts
grep -q '^127.0.1.1' /etc/hosts || echo -e "127.0.1.1\tHostName" >> /etc/hosts

# SSH 配置
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -ri 's/^#?Port.*/Port sshPORT/g' /etc/ssh/sshd_config

# 重启 SSH
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# 安装基础工具
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget dnsutils fail2ban 2>&1 | tail -5 || true

# 启用 fail2ban
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
EOFUSERDATA

# 替换占位符
sed -i "s|tmpWORD|${tmpWORD}|g" /mnt/var/lib/cloud/seed/nocloud/user-data
sed -i "s|sshPORT|${sshPORT}|g" /mnt/var/lib/cloud/seed/nocloud/user-data
sed -i "s|HostName|${HostName}|g" /mnt/var/lib/cloud/seed/nocloud/user-data

# Disable any datahouse.
# Reference: https://github.com/canonical/cloud-init/issues/3772
echo 'datasource_list: [ NoCloud, None ]' >/mnt/etc/cloud/cloud.cfg.d/90_dpkg.cfg

# Disable sshd service to read configs from "ssh.socket" otherwise any changes on "/etc/ssh/sshd_config" will not take effects after Ubuntu 22.10, 23.04, 23.10… .
# This is a preparation for dealing with the future versions of Ubuntu for example Ubuntu 24.04 LTS and later.
# Reference: https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189/23
rm -rf /mnt/etc/systemd/system/ssh.service.d/*.conf
sed -ri 's#^Include /etc/ssh/sshd_config.d/#\#Include /etc/ssh/sshd_config.d/#g' /mnt/etc/ssh/sshd_config

# Permit root user login by password, change ssh port.
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /mnt/etc/ssh/sshd_config
sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/g' /mnt/etc/ssh/sshd_config
sed -ri 's/^#?Port.*/Port '${sshPORT}'/g' /mnt/etc/ssh/sshd_config
# Change ssh port for service of "ssh.socket".
# https://askubuntu.com/questions/1439461/ssh-default-port-not-changing-ubuntu-22-10
sed -ri 's/^ListenStream=.*/ListenStream='${sshPORT}'/g' /mnt/lib/systemd/system/ssh.socket
sed -ri 's/^Accept=.*/Accept=yes/g' /mnt/lib/systemd/system/ssh.socket

# Disable installing fail2ban.
[[ "$setFail2banStatus" != "1" ]] && {
	sed -ri 's/dnsutils fail2ban/dnsutils/g' /mnt/var/lib/cloud/seed/nocloud/user-data
	sed -i '/fail2ban/d' /mnt/var/lib/cloud/seed/nocloud/user-data
}

# Preserve the original cloud-init datasource compatibility workaround.
utilProgram=$(find /mnt/usr/lib/python* -name "util.py" | grep "cloudinit" | head -n 1)
sed -ri 's/iso9660/osi9876/g' $utilProgram
sed -ri 's#"blkid"#"echo"#g' $utilProgram

# Umount mounted directory and loop device.
umount /mnt
kpartx -dv $loopDevice
losetup -d $loopDevice

# Reboot, the temporary intermediary system of AlpineLinux which is executing in memory will be destroyed during the power down and then server will reboot to the newly installed system immediately.
exec reboot
