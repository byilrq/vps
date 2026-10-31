#!/bin/bash
##
## License: GPL
## Local Debian/Ubuntu installer. Alpine is retained only as the temporary DD runtime.
## Local-only script/template edition, 2026-10-23. Original GPL attribution retained.
## Default root password: LeitboGi0ro
## Written By MoeClub.org
## Blog: https://moeclub.org
## Modified By 秋水逸冰
## Blog: https://teddysun.com/
## Modified By VPS收割者
## Blog: https://www.idcoffer.com/
## Modified By airium
## Blog: https://github.com/airium
## Modified By 王煎饼
## Github: https://github.com/bin456789/
## Modified By nat.ee
## Forum: https://hostloc.com/space-uid-49984.html
## Modified By Bohan Yang
## Twitter: https://twitter.com/brentybh
## Modified By Leitbogioro
## Blog: https://www.zhihu.com/column/originaltechnic


# Resolve before checkSys or any other routine changes the working directory.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

show_help() {
    cat <<'HELP'
Local Debian/Ubuntu reinstall engine
  bash d.sh                               Interactive menu (recommended)
  bash engine.sh --check                   Local files/syntax only; no root/network/writes
  bash engine.sh -debian 12|13 [options]    Debian netboot/preseed
  bash engine.sh -ubuntu 22.04|24.04 [options]

Options: -port PORT -pwd PASSWORD -hostname NAME -setdisk /dev/DISK
         --network dhcp|static --ip-addr IP --ip-mask MASK --ip-gate GATE
         --ip6-addr IP --ip6-mask PREFIX --ip6-gate GATE
         -architecture amd64|arm64 -dd URL -filetype raw|xz|gz
         --init-file /absolute/local/script.sh
Images, netboot kernels and distribution packages still require networking.
Only Debian and Ubuntu targets are supported; there is no remote-script fallback.
WARNING: Installation permanently overwrites the selected target disk.
HELP
}

check_local_files() {
    local f
    for f in engine.sh ubuntuInit.sh \
        CloudInit/dhcp_interfaces.cfg \
        CloudInit/ipv4_static_interfaces.cfg \
        CloudInit/ipv4_dhcp_ipv6_static_interfaces.cfg \
        CloudInit/ipv4_static_ipv6_dhcp_interfaces.cfg \
        CloudInit/ipv4_static_ipv6_static_interfaces.cfg \
        CloudInit/ipv6_static_interfaces.cfg; do
        [[ -f "$SCRIPT_DIR/$f" && -s "$SCRIPT_DIR/$f" && -r "$SCRIPT_DIR/$f" ]] || {
            printf '[ERROR] Missing/empty/unreadable local file: %s\n' "$SCRIPT_DIR/$f" >&2
            return 1
        }
    done
    for f in engine.sh ubuntuInit.sh; do
        bash -n "$SCRIPT_DIR/$f" || return 1
    done
    return 0
}

case "${1:-}" in
    --check)
        [[ $# -eq 1 ]] || { show_help >&2; exit 2; }
        check_local_files || exit 1
        printf '[OK] Local scripts and all 6 network templates are present; syntax passed.\n'
        exit 0 ;;
    -h|--help) show_help; exit 0 ;;
    '') show_help; exit 2 ;;
esac

# color
underLine='\033[4m'
aoiBlue='\033[36m'
blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'

export tmpVER=''
export tmpDIST=''
export tmpURL=''
export tmpWORD=''
export tmpMirror=''
export tmpDHCP=''
export targetRelese=''
export finalDIST=''
export customInitFile=''
export TimeZone=''
export setIpStack=''
export ipAddr=''
export ipMask=''
export ipGate=''
export ipDNS='8.8.8.8 1.1.1.1'
export ip6Addr=''
export ip6Mask=''
export ip6Gate=''
export ip6DNS='2001:4860:4860::8888 2606:4700:4700::1111'
export IncDisk=''
export interface=''
export interfaceSelect=''
export setInterfaceName='0'
export autoPlugAdapter='1'
export IsCN=''
export Relese=''
export sshPORT=''
export ddMode='0'
export setNet='0'
export tmpSetIPv6=''
export setIPv6='1'
export setRaid=''
export setDisk=''
export swapSpace='0'
export partitionTable='mbr'
export fileSystem=''
export setMemCheck='1'
export setCloudKernel=''
export enableBBR='0'
export isMirror='0'
export FindDists='0'
export setFileType=''
export loaderMode='0'
export setMotd=''
export setDns=''
export LANG="en_US.UTF-8"
export LANGUAGE="en_US:en"
export IncFirmware='0'
export SpikCheckDIST='0'
export GRUBDIR=''
export GRUBFILE=''
export GRUBVER=''
export VER=''
export setCMD=""
export setConsole=''
export setFail2ban=''
export setAutoConfig='1'
export FirmwareImage=''
export AddNum='1'
export DebianModifiedProcession=''

while [[ $# -ge 1 ]]; do
    case "$1" in
        -architecture|-debian|-Debian|-ubuntu|-Ubuntu|-dd|--image|--networkstack|\
        --ip-addr|--ip-mask|--ip-gate|--ip-dns|--ip6-addr|--ip6-mask|--ip6-gate|--ip6-dns|\
        --network|--adapter|--autoplugadapter|--fail2ban|-mirror|-raid|-setdisk|-swap|\
        -virtualmemory|-virtualram|-partition|-filesystem|-timezone|-cmd|-console|\
        --cloudkernel|--init-file|-filetype|-port|-pwd|-password|-hostname|--setipv6)
            [[ $# -ge 2 ]] || { printf '[ERROR] Missing value for %s\n' "$1" >&2; exit 2; } ;;
    esac
	case $1 in
	-architecture)
		shift
		tmpVER="$1"
		shift
		;;
	-debian | -Debian)
		shift
		Relese='Debian'
		tmpDIST="$1"
		shift
		;;
	-ubuntu | -Ubuntu)
		shift
		ddMode='1'
		finalDIST="$1"
		targetRelese='Ubuntu'
		shift
		;;
	-dd | --image)
		shift
		ddMode='1'
		tmpURL="$1"
		shift
		;;
	--networkstack)
		shift
		setIpStack="$1"
		shift
		;;
	--ip-addr)
		shift
		ipAddr="$1"
		shift
		;;
	--ip-mask)
		shift
		ipMask="$1"
		shift
		;;
	--ip-gate)
		shift
		ipGate="$1"
		shift
		;;
	--ip-dns)
		shift
		ipDNS="$1"
		ipDNSChanged='1'
		shift
		;;
	--ip6-addr)
		shift
		ip6Addr="$1"
		shift
		;;
	--ip6-mask)
		shift
		ip6Mask="$1"
		shift
		;;
	--ip6-gate)
		shift
		ip6Gate="$1"
		shift
		;;
	--ip6-dns)
		shift
		ip6DNS="$1"
		ip6DNSChanged='1'
		shift
		;;
	--network)
		shift
		tmpDHCP="$1"
		shift
		;;
	--adapter)
		shift
		interfaceSelect="$1"
		shift
		;;
	--netdevice-unite)
		shift
		setInterfaceName='1'
		;;
	--autoplugadapter)
		shift
		autoPlugAdapter="$1"
		shift
		;;
	--loader)
		shift
		loaderMode='1'
		;;
	--fail2ban)
		shift
		setFail2ban="$1"
		shift
		;;
	--setdns)
		shift
		setDns='1'
		;;
	-mirror)
		shift
		isMirror='1'
		tmpMirror="$1"
		shift
		;;
	-raid)
		shift
		setRaid="$1"
		shift
		;;
	-setdisk)
		shift
		setDisk="$1"
		shift
		;;
	-swap | -virtualmemory | -virtualram)
		shift
		setSwap="$1"
		shift
		;;
	-partition)
		shift
		partitionTable="$1"
		shift
		;;
	-filesystem)
		shift
		setFileSystem="$1"
		shift
		;;
	-timezone)
		shift
		TimeZone="$1"
		shift
		;;
	-cmd)
		shift
		setCMD="$1"
		shift
		;;
	-console)
		shift
		setConsole="$1"
		shift
		;;
	-firmware)
		shift
		IncFirmware="1"
		shift
		;;
	--cloudkernel)
		shift
		setCloudKernel="$1"
		shift
		;;
	--init-file)
		shift
		customInitFile="$1"
		shift
		;;
	-filetype)
		shift
		setFileType="$1"
		shift
		;;
	-port)
		shift
		sshPORT="$1"
		shift
		;;
	-pwd | -password)
		shift
		tmpWORD="$1"
		shift
		;;
	-hostname)
		shift
		tmpHostName="$1"
		shift
		;;
	--setipv6)
		shift
		tmpSetIPv6="$1"
		shift
		;;
	--bbr)
		shift
		enableBBR="1"
		;;
	--allbymyself)
		shift
		setAutoConfig='0'
		;;
	--nomemcheck)
		shift
		setMemCheck='0'
		;;
	*)
        printf '[ERROR] Unsupported option/target: %s\n' "$1" >&2
        show_help >&2
        exit 2
        ;;
	esac
done


# Fail before checkSys, disk, boot or package changes.
check_local_files || exit 1
if [[ "$targetRelese" == 'Ubuntu' ]]; then
    case "${finalDIST:-22.04}" in
        22.04|jammy) finalDIST='22.04' ;;
        24.04|noble) finalDIST='24.04' ;;
        *) printf '[ERROR] Supported Ubuntu versions: 22.04 / 24.04.\n' >&2; exit 2 ;;
    esac
else
    case "${tmpDIST:-13}" in
        12|bookworm) tmpDIST='12' ;;
        13|trixie) tmpDIST='13' ;;
        *) printf '[ERROR] Supported Debian netboot versions: 12 / 13.\n' >&2; exit 2 ;;
    esac
    [[ "$ddMode" == '0' ]] || {
        printf '[ERROR] Debian only supports netboot; -dd is only supported with -ubuntu.\n' >&2; exit 2
    }
    Relese='Debian'
fi
if [[ -n "$customInitFile" ]]; then
    [[ "$targetRelese" == 'Ubuntu' ]] || {
        printf '[ERROR] --init-file is only valid in DD mode.\n' >&2; exit 2
    }
    [[ "$customInitFile" != *://* && -f "$customInitFile" && -s "$customInitFile" && -r "$customInitFile" ]] || {
        printf '[ERROR] --init-file requires a readable nonempty LOCAL file.\n' >&2; exit 2
    }
    customInitFile="$(cd -- "$(dirname -- "$customInitFile")" && pwd -P)/$(basename -- "$customInitFile")" || exit 1
    bash -n "$customInitFile" || exit 1
fi

# Check Root
[[ "$EUID" -ne '0' || $(id -u) != '0' ]] && echo -ne "\n[${red}Error${plain}] This script must be executed as root!\n\nTry to type:\n${yellow}sudo -s\n${plain}\nAfter entering the password, switch to root dir to execute this script:\n${yellow}cd ~${plain}\n\n" && exit 1

# Ping delay to YouTube($2), Instagram($3), Wikipedia($4) and BBC($5), support both IPv4 and IPv6 access, $1 is $IPStackType
function checkCN() {
	for TestUrl in "$2" "$3" "$4" "$5"; do
		# "rtt" result of ping command of Alpine Linux is "round-trip" and it can't handle "sed -n" well.
		IPv4PingDelay=$(ping -4 -c 2 -w 2 "$TestUrl" | grep "rtt\|round-trip" | cut -d'/' -f5 | awk -F'.' '{print $NF}' | sed -E '/^[0-9]\+\(\.[0-9]\+\)\?$/p')
		IPv6PingDelay=$(ping -6 -c 2 -w 2 "$TestUrl" | grep "rtt\|round-trip" | cut -d'/' -f5 | awk -F'.' '{print $NF}' | sed -E '/^[0-9]\+\(\.[0-9]\+\)\?$/p')
		if [[ "$1"="BiStack" ]]; then
			[[ "$IPv4PingDelay" != "" || "$IPv6PingDelay" != "" ]] && tmpIsCN+="" || tmpIsCN+="cn"
		elif [[ "$1"="IPv4Stack" ]]; then
			[[ "$IPv4PingDelay" != "" ]] && tmpIsCN+="" || tmpIsCN+="cn"
		elif [[ "$1"="IPv6Stack" ]]; then
			[[ "$IPv6PingDelay" != "" ]] && tmpIsCN+="" || tmpIsCN+="cn"
		fi
	done
	# If testing servers are all unaccessible, the server may be in mainland of China.
	[[ $(echo $tmpIsCN | grep -o "cn" | wc -l) == "4" ]] && {
		IsCN="cn"
		[[ "$ipDNSChanged" != "1" ]] && ipDNS="119.29.29.29 223.6.6.6"
		[[ "$ip6DNSChanged" != "1" ]] && ip6DNS="2402:4e00:: 2400:3200::1"
	}
}

# "$1" is "$ipDNS" or "$ip6DNS"
# Preserve the DNS separator expected by Debian.
function checkDNS() {
	printf '%s\n' "$1"
}

function dependence() {
	Full='0'
	for BIN_DEP in $(echo "$1" | sed 's/,/\n/g'); do
		if [[ -n "$BIN_DEP" ]]; then
			Found='0'
			for BIN_PATH in $(echo "$PATH" | sed 's/:/\n/g'); do
				ls $BIN_PATH/$BIN_DEP >/dev/null 2>&1
				if [ $? == '0' ]; then
					Found='1'
					break
				fi
			done
			if [ "$Found" == '1' ]; then
				echo -en "[${green}ok${plain}]\t"
			else
				Full='1'
				echo -en "[${red}Not Install${plain}]"
			fi
			echo -en "\t$BIN_DEP\n"
		fi
	done
	if [ "$Full" == '1' ]; then
		echo -ne "\n[${red}Error${plain}] Please use '${yellow}apt-get${plain}' or '${yellow}yum / dnf${plain}' install it. \n\n"
		exit 1
	fi
}

function selectMirror() {
	[ $# -ge 3 ] || exit 1
	Relese=$(echo "$1" | sed -r 's/(.*)/\L\1/')
	DIST=$(echo "$2" | sed 's/\ //g' | sed -r 's/(.*)/\L\1/')
	VER=$(echo "$3" | sed 's/\ //g' | sed -r 's/(.*)/\L\1/')
	New=$(echo "$4" | sed 's/\ //g')
	[ -n "$Relese" ] && [ -n "$DIST" ] && [ -n "$VER" ] || exit 1
	if [ "$Relese" == "debian" ]; then
        TEMP="SUB_MIRROR/dists/${DIST}/main/installer-${VER}/current/images/netboot/debian-installer/${VER}/initrd.gz"
    elif [ "$Relese" == "alpinelinux" ]; then
        TEMP="SUB_MIRROR/${DIST}/releases/${VER}/netboot/${InitrdName}"
    fi
	[ -n "$TEMP" ] || exit 1
	mirrorStatus=0
	declare -A MirrorBackup
	if [[ "$IsCN" == "cn" ]]; then
		MirrorBackup=(["debian0"]="" ["debian1"]="http://mirror.sjtu.edu.cn/debian" ["debian2"]="http://mirror.nju.edu.cn/debian" ["debian3"]="https://mirrors.tuna.tsinghua.edu.cn/debian" ["debian4"]="https://mirrors.aliyun.com/debian-archive/debian" ["alpinelinux0"]="" ["alpinelinux1"]="http://mirror.nju.edu.cn/alpine" ["alpinelinux2"]="http://mirrors.tuna.tsinghua.edu.cn/alpine" )
	else
		MirrorBackup=(["debian0"]="" ["debian1"]="http://deb.debian.org/debian" ["debian2"]="http://mirrors.ocf.berkeley.edu/debian" ["debian3"]="http://ftp.yz.yamagata-u.ac.jp/pub/linux/debian" ["debian4"]="http://archive.debian.org/debian" ["alpinelinux0"]="" ["alpinelinux1"]="http://dl-cdn.alpinelinux.org/alpine" ["alpinelinux2"]="https://mirrors.edge.kernel.org/alpine" )
	fi
	echo "$New" | grep -q '^http://\|^https://\|^ftp://' && MirrorBackup[${Relese}0]="${New%*/}"
	for mirror in $(echo "${!MirrorBackup[@]}" | sed 's/\ /\n/g' | sort -n | grep "^$Relese"); do
		Current="${MirrorBackup[$mirror]}"
		[ -n "$Current" ] || continue
		MirrorURL=$(echo "$TEMP" | sed "s#SUB_MIRROR#${Current}#g")
		wget --no-check-certificate --spider --timeout=3 -o /dev/null "$MirrorURL"
		[ $? -eq 0 ] && mirrorStatus=1 && break
	done
	[ $mirrorStatus -eq 1 ] && echo "$Current" || exit 1
}

function getIPv4Address() {
	# Differences from scope link, scope host and scope global of IPv4, reference: https://qiita.com/testnin2/items/7490ff01a4fe1c7ad61f
	allI4Addrs=$(ip -4 addr show | grep -wA 1024 "$interface4" | grep -w "$interface4" | grep -wv "lo\|host" | grep -w "inet" | grep -w "scope global*\|link*" | awk -F " " '{for (i=2;i<=NF;i++)printf("%s ", $i);print ""}' | awk '{print$1}')
	[[ -z "$allI4Addrs" ]] && allI4Addrs=$(ip -4 addr show | grep -wA 1024 "$interface4" | grep -wv "lo\|host" | grep -w "inet" | grep -w "scope global*\|link*" | awk -F " " '{for (i=2;i<=NF;i++)printf("%s ", $i);print ""}' | awk '{print$1}')
	iAddr=$(echo "$allI4Addrs" | head -n 1)
	iAddrNum=$(echo "$allI4Addrs" | wc -l)
	collectAllIpv4Addresses "$iAddrNum"
	ipAddr=$(echo ${iAddr} | cut -d'/' -f1)
	ipPrefix=$(echo ${iAddr} | cut -d'/' -f2)
	ipMask=$(netmask "$ipPrefix")
	# Get real IPv4 subnet of current System
	ip4RouteScopeLink=$(ip -4 route show scope link | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -w "$interface4" | grep -w "$ipAddr" | grep -m1 -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)
	actualIp4Prefix=$(ip -4 route show scope link | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -w "$interface4" | grep -w "$ip4RouteScopeLink" | head -n 1 | awk '{print $1}' | awk -F '/' '{print $2}')
	[[ -z "$actualIp4Prefix" ]] && actualIp4Prefix="$ipPrefix"
	actualIp4Subnet=$(netmask "$actualIp4Prefix")
	# In most situation, at least 99.9% probability, the first hop of the network should be the same as the available gateway.
	# But in 0.1%, they are actually different.
	# Because one of the first hop of a tested machine is 5.45.72.1, I told Debian installer this router as a gateway
	# But installer said the correct gateway should be 5.45.76.1, in a typical network, for example, your home,
	# the default gateway is the same as the first route hop of the machine, it may be 192.168.0.1.
	# If possible, we should configure out the real available gateway of the network.
	FirstRoute=$(ip -4 route show default | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -w "via" | grep -w "dev $interface4*" | head -n 1 | awk -F " " '{for (i=3;i<=NF;i++)printf("%s ", $i);print ""}' | awk '{print$1}')
	# We should find it in ARP, the first hop IP and gateway IP is managed by the same device, use device mac address to configure it out.
	RouterMac=$(arp -n | grep "$FirstRoute" | awk '{print$3}')
	FrFirst=$(echo "$FirstRoute" | cut -d'.' -f 1,2)
	FrThird=$(echo "$FirstRoute" | cut -d'.' -f 3)
	# Print all matched available gateway.
	ipGates=$(ip -4 route show | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -v "via" | grep -w "dev $interface4*" | grep -w "proto*" | grep -w "scope global\|link src $ipAddr*" | awk '{print$1}')
	# Figure out the line of this list.
	ipGateLine=$(echo "$ipGates" | wc -l)
	# The line determines the cycling times.
	for ((i = 1; i <= "$ipGateLine"; i++)); do
		# Current one gateway of the ip gateways. the formart is as of 10.0.0.0/22
		tmpIpGate=$(echo "$ipGates" | sed -n ''$i'p')
		# Intercept a standard IPv4 address.
		tmpIgAddr=$(echo $tmpIpGate | cut -d'/' -f1)
		# Intercept the prefix of the gateway.
		tmpIgPrefix=$(echo $tmpIpGate | cut -d'/' -f2)
		# Calculate the first ip in all network segment, it should be the the same range with gateway in this network.
		minIpGate=$(ipv4Calc "$tmpIgAddr" "$tmpIgPrefix" | grep "FirstIP:" | awk '{print$2}')
		# Intercept the A and B class of the current ip address of gateway.
		tmpIpGateFirst=$(echo "$minIpGate" | cut -d'.' -f 1,2)
		tmpIpGateThird=$(echo "$minIpGate" | cut -d'.' -f 3)
		# If the class A and B class of the current local ip address is as same as current gateway, this gateway may a valid one.
		[[ "$FrFirst" == "$tmpIpGateFirst" ]] && {
			if [[ "$FrThird" == "$tmpIpGateThird" ]]; then
				ipGate="$FirstRoute"
				break
			elif [[ "$FrThird" != "$tmpIpGateThird" ]]; then
				# The A, B and C class address of min ip gate.
				tmpMigFirst=$(echo $minIpGate | cut -d'.' -f 1,2,3)
				# Search it in ARP, it's belonged to the same network device which has been distinguished by mac address of first hop of the IP.
				ipGate=$(arp -n | grep "$tmpMigFirst" | grep "$RouterMac" | awk '{print$1}')
				break
			fi
		}
	done
	# If there is no one of other gateway in this current network, use if access the public internet, the first hop route of this machine as the gateway.
	[[ "$ipGates" == "" || "$ipGate" == "" ]] && ipGate="$FirstRoute"
	transferIPv4AddressFormat "$ipAddr" "$ipGate"
}

# $1 is "$ipAddr", $2 is "$ipGate".
function transferIPv4AddressFormat() {
	# Some cloud providers like Godaddy, Arkecx, Hetzner(include DHCP) etc, the subnet mask of IPv4 static network configuration of their original template OS is incorrect.
	# The following is the sample:
	#
	# auto eth0
	#   iface eth0 inet static
	#     address 190.168.23.175
	#     netmask 255.255.255.240
	#     dns-nameservers 8.8.8.8 8.8.4.4
	#     up ip -4 route add default via 169.254.0.1 dev eth0 onlink
	#
	# The netmask tells the total number of IP in the network is only 15(240 - 255),
	# but we obsessed that there are more than 15 IPv4 addresses between 169.254.0.1 and 190.168.23.175 clearly.
	# So if netmask is 255.255.255.240(prefix is 28), the computer only find IP between 190.168.23.160 and 190.168.23.175,
	# the gateway 169.254.0.1 is obviously not be included in this range.
	# So we need to expand the range of the netmask(reduce the value number of the prefix) to make sure the IPv4 gateway can be contained.
	# If this mistake has not be repaired, Debian installer will return error "untouchable gateway".
	# DHCP IPv4 network(even IPv4 netmask is "32") may not be effected by this situation.
	# The following consulted calculations are calculated by Vultr IPv4 subnet calculator, reference: https://www.vultr.com/resources/subnet-calculator/
	ipv4SubnetCertificate "$1" "$2"
	ipPrefix="$tmpIpMask"
	ipMask=$(netmask "$tmpIpMask")
	# Some servers' provided by Hetzner are so confused because the IPv4 configurations of them are static but they are not fitted with standard, here is a sample:
	#
	# auto ens3
	# iface ens3 inet static
	#     address: 89.163.208.5
	#     netmask: 255.255.255.0
	#     broadcast +
	#     up ip -f inet route add 169.254.0.1 dev ens3
	#     up ip -f inet route add default via 169.254.0.1 dev ens3
	#
	# The A class of address and gateway are entirely different, although we should make sure the value of the suggested subnet mask is "128.0.0.1"(prefix "1")
	# to expand IPv4 range as large as possible, but in above situation, the largest IPv4 range is from 0.0.0.0 to 127.255.255.255, the IPv4 gate "169.254.0.1"
	# can't be included, so the reserve approach is to get the result of "ip -4 route show scope link"(89.163.208.0/24) to ensure the correct subnet and gateway,
	# then we can fix these weird settings from incorrect network router.
	# IPv4 network from Hetzner support dhcp even though it's configurated by static in "/etc/network/interfaces".
	# ip4RangeFirst=`ipv4Calc "$1" "$actualIp4Prefix" | grep "FirstIP:" | awk '{print$2}' | cut -d'.' -f1`
	# ip4RangeLast=`ipv4Calc "$1" "$actualIp4Prefix" | grep "LastIP:" | awk '{print$2}' | cut -d'.' -f1`
	ip4AddrFirst=$(echo $1 | cut -d'.' -f1)
	ip4AddrSecond=$(echo $1 | cut -d'.' -f2)
	ip4GateFirst=$(echo $2 | cut -d'.' -f1)
	ip4GateSecond=$(echo $2 | cut -d'.' -f2)
	# Common ranges of IPv4 intranet:
	# Reference: https://hczhang.cn/network/reserved-ip-addresses.html
	[[ "$ip4AddrFirst""$ip4AddrSecond" != "$ip4GateFirst""$ip4GateSecond" ]] && {
		checkIfIpv4AndIpv6IsLocalOrPublic "$2" ""
		[[ "$ipv4LocalOrPublicStatus" == '1' ]] || [[ "$ip4AddrFirst" != "$ip4GateFirst" ]] || [[ "$ip4AddrSecond" != "$ip4GateSecond" ]] && {
			# [[ -z "$ip4RouteScopeLink" ]] && ipGate=`ipv4Calc "$1" "$ipPrefix" | grep "FirstIP:" | awk '{print$2}'` || ipGate=`ipv4Calc "$ip4RouteScopeLink" "$ipPrefix" | grep "FirstIP:" | awk '{print$2}'`
			if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'alpinelinux' ]]; then
				ipPrefix="$actualIp4Prefix"
				ipMask="$actualIp4Subnet"
				Network4Config="isStatic"
				# Redirecting all actual names of network adapters to "eth0", "eth1"... by force aims to make a convenience to adding gateway(route) in soft hacking process.
				setInterfaceName='1'
			fi
			# Temporary installation of Debian 12 and Kali can't handle IPv4 public address and IPv4 private gateway well, so we prefer to invoke irregular IPv6 parameters to configure network in "busybox" and write static configs for IPv4 in later stage of the installation.
			[[ "$IPStackType" == "BiStack" ]] && {
				[[ "$linux_relese" == 'debian' ]] && {
					BiStackPreferIpv6Status='1'
				}
			}
			# Installation environment of Debian 11 and former releases can't handle either irregular(gateway is not within the range of which is calculated by IP/mask) IPv4 or IPv6 parameters, so we need to execute a "ip route add" trick to make sure the networking of pure IPv4 stack servers works normally in "busybox".
			[[ "$IPStackType" == "IPv4Stack" || "$linux_relese" == 'alpinelinux' ]] && BurnIrregularIpv4Status='1'
		}
	}
	[[ "$interfacesNum" -ge "2" ]] && {
		# If there are two and more network adapters on the system like "eth0" and "eth1" and the first adapter "eth0" plays a role of connecting to the public network by dhcp method,
		# AlpineLinux will prefer to use the last order of the adapter like "eth1" to configure the network instead of "eth0" if assign "ip=dhcp" parameter to the netboot kernel,
		# so we need to switch the network configuration method to static to make sure the expect valid network adapter "eth0" can be activated.
		[[ "$linux_relese" == 'alpinelinux' ]] && Network4Config="isStatic"
	}
}

function netmask() {
	n="${1:-32}"
	b=""
	m=""
	for ((i = 0; i < 32; i++)); do
		[ $i -lt $n ] 2>/dev/null && b="${b}1" || b="${b}0"
	done
	for ((i = 0; i < 4; i++)); do
		s=$(echo "$b" | cut -c$(($(($i * 8)) + 1))-$(($(($i + 1)) * 8)))
		[ "$m" == "" ] && m="$((2#${s}))" || m="${m}.$((2#${s}))"
	done
	echo "$m"
}

# $1 is IPv4 address, $2 is IPv4 subnet.
function ipv4Calc() {
	tmpIp4="$1"
	tmpIp4Mask=$(netmask "$2")

	IFS=. read -r i1 i2 i3 i4 <<<"$tmpIp4"
	IFS=. read -r m1 m2 m3 m4 <<<"$tmpIp4Mask"

	tmpNetwork="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))"
	tmpBroadcast="$((i1 & m1 | 255 - m1)).$((i2 & m2 | 255 - m2)).$((i3 & m3 | 255 - m3)).$((i4 & m4 | 255 - m4))"
	tmpFirstIP="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$(((i4 & m4) + 1))"
	tmpFiLast="$(echo "$tmpFirstIP" | cut -d'.' -f 4)"
	FirstIP="$tmpFirstIP"
	tmpLastIP="$((i1 & m1 | 255 - m1)).$((i2 & m2 | 255 - m2)).$((i3 & m3 | 255 - m3)).$(((i4 & m4 | 255 - m4) - 1))"
	tmpLiLast="$(echo "$tmpLastIP" | cut -d'.' -f 4)"
	LastIP="$tmpLastIP"
	[[ "$tmpFiLast" > "$tmpLiLast" ]] && {
		FirstIP="$tmpLastIP"
		LastIP="$tmpFirstIP"
	}
	[[ "$2" > "31" ]] && {
		FirstIP="$tmpNetwork"
		LastIP="$tmpNetwork"
	}
	echo -e "Network:   $tmpNetwork\nBroadcast: $tmpBroadcast\nFirstIP:   $FirstIP\nLastIP:    $LastIP\n"
}

# Unsuitable settings of subnet will cause not only "Death Red" of Debian installer which is called "unreachable gateway"
# but also contributes to some additional negative results as of if it's wider than the actual,
# this host will lose communications with some other servers which are serving in public internet because these will be treated as intranet hosts.
# To the opposite, if the subnet of one server is narrower than the actual, this host will lose communications with some local hosts because these will be treated as public servers.
# As an environment of a VPS, a narrower subnet causes less bad subsequentials than a wider prefer because VPS is usually be used by individual.
# If it's in a cluster such as home, office or company which is a place of that usually needs to transmit data with other hosts within LAN(local area network),
# the better opinion is to setting a wider value if you don't know them well.
# To figure out the most suitable subnet of a class segment of one IP or just a specific IP address,
# you can visit: https://bgp.tools/ which allows you to inquire announced allocations of IP addresses that were assigned by Internet Organizations.
#
# $1 is "$ipAddr", $2 is "$ipGate"
function ipv4SubnetCertificate() {
	# If the IP and gateway are not in the same IPv4 A class, the prefix of netmask should be "1", transfer to whole IPv4 address is 128.0.0.1
	# The range of 190.168.23.175/1 is 128.0.0.0 - 255.255.255.255, the gateway 169.254.0.1 can be included.
	[[ $(echo $1 | cut -d'.' -f 1) != $(echo $2 | cut -d'.' -f 1) ]] && tmpIpMask="1"
	# If the IP and gateway are in the same IPv4 A class, not in the same IPv4 B class, the prefix of netmask should less equal than "8", transfer to whole IPv4 address is 255.0.0.0
	# The range of 190.168.23.175/8 is 190.0.0.0 - 190.255.255.255, the gateway 169... can't be included.
	[[ $(echo $1 | cut -d'.' -f 1) == $(echo $2 | cut -d'.' -f 1) ]] && tmpIpMask="8"
	# If the IP and gateway are in the same IPv4 A B class, not in the same IPv4 C class, the prefix of netmask should less equal than "16", transfer to whole IPv4 address is 255.255.0.0
	# The range of 190.168.23.175/16 is 190.168.0.0 - 190.168.255.255, the gateway 169... can't be included.
	[[ $(echo $1 | cut -d'.' -f 1,2) == $(echo $2 | cut -d'.' -f 1,2) ]] && tmpIpMask="16"
	# If the IP and gateway are in the same IPv4 A B C class, not in the same IPv4 D class, the prefix of netmask should less equal than "24", transfer to whole IPv4 address is 255.255.255.0
	# The range of 190.168.23.175/24 is 190.168.23.0 - 190.168.23.255, the gateway 169... can't be included.
	[[ $(echo $1 | cut -d'.' -f 1,2,3) == $(echo $2 | cut -d'.' -f 1,2,3) ]] && tmpIpMask="24"
	# So in summary of the IPv4 sample in above, we should assign subnet mask "128.0.0.1"(prefix "1") for it.
}

# $1 is "$setDisk", $2 is "linux_relese"
function getDisk() {
	# $disks is definited as the default disk, if server has 2 and more disks, the first disk will be responsible of the grub booting.
	rootPart=$(lsblk -ip | grep -v "fd[0-9]*\|sr[0-9]*\|ram[0-9]*\|loop[0-9]*" | sed 's/[[:space:]]*$//g' | grep -w "part /\|part /boot" | head -n 1 | cut -d' ' -f1 | sed 's/..//')
	# majorMin=`lsblk -ip | grep -w "$rootPart" | head -n 1 | awk '{print $2}' | sed -r 's/:(.*)/:0/g'`
	diskSuffix=${rootPart: -4}
	# ssd like NVMe(/dev/nvme0n1), MMC sd card(/dev/mmcblk0) are parted with "p number" suffix like: "/dev/nvme0n1p1" "/dev/mmcblk0p2",
	# The partitions of vda and sda devices are ended with number "/dev/sda1" "/dev/vda2".
	[[ -n $(echo $diskSuffix | grep -o "[0-9]p[0-9]") ]] && disks=$(echo $rootPart | sed 's/p[0-9]*.$//') || disks=$(echo $rootPart | sed 's/[0-9]*.$//')
	# disks=`lsblk -ip | grep -w "$majorMin" | head -n 1 | awk '{print $1}'`
	[[ -z "$disks" ]] && disks=$(lsblk -ip | grep -v "fd[0-9]*\|sr[0-9]*\|ram[0-9]*\|loop[0-9]*" | sed 's/[[:space:]]*$//g' | grep -w "disk /\|disk /boot" | head -n 1 | cut -d' ' -f1)
	[[ -z "$disks" ]] && disks=$(lsblk -ip | grep -v "fd[0-9]*\|sr[0-9]*\|ram[0-9]*\|loop[0-9]*" | sed 's/[[:space:]]*$//g' | grep -w "disk" | grep -i "[0-9]g\|[0-9]t\|[0-9]p\|[0-9]e\|[0-9]z\|[0-9]y" | head -n 1 | cut -d' ' -f1)
	[ -n "$disks" ] || echo ""
	echo "$disks" | grep -q "/dev"
	[ $? -eq 0 ] && IncDisk="$disks" || IncDisk="/dev/$disks"
	AllDisks=""
	# Find all disks on this server.
	for Count in $(lsblk -ipd | grep -v "fd[0-9]*\|sr[0-9]*\|ram[0-9]*\|loop[0-9]*" | sed 's/[[:space:]]*$//g' | grep -w "disk" | grep -i "[0-9]g\|[0-9]t\|[0-9]p\|[0-9]e\|[0-9]z\|[0-9]y" | cut -d' ' -f1); do
		AllDisks+="$Count "
	done
	AllDisks=$(echo "$AllDisks" | sed 's/.$//')
	# All numbers of disks' statistic of this server.
	disksNum=$(echo $AllDisks | grep -o "/dev/*" | wc -l)

	# Some cloud providers using first SCSI/SATA device like "sda" to mount ISO image instead of using "sr0":
	#
	# root@node:~# lsblk -ipf
	# NAME        FSTYPE  FSVER            LABEL  UUID                                 FSAVAIL FSUSE% MOUNTPOINTS
	# /dev/sda    iso9660 Joliet Extension cidata 2023-07-13-09-35-07-00
	# /dev/sr0
	# /dev/vda
	# |-/dev/vda1
	# |-/dev/vda2 vfat    FAT32                   0BBB-E1CA                            119.9M  0%     /boot/efi
	# `-/dev/vda3 xfs                             0c93f6bc-ef9c-468d-be02-84b4a70d3678 44.4G   11%    /
	#
	# Because of "sda" can't be written, If system is selected to install on "sda", the installation will meet a fatal,
	# So we should exclude all these devices.
	for ((d = 1; d <= $disksNum; d++)); do
		currentDisk=$(echo "$AllDisks" | cut -d' ' -f$d)
		checkIfIsoPartition=$(lsblk -ipf | grep "$currentDisk" | head -n 1 | awk '{print $2}' | grep -i "iso")
		[[ -z "$checkIfIsoPartition" ]] && tmpAllDisks+="$currentDisk "
	done
	tmpAllDisks=$(echo "$tmpAllDisks" | sed 's/.$//')

	[[ "$AllDisks" != "$tmpAllDisks" ]] && {
		AllDisks="$tmpAllDisks"
		disksNum=$(echo $AllDisks | grep -o "/dev/*" | wc -l)
		[[ "$IncDisk" =~ "$AllDisks" ]] || IncDisk=$(echo "$AllDisks" | cut -d' ' -f1)
	}

	# Allow user to install system to one disk manually.
	[[ -n "$1" && "$1" != "all" && "$(echo $1 | cut -d '/' -f 3)" =~ ^[a-z0-9]+$ || "$(echo $1 | cut -d '/' -f 3)" =~ ^[a-z]+$ ]] && {
		[[ "$1" =~ "/dev/" ]] && IncDisk="$1" || IncDisk="/dev/$1"
	}

	# Preserve the existing Debian multi-disk LVM handling.
	[[ -z "$1" && "$disksNum" -ge "2" && -n $(lsblk -ip | awk '{print $6}' | grep -io "lvm") ]] && {
		[[ "$2" == 'debian' ]] && setDisk="all"
	}

	# Read target disk capacity for the existing memory/disk checks.
	diskCapacity=$(lsblk -ipb | grep -w "$IncDisk" | awk {'print $4'})
}

function diskType() {
	echo $(udevadm info --query all "$1" 2>/dev/null | grep 'ID_PART_TABLE_TYPE' | cut -d'=' -f2)
}

# Default to make a GPT partition to support 3TB hard drive or larger.
# To remove LVM VGM PVM force automatically:
# https://serverfault.com/questions/571363/unable-to-automatically-remove-lvm-data
# To part all disks for preseed:
# https://unix.stackexchange.com/questions/341253/using-d-i-partman-recipe-strings
#
# $1 is "$linux_relese", $2 is "$disksNum", $3 is "$setSwap", $4 is "$setDisk", $5 is "$partitionTable", $6 is "$setFileSystem", $7 is "$EfiSupport", $8 is "$diskCapacity", $9 is "$IncDisk", ${10} is "$AllDisks".
function setNormalRecipe() {
	[[ -n "$3" && $(echo "$3" | grep -o '[0-9]') ]] && swapSpace="$setSwap" || swapSpace='0'
	if [[ "$1" == 'debian' ]]; then
		[[ "$lowMemMode" == "1" ]] && {
			[[ -z "$swapSpace" || "$swapSpace" -lt "512" ]] && swapSpace="512"
		}
		if [[ -n "$swapSpace" && "$swapSpace" -gt "0" ]]; then
			swapSpace=$(awk 'BEGIN{print '${swapSpace}'*1.05078125 }' | cut -d '.' -f '1')
			swapRecipe=''${swapSpace}' 200 '${swapSpace}' linux-swap method{ swap } format{ } .'
		else
			swapRecipe=""
		fi
		if [[ "$6" == "xfs" ]]; then
			fileSystem="xfs"
		else
			fileSystem="ext4"
		fi
		defaultFileSystem='d-i partman/default_filesystem string '${fileSystem}''
		mainRecipe='1076 150 -1 '${fileSystem}' method{ format } format{ } use_filesystem{ } filesystem{ '${fileSystem}' } mountpoint{ / } .'
		if [[ "$2" -gt "1" && "$4" == "all" ]]; then
			PartmanEarlyCommand='debconf-set partman-auto/disk '${10}';'
			selectDisks='d-i partman-auto/disk string '${10}''
		else
			PartmanEarlyCommand='debconf-set partman-auto/disk "$(list-devices disk | grep '${9}' | head -n 1)";'
			selectDisks='d-i partman-auto/disk string '${9}''
		fi
		if [[ "$5" == "gpt" || "$7" == "enabled" || "$8" -ge "2199023255552" ]]; then
			gptPartitionPreseed=$(echo -e "d-i partman-basicfilesystems/choose_label string gpt
d-i partman-basicfilesystems/default_label string gpt
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
d-i partman/choose_label string gpt
d-i partman/default_label string gpt")
			gptForBios='1 100 1 free $iflabel{ gpt } $reusemethod{ } method{ biosgrub } .'
		else
			gptPartitionPreseed=""
			gptForBios=""
		fi
		if [[ "$7" == "enabled" ]]; then
			normalRecipes=$(echo -e "d-i partman-auto/choose_recipe select normal
d-i partman-auto/expert_recipe string normal ::                                   \
    538 100 1076 free \$iflabel{ gpt } \$reusemethod{ } method{ efi } format{ } . \
    $swapRecipe                                                                   \
    $mainRecipe
d-i partman-efi/non_efi_system boolean true")
		else
			normalRecipes=$(echo -e "d-i partman-auto/choose_recipe select normal
d-i partman-auto/expert_recipe string normal :: \
    $gptForBios                                 \
    $swapRecipe                                 \
    $mainRecipe
")
		fi
		FormatDisk=$(echo -e "$selectDisks
d-i partman-auto/method string regular
d-i partman-basicfilesystems/no_swap boolean false
$normalRecipes
$gptPartitionPreseed
")
	fi
}

# $1 is "$setRaid", $2 is "$disksNum", $3 is "$AllDisks", $4 is "$linux_relese".
function setRaidRecipe() {
	[[ -n "$1" ]] && {
		# Soft Raid 0, 1, 5, 6 and 10 methods are supported by Debian, only one disk can't be as a component for any Raid method.
		# Raid 0 needs at least two disks, all space of the disks will be exploited, and it's the most dangerous for the safety of the data.
		# Raid 1 needs at least two disks, the space can be exploited is always equal one disk, it's safest for the date but a bit wasteful.
		# Raid 5 needs at least three disks, it storages data on two disks and storages parity checking data on one disk, it's not save on any single disk over 4TB.
		# Raid 6 needs at least four disks, it's an enhanced version of Raid 5, it uses two parity stripes by practicing of dividing data across the set of drives,
		# it allows for two disk failures within the RAID set before any data is lost.
		# Raid 10 needs at least four disks, it's a combination of Raid 0 and Raid 1, the disk 0 and disk 1 as a set of Raid 0, the same as disk 2 and disk 3,
		# and then the sets of disk 0,1 and disk 2,3 are composed as one Raid 1.
		if [[ "$1" == "0" || "$1" == "1" || "$1" == "5" || "$1" == "6" || "$1" == "10" ]]; then
			[[ "$1" == "0" || "$1" == "1" ]] && [[ "$2" -lt "2" ]] && {
				echo -ne "\n[${red}Error${plain}] There are $2 drives on your machine, Raid $1 partition recipe only supports a basic set of dual drive or more!\n"
				exit 1
			}
			[[ "$1" == "5" ]] && [[ "$2" -lt "3" ]] && {
				echo -ne "\n[${red}Error${plain}] There are $2 drives on your machine, Raid $1 partition recipe only supports a basic set of triple drive or more!\n"
				exit 1
			}
			[[ "$1" == "6" || "$1" == "10" ]] && [[ "$2" -lt "4" ]] && {
				echo -ne "\n[${red}Error${plain}] There are $2 drives on your machine, Raid $1 partition recipe only supports a basic set of quad drive or more!\n"
				exit 1
			}
		else
			echo -ne "\n[${red}Error${plain}] Raid $1 partition recipe is not suitable, only Raid 0, 1, 5, 6 or 10 is supported!\n"
			exit 1
		fi
		if [[ "$4" == 'debian' ]]; then
			defaultFileSystem='d-i partman/default_filesystem string ext4'
			for ((r = 1; r <= "$2"; r++)); do
				tmpAllDisksPart=$(echo "$3" | cut -d ' ' -f"$r")
				# Some NVME controller hard drives like "/dev/nvme0n1" etc are end of a number in there names must add "p" with partition numbers for "d-i partman-auto-raid/recipe string",
				# SCSI controller or Virtual controller drives like "/dev/sda" or "/dev/vda" are not effected by this situation.
				# Drives and their partitions must be connected with "#" like "/dev/nvme0n1p2#/dev/nvme0n2p2".
				echo "${tmpAllDisksPart: -1}" | [[ -n "$(sed -n '/^[0-9][0-9]*$/p')" ]] && tmpAllDisksPart="$tmpAllDisksPart""p" || tmpAllDisksPart="$tmpAllDisksPart"
				AllDisksPart1+="$tmpAllDisksPart""1#"
				AllDisksPart2+="$tmpAllDisksPart""2#"
				AllDisksPart3+="$tmpAllDisksPart""3#"
			done
			AllDisksPart1=$(echo "$AllDisksPart1" | sed 's/.$//')
			AllDisksPart2=$(echo "$AllDisksPart2" | sed 's/.$//')
			AllDisksPart3=$(echo "$AllDisksPart3" | sed 's/.$//')
			# Remove existed raid md devices without confirming; select raid recipe and all disks; don't assign swap; when one device on raid 1 is offline, the system still can be booted.
			# Reference: https://wiki.ubuntu.com/BootDegradedRaid
			RaidRecipes=$(echo -e "d-i partman-md/confirm boolean true
d-i partman-md/confirm_nooverwrite boolean true
d-i partman-md/confirm_nochanges boolean false
d-i partman-basicfilesystems/no_swap boolean false
d-i partman-auto/method string raid
d-i partman-auto/disk string $3
d-i mdadm/boot_degraded boolean true")
			# In environment of UEFI firmware motherboard computers, it's not suggested to creat any Raid recipe for "/boot/efi" partition,
			# in any virtual machine which created by VMware Workstation Pro, version up to the current 17.0.2(2023/6), host OS is Windows 10 Enterprise x64,
			# we must assign an additional Raid 1 recipe for "/boot" partition to prevent the case of following to happen：
			# otherwise except of the first reboot of the Debian 12 installed soon, the next time hard reboot the system, it will failed into "GNU GRUB version 2.0x"
			# and we must type "exit" to fallback to "Boot Manager", select and enter the default opinion of "Boot normally" and then find that Debian can be booted by grub.
			# This is a particularly fatal for those servers which has no permission to access VNC in website back-end management and impossible to manipulate UEFI boot manager to boot the system normally.
			if [[ "$EfiSupport" == "enabled" ]]; then
				FormatDisk=$(echo -e "$RaidRecipes
d-i partman-auto-raid/recipe string     \
    1  $2 0 ext4 /boot $AllDisksPart2 . \
    $1 $2 0 ext4 /     $AllDisksPart3 .
d-i partman-auto/expert_recipe string multiraid ::                                                            \
    538  100 1076 free \$bootable{ } \$primary{ } method{ efi } \$iflabel{ gpt } \$reusemethod{ } format{ } . \
    1076 150 2152 raid               \$primary{ } method{ raid } .                                            \
    100  200 -1   raid               \$primary{ } method{ raid } .
d-i partman-efi/non_efi_system boolean true
d-i partman-partitioning/choose_label select gpt
d-i partman-partitioning/default_label string gpt")
			else
				# GPT table partition should not be included in BIOS Raid recipes so that it will cause Debian installer "Unable to install GRUB in /dev/sda" by installing grub.
				FormatDisk=$(echo -e "$RaidRecipes
d-i partman-auto-raid/recipe string     \
    1  $2 0 ext4 /boot $AllDisksPart1 . \
    $1 $2 0 ext4 /     $AllDisksPart2 .
d-i partman-auto/expert_recipe string multiraid ::                 \
    1076 100 2152 raid \$bootable{ } \$primary{ } method{ raid } . \
    100  200 -1   raid               \$primary{ } method{ raid } .
")
			fi
			# Reference: https://github.com/airium/Linux-Reinstall/blob/master/install-raid0.sh
			#            https://www.debian.org/releases/bookworm/example-preseed.txt
			#            https://www.cnblogs.com/zhangshan-log/articles/14542166.html
			#            https://gist.github.com/jnerius/6573343
			#            https://gist.github.com/bearice/331a954d86d890d9dbeacdd7de3aabe8
			#            https://lala.im/7911.html
			#            https://github.com/office-itou/Linux/blob/master/installer/source/preseed_debian.cfg
			#            https://qiita.com/YasuhiroABE/items/ff233459035d8187263d
		else
			echo -ne "\n[${red}Warning${plain}] Raid $1 recipe is not supported by target system!\n"
			exit 1
		fi
	}
}

# $1 is timezone checkfile direction, $2 $3 $4 $5 and $6/$7/$8 are different IP geography location data providers to avoid if any of them has a downtime.
function getUserTimeZone() {
	if [[ ! "$TimeZone" =~ ^[a-zA-Z] ]]; then
		loginUser=$(who am i | awk '{print $1}' | sed 's/(//g' | sed 's/)//g')
		[[ -z "$loginUser" ]] && loginUser="root"
		# "azureuser" can't be shown compeletely in output of "netstat" and it's the default username in official template of Azure.
		[[ "${#loginUser}" -ge "7" ]] && loginUser=$(echo ${loginUser:0:7})
		# Alpine Linux doesn't support "who am i".
		# In some situations, there are several users with different IPs to connect to server by ssh service,
		# So we need to filter a list of "Send-Q" and IPs from netstat and sort from largest to smallest by "Sent-Q" to ensure which IP is the current user,
		# because the "Sent-Q" can record the data packs which IP is active for current ssh user.
		# The same as for IPv6s.
		GuestIP=$(netstat -naputeoW | grep -i 'established' | grep -i 'sshd: '$loginUser'' | grep -iw '^tcp\|udp' | awk '{print $3,$5}' | sort -t ' ' -k 1 -rn | awk '{print $2}' | head -n 1 | cut -d':' -f'1')
		[[ -z "$GuestIP" ]] && GuestIP=$(netstat -naputeoW | grep -i 'established' | grep -i "sshd-session" | grep -i "on" | grep -iw '^tcp\|udp' | awk '{print $3,$5}' | sort -t ' ' -k 1 -rn | awk '{print $2}' | head -n 1 | cut -d':' -f'1')
		if [[ ! -z "$GuestIP" ]]; then
			checkIfIpv4AndIpv6IsLocalOrPublic "$GuestIP" ""
			# If some users are connecting to ssh service via private IPs, the actual location of this server may be the same as the public IP of this server like:
			# I created a virtual machine by VMware on my laptop and access it with as "192.168.0.217", to determine timezone of current user according to this IP is meaningless.
			[[ "$ipv4LocalOrPublicStatus" == '1' ]] && {
				GuestIP=$(timeout 0.3s dig -4 TXT +short o-o.myaddr.l.google.com @ns3.google.com | sed 's/\"//g')
				[[ "$GuestIP" == "" ]] && GuestIP=$(timeout 0.3s dig -4 TXT CH +short whoami.cloudflare @1.0.0.3 | sed 's/\"//g')
			}
		else
			GuestIP=$(netstat -naputeoW | grep -i 'established' | grep -i 'sshd: '$loginUser'' | grep -iw '^tcp6\|udp6' | awk '{print $3,$5}' | sort -t ' ' -k 1 -rn | awk '{print $2}' | head -n 1 | awk -F':' '{for (i=1;i<=NF-1;i++)printf("%s:", $i);print ""}' | sed 's/.$//')
			[[ -z "$GuestIP" ]] && GuestIP=$(netstat -naputeoW | grep -i 'established' | grep -i "sshd-session" | grep -i "on" | grep -iw '^tcp6\|udp6' | awk '{print $3,$5}' | sort -t ' ' -k 1 -rn | awk '{print $2}' | head -n 1 | awk -F':' '{for (i=1;i<=NF-1;i++)printf("%s:", $i);print ""}' | sed 's/.$//')
			checkIfIpv4AndIpv6IsLocalOrPublic "" "$GuestIP"
			[[ "$ipv6LocalOrPublicStatus" == '1' ]] && {
				GuestIP=$(timeout 0.3s dig -6 TXT +short o-o.myaddr.l.google.com @ns3.google.com | sed 's/\"//g')
				[[ "$GuestIP" == "" ]] && GuestIP=$(timeout 0.3s dig -6 TXT CH +short whoami.cloudflare @2606:4700:4700::1003 | sed 's/\"//g')
			}
		fi
		for Count in "$2$GuestIP" "$3$GuestIP" "$4$GuestIP" "$5$GuestIP/json/" "$6" "$7" "$8"; do
			[[ "$TimeZone" == "Asia/Shanghai" ]] && break
			if [[ "$Count" =~ ^[a-zA-Z0-9]+$ ]]; then
				tmpApi=$(echo -n "$Count" | base64 -d)
				Count="https://api.ipgeolocation.io/timezone?apiKey=$tmpApi&ip=$GuestIP"
			fi
			TimeZone=$(curl -s "$Count" -A firefox 2>/dev/null | jq '.timezone, .time_zone' 2>/dev/null | grep -v "null" | tr -d '"')
			checkTz=$(echo $TimeZone | cut -d'/' -f 1)
			[[ -n "$checkTz" && "$checkTz" =~ ^[a-zA-Z] ]] && break
		done
		[[ -z "$TimeZone" ]] && TimeZone="Asia/Tokyo"
	else
		echo $(timedatectl list-timezones) >>"$1"
		[[ $(grep -c "$TimeZone" "$1") == "0" || ! "/usr/share/zoneinfo/$1" ]] && TimeZone="Asia/Tokyo"
		rm -rf "$1"
	fi
}

function checkEfi() {
	EfiStatus=$(efibootmgr l)
	EfiVars=""
	for Count in "$1" "$2" "$3" "$4"; do
		EfiVars=$(ls -Sa $Count | wc -l)
		[[ "$EfiVars" -ge "1" ]] && break
	done
	if [[ "$EfiStatus" == "" ]] || [[ "$EfiVars" == "0" ]]; then
		EfiSupport="disabled"
	elif [[ -n $(echo "$EfiStatus" | grep -i "bootcurrent" | awk '{print $2}' | sed -n '/^[[:xdigit:]]*$/p' | head -n 1) || -n $(echo "$EfiStatus" | grep -i "bootorder" | awk '{print $2}' | awk -F ',' '{print $NF}' | sed -n '/^[[:xdigit:]]*$/p' | head -n 1) ]] && [[ "$EfiVars" != "0" ]]; then
		EfiSupport="enabled"
	else
		echo -ne "\n[${red}Error${plain}] UEFI boot firmware of your system could not be confirmed!\n"
		exit 1
	fi
}

# $1 is "/boot/grub/", $2 is "/boot/grub2/", $3 is "/etc/", $4 is "grub.cfg", $5 is "grub.conf", $6 is "/boot/efi/EFI/"
# In some templates of Redhat series 7-8, UEFI firmware from Hetzner and etc. , there are two directions of grub configure files like:
#
# /boot/efi/EFI/rocky/grub.cfg
# /boot/grub2/grub.cfg
#
# The contents of the above two files are almost equal, but the new boot menuentry which we need to write in file "/etc/grub.d/40_custom"
# can only valid after reboot by using "grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg", "grub2-mkconfig -o /boot/grub2/grub.cfg" doesn't cause any effect,
# So in this situation, to find out the valid grub config file like "/boot/efi/EFI/rocky/grub.cfg" at first is necessary.
# For Redhat series 9 and later, including Fedora 36+, the valid direction of grub config files are unified back to "/boot/grub2/grub.cfg" now,
# so we won't have to consider the troubles which were caused by Redhat 7-8 series's abnormal settings.
function checkGrub() {
	GRUBDIR=""
	GRUBFILE=""
	for Count in "$4" "$5"; do
		GRUBFILE=$(find "$6" -name "$Count")
		if [[ -n "$GRUBFILE" ]]; then
			GRUBDIR=$(echo "$GRUBFILE" | sed "s/$Count//g")
			GRUBFILE="$Count"
			break
		fi
	done
	GRUBDIR=$(echo $GRUBDIR | awk '{print $1}')
	if [[ -z "$GRUBFILE" ]] || [[ $(grep -c "insmod*" $GRUBDIR$GRUBFILE) == "0" ]] || [[ -n "$GRUBFILE" && $(grep -c "insmod*" $GRUBDIR$GRUBFILE) != "0" && "$EfiSupport" == "disabled" ]]; then
		for Count in "$1" "$2" "$3"; do
			# Don't support grub1 of CentOS/Redhat Enterprise Linux/Oracle Linux 6.x
			if [[ -f "$Count""$4" ]] && [[ $(grep -c "insmod*" $Count$4) -ge "1" ]]; then
				GRUBDIR="$Count"
				GRUBFILE="$4"
			elif [[ -f "$Count""$5" ]] && [[ $(grep -c "insmod*" $Count$5) -ge "1" ]]; then
				GRUBDIR="$Count"
				GRUBFILE="$5"
			fi
		done
	fi
	GRUBDIR=$(echo ${GRUBDIR%?})
	if [[ $(awk '/menuentry*/{print NF}' $GRUBDIR/$GRUBFILE | head -n 1) -ge "1" ]] || [[ $(awk '/feature*/{print $a}' $GRUBDIR/$GRUBFILE | head -n 1) != "" ]] || [[ $(awk '/insmod*/{print $a}' $GRUBDIR/$GRUBFILE | head -n 1) != "" ]]; then
		if [[ -n $(grep -w "grub2-.*" $GRUBDIR/$GRUBFILE) ]] || [[ $(type grub2-mkconfig) != "" ]]; then
			GRUBTYPE="isGrub2"
		elif [[ -n $(grep -w "grub-.*" $GRUBDIR/$GRUBFILE) ]] || [[ $(type grub-mkconfig) != "" ]]; then
			GRUBTYPE="isGrub1"
		elif [[ "$CurrentOS" == "CentOS" || "$CurrentOS" == "OracleLinux" ]] && [[ "$CurrentOSVer" -le "6" ]]; then
			GRUBTYPE="isGrub1"
		fi
	fi
}

# We found out an expedite and critical bug of Alpine Linux 3.19+ and edge(based on testing version of 3.20 at Mar. 2024) is that
# when restarting Ubuntu 22.04 or Redhat series to boot on grub in order to start Alpine's netboot kernel will be failed because of Alpine was updated
# the new grub version of 2.12 and added a new parameter of 'fwsetup --is-supported' but it could not be recognized by grub 2.06 only on arm64 hardware.
# Debian 12 was not effected.
#
# A valid solution is to download an always up-to-date 'grub.efi' file which offered by OpenSUSE and replace the original one before restart.
# Grub 2.12 is compatible with 2.06 .
#
# In official image of Ubuntu 22.04 provided by Hetzner arm64, directory of "/boot/efi/EFI/ubuntu/" was not existed, we should use "grub-install" to rebuild it.
#
# http://ftp.kddilabs.jp/pub/debian/dists/bookworm/main/installer-arm64/current/images/netboot/debian-installer/arm64/grubaa64.efi
#
# Reference: https://wiki.alpinelinux.org/wiki/Release_Notes_for_Alpine_3.20.0
#            https://gitlab.alpinelinux.org/alpine/aports/-/issues/15263
#            https://fosstodon.org/@alpinelinux/111703786706332100
function checkAndReplaceEfiGrub() {
	if [[ "$VER" == "aarch64" || "$VER" == "arm64" ]] && [[ "$EfiSupport" == "enabled" ]] && [[ "$linux_relese" == 'alpinelinux' ]]; then
		[[ "$AlpineVer1" == "3" && "$AlpineVer2" -ge "19" ]] || [[ "$DIST" == "edge" ]] && {
			efiGrubFull=$(find "/boot/efi/EFI/" -name "*.efi" | grep -i "grub" | head -n 1)
			[[ -z "$efiGrubFull" ]] && {
				grub-install
				efiGrubFull=$(find "/boot/efi/EFI/" -name "*.efi" | grep -i "grub" | head -n 1)
			}
			efiGrubDir=$(echo ${efiGrubFull%/*}"/")
			efiGrubFile=$(echo $efiGrubFull | awk -F "/" '{print $NF}')
			mv "$efiGrubFull" "$efiGrubFull"".bak"
			if [[ "$IsCN" == "cn" ]]; then
				aarch64EfiGrubMirror="https://mirrors.tuna.tsinghua.edu.cn/opensuse/ports/aarch64/tumbleweed/repo/oss/EFI/BOOT/"
			else
				aarch64EfiGrubMirror="http://download.opensuse.org/ports/aarch64/tumbleweed/repo/oss/EFI/BOOT/"
			fi
			aarch64EfiGrubUrl="$aarch64EfiGrubMirror""grub.efi"
			wget --no-check-certificate -qO "$efiGrubDir$efiGrubFile" "$aarch64EfiGrubUrl"
		}
	fi
}

# $1 is "$VER".
# For AWS arm64, "console=tty1 console=ttyS0,115200n8" must be added to menuentry of the grub in order to successfully rebooting to the netboot installer kernel and viewing graphis on serial console.
# Note: When booting into a new grub menuentry that we generated, this is not suitable for amd64 architecture otherwise it will cause boot with "RETBleed attacks, data leaks possible!" and failed.
#       Arm64 instances of Oracle Cloud need "console=tty1".
#       Guest video display will be disabled on VNC of Oracle Cloud if arm64 cloud kernel installed.
#       Native Debian installation and generic cloud image of Debian will boot failed on arm64 instance of AWS EC2 because of missing drivers of ssd.
#
# Serial console parameters of default grub in official cloud images of several linux distributions:
# Debian 12 amd64:           console=tty0 console=ttyS0,115200 earlyprintk=ttyS0,115200 consoleblank=0
# AlmaLinux 9.2 arm64:       console=tty0 console=ttyS0,115200n8
# RockyLinux 9.2 arm64:      console=ttyS0,115200n8
# Ubuntu 22.04+ amd/arm64:   console=tty1 console=ttyS0
# For Ampere A1 arm64 processor, "console=ttyS0" is necessary.
# Serial console parameters of "yitian 710" arm64 processor in servers of AlibabaCloud ECS:
# Ubuntu 18.04+ arm64:       console=tty0 console=ttyAMA0,115200n8
# Cloud images of Ubuntu 20.04-22.04 will boot fail on "yitian 710".
function checkConsole() {
	for ttyItems in "console=tty" "console=ttyAMA" "console=ttyS"; do
		[[ $(grep "$ttyItems" $GRUBDIR/$GRUBFILE) ]] && {
			ttyConsole+="${ttyItems}0 "
		}
	done
	if [[ "$1" == "aarch64" || "$1" == "arm64" ]]; then
		[[ ! "$ttyConsole" =~ "ttyS" ]] && {
			if [[ $(echo "$ttyConsole" | grep "tty[0-9]") ]]; then
				ttyConsole="${ttyConsole} console=ttyS0 "
			else
				ttyConsole="${ttyConsole} console=tty1 console=ttyS0 "
			fi
		}
	fi
	ttyConsole=$(echo "$ttyConsole" | sed 's/console=tty[0-9]/console=tty1/g' | sed 's/console=ttyAMA[0-9]/console=ttyAMA0,115200n8/g' | sed 's/console=ttyS[0-9]/console=ttyS0,115200n8/g' | sed 's/.$//')
	[[ "$ttyConsole" =~ "ttyS" ]] && serialConsolePropertiesForGrub="$ttyConsole earlyprintk=ttyS0,115200n8 consoleblank=0"
	[[ "$1" == "aarch64" || "$1" == "arm64" ]] || ttyConsole=""
}

# $1 is $linux_relese, $2 is $RedHatSeries, $3 is $targetRelese
function checkMem() {
	# "dmesg" is most accurate to detect the actually valuable memory.
	# Reference: https://blog.csdn.net/imliuqun123/article/details/126120360
	# The constant ratio of threshold value(triggering the following conditions) and nominal value(the space of the memory which announced by cloud provider) is coefficient of "0.99".
	# If it can't be divisible by number "4", we'll take a value that is the multiple of 4 and litter less than the former one.
	TotalMem=$(($(dmesg | grep -i 'memory' | grep -i 'available' | awk -F ':' '{print $2}' | awk '{print $1}' | cut -d '/' -f 2 | tr -d "a-zA-Z") / 1024))
	# Alternate methods but not clearly accurate for example "kdump" service occupied a part of memory.
	[[ -z "$TotalMem" ]] && TotalMem=$(lsmem -b | grep -i "online memory" | awk '{print $NF/1024/1024}')
	[[ -z "$TotalMem" ]] && TotalMem=$(($(cat /proc/meminfo | grep "^MemTotal:" | sed 's/kb//i' | grep -o "[0-9]*" | awk -F' ' '{print $NF}') / 1024))
	[[ -z "$TotalMem" ]] && TotalMem=$(free -m | grep -wi "mem*" | awk '{printf $2}')

	# "lowmem=+0, 1 or 2" is only for Debian.
	# "lowmem=+2" is dangerous because it will cause net-installer-kernel booting failed in any memory capacity.
	# "lowmem=+1" will disable many features including load other drivers to save memory to make installation successful.
	# "lowmem=+0" is to avoid Debian installer to enable low memory mode by force so that it can urge Debian installer to read "d-i non-free-firmware" from "preseed.cfg" to load many drivers like NVME disks to improve hardware compatibility, tested succeed on 512MB memory servers with Debian, Kali.
	# The actual available capacity of memory on AWS ec2 arm64 t4g model is 472mb in spite of the hardware which was announced by Amazon is "0.5G"
	# so that in this situation, distributing 512mb swap for target machine is necessary to avoid of installing linux kernel will meet a fatal for Debian series.
	# I decided to set a baseline of 672mb(any ram of current machine is lower than this) to deal with it at current(2023.11).
	[[ "$1" == 'debian' ]] || [[ "$1" == 'ubuntu' ]] && {
		[[ "$TotalMem" -le "672" ]] && lowMemMode="1"
		if [[ "$TotalMem" -le "448" ]]; then
			lowmemLevel="lowmem=+1"
		elif [[ "$TotalMem" -le "1500" ]]; then
			lowmemLevel="lowmem=+0"
		else
			lowmemLevel=""
		fi
		[[ "$setMemCheck" == '1' ]] && {
			[[ "$TotalMem" -le "336" ]] && {
				echo -ne "\n[${red}Error${plain}] Minimum system memory requirement is 384 MB!\n"
				exit 1
			}
		}
	}
	[[ "$setMemCheck" == '1' ]] && {
		[[ "$1" == 'alpinelinux' || "$3" == 'Ubuntu' ]] && {
			if [[ "$3" == 'Ubuntu' ]]; then
				[[ "$TotalMem" -le "448" ]] && {
					echo -ne "\n[${red}Error${plain}] Minimum system memory requirement is 512 MB!\n"
					exit 1
				}
			elif [[ "$1" == 'alpinelinux' ]]; then
				[[ "$TotalMem" -le "228" ]] && {
					echo -ne "\n[${red}Error${plain}] Minimum system memory requirement is 256 MB!\n"
					exit 1
				}
				[[ "$TotalMem" -le "736" ]] && {
					lowMemMode="1"
					setMotd="0"
				}
			fi
		}
		if [[ "$TotalMem" -le "2028" ]]; then
			setFail2banStatus="0"
			[[ "$setFail2ban" == "1" ]] && setFail2banStatus="1"
		else
			[[ "$setFail2ban" == "0" ]] && setFail2banStatus="0" || setFail2banStatus="1"
		fi
		[[ "$linux_relese" == 'debian' && "$DebianDistNum" -le "8" ]] && setFail2banStatus="0"
	}
}

function checkVirt() {
	virtWhat=""
	virtType=""
	[[ -n $(virt-what) ]] && {
		for virtItem in $(virt-what); do
			virtWhat+="$virtItem "
		done
		# Does not support OpenVZ or LXC.
		[[ $(echo $virtWhat | grep -i "openvz") || $(echo $virtWhat | grep -i "lxc") ]] && {
			echo -ne "\n[${red}Error${plain}] Virtualization of ${yellow}$virtWhat${plain}could not be supported!\n"
			echo -ne "\nTry to refer to the ${blue}following project${plain}: \n\n${underLine}https://github.com/LloydAsp/OsMutation${plain} \n\nfor learning more and then execute it as the re-installation.\n"
			exit 1
		}
	}
	for virtItem in $(dmidecode -s system-manufacturer | sed 's/[[:space:]]//g' | sed 's/[A-Z]/\l&/g') $(systemd-detect-virt | sed 's/[A-Z]/\l&/g') $(lscpu | grep -i "hypervisor vendor" | cut -d ':' -f 2 | sed 's/^[ \t]*//g' | sed 's/[A-Z]/\l&/g'); do
		virtType+="$virtItem "
	done
	showAllVirts=$(echo "$virtType$virtWhat" | sed 's/[[:space:]]/\n/g' | sort -u | tr -s '\n' ' ' | sed 's/^[ \t]*//g' | sed 's/[ \t]*$//g')
}

function checkSys() {
    # Preserve source-host compatibility; agent removal is not downloaded/executed.
    aliyundunProcess=$(ps -ef | grep -Ei 'aegis|aliyundun|assist-daemon' | grep -v grep || true)
    if [[ -n "$aliyundunProcess" ]]; then
        printf '[ERROR] Cloud guard agent detected. Remove/disable it using the provider procedure, then rerun.\n' >&2
        exit 1
    fi

	rm -rf /swapspace
	# Allocate 512 MB temporary swap to provent yum dead.
	if [[ ! -e "/swapspace" ]]; then
		fallocate -l 512M /swapspace
		chmod 600 /swapspace
		mkswap /swapspace
		swapon /swapspace
		# Prefer to divert temporary data from RAM to virtual memory when there are 70% left and below of RAM to pull out a biggest effort to make sure the allowance of RAM is sufficient for installing dependence.
		# In RAM that less and equal than 512 MB environment, the occupation of "yum / dnf" process could reach to nearly 49% at highest, the original value of swappiness in official templates of Simple Application Servers from Alibaba Cloud is "0".
		# The default number of this value is "60" for a standard Linux distribution like Debian/Redhat series, it's "90" on Alpine.
		# Mem:  446028(total)  216752(used)
		[[ $(cat /proc/sys/vm/swappiness | sed 's/[^0-9]//g') -lt "70" ]] && sysctl vm.swappiness=70
	fi

	# Fix debian security sources 404 not found (only of default sources)
	sed -i 's/^\(deb.*security.debian.org\/\)\(.*\)\/updates/\1debian-security\2-security/g' /etc/apt/sources.list

	CurrentOSVer=$(cat /etc/os-release | grep -w "VERSION_ID=*" | awk -F '=' '{print $2}' | sed 's/\"//g' | cut -d'.' -f 1)
	DebianRelease=""
	IsUbuntu=$(uname -a | grep -i "ubuntu")
	IsDebian=$(uname -a | grep -i "debian")
	IsKali=$(uname -a | grep -i "kali")
	apt update -y
	# Try to fix error of connecting to current mirror for Debian.
	if [[ "$CurrentOSVer" -ne 0 ]]; then
		apt update -y >/root/apt_execute.log
		if [[ $(grep -i "debian" /root/apt_execute.log) ]]; then
			# Delete the apt mirror with ejected optical drive.
			if [[ $(grep -i "err:[0-9]" /root/apt_execute.log) ]] && [[ $(grep -i "cdrom" /root/apt_execute.log) ]]; then
				sed -i "/^deb cdrom/d" /etc/apt/sources.list
				# Refresh cache of logs of apt update.
				rm -rf /root/apt_execute.log
				apt update -y >/root/apt_execute.log
			fi
			if [[ $(grep -i "err:[0-9]" /root/apt_execute.log) || $(grep -i "404  not found" /root/apt_execute.log) ]]; then
				currentDebianMirror=$(sed -n '/^deb /'p /etc/apt/sources.list | head -n 1 | awk '{print $2}' | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				if [[ "$CurrentOSVer" -gt "9" ]]; then
					# Replace invalid mirror of Debian to 'deb.debian.org' if current version has not been 'EOL'(End Of Life).
					sed -ri "s/$currentDebianMirror/deb.debian.org/g" /etc/apt/sources.list
				else
					# Replace invalid mirror of Debian to 'archive.debian.org' because it had been marked with 'EOL'.
					sed -ri "s/$currentDebianMirror/archive.debian.org/g" /etc/apt/sources.list
				fi
				# Disable get security update.
				sed -ri 's/^deb-src/# deb-src/g' /etc/apt/sources.list
				apt update -y
			fi
		fi
		# Fix security signature check failure of Kali.
		if [[ "$IsKali" ]] && [[ $(grep -i "public key is not available" /root/apt_execute.log) || $(grep -i "an error occurred during the signature verification" /root/apt_execute.log) || $(grep -i "the following signatures couldn't be verified" /root/apt_execute.log) ]]; then
			wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
			apt update -y
		fi
		rm -rf /root/apt_execute.log
	fi
	apt install lsb-release -y

	# Delete mirrors from elrepo.org because it will causes dnf/yum checking updates continuously(maybe some of the server mirror lists are in the downtime?)
	[[ $(grep -wri "elrepo.org" /etc/yum.repos.d/) != "" ]] && {
		elrepoFile=$(grep -wri "elrepo.org" /etc/yum.repos.d/ | head -n 1 | cut -d':' -f 1)
		mv "$elrepoFile" "$elrepoFile.bak"
	}
	yum install redhat-lsb -y
	OsLsb=$(lsb_release -d | awk '{print$2}')

	RedHatRelease=""
	for Count in $(cat /etc/redhat-release | awk '{print$1}') $(cat /etc/system-release | awk '{print$1}') $(cat /etc/os-release | grep -w "ID=*" | awk -F '=' '{print $2}' | sed 's/\"//g') "$OsLsb"; do
		[[ -n "$Count" ]] && RedHatRelease=$(echo -e "$Count")"$RedHatRelease"
	done

	for Count in $(cat /etc/os-release | grep -w "ID=*" | awk -F '=' '{print $2}') $(cat /etc/issue | awk '{print $1}') "$OsLsb"; do
		[[ -n "$Count" ]] && DebianRelease=$(echo -e "$Count")"$DebianRelease"
	done

	AlpineRelease=""
	apk update
	for Count in $(cat /etc/os-release | grep -w "ID=*" | awk -F '=' '{print $2}') $(cat /etc/issue | awk '{print $3}' | head -n 1) $(uname -v | awk '{print $1}' | sed 's/[^a-zA-Z]//g'); do
		[[ -n "$Count" ]] && AlpineRelease=$(echo -e "$Count")"$AlpineRelease"
	done

	if [[ $(echo "$RedHatRelease" | grep -i 'centos') != "" ]]; then
		CurrentOS="CentOS"
	elif [[ $(echo "$RedHatRelease" | grep -i 'cloudlinux') != "" ]]; then
		CurrentOS="CloudLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'alma') != "" ]]; then
		CurrentOS="AlmaLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'rocky') != "" ]]; then
		CurrentOS="RockyLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'fedora') != "" ]]; then
		CurrentOS="Fedora"
	elif [[ $(echo "$RedHatRelease" | grep -i 'virtuozzo') != "" ]]; then
		CurrentOS="Vzlinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'ol\|oracle') != "" ]]; then
		CurrentOS="OracleLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'opencloud') != "" ]]; then
		CurrentOS="OpenCloudOS"
	elif [[ $(echo "$RedHatRelease" | grep -i 'alibaba\|alinux\|aliyun') != "" ]]; then
		CurrentOS="AlibabaCloudLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'amazon\|amzn') != "" ]]; then
		CurrentOS="AmazonLinux"
		amazon-linux-extras install epel -y
	elif [[ $(echo "$RedHatRelease" | grep -i 'red\|rhel') != "" ]]; then
		CurrentOS="RedHatEnterpriseLinux"
	elif [[ $(echo "$RedHatRelease" | grep -i 'anolis') != "" ]]; then
		CurrentOS="OpenAnolis"
	elif [[ $(echo "$RedHatRelease" | grep -i 'scientific') != "" ]]; then
		CurrentOS="ScientificLinux"
	elif [[ $(echo "$AlpineRelease" | grep -i 'alpine') != "" ]]; then
		CurrentOS="AlpineLinux"
	elif [[ "$IsUbuntu" ]] || [[ $(echo "$DebianRelease" | grep -i 'ubuntu') != "" ]]; then
		CurrentOS="Ubuntu"
		CurrentOSVer=$(lsb_release -r | awk '{print$2}' | cut -d'.' -f1)
	elif [[ "$IsDebian" ]] || [[ $(echo "$DebianRelease" | grep -i 'debian') != "" ]]; then
		CurrentOS="Debian"
		CurrentOSVer=$(lsb_release -r | awk '{print$2}' | cut -d'.' -f1)
	elif [[ "$IsKali" ]] || [[ $(echo "$DebianRelease" | grep -i 'kali') != "" ]]; then
		CurrentOS="Kali"
		CurrentOSVer=$(lsb_release -r | awk '{print$2}' | cut -d'.' -f1)
	else
		echo -ne "\n[${red}Error${plain}] Does't support your system!\n"
		exit 1
	fi
	# Don't support Redhat like linux OS under 6 version.
	if [[ "$CurrentOS" == "CentOS" || "$CurrentOS" == "OracleLinux" ]] && [[ "$CurrentOSVer" -le "6" ]]; then
		echo -e "Does't support your system!\n"
		exit 1
	fi

	# Remove "inetutils-ping" because it does not support the statement of "ping -4" or "ping -6".
	# "kexec-tools" is also need to be removed because in environment of official template of Debian 12 on Tencent Cloud, whether it is executing on instance of "Lighthouse" or "CVM"(Cloud Virtual Machine).
	# This component may cause the menuentry of grub which we had generated and wrote can't be booted successfully when rebooting the system.
	# "kdump-tools" is a dependence of "kexec-tools".
	apt purge inetutils-ping kdump-tools kexec-tools -y
	# Debian like linux OS necessary components.
	apt install cpio curl dmidecode dnsutils efibootmgr fdisk file gzip iputils-ping jq net-tools openssl sudo tuned util-linux virt-what wget xz-utils -y

	# Redhat like Linux OS prefer to use dnf instead of yum because former has a higher execute efficiency.
	yum install dnf -y
	if [[ $? -eq 0 ]]; then
		# To avoid "Failed loading plugin "osmsplugin": No module named 'librepo'"
		# Reference: https://anatolinicolae.com/failed-loading-plugin-osmsplugin-no-module-named-librepo/
		[[ "$CurrentOS" == "CentOS" && "$CurrentOSVer" == "8" ]] && dnf install python3-librepo -y
		# Redhat like linux OS necessary components.
		dnf install epel-release -y
		dnf install bind-utils cpio curl dmidecode dnsutils efibootmgr file gzip jq net-tools openssl redhat-lsb syslinux tuned util-linux virt-what wget xz --skip-broken -y
	else
		yum install dnf -y >/root/yum_execute.log 2>&1
		# In some versions of CentOS 8 which are not subsumed into CentOS-stream are end of supporting by CentOS official, so the source is failure.
		# We need to change the source from http://mirror.centos.org to http://vault.centos.org to make repository is still available.
		# Reference: https://techglimpse.com/solve-failed-synchronize-cache-repo-appstream/
		#            https://qiita.com/yamada-hakase/items/cb1b6124e11ca65e2a2b
		if [[ $(grep -i "failed to\|no urls in mirrorlist" /root/yum_execute.log) ]]; then
			if [[ "$CurrentOS" == "CentOS" ]]; then
				cd /etc/yum.repos.d/
				sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
				baseRepo=$(ls /etc/yum.repos.d/ | grep -i "base\|cr" | head -n 1)
				currentRedhatMirror=$(sed -n '/^#baseurl=\|^baseurl=/'p /etc/yum.repos.d/$baseRepo | head -n 1 | awk -F '=' '{print $2}' | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				sed -ri 's/#baseurl/baseurl/g' /etc/yum.repos.d/CentOS-*
				sed -ri 's/'$currentRedhatMirror'/vault.centos.org/g' /etc/yum.repos.d/CentOS-*
				[[ "$CurrentOSVer" == "8" ]] && dnf install python3-librepo -y
			fi
			yum install dnf -y
			# Run dnf update and install components.
			# In official template of AlmaLinux 9 of Linode, "tuned" must be installed otherwise "grub2-mkconfig" can't work formally.
			# Reference: https://phanes.silogroup.org/fips-disa-stig-hardening-on-centos9/
			dnf install epel-release -y
			dnf install bind-utils cpio curl dmidecode dnsutils efibootmgr file gzip jq net-tools openssl redhat-lsb sudo syslinux tuned util-linux virt-what wget xz --skip-broken -y
			# Oracle Linux 7 doesn't support DNF.
		elif [[ $(grep -i "no package" /root/yum_execute.log) ]]; then
			yum install epel-release -y
			yum install bind-utils cpio curl dmidecode dnsutils efibootmgr file gzip jq net-tools openssl redhat-lsb sudo syslinux tuned util-linux virt-what wget xz --skip-broken -y
		fi
		rm -rf /root/yum_execute.log
	fi

	# Alpine Linux necessary components and configurations.
	[[ "$CurrentOS" == "AlpineLinux" ]] && {
		# Get current version number of Alpine Linux
		CurrentAlpineVer=$(cut -d. -f1,2 </etc/alpine-release)
		# Try to remove comments of any valid mirror.
		sed -i 's/#//' /etc/apk/repositories
		# Add community mirror.
		[[ ! $(grep -i "community" /etc/apk/repositories) ]] && sed -i '$a\http://dl-cdn.alpinelinux.org/alpine/v'${CurrentAlpineVer}'/community' /etc/apk/repositories
		# Add testing mirror.
		# [[ ! `grep -i "testing" /etc/apk/repositories` ]] && sed -i '$a\http://ftp.udx.icscoe.jp/Linux/alpine/edge/testing' /etc/apk/repositories
		# Alpine Linux use "apk" as package management.
		apk update
		apk add bash bind-tools coreutils cpio curl dmidecode efibootmgr file gawk grep gzip jq lsblk net-tools openssl sed shadow sudo tzdata util-linux virt-what wget xz
		# Use bash to replace ash.
		sed -i 's/root:\/bin\/ash/root:\/bin\/bash/g' /etc/passwd
	}
}

function checkVER() {
	# Get architecture of current os automatically
	ArchName=$(uname -m)
	[[ -z "$ArchName" ]] && ArchName=$(echo $(hostnamectl status | grep "Architecture" | cut -d':' -f 2))
	case $ArchName in arm64) VER="arm64" ;; aarch64) VER="aarch64" ;; x86 | i386 | i686) VER="i386" ;; x86_64) VER="x86_64" ;; x86-64) VER="x86-64" ;; amd64) VER="amd64" ;; *) VER="" ;; esac
	# Exchange architecture name
	if [[ "$linux_relese" == 'debian' ]]; then
		# In debian 12, the result of "uname -m" is "x86_64";
		# the result of "echo `hostnamectl status | grep "Architecture" | cut -d':' -f 2`" is "x86-64"
		if [[ "$VER" == "x86_64" ]] || [[ "$VER" == "x86-64" ]]; then
			VER="amd64"
		elif [[ "$VER" == "aarch64" ]]; then
			VER="arm64"
		fi
	elif [[ "$linux_relese" == 'alpinelinux' ]]; then
		if [[ "$VER" == "amd64" ]] || [[ "$VER" == "x86-64" ]]; then
			VER="x86_64"
		elif [[ "$VER" == "arm64" ]]; then
			VER="aarch64"
		fi
	fi

	# Check and exchange input architecture name
	tmpVER="$(echo "$tmpVER" | sed -r 's/(.*)/\L\1/')"
	if [[ -n "$tmpVER" ]]; then
		case "$tmpVER" in
		i386 | i686 | x86 | 32)
			VER="i386"
			;;
		amd64 | x86_64 | x64 | 64)
			[[ "$linux_relese" == 'alpinelinux' ]] && VER='x86_64' || VER='amd64'
			;;
		aarch64 | arm64 | arm)
			[[ "$linux_relese" == 'alpinelinux' ]] && VER='aarch64' || VER='arm64'
			;;
		*)
			VER=''
			;;
		esac
	fi

	[[ ! -n "$VER" ]] && {
		echo -ne "\n[${red}Error${plain}] Unknown architecture.\n"
		bash $0 error
		exit 1
	}
}

function checkDIST() {
	if [[ "$Relese" == 'Debian' ]]; then
		SpikCheckDIST='0'
		DIST="$(echo "$tmpDIST" | sed -r 's/(.*)/\L\1/')"
		DebianDistNum="${DIST}"
		echo "$DIST" | grep -q '[0-9]'
		[[ $? -eq '0' ]] && {
			isDigital="$(echo "$DIST" | grep -o '[\.0-9]\{1,\}' | sed -n '1h;1!H;$g;s/\n//g;$p' | cut -d'.' -f1)"
			[[ -n $isDigital ]] && {
				[[ "$isDigital" == '12' ]] && DIST='bookworm'
				[[ "$isDigital" == '13' ]] && DIST='trixie'
				# Debian releases TBA reference: https://wiki.debian.org/DebianReleases
				#                                https://en.wikipedia.org/wiki/Debian_version_history#Release_table
			}
		}
		LinuxMirror=$(selectMirror "$Relese" "$DIST" "$VER" "$tmpMirror")
	fi
	if [[ "$Relese" == 'AlpineLinux' ]]; then
		SpikCheckDIST='0'
		DIST="$(echo "$tmpDIST" | sed -r 's/(.*)/\L\1/')"
		# Recommend "edge" version of Alpine Linux to make sure to keep always updating.
		AlpineVer1=$(echo "$DIST" | sed 's/[a-z][A-Z]*//g' | cut -d"." -f 1)
		AlpineVer2=$(echo "$DIST" | sed 's/[a-z][A-Z]*//g' | cut -d"." -f 2)
		if [[ "$AlpineVer1" -lt "3" || "$AlpineVer2" -le "15" ]] && [[ "$DIST" != "edge" ]]; then
			echo -ne "\n[${red}Warning${plain}] $Relese $DIST is not supported!\n"
			exit 1
		fi
		# Alpine Linux releases reference: https://alpinelinux.org/releases/
		[[ "$DIST" != "edge" && ! "$DIST" =~ "v" ]] && DIST="v""$DIST"
		if [[ "$setCloudKernel" == "" ]]; then
			[[ -n "$virtWhat" ]] && virtualizationStatus='1' || virtualizationStatus='0'
		elif [[ "$setCloudKernel" == "1" ]]; then
			virtualizationStatus='1'
		fi
		# Virtual linux kernel of "vmlinuz-virt" of Alpine is unable to probe modules of IPv6 at the beginning so that "modloop" can't be downloaded and loaded!
		if [[ "$virtualizationStatus" == "1" && "$IPStackType" != "IPv6Stack" ]]; then
			InitrdName="initramfs-virt"
			VmLinuzName="vmlinuz-virt"
			ModLoopName="modloop-virt"
		else
			InitrdName="initramfs-lts"
			VmLinuzName="vmlinuz-lts"
			ModLoopName="modloop-lts"
		fi
		LinuxMirror=$(selectMirror "$Relese" "$DIST" "$VER" "$tmpMirror")
	fi
}

# $1 is "$ipAddr", $2 is "$ip6Addr"
# "1.1.1.1" of CloudFlare was banned in mainland of China, "1.0.0.3" will meet the same death soon later, maybe.
function checkIpv4OrIpv6() {
	for ((w = 1; w <= 2; w++)); do
		IPv4DNSLookup=$(timeout 0.3s dig -4 TXT +short o-o.myaddr.l.google.com @ns3.google.com | sed 's/\"//g')
		[[ "$IPv4DNSLookup" == "" ]] && IPv4DNSLookup=$(timeout 0.3s dig -4 TXT CH +short whoami.cloudflare @1.0.0.3 | sed 's/\"//g')
		[[ "$IPv4DNSLookup" != "" ]] && break
	done
	for ((x = 1; x <= 2; x++)); do
		IPv6DNSLookup=$(timeout 0.3s dig -6 TXT +short o-o.myaddr.l.google.com @ns3.google.com | sed 's/\"//g')
		[[ "$IPv6DNSLookup" == "" ]] && IPv6DNSLookup=$(timeout 0.3s dig -6 TXT CH +short whoami.cloudflare @2606:4700:4700::1003 | sed 's/\"//g')
		[[ "$IPv6DNSLookup" != "" ]] && break
	done
	for y in "$3" "$4" "$5" "$6"; do
		IPv4PingDNS=$(timeout 0.3s ping -4 -c 1 "$y" | grep "rtt\|round-trip" | cut -d'/' -f5 | awk -F'.' '{print $NF}' | sed -E '/^[0-9]\+\(\.[0-9]\+\)\?$/p')"$IPv4PingDNS"
		[[ "$IPv4PingDNS" != "" ]] && break
	done
	for z in "$7" "$8" "$9" "${10}"; do
		IPv6PingDNS=$(timeout 0.3s ping -6 -c 1 "$z" | grep "rtt\|round-trip" | cut -d'/' -f5 | awk -F'.' '{print $NF}' | sed -E '/^[0-9]\+\(\.[0-9]\+\)\?$/p')"$IPv6PingDNS"
		[[ "$IPv6PingDNS" != "" ]] && break
	done

	# Use ping -4/-6 to replace dig -4/-6 because some IPv4 network will callback IPv6 address from DNS even if we use "dig -4" to get DNS result.
	[[ "$IPv4PingDNS" =~ ^[0-9] && "$IPv6PingDNS" =~ ^[0-9] ]] && IPStackType="BiStack"
	[[ "$IPv4PingDNS" =~ ^[0-9] && ! "$IPv6PingDNS" =~ ^[0-9] ]] && IPStackType="IPv4Stack"
	[[ ! "$IPv4PingDNS" =~ ^[0-9] && "$IPv6PingDNS" =~ ^[0-9] ]] && IPStackType="IPv6Stack"
	[[ -n "$1" || -n "$2" ]] && {
		if [[ -n "$1" && -z "$2" ]]; then
			for ipCheck in "$1" "$ipGate"; do
				verifyIPv4FormatLawfulness "$ipCheck"
			done
		elif [[ -n "$1" && -n "$2" ]]; then
			for ipCheck in "$1" "$ipGate"; do
				verifyIPv4FormatLawfulness "$ipCheck"
			done
			for ipCheck in "$2" "$ip6Gate"; do
				verifyIPv6FormatLawfulness "$ipCheck"
			done
			IPStackType="BiStack"
		elif [[ -z "$1" && -n "$2" ]]; then
			for ipCheck in "$2" "$ip6Gate"; do
				verifyIPv6FormatLawfulness "$ipCheck"
			done
		fi
	}

	[[ $(echo "$setIpStack" | grep -i "bi\|bistack\|dual\|two") ]] && IPStackType="BiStack"
	[[ $(echo "$setIpStack" | grep -i "4\|i4\|ip4\|ipv4") ]] && IPStackType="IPv4Stack"
	[[ $(echo "$setIpStack" | grep -i "6\|i6\|ip6\|ipv6") ]] && IPStackType="IPv6Stack"

	# [[ "$IPStackType" == "IPv4Stack" ]] && setIPv6="0" || setIPv6="1"
	[[ "$tmpSetIPv6" == "0" ]] && setIPv6="0" || setIPv6="1"
}

function verifyIPv4FormatLawfulness() {
	[[ -n "$1" ]] && IP_Check="$1"
	if expr "$IP_Check" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
		for i in 1 2 3 4; do
			if [ $(echo "$IP_Check" | cut -d. -f$i) -gt 255 ]; then
				echo "fail ($IP_Check)"
				exit 1
			fi
		done
		IP_Check="isIPv4"
	fi
	[[ "$IP_Check" != "isIPv4" ]] && {
		echo -ne "\n[${red}Error${plain}] Invalid inputted IPv4 format!\n"
		exit 1
	}
}

function verifyIPv6FormatLawfulness() {
	[[ -n "$1" ]] && IPv6_Check="$1"
	# If the last two strings of IPv6 is "::", we should replace ":" to "0" for the last string to make sure it's a valid IPv6(can't end with ":").
	[[ "${IPv6_Check: -1}" == ":" ]] && IPv6_Check=$(echo "$IPv6_Check" | sed 's/.$/0/')
	# If the first two strings of IPv6 is "::", we should replace ":" to "0" for the first string to make sure it's a valid IPv6(can't start with ":").
	[[ "${IPv6_Check:0:1}" == ":" ]] && IPv6_Check=$(echo "$IPv6_Check" | sed 's/^./0/')
	# Add ":" in the last of the IPv6 address for cut all items infront of the ":" by split by symbol ":".
	IP6_Check_Temp="$IPv6_Check"":"
	# Total numbers of the hex blocks in IPv6 address includes with empty value(abbreviation of "0000").
	IP6_Hex_Num=$(echo "$IP6_Check_Temp" | tr -cd ":" | wc -c)
	# Default number of empty values of the hex block is "0".
	IP6_Hex_Abbr="0"
	# The first filter plays a role of:
	# 1. check if 0-9 or a-z and ":" in original IPv6;
	# 2. the longest number of ":" in IPv6 is "7", because of variable "IP6_Check_Temp" one more ":" has been add,
	# so the total number of ":" in variable "IP6_Check_Temp" should be less or equal "8".
	if [[ $(echo "$IPv6_Check" | grep -i '[[:xdigit:]]' | grep ':') ]] && [[ "$IP6_Hex_Num" -le "8" ]]; then
		# IPv6 address doesn't allow two "::" existed, the number of ":" should not above 7.
		# If number of ":" is less than 6, at least one "::" is required.
		# IPv6 can't end with "hex_number:"
		[[ $(echo "$1" | grep -o ":::" | wc -l) -gt "0" ]] || [[ $(echo "$1" | grep -o "::" | wc -l) -gt "1" || $(echo "$1" | grep -o ":" | wc -l) -gt "7" ]] || [[ "$IP6_Hex_Num" -le "7" && $(echo "$1" | grep -o "::" | wc -l) -lt "1" ]] || [[ "${1: -2}" != "::" && "${1: -1}" == ":" ]] && {
			echo -ne "\n[${red}Error${plain}] Invalid inputted IPv6 format!\n"
			exit 1
		}
		# Total cycles of the check(sequence of the current hex block).
		for ((i = 1; i <= "$IP6_Hex_Num"; i++)); do
			# Every IPv6 hex block of current cycle.
			IP6_Hex=$(echo "$IP6_Check_Temp" | cut -d: -f$i)
			# Count "::" abbreviations for this IPv6.
			[[ "$IP6_Hex" == "" ]] && IP6_Hex_Abbr=$(expr $IP6_Hex_Abbr + 1)
			# String number of letters or numbers in one block should less or equal "4".
			if [[ $(echo "$IP6_Hex" | wc -m) -le "5" ]]; then
				# The second filter plays a reversion role of the following to exclude an effective IPv6 hex block:
				# 1. Except 0-9 and a-f;
				# 2. Abbreviation of hex block should be appeared less than or equal one time in principle.
				[[ $(echo "$IP6_Hex" | grep -iE '[^0-9a-f]') || "$IP6_Hex_Abbr" -gt "1" ]] && {
					echo -ne "\n[${red}Error${plain}] Invalid inputted IPv6 format!\n"
					exit 1
				}
			else
				echo -ne "\n[${red}Error${plain}] Invalid inputted IPv6 format!\n"
				exit 1
			fi
		done
		IP6_Check="isIPv6"
	fi
	[[ "$IP6_Check" != "isIPv6" ]] && {
		echo -ne "\n[${red}Error${plain}] Invalid inputted IPv6 format!\n"
		exit 1
	}
}

# $1 is for IPv4s, $2 is for IPv6s, '1' is private to each stack.
function checkIfIpv4AndIpv6IsLocalOrPublic() {
	ipv4LocalOrPublicStatus=''
	ipv6LocalOrPublicStatus=''
	ip4CertFirst=''
	ip4CertSecond=''
	ip4CertThird=''
	ip6CertAddrWhole=''
	ip6CertAddrFirst=''
	[[ -n "$1" ]] && {
		ip4CertFirst=$(echo $1 | cut -d'.' -f1)
		ip4CertSecond=$(echo $1 | cut -d'.' -f2)
		ip4CertThird=$(echo $1 | cut -d'.' -f3)
		[[ "$ip4CertFirst" == "169" && "$ip4CertSecond" == "254" ]] || [[ "$ip4CertFirst" == "172" && "$ip4CertSecond" -ge "16" && "$ip4CertSecond" -le "31" ]] || [[ "$ip4CertFirst" == "192" && "$ip4CertSecond" == "168" ]] || [[ "$ip4CertFirst" == "100" && "$ip4CertSecond" -ge "64" && "$ip4CertSecond" -le "127" ]] || [[ "$ip4CertFirst" == "10" && "$ip4CertSecond" -ge "0" && "$ip4CertSecond" -le "255" ]] || [[ "$ip4CertFirst" == "127" && "$ip4CertSecond" -ge "0" && "$ip4CertSecond" -le "255" ]] || [[ "$ip4CertFirst" == "198" && "$ip4CertSecond" -ge "18" && "$ip4CertSecond" -le "19" ]] || [[ "$ip4CertFirst" == "192" && "$ip4CertSecond" == "0" && "$ip4CertThird" == "0" || "$ip4CertThird" == "2" ]] || [[ "$ip4CertFirst" == "198" && "$ip4CertSecond" == "51" && "$ip4CertThird" == "100" ]] || [[ "$ip4CertFirst" == "203" && "$ip4CertSecond" == "0" && "$ip4CertThird" == "113" ]] && {
			ipv4LocalOrPublicStatus='1'
		}
	}
	[[ -n "$2" ]] && {
		ip6CertAddrWhole=$(ultimateFormatOfIpv6 "$2")
		ip6CertAddrFirst=$(echo $ip6CertAddrWhole | sed 's/\(.\{4\}\).*/\1/' | sed 's/[a-z]/\u&/g')
		[[ "$((16#$ip6CertAddrFirst))" -ge "$((16#FE80))" && "$((16#$ip6CertAddrFirst))" -le "$((16#FEBF))" ]] || [[ "$((16#$ip6CertAddrFirst))" -ge "$((16#FC00))" && "$((16#$ip6CertAddrFirst))" -le "$((16#FDFF))" ]] && {
			ipv6LocalOrPublicStatus='1'
		}
	}
}

# Some "BiStack" types are accomplished by Warp which provided by CloudFlare, so we need to distinguish whether IPv4 or IPv6 stack is enabled by Warp then exclude it.
# $1 is "warp*.conf", maybe "warp.conf" or "warp-profile.conf"; $2 is "wgcf*.conf", maybe "wgcf.conf" or "wgcf-profile.conf"; $3 is "wg[0-9]", maybe "wg0.conf" or etc.
# $4/$5/$6 are "warp*/wgcf*/wg[0-9]", $7/$8 are "PrivateKey/PublicKey".
function checkWarp() {
	warpConfFiles=$(find / -maxdepth 6 -name "$1" -print -or -name "$2" -print -or -name "$3" -print)
	sysctlWarpProcess=$(systemctl 2>&1 | grep -i "$4\|$5\|$6" | wc -l)
	rcWarpProcess=$(rc-status 2>&1 | grep -i "$4\|$5\|$6" | wc -l)
	[[ "$IPStackType" == "BiStack" ]] && {
		[[ -n "$warpConfFiles" ]] && {
			for warpConfFile in $(find / -maxdepth 6 -name "$1" -print -or -name "$2" -print -or -name "$3" -print); do
				if [[ $(grep -ic "$7" "$warpConfFile") -ge "1" || $(grep -ic "$8" "$warpConfFile") -ge "1" ]]; then
					warpStatic="1"
					break
				fi
			done
		}
		[[ "$sysctlWarpProcess" -gt "0" || "$rcWarpProcess" -gt "0" ]] && warpStatic="1"
	}
	[[ "$warpStatic" == "1" ]] && {
		[[ -z "$ipGate" ]] && IPStackType="IPv6Stack"
		[[ -z "$ip6Gate" ]] && IPStackType="IPv4Stack"
	}
}

# Examples:
# input:    ::
# output:   0:0:0:0:0:0:0:0
# input:    2620:119:35::c4
# output:   2620:119:35:0:0:0:0:c4
function fillAbbrOfIpv6() {
	inputIpv6="$1"
	# Static of how many delimiters of ":" are in one ipv6 address, only one abbreviation of "::" is allowed in one IPv6 address in principle.
	delimiterNum=$(echo $inputIpv6 | awk '{print gsub(/:/, "")}')
	replaceStr=""
	# A standard of IPv6 should have 7 colons, the number "7" minus total numbers of colons in an abbreviated IPv6 address and add "0" after every ":" can help us to fulfill the whole IPv6 address.
	for ((i = 0; i <= $((7 - $delimiterNum)); i++)); do
		replaceStr="$replaceStr"":0"
	done
	# Must add one ":" after the last of expanded "0" to separate with the following IPv6 block which is not been abbreviated.
	replaceStr="$replaceStr"":"
	# Replace abbreviated IPv6 address "::" to expanded IPv6 address($replaceStr).
	ipv6Expanded=${inputIpv6/::/$replaceStr}
	# If the last two strings of abbreviated IPv6 is "::", we should add a "0" for the last ":" to pledge the validation of this IPv6(can't end with ":").
	[[ "$ipv6Expanded" == *: ]] && ipv6Expanded="$ipv6Expanded""0"
	# If the first two strings of abbreviated IPv6 is "::", we should add a "0" for the first ":" to pledge the validation of this IPv6(can't begin with ":").
	[[ "$ipv6Expanded" == :* ]] && ipv6Expanded="0""$ipv6Expanded"
	# Return IPv6 which is filled with one "0" in every abbreviated block.
	echo "$ipv6Expanded"
}

# Examples:
# input:    0:0:0:0:0:0:0:0
# output:   0000:0000:0000:0000:0000:0000:0000:0000
# input:    2620:119:35:0:0:0:0:c4
# output:   2620:0119:0035:0000:0000:0000:0000:00c4
function ultimateFormatOfIpv6() {
	abbrExpandedOfIpv6=$(fillAbbrOfIpv6 "$1")
	# To make a new array names "$ipv6Hex" to storage every hex block like "2620" "119e" of IPv6, this array should have 8 indices.
	ipv6Hex=(${abbrExpandedOfIpv6//:/ })
	for ((j = 0; j < 8; j++)); do
		# Static number of strings in every hex block of IPv6.
		length="${#ipv6Hex[j]}"
		# Use decrement cycle to count how many zeroes need to be fulfilled because there are most 4 strings in one hex block in theory.
		for ((k = 4; k > $length; k--)); do
			# Zeroes which must be added on the head if number of digits of a hexadecimal number in one hex block is less than 4.
			ipv6Hex[j]="0${ipv6Hex[j]}"
		done
	done
	# Return all elements of array of "$ipv6Hex" which is filled with 4 digits in every hexadecimal block and use colon to stitch with hexes instead of space to achieve the recovery of an abbreviated IPv6 address.
	echo ${ipv6Hex[@]} | sed 's/ /\:/g'
}

function getIPv6Address() {
	# Differences from scope link, scope host and scope global of IPv6, reference: https://qiita.com/_dakc_/items/4eefa443306860bdcfde
	allI6Addrs=$(ip -6 addr show | grep -wA 32768 "$interface6" | grep -wv "lo" | grep -wv "link\|host" | grep -w "inet6" | grep "scope" | grep "global" | awk -F " " '{for (i=2;i<=NF;i++)printf("%s ", $i);print ""}' | awk '{print $1}')
	i6Addr=$(echo "$allI6Addrs" | head -n 1)
	i6AddrNum=$(echo "$allI6Addrs" | wc -l)
	collectAllIpv6Addresses "$i6AddrNum"
	ip6Addr=$(echo ${i6Addr} | cut -d'/' -f1)
	ip6Mask=$(echo ${i6Addr} | cut -d'/' -f2)
	ip6Gate=$(ip -6 route show default | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -w "$interface6" | grep -w "via" | grep "dev" | head -n 1 | awk -F " " '{for (i=3;i<=NF;i++)printf("%s ", $i);print ""}' | awk '{print$1}')
	# Get real IPv6 subnet of current System
	actualIp6Prefix=$(ip -6 route show | grep -iv "warp\|wgcf\|wg[0-9]\|docker[0-9]" | grep -w "$interface6" | grep -v "default" | grep -v "multicast" | grep -P '../[0-9]{1,3}' | head -n 1 | awk '{print $1}' | awk -F '/' '{print $2}')
	[[ -z "$actualIp6Prefix" || "$i6AddrNum" -ge "2" ]] && actualIp6Prefix="$ip6Mask"
	transferIPv6AddressFormat "$ip6Addr" "$ip6Gate"
}

# $1 is "$ip6Addr", $2 is "$ip6Gate".
function transferIPv6AddressFormat() {
	# Some Bi-Stack server has a public IPv4 address with a private IPv4 gateway and has a dhcp configuration for IPv6 stack,
	# so we need to tell Debian installer IPv6 static configurations to config IPv6 network first by force.
	[[ "$BiStackPreferIpv6Status" == "1" ]] && Network6Config="isStatic"
	# In some original template OS of cloud provider like Akile.io etc,
	# if prefix of IPv6 mask is 128 in static network configuration, it means there is only one IPv6(current server itself) in the network.
	# The following is the sample:
	#
	# auto eth0
	#   iface eth0 inet6 static
	#     address 2603:c020:8:a19b::ffff:e6da
	#     gateway 2603:c020:8:a19b::ffff
	#     netmask 128
	#     dns-nameservers 2001:4860:4860::8888
	#
	# In this condition, if IPv6 gateway has a different address with IPv6 address, the Debian installer couldn't find the correct gateway.
	# The installation will fail in the end. The reason is mostly the upstream wrongly configurated the current network of this system.
	# So we try to revise this value for 8 levels to expand the range of the IPv6 network and help installer to find the correct gateway.
	# DHCP IPv6 network(even IPv6 netmask is "128") may not be effected by this situation.
	# The result of function ' ipv6SubnetCalc "$ip6Mask" ' is "$ip6Subnet"
	# The following consulted calculations are calculated by Vultr IPv6 subnet calculator and IPv6 subnet range calculator which is provided by iP Jisuanqi.
	# Reference: https://www.vultr.com/resources/subnet-calculator-ipv6/
	#            https://ipjisuanqi.com/ipv6.html
	[[ "$Network6Config" == "isStatic" ]] && {
		# IPv6 expansion algorithm code reference: https://blog.caoyu.info/expand-ipv6-by-shell.html
		ip6AddrWhole=$(ultimateFormatOfIpv6 "$1")
		ip6GateWhole=$(ultimateFormatOfIpv6 "$2")
		tmpIp6AddrFirst=$(echo $ip6AddrWhole | sed 's/\(.\{4\}\).*/\1/' | sed 's/[a-z]/\u&/g')
		tmpIp6GateFirst=$(echo $ip6GateWhole | sed 's/\(.\{4\}\).*/\1/' | sed 's/[a-z]/\u&/g')
		if [[ "$tmpIp6AddrFirst" != "$tmpIp6GateFirst" ]]; then
			# If some brave guys set --network "static" by force, IPv6 address, mask and gateway of IPv6 DHCP configurations like Oracle Cloud etc. are:
			# a public IPv6 address, a "128" mask, a local IPv6 gateway(starts with "fe80" mostly, like "fe80::200:f1e9:dec3:4ab").
			# The value of mask must be set as "128", not "1" which determined by first condition of above because the local IPv6 address is unique in its' network
			# and plays the role of IPv6 network discovery and identical authentication to ensure that authenticated device is certificated by upstream.
			# Explanation of using local IPv6 address as gateway quoted from Scott Hogg:
			#
			# Link-local IPv6 addresses are on every interface of every IPv6-enabled host and router. They are essential for LAN-based Neighbor Discovery communication.
			# After the host has gone through the Duplicate Address Detection (DAD) process ensuring that its link-local address (and associated IID) is unique on the LAN segment,
			# it then proceeds to sending an ICMPv6 Router Solicitation (RS) message sourced from that address.
			#
			# There are total three IPv6 address ranges divided into local address: fe80::/10, fec0::/10, fc00::/7.
			# "fe80::/10" is similar with "169.254.0.0/16" of IPv4 of February, 2006 according to RFC 4291, ranges from fe80:0000:0000:0000:0000:0000:0000:0000 to febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
			# "fec0::/10" is similar with "192.168.0.0/16" of IPv4 which was deprecated and returned to public IPv6 address again of September, 2004 according to RFC 3879.
			# The function of "fec0::/10" was replaced by "fc00::/7" of October, 2005 according to RFC 4193, ranges from fc00:0000:0000:0000:0000:0000:0000:0000 to fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
			# So we need to calculate ranges of "fe80::/10" and "fc00::/7", if IPv6 address is public and IPv6 gateway belongs to local IPv6 address.
			# English strings in hexadecimal must be converted as capital alphabets that comparison operations can be processed by shell.
			# Reference: https://blogs.infoblox.com/ipv6-coe/fe80-1-is-a-perfectly-valid-ipv6-default-gateway-address/ chapter: Link-Local Address as Default Gateway
			#            https://www.wdic.org/w/WDIC/IPv6%E3%82%A2%E3%83%89%E3%83%AC%E3%82%B9 chapter: アドレスの種類(Types of address) → エニキャストアドレス(Anycast address)
			#            https://www.wdic.org/w/WDIC/IPv6%E3%82%A2%E3%83%89%E3%83%AC%E3%82%B9 chapter: サイトローカルアドレス(Site local address)
			#            https://www.wdic.org/w/WDIC/%E3%83%A6%E3%83%8B%E3%83%BC%E3%82%AF%E3%83%AD%E3%83%BC%E3%82%AB%E3%83%AB%E3%83%A6%E3%83%8B%E3%82%AD%E3%83%A3%E3%82%B9%E3%83%88%E3%82%A2%E3%83%89%E3%83%AC%E3%82%B9
			#            https://www.ipentec.com/document/network-format-ipv6-local-adddress chapter: IPv6のリンクローカルアドレス(Link local address of IPv6)
			#            https://www.rfc-editor.org/rfc/rfc4291.html#section-2.4 chapter: 2.4. Address Type Identification
			checkIfIpv4AndIpv6IsLocalOrPublic "" "$2"
			if [[ "$ipv6LocalOrPublicStatus" == '1' ]]; then
				tmpIp6Mask="64"
				# Installer of Debian 11 and former doesn't support irregular IPv6 configs.
				[[ "$linux_relese" == 'debian' && -n $(echo $tmpDIST | grep -o "[0-9]") && "$tmpDIST" -le "11" && "$IPStackType" == "IPv6Stack" && "$Network6Config" == "isStatic" ]] && BurnIrregularIpv6Status='1'
			else
				# If the IPv6 and IPv6 gateway are not in the same IPv6 A class, the prefix of netmask should be "1",
				# transfer to whole IPv6 subnet address is 8000:0000:0000:0000:0000:0000:0000:0000.
				# The range of 2603:c020:8:a19b::ffff:e6da/1 is 0000:0000:0000:0000:0000:0000:0000:0000 - 7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the gateway 2603:c020:0008:a19b:0000:0000:0000:ffff can be included.
				tmpIp6Mask="1"
			fi
		else
			ipv6SubnetCertificate "$ip6AddrWhole" "$ip6GateWhole"
		fi
		# Too narrow of IPv6 prefix may cause some unpredictable risks.
		[[ "$tmpIp6Mask" -le "16" ]] && {
			[[ "$BiStackPreferIpv6Status" == "1" ]] || [[ "$linux_relese" == 'debian' && "$IPStackType" == "IPv6Stack" && "$Network6Config" == "isStatic" ]] && BurnIrregularIpv6Status='1'
		}
		ip6Mask="$tmpIp6Mask"
		# Because of function "ipv6SubnetCalc" includes self-increment,
		# so we need to confirm the goal of IPv6 prefix and make function to operate only one time in the last to save performance and avoid all
		# gears of IPv6 prefix which meets well with the conditions of above are transformed to whole IPv6 addresses in one variable.
		# The same thought of moving function "netmask" to the last, only need to transform IPv4 prefix to whole IPv4 address for one time.
		ipv6SubnetCalc "$ip6Mask"
		# So in summary of the IPv6 sample in above, we should assign subnet mask "ffff:ffff:ffff:ffff:ffff:ffff:0000:0000"(prefix is "96") for it.
	}
}

# $1 is "$ip6AddrWhole", $2 is "$$ip6GateWhole".
function ipv6SubnetCertificate() {
	# If the IP and gateway are in the same IPv6 A class, not in the same IPv6 B class, the prefix of netmask should less equal than "16",
	# transfer to whole IPv6 subnet address is ffff:0000:0000:0000:0000:0000:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/16 is 2603:0000:0000:0000:0000:0000:0000:0000 - 2603:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1) == $(echo $2 | cut -d':' -f 1) ]] && tmpIp6Mask="16"
	# If the IP and gateway are in the same IPv6 A B class, not in the same IPv6 C class, the prefix of netmask should less equal than "32",
	# transfer to whole IPv6 subnet address is ffff:ffff:0000:0000:0000:0000:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/32 is 2603:c020:0000:0000:0000:0000:0000:0000 - 2603:c020:ffff:ffff:ffff:ffff:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1,2) == $(echo $2 | cut -d':' -f 1,2) ]] && tmpIp6Mask="32"
	# If the IP and gateway are in the same IPv6 A B C class, not in the same IPv6 D class, the prefix of netmask should less equal than "48",
	# transfer to whole IPv6 subnet address is ffff:ffff:ffff:0000:0000:0000:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/48 is 2603:c020:0008:0000:0000:0000:0000:0000 - 2603:c020:0008:ffff:ffff:ffff:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1,2,3) == $(echo $2 | cut -d':' -f 1,2,3) ]] && tmpIp6Mask="48"
	# If the IP and gateway are in the same IPv6 A B C D class, not in the same IPv6 E class, the prefix of netmask should less equal than "64",
	# transfer to whole IPv6 subnet address is ffff:ffff:ffff:ffff:0000:0000:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/64 is 2603:c020:0008:a19b:0000:0000:0000:0000 - 2603:c020:0008:a19b:ffff:ffff:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1,2,3,4) == $(echo $2 | cut -d':' -f 1,2,3,4) ]] && tmpIp6Mask="64"
	# If the IP and gateway are in the same IPv6 A B C D E class, not in the same IPv6 F class, the prefix of netmask should less equal than "80",
	# transfer to whole IPv6 subnet address is ffff:ffff:ffff:ffff:ffff:0000:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/80 is 2603:c020:0008:a19b:0000:0000:0000:0000 - 2603:c020:0008:a19b:0000:ffff:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1,2,3,4,5) == $(echo $2 | cut -d':' -f 1,2,3,4,5) ]] && tmpIp6Mask="80"
	# If the IP and gateway are in the same IPv6 A B C D E F class, not in the same IPv6 G class, the prefix of netmask should less equal than "96",
	# transfer to whole IPv6 subnet address is ffff:ffff:ffff:ffff:ffff:ffff:0000:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/96 is 2603:c020:0008:a19b:0000:0000:0000:0000 - 2603:c020:0008:a19b:0000:0000:ffff:ffff, the gateway 2603:... can be included.
	[[ $(echo $1 | cut -d':' -f 1,2,3,4,5,6) == $(echo $2 | cut -d':' -f 1,2,3,4,5,6) ]] && tmpIp6Mask="96"
	# If the IP and gateway are in the same IPv6 A B C D E F G class, not in the same IPv6 H class, the prefix of netmask should less equal than "112",
	# transfer to whole IPv6 subnet address is ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000.
	# The range of 2603:c020:8:a19b::ffff:e6da/112 is 2603:c020:0008:a19b:0000:0000:ffff:0000 - 2603:c020:0008:a19b:0000:0000:ffff:ffff, the gateway 2603:c020:0008:a19b:0000:0000:0000:ffff can't be included.
	[[ $(echo $1 | cut -d':' -f 1,2,3,4,5,6,7) == $(echo $2 | cut -d':' -f 1,2,3,4,5,6,7) ]] && tmpIp6Mask="112"
}

# $1 is $ip6Mask
function ipv6SubnetCalc() {
	tmpIp6Subnet=""
	ip6Subnet=""
	ip6SubnetEleNum=$(expr $1 / 4)
	ip6SubnetEleNumRemain=$(expr $1 - $ip6SubnetEleNum \* 4)
	if [[ "$ip6SubnetEleNumRemain" == 0 ]]; then
		ip6SubnetHex="0"
	elif [[ "$ip6SubnetEleNumRemain" == 1 ]]; then
		ip6SubnetHex="8"
	elif [[ "$ip6SubnetEleNumRemain" == 2 ]]; then
		ip6SubnetHex="c"
	elif [[ "$ip6SubnetEleNumRemain" == 3 ]]; then
		ip6SubnetHex="e"
	fi
	for ((i = 1; i <= "$ip6SubnetEleNum"; i++)); do
		tmpIp6Subnet+="f"
	done
	tmpIp6Subnet=$tmpIp6Subnet$ip6SubnetHex
	for ((j = 1; j <= $(expr 32 - $ip6SubnetEleNum); j++)); do
		tmpIp6Subnet+="0"
	done
	if [[ $(echo $tmpIp6Subnet | wc -c) -ge "33" ]]; then
		tmpIp6Subnet=$(echo $tmpIp6Subnet | sed 's/.$//')
	fi
	for ((k = 0; k <= 7; k++)); do
		ip6Subnet+=$(echo ${tmpIp6Subnet:$(expr $k \* 4):4})":"
	done
	ip6Subnet=$(echo ${ip6Subnet%?})
}

# $1 is "$iAddrNum".
function collectAllIpv4Addresses() {
	[[ "$1" -ge "2" && "$IPStackType" != "IPv6Stack" ]] && {
		Network4Config="isStatic"
		iAddrs=()
		for tmpIp in $allI4Addrs; do
			iAddrs[${#iAddrs[@]}]=$tmpIp
		done
	}
}

# $1 is "$iAddrNum", $2 is "in-target", $3 is 'netconfig file'.
function writeMultipleIpv4Addresses() {
	[[ "$1" -ge "2" && "$IPStackType" != "IPv6Stack" ]] && {
		if [[ "$linux_relese" == 'debian' ]]; then
			unset iAddrs[0]
			for writeIps in ${iAddrs[@]}; do
				ipAddrItem="up ip addr add $writeIps dev $interface4"
				tmpWriteIpsCmd+=''$2' sed -i '\''$a\\t'$ipAddrItem''\'' '$3'; '
			done
			writeIpsCmd=$(echo $tmpWriteIpsCmd)
			SupportMultipleIPv4="$writeIpsCmd"
		elif [[ "$targetRelese" == 'Ubuntu' ]]; then
			for writeIps in ${iAddrs[@]}; do
				ipAddrItem="$writeIps"
				tmpWriteIpsCmd+=''$ipAddrItem','
			done
			writeIpsCmd=$(echo ''$tmpWriteIpsCmd'' | sed 's/.$//')
		fi
	}
}

# $1 is "$i6AddrNum".
function collectAllIpv6Addresses() {
	[[ "$1" -ge "2" && "$IPStackType" != "IPv4Stack" ]] && {
		Network6Config="isStatic"
		i6Addrs=()
		for tmpIp6 in $allI6Addrs; do
			# The best way to add several elements into an array by using "for" loop in the shell.
			# Reference: https://linuxhandbook.com/bash-append-array/
			i6Addrs[${#i6Addrs[@]}]=$tmpIp6
		done
		if [[ "$IPStackType" == "IPv6Stack" ]] || [[ "$IPStackType" == "BiStack" && -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]]; then
			# A sample result of the following arrays which were programmed by "for" loops:
			#
			# ${i6Addrs[@]}                         : 2606:a8c0:3:6f::b/64 2606:a8c0:3:6f::a/64 2606:a8c0:3::64/128
			# ${allI6AddrsWithoutSuffix[@]}         : 2606:a8c0:3:6f::b 2606:a8c0:3:6f::a 2606:a8c0:3::64
			# ${allI6AddrsWithUltimateFormat[@]}    : 2606:a8c0:0003:006f:0000:0000:0000:000b 2606:a8c0:0003:006f:0000:0000:0000:000a 2606:a8c0:0003:0000:0000:0000:0000:0064
			# ${allI6AddrsWithOmittedClassesNum[@]} : 3 3 4
			# $omittedClassesMaxNum                 : 4
			# $mainIp6Index                         : 2
			# $i6Addr                               : 2606:a8c0:3::64/128
			#
			# To find out the segment with the largest range of one IPv6 in all of the IPv6s as default to config IPv6 network in netboot environment for machines of IPv6 stack.
			allI6AddrsWithoutSuffix=()
			for tmpIp6 in ${i6Addrs[@]}; do
				tmpIp6=$(echo $tmpIp6 | cut -d'/' -f1)
				allI6AddrsWithoutSuffix[${#allI6AddrsWithoutSuffix[@]}]=$tmpIp6
			done
			allI6AddrsWithUltimateFormat=()
			for tmpIp6 in ${allI6AddrsWithoutSuffix[@]}; do
				tmpIp6=$(ultimateFormatOfIpv6 "$tmpIp6")
				allI6AddrsWithUltimateFormat[${#allI6AddrsWithUltimateFormat[@]}]=$tmpIp6
			done
			allI6AddrsWithOmittedClassesNum=()
			for tmpIp6 in ${allI6AddrsWithUltimateFormat[@]}; do
				tmpIp6=$(echo $tmpIp6 | grep -oi "0000" | wc -l)
				allI6AddrsWithOmittedClassesNum[${#allI6AddrsWithOmittedClassesNum[@]}]=$tmpIp6
			done
			omittedClassesMaxNum=${allI6AddrsWithOmittedClassesNum[0]}
			for tmpIp6 in ${!allI6AddrsWithOmittedClassesNum[@]}; do
				if [[ "$omittedClassesMaxNum" -le "${allI6AddrsWithOmittedClassesNum[${tmpIp6}]}" ]]; then
					omittedClassesMaxNum=${allI6AddrsWithOmittedClassesNum[${tmpIp6}]}
				fi
			done
			getArrItemIdx "${allI6AddrsWithOmittedClassesNum[*]}" "$omittedClassesMaxNum"
			mainIp6Index="$index"
			i6Addr=${i6Addrs[$mainIp6Index]}
		fi
	}
}

# Debian installer can't accept any command that writing multi lines by one "sed -i" or "echo -e" etc in "preseed.cfg".
# For example, if we want to add two lines or more like "up ip addr add IPv6one/48 dev eth0" and "up ip addr add IPv6two/40 dev eth0" to "network file",
# using "sed -i '$a\\tup ip addr add IPv6one/48 dev eth0' 'network file';" and then "sed -i '$a\\tup ip addr add IPv6two/40 dev eth0' 'network file';" is necessary.
# Otherwise, if try to use "sed -i '$a\\tup ip addr add IPv6one/48 dev eth0\n\tup ip addr add IPv6two/40 dev eth0' 'network file';"
# to add two IPv6 addresses config lines in the same "sed -i", Debian installer will meet a fatal.
#
# An excellent method to add multiple IPv6 addresses and the IPv6 gateway of them in Bi-stack(dual-stack) network configuration file for Debian, here is the sample:
#
# allow-hotplug eth0
# iface eth0 inet static
#     address 59.67.82.30
#     gateway 59.67.82.1
#     netmask 255.255.255.0
#     dns-nameservers 1.0.0.1 8.8.4.4 2606:4700:4700::1001 2001:4860:4860::8844
#     up ip addr add 2a12:a520:d420::736f/48 dev eth0
#     up ip addr add 2a12:a520:2e0b::a89c:11de/40 dev eth0
#     up ip -6 route add 2a12:a520:2e0b:0000:0000:0000:0000:0001 dev eth0
#     up ip -6 route add default via 2a12:a520:2e0b:0000:0000:0000:0000:0001 dev eth0
#
# A standard format of adding multiple IPv6 configs into IPv6 stack server for Debian series:
#
# allow-hotplug enp3s0
# iface enp3s0 inet6 static
#	    address 2606:a8c0:3::64/128
#	    gateway 2606:a8c0:3::1
#	    dns-nameservers 2606:4700:4700::1001 2001:4860:4860::8844
#   	dns-search debian
# 	  up ip addr add 2606:a8c0:3:6f::3b/64 dev enp3s0
#	    up ip addr add 2606:a8c0:3:6f::a/64 dev enp3s0
#
# A standard formart of adding multiple IPv6 addresses for the second network adapter in Bi-stack(dual-stack) server for Debian series:
# The first network adapter which is called such as "eth0" plays a role of establishing IPv4 stack network,
# and then the second network adapter of "eth1" is responsible of creating multiple terms of IPv6 stack networking configurations.
# This uncommon and extreme situation can only be applied for Debian series at current because the file of "/etc/network/interfaces" is easily to be modified.
#
# allow-hotplug eth0
# iface eth0 inet static
#     address 104.36.84.237/32
#     gateway 104.36.84.1
#     dns-nameservers 1.0.0.1 8.8.4.4
#
# allow-hotplug eth1
# iface eth1 inet6 static
#     address 2606:a8c0:3::64/128
#     gateway 2606:a8c0:3::1
#     dns-nameservers 2606:4700:4700::1001 2001:4860:4860::8844
#     up ip -6 addr add 2606:a8c0:3:6f::2f/64 dev eth1
#     up ip -6 addr add 2606:a8c0:3:6f::1c/64 dev eth1
#
# $1 is "$i6AddrNum", $2 is "in-target", $3 is 'netconfig file'.
function writeMultipleIpv6Addresses() {
	[[ "$1" -ge "2" && "$IPStackType" != "IPv4Stack" ]] && {
		# For environment of IPv6 stack, one main IPv6 config will be written to system by "preseed" or "kickstart" into the unattend file to config the network firstly.
		# So the main IPv6 config should be excluded in the array of "i6Addrs[@]" for the later stage of writing other IPv6s to the network config file in the newly installed system.
		if [[ "$linux_relese" == 'debian' ]]; then
			if [[ "$IPStackType" == "IPv6Stack" ]] || [[ "$IPStackType" == "BiStack" && -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]]; then
				unset i6Addrs[$mainIp6Index]
			fi
			for writeIp6s in ${i6Addrs[@]}; do
				[[ "$IPStackType" == "BiStack" && -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && ip6AddrItem="up ip -6 addr add $writeIp6s dev $interface6" || ip6AddrItem="up ip addr add $writeIp6s dev $interface6"
				tmpWriteIp6sCmd+=''$2' sed -i '\''$a\\t'$ip6AddrItem''\'' '$3'; '
			done
			writeIp6sCmd=$(echo $tmpWriteIp6sCmd)
			writeIp6GateCmd=''$2' sed -i '\''$a\\tup ip -6 route add '$ip6Gate' dev '$interface6''\'' '$3'; '$2' sed -i '\''$a\\tup ip -6 route add default via '$ip6Gate' dev '$interface6''\'' '$3';'
			addIpv6DnsForPreseed=''$2' sed -ri '\''s/'$ipDNS'/'$ipDNS' '$ip6DNS'/g'\'' '$3';'
			preferIpv6Access=''$2' sed -i '\''$alabel 2002::/16'\'' /etc/gai.conf; '$2' sed -i '\''$alabel 2001:0::/32'\'' /etc/gai.conf;'
			SupportMultipleIPv6=''$writeIp6sCmd' '$writeIp6GateCmd' '$addIpv6DnsForPreseed' '$preferIpv6Access''
			[[ "$IPStackType" == "IPv6Stack" ]] && SupportIPv6orIPv4=''$writeIp6sCmd' '$preferIpv6Access''
			[[ "$IPStackType" == "BiStack" && -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && {
				addIpv6Adapter=''$2' sed -i '\''$a\ '\'' '$3'; '$2' sed -i '\''$aallow-hotplug '$interface6''\'' '$3';'
				addFirstIpv6Config=''$2' sed -i '\''$aiface '$interface6' inet6 static'\'' '$3'; '$2' sed -i '\''$a\\taddress '$i6Addr''\'' '$3'; '$2' sed -i '\''$a\\tgateway '$ip6Gate''\'' '$3'; '$2' sed -i '\''$a\\tdns-nameservers '$ip6DNS''\'' '$3';'
				SupportMultipleIPv6=''$addIpv6Adapter' '$addFirstIpv6Config' '$writeIp6sCmd' '$preferIpv6Access''
			}
		elif [[ "$targetRelese" == 'Ubuntu' ]]; then
			for writeIp6s in ${i6Addrs[@]}; do
				ip6AddrItem="$writeIp6s"
				tmpWriteIp6sCmd+=''$ip6AddrItem','
			done
			writeIp6sCmd=$(echo ''$tmpWriteIp6sCmd'' | sed 's/.$//')
		fi
	}
}

# This function help us to sort sizes for different files from different directions.
# "$FilesDirArr" storages original absolute pathes of files.
# "$FilesLineArr" receives amount of alphabets and numbers etc. in one file from "$FilesDirNum"
# "$FilesDir" is the list of absolute files' pathes those are executed by command like "grep" etc.
# According to file size, "$tmpSizeArray" sorts "$FilesLineArr"'s numbers from smallest to largest(-sort h) or from largest to smallest(-sort hr).
# "$1" are direction of files, "$2" is sort method.
function sortFileSize() {
	FilesDirArr=()
	FilesLineArr=()
	FilesDir="$1"

	for Count in $FilesDir; do
		FilesDirArr+=($Count)
		FilesDirNum=$(cat $Count | wc -c)
		FilesLineArr+=($FilesDirNum)
	done

	tmpSizeArray=($(echo ${FilesLineArr[*]} | tr ' ' '\n' | $2))
}

# This function may help us to find the index order in one array if we provide a random data in this array.
# "$1" is one array like "${FilesLineArr[*]}", "$2" is one element which index of this array needs to be found like "${tmpSizeArray[0]}"
function getArrItemIdx() {
	arr=$1
	item=$2
	index=0

	for i in ${arr[*]}; do
		[[ $item == $i ]] && {
			echo $index >>/dev/null 2>&1
			return
		}
		index=$(($index + 1))
	done
}

# "$1" is the absolute path of a file.
function splitDirAndFile() {
	FileName=$(echo $1 | awk -F/ '{print $NF}')
	FileDirection=$(echo $1 | sed "s/$FileName//g")
}

# In Debian 11 OS template of DigitalOcean, there are 5 directions deposing network configurations after filtered by command of "find" and "grep":
# /run/network/interfaces.d/eth0            31  bytes
# /run/network/interfaces.d/eth1            31  bytes
# /etc/network/interfaces                   755 bytes
# /etc/network/interfaces.d/50-cloud-init   716 bytes
# /etc/network/cloud-interfaces-template    39  bytes
# We should get help by some algorithms to select the largest size of the file, the correct network configuration, "/etc/network/interfaces" is just there.
#
# "$1" is an array which storages temp files. "$2" is sort method, "sort -hr" is largest, "sort -h" is smallest.
function getLargestOrSmallestFile() {
	for Count in "$1"; do
		sortFileSize "$Count" "$2"
		getArrItemIdx "${FilesLineArr[*]}" "${tmpSizeArray[0]}"
		fullFilePath="${FilesDirArr[$index]}"
		[[ "$fullFilePath" != "" ]] && {
			splitDirAndFile "$fullFilePath"
			break
		}
	done
}

# A function about parsing "*.yaml" files by native bash.
# Reference: https://stackoverflow.com/questions/5014632/how-can-i-parse-a-yaml-file-from-a-linux-shell-script
function parseYaml() {
	prefix=$2
	s='[[:space:]]*' w='[a-zA-Z0-9_]*'
	fs=$(echo @ | tr @ '\034')
	sed -ne "s|,$s\]$s\$|]|" \
		-e ":1;s|^\($s\)\($w\)$s:$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1\2: [\3]\n\1  - \4|;t1" \
		-e "s|^\($s\)\($w\)$s:$s\[$s\(.*\)$s\]|\1\2:\n\1  - \3|;p" $1 |
		sed -ne "s|,$s}$s\$|}|" \
			-e ":1;s|^\($s\)-$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1- {\2}\n\1  \3: \4|;t1" \
			-e "s|^\($s\)-$s{$s\(.*\)$s}|\1-\n\1  \2|;p" |
		sed -ne "s|^\($s\):|\1|" \
			-e "s|^\($s\)-$s[\"']\(.*\)[\"']$s\$|\1$fs$fs\2|p" \
			-e "s|^\($s\)-$s\(.*\)$s\$|\1$fs$fs\2|p" \
			-e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
			-e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p" |
		awk -F$fs '{
    indent=length($1)/2
    vname[indent]=$2
    for (i in vname) {if (i>indent) {delete vname[i]; idx[i]=0}}
    if (length($2)==0) {vname[indent]= ++idx[indent]}
    if (length($3)>0) {
      vn=""
      for (i=0;i<indent;i++) {vn=(vn)(vname[i])("_")}
      printf("%s%s%s=\"%s\"\n","'$prefix'",vn,vname[indent],$3)
    }
  }'
}

# $1 is $CurrentOS
function getInterface() {
	# Network config file for Ubuntu 16.04 and former version,
	# Debian all version included the latest Debian 11 is deposited in /etc/network/interfaces, they managed by "ifupdown".
	# Ubuntu 18.04 and later version, using netplan to replace legacy ifupdown, the network config file is in /etc/netplan/
	interface=""
	Interfaces=()
	allInterfaces=$(cat /proc/net/dev | grep ':' | cut -d':' -f1 | sed 's/\s//g' | grep -iv '^lo\|^sit\|^stf\|^gif\|^dummy\|^vmnet\|^vir\|^gre\|^ipip\|^ppp\|^bond\|^tun\|^tap\|^ip6gre\|^ip6tnl\|^teql\|^ocserv\|^vpn\|^warp\|^wgcf\|^wg\|^docker' | sort -n)
	for interfaceItem in $allInterfaces; do
		Interfaces[${#Interfaces[@]}]=$interfaceItem
	done
	interfacesNum="${#Interfaces[*]}"
	# Some server has two different network adapters and for example: eth0 is for IPv4, eth1 is for IPv6, so we need to distinguish whether they are the same.
	default4Route=$(ip -4 route show default | grep -A 3 "^default")
	# In Vultr server of 2.5$/mo plan, it has only IPv6 address, so the default route is via IPv6.
	# The name of interface is not always in the first line:
	# root@layer7:~# ip -6 route show
	# 2a12:5e40:15::/48 dev eth0 proto ra metric 1024 expires 2591978sec pref medium
	# fe80::/64 dev eth0 proto kernel metric 256 pref medium
	# default proto static metric 1024 pref medium
	# nexthop via 2a12:5e40:1::1 dev eth0 weight 1
	# nexthop via fe80::e6c7:22ff:fe4d:b63c dev eth0 weight 1
	default6Route=$(ip -6 route show default | grep -A 3 "^default")
	for item in ${Interfaces[*]}; do
		[ -n "$item" ] || continue
		echo "$default4Route" | grep -q "$item"
		[ $? -eq 0 ] && interface4="$item" && break
	done
	for item in ${Interfaces[*]}; do
		[ -n "$item" ] || continue
		echo "$default6Route" | grep -q "$item"
		[ $? -eq 0 ] && interface6="$item" && break
	done
	interface="$interface4 $interface6"
	[[ "$interface4" == "$interface6" ]] && interface=$(echo "$interface" | cut -d' ' -f 1)
	[[ -z "$interface4" || -z "$interface6" ]] && {
		interface=$(echo "$interface" | sed 's/[[:space:]]//g')
		[[ -z "$interface4" ]] && interface4="$interface"
		[[ -z "$interface6" ]] && interface6="$interface"
	}
	echo "$interface" >/dev/null
	getArrItemIdx "${Interfaces[*]}" "$interface4"
	interface4DeviceOrder="$index"
	getArrItemIdx "${Interfaces[*]}" "$interface6"
	interface6DeviceOrder="$index"
	# Some templates of cloud provider like Bandwagonhosts, Ubuntu 22.04, may modify parameters in " GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0" " in /etc/default/grub
	# to make Linux kernel redirect names of network adapters from real name like ens18, ens3, enp0s4 to eth0, eth1, eth2...
	# This setting may confuse program to get real adapter name from reading /proc/cat/dev
	GrubCmdLine=$(grep "GRUB_CMDLINE_LINUX" /etc/default/grub | grep -v "#" | grep "net.ifnames=0\|biosdevname=0")
	# So we need to comfirm whether adapter name is renamed and whether we should inherit it into new system.
	[[ -n "$interfaceSelect" ]] && {
		interface="$interfaceSelect"
		interface4="$interface"
		interface6="$interface"
	}
	if [[ -n "$GrubCmdLine" && -z "$interfaceSelect" ]] || [[ "$interface4" =~ "eth" ]] || [[ "$interface6" =~ "eth" ]] || [[ "$linux_relese" == 'alpinelinux' ]]; then
		setInterfaceName='1'
	fi
	[[ -z "$tmpDHCP" ]] && {
		if [[ "$1" == 'CentOS' || "$1" == 'AlmaLinux' || "$1" == 'RockyLinux' || "$1" == 'Fedora' || "$1" == 'Vzlinux' || "$1" == 'OracleLinux' || "$1" == 'OpenCloudOS' || "$1" == 'AlibabaCloudLinux' || "$1" == 'ScientificLinux' || "$1" == 'AmazonLinux' || "$1" == 'RedHatEnterpriseLinux' || "$1" == 'OpenAnolis' || "$1" == 'CloudLinux' ]]; then
			[[ ! $(find / -maxdepth 5 -path /*network-scripts -type d -print -or -path /*system-connections -type d -print) ]] && {
				echo -ne "\n[${red}Error${plain}] Invalid network configuration!\n"
				exit 1
			}
			NetCfgWhole=()
			tmpNetCfgFiles=""
			for Count in $(find / -maxdepth 5 -path /*network-scripts -type d -print -or -path /*system-connections -type d -print); do
				NetCfgDir="$Count""/"
				# If "NetworkManager" replaced "network-scripts", there is a file called "readme-ifcfg-rh.txt" in dir: /etc/sysconfig/network-scripts/
				# NetCfgFile=`ls -Sl $NetCfgDir 2>/dev/null | awk -F' ' '{print $NF}' | grep -iv 'lo\|sit\|stf\|gif\|dummy\|vmnet\|vir\|gre\|ipip\|ppp\|bond\|tun\|tap\|ip6gre\|ip6tnl\|teql\|ocserv\|vpn\|readme' | grep -s "$interface" | head -n 1`
				# Only filter files similar as "lo.nmconnections".
				# Condition of "grep -iv 'lo\|sit\|stf..." has been deperated because the config file name of "NetworkManager" which initiated by "cloud init" is like "cloud-init-eth0.nmconnection".
				# Different from command "grep", command "ls" can only show file name but not full file direction.
				# There are 3 files named "ifcfg-ens18  ifcfg-eth0  ifcfg-eth1" in dir "/etc/sysconfig/network-scripts/" of Almalinux 8 of Bandwagonhosts template.
				# We should select the correct one by adjust whether includes interface name and file size.
				# Files in "/etc/sysconfig/network-scripts/", reference: https://zetawiki.com/wiki/%EB%B6%84%EB%A5%98:/etc/sysconfig/network-scripts
				NetCfgFiles=$(ls -Sl $NetCfgDir 2>/dev/null | grep -v '^total ' | awk -F' ' '{print $NF}' | grep -iv 'readme-\|ifcfg-lo\|ifcfg-bond\|ifup\|ifdown\|vpn\|init.ipv6-global\|network-functions\|lo\.' | grep -s "ifcfg\|nmconnection")
				for Files in $NetCfgFiles; do
					if [[ $(grep -w "$interface4\|$interface6" "$NetCfgDir$Files") != "" ]]; then
						tmpNetCfgFiles+=$(echo -e "\n""$NetCfgDir$Files")
					fi
				done
				getLargestOrSmallestFile "$tmpNetCfgFiles" "sort -hr"
				NetCfgFile="$FileName"
				# In Google Cloud Platform, network configuration files of Redhat Enterprise 8+, CentOS-stream 8+, RockyLinux 8+ are all named " 'Wired connection 1.nmconnection' " in "/run/NetworkManager/system-connections/" direction.
				# Yes, that's right, the name of this file includes spaces and two single quotes which are in the first and last.
				# Only command "ls" can show the whole file name:
				#
				# [root@instance-2 ~]# ls -l /run/NetworkManager/system-connections/
				# total 4
				# -rw-------. 1 root root 270 May  4 22:15 'Wired connection 1.nmconnection'
				#
				# Many commands in linux can't handle these son of bitches because single quote is a strong reference so that the strings between two single quotes can't be any parameters.
				# The most typical case is when you search these fuckin files by "grub", the result deleted two single quotes automatically like:
				#
				# [root@instance-2 ~]# grep -r "ipv4" /run/NetworkManager/system-connections/
				# /run/NetworkManager/system-connections/Wired connection 1.nmconnection:[ipv4]
				#
				# When we try to use command "head" and "tail" to be pipeline items after the first command "ls", the result is also the same:
				#
				# [root@instance-2 ~]# ls /run/NetworkManager/system-connections/ | head -n 1 | tail -n 1
				# Wired connection 1.nmconnection
				#
				# A file name includes space is very dangerous in linux because the operating system will use a couple of single quotes to bundle it as a "not be referenced" file to prevent os identify them error.
				# No matter what command you choice, unless attach its' absolute direction and execute it with other commands directly in the shell, it can work correctly, otherwise you wanna be cried when handle them by parameters transactions.
				# We should use "grep" to extract which key words we need and print the result to another file.
				# If this universe has hell, those jackass  who deployed these tortured settings of OS templates works on Google Cloud Platform will go to there when they died.
				if [[ ! -z "$NetCfgFile" && ! -f "$NetCfgDir$NetCfgFile" ]]; then
					tmpNetcfgDir="/root/tmp/installNetcfgCollections/"
					[[ ! -d "$tmpNetcfgDir" ]] && mkdir -p "$tmpNetcfgDir"
					if [[ "$NetCfgFile" =~ "nmconnection" ]]; then
						NetCfgFile="$interface.nmconnection"
						grep -wr "$interface\|\[ipv4\]\|\[ipv6\]\|\[connection\]\|\[ethernet\]\|id=*\|interface-name=*\|type=*\|method=*" "$NetCfgDir" | cut -d ':' -f 2 | tee -a "$tmpNetcfgDir$NetCfgFile"
						NetCfgDir="$tmpNetcfgDir"
					elif [[ "$NetCfgFile" =~ "ifcfg" ]]; then
						NetCfgFile="$ifcfg-$interface"
						grep -wr "$interface\|BOOTPROTO=*\|DEVICE=*\|ONBOOT=*\|TYPE=*\|HWADDR=*\|IPV6_AUTOCONF=*\|DHCPV6C=*" "$NetCfgDir" | cut -d ':' -f 2 | tee -a "$tmpNetcfgDir$NetCfgFile"
						NetCfgDir="$tmpNetcfgDir"
					fi
				fi
				# The following conditions must appeared at least 3 times in a vaild network config file.
				[[ $(grep -wcs "$interface4\|$interface6\|BOOTPROTO=*\|DEVICE=*\|ONBOOT=*\|TYPE=*\|HWADDR=*\|id=*\|\[connection\]\|interface-name=*\|type=*\|method=*" $NetCfgDir$NetCfgFile) -ge "3" ]] && {
					# In AlmaLinux 9 template of DigitalOcean, network adapter name is "eth0", there are two network config files in the OS, and they all belong to "eth0".
					# /etc/sysconfig/network-scripts/ifcfg-eth0
					# /etc/NetworkManager/system-connections/eth0.nmconnection
					# Which is the vaild one? We can storage them to one array first.
					NetCfgWhole+=("$NetCfgDir$NetCfgFile")
				}
			done
			# If index "1"(starts in "0") is not empty, it means there at least two network config files in current OS.
			if [[ "${NetCfgWhole[1]}" != "" ]]; then
				for c in "${NetCfgWhole[@]}"; do
					# Cloud providers usually use automatic tools like SolusVM or Cloud-init etc. to initial different Linux OS.
					# The first row of the network config files is showed like the following example regularly:
					# # Generated by SolusVM
					# # Created by cloud-init on instance boot automatically, do not edit.
					# So the "#" and preposition "(did something) by (who)" is a obvious hint to help us to distinguish:
					[[ $(sed -e "4"p "$c" | grep " by " | grep -c "#") -ge "1" ]] && {
						NetCfgWhole="$c"
						break
					}
				done
				# If the array of "${NetCfgWhole}" doesn't be turned into a parameter, it means there are not any annotates generated by automatic tools.
				# We need to import command "declare" to make an inspection to comfirm whether it's an array or a parameter,
				# If it's still an arrary, we can only assume the index "0" in this array as the valid network config file.
				[[ $(declare -p NetCfgWhole 2>/dev/null | grep -iw '^declare -a') ]] && {
					NetCfgWhole="${NetCfgWhole[0]}"
				}
			fi
			splitDirAndFile "$NetCfgWhole"
			NetCfgFile="$FileName"
			NetCfgDir="$FileDirection"
		else
			readNetplan=$(find $(echo $(find / -maxdepth 4 -path /*netplan)) -maxdepth 1 -name "*.yaml" -print)
			readIfupdown=$(find / -maxdepth 5 -path /*network -type d -print | grep -v "lib\|systemd")
			if [[ ! -z "$readNetplan" ]]; then
				# Ubuntu 18+ network configuration
				networkManagerType="netplan"
				tmpNetCfgFiles=""
				for Count in $readNetplan; do
					tmpNetCfgFiles+=$(echo -e "\n"$(grep -wrl "network" | grep -wrl "ethernets" | grep -wrl "$interface4\|$interface6" "$Count" 2>/dev/null))
				done
				getLargestOrSmallestFile "$tmpNetCfgFiles" "sort -hr"
				NetCfgFile="$FileName"
				NetCfgDir="$FileDirection"
				NetCfgWhole="$NetCfgDir$NetCfgFile"
			elif [[ ! -z "$readIfupdown" ]]; then
				# Debian/AlpineLinux network configuration
				# Some versions of Ubuntu 18 like virmach template use ifupdown not netplan.
				networkManagerType="ifupdown"
				# Collect all eligible config files by the several parent directions names "network".
				# Reference: https://wiki.debian.org/NetworkConfiguration
				#            https://wiki.debian.org/IPv6PrefixDelegation
				tmpNetCfgFiles=""
				for Count in $readIfupdown; do
					if [[ "$IPStackType" == "IPv4Stack" ]]; then
						NetCfgFiles=$(timeout 4s grep -wrl 'iface' | grep -wrl "auto\|dhcp\|static\|manual" | grep -wrl 'inet\|ip addr\|ip route' "$Count""/" 2>/dev/null | grep -v "if-*" | grep -v "state" | grep -v "helper" | grep -v "template")
					elif [[ "$IPStackType" == "BiStack" ]] || [[ "$IPStackType" == "IPv6Stack" ]]; then
						NetCfgFiles=$(timeout 4s grep -wrl 'iface' | grep -wrl "auto\|dhcp\|static\|manual" | grep -wrl 'inet\|ip addr\|ip route\|inet6\|ip -6' "$Count""/" 2>/dev/null | grep -v "if-*" | grep -v "state" | grep -v "helper" | grep -v "template")
					fi
					for Files in $NetCfgFiles; do
						if [[ $(timeout 4s grep -w "$interface4\|$interface6" "$Files") != "" ]]; then
							tmpNetCfgFiles+=$(echo -e "\n""$Files")
						fi
					done
				done
				getLargestOrSmallestFile "$tmpNetCfgFiles" "sort -hr"
				NetCfgFile="$FileName"
				NetCfgDir="$FileDirection"
				NetCfgWhole="$NetCfgDir$NetCfgFile"
			else
				echo -ne "\n[${red}Error${plain}] Invalid network configuration!\n"
				exit 1
			fi
		fi
	}
}

# $1 is "$ipMask", $2 is "$ip6Mask". Can only accept prefix number transmit.
function acceptIPv4AndIPv6SubnetValue() {
	[[ -n "$1" ]] && {
		if [[ $(echo "$1" | grep '^[[:digit:]]*$') && "$1" -ge "1" && "$1" -le "32" ]]; then
			ipPrefix="$1"
			actualIp4Prefix="$ipPrefix"
			ipMask=$(netmask "$1")
			actualIp4Subnet=$(netmask "$1")
		else
			echo -ne "\n[${red}Warning${plain}] Only accept prefix format of IPv4 address, length from 1 to 32."
			echo -ne "\nIPv4 CIDR Calculator: https://www.vultr.com/resources/subnet-calculator/\n"
			exit 1
		fi
	}
	[[ -n "$2" ]] && {
		if [[ $(echo "$2" | grep '^[[:digit:]]*$') && "$2" -ge "1" && "$2" -le "128" ]]; then
			actualIp6Prefix="$2"
			ipv6SubnetCalc "$2"
		else
			echo -ne "\n[${red}Warning${plain}] Only accept prefix format of IPv6 address, length from 1 to 128."
			echo -ne "\nIPv6 CIDR Calculator: https://en.rakko.tools/tools/27/\n"
			exit 1
		fi
	}
}

# To confuse whether ipv4 is dhcp or static and whether ipv6 is dhcp or static in Redhat like os in version 9 and later,
# $1 is $NetCfgDir, $2 is $NetCfgFile, $3 is "ipv4" or "ipv6", $4 is "method="
function checkIpv4OrIpv6ConfigForRedhat9Later() {
	IpTypeLine="$(awk '/\['$3'\]/{print NR}' $1/$2 | head -n 2 | tail -n 1)"
	ConnectTypeArray=()
	CtaSpace=()
	for tmpConnectType in $(awk '/'$4'/{print NR}' $1/$2); do
		ConnectTypeArray+=("$tmpConnectType" "$ConnectTypeArray")
		[[ $(expr $tmpConnectType - $IpTypeLine) -gt "0" ]] && CtaSpace+=($(expr "$tmpConnectType" - "$IpTypeLine") "$CtaSpace")
	done
	minArray=${CtaSpace[0]}
	for ((i = 1; i <= $(grep -io "$4" $1/$2 | wc -l); i++)); do
		for j in ${CtaSpace[@]}; do
			[[ "$minArray" -gt "$j" ]] && minArray=$j
		done
	done
	NetCfgLineNum=$(expr $minArray + $IpTypeLine)
}

# If original system using DHCP, skip IP address, subnet mask, gateway, DNS server settings manually.
# In many DHCP servers, manual settings may cause some additional problems.
# For example, in Hetzner's machine, the network configuration of official template is DHCP for IPv4, STATIC for IPv6,
# If we config both IPv4 and IPv6 as STATIC, IPv4 network will failure, even though according to the bullshit network config guide which provided by Hetzner:
# https://docs.hetzner.com/cloud/servers/static-configuration/
# So we need to distinguish whether IPv4 is DHCP or STATIC and whether IPv6 is DHCP or STATIC separately and clearly.

# $1 is $CurrentOS, $2 is $CurrentOSVer, $3 is $IPStackType
function checkDHCP() {
	getInterface "$1"
	IPv4DhcpStatus=$(ip -4 -o addr show dev $interface4 | grep -w "inet" | grep -wv "lo\|host" | grep -w "scope global*\|link*" | grep -i "dynamic" | head -n1)
	# IPv6 DHCPv6 can’t be reliably by detecting via `ip -6 addr show`: the `dynamic` flag is common for SLAAC/temporary privacy addresses,
	# and many networks use SLAAC for addressing while DHCPv6 only provides options (e.g., DNS), so the presence of an IPv6 address doesn’t prove DHCPv6 is in use.
	IPv6DhcpStatus=$(ss -uapn 2>/dev/null | grep -w $interface6 | awk '/:546[[:space:]]/{print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | head -n1)
	[[ -z "$tmpDHCP" ]] && {
		if [[ "$1" == 'CentOS' || "$1" == 'AlmaLinux' || "$1" == 'RockyLinux' || "$1" == 'Fedora' || "$1" == 'Vzlinux' || "$1" == 'OracleLinux' || "$1" == 'OpenCloudOS' || "$1" == 'AlibabaCloudLinux' || "$1" == 'ScientificLinux' || "$1" == 'AmazonLinux' || "$1" == 'RedHatEnterpriseLinux' || "$1" == 'OpenAnolis' || "$1" == 'CloudLinux' ]]; then
			# RedHat like linux system 8 and before network config name is "ifcfg-interface", deposited in /etc/sysconfig/network-scripts/
			# RedHat like linux system 9 and later network config name is "interface.nmconnection", deposited in /etc/NetworkManager/system-connections/
			# In some templates like RockyLinux 9 x64 of DigitalOcean, both "/etc/sysconfig/network-scripts/ifcfg-eth0" and "/etc/NetworkManager/system-connections/ens3.nmconnection" are existed.
			# in "ifcfg-eth0", BOOTPROTO=none; in "ens3.nmconnection", [ipv4] method=auto. the actually network adapter is "eth0", so the vaild network config file name is "ifcfg-eth0".
			# So we need to check the type of the network configuration file to determine whether the method of config is dhcp or static.
			if [[ "$NetCfgFile" =~ "ifcfg" ]]; then
				# "BOOTPROTO=dhcp" is for IPv4 DHCP, "=none" or "=static" is Static.
				# "IPv6_AUTOCONf=yes" or "DHCPV6C=yes" is IPv6 DHCP, "=no" is IPv6 Static.
				# For IPv6 STATIC configuration, "IPv6_AUTOCONf=no" or "DHCPV6C=no" doesn't exist is allowed.
				# For IPv6 DHCP configuration, "IPv6_AUTOCONf=yes" or "DHCPV6C=yes" is necessary.
				# Reference: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s1-networkscripts-interfaces
				if [[ "$3" == "IPv4Stack" ]]; then
					Network6Config="isDHCP"
					[[ -n $(timeout 4s grep -Ewirn "BOOTPROTO=none|BOOTPROTO=\"none\"|BOOTPROTO=\'none\'|BOOTPROTO=NONE|BOOTPROTO=\"NONE\"|BOOTPROTO=\'NONE\'|BOOTPROTO=static|BOOTPROTO=\"static\"|BOOTPROTO=\'static\'|BOOTPROTO=STATIC|BOOTPROTO=\"STATIC\"|BOOTPROTO=\'STATIC\'" $NetCfgWhole) ]] && Network4Config="isStatic" || Network4Config="isDHCP"
				elif [[ "$3" == "BiStack" ]]; then
					[[ -n $(timeout 4s grep -Ewirn "BOOTPROTO=none|BOOTPROTO=\"none\"|BOOTPROTO=\'none\'|BOOTPROTO=NONE|BOOTPROTO=\"NONE\"|BOOTPROTO=\'NONE\'|BOOTPROTO=static|BOOTPROTO=\"static\"|BOOTPROTO=\'static\'|BOOTPROTO=STATIC|BOOTPROTO=\"STATIC\"|BOOTPROTO=\'STATIC\'" $NetCfgWhole) ]] && Network4Config="isStatic" || Network4Config="isDHCP"
					[[ -n $(timeout 4s grep -Ewirn "IPV6_AUTOCONF=yes|IPV6_AUTOCONF=\"yes\"|IPV6_AUTOCONF=YES|IPV6_AUTOCONF=\"YES\"|DHCPV6C=yes|DHCPV6C=\"yes\"" $NetCfgWhole) ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				elif [[ "$3" == "IPv6Stack" ]]; then
					Network4Config="isDHCP"
					[[ -n $(timeout 4s grep -Ewirn "IPV6_AUTOCONF=yes|IPV6_AUTOCONF=\"yes\"|IPV6_AUTOCONF=YES|IPV6_AUTOCONF=\"YES\"|DHCPV6C=yes|DHCPV6C=\"yes\"" $NetCfgWhole) ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				fi
			elif [[ "$NetCfgFile" =~ "nmconnection" ]]; then
				# In NetworkManager for Redhat 9 and later, IPv4 and IPv6 share the same config method and value like the following sample:
				#
				# [ethernet]
				#
				# [ipv4]
				# method=auto
				#
				# [ipv6]
				# addr-gen-mode=eui64
				# method=auto
				#
				# So we need to import the function "checkIpv4OrIpv6ConfigForRedhat9Later" to confuse.
				# which "method=auto or manual" is belonged to [ipv4], which "method=auto or manual" is belonged to [ipv6].
				checkIpv4OrIpv6ConfigForRedhat9Later "$NetCfgDir" "$NetCfgFile" "ipv4" "method="
				NetCfg4LineNum="$NetCfgLineNum"
				checkIpv4OrIpv6ConfigForRedhat9Later "$NetCfgDir" "$NetCfgFile" "ipv6" "method="
				NetCfg6LineNum="$NetCfgLineNum"
				if [[ "$3" == "IPv4Stack" ]]; then
					Network6Config="isDHCP"
					[[ $(timeout 4s sed -n "$NetCfg4LineNum"p $NetCfgWhole) == "method=auto" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
				elif [[ "$3" == "BiStack" ]]; then
					[[ $(timeout 4s sed -n "$NetCfg4LineNum"p $NetCfgWhole) == "method=auto" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
					[[ $(timeout 4s sed -n "$NetCfg6LineNum"p $NetCfgWhole) == "method=auto" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				elif [[ "$3" == "IPv6Stack" ]]; then
					Network4Config="isDHCP"
					[[ $(timeout 4s sed -n "$NetCfg6LineNum"p $NetCfgWhole) == "method=auto" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				fi
			fi
		elif [[ "$1" == 'Debian' ]] || [[ "$1" == 'Kali' ]] || [[ "$1" == 'Ubuntu' ]] || [[ "$1" == 'AlpineLinux' ]]; then
			if [[ "$networkManagerType" == "ifupdown" ]]; then
				# Debian network configs may be deposited in the following directions.
				# /etc/network/interfaces or /etc/network/interfaces.d/interface or /run/network/interfaces.d/interface
				if [[ "$3" == "IPv4Stack" ]]; then
					Network6Config="isDHCP"
					[[ $(timeout 4s grep -iw "iface" $NetCfgWhole | grep -iw "$interface4" | grep -iw "inet" | grep -ic "auto\|dhcp") -ge "1" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
				elif [[ "$3" == "BiStack" ]]; then
					[[ $(timeout 4s grep -iw "iface" $NetCfgWhole | grep -iw "$interface4" | grep -iw "inet" | grep -ic "auto\|dhcp") -ge "1" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
					[[ $(timeout 4s grep -iw "iface" $NetCfgWhole | grep -iw "$interface6" | grep -iw "inet6" | grep -ic "auto\|dhcp") -ge "1" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				elif [[ "$3" == "IPv6Stack" ]]; then
					Network4Config="isDHCP"
					[[ $(timeout 4s grep -iw "iface" $NetCfgWhole | grep -iw "$interface6" | grep -iw "inet6" | grep -ic "auto\|dhcp") -ge "1" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				fi
				# Configure method in OVH can't boot with dhcp.
				[[ -n $(timeout 4s grep "accept_ra" $NetCfgWhole) ]] && {
					Network4Config="isStatic"
					Network6Config="isStatic"
				}
			elif [[ "$networkManagerType" == "netplan" ]]; then
				# For netplan(Ubuntu 18 and later), if network configuration is Static whether IPv4 or IPv6.
				# in "*.yaml" config file, dhcp(4 or 6): no or false doesn't exist is allowed.
				# But if is DHCP, dhcp(4 or 6): yes or true is necessary.
				# Typical format of dhcp status in "*.yaml" is "dhcp4/6: true/false" or "dhcp4/6: yes/no".
				# The raw sample processed by function "parseYaml" is: " network_ethernets_enp1s0_dhcp4="true" network_ethernets_enp1s0_dhcp6="true" ".
				[[ ! -z "$NetCfgWhole" ]] && {
					dhcp4Status=$(parseYaml "$NetCfgWhole" | grep "$interface4" | grep "dhcp")
					dhcp6Status=$(parseYaml "$NetCfgWhole" | grep "$interface6" | grep "dhcp")
				}
				if [[ "$3" == "IPv4Stack" ]]; then
					Network6Config="isDHCP"
					[[ "$dhcp4Status" =~ "dhcp4=\"true\"" || "$dhcp4Status" =~ "dhcp4=\"yes\"" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
				elif [[ "$3" == "BiStack" ]]; then
					[[ "$dhcp4Status" =~ "dhcp4=\"true\"" || "$dhcp4Status" =~ "dhcp4=\"yes\"" ]] && Network4Config="isDHCP" || Network4Config="isStatic"
					[[ "$dhcp6Status" =~ "dhcp6=\"true\"" || "$dhcp6Status" =~ "dhcp6=\"yes\"" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				elif [[ "$3" == "IPv6Stack" ]]; then
					Network4Config="isDHCP"
					[[ "$dhcp6Status" =~ "dhcp6=\"true\"" || "$dhcp6Status" =~ "dhcp6=\"yes\"" ]] && Network6Config="isDHCP" || Network6Config="isStatic"
				fi
			fi
		fi
		rm -rf "$tmpNetcfgDir"
	}
	[[ -z "$IPv4DhcpStatus" ]] && Network4Config="isStatic"
	[[ -z "$IPv6DhcpStatus" ]] && Network6Config="isStatic"
	[[ "$Network4Config" == "" ]] && Network4Config="isStatic"
	[[ "$Network6Config" == "" ]] && Network6Config="isStatic"
}

# $1 is "$tmpDHCP", $2 is "$virtWhat", $3 is "$virtType".
# For GCP, network config method for netboot kernel must be static.
# In official template of Debian 10-11, Ubuntu 20.04-22.04 of GCP, the result of "virt-what" can only be shown as "kvm", so we need to figure out the actual manufacturer from both "$virtWhat" and "$virtType".
function setDhcpOrStatic() {
	[[ "$1" == "dhcp" || "$1" == "auto" || "$1" == "automatic" || "$1" == "true" || "$1" == "yes" || "$1" == "1" ]] && {
		Network4Config="isDHCP"
		Network6Config="isDHCP"
	}
	[[ "$1" == "static" || "$1" == "manual" || "$1" == "none" || "$1" == "false" || "$1" == "no" || "$1" == "0" || -n $(echo $2 $3 | grep -io 'google') ]] && {
		Network4Config="isStatic"
		Network6Config="isStatic"
	}
}

# $1 is "in-target", $2 is "/etc/network/interfaces", $3 is "/etc/sysctl.d/99-sysctl.conf".
function DebianModifiedPreseed() {
	if [[ "$linux_relese" == 'debian' ]]; then
		# Must use ";" instead of using "&&", "echo -e" etc to combine multiple commands, or write text in files, recommend sed.
		# Can't pass parameters correctly in preseed environment.
		# DebianVimVer=`ls -a /usr/share/vim | grep vim[0-9]`
		if [[ "$DebianDistNum" -ge "9" && "$DebianDistNum" -le "11" ]]; then
			DebianVimVer="vim"$(expr ${DebianDistNum} + 71)
		elif [[ "$DebianDistNum" -ge "12" ]]; then
			DebianVimVer="vim"$(expr ${DebianDistNum} + 78)
		else
			DebianVimVer=""
		fi
		# Set parameter "mouse-=a" in /usr/share/vim/vim-version/defaults.vim to support copy text from terminal to client.
		VimSupportCopy="$1 sed -i 's/set mouse=a/set mouse-=a/g' /usr/share/vim/${DebianVimVer}/defaults.vim;"
		# Enable cursor edit backspace freely in insert mode.
		# Reference: https://wonderwall.hatenablog.com/entry/2016/03/23/232634
		VimIndentEolStart="$1 sed -i 's/set compatible/set nocompatible/g' /etc/vim/vimrc.tiny; $1 sed -i '/set nocompatible/a\set backspace=2' /etc/vim/vimrc.tiny;"
		[[ "$DebianVimVer" == "" ]] && {
			VimSupportCopy=""
			VimIndentEolStart=""
		}
		# Fail2ban configurations.
		# Reference: https://github.com/fail2ban/fail2ban/issues/2756
		#            https://www.mail-archive.com/debian-bugs-dist@lists.debian.org/msg1879390.html
		[[ "$setFail2banStatus" == "1" ]] && {
			EnableFail2ban="$1 sed -i '/^\[Definition\]/a allowipv6 = auto' /etc/fail2ban/fail2ban.conf; $1 sed -ri 's/^backend = auto/backend = systemd/g' /etc/fail2ban/jail.conf; $1 update-rc.d fail2ban enable; $1 /etc/init.d/fail2ban restart;"
			fail2banComponent="fail2ban"
		}
		AptUpdating="$1 apt update -y;"
		# pre-install some commonly used software.
		InstallComponents="$1 apt install apt-transport-https ca-certificates cron curl dnsutils dpkg ${fail2banComponent} file lrzsz lsb-release net-tools sudo vim wget -y;"
		# In Debian 9 and former, some certificates are expired.
		DisableCertExpiredCheck="$1 sed -i '/^mozilla\/DST_Root_CA_X3/s/^/!/' /etc/ca-certificates.conf; $1 update-ca-certificates -f;"
        # Use the installed distribution's own shell defaults, not a remote .bashrc.
        ChangeBashrc="$1 cp -f /etc/skel/.bashrc /root/.bashrc;"
        ModifyMOTD=""
        DnsChangePermanently=""
        if [[ "$setDns" == "1" ]]; then
            DnsChangePermanently="$1 mkdir -p /etc/resolvconf/resolv.conf.d; $1 touch /etc/resolvconf/resolv.conf.d/head;"
            local ns
            for ns in $ipDNS $ip6DNS; do
                [[ "$ns" =~ ^[0-9a-fA-F:.]+$ ]] || continue
                DnsChangePermanently+=" $1 sed -i '\$anameserver $ns' /etc/resolvconf/resolv.conf.d/head;"
            done
            DnsChangePermanently+=" $1 env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install resolvconf;"
        fi
		# For multiple interfaces environment, if the interface which is configurated by "auto", regardless of it is plugged by internet cable,
		# Debian will continuously try to wake and start up it contains with dhcp even timeout.
		# Set up with "allow-hotplug(default setting by Debian installer)" will skip this problem, but if one interface has more than 1 IP or it will connect to
		# another network bridge, when system restarted, the interfaces' initialization will be failed, in most of VPS environments, the interfaces of machine should be stable,
		# so replace the default from "allow-hotplug" to "auto" for interfaces config method is a better idea?
		[[ "$autoPlugAdapter" == "1" ]] && AutoPlugInterfaces="$1 sed -ri \"s/allow-hotplug $interface4/auto $interface4/g\" $2; $1 sed -ri \"s/allow-hotplug $interface6/auto $interface6/g\" $2;" || AutoPlugInterfaces=""
		# If the network config type of server is DHCP and it have both public IPv4 and IPv6 address,
		# Debian install program even get nerwork config with DHCP, but after log into new system,
		# only the IPv4 of the server has been configurated.
		# so need to write "iface interface inet6 dhcp" to /etc/network/interfaces in preseeding process for Bi-stack machine,
		# to avoid config IPv6 manually after log into new system.
		SupportIPv6orIPv4=""
		ReplaceActualIpPrefix=""
		PreferIPv4Access="$1 sed -i '\$aprecedence ::ffff:0:0/96  100' /etc/gai.conf;"
		if [[ "$IPStackType" == "IPv4Stack" ]]; then
			[[ "$BurnIrregularIpv4Status" == "1" ]] && BurnIrregularIpv4Gate="$1 sed -i '\$a\\\tgateway $actualIp4Gate' $2;"
			# This IPv4Stack machine should be setting as IPv4 network accessing priority.
			SupportIPv6orIPv4="$PreferIPv4Access"
			ReplaceActualIpPrefix="$1 sed -ri \"s/address $ipAddr\/$ipPrefix/address $ipAddr\/$actualIp4Prefix/g\" $2;"
			[[ "$iAddrNum" -ge "2" ]] && {
				writeMultipleIpv4Addresses "$iAddrNum" "$1" ''$2''
				SupportIPv6orIPv4="$SupportMultipleIPv4 $PreferIPv4Access"
			}
		elif [[ "$IPStackType" == "BiStack" ]]; then
			# Enable IPv4 dhcp or static configurations.
			if [[ "$BiStackPreferIpv6Status" == "1" ]]; then
				if [[ "$Network4Config" == "isDHCP" ]]; then
					SupportIPv6orIPv4="$1 sed -i '\$aiface $interface inet dhcp' $2;"
					[[ -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && SupportIPv6orIPv4="$1 sed -i '\$a\ ' $2; $1 sed -i '\$aallow-hotplug $interface4' $2; $1 sed -i '\$aiface $interface4 inet dhcp' $2;"
					ReplaceActualIpPrefix="$1 sed -ri \"s/address $ip6Addr\/$ip6Mask/address $ip6Addr\/$actualIp6Prefix/g\" $2;"
				elif [[ "$Network4Config" == "isStatic" ]]; then
					SupportIPv6orIPv4="$1 sed -i '\$aiface $interface inet static' $2; $1 sed -i '\$a\\\taddress $ipAddr' $2; $1 sed -i '\$a\\\tnetmask $MASK' $2; $1 sed -i '\$a\\\tgateway $GATE' $2; $1 sed -i '\$a\\\tdns-nameservers $ipDNS' $2;"
					[[ -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && SupportIPv6orIPv4="$1 sed -i '\$a\ ' $2; $1 sed -i '\$aallow-hotplug $interface4' $2; $1 sed -i '\$aiface $interface4 inet static' $2; $1 sed -i '\$a\\\taddress $ipAddr' $2; $1 sed -i '\$a\\\tnetmask $MASK' $2; $1 sed -i '\$a\\\tgateway $GATE' $2; $1 sed -i '\$a\\\tdns-nameservers $ipDNS' $2;"
					ReplaceActualIpPrefix="$1 sed -ri \"s/address $ip6Addr\/$ip6Mask/address $ip6Addr\/$actualIp6Prefix/g\" $2; $1 sed -ri \"s/netmask $MASK/netmask $actualIp4Subnet/g\" $2;"
				fi
			else
				[[ "$BurnIrregularIpv4Status" == "1" ]] && BurnIrregularIpv4Gate="$1 sed -i '\$a\\\tgateway $actualIp4Gate' $2;"
				if [[ "$Network6Config" == "isDHCP" ]]; then
					SupportIPv6orIPv4="$1 sed -i '\$aiface $interface inet6 dhcp' $2;"
					[[ -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && SupportIPv6orIPv4="$1 sed -i '\$a\ ' $2; $1 sed -i '\$aallow-hotplug $interface6' $2; $1 sed -i '\$aiface $interface6 inet6 dhcp' $2;"
					ReplaceActualIpPrefix="$1 sed -ri \"s/address $ipAddr\/$ipPrefix/address $ipAddr\/$actualIp4Prefix/g\" $2;"
				elif [[ "$Network6Config" == "isStatic" ]]; then
					SupportIPv6orIPv4="$1 sed -i '\$aiface $interface inet6 static' $2; $1 sed -i '\$a\\\taddress $ip6Addr' $2; $1 sed -i '\$a\\\tnetmask $ip6Mask' $2; $1 sed -i '\$a\\\tgateway $ip6Gate' $2; $1 sed -i '\$a\\\tdns-nameservers $ip6DNS' $2;"
					[[ -n "$interface4" && -n "$interface6" && "$interface4" != "$interface6" ]] && SupportIPv6orIPv4="$1 sed -i '\$a\ ' $2; $1 sed -i '\$aallow-hotplug $interface6' $2; $1 sed -i '\$aiface $interface6 inet6 static' $2; $1 sed -i '\$a\\\taddress $ip6Addr' $2; $1 sed -i '\$a\\\tnetmask $ip6Mask' $2; $1 sed -i '\$a\\\tgateway $ip6Gate' $2; $1 sed -i '\$a\\\tdns-nameservers $ip6DNS' $2;"
					ReplaceActualIpPrefix="$1 sed -ri \"s/address $ipAddr\/$ipPrefix/address $ipAddr\/$actualIp4Prefix/g\" $2; $1 sed -ri \"s/netmask $ip6Mask/netmask $actualIp6Prefix/g\" $2;"
				fi
			fi
			[[ "$iAddrNum" -ge "2" || "$i6AddrNum" -ge "2" ]] && {
				writeMultipleIpv4Addresses "$iAddrNum" "$1" ''$2''
				writeMultipleIpv6Addresses "$i6AddrNum" "$1" ''$2''
				if [[ "$iAddrNum" == "1" || "$i6AddrNum" == "1" ]]; then
					SupportIPv6orIPv4="$SupportMultipleIPv4 $SupportMultipleIPv6 $SupportIPv6orIPv4"
				else
					SupportIPv6orIPv4="$SupportMultipleIPv4 $SupportMultipleIPv6"
				fi
			}
		elif [[ "$IPStackType" == "IPv6Stack" ]]; then
			[[ "$BurnIrregularIpv6Status" == "1" ]] && BurnIrregularIpv6Gate="$1 sed -i '\$a\\\tgateway $ip6Gate' $2;"
			# This IPv6Stack machine has been setting up as IPv6 network accessing priority by default.
			ReplaceActualIpPrefix="$1 sed -ri \"s/address $ip6Addr\/$ip6Mask/address $ip6Addr\/$actualIp6Prefix/g\" $2;"
			[[ "$i6AddrNum" -ge "2" ]] && {
				writeMultipleIpv6Addresses "$i6AddrNum" "$1" ''$2''
				SupportIPv6orIPv4="$SupportMultipleIPv6"
			}
		fi
		# a typical network configuration sample of IPv6 static for Debian:
		# iface eth0 inet static
		#         address 10.0.0.72
		#         netmask 255.255.255.0
		#         gateway 10.0.0.1
		#         dns-nameservers 1.0.0.1 8.4.4.8
		#
		# a typical network configuration sample of IPv6 static for Debian:
		# iface eth0 inet6 static
		#         address 2702:b43c:492a:9d1e:8270:fd59:6de4:20f1
		#         netmask 128
		#         gateway fe80::200:17ff:fe9e:f9d0
		#         dns-nameservers 2606:4700:4700::1001 2001:4860:4860::8844
		# Write the following configs to "/etc/sysctl.d/99-sysctl.conf", including basic and general network optimization only:
		#
		# net.core.default_qdisc = fq
		# net.ipv4.tcp_congestion_control = bbr
		# net.ipv4.tcp_mtu_probing = 1
		# net.ipv4.tcp_slow_start_after_idle = 0
		#
		# "net.ipv4.tcp_syncookies" is already enabled by default.
		# To enable BBR is only suitable for Debian 11+
		[[ "$enableBBR" == "1" ]] && [[ "$DebianDistNum" -ge "11" ]] && {
			[[ "$DebianDistNum" -ge "13" ]] && {
				# Debian 13 and later has been removed the integrated file of "99-sysctl.conf" in dir "/etc/sysctl.d/".
				WriteSysctlConf="$1 touch $3;"
			} || {
				WriteSysctlConf=""
			}
			EnableBBR="$1 sed -i '\$a# --- Core: BBR + fq ---' $3; $1 sed -i '\$anet.core.default_qdisc = fq' $3; $1 sed -i '\$anet.ipv4.tcp_congestion_control = bbr' $3; $1 sed -i -e '\$a\\' -e '' $3; $1 sed -i '\$a# PMTU blackhole tolerance (common with tunnels / some WAN paths)' $3; $1 sed -i '\$anet.ipv4.tcp_mtu_probing = 1' $3; $1 sed -i -e '\$a\\' -e '' $3; $1 sed -i '\$a# avoid slow-start penalty after idle (often helps proxy patterns)' $3; $1 sed -i '\$anet.ipv4.tcp_slow_start_after_idle = 0' $3; $1 systemctl restart systemd-sysctl; $1 sed -i -e '\$a\\' -e '' $3;"
		} || {
			EnableBBR=""
		}
		# For some cloud providers which servers boot from their own grub2 bootloader first by force, not boot from grub in harddisk of our own servers directly,
		# we need to creat a soft link for grub2 from grub1 to make sure the first reboot after installation won't meet a fatal.
		# In this situation, the partition table and filesystem of the newly installed OS must be "mbr" and "ext4".
		# This case has been occurred in these cloud providers such as "app.cloudcone.com", "www.readyidc.com".
		CreateSoftLinkToGrub2FromGrub1="$1 ln -s /boot/grub/ /boot/grub2;"
		# Statement of "grub-pc/timeout" in "preseed.cfg" is only valid for BIOS.
		[[ "$EfiSupport" == "enabled" ]] && SetGrubTimeout="$1 sed -ri 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=3/g' /etc/default/grub; $1 sed -ri 's/set timeout=5/set timeout=3/g' /boot/grub/grub.cfg;" || SetGrubTimeout=""
		export DebianModifiedProcession="${AptUpdating} ${InstallComponents} ${DisableCertExpiredCheck} ${ChangeBashrc} ${VimSupportCopy} ${VimIndentEolStart} ${ModifyMOTD} ${BurnIrregularIpv4Gate} ${BurnIrregularIpv6Gate} ${SupportIPv6orIPv4} ${ReplaceActualIpPrefix} ${AutoPlugInterfaces} ${EnableFail2ban} ${WriteSysctlConf} ${EnableBBR} ${DnsChangePermanently} ${CreateSoftLinkToGrub2FromGrub1} ${SetGrubTimeout}"
	fi
}

function DebianPreseedProcess() {
	if [[ "$setAutoConfig" == "1" ]]; then
		# Debian security mirror of Tsinghua University: https://mirrors.tuna.tsinghua.edu.cn/help/debian/
		if [[ "$linux_relese" == 'debian' ]]; then
			[[ "$IsCN" == "cn" ]] && debianSecurityMirror="mirrors.tuna.tsinghua.edu.cn" || debianSecurityMirror="security.debian.org"
		fi
		# Debian linux cloud kernel only include drivers of network adapter can reduce resource usage for most virtual servers.
		# If target system need to set a raid recipe, to make sure to support more disk controllers, cloud kernel should not be installed.
		# Reference: https://docs.software-univention.de/installation-4.4.pdf
		#            https://unix.stackexchange.com/questions/639608/difference-between-debians-linux-image-cloud-amd64-and-linux-image-amd64
		addCloudKernelCmd="d-i base-installer/kernel/image string"
		if [[ "$setCloudKernel" == "" ]]; then
			[[ -n "$virtWhat" ]] && {
				[[ "$linux_relese" == 'debian' && "$DebianDistNum" -ge "11" ]] && AddCloudKernel="$addCloudKernelCmd linux-image-cloud-$VER" || AddCloudKernel=""
			}
		elif [[ "$setCloudKernel" == "1" ]]; then
			[[ "$linux_relese" == 'debian' && "$DebianDistNum" -ge "11" ]] && AddCloudKernel="$addCloudKernelCmd linux-image-cloud-$VER" || AddCloudKernel=""
		fi
		# Despite VMware and Virtualbox are some kinds of virtualizations but Cloud kernel isn't suitable for them otherwise Debian series will meet a fatal when booting into the newly installed system.
		[[ -n "$setRaid" || "$ddMode" == '1' || -n $(echo $virtWhat | grep -io 'vmware\|virtualbox') ]] && AddCloudKernel=""
		setNormalRecipe "$linux_relese" "$disksNum" "$setSwap" "$setDisk" "$partitionTable" "$setFileSystem" "$EfiSupport" "$diskCapacity" "$IncDisk" "$AllDisks"
		setRaidRecipe "$setRaid" "$disksNum" "$AllDisks" "$linux_relese"
		# Preserve the existing Debian irregular-gateway and dual-stack selection rules.
		if [[ "$BiStackPreferIpv6Status" == "1" ]]; then
			if [[ "$interfacesNum" -ge "2" ]] || [[ "$linux_relese" == 'debian' && "$DebianDistNum" -le "11" ]] || [[ "$ddMode" == '1' ]]; then
				BiStackPreferIpv6Status=""
				BurnIrregularIpv6Status=""
				BurnIrregularIpv4Status='1'
				interfaceSelect="$interface4"
			fi
		fi
		# A valid method to add an irregular gateway by force:
		# This method aims to hack IPv4 network service and add IPv4 route by force in busybox, so we need to assign "none" for "d-i netcfg/get_gateway string" to avoid Debian installer report "unreachable gateway",
		# don't forget to write IPv4 gateway back in "d-i preseed/late_command" stage.
		# Reference: https://lab.civicrm.org/infra/ops/blob/master/ansible/roles/kvm-server/templates/etc/preseeds/host/preseed.cfg
		#
		# Reserved empty variables for engineering debugging, if you are not known them well, don't uncomment with them!
		# BurnIrregularIpv4Status='1'
		# ipPrefix=""
		# MASK=""
		[[ Network4Config == "isDHCP" ]] && BurnIrregularIpv4Status='0'
		[[ "$BurnIrregularIpv4Status" == "1" ]] && {
			actualIp4Gate="$GATE"
			GATE="none"
			if [[ "$IPStackType" == "IPv4Stack" ]]; then
				writeDnsByForce='echo '\''nameserver '$ipDNS1''\'' > /etc/resolv.conf && echo '\''nameserver '$ipDNS2''\'' >> /etc/resolv.conf'
			elif [[ "$IPStackType" == "BiStack" ]]; then
				writeDnsByForce='echo '\''nameserver '$ipDNS1''\'' > /etc/resolv.conf && echo '\''nameserver '$ip6DNS1''\'' >> /etc/resolv.conf && echo '\''nameserver '$ipDNS2''\'' >> /etc/resolv.conf && echo '\''nameserver '$ip6DNS2''\'' >> /etc/resolv.conf'
			fi
			# If subnet of some machines of IPv4 config is "32"(255.255.255.255) means the intranet range is smallest, just including the server itself,
			# the "onlink" must be included in command of adding gateway(route) by force via soft hack, for example:
			#
			# ip route add default via 10.0.0.1 dev eth0 onlink
			#
			# to tell the networking service that the gateway of "10.0.0.1" will serve the device of network adapter "eth0" via "onlink" by IPv4 stack protocol
			# because "onlink" stipulates networking to establish a connection from local to gateway by "arp" directly without creating any area of intranet.
			BurnIrregularIpv4ByForce=$(echo -e 'd-i preseed/early_command string ip link set dev '$interface4' up; ip addr add '$IPv4'/'$ipPrefix' dev '$interface4'; echo "(ip route add '$actualIp4Gate' dev '$interface4' || true) && (ip route add default via '$actualIp4Gate' dev '$interface4' onlink || true) && '$writeDnsByForce'" > /bin/ethdetect; echo "(test -x /bin/ethdetect && /bin/ethdetect) || true" >> /usr/share/debconf/confmodule;')
		}
		# Prefer to use IPv4 stack to config networking.
		if [[ "$IPStackType" == "IPv4Stack" ]] || [[ "$IPStackType" == "BiStack" && "$BiStackPreferIpv6Status" != "1" ]]; then
			[[ "$Network4Config" == "isStatic" ]] && NetConfigManually=$(echo -e "d-i netcfg/disable_autoconfig boolean true\nd-i netcfg/dhcp_failed note\nd-i netcfg/dhcp_options select Configure network manually\nd-i netcfg/get_ipaddress string $IPv4\nd-i netcfg/get_netmask string $MASK\nd-i netcfg/get_gateway string $GATE\nd-i netcfg/get_nameservers string $ipDNS\nd-i netcfg/no_default_route boolean true\nd-i netcfg/confirm_static boolean true") || NetConfigManually=""
			# Prefer to use IPv6 stack to configure network because Debian 12 supports public IPv6 address with private gateway like "fe80::1" and works well,
			# if IPv4 configuration of one BiStack server has public IPv4 and private gateway like "172.31.1.1" because this case will cause Debian installer notices "unreachable gateway".
		elif [[ "$IPStackType" == "IPv6Stack" ]] || [[ "$IPStackType" == "BiStack" && "$BiStackPreferIpv6Status" == "1" ]]; then
			[[ "$Network6Config" == "isStatic" ]] && NetConfigManually=$(echo -e "d-i netcfg/disable_autoconfig boolean true\nd-i netcfg/dhcp_failed note\nd-i netcfg/dhcp_options select Configure network manually\nd-i netcfg/get_ipaddress string $ip6Addr\nd-i netcfg/get_netmask string $ip6Subnet\nd-i netcfg/get_gateway string $ip6Gate\nd-i netcfg/get_nameservers string $ip6DNS\nd-i netcfg/no_default_route boolean true\nd-i netcfg/confirm_static boolean true") || NetConfigManually=""
		fi
		# The similar principle as hacking IPv4.
		[[ "$BurnIrregularIpv6Status" == "1" ]] && {
			writeDnsByForce='echo '\''nameserver '$ip6DNS1''\'' > /etc/resolv.conf && echo '\''nameserver '$ip6DNS2''\'' >> /etc/resolv.conf'
			BurnIrregularIpv6ByForce=$(echo -e 'd-i preseed/early_command string ip link set dev '$interface6' up; ip -6 addr add '$ip6Addr'/'$actualIp6Prefix' dev '$interface6'; echo "(ip -6 route add '$ip6Gate' dev '$interface6' || true) && (ip -6 route add default via '$ip6Gate' dev '$interface6' onlink || true) && '$writeDnsByForce'" > /bin/ethdetect; echo "(test -x /bin/ethdetect && /bin/ethdetect) || true" >> /usr/share/debconf/confmodule;')
			NetConfigManually=$(echo -e "d-i netcfg/disable_autoconfig boolean true\nd-i netcfg/dhcp_failed note\nd-i netcfg/dhcp_options select Configure network manually\nd-i netcfg/get_ipaddress string $ip6Addr\nd-i netcfg/get_netmask string $ip6Subnet\nd-i netcfg/get_gateway string none\nd-i netcfg/get_nameservers string $ip6DNS\nd-i netcfg/no_default_route boolean true\nd-i netcfg/confirm_static boolean true")
		}
		# Debian installer can only identify the full IPv6 address of IPv6 mask,
		# so we need to covert IPv6 prefix shortening from "0-128" to whole IPv6 address.
		# The result of "$ip6Subnet" is calculated by function "ipv6SubnetCalc".
		#
		# Manually network setting configurations, including:
		# d-i netcfg/disable_autoconfig boolean true
		# d-i netcfg/dhcp_failed note
		# d-i netcfg/dhcp_options select Configure network manually
		# d-i netcfg/get_ipaddress string $IPv4/$ip6Addr
		# d-i netcfg/get_netmask string $MASK/$ip6Subnet
		# d-i netcfg/get_gateway string $GATE/$ip6Gate
		# d-i netcfg/get_nameservers string $ipDNS/$ip6DNS
		# d-i netcfg/no_default_route boolean true
		# d-i netcfg/confirm_static boolean true
		DebianModifiedPreseed "in-target" "/etc/network/interfaces" "/etc/sysctl.d/99-sysctl.conf"
		cat >/tmp/boot/preseed.cfg <<EOF
### Unattended Installation
d-i auto-install/enable boolean true
d-i debconf/priority select critical

### Localization
d-i debian-installer/locale string en_US.UTF-8
d-i debian-installer/country string US
d-i debian-installer/language string en
d-i debian-installer/allow_unauthenticated boolean true
d-i console-setup/layoutcode string us
d-i keyboard-configuration/xkb-keymap string us

### Low memory mode
d-i lowmem/low note

### Select security, updates and backports
d-i apt-setup/services-select multiselect security, updates

### Configure source repositories
d-i apt-setup/enable-source-repositories boolean true

### Security setup
d-i apt-setup/security_host string ${debianSecurityMirror}

### Config contrib, non-free and non-free firmware
d-i apt-setup/contrib boolean true
d-i apt-setup/non-free boolean true
d-i apt-setup/non-free-firmware boolean true

### Disable CD-rom automatic scan
d-i apt-setup/cdrom/set-first boolean false
d-i apt-setup/cdrom/set-next boolean false
d-i apt-setup/cdrom/set-failed boolean false

### Configure cloud kernel
${AddCloudKernel}

### Network configuration
d-i netcfg/choose_interface select $interfaceSelect
${NetConfigManually}
d-i hw-detect/load_firmware boolean true
${BurnIrregularIpv4ByForce}
${BurnIrregularIpv6ByForce}

### Mirror settings
d-i mirror/country string manual
d-i mirror/http/hostname string $MirrorHost
d-i mirror/http/directory string $MirrorFolder

### Account setup
d-i passwd/root-login boolean true
d-i passwd/make-user boolean false
d-i passwd/root-password-crypted password ${myPASSWORD}
d-i user-setup/allow-password-weak boolean true
d-i user-setup/encrypt-home boolean false

### Clock and time zone setup
d-i clock-setup/utc boolean true
d-i time/zone string ${TimeZone}
d-i clock-setup/ntp boolean true
d-i clock-setup/ntp-server string ntp.nict.jp

### Select target disk for Debian partitioning
d-i partman/early_command string \
lvremove --select all -ff -y; \
vgremove --select all -ff -y; \
pvremove /dev/* -ff -y; \
[[ -n "\$(blkid -t TYPE='vfat' -o device)" ]] && umount "\$(blkid -t TYPE='vfat' -o device)"; \
${PartmanEarlyCommand} \
umount /media || true; \

### Partitioning
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/device_remove_lvm_span boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
${defaultFileSystem}
d-i partman/mount_style select uuid
d-i partman-md/device_remove_md boolean true
${FormatDisk}

### Package selection
tasksel tasksel/first multiselect minimal
d-i pkgsel/include string openssh-server

# Automatic updates are not applied, everything is updated manually.
d-i pkgsel/update-policy select none
d-i pkgsel/upgrade select none

### Disable to upload developer statistics anonymously
popularity-contest popularity-contest/participate boolean false

### Grub
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string ${IncDisk}
d-i grub-installer/force-efi-extra-removable boolean true
d-i debian-installer/add-kernel-opts string net.ifnames=0 biosdevname=0 ipv6.disable=1 ${serialConsolePropertiesForGrub}
grub-pc grub-pc/hidden_timeout boolean false
grub-pc grub-pc/timeout string 3

### Shutdown machine
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true

### Write preseed
d-i preseed/late_command string	\
sed -ri 's/^#?Port.*/Port ${sshPORT}/g' /target/etc/ssh/sshd_config; \
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /target/etc/ssh/sshd_config; \
sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/g' /target/etc/ssh/sshd_config; \
echo '@reboot root cat /etc/run.sh 2>/dev/null |base64 -d >/tmp/run.sh; rm -rf /etc/run.sh; sed -i /^@reboot/d /etc/crontab; bash /tmp/run.sh' >>/target/etc/crontab; \
echo '' >>/target/etc/crontab; \
echo '${setCMD}' >/target/etc/run.sh; \
echo '${HostName}' >/target/etc/hostname; \
sed -ri 's/^127.0.1.1.*/127.0.1.1\t${HostName}/g' /target/etc/hosts; \
grep -q '^127.0.1.1' /target/etc/hosts || echo '127.0.1.1\t${HostName}' >>/target/etc/hosts; \
${DebianModifiedProcession}
EOF
	fi
}

# The parameter which be passed into the function after 10th order must be included with "{}".
function selectLocalDdAssets() {
    # All DD targets use the same known-good Alpine bridge as before.
    AlpineInitFile="${customInitFile:-$SCRIPT_DIR/ubuntuInit.sh}"
    AlpineInitFileName='ubuntuConf.start'
    if [[ "$IsCN" == "cn" ]]; then
        if [[ "$ubuntuArchitecture" == "arm64" ]]; then
            targetLinuxMirror='mirrors.tuna.tsinghua.edu.cn'
            targetLinuxSecurityMirror='mirrors.tuna.tsinghua.edu.cn'
        else
            targetLinuxMirror='mirrors.ustc.edu.cn'
            targetLinuxSecurityMirror='mirrors.ustc.edu.cn'
        fi
    else
        if [[ "$ubuntuArchitecture" == "arm64" ]]; then
            targetLinuxMirror='ports.ubuntu.com'
            targetLinuxSecurityMirror='ports.ubuntu.com'
        else
            targetLinuxMirror='archive.ubuntu.com'
            targetLinuxSecurityMirror='security.ubuntu.com'
        fi
    fi
    [[ "$setIPv6" == '0' ]] || setIPv6='1'
    local template
    case "$IPStackType" in
        IPv4Stack)
            networkAdapter="$interface4"
            case "$Network4Config" in
                isDHCP) template='dhcp_interfaces.cfg' ;;
                isStatic) template='ipv4_static_interfaces.cfg' ;;
                *) printf '[ERROR] Invalid IPv4 network mode.\n' >&2; return 1 ;;
            esac ;;
        IPv6Stack)
            networkAdapter="$interface6"
            case "$Network6Config" in
                isDHCP) template='dhcp_interfaces.cfg' ;;
                isStatic) template='ipv6_static_interfaces.cfg' ;;
                *) printf '[ERROR] Invalid IPv6 network mode.\n' >&2; return 1 ;;
            esac ;;
        BiStack)
            networkAdapter="$interface4"
            case "$Network4Config/$Network6Config" in
                isDHCP/isDHCP) template='dhcp_interfaces.cfg' ;;
                isDHCP/isStatic) template='ipv4_dhcp_ipv6_static_interfaces.cfg' ;;
                isStatic/isDHCP) template='ipv4_static_ipv6_dhcp_interfaces.cfg' ;;
                isStatic/isStatic) template='ipv4_static_ipv6_static_interfaces.cfg' ;;
                *) printf '[ERROR] Invalid dual-stack network mode.\n' >&2; return 1 ;;
            esac ;;
        *) printf '[ERROR] Unknown IP stack.\n' >&2; return 1 ;;
    esac
    cloudInitLocalFile="$SCRIPT_DIR/CloudInit/$template"
    [[ -s "$AlpineInitFile" && -r "$AlpineInitFile" && -s "$cloudInitLocalFile" ]] || {
        printf '[ERROR] Local DD initialization script/template is missing.\n' >&2
        return 1
    }
    bash -n "$AlpineInitFile" || return 1
    return 0
}

function stageLocalDdAssets() {
    # $1 is the unpacked initramfs directory, never the root of the installed OS.
    local root="$1" assetDir="$1/ddinstall-assets" ns
    [[ -d "$root" && -f "$root/init" ]] || {
        printf '[ERROR] Invalid initramfs staging directory.\n' >&2; return 1
    }
    mkdir -p "$assetDir" || return 1
    cp -f -- "$AlpineInitFile" "$assetDir/init.start" || return 1
    cp -f -- "$cloudInitLocalFile" "$assetDir/cloud-init.cfg" || return 1
    : > "$assetDir/resolv.conf" || return 1
    if [[ "$IPStackType" != 'IPv6Stack' ]]; then
        for ns in "$ipDNS1" "$ipDNS2"; do
            [[ "$ns" =~ ^[0-9.]+$ ]] && printf 'nameserver %s\n' "$ns" >> "$assetDir/resolv.conf"
        done
    fi
    if [[ "$IPStackType" != 'IPv4Stack' ]]; then
        for ns in "$ip6DNS1" "$ip6DNS2"; do
            [[ "$ns" =~ ^[0-9a-fA-F:]+$ ]] && printf 'nameserver %s\n' "$ns" >> "$assetDir/resolv.conf"
        done
    fi
    [[ -s "$assetDir/resolv.conf" ]] || { printf '[ERROR] No usable DNS server.\n' >&2; return 1; }
    # Retain the legacy two-space key/value format read by both DD scripts.
    # printf makes URLs containing '&' and other shell metacharacters inert data.
    local key value
    : > "$assetDir/alpine.config" || return 1
    for key in alpineArchitecture ubuntuArchitecture IncDisk LinuxMirror alpineVer \
        ubuntuDigital targetRelese targetLinuxMirror targetLinuxSecurityMirror \
        TimeZone tmpWORD sshPORT networkAdapter Network4Config IPv4 MASK ipPrefix \
        actualIp4Prefix actualIp4Subnet GATE actualIp4Gate BurnIrregularIpv4Status \
        ipDNS1 ipDNS2 iAddrNum writeIpsCmd Network6Config ip6Addr ip6Mask \
        actualIp6Prefix ip6Gate ip6DNS1 ip6DNS2 i6AddrNum writeIp6sCmd setIPv6 \
        HostName virtualizationStatus serialConsolePropertiesForGrub \
        setFail2banStatus setMotd lowMemMode DDURL DEC_CMD cloudInitLocalFile; do
        case "$key" in
            alpineVer) value="$DIST" ;;
            cloudInitLocalFile) value='/root/ddinstall-assets/cloud-init.cfg' ;;
            *) value="${!key}" ;;
        esac
        [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || {
            printf '[ERROR] Invalid multiline value for %s.\n' "$key" >&2; return 1
        }
        printf '%s  %s\n' "$key" "$value" >> "$assetDir/alpine.config" || return 1
    done
    chmod 700 "$assetDir/init.start" || return 1
    chmod 600 "$assetDir/cloud-init.cfg" "$assetDir/resolv.conf" "$assetDir/alpine.config" || return 1
    return 0
}

function installBootPayload() {
    local source="$1" destination="$2" temporary
    [[ -s "$source" && ! -d "$destination" ]] || return 1
    temporary=$(mktemp "${destination}.tmp.XXXXXX") || return 1
    if ! cp -f -- "$source" "$temporary" || ! chmod 600 "$temporary" || ! mv -f -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        return 1
    fi
    return 0
}

# $1 is "$tmpURL".
function verifyUrlValidationOfDdImages() {
	echo "$1" | grep -q '^http://\|^ftp://\|^https://'
	[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Please input a vaild URL, only support http://, ftp:// and https:// ! \n" && exit 1
	tmpURLCheck=$(curl -4skIL -o /dev/null -w '%{http_code}' --max-time 15 "$1")
	[[ "$tmpURLCheck" != "200" ]] && tmpURLCheck=$(wget -4 --no-check-certificate --spider -S --timeout=15 "$1" 2>&1 | awk '/HTTP\//{c=$2} END{print c}')
	[[ "$tmpURLCheck" != "200" ]] && tmpURLCheck=$(curl -6skIL -o /dev/null -w '%{http_code}' --max-time 15 "$1")
	[[ "$tmpURLCheck" != "200" ]] && {
		echo -ne "\n[${red}Error${plain}] The mirror of DD images is temporarily unavailable!\n"
		exit 1
	}
	DDURL="$1"
    # Query strings are not part of the image suffix (common with cloud-drive links).
    local imagePath="${DDURL%%\?*}"
    imagePath="${imagePath%%\#*}"
    case "${imagePath,,}" in
        *.xz) DEC_CMD='xzcat' ;;
        *.gz) DEC_CMD='gunzip -dc' ;;
        *)
            case "$setFileType" in
                xz) DEC_CMD='xzcat' ;;
                gz) DEC_CMD='gunzip -dc' ;;
                ''|raw) DEC_CMD='cat' ;;
                *) printf '[ERROR] Unsupported image compression type.\n' >&2; exit 1 ;;
            esac ;;
    esac

}

checkSys

# Get the name of network adapter($interface).
# [[ -z "$interface" ]] && interface=`getInterface "$CurrentOS"
# Try to enable IPv4 by DHCP
# timeout 5 dhclient -4 $interface
# Try to enable IPv6 by DHCP
# timeout 5 dhclient -6 $interface

# IPv4 and IPv6 DNS check servers from OpenDNS, Quad9, Verisign and TWNIC.
checkIpv4OrIpv6 "$ipAddr" "$ip6Addr" "208.67.220.220" "9.9.9.9" "64.6.65.6" "101.102.103.104" "2620:0:ccc::2" "2620:fe::9" "2620:74:1b::1:1" "2001:de4::101"

# Youtube, Instagram, Wikipedia and BBC are all have public IPv4 and IPv6 address and are also banned in mainland of China.
checkCN "$IPStackType" "www.youtube.com" "www.instagram.com" "www.wikipedia.org" "bbc.com"

checkEfi "/sys/firmware/efi/efivars/" "/sys/firmware/efi/vars/" "/sys/firmware/efi/runtime-map/" "/sys/firmware/efi/mok-variables/"

checkVirt

if [[ "$sshPORT" ]]; then
	if [[ ! ${sshPORT} -ge "1" ]] || [[ ! ${sshPORT} -le "65535" ]] || [[ $(grep '^[[:digit:]]*$' <<<'${sshPORT}') ]]; then
		sshPORT='22'
	fi
else
	sshPORT=$(grep -Ei "^port|^#port" /etc/ssh/sshd_config | head -n 1 | awk -F' ' '{print $2}')
	[[ "$sshPORT" == "" ]] && sshPORT=$(netstat -anp | grep -i 'sshd: root' | grep -iw 'tcp' | awk '{print $4}' | head -n 1 | cut -d':' -f'2')
	[[ "$sshPORT" == "" ]] && sshPORT=$(netstat -anp | grep -i 'sshd: root' | grep -iw 'tcp6' | awk '{print $4}' | head -n 1 | awk -F':' '{print $NF}')
	if [[ "$sshPORT" == "" ]] || [[ ! ${sshPORT} -ge "1" ]] || [[ ! ${sshPORT} -le "65535" ]] || [[ $(grep '^[[:digit:]]*$' <<<'${sshPORT}') ]]; then
		sshPORT='22'
	fi
fi

[[ -n "$Relese" ]] || Relese='Debian'
linux_relese=$(echo "$Relese" | sed 's/\ //g' | sed -r 's/(.*)/\L\1/')

[[ -z "$tmpDIST" ]] && {
	[ "$Relese" == 'Debian' ] && tmpDIST='13'
}
[[ -z "$finalDIST" ]] && {
	[ "$targetRelese" == 'Ubuntu' ] && finalDIST='22.04'
}

checkVER
if [[ -n "$tmpDIST" ]]; then
	checkDIST
fi

if [[ "$loaderMode" == "0" ]]; then
	checkGrub "/boot/grub/" "/boot/grub2/" "/etc/" "grub.cfg" "grub.conf" "/boot/efi/EFI/"
	if [[ -z "$GRUBTYPE" ]]; then
		echo -ne "\n[${red}Error${plain}] Not found grub!\n"
		exit 1
	fi
	checkConsole "$VER"
fi

clear

[[ ! -d "/tmp/" ]] && mkdir /tmp

# Disable SELinux
[[ -f /etc/selinux/config ]] && {
	SELinuxStatus=$(sestatus -v | grep -i "selinux status:" | grep "enabled")
	[[ "$SELinuxStatus" != "" ]] && {
		echo -ne "\n${aoiBlue}# Disabling SELinux${plain}\n"
		setenforce 0 2>/dev/null
		echo -e "\nSuccess"
	}
}

# Preserve Debian and DD memory checks.
checkMem "$linux_relese" "" "$targetRelese"
Add_OPTION="$Add_OPTION $lowmemLevel"
checkDIST

[[ -n "$TotalMem" ]] && {
	echo -ne "\n${aoiBlue}# System Memory${plain}\n"
	echo -e "\n${TotalMem} MB"
}

[[ -n "$showAllVirts" ]] && {
	echo -ne "\n${aoiBlue}# Virtualization and Manufacturer${plain}\n"
	echo -e "\n${showAllVirts}"
}

[[ "$ddMode" == '1' ]] && {
    # Alpine is only the in-memory bridge, never an installable target.
    Relese='AlpineLinux'
    tmpDIST='edge'
    linux_relese='alpinelinux'
    checkVER
    checkDIST
}

[[ -z "$LinuxMirror" ]] && {
	echo -ne "\n[${red}Error${plain}] Invaild mirror! \n"
	[ "$Relese" == 'Debian' ] && echo -ne "${yellow}Please check mirror lists:${plain} https://www.debian.org/mirror/list\n\n"
	[ "$Relese" == 'AlpineLinux' ] && echo -ne "${yellow}Please check mirror lists:${plain} https://mirrors.alpinelinux.org/\n\n"
	# bash $0 error
	exit 1
}

echo -ne "\n${aoiBlue}# Check Dependence${plain}\n\n"

dependence awk,basename,cat,cpio,curl,cut,dirname,file,find,grep,gzip,ip,lsblk,mktemp,openssl,sed,wget

ipDNS1=$(echo $ipDNS | cut -d ' ' -f 1)
ipDNS2=$(echo $ipDNS | cut -d ' ' -f 2)
ip6DNS1=$(echo $ip6DNS | cut -d ' ' -f 1)
ip6DNS2=$(echo $ip6DNS | cut -d ' ' -f 2)
ipDNS=$(checkDNS "$ipDNS")
ip6DNS=$(checkDNS "$ip6DNS")

if [[ -n "$ipAddr" && -n "$ipMask" && -n "$ipGate" ]] && [[ -z "$ip6Addr" && -z "$ip6Mask" && -z "$ip6Gate" ]]; then
	setNet='1'
	checkDHCP "$CurrentOS" "$CurrentOSVer" "$IPStackType"
	setDhcpOrStatic "$tmpDHCP" "$virtWhat" "$virtType"
	Network4Config="isStatic"
	acceptIPv4AndIPv6SubnetValue "$ipMask" ""
	[[ "$IPStackType" != "IPv4Stack" ]] && getIPv6Address
	# Accept IPv4 configs from user and set to Bi-Stack.
	[[ "$IPStackType" == "IPv6Stack" ]] && {
		IPStackType="BiStack"
		iAddrNum="1"
	}
elif [[ -n "$ipAddr" && -n "$ipMask" && -n "$ipGate" ]] && [[ -n "$ip6Addr" && -n "$ip6Mask" && -n "$ip6Gate" ]]; then
	setNet='1'
	[[ -z "$interfaceSelect" ]] && getInterface "$CurrentOS"
	Network4Config="isStatic"
	Network6Config="isStatic"
	acceptIPv4AndIPv6SubnetValue "$ipMask" "$ip6Mask"
	# Accept IPv4 and IPv6 configs from user and set to Bi-Stack.
	IPStackType="BiStack"
elif [[ -z "$ipAddr" && -z "$ipMask" && -z "$ipGate" ]] && [[ -n "$ip6Addr" && -n "$ip6Mask" && -n "$ip6Gate" ]]; then
	setNet='1'
	checkDHCP "$CurrentOS" "$CurrentOSVer" "$IPStackType"
	setDhcpOrStatic "$tmpDHCP" "$virtWhat" "$virtType"
	Network6Config="isStatic"
	acceptIPv4AndIPv6SubnetValue "" "$ip6Mask"
	getIPv4Address
	# Accept IPv6 configs from user and set to Bi-Stack.
	[[ "$IPStackType" == "IPv4Stack" ]] && {
		IPStackType="BiStack"
		i6AddrNum="1"
	}
fi

if [[ "$setNet" == "0" ]]; then
	checkDHCP "$CurrentOS" "$CurrentOSVer" "$IPStackType"
	setDhcpOrStatic "$tmpDHCP" "$virtWhat" "$virtType"
	getIPv4Address
	[[ "$IPStackType" != "IPv4Stack" ]] && getIPv6Address
	if [[ "$IPStackType" == "BiStack" && "$iAddrNum" -ge "2" || "$i6AddrNum" -ge "2" ]]; then
		if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'alpinelinux' ]]; then
			Network4Config="isStatic"
		fi
		[[ "$BiStackPreferIpv6Status" == "1" ]] && {
			BiStackPreferIpv6Status=""
			BurnIrregularIpv6Status=""
			BurnIrregularIpv4Status='1'
		}
	fi
fi

checkWarp "warp*.conf" "wgcf*.conf" "wg[0-9].conf" "warp*" "wgcf*" "wg[0-9]" "privatekey" "publickey"

IPv4="$ipAddr"
MASK="$ipMask"
GATE="$ipGate"
if [[ -z "$IPv4" && -z "$MASK" && -z "$GATE" ]] && [[ -z "$ip6Addr" && -z "$ip6Mask" && -z "$ip6Gate" ]]; then
	echo -ne "\n[${red}Error${plain}] The network of your machine may not be available!\n"
	bash $0 error
	exit 1
fi

echo -ne "\n${aoiBlue}# Network Details${plain}\n"
[[ -n "$interfaceSelect" ]] && echo -ne "\n[${yellow}Adapter Name${plain}]  $interfaceSelect" || echo -ne "\n[${yellow}Adapter Name${plain}]  $interface"
[[ -n "$NetCfgWhole" ]] && echo -ne "\n[${yellow}Network File${plain}]  $NetCfgWhole" || echo -ne "\n[${yellow}Network File${plain}]  N/A"
echo -ne "\n[${yellow}Server Stack${plain}]  $IPStackType\n"
[[ "$IPStackType" != "IPv6Stack" ]] && echo -ne "\n[${yellow}IPv4  Method${plain}]  $Network4Config\n" || echo -ne "\n[${yellow}IPv4  Method${plain}]  N/A\n"
[[ "$IPv4" && "$IPStackType" != "IPv6Stack" ]] && echo -e "[${yellow}IPv4 Address${plain}]  ""$IPv4" || echo -e "[${yellow}IPv4 Address${plain}]  ""N/A"
[[ "$IPv4" && "$IPStackType" != "IPv6Stack" ]] && echo -e "[${yellow}IPv4  Subnet${plain}]  ""$actualIp4Subnet" || echo -e "[${yellow}IPv4  Subnet${plain}]  ""N/A"
[[ "$IPv4" && "$IPStackType" != "IPv6Stack" ]] && echo -e "[${yellow}IPv4 Gateway${plain}]  ""$GATE" || echo -e "[${yellow}IPv4 Gateway${plain}]  ""N/A"
[[ "$IPv4" && "$IPStackType" != "IPv6Stack" ]] && echo -e "[${yellow}IPv4     DNS${plain}]  ""$ipDNS" || echo -e "[${yellow}IPv4     DNS${plain}]  ""N/A"
[[ "$IPv4" && "$IPStackType" != "IPv6Stack" ]] && echo -e "[${yellow}IPv4  Amount${plain}]  ""$iAddrNum" || echo -e "[${yellow}IPv4  Amount${plain}]  ""N/A"
[[ "$IPStackType" != "IPv4Stack" ]] && echo -ne "\n[${yellow}IPv6  Method${plain}]  $Network6Config\n" || echo -ne "\n[${yellow}IPv6  Method${plain}]  N/A\n"
[[ "$ip6Addr" && "$IPStackType" != "IPv4Stack" ]] && echo -e "[${yellow}IPv6 Address${plain}]  ""$ip6Addr" || echo -e "[${yellow}IPv6 Address${plain}]  ""N/A"
[[ "$ip6Addr" && "$IPStackType" != "IPv4Stack" ]] && echo -e "[${yellow}IPv6  Subnet${plain}]  ""$actualIp6Prefix" || echo -e "[${yellow}IPv6  Subnet${plain}]  ""N/A"
[[ "$ip6Addr" && "$IPStackType" != "IPv4Stack" ]] && echo -e "[${yellow}IPv6 Gateway${plain}]  ""$ip6Gate" || echo -e "[${yellow}IPv6 Gateway${plain}]  ""N/A"
[[ "$ip6Addr" && "$IPStackType" != "IPv4Stack" ]] && echo -e "[${yellow}IPv6     DNS${plain}]  ""$ip6DNS" || echo -e "[${yellow}IPv6     DNS${plain}]  ""N/A"
[[ "$ip6Addr" && "$IPStackType" != "IPv4Stack" ]] && echo -e "[${yellow}IPv6  Amount${plain}]  ""$i6AddrNum" || echo -e "[${yellow}IPv6  Amount${plain}]  ""N/A"

getUserTimeZone "/root/timezonelists" "https://api.ip.sb/geoip/" "http://ifconfig.co/json?ip=" "http://ip-api.com/json/" "https://ipapi.co/" "YjNhNjAxNjY5YTFiNDI2MmFmOGYxYjJjZDk3ZjNiN2YK" "MmUxMjBhYmM0Y2Q4NDM1ZDhhMmQ5YzQzYzk4ZTZiZTEK" "NjBiMThjZWJlMWU1NGQ5NDg2YWY0MTgyMWM0ZTZiZDgK"
[[ -z "$TimeZone" ]] && TimeZone="Asia/Tokyo"
echo -ne "\n${aoiBlue}# User Timezone${plain}\n\n"
echo "$TimeZone"

# Hostname should not be "localhost".
[[ -n "$tmpHostName" ]] && HostName="$tmpHostName" || HostName=$(hostname)
[[ -z "$HostName" || "$HostName" =~ "localhost" || "$HostName" =~ "localdomain" || "$HostName" == "random" ]] && HostName="instance-$(date "+%Y%m%d")-$(date "+%H%M")"
echo -ne "\n${aoiBlue}# Hostname${plain}\n\n"
echo "$HostName"

if [[ -z "$tmpWORD" ]]; then
	tmpWORD='LeitboGi0ro'
	myPASSWORD='$6$qE9Lqgrd0QTOq46i$YMECmKvIw2SeBP4X411I0ZWmtyMsRcBi4Rxu7HYRsqdwqSApi6zjds5UJyM4HrAoBcuLBmjPyLatGydulmCDb0'
else
	# "-1" is MD5, "-5" is SHA256, "-6" is SHA512. MD5 is no longer secure.
	myPASSWORD=$(openssl passwd -6 ''$tmpWORD'' 2>/dev/null)
	# Version 1.0.2k of openssl in CentOS 7 is too old that it's only support MD5, the same as Debian 9.
	[[ -z "$myPASSWORD" || "$myPASSWORD" =~ "NULL" ]] && myPASSWORD=$(openssl passwd -1 ''$tmpWORD'')
fi

echo -ne "\n${aoiBlue}# SSH Port, Username and Password${plain}\n\n"
echo "$sshPORT"
echo "root"
echo "$tmpWORD"

setDisk=$(echo "$setDisk" | sed 's/[A-Z]/\l&/g')
getDisk "$setDisk" "$linux_relese"
echo -ne "\n${aoiBlue}# Formatting and Installing Drives${plain}\n\n"
[[ "$setDisk" == "all" || -n "$setRaid" ]] && echo "$AllDisks" || echo "$IncDisk"

echo -ne "\n${aoiBlue}# Motherboard Firmware${plain}\n\n"
[[ "$EfiSupport" == "enabled" ]] && echo "UEFI" || echo "BIOS"

if [[ "$SpikCheckDIST" == '0' ]]; then
	echo -ne "\n${aoiBlue}# Check DIST${plain}\n"
	[[ "$linux_relese" == 'debian' ]] && DistsList="$(wget --no-check-certificate -qO- "$LinuxMirror/dists/" | grep -o 'href=.*/"' | cut -d'"' -f2 | sed '/-\|old\|README\|Debian\|experimental\|stable\|test\|sid\|devel/d' | grep '^[^/]' | sed -n '1h;1!H;$g;s/\n//g;s/\//\;/g;$p')"
	[[ "$linux_relese" == 'alpinelinux' ]] && DistsList="$(wget --no-check-certificate -qO- "$LinuxMirror/" | grep -o 'href=.*/"' | cut -d'"' -f2 | sed '/-/d' | grep '^[^/]' | sed -n '1h;1!H;$g;s/\n//g;s/\//\;/g;$p')"
	for CheckDEB in $(echo "$DistsList" | sed 's/;/\n/g'); do
		# In some mirror, the value of parameter "DistsList" is "?C=N;O=Dbookworm;bullseye;buster;http:;;wisepoint.jp;product;wpshibb;"
		# The second item in "DistsList" which is splited by ";" is O=Dbookworm.
		# So we need to check whether "DIST" is approximately equal(contains) to "CheckDEB".
		[[ "$CheckDEB" =~ "$DIST" ]] && FindDists='1' && break
	done
	[[ "$FindDists" == '0' ]] && {
		echo -ne "\n[${red}Error${plain}] The dists version not found, Please check it! \n\n"
		exit 1
	}
	echo -e "\nSuccess"
fi

if [[ "$ddMode" == '1' ]]; then
	if [[ "$targetRelese" == 'Ubuntu' ]]; then
		ubuntuDIST="$(echo "$finalDIST" | sed -r 's/(.*)/\L\1/')"
		UbuntuDistNum=$(echo "$ubuntuDIST" | cut -d'.' -f1)
		echo "$ubuntuDIST" | grep -q '[0-9]'
		[[ $? -eq '0' ]] && {
			ubuntuDigital="$(echo "$ubuntuDIST" | grep -o '[\.0-9]\{1,\}' | sed -n '1h;1!H;$g;s/\n//g;$p')"
			ubuntuDigital1=$(echo "$ubuntuDigital" | cut -d'.' -f1)
			ubuntuDigital2=$(echo "$ubuntuDigital" | cut -d'.' -f2)
			if [[ "$ubuntuDigital1" -le "19" || "$ubuntuDigital1" -ge "25" || $((${ubuntuDigital1} % 2)) = 1 ]] || [[ "$ubuntuDigital2" != "04" ]]; then
				echo -ne "\n[${red}Error${plain}] The dists version not found, Please check it! \n'"
				exit 1
			fi
			[[ -n $ubuntuDigital ]] && {
				[[ "$ubuntuDigital" == '22.04' ]] && finalDIST='jammy'
				[[ "$ubuntuDigital" == '24.04' ]] && finalDIST='noble'
				# Ubuntu releases reference: https://wiki.ubuntu.com/Releases/
			}
		}
		if [[ "$VER" == "x86_64" ]] || [[ "$VER" == "x86-64" ]]; then
			ubuntuArchitecture="amd64"
		elif [[ "$VER" == "aarch64" ]]; then
			ubuntuArchitecture="arm64"
		fi
		if [[ "$tmpURL" == "" ]]; then
			tmpURL="https://cloud-images.a.disk.re/$targetRelese/"
			setFileType="xz"
			packageName="$finalDIST-server-cloudimg-$ubuntuArchitecture"
			verifyUrlValidationOfDdImages "$tmpURL$packageName.$setFileType"
		else
			verifyUrlValidationOfDdImages "$tmpURL"
		fi
		ReleaseName="$targetRelese $finalDIST $ubuntuArchitecture"
	else
		echo -ne "\n[${red}Warning${plain}] Please input a vaild image URL!\n"
		exit 1
	fi
fi

# The first network adapter name is must be "eth0" if kernel is loaded with parameter "net.ifnames=0 biosdevname=0".
# If the names of network adapters on original system were not be redirected, we can speculate them according to the sequence
# which they had plugged into the system by a physical queue if newly installed system need to redirect network adapters.
if [[ "$setInterfaceName" == "1" ]] && [[ ! "$interface4" =~ "eth" || ! "$interface6" =~ "eth" ]]; then
	interface4="eth""$interface4DeviceOrder"
	interface6="eth""$interface6DeviceOrder"
	interface="$interface4"
	[[ "$IPStackType" == "IPv6Stack" ]] && interface="$interface6"
fi

if [ -z "$interfaceSelect" ]; then
	if [[ "$linux_relese" == 'debian' ]]; then
		interfaceSelect="auto"
	fi
	# Some cloud providers using the second or further order back of interface adapter like "eth1" to config public networking usually and we don't know what's role of "eth0".
	[[ "$interfacesNum" -ge "2" ]] && {
		if [[ "$IPStackType" == "IPv6Stack" ]]; then
			# Approximately equal "=~" to "eth..." is for the redirected situation, "device order" is on the contrary for an un-redirected example.
			[[ "$interface6" =~ "eth" && $(echo "$interface6" | grep -o '[0-9]') != "0" ]] || [[ "$interface6DeviceOrder" != "0" ]] && {
				interfaceSelect="$interface6"
			}
		elif [[ "$IPStackType" == "BiStack" || "$IPStackType" == "IPv4Stack" ]]; then
			[[ "$interface4" =~ "eth" && $(echo "$interface4" | grep -o '[0-9]') != "0" ]] || [[ "$interface4DeviceOrder" != "0" ]] && {
				interfaceSelect="$interface4"
			}
		fi
	}
else
	# If the kernel of original system is loaded with parameter "net.ifnames=0 biosdevname=0" and users don't want to set this
	# one in new system, they have to assign a valid, real name of their network adapter and the parameter "$interface"
	# will be written to new network configuration in preseed file for new system.
	interface4=$(echo "$interfaceSelect" | cut -d' ' -f 1)
	interface6=$(echo "$interfaceSelect" | cut -d' ' -f 2)
	interface="$interface4"
	[[ -z "$interface6" ]] && {
		interface=$(echo "$interfaceSelect" | sed 's/[[:space:]]//g')
		interface6="$interface"
	}
fi

echo -ne "\n${aoiBlue}# Installation Starting${plain}\n"

[[ "$ddMode" == '1' ]] && echo -ne "\n${blue}Overwriting Packaged Image Mode${plain} Target System [${yellow}$ReleaseName${plain}]\n$DDURL\n"

echo -ne "\n[${yellow}$Relese${plain}] [${yellow}$DIST${plain}] [${yellow}$VER${plain}] Downloading...\n"

if [[ "$linux_relese" == 'debian' ]]; then
	InitrdUrl="${LinuxMirror}/dists/${DIST}/main/installer-${VER}/current/images/netboot/${linux_relese}-installer/${VER}/initrd.gz"
	VmLinuzUrl="${LinuxMirror}/dists/${DIST}${inUpdate}/main/installer-${VER}/current/images/netboot/${linux_relese}-installer/${VER}/linux"
	echo -ne "[${yellow}Mirror${plain}] $InitrdUrl\n\t $VmLinuzUrl\n"
	wget --no-check-certificate -qO '/tmp/initrd.img' "$InitrdUrl"
	[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download 'initrd.img' for ${yellow}$linux_relese${plain} failed! \n" && exit 1
	wget --no-check-certificate -qO '/tmp/vmlinuz' "$VmLinuzUrl"
	[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download 'vmlinuz' for ${yellow}$linux_relese${plain} failed! \n" && exit 1
	MirrorHost="$(echo "$LinuxMirror" | awk -F'://|/' '{print $2}')"
	MirrorFolder="$(echo "$LinuxMirror" | awk -F''${MirrorHost}'' '{print $2}')/"
	[ -n "$MirrorFolder" ] || MirrorFolder="/"
elif [[ "$linux_relese" == 'alpinelinux' ]]; then
	InitrdUrl="${LinuxMirror}/${DIST}/releases/${VER}/netboot/${InitrdName}"
	VmLinuzUrl="${LinuxMirror}/${DIST}/releases/${VER}/netboot/${VmLinuzName}"
	ModLoopUrl="${LinuxMirror}/${DIST}/releases/${VER}/netboot/${ModLoopName}"
	echo -ne "[${yellow}Mirror${plain}] $InitrdUrl\n\t $VmLinuzUrl\n"
	wget --no-check-certificate -qO '/tmp/initrd.img' "$InitrdUrl"
	[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download '$InitrdName' for ${yellow}$linux_relese${plain} failed! \n" && exit 1
	wget --no-check-certificate -qO '/tmp/vmlinuz' "$VmLinuzUrl"
	[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download '$VmLinuzName' for ${yellow}$linux_relese${plain} failed! \n" && exit 1
else
	bash $0 error
	exit 1
fi

if [[ "$IncFirmware" == '1' ]]; then
	if [[ "$linux_relese" == 'debian' ]]; then
		if [[ "$IsCN" == "cn" ]]; then
			wget --no-check-certificate -qO '/tmp/firmware.cpio.gz' "https://mirrors.ustc.edu.cn/debian-cdimage/unofficial/non-free/firmware/${DIST}/current/firmware.cpio.gz"
			[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download firmware for ${red}$linux_relese${plain} failed! \n" && exit 1
		else
			wget --no-check-certificate -qO '/tmp/firmware.cpio.gz' "http://cdimage.debian.org/cdimage/unofficial/non-free/firmware/${DIST}/current/firmware.cpio.gz"
			[[ $? -ne '0' ]] && echo -ne "\n[${red}Error${plain}] Download firmware for ${red}$linux_relese${plain} failed! \n" && exit 1
		fi
		if [[ "$ddMode" == '1' ]]; then
			vKernel_udeb=$(wget --no-check-certificate -qO- "http://$LinuxMirror/dists/$DIST/main/installer-$VER/current/images/udeb.list" | grep '^acpi-modules' | head -n1 | grep -o '[0-9]\{1,2\}.[0-9]\{1,2\}.[0-9]\{1,2\}-[0-9]\{1,2\}' | head -n1)
			[[ -z "vKernel_udeb" ]] && vKernel_udeb="6.1.0-11"
		fi

	fi
fi

# Resize "/tmp" to avoid too low space to contain netboot kernel, base measure is "MB".
tmpDirAvail=$(df -TBM | grep "/tmp\|/dev/shm" | head -n 1 | awk '{print $5}' | tr -cd "[0-9]")
[[ "$tmpDirAvail" -lt "1024" ]] && mount -o remount,size=1G,noexec,nosuid,nodev,noatime tmpfs /tmp 2>/dev/null

[[ -d /tmp/boot ]] && rm -rf /tmp/boot
mkdir -p /tmp/boot
cd /tmp/boot

COMPTYPE="gzip"
CompDected='0'
for COMP in $(echo -en 'gzip\nlzma\nxz'); do
	if [[ "$COMPTYPE" == "$COMP" ]]; then
		CompDected='1'
		if [[ "$COMPTYPE" == 'gzip' ]]; then
			NewIMG="initrd.img.gz"
		else
			NewIMG="initrd.img.$COMPTYPE"
		fi
		mv -f "/tmp/initrd.img" "/tmp/$NewIMG"
		break
	fi
done
[[ "$CompDected" != '1' ]] && echo "Detect compressed type not support." && exit 1
[[ "$COMPTYPE" == 'lzma' ]] && UNCOMP='xz --format=lzma --decompress'
[[ "$COMPTYPE" == 'xz' ]] && UNCOMP='xz --decompress'
[[ "$COMPTYPE" == 'gzip' ]] && UNCOMP='gzip -d'
(set -o pipefail; $UNCOMP </tmp/$NewIMG | cpio --extract --make-directories --preserve-modification-time >>/dev/null 2>&1) || { echo '[ERROR] Could not extract initramfs.' >&2; exit 1; }

if [[ "$linux_relese" == 'debian' ]]; then
	DebianPreseedProcess
	if [[ "$loaderMode" != "0" ]] && [[ "$setNet" == '0' ]]; then
		sed -i '/netcfg\/disable_autoconfig/d' /tmp/boot/preseed.cfg
		sed -i '/netcfg\/dhcp_options/d' /tmp/boot/preseed.cfg
		sed -i '/netcfg\/get_.*/d' /tmp/boot/preseed.cfg
		sed -i '/netcfg\/confirm_static/d' /tmp/boot/preseed.cfg
	fi
	# If server has only one disk, lv/vg/pv volumes removement by force should be disallowed, it may causes partitioner continuous execution but not finished.
	if [[ "$disksNum" -le "1" || "$setDisk" != "all" || -n "$setRaid" ]]; then
		sed -i 's/lvremove --select all -ff -y;//g' /tmp/boot/preseed.cfg
		sed -i 's/vgremove --select all -ff -y;//g' /tmp/boot/preseed.cfg
		sed -i 's/pvremove \/dev\/\* -ff -y;//g' /tmp/boot/preseed.cfg
	elif [[ "$disksNum" -ge "2" && "$setDisk" == "all" ]]; then
		# Some virtual machines will hanging on partition step if execute pvremove.
		[[ -z "$virtWhat" ]] || sed -i 's/pvremove \/dev\/\* -ff -y;//g' /tmp/boot/preseed.cfg
	fi
	if [[ "$disksNum" -ge "2" ]] && [[ -n "$setRaid" ]]; then
		sed -i 's/d-i partman\/early_command.*//g' /tmp/boot/preseed.cfg
		sed -ri "/d-i grub-installer\/bootdev.*/c\d-i grub-installer\/bootdev string $AllDisks" /tmp/boot/preseed.cfg
	fi
	# Debian 8 and former or Raid mode don't support xfs.
	[[ "$DebianDistNum" -le "8" || -n "$setRaid" ]] && sed -i '/d-i\ partman\/default_filesystem string xfs/d' /tmp/boot/preseed.cfg
	if [[ "$linux_relese" == 'debian' ]]; then
		sed -i '/user-setup\/allow-password-weak/d' /tmp/boot/preseed.cfg
		sed -i '/user-setup\/encrypt-home/d' /tmp/boot/preseed.cfg
		sed -i '/pkgsel\/update-policy/d' /tmp/boot/preseed.cfg
		sed -i 's/umount\ \/media.*true\;\ //g' /tmp/boot/preseed.cfg
		[[ -f '/tmp/firmware.cpio.gz' ]] && gzip -d </tmp/firmware.cpio.gz | cpio --extract --verbose --make-directories --no-absolute-filenames >>/dev/null 2>&1

	fi
	# Preserve legacy Debian security handling; CLI currently limits netboot to 12/13.
	if [[ "$linux_relese" == 'debian' && "$DebianDistNum" -le "9" ]]; then
		sed -ri 's/services-select multiselect security, updates/services-select multiselect/g' /tmp/boot/preseed.cfg
		sed -ri 's/enable-source-repositories boolean true/enable-source-repositories boolean false/g' /tmp/boot/preseed.cfg
		sed -i '/d-i\ apt-setup\/security_host string/d' /tmp/boot/preseed.cfg
	fi
	# Static network environment doesn't support ntp clock setup.
	if [[ "$Network4Config" == "isStatic" ]] || [[ "$Network6Config" == "isStatic" ]]; then
		sed -i 's/ntp boolean true/ntp boolean false/g' /tmp/boot/preseed.cfg
		sed -i '/d-i\ clock-setup\/ntp-server string ntp.nict.jp/d' /tmp/boot/preseed.cfg
	fi
	# If network adapter is not redirected, delete this setting to new system.
	[[ "$setInterfaceName" == "0" ]] && sed -i 's/net.ifnames=0 biosdevname=0//g' /tmp/boot/preseed.cfg
	# If user not setting disable IPv6 or network is IPv6 or bio-stack, "ipv6.disable=1" should be deleted.
	[[ "$setIPv6" == "1" ]] && sed -i 's/ipv6.disable=1//g' /tmp/boot/preseed.cfg

elif [[ "$linux_relese" == 'alpinelinux' ]]; then
	alpineArchitecture="$VER"
	# Enable IPv6
	echo "ipv6" >>/tmp/boot/etc/modules
	if [[ "$setAutoConfig" == "1" ]]; then
		selectLocalDdAssets || exit 1
		if [[ "$IPStackType" == "BiStack" || "$IPStackType" == "IPv4Stack" ]]; then
			# Soft hack of irregular IPv4 configs.
			# Reserved empty variables for engineering debugging, if you are not known them well, don't uncomment with them!
			# BurnIrregularIpv4Status='1'
			# ipPrefix=""
			# ipMask=""
			[[ "$BurnIrregularIpv4Status" == "1" ]] && {
				actualIp4Gate="$GATE"
				# To add the following soft hacking commands in function "configure_ip()" of the initial file which is dedicated for AlpineLinux can let network service execute immediately at netboot kernel starting,
				# it has a similar effect with "d-i preseed/early_command" in the file "preseed.cfg" of Debian series.
				# A valid anchor is a comment of "# manual configuration" in this function.
				sed -i '/manual configuration/a\\t\tip link set dev '$interface4' up\n\t\tip addr add '$IPv4'/'$ipPrefix' dev '$interface4'\n\t\tip route add '$actualIp4Gate' dev '$interface4'\n\t\tip route add default via '$actualIp4Gate' dev '$interface4' onlink\n\t\techo '\''nameserver '$ipDNS1''\'' > /etc/resolv.conf\n\t\techo '\''nameserver '$ipDNS2''\'' >> /etc/resolv.conf' /tmp/boot/init
			}
		elif [[ "$IPStackType" == "IPv6Stack" ]]; then
			# Attention:
			# Configure networking in pure IPv6 or irregular IPv4 environment so that to let AlpineLinux netboot kernel to support to connect to the public network was not recognized by official at current(date 2023.08).
			# This is only belonged to an appertain of my ingenuity in this earth. I'm glad to introduce to you without any reservation that how I was accomplished to dealing with it.
			# By using "ip link set IPv6 network adaper", "ip -6 add IPv6 address and subnet", "ip -6 route add..." are similar with handling irregular IPv4s.
			# For pure IPv6 stack, static network configure method, we need to generate a nonexistent IPv4 configurations to make a cheat to let AlpineLinux to initiate network service.
			# For pure IPv6 stack, dhcp network configure method, in most of these environments, upstream networking topology may also has a IPv4 dhcp configuration but server won't get any public IPv4 address acrossing IPv4 route,
			# so we need to add IPv6 hijack commands after IPv4 dhcp configure method context after comment of "# automatic configuration" in function of "configure_ip()".
			# About deciding to write which different contents of "ip=..." in grub section, "ip=dhcp" is for IPv6 automatic method, for IPv6 manual method is like "ip=172.25.255.72:::255.255.255.0::eth0:::", no matter for menuentry of grub1 or grub2 format are all applicable.
			# All of these deceptions of above are only for let AlpineLinux netboot kernel to creating IPv6 network successfully during a temporary AlpineLinux environment in RAM
			# when the Debian or Ubuntu DD image is installed, the networking configure files will be all rewritten so that the "fakeIpv4 ", etc. have no negative impacts to these finally installed target systems.
			if [[ "$Network6Config" == "isStatic" ]]; then
				fakeIpv4="172.25.255.72"
				fakeIpMask="255.255.255.0"
				hackIpv6Context="manual configuration"
			elif [[ "$Network6Config" == "isDHCP" ]]; then
				hackIpv6Context="automatic configuration"
			fi
			sed -i '/'"$hackIpv6Context"'/a\\t\tdepmod\n\t\tmodprobe ipv6\n\t\tip link set dev '$interface6' up\n\t\tip -6 addr add '$ip6Addr'/'$actualIp6Prefix' dev '$interface6'\n\t\tip -6 route add '$ip6Gate' dev '$interface6'\n\t\tip -6 route add default via '$ip6Gate' dev '$interface6' onlink\n\t\techo '\''nameserver '$ip6DNS1''\'' > /etc/resolv.conf\n\t\techo '\''nameserver '$ip6DNS2''\'' >> /etc/resolv.conf' /tmp/boot/init
		fi
		writeMultipleIpv4Addresses "$iAddrNum"
		writeMultipleIpv6Addresses "$i6AddrNum"
        # Network hooks above can insert lines. Locate switch_root AFTER those edits.
        [[ $(grep -Ec '^exec (/bin/busybox )?switch_root' /tmp/boot/init) -eq 1 ]] || {
            printf '[ERROR] Unsupported Alpine init layout: expected one switch_root.\n' >&2
            exit 1
        }
        AlpineInitLineNum=$(grep -En '^exec (/bin/busybox )?switch_root' /tmp/boot/init | cut -d: -f1)
        [[ "$AlpineInitLineNum" -gt 1 ]] || exit 1
        AlpineInitLineNum=$((AlpineInitLineNum - 1))
        stageLocalDdAssets /tmp/boot || exit 1
		# All the following steps are processed in the temporary Alpine Linux.
		cat <<EOF | sed -i "${AlpineInitLineNum}r /dev/stdin" /tmp/boot/init
# Local payload is in the initramfs itself, not on the disk about to be overwritten.
mkdir -p "\$sysroot/root/ddinstall-assets" "\$sysroot/etc/local.d" "\$sysroot/etc/runlevels/default" || exit 1
cp /ddinstall-assets/cloud-init.cfg "\$sysroot/root/ddinstall-assets/cloud-init.cfg" || exit 1
cp /ddinstall-assets/resolv.conf "\$sysroot/etc/resolv.conf" || exit 1

# Copy configuration as data; it must never be sourced or evaluated.
cp /ddinstall-assets/alpine.config "\$sysroot/root/alpine.config" || exit 1
chmod 600 "\$sysroot/root/alpine.config" "\$sysroot/root/ddinstall-assets/cloud-init.cfg" || exit 1

# Install the pre-bundled local init program.
cp /ddinstall-assets/init.start "\$sysroot/etc/local.d/${AlpineInitFileName}" || exit 1

# Set initial program to execute automatically.
chmod 700 "\$sysroot/etc/local.d/${AlpineInitFileName}" || exit 1
ln -sf /etc/init.d/local "\$sysroot/etc/runlevels/default/local" || exit 1
EOF
        [[ ${PIPESTATUS[1]} -eq 0 ]] || { echo '[ERROR] Could not inject local startup.' >&2; exit 1; }
	fi

fi

# find . | cpio -H newc --create --verbose | gzip -1 > /tmp/initrd.img
(set -o pipefail; find . | cpio -o -H newc | gzip -1 >/tmp/initrd.img) || { echo '[ERROR] Could not pack initramfs.' >&2; exit 1; }
[[ -s /tmp/initrd.img && -s /tmp/vmlinuz ]] || { echo '[ERROR] Empty boot payload.' >&2; exit 1; }

# Grub config start
# Debian/Ubuntu (Alpine DD bridge) Grub1 setting start
if [[ ! -z "$GRUBTYPE" && "$GRUBTYPE" == "isGrub1" ]]; then
		# In templates of Debian of equinix.com, the default "grub.cfg" is not match with the standard format, so it should be re-generated.
		[[ ! $(grep -iE '/etc/grub.d|begin|end|savedefault|load_video|gfxmode' $GRUBDIR/$GRUBFILE) ]] && {
			grub-mkconfig -o $GRUBDIR/$GRUBFILE >>/dev/null 2>&1
		}
		READGRUB='/tmp/grub.read'
		[[ -f $READGRUB ]] && rm -rf $READGRUB
		touch $READGRUB
		# Backup original grub config file
		cp $GRUBDIR/$GRUBFILE "${GRUBDIR}/${GRUBFILE}_$(date "+%Y%m%d%H%M").bak"
		# Read grub file, search boot item.
		#
		# Here is the sample of "menuentry" in most regular Debian like Linux releases:
		#
		# menuentry 'Debian GNU/Linux' {
		#   load_video
		#   insmod ...
		#   if [ x$grub_platform = xxen ]; then insmod ...; fi
		#   set root='hd...'
		#   if [ x$feature_platform_search_hint = xy ]; then
		#	    search --no-floppy --fs-uuid --set=root --hint- ...
		#   else
		#     search --no-floppy --fs-uuid --set=root some uuid
		#   fi
		#   echo	'Loading Linux ...'
		#	  linux	/boot/vmlinuz
		#   echo	'Loading initial ramdisk ...'
		#   initrd	/boot/initrd.img
		# }
		#
		# But in Ubuntu series(version 20.04+) of official templates of Amazon Lightsail, there are two "}" in one set of the "menuentry" like:
		#
		# menuentry 'Ubuntu' {
		#   gfxpayload ...
		#   insmod ...
		#   if [ x$grub_platform = xxen ]; then insmod xzio; insmod lzopio; fi
		#   if [ x$feature_platform_search_hint = xy ]; then ...; fi
		#   if [ "${initrdfail}" = 1 ]; then
		#     linux	/boot/vmlinuz
		#     initrd	/boot/initrd.img
		#   else
		#     ...
		#   fi
		#   initrdfail
		# }
		#
		# Original regex " grep -om 1 'menuentry\ [^}]*}' " written by "MoeClub" can only matches end to " menuentry 'Ubuntu' {..... if [ "${initrdfail} " so that " grep -om 1 'menuentry\ [^}]*}%%%%%%% " caused "$READGRUB" has nothing.
		# That's why we need to add "." to split every regex conditions and delete space lines of "# code comments".
		#
		# Some grub file is written as a binary file, add parameter "-a, --text" process this file as if it were text; this is equivalent to the --binary-files=text option
		cat $GRUBDIR/$GRUBFILE | sed -n '1h;1!H;$g;s/\n/%%%%%%%/g;$p' | grep -aom 1 'menuentry\ [^{].*{.[^}].*}%%%%%%%' | sed 's/%%%%%%%/\n/g' | grep -v '^#' | sed '/^[[:space:]]*$/d' >$READGRUB
		LoadNum="$(cat $READGRUB | grep -c 'menuentry ')"
		if [[ "$LoadNum" -eq '1' ]]; then
			cat $READGRUB | sed '/^$/d' >/tmp/grub.new
		elif [[ "$LoadNum" -gt '1' ]]; then
			CFG0="$(awk '/menuentry /{print NR}' $READGRUB | head -n 1)"
			CFG2="$(awk '/menuentry /{print NR}' $READGRUB | head -n 2 | tail -n 1)"
			CFG1=""
			for tmpCFG in $(awk '/}/{print NR}' $READGRUB); do
				[ "$tmpCFG" -gt "$CFG0" -a "$tmpCFG" -lt "$CFG2" ] && CFG1="$tmpCFG"
			done
			[[ -z "$CFG1" ]] && {
				echo -ne "\n[${red}Error${plain}] Read $GRUBFILE !\n"
				exit 1
			}
			sed -n "$CFG0,$CFG1"p $READGRUB >/tmp/grub.new
			[[ -f /tmp/grub.new ]] && [[ "$(grep -c '{' /tmp/grub.new)" -eq "$(grep -c '}' /tmp/grub.new)" ]] || {
				echo -ne "\n[${red}Error${plain}] Not configure $GRUBFILE !\n"
				exit 1
			}
		fi
		[ ! -f /tmp/grub.new ] && echo -ne "\n[${red}Error${plain}] $GRUBFILE ! " && exit 1
		sed -i "/menuentry.*/c\menuentry\ \'Install OS \[$Relese\ $DIST\ $VER\]\'\ --class $linux_relese\ --class\ gnu-linux\ --class\ gnu\ --class\ os\ \{" /tmp/grub.new
		sed -i "/echo.*Loading/d" /tmp/grub.new
		INSERTGRUB="$(awk '/menuentry /{print NR}' $GRUBDIR/$GRUBFILE | head -n 1)"

		[[ -n "$(grep 'linux.*/\|kernel.*/' /tmp/grub.new | awk '{print $2}' | tail -n 1 | grep '^/boot/')" ]] && Type='InBoot' || Type='NoBoot'

		LinuxKernel="$(grep 'linux.*/\|kernel.*/' /tmp/grub.new | awk '{print $1}' | head -n 1)"
		[[ -z "$LinuxKernel" ]] && echo -ne "\n${red}Error${plain} read grub config!\n" && exit 1
		LinuxIMG="$(grep 'initrd.*/' /tmp/grub.new | awk '{print $1}' | tail -n 1)"
		[ -z "$LinuxIMG" ] && sed -i "/$LinuxKernel.*\//a\\\tinitrd\ \/" /tmp/grub.new && LinuxIMG='initrd'
		# If network adapter need to redirect eth0, eth1... in new system, add this setting in grub file of the current system for netboot install file which need to be loaded after restart.
		# The same behavior for grub2.
		[[ "$setInterfaceName" == "1" ]] && Add_OPTION="$Add_OPTION net.ifnames=0 biosdevname=0" || Add_OPTION="$Add_OPTION"
		[[ "$setIPv6" == "0" ]] && Add_OPTION="$Add_OPTION ipv6.disable=1" || Add_OPTION="$Add_OPTION"

		if [[ "$linux_relese" == 'debian' ]]; then
			# The method for Debian series installer to search network adapter automatically is to set "d-i netcfg/choose_interface select auto" in preseed file.
			# The same behavior for grub2.
			BOOT_OPTION="auto=true $Add_OPTION hostname=$HostName domain=$linux_relese quiet"
		elif [[ "$linux_relese" == 'alpinelinux' ]]; then
			# Reference: https://wiki.alpinelinux.org/wiki/PXE_boot
			# IPv4 dhcp config:
			# ip=dhcp or not assign it.
			# Allow a valid IPv4 static config:
			# ip=client-ip::geteway:mask::adapter::dns:
			# Sample:
			# ip=179.86.100.76::179.86.100.1:255.255.255.0::eth0::1.0.0.1 8.8.8.8:
			# Any of IPv6 address format can't be recognized.
			if [[ "$IPStackType" == "BiStack" || "$IPStackType" == "IPv4Stack" ]]; then
				[[ "$Network4Config" == "isStatic" ]] && Add_OPTION="ip=$IPv4::$GATE:$MASK::$interface4::$ipDNS:" || Add_OPTION="ip=dhcp"
				[[ "$BurnIrregularIpv4Status" == "1" ]] && Add_OPTION="ip=$IPv4:::$ipMask::$interface4::$ipDNS:"
			elif [[ "$IPStackType" == "IPv6Stack" ]]; then
				[[ "$Network6Config" == "isStatic" ]] && Add_OPTION="ip=$fakeIpv4:::$fakeIpMask::$interface6:::" || Add_OPTION="ip=dhcp"
			fi
			BOOT_OPTION="alpine_repo=$LinuxMirror/$DIST/main/ modloop=$ModLoopUrl $Add_OPTION"

		fi

		[[ -n "$ttyConsole" ]] && BOOT_OPTION="$BOOT_OPTION $ttyConsole"
		[ -n "$setConsole" ] && BOOT_OPTION="$BOOT_OPTION --- console=$setConsole"

		[[ "$Type" == 'InBoot' ]] && {
			sed -i "/$LinuxKernel.*\//c\\\t$LinuxKernel\\t\/boot\/ddinstall-vmlinuz $BOOT_OPTION" /tmp/grub.new
			sed -i "/$LinuxIMG.*\//c\\\t$LinuxIMG\\t\/boot\/ddinstall-initrd.img" /tmp/grub.new
		}
		[[ "$Type" == 'NoBoot' ]] && {
			sed -i "/$LinuxKernel.*\//c\\\t$LinuxKernel\\t\/ddinstall-vmlinuz $BOOT_OPTION" /tmp/grub.new
			sed -i "/$LinuxIMG.*\//c\\\t$LinuxIMG\\t\/ddinstall-initrd.img" /tmp/grub.new
		}

		sed -i '$a\\n' /tmp/grub.new

		# To eliminate the undesirable effect of the condition of "initrdfail" in grub for Ubuntu series of AWS EC2 arm64 t4g instances.
		#
		# menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-0694475a-b8e4-4c51-a03f-0c6f41144a12' {
		#   recordfail
		#   load_video
		#   gfxmode $linux_gfx_mode
		#   insmod gzio
		#   if [ x$grub_platform = xxen ]; then insmod xzio; insmod lzopio; fi
		#   insmod part_gpt
		#   insmod ext2
		#   search --no-floppy --fs-uuid --set=root 0694475a-b8e4-4c51-a03f-0c6f41144a12
		#   if [ "${initrdfail}" = 1 ]; then
		#     echo  'GRUB_FORCE_PARTUUID set, initrdless boot failed. Attempting with initrd.'
		#     linux  /boot/vmlinuz-5.19.0-1025-aws root=PARTUUID=7819481c-7167-49eb-8354-9a1efe601215 ro  console=tty1 console=ttyS0 nvme_core.io_timeout=4294967295
		#     initrd  /boot/initrd.img-5.19.0-1025-aws
		#   else
		#     echo  'GRUB_FORCE_PARTUUID set, attempting initrdless boot.'
		#     linux  /boot/vmlinuz-5.19.0-1025-aws root=PARTUUID=7819481c-7167-49eb-8354-9a1efe601215 ro  console=tty1 console=ttyS0 nvme_core.io_timeout=4294967295 panic=-1
		#   fi
		#   initrdfail
		# }
		#
		# The same as AWS Lightsail, GCP, Azure.
		#
		# "initrdfail" is a recovery feature of Ubuntu. This option is used as when booting without initrd/initramfs for the cloud,
		# and is not suitable in a normal Ubuntu installation environment. This option is similar to "recordfail",
		# the variables of "initrdfail" are set on the GRUB side when each booting and then they will be deleted after startup,
		# the behavior changes at the next startup depending on the contents of the variables.
		#
		# Reference: https://gihyo.jp/admin/serial/01/ubuntu-recipe/0746
		#     Title: 第746回: update-grubの仕組みを使ってUbuntuのGRUBをさらにカスタマイズする
		#   Chapter: 起動が失敗した時のリカバリー機能
		#
		[[ -n $(grep "initrdfail" /tmp/grub.new) ]] && {
			sed -ri 's/\"\$\{initrdfail\}\".*/\"\$\{initrdfail\}\" = \"\" ]; then/g' /tmp/grub.new
			sed -ri 's/initrdfail/initrdfial/g' /tmp/grub.new
		}

		sed -i ''${INSERTGRUB}'i\\n' $GRUBDIR/$GRUBFILE
		sed -i ''${INSERTGRUB}'r /tmp/grub.new' $GRUBDIR/$GRUBFILE
		[[ -f $GRUBDIR/grubenv ]] && sed -i 's/saved_entry/#saved_entry/g' $GRUBDIR/grubenv

		# The value of " set default=... " in "/boot/grub/grub.cfg" in Ubuntu 20.04 of Tencent Cloud is "1", to boot to the new menuentry that we generated, the value of it must be replaced to "0".
		[[ $(grep "set default=\"[0-9]" $GRUBDIR/$GRUBFILE | tr -cd "[0-9]") != "0" ]] && {
			sed -ri 's/set default=\"[0-9].*/set default=\"0\"/g' $GRUBDIR/$GRUBFILE
		}

		# Debian/Ubuntu (Alpine DD bridge) grub1 setting end
elif [[ ! -z "$GRUBTYPE" && "$GRUBTYPE" == "isGrub2" ]]; then
		# RedHat grub2 setting start
		# Confirm linux and initrd kernel direction
		if [[ -f $GRUBDIR/grubenv ]] && [[ -d /boot/loader/entries ]] && [[ "$(ls /boot/loader/entries | wc -l)" != "0" ]]; then
			LoaderPath=$(cat $GRUBDIR/grubenv | grep 'saved_entry=' | awk -F '=' '{print $2}')
			LpLength=$(echo ${#LoaderPath})
			LpFile="/boot/loader/entries/$LoaderPath.conf"
			# The saved_entry of OpenCloudOS(Tencent Cloud) is equal "0"
			# [root@VM-4-11-opencloudos ~]# cat /boot/grub2/grubenv
			# GRUB Environment Block
			# saved_entry=0
			# kernelopts=root=UUID=c21f153f-c0a8-42db-9ba5-8299e3c3d5b9 ro quiet elevator=noop console=ttyS0,115200 console=tty0 vconsole.keymap=us crashkernel=1800M-64G:256M,64G-128G:512M,128G-:768M vconsole.font=latarcyrheb-sun16 net.ifnames=0 biosdevname=0 intel_idle.max_cstate=1 intel_pstate=disable iommu=pt amd_iommu=on
			# boot_success=0
			if [[ "$LpLength" -le "1" ]] || [[ ! -f "$LpFile" ]]; then
				LpFile=$(ls -Sl /boot/loader/entries/ | grep -wv "*rescue*" | awk -F' ' '{print $NF}' | sed -n '2p')
				[[ "$(cat /boot/loader/entries/$LpFile | grep '^linux /boot/')" ]] && BootDIR='/boot' || BootDIR=''
			else
				[[ "$(cat $LpFile | grep '^linux /boot/')" ]] && BootDIR='/boot' || BootDIR=''
			fi
		else
			[[ -n "$(grep 'linux.*/\|kernel.*/' $GRUBDIR/$GRUBFILE | awk '{print $2}' | tail -n 1 | grep '^/boot/')" ]] && BootDIR='/boot' || BootDIR=''
		fi
		# Confirm if BIOS or UEFI firmware for architecture of x86_64(AMD64) processors.
		if [[ "$VER" == "x86_64" || "$VER" == "amd64" ]]; then
			[[ "$EfiSupport" == "enabled" ]] && BootHex="efi" || BootHex="16"
			# The architecture of aarch64(ARM64) processors have matched for only UEFI firmware even nowadays.
		elif [[ "$VER" == "aarch64" || "$VER" == "arm64" ]]; then
			BootHex=""
		fi
		# Get main menuentry parameter from current system
		CFG0="$(awk '/insmod part_/{print NR}' $GRUBDIR/$GRUBFILE | head -n 1)"
		CFG2tmp="$(awk '/--fs-uuid --set=root/{print NR}' $GRUBDIR/$GRUBFILE | head -n 2 | tail -n 1)"
		CFG2=$(expr $CFG2tmp + 1)
		CFG1=""
		for tmpCFG in $(awk '/fi/{print NR}' $GRUBDIR/$GRUBFILE); do
			[ "$tmpCFG" -ge "$CFG0" -a "$tmpCFG" -le "$CFG2" ] && CFG1="$tmpCFG"
		done
		if [[ -z "$CFG1" ]]; then
			# In standard Redhat like linux OS with grub2 above version of 7, the OS boot configuration in "grub.cfg" is like:
			#
			# insmod part_msdos
			# insmod xfs
			# set root='hd0,msdos1'
			# if [ x$feature_platform_search_hint = xy ]; then
			#   search --no-floppy --fs-uuid --set=root --hint='hd0,msdos1'  d34311d7-62fd-419e-8f19-71494c773ddd
			# else
			#   search --no-floppy --fs-uuid --set=root d34311d7-62fd-419e-8f19-71494c773ddd
			# fi
			#
			# But in RockyLinux 9.1 of official templates in Oracle Cloud, OVH Cloud etc, the boot configuration in "grub.cfg" is different from any other of Redhat release versions compeletely:
			#
			# insmod part_gpt
			# insmod xfs
			# search --no-floppy --fs-uuid --set=root 11000e8c-9777-43c3-a83b-54a13d609fdb
			# insmod part_gpt
			# insmod fat
			# search --no-floppy --fs-uuid --set=boot 9E70-9B63
			#
			# In CentOS 7, Fedora 36+, AlmaLinux/CentOS-stream/RockyLinux 8+ of official templates in Linode, all the samples are the same:
			#
			# insmod part_msdos
			# insmod ext2
			# set root='hd0,gpt2'
			# insmod part_msdos
			# insmod ext2
			# set boot='hd0,gpt2'
			#
			# Only the following method will effective:
			#
			# The expect component in grub file should be like "search --no-floppy --fs-uuid --set=root 9340b3c7-e898-44ae-bd1e-4c58dec2b16d" or "set boot='hd0'".
			SetRootCfg="$(awk '/--fs-uuid --set=root/{print NR}' $GRUBDIR/$GRUBFILE | head -n 2 | tail -n 1)"
			[[ "$SetRootCfg" == "" ]] && SetRootCfg="$(awk '/set root='\''hd[0-9]/{print NR}' /boot/grub2/grub.cfg | head -n 2 | tail -n 1)"
			# An array for depositing all rows of "insmod part_".
			InsmodPartArray=()
			# An array for row number of "search --no-floppy --fs-uuid --set=root..." minus row number of "insmod part_".
			IpaSpace=()
			# Static how many times does "insmod part_" appeared and storage rows in array of "InsmodPartArray",
			# storage minus rows in arrary of "IpaSpace"
			for tmpCFG in $(awk '/insmod part_/{print NR}' $GRUBDIR/$GRUBFILE); do
				InsmodPartArray+=("$tmpCFG" "$InsmodPartArray")
				# One number of row minus another one shouldn't be less than "0".
				[[ $(expr $SetRootCfg - $tmpCFG) -gt "0" ]] && IpaSpace+=($(expr "$SetRootCfg" - "$tmpCFG") "$IpaSpace")
			done
			# Definite order "0" in "IpaSpace" as a default value of variable of "minArray".
			minArray=${IpaSpace[0]}
			# The outer condition of this cycle is to definite how many times does it will execute.
			for ((i = 1; i <= $(grep -io "insmod part_*" $GRUBDIR/$GRUBFILE | wc -l); i++)); do
				# The inner condition of this cycle is the orders in array of "IpaSpace".
				for j in ${IpaSpace[@]}; do
					# A typical buddle sort for compare whether the current variable "minArray" is greater than the order of number in "IpaSpace" of current cycle.
					# If "minArray" is greater than the order "j" in array of "IpaSpace", the less one "j" will replace the former "IpaSpace".
					[[ $minArray -gt $j ]] && minArray=$j
				done
			done
			# The least "minArray" will be the result and once it plus "SetRootCfg" will be the nearest row number of "insmod part_".
			# So we can figure out the valid section of boot configuration in "grub.cfg" like:
			#
			# insmod part_gpt
			# insmod xfs
			# search --no-floppy --fs-uuid --set=root 9340b3c7-e898-44ae-bd1e-4c58dec2b16d
			#
			CFG0=$(expr $SetRootCfg - $minArray)
			CFG1="$SetRootCfg"
		fi
		[[ -z "$CFG0" || -z "$CFG1" ]] && {
			echo -ne "\n[${red}Error${plain}] Read $GRUBFILE !\n"
			exit 1
		}
		sed -n "$CFG0,$CFG1"p $GRUBDIR/$GRUBFILE >/tmp/grub.new
		sed -i -e 's/^/  /' /tmp/grub.new
		[[ -f /tmp/grub.new ]] && [[ "$(grep -c '{' /tmp/grub.new)" -eq "$(grep -c '}' /tmp/grub.new)" ]] || {
			echo -ne "\n[${red}Error${plain}] Not configure $GRUBFILE !\n"
			exit 1
		}
		[ ! -f /tmp/grub.new ] && echo -ne "\n[${red}Error${plain}] $GRUBFILE !\n" && exit 1
		# Set IPv6 or distribute unite network adapter interface
		[[ "$setInterfaceName" == "1" ]] && Add_OPTION="$Add_OPTION net.ifnames=0 biosdevname=0" || Add_OPTION="$Add_OPTION"
		[[ "$setIPv6" == "0" ]] && Add_OPTION="$Add_OPTION ipv6.disable=1" || Add_OPTION="$Add_OPTION"
		# Write menuentry to grub
		# Find existed boot entries: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-command-line-parameters_managing-monitoring-and-updating-the-kernel#what-boot-entries-are_configuring-kernel-command-line-parameters
		# There is no directory of "/boot/loader/entries/" in CentOS 7.
		grub2Order=$(find /boot/loader/entries/ -maxdepth 1 -name "*.conf" 2>/dev/null | wc -l)
		[[ "$grub2Order" == "0" ]] && grub2Order=$(grep -ic "menuentry '*'" $GRUBDIR/$GRUBFILE)
		[[ "$grub2Order" == "0" ]] && grub2Order=$(grub2-mkconfig -o $GRUBDIR/$GRUBFILE 2>&1 | grep -ic "linux image:")
		[[ "$grub2Order" == "0" ]] && grub2Order="saved"
		# Make grub2 to prefer installation item to boot first.
		sed -ri 's/GRUB_DEFAULT=.*/GRUB_DEFAULT='$grub2Order'/g' /etc/default/grub
		if [[ "$linux_relese" == 'debian' ]]; then
			BOOT_OPTION="auto=true $Add_OPTION hostname=$HostName domain=$linux_relese quiet"
		elif [[ "$linux_relese" == 'alpinelinux' ]]; then
			if [[ "$IPStackType" == "BiStack" || "$IPStackType" == "IPv4Stack" ]]; then
				[[ "$Network4Config" == "isStatic" ]] && Add_OPTION="ip=$IPv4::$GATE:$MASK::$interface4::$ipDNS:" || Add_OPTION="ip=dhcp"
				[[ "$BurnIrregularIpv4Status" == "1" ]] && Add_OPTION="ip=$IPv4:::$ipMask::$interface4::$ipDNS:"
			elif [[ "$IPStackType" == "IPv6Stack" ]]; then
				[[ "$Network6Config" == "isStatic" ]] && Add_OPTION="ip=$fakeIpv4:::$fakeIpMask::$interface6:::" || Add_OPTION="ip=dhcp"
			fi
			BOOT_OPTION="alpine_repo=$LinuxMirror/$DIST/main/ modloop=$ModLoopUrl $Add_OPTION"

		fi
		[[ -n "$ttyConsole" ]] && BOOT_OPTION="$BOOT_OPTION $ttyConsole"
		cat >>/etc/grub.d/40_custom <<EOF
menuentry 'Install $Relese $DIST $VER' --class $linux_relese --class gnu-linux --class gnu --class os {
  load_video
  set gfxpayload=text
  insmod gzio
$(cat /tmp/grub.new)
  linux$BootHex $BootDIR/ddinstall-vmlinuz $BOOT_OPTION
  initrd$BootHex $BootDIR/ddinstall-initrd.img
}
EOF
		# Refreshing current system grub2 service
		grub2-mkconfig -o $GRUBDIR/$GRUBFILE >>/dev/null 2>&1 || { echo '[ERROR] GRUB setup failed; DO NOT REBOOT.' >&2; exit 1; }
		grub2-set-default "Install $Relese $DIST $VER" >>/dev/null 2>&1 || { echo '[ERROR] GRUB setup failed; DO NOT REBOOT.' >&2; exit 1; }
		grub2-reboot "Install $Relese $DIST $VER" >>/dev/null 2>&1 || { echo '[ERROR] GRUB setup failed; DO NOT REBOOT.' >&2; exit 1; }
		# RedHat grub setting end
fi
# Grub config end

# To fix errors about grub 2.06 reading configs from grub 2.12 .
checkAndReplaceEfiGrub

if [[ "$loaderMode" == "0" ]]; then
	# sleep 5 && reboot || sudo reboot >/dev/null 2>&1
    installBootPayload /tmp/initrd.img /boot/ddinstall-initrd.img || { echo '[ERROR] Could not install initrd.img; DO NOT REBOOT.' >&2; exit 1; }
    installBootPayload /tmp/vmlinuz /boot/ddinstall-vmlinuz || { echo '[ERROR] Could not install vmlinuz; DO NOT REBOOT.' >&2; exit 1; }
	chown root:root $GRUBDIR/$GRUBFILE
	chmod 444 $GRUBDIR/$GRUBFILE
else
	rm -rf "$HOME/loader"
	mkdir -p "$HOME/loader"
	cp -rf "/tmp/initrd.img" "$HOME/loader/initrd.img"
	cp -rf "/tmp/vmlinuz" "$HOME/loader/vmlinuz"
	[[ -f "/tmp/initrd.img" ]] && rm -rf "/tmp/initrd.img"
	[[ -f "/tmp/vmlinuz" ]] && rm -rf "/tmp/vmlinuz"
	echo && ls -AR1 "$HOME/loader"
fi

[[ "$setAutoConfig" != "0" || "$loaderMode" == "0" ]] && {
	echo -ne "\n${aoiBlue}# Directory of Grub and Unattended Disposition File${plain}\n\n"
	echo "$GRUBDIR/$GRUBFILE"
	if [[ "$linux_relese" == 'debian' ]]; then
		echo "/tmp/boot/preseed.cfg"
	elif [[ "$linux_relese" == 'alpinelinux' ]]; then
		echo "/tmp/boot/init"
	fi
}

echo -ne "\n[${green}Finish${plain}] Input '${yellow}reboot${plain}' to continue the subsequential installation.\n"
exit 0
