#!/bin/bash
##
## License: GPL
## DD 重装脚本 - 仅支持 Debian 12~13 / Ubuntu 22~24
## 仓库: https://github.com/byilrq/vps/tree/main/ddinstall
## 用法: bash install.sh

repoURL='https://raw.githubusercontent.com/byilrq/vps/main/ddinstall'
workDir='/root/ddinstall'
confFile='/root/alpine.config'

blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'

export tmpWORD=''
export sshPORT='2222'
export TimeZone='Asia/Shanghai'
export setIPv6='1'
export IncDisk=''
export DDURL=''
export DEC_CMD=''
export targetRelease=''
export ubuntuDigital=''
export DIST=''
export ubuntuArchitecture='amd64'
export networkAdapter=''
export Network4Config='dhcp'
export IPv4=''
export MASK=''
export GATE=''
export ipDNS1='8.8.8.8'
export ipDNS2='1.1.1.1'
export cloudInitUrl=''

[[ $EUID -ne 0 ]] && echo -ne "\n[${red}错误${plain}] 请以 root 身份运行本脚本！\n\n" && exit 1

# ============================================================================
# 生成 16 位随机密码（含大写、小写、数字、%&*$）
# ============================================================================
gen_password() {
	local pw=''
	while :; do
		pw=$(tr -dc 'A-Za-z0-9%&*$' < /dev/urandom | head -c 16)
		echo "$pw" | grep -q '[A-Z]' || continue
		echo "$pw" | grep -q '[a-z]' || continue
		echo "$pw" | grep -q '[0-9]' || continue
		echo "$pw" | grep -q '[%&*$]' || continue
		break
	done
	echo "$pw"
}

# ============================================================================
# 设置 root 密码与 SSH 端口
# ============================================================================
set_password_port() {
	local random_pw=$(gen_password)
	echo -ne "\n${green}root 密码设置：${plain}\n"
	echo -ne "直接回车使用随机密码 ${yellow}${random_pw}${plain}，或输入自定义密码: "
	read -e -r input_pw
	tmpWORD="${input_pw:-$random_pw}"

	echo -ne "${green}SSH 端口设置：${plain}\n"
	echo -ne "直接回车使用默认端口 ${yellow}2222${plain}，或输入自定义端口: "
	read -e -r input_port
	if [[ -n "$input_port" ]]; then
		[[ "$input_port" =~ ^[0-9]+$ && "$input_port" -ge 1 && "$input_port" -le 65535 ]] || {
			echo -ne "[${red}错误${plain}] 端口无效，已改用默认 2222\n"
			input_port='2222'
		}
		sshPORT="$input_port"
	fi
}

# ============================================================================
# 从 GitHub 仓库下载支持文件
# ============================================================================
download_support_files() {
	mkdir -p "$workDir/CloudInit"
	local files=(
		"CloudInit/dhcp_interfaces.cfg"
		"CloudInit/ipv4_static_interfaces.cfg"
		"CloudInit/ipv4_dhcp_ipv6_static_interfaces.cfg"
		"CloudInit/ipv4_static_ipv6_dhcp_interfaces.cfg"
		"CloudInit/ipv4_static_ipv6_static_interfaces.cfg"
		"CloudInit/ipv6_static_interfaces.cfg"
		"ddlinux.sh"
	)
	echo -ne "${blue}正在从 GitHub 下载支持文件...${plain}\n"
	for f in "${files[@]}"; do
		[[ -s "$workDir/$f" ]] && continue
		wget --no-check-certificate -qO "$workDir/$f" "$repoURL/$f"
		if [[ $? -ne 0 || ! -s "$workDir/$f" ]]; then
			echo -ne "[${yellow}警告${plain}] 下载失败: $f（DD 时将直接使用仓库地址）\n"
			rm -f "$workDir/$f"
		fi
	done
	echo -ne "${green}✓ 支持文件已就绪: $workDir${plain}\n"
}

# ============================================================================
# 检测系统架构
# ============================================================================
check_architecture() {
	case "$(uname -m)" in
	x86_64) ubuntuArchitecture='amd64' ;;
	aarch64) ubuntuArchitecture='arm64' ;;
	*) echo -ne "[${red}错误${plain}] 不支持的架构: $(uname -m)\n" && exit 1 ;;
	esac
}

# ============================================================================
# 检测网络（网卡、IP、网关）
# ============================================================================
check_network() {
	networkAdapter=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
	GATE=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
	IPv4=$(ip -4 addr show "$networkAdapter" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d'/' -f1)
	local prefix=$(ip -4 addr show "$networkAdapter" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d'/' -f2)
	if [[ -n "$prefix" ]]; then
		local m=$((0xffffffff << (32 - prefix) & 0xffffffff))
		MASK="$((m >> 24 & 255)).$((m >> 16 & 255)).$((m >> 8 & 255)).$((m & 255))"
	fi
	echo -ne "${green}当前网络: ${yellow}${networkAdapter} ${IPv4}/${MASK} 网关 ${GATE}${plain}\n"
	echo -ne "新系统是否使用 DHCP 自动获取 IP？(回车=y / 输入 n=保留当前静态 IP): "
	read -e -r net_choice
	if [[ "$net_choice" == "n" || "$net_choice" == "no" ]]; then
		Network4Config='static'
		cloudInitUrl="$repoURL/CloudInit/ipv4_static_interfaces.cfg"
	else
		Network4Config='dhcp'
		cloudInitUrl="$repoURL/CloudInit/dhcp_interfaces.cfg"
	fi
}

# ============================================================================
# 检测目标磁盘
# ============================================================================
get_disk() {
	local disk_array=($(lsblk -dpln -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | grep -v 'loop\|sr[0-9]'))
	local disk_count=${#disk_array[@]}
	if [[ $disk_count -eq 0 ]]; then
		echo -ne "[${red}错误${plain}] 未检测到硬盘！\n" && exit 1
	elif [[ $disk_count -eq 1 ]]; then
		IncDisk="${disk_array[0]}"
		echo -ne "${green}✓ 目标磁盘: ${yellow}$IncDisk${plain}\n"
	else
		echo -ne "${yellow}检测到多个磁盘:${plain}\n"
		lsblk -dpln -o NAME,SIZE,TYPE | awk '$3=="disk"{print "   "NR") "$1"  "$2}'
		echo -ne "请选择目标磁盘 (1-$disk_count): "
		read -e -r c
		[[ $c -ge 1 && $c -le $disk_count ]] || { echo -ne "[${red}错误${plain}] 选择无效！\n"; exit 1; }
		IncDisk="${disk_array[$((c - 1))]}"
		echo -ne "${green}✓ 目标磁盘: ${yellow}$IncDisk${plain}\n"
	fi
}

# ============================================================================
# 校验 DD 镜像直链（pCloud 等）
# ============================================================================
verify_dd_url() {
	local url="$1"
	echo "$url" | grep -q '^http://\|^https://\|^ftp://' || {
		echo -ne "[${red}错误${plain}] 链接无效，仅支持 http/https/ftp！\n"
		return 1
	}
	echo -ne "${blue}正在检查链接可用性...${plain}\n"
	local code=$(curl -4skIL -o /dev/null -w '%{http_code}' --max-time 15 "$url")
	[[ "$code" != "200" ]] && code=$(wget -4 --no-check-certificate --spider -S --timeout=15 "$url" 2>&1 | awk '/HTTP\//{c=$2} END{print c}')
	[[ "$code" != "200" ]] && code=$(curl -6skIL -o /dev/null -w '%{http_code}' --max-time 15 "$url")
	[[ "$code" != "200" ]] && {
		echo -ne "[${red}错误${plain}] 链接无法访问 (HTTP ${code:-000})！\n"
		return 1
	}
	DDURL="$url"
	case "$url" in
	*.xz) DEC_CMD="xzcat" ;;
	*.gz) DEC_CMD="gunzip -dc" ;;
	*) DEC_CMD="cat" ;;
	esac
	echo -ne "${green}✓ 链接有效，解压方式: ${yellow}$DEC_CMD${plain}\n"
	return 0
}

# ============================================================================
# 写入配置文件
# ============================================================================
generate_config() {
	cat > "$confFile" << EOF
ubuntuArchitecture  ${ubuntuArchitecture}
IncDisk  ${IncDisk}
targetRelese  ${targetRelease}
ubuntuDigital  ${ubuntuDigital}
DDURL  ${DDURL}
DEC_CMD  ${DEC_CMD}
tmpWORD  ${tmpWORD}
sshPORT  ${sshPORT}
TimeZone  ${TimeZone}
setIPv6  ${setIPv6}
networkAdapter  ${networkAdapter}
Network4Config  ${Network4Config}
IPv4  ${IPv4}
MASK  ${MASK}
GATE  ${GATE}
ipDNS1  ${ipDNS1}
ipDNS2  ${ipDNS2}
cloudInitUrl  ${cloudInitUrl}
HostName  localhost
EOF
	echo -ne "${green}✓ 配置已写入: ${confFile}${plain}\n"
}

# ============================================================================
# 选择镜像来源：1.默认镜像源  2.云盘直链
# ============================================================================
select_image_source() {
	local candidates=()
	if [[ "$targetRelease" == "Debian" ]]; then
		local pkg="debian-${ubuntuDigital}-genericcloud-${ubuntuArchitecture}.raw"
		candidates=(
			"https://gemmei.ftp.acc.umu.se/images/cloud/${DIST}/latest/${pkg}"
			"https://saimei.ftp.acc.umu.se/images/cloud/${DIST}/latest/${pkg}"
			"https://laotzu.ftp.acc.umu.se/images/cloud/${DIST}/latest/${pkg}"
			"https://cdimage.debian.org/images/cloud/${DIST}/latest/${pkg}"
		)
	else
		candidates=(
			"https://cloud-images.a.disk.re/Ubuntu/${DIST}-server-cloudimg-${ubuntuArchitecture}.xz"
		)
	fi

	echo -ne "\n${green}请选择镜像来源:${plain}\n"
	echo -ne "  ${yellow}1${plain}) 默认镜像源（自动测试多个镜像站）\n"
	echo -ne "  ${yellow}2${plain}) 手动输入云盘直链（pCloud 等）\n"
	echo -ne "请输入 (直接回车=1): "
	read -e -r src_choice

	if [[ "$src_choice" == "2" ]]; then
		echo -ne "${yellow}注意: 云盘直链必须是可直接 DD 写盘的 raw / raw.xz / raw.gz 镜像文件！${plain}\n"
		echo -ne "${yellow}qcow2、img(qcow2)、iso 等格式不能直接 DD。${plain}\n"
		echo -ne "${green}请输入 DD 镜像直链:${plain}\n链接: "
		read -e -r image_url
		[[ -z "$image_url" ]] && echo -ne "[${red}错误${plain}] 链接不能为空！\n" && return 1
		verify_dd_url "$image_url" || return 1
		return 0
	fi

	for image_url in "${candidates[@]}"; do
		echo -ne "${blue}测试镜像: ${image_url}${plain}\n"
		verify_dd_url "$image_url" && return 0
	done
	echo -ne "[${red}错误${plain}] 所有默认镜像均不可用，请改用云盘直链！\n"
	return 1
}

# ============================================================================
# DD 通用配置流程（Debian/Ubuntu 共用）
# ============================================================================
setup_dd() {
	get_disk
	check_network
	set_password_port

	select_image_source || return 1

	echo -ne "\n${green}配置确认:${plain}\n"
	echo -ne "  系统:     ${yellow}${targetRelease} ${ubuntuDigital}${plain}\n"
	echo -ne "  磁盘:     ${yellow}${IncDisk}${plain}\n"
	echo -ne "  镜像:     ${yellow}${DDURL}${plain}\n"
	echo -ne "  网络:     ${yellow}${Network4Config}${plain}\n"
	echo -ne "  SSH 端口: ${yellow}${sshPORT}${plain}\n"
	echo -ne "  root 密码: ${yellow}${tmpWORD}${plain}\n\n"
	echo -ne "${red}警告: ${yellow}${IncDisk}${red} 上的所有数据将被销毁！${plain}\n"
	echo -ne "输入 ${yellow}yes${plain} 确认: "
	read -e -r confirm
	[[ "$confirm" != "yes" ]] && echo -ne "[${yellow}已取消${plain}]\n" && return 1

	download_support_files
	generate_config

	echo -ne "\n${green}✓ ${targetRelease} DD 配置完成，重启后开始自动安装。${plain}\n"
	echo -ne "${yellow}请务必保存好上方的 root 密码和 SSH 端口！${plain}\n"
	echo -ne "${yellow}如需在重启前取消，请重新运行本脚本并选择菜单 3。${plain}\n\n"
	read -e -r -p "按回车键返回主菜单..."
	return 0
}

setup_debian_dd() {
	targetRelease="Debian"
	echo -ne "\n${green}请选择 Debian 版本:${plain}\n  ${yellow}1${plain}) Debian 12 (bookworm)\n  ${yellow}2${plain}) Debian 13 (trixie)\n请输入 (1-2): "
	read -e -r c
	case $c in
	1) DIST="bookworm" && ubuntuDigital="12" ;;
	2) DIST="trixie" && ubuntuDigital="13" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
	setup_dd
}

setup_ubuntu_dd() {
	targetRelease="Ubuntu"
	echo -ne "\n${green}请选择 Ubuntu 版本:${plain}\n  ${yellow}1${plain}) Ubuntu 22.04 (jammy)\n  ${yellow}2${plain}) Ubuntu 24.04 (noble)\n请输入 (1-2): "
	read -e -r c
	case $c in
	1) DIST="jammy" && ubuntuDigital="22.04" ;;
	2) DIST="noble" && ubuntuDigital="24.04" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
	setup_dd
}

# ============================================================================
# 清除 DD 参数（避免系统反复进入 DD）
# ============================================================================
clear_dd_params() {
	echo -ne "\n${blue}正在清除 DD 参数...${plain}\n"
	[[ -f "$confFile" ]] && rm -f "$confFile" && echo -ne "${green}✓ 已删除 ${confFile}${plain}\n"
	[[ -d "$workDir" ]] && rm -rf "$workDir" && echo -ne "${green}✓ 已删除 ${workDir}${plain}\n"
	echo -ne "${green}✓ 清除完成，系统将正常启动。${plain}\n\n"
	read -e -r -p "按回车键返回主菜单..."
}

# ============================================================================
# 依赖检查
# ============================================================================
dependence() {
	for dep in awk grep sed cut wget curl lsblk ip; do
		type -P "$dep" > /dev/null 2>&1 || {
			echo -ne "[${red}错误${plain}] 缺少命令 '$dep'，请先安装。\n"
			exit 1
		}
	done
}

# ============================================================================
# 主程序
# ============================================================================
main() {
	dependence
	check_architecture
	while true; do
		clear
		echo -ne "\n${blue}==============================${plain}\n"
		echo -ne "${blue}   DD 重装脚本 (Debian/Ubuntu)${plain}\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "  ${yellow}1${plain}) DD Debian (12/13)\n"
		echo -ne "  ${yellow}2${plain}) DD Ubuntu (22.04/24.04)\n"
		echo -ne "  ${yellow}3${plain}) 清除 DD 参数\n"
		echo -ne "  ${yellow}0${plain}) 退出\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "请选择: "
		read -e -r choice
		case $choice in
		1) setup_debian_dd ;;
		2) setup_ubuntu_dd ;;
		3) clear_dd_params ;;
		0) exit 0 ;;
		*) sleep 1 ;;
		esac
	done
}

main
