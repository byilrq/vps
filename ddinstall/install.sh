#!/bin/bash
##
## License: GPL
## DD 重装脚本（中文菜单前端）- 仅支持 Debian 12~13 / Ubuntu 22~24
## 仓库: https://github.com/byilrq/vps/tree/main/ddinstall
## 用法: bash install.sh
##
## 本脚本仅负责中文交互与参数采集，真正的 Alpine 引导 + DD 写盘
## 由经过验证的引擎 engine.sh 完成（等价于原版 InstallNET.sh）。

repoURL='https://raw.githubusercontent.com/byilrq/vps/main/ddinstall'
workDir='/root/ddinstall'
engineFile="$workDir/engine.sh"

blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'

sshPORT='2222'
tmpWORD=''
ARCH='amd64'

[[ $EUID -ne 0 ]] && echo -ne "\n[${red}错误${plain}] 请以 root 身份运行本脚本！\n\n" && exit 1

# ============================================================================
# 依赖检查
# ============================================================================
dependence() {
	for dep in awk grep sed cut wget curl lsblk ip; do
		type -P "$dep" > /dev/null 2>&1 || {
			echo -ne "[${red}错误${plain}] 缺少命令 '$dep'，请先安装后重试。\n"
			exit 1
		}
	done
}

# ============================================================================
# 检测架构
# ============================================================================
check_architecture() {
	case "$(uname -m)" in
	x86_64) ARCH='amd64' ;;
	aarch64) ARCH='arm64' ;;
	*) echo -ne "[${red}错误${plain}] 不支持的架构: $(uname -m)\n" && exit 1 ;;
	esac
}

# ============================================================================
# 下载引擎（engine.sh）
# ============================================================================
download_engine() {
	mkdir -p "$workDir"
	echo -ne "${blue}正在从 GitHub 下载安装引擎...${plain}\n"
	wget --no-check-certificate -qO "$engineFile" "$repoURL/engine.sh"
	if [[ $? -ne 0 || ! -s "$engineFile" ]]; then
		echo -ne "[${red}错误${plain}] 引擎下载失败，请检查网络或仓库地址。\n"
		return 1
	fi
	echo -ne "${green}✓ 引擎已就绪: ${engineFile}${plain}\n"
	return 0
}

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
	local random_pw
	random_pw=$(gen_password)
	echo -ne "\n${green}root 密码设置：${plain}\n"
	echo -ne "直接回车使用随机密码 ${yellow}${random_pw}${plain}，或输入自定义密码: "
	read -e -r input_pw
	tmpWORD="${input_pw:-$random_pw}"

	echo -ne "${green}SSH 端口设置：${plain}\n"
	echo -ne "直接回车使用默认端口 ${yellow}2222${plain}，或输入自定义端口: "
	read -e -r input_port
	sshPORT='2222'
	if [[ -n "$input_port" ]]; then
		if [[ "$input_port" =~ ^[0-9]+$ && "$input_port" -ge 1 && "$input_port" -le 65535 ]]; then
			sshPORT="$input_port"
		else
			echo -ne "[${red}错误${plain}] 端口无效，已改用默认 2222\n"
		fi
	fi
}
# ============================================================================
# 选择目标磁盘（多盘时让用户选）
# ============================================================================
DISK=''
get_disk() {
	local disk_array
	disk_array=($(lsblk -dpln -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | grep -v 'loop\|sr[0-9]'))
	local disk_count=${#disk_array[@]}
	if [[ $disk_count -eq 0 ]]; then
		echo -ne "[${red}错误${plain}] 未检测到硬盘！\n"
		return 1
	elif [[ $disk_count -eq 1 ]]; then
		DISK="${disk_array[0]}"
		echo -ne "${green}✓ 目标磁盘: ${yellow}$DISK${plain}\n"
	else
		echo -ne "${yellow}检测到多个磁盘:${plain}\n"
		lsblk -dpln -o NAME,SIZE,TYPE | awk '$3=="disk"{print "   "NR") "$1"  "$2}'
		echo -ne "请选择目标磁盘 (1-$disk_count): "
		read -e -r c
		[[ "$c" =~ ^[0-9]+$ && $c -ge 1 && $c -le $disk_count ]] || { echo -ne "[${red}错误${plain}] 选择无效！\n"; return 1; }
		DISK="${disk_array[$((c - 1))]}"
		echo -ne "${green}✓ 目标磁盘: ${yellow}$DISK${plain}\n"
	fi
	return 0
}

# ============================================================================
# 网络方式：DHCP 或保留当前静态 IP
# ============================================================================
NET_ARGS=''
check_network() {
	local adapter gate ipv4 prefix mask
	adapter=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
	gate=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
	ipv4=$(ip -4 addr show "$adapter" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d'/' -f1)
	prefix=$(ip -4 addr show "$adapter" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d'/' -f2)
	if [[ -n "$prefix" ]]; then
		local m=$((0xffffffff << (32 - prefix) & 0xffffffff))
		mask="$((m >> 24 & 255)).$((m >> 16 & 255)).$((m >> 8 & 255)).$((m & 255))"
	fi
	echo -ne "${green}当前网络: ${yellow}${adapter} ${ipv4}/${mask} 网关 ${gate}${plain}\n"
	echo -ne "新系统是否使用 DHCP 自动获取 IP？(回车=y / 输入 n=保留当前静态 IP): "
	read -e -r net_choice
	if [[ "$net_choice" == "n" || "$net_choice" == "no" ]]; then
		[[ -z "$ipv4" || -z "$mask" || -z "$gate" ]] && {
			echo -ne "[${yellow}警告${plain}] 未能识别当前静态 IP，已回退为 DHCP。\n"
			NET_ARGS=''
			return 0
		}
		NET_ARGS="--network static --ip-addr $ipv4 --ip-mask $mask --ip-gate $gate"
		echo -ne "${green}✓ 保留静态 IP: ${yellow}${ipv4}/${mask} 网关 ${gate}${plain}\n"
	else
		NET_ARGS="--network dhcp"
		echo -ne "${green}✓ 使用 DHCP${plain}\n"
	fi
	return 0
}

# ============================================================================
# 校验镜像直链可用性（强制 IPv4，回退 wget/ IPv6）
# ============================================================================
verify_dd_url() {
	local url="$1"
	echo "$url" | grep -q '^http://\|^https://\|^ftp://' || {
		echo -ne "[${red}错误${plain}] 链接无效，仅支持 http/https/ftp！\n"
		return 1
	}
	echo -ne "${blue}正在检查链接可用性...${plain}\n"
	local code
	code=$(curl -4skIL -o /dev/null -w '%{http_code}' --max-time 15 "$url")
	[[ "$code" != "200" ]] && code=$(wget -4 --no-check-certificate --spider -S --timeout=15 "$url" 2>&1 | awk '/HTTP\//{c=$2} END{print c}')
	[[ "$code" != "200" ]] && code=$(curl -6skIL -o /dev/null -w '%{http_code}' --max-time 15 "$url")
	[[ "$code" != "200" ]] && {
		echo -ne "[${red}错误${plain}] 链接无法访问 (HTTP ${code:-000})！\n"
		return 1
	}
	echo -ne "${green}✓ 链接有效${plain}\n"
	return 0
}
# ============================================================================
# 选择镜像来源：1.默认镜像源  2.云盘直链
#   返回：设置全局 IMG_URL（Ubuntu 默认源可留空，交由引擎自动拼接）
# ============================================================================
IMG_URL=''
select_image_source() {
	local os="$1" dist="$2" candidates=()
	IMG_URL=''
	if [[ "$os" == "Debian" ]]; then
		local ver="$3"
		local pkg="debian-${ver}-genericcloud-${ARCH}.raw"
		candidates=(
			"https://gemmei.ftp.acc.umu.se/images/cloud/${dist}/latest/${pkg}"
			"https://saimei.ftp.acc.umu.se/images/cloud/${dist}/latest/${pkg}"
			"https://laotzu.ftp.acc.umu.se/images/cloud/${dist}/latest/${pkg}"
			"https://cdimage.debian.org/images/cloud/${dist}/latest/${pkg}"
		)
	fi

	echo -ne "\n${green}请选择镜像来源:${plain}\n"
	if [[ "$os" == "Debian" ]]; then
		echo -ne "  ${yellow}1${plain}) 默认镜像源（自动测试多个镜像站）\n"
	else
		echo -ne "  ${yellow}1${plain}) 默认镜像源（引擎内置 Ubuntu 云镜像）\n"
	fi
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
		IMG_URL="$image_url"
		return 0
	fi

	# 默认源
	if [[ "$os" == "Ubuntu" ]]; then
		# 留空，交由引擎按版本自动拼接官方转制的 raw 镜像
		IMG_URL=''
		echo -ne "${green}✓ 使用引擎内置 Ubuntu 默认源${plain}\n"
		return 0
	fi
	for image_url in "${candidates[@]}"; do
		echo -ne "${blue}测试镜像: ${image_url}${plain}\n"
		verify_dd_url "$image_url" && { IMG_URL="$image_url"; return 0; }
	done
	echo -ne "[${red}错误${plain}] 所有默认镜像均不可用，请改用云盘直链！\n"
	return 1
}
# ============================================================================
# 调用引擎执行 DD（引擎负责下载 Alpine 内核、改 grub、重启进 Alpine 写盘）
#   引擎的 Ubuntu 云镜像分支是唯一会注入 root 密码/SSH 端口/网络的路径，
#   Debian genericcloud 采用相同的 cloud-init(NoCloud) 机制，故复用该分支。
# 参数: $1=Ubuntu版本号(22.04/24.04)  $2=可选自定义镜像URL
# ============================================================================
run_engine() {
	local ubuntu_ver="$1" img="$2"
	local args=(-ubuntu "$ubuntu_ver" -port "$sshPORT" -pwd "$tmpWORD" -setdisk "$DISK")
	[[ -n "$img" ]] && args+=(-dd "$img")
	# 网络参数（DHCP 或静态）
	[[ -n "$NET_ARGS" ]] && args+=($NET_ARGS)

	echo -ne "\n${blue}即将调用安装引擎，参数如下:${plain}\n"
	echo -ne "  ${yellow}engine.sh ${args[*]}${plain}\n\n"
	bash "$engineFile" "${args[@]}"
}

# ============================================================================
# DD 通用流程
# 参数: $1=OS(Debian/Ubuntu)  $2=代号  $3=版本号(Debian:12/13, Ubuntu:22.04/24.04)
#       $4=映射到引擎的 Ubuntu 版本号(固定 22.04 或 24.04)
# ============================================================================
setup_dd() {
	local os="$1" dist="$2" ver="$3" engine_ubuntu_ver="$4"

	get_disk || return 1
	check_network || return 1
	set_password_port
	select_image_source "$os" "$dist" "$ver" || return 1

	echo -ne "\n${green}配置确认:${plain}\n"
	echo -ne "  系统:     ${yellow}${os} ${ver}${plain}\n"
	echo -ne "  磁盘:     ${yellow}${DISK}${plain}\n"
	echo -ne "  镜像:     ${yellow}${IMG_URL:-引擎默认源}${plain}\n"
	echo -ne "  网络:     ${yellow}${NET_ARGS:---network dhcp}${plain}\n"
	echo -ne "  SSH 端口: ${yellow}${sshPORT}${plain}\n"
	echo -ne "  root 密码: ${yellow}${tmpWORD}${plain}\n\n"
	echo -ne "${red}警告: ${yellow}${DISK}${red} 上的所有数据将被销毁！${plain}\n"
	echo -ne "输入 ${yellow}yes${plain} 确认: "
	read -e -r confirm
	[[ "$confirm" != "yes" ]] && echo -ne "[${yellow}已取消${plain}]\n" && return 1

	echo -ne "${yellow}请务必先保存好上方的 root 密码和 SSH 端口！${plain}\n"
	run_engine "$engine_ubuntu_ver" "$IMG_URL"
	# 引擎成功后会自行 reboot；若返回到此说明未重启（可能出错或被中断）
	echo -ne "\n${yellow}引擎已执行完毕。如未自动重启，请检查上方输出。${plain}\n"
	echo -ne "${yellow}如需取消本次 DD，请重新运行本脚本并选择菜单 3。${plain}\n\n"
	read -e -r -p "按回车键返回主菜单..."
	return 0
}

setup_debian_dd() {
	echo -ne "\n${green}请选择 Debian 版本:${plain}\n  ${yellow}1${plain}) Debian 12 (bookworm)\n  ${yellow}2${plain}) Debian 13 (trixie)\n请输入 (1-2): "
	read -e -r c
	case $c in
	# Debian 复用引擎 Ubuntu 云镜像分支：引擎版本号取 24.04 仅用于走 cloud-init 流程，
	# 实际写盘镜像由 -dd 指定的 Debian raw 决定。
	1) download_engine && setup_dd "Debian" "bookworm" "12" "24.04" ;;
	2) download_engine && setup_dd "Debian" "trixie" "13" "24.04" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
}

setup_ubuntu_dd() {
	echo -ne "\n${green}请选择 Ubuntu 版本:${plain}\n  ${yellow}1${plain}) Ubuntu 22.04 (jammy)\n  ${yellow}2${plain}) Ubuntu 24.04 (noble)\n请输入 (1-2): "
	read -e -r c
	case $c in
	1) download_engine && setup_dd "Ubuntu" "jammy" "22.04" "22.04" ;;
	2) download_engine && setup_dd "Ubuntu" "noble" "24.04" "24.04" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
}

# ============================================================================
# 清除 DD 参数：撤销引擎写入的 grub 引导项，避免系统反复进入 DD
# ============================================================================
clear_dd_params() {
	echo -ne "\n${blue}正在清除 DD 参数...${plain}\n"

	# 1) 删除引擎写入的自定义 grub 菜单项
	if [[ -f /etc/grub.d/40_custom ]]; then
		if grep -q "Install .*Alpine\|Install Debian\|Install Ubuntu\|Install AlpineLinux" /etc/grub.d/40_custom; then
			sed -i '/menuentry .Install /,/^}/d' /etc/grub.d/40_custom
			echo -ne "${green}✓ 已移除 40_custom 中的 DD 引导项${plain}\n"
		fi
	fi

	# 2) 复位默认引导项
	if type -P grub-set-default > /dev/null 2>&1; then
		grub-set-default 0 > /dev/null 2>&1
	elif type -P grub2-set-default > /dev/null 2>&1; then
		grub2-set-default 0 > /dev/null 2>&1
	fi
	if [[ -f /etc/default/grub ]]; then
		sed -ri 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
		echo -ne "${green}✓ 已复位 GRUB_DEFAULT=0${plain}\n"
	fi

	# 3) 重新生成 grub 配置
	local gcfg=''
	for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
		[[ -f "$f" ]] && gcfg="$f" && break
	done
	if [[ -n "$gcfg" ]]; then
		chattr -i "$gcfg" 2>/dev/null
		chmod 644 "$gcfg" 2>/dev/null
		if type -P grub-mkconfig > /dev/null 2>&1; then
			grub-mkconfig -o "$gcfg" > /dev/null 2>&1
		elif type -P grub2-mkconfig > /dev/null 2>&1; then
			grub2-mkconfig -o "$gcfg" > /dev/null 2>&1
		fi
		echo -ne "${green}✓ 已重新生成 ${gcfg}${plain}\n"
	fi

	# 4) 清除引擎下载的临时文件与残留配置
	[[ -f /root/alpine.config ]] && rm -f /root/alpine.config && echo -ne "${green}✓ 已删除 /root/alpine.config${plain}\n"
	rm -f /boot/vmlinuz /boot/initrd.img 2>/dev/null
	[[ -d "$workDir" ]] && rm -rf "$workDir" && echo -ne "${green}✓ 已删除 ${workDir}${plain}\n"

	echo -ne "${green}✓ 清除完成，系统重启后将进入原系统而非 DD。${plain}\n\n"
	read -e -r -p "按回车键返回主菜单..."
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
