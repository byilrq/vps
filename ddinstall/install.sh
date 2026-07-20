#!/bin/bash
##
## License: GPL
## DD Installer - Debian 12~13, Ubuntu 22~24 Only
## Repo: https://github.com/byilrq/vps/tree/main/ddinstall
## Usage: bash install.sh
## Default root password: LeitboGi0ro

repoURL='https://raw.githubusercontent.com/byilrq/vps/main/ddinstall'
workDir='/root/ddinstall'
confFile='/root/alpine.config'

blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'

export tmpWORD='LeitboGi0ro'
export sshPORT='22'
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

[[ $EUID -ne 0 ]] && echo -ne "\n[${red}Error${plain}] This script must be run as root!\n\n" && exit 1

# ============================================================================
# Download support files from GitHub repo
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
		"ubuntuInit.sh"
	)
	echo -ne "${blue}Downloading support files from GitHub...${plain}\n"
	for f in "${files[@]}"; do
		[[ -s "$workDir/$f" ]] && continue
		wget --no-check-certificate -qO "$workDir/$f" "$repoURL/$f"
		if [[ $? -ne 0 || ! -s "$workDir/$f" ]]; then
			echo -ne "[${yellow}Warn${plain}] Failed to download: $f (will use repo URL at DD time)\n"
			rm -f "$workDir/$f"
		fi
	done
	echo -ne "${green}✓ Support files ready: $workDir${plain}\n"
}

# ============================================================================
# Detect architecture
# ============================================================================
check_architecture() {
	case "$(uname -m)" in
	x86_64) ubuntuArchitecture='amd64' ;;
	aarch64) ubuntuArchitecture='arm64' ;;
	*) echo -ne "[${red}Error${plain}] Unsupported architecture: $(uname -m)\n" && exit 1 ;;
	esac
}

# ============================================================================
# Detect network (adapter, IP, gateway)
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
	echo -ne "${green}Network: ${yellow}${networkAdapter} ${IPv4}/${MASK} gw ${GATE}${plain}\n"
	echo -ne "Use DHCP in new system? (Enter=yes / n=keep static IP): "
	read -r net_choice
	if [[ "$net_choice" == "n" || "$net_choice" == "no" ]]; then
		Network4Config='static'
		cloudInitUrl="$repoURL/CloudInit/ipv4_static_interfaces.cfg"
	else
		Network4Config='dhcp'
		cloudInitUrl="$repoURL/CloudInit/dhcp_interfaces.cfg"
	fi
}

# ============================================================================
# Detect target disk
# ============================================================================
get_disk() {
	local disk_array=($(lsblk -dpln -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | grep -v 'loop\|sr[0-9]'))
	local disk_count=${#disk_array[@]}
	if [[ $disk_count -eq 0 ]]; then
		echo -ne "[${red}Error${plain}] No hard disk found!\n" && exit 1
	elif [[ $disk_count -eq 1 ]]; then
		IncDisk="${disk_array[0]}"
		echo -ne "${green}✓ Disk: ${yellow}$IncDisk${plain}\n"
	else
		echo -ne "${yellow}Multiple disks found:${plain}\n"
		lsblk -dpln -o NAME,SIZE,TYPE | awk '$3=="disk"{print "   "NR") "$1"  "$2}'
		echo -ne "Select target disk (1-$disk_count): "
		read -r c
		[[ $c -ge 1 && $c -le $disk_count ]] || { echo -ne "[${red}Error${plain}] Invalid selection!\n"; exit 1; }
		IncDisk="${disk_array[$((c - 1))]}"
		echo -ne "${green}✓ Disk: ${yellow}$IncDisk${plain}\n"
	fi
}

# ============================================================================
# Verify pCloud/direct DD image URL
# ============================================================================
verify_dd_url() {
	local url="$1"
	echo "$url" | grep -q '^http://\|^https://\|^ftp://' || {
		echo -ne "[${red}Error${plain}] Invalid URL, only http/https/ftp supported!\n"
		return 1
	}
	echo -ne "${blue}Checking URL...${plain}\n"
	local code=$(curl -sIL -o /dev/null -w '%{http_code}' --max-time 15 "$url")
	[[ "$code" != "200" ]] && {
		echo -ne "[${red}Error${plain}] URL not accessible (HTTP $code)!\n"
		return 1
	}
	DDURL="$url"
	case "$url" in
	*.xz) DEC_CMD="xzcat" ;;
	*.gz) DEC_CMD="gunzip -dc" ;;
	*) DEC_CMD="cat" ;;
	esac
	echo -ne "${green}✓ URL OK, decompress: ${yellow}$DEC_CMD${plain}\n"
	return 0
}

# ============================================================================
# Write config file
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
	echo -ne "${green}✓ Config written: ${confFile}${plain}\n"
}

# ============================================================================
# Common DD setup (called by Debian/Ubuntu entries)
# ============================================================================
setup_dd() {
	get_disk
	check_network

	echo -ne "\n${green}Enter DD image URL (pCloud direct link):${plain}\n"
	echo -ne "URL: "
	read -r image_url
	[[ -z "$image_url" ]] && echo -ne "[${red}Error${plain}] URL cannot be empty!\n" && return 1
	verify_dd_url "$image_url" || return 1

	echo -ne "\n${green}Summary:${plain}\n"
	echo -ne "  System:   ${yellow}${targetRelease} ${ubuntuDigital}${plain}\n"
	echo -ne "  Disk:     ${yellow}${IncDisk}${plain}\n"
	echo -ne "  Image:    ${yellow}${DDURL}${plain}\n"
	echo -ne "  Network:  ${yellow}${Network4Config}${plain}\n"
	echo -ne "  Password: ${yellow}${tmpWORD}${plain}\n\n"
	echo -ne "${red}WARNING: ALL data on ${yellow}${IncDisk}${red} will be DESTROYED!${plain}\n"
	echo -ne "Type ${yellow}yes${plain} to confirm: "
	read -r confirm
	[[ "$confirm" != "yes" ]] && echo -ne "[${yellow}Cancelled${plain}]\n" && return 1

	download_support_files
	generate_config

	echo -ne "\n${green}✓ ${targetRelease} DD configured. Reboot to start installation.${plain}\n"
	echo -ne "${yellow}To cancel before reboot, run this script and choose menu 3.${plain}\n\n"
	read -p "Press Enter to return to menu..."
	return 0
}

setup_debian_dd() {
	targetRelease="Debian"
	echo -ne "\n${green}Select Debian version:${plain}\n  ${yellow}1${plain}) Debian 12 (bookworm)\n  ${yellow}2${plain}) Debian 13 (trixie)\nChoice (1-2): "
	read -r c
	case $c in
	1) DIST="bookworm" && ubuntuDigital="12" ;;
	2) DIST="trixie" && ubuntuDigital="13" ;;
	*) echo -ne "[${red}Error${plain}] Invalid selection!\n" && return 1 ;;
	esac
	setup_dd
}

setup_ubuntu_dd() {
	targetRelease="Ubuntu"
	echo -ne "\n${green}Select Ubuntu version:${plain}\n  ${yellow}1${plain}) Ubuntu 22.04 (jammy)\n  ${yellow}2${plain}) Ubuntu 24.04 (noble)\nChoice (1-2): "
	read -r c
	case $c in
	1) DIST="jammy" && ubuntuDigital="22.04" ;;
	2) DIST="noble" && ubuntuDigital="24.04" ;;
	*) echo -ne "[${red}Error${plain}] Invalid selection!\n" && return 1 ;;
	esac
	setup_dd
}

# ============================================================================
# Clear DD parameters (prevent repeated DD boot)
# ============================================================================
clear_dd_params() {
	echo -ne "\n${blue}Clearing DD parameters...${plain}\n"
	[[ -f "$confFile" ]] && rm -f "$confFile" && echo -ne "${green}✓ Removed ${confFile}${plain}\n"
	[[ -d "$workDir" ]] && rm -rf "$workDir" && echo -ne "${green}✓ Removed ${workDir}${plain}\n"
	echo -ne "${green}✓ Done. System will boot normally.${plain}\n\n"
	read -p "Press Enter to return to menu..."
}

# ============================================================================
# Dependencies
# ============================================================================
dependence() {
	for dep in awk grep sed cut wget curl lsblk ip; do
		type -P "$dep" > /dev/null 2>&1 || {
			echo -ne "[${red}Error${plain}] '$dep' is not installed, please install it first.\n"
			exit 1
		}
	done
}

# ============================================================================
# Main
# ============================================================================
main() {
	dependence
	check_architecture
	while true; do
		clear
		echo -ne "\n${blue}==============================${plain}\n"
		echo -ne "${blue}  DD Installer (Debian/Ubuntu)${plain}\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "  ${yellow}1${plain}) DD Debian (12/13)\n"
		echo -ne "  ${yellow}2${plain}) DD Ubuntu (22.04/24.04)\n"
		echo -ne "  ${yellow}3${plain}) Clear DD parameters\n"
		echo -ne "  ${yellow}0${plain}) Exit\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "Choice: "
		read -r choice
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
