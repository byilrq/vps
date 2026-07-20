#!/bin/bash
##
## License: GPL
## Simplified DD Installer Script - Support Debian 12~13, Ubuntu 22~24 Only
## Based on InstallNET.sh by MoeClub.org
## Simplified Version with Interactive Menu
## Default root password: LeitboGi0ro

# ============================================================================
# Color Definitions
# ============================================================================
underLine='\033[4m'
aoiBlue='\033[36m'
blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'

# ============================================================================
# Global Variables
# ============================================================================
export tmpDIST=''
export tmpURL=''
export tmpWORD='LeitboGi0ro'
export tmpMirror=''
export targetRelease=''
export VER='amd64'
export TimeZone='UTC'
export IncDisk=''
export interface=''
export setInterfaceName='0'
export autoPlugAdapter='1'
export IsCN=''
export Relese=''
export DIST=''
export finalDIST=''
export sshPORT='22'
export ddMode='0'
export setNet='0'
export ipAddr=''
export ipMask=''
export ipGate=''
export ipDNS='8.8.8.8 1.1.1.1'
export setIPv6='1'
export ip6Addr=''
export ip6Mask=''
export ip6Gate=''
export ip6DNS='2001:4860:4860::8888 2606:4700:4700::1111'
export DDURL=''
export DEC_CMD=''
export ubuntuArchitecture='amd64'
export ubuntuDigital=''
export partitionTable='mbr'
export setMemCheck='1'
export LANG="en_US.UTF-8"
export LANGUAGE="en_US:en"

# ============================================================================
# Check Root Permission
# ============================================================================
if [[ $EUID -ne 0 ]]; then
	echo -ne "\n[${red}Error${plain}] This script must be run as root! \n\n"
	exit 1
fi

# ============================================================================
# Function: Show Main Menu
# ============================================================================
show_main_menu() {
	clear
	echo -ne "\n${blue}========================================${plain}\n"
	echo -ne "${blue}    DD Linux Installer${plain}\n"
	echo -ne "${blue}    Support: Debian 12~13, Ubuntu 22~24${plain}\n"
	echo -ne "${blue}========================================${plain}\n\n"
	echo -ne "${green}Please select an option:${plain}\n"
	echo -ne "  ${yellow}1${plain}) DD Debian (12/13)\n"
	echo -ne "  ${yellow}2${plain}) DD Ubuntu (22.04/24.04)\n"
	echo -ne "  ${yellow}3${plain}) Clear DD Parameters\n"
	echo -ne "  ${yellow}0${plain}) Exit\n\n"
	echo -ne "${blue}========================================${plain}\n"
	echo -ne "Enter your choice: "
}

# ============================================================================
# Function: Clear DD Parameters
# ============================================================================
clear_dd_params() {
	echo -ne "\n${blue}Clearing DD parameters...${plain}\n"

	# Remove the alpine.config file if it exists
	if [[ -f /root/alpine.config ]]; then
		rm -f /root/alpine.config
		echo -ne "${green}✓${plain} Configuration file cleared: /root/alpine.config\n"
	fi

	# Clear DD-related environment variables
	export DDURL=""
	export DEC_CMD=""
	export ddMode='0'
	export tmpURL=""

	echo -ne "${green}✓${plain} DD parameters have been cleared\n"
	echo -ne "${green}✓${plain} System can proceed without DD configuration\n\n"

	read -p "Press Enter to return to main menu..."
	return 0
}

# ============================================================================
# Function: Check Dependencies
# ============================================================================
dependence() {
	local dep_array=(
		'awk'
		'grep'
		'sed'
		'cut'
		'wget'
		'curl'
		'xz'
		'parted'
		'fdisk'
		'sfdisk'
		'printf'
		'mktemp'
		'losetup'
		'blockdev'
		'kpartx'
	)

	for ((i = 0; i < ${#dep_array[@]}; i++)); do
		type -P "${dep_array[$i]}" > /dev/null 2>&1
		[[ $? -ne 0 ]] && {
			echo -ne "[${red}Error${plain}] ${dep_array[$i]} is not installed.\n"
			echo -ne "[${red}Error${plain}] Please use 'apt-get' or 'yum' to install it.\n\n"
			exit 1
		}
	done
}

# ============================================================================
# Function: Get System Architecture
# ============================================================================
check_architecture() {
	VER=$(uname -m)
	if [[ "$VER" == "x86_64" ]]; then
		VER="amd64"
		ubuntuArchitecture="amd64"
	elif [[ "$VER" == "aarch64" ]]; then
		VER="arm64"
		ubuntuArchitecture="arm64"
	fi

	echo -ne "${green}System Architecture: ${yellow}$VER${plain}\n"
}

# ============================================================================
# Function: Get Primary Hard Disk
# ============================================================================
get_disk() {
	echo -ne "\n${blue}Detecting hard disk...${plain}\n"

	# Get list of available disks
	local disks=$(lsblk -dplnx name,size | grep -v "loop" | awk '{print $1}')
	local disk_count=0
	local disk_array=()

	for disk in $disks; do
		disk_count=$((disk_count + 1))
		disk_array+=("$disk")
	done

	if [[ $disk_count -eq 0 ]]; then
		echo -ne "[${red}Error${plain}] No hard disk found!\n"
		exit 1
	elif [[ $disk_count -eq 1 ]]; then
		IncDisk="${disk_array[0]}"
		echo -ne "${green}✓ Disk detected: ${yellow}$IncDisk${plain}\n"
	else
		echo -ne "${yellow}Multiple disks found:${plain}\n"
		for ((i = 0; i < disk_count; i++)); do
			echo -ne "  ${yellow}$((i+1))${plain}) ${disk_array[$i]}\n"
		done
		echo -ne "Select target disk (1-$disk_count): "
		read -r disk_choice

		if [[ $disk_choice -ge 1 && $disk_choice -le $disk_count ]]; then
			IncDisk="${disk_array[$((disk_choice-1))]}"
			echo -ne "${green}✓ Target disk: ${yellow}$IncDisk${plain}\n"
		else
			echo -ne "[${red}Error${plain}] Invalid disk selection!\n"
			exit 1
		fi
	fi
}

# ============================================================================
# Function: Verify DD Image URL
# ============================================================================
verify_url_validation_of_dd_images() {
	local url="$1"

	# Check URL format
	echo "$url" | grep -q '^http://\|^ftp://\|^https://'
	if [[ $? -ne 0 ]]; then
		echo -ne "\n[${red}Error${plain}] Invalid URL format!\n"
		echo -ne "[${red}Error${plain}] Only support http://, https:// or ftp:// URLs\n"
		return 1
	fi

	# Check URL accessibility
	echo -ne "${blue}Checking URL accessibility...${plain}\n"
	tmpURLCheck=$(echo $(curl -s -I -X GET "$url") | grep -wi "http/[0-9]*" | awk '{print $2}')
	if [[ $tmpURLCheck != "200" ]]; then
		echo -ne "[${red}Error${plain}] Cannot access the image URL!\n"
		echo -ne "[${red}Error${plain}] HTTP Response: $tmpURLCheck\n"
		return 1
	fi

	DDURL="$url"

	# Determine decompression command
	if [[ "$DDURL" == *.xz ]]; then
		DEC_CMD="xzcat"
	elif [[ "$DDURL" == *.gz ]]; then
		DEC_CMD="gunzip -dc"
	else
		# Try to guess based on content
		DEC_CMD="xzcat"
	fi

	echo -ne "${green}✓ URL is valid${plain}\n"
	echo -ne "${green}✓ Decompression method: ${yellow}$DEC_CMD${plain}\n"
	return 0
}

# ============================================================================
# Function: Select Mirror
# ============================================================================
select_mirror() {
	local release="$1"
	local dist="$2"
	local ver="$3"

	release=$(echo "$release" | sed -r 's/(.*)/\L\1/')
	dist=$(echo "$dist" | sed 's/\ //g' | sed -r 's/(.*)/\L\1/')

	local mirror_status=0
	declare -A mirror_backup

	# Define mirror sources
	if [[ "$IsCN" == "cn" ]]; then
		mirror_backup=(
			["debian0"]=""
			["debian1"]="http://mirror.sjtu.edu.cn/debian"
			["debian2"]="http://mirror.nju.edu.cn/debian"
			["debian3"]="https://mirrors.tuna.tsinghua.edu.cn/debian"
			["ubuntu0"]=""
			["ubuntu1"]="https://mirrors.ustc.edu.cn/ubuntu"
			["ubuntu2"]="http://mirrors.xjtu.edu.cn/ubuntu"
		)
	else
		mirror_backup=(
			["debian0"]=""
			["debian1"]="http://deb.debian.org/debian"
			["debian2"]="http://mirrors.ocf.berkeley.edu/debian"
			["debian3"]="http://ftp.yz.yamagata-u.ac.jp/pub/linux/debian"
			["ubuntu0"]=""
			["ubuntu1"]="http://archive.ubuntu.com/ubuntu"
			["ubuntu2"]="http://ports.ubuntu.com"
		)
	fi

	# Use custom mirror if provided
	if echo "$tmpMirror" | grep -q '^http://\|^https://\|^ftp://'; then
		mirror_backup[${release}0]="${tmpMirror%*/}"
	fi

	# Test mirrors
	for mirror_key in $(echo "${!mirror_backup[@]}" | sed 's/\ /\n/g' | sort -n); do
		[[ ! "$mirror_key" =~ ^"$release" ]] && continue

		local current="${mirror_backup[$mirror_key]}"
		[[ -z "$current" ]] && continue

		# Simple mirror test
		wget --no-check-certificate --spider --timeout=3 -o /dev/null "$current" 2>/dev/null
		if [[ $? -eq 0 ]]; then
			mirror_status=1
			echo -ne "${green}✓ Using mirror: ${yellow}$current${plain}\n"
			echo "$current"
			return 0
		fi
	done

	if [[ $mirror_status -eq 0 ]]; then
		echo -ne "[${red}Error${plain}] No available mirror found!\n"
		return 1
	fi
}

# ============================================================================
# Function: Generate alpine.config
# ============================================================================
generate_config() {
	echo -ne "${blue}Generating configuration file...${plain}\n"

	cat > /root/alpine.config << EOF
# DD System Configuration File
# Generated automatically

# System Architecture
ubuntuArchitecture  ${ubuntuArchitecture}

# Target Disk
IncDisk  ${IncDisk}

# Target System Information
targetRelese  ${targetRelease}
ubuntuDigital  ${ubuntuDigital}

# DD Image URL and Decompression
DDURL  ${DDURL}
DEC_CMD  ${DEC_CMD}

# Root Password
tmpWORD  ${tmpWORD}

# SSH Configuration
sshPORT  ${sshPORT}

# Network Configuration (optional, can be configured in target system)
setIPv6  ${setIPv6}

# Timezone
TimeZone  ${TimeZone}

# Network Interface
networkAdapter

# IP Configuration Method (dhcp or static)
Network4Config

# IPv4 Configuration
IPv4
MASK
GATE

# IPv6 Configuration
setIPv6  ${setIPv6}

EOF

	echo -ne "${green}✓ Configuration file generated: /root/alpine.config${plain}\n"
}

# ============================================================================
# Function: Setup Debian DD
# ============================================================================
setup_debian_dd() {
	clear
	echo -ne "\n${blue}========== DD Debian Setup ==========${plain}\n"

	Relese="Debian"
	targetRelease="Debian"
	ddMode='1'

	# Ask for Debian version
	echo -ne "\n${green}Select Debian version:${plain}\n"
	echo -ne "  ${yellow}1${plain}) Debian 12 (bookworm)\n"
	echo -ne "  ${yellow}2${plain}) Debian 13 (trixie)\n"
	echo -ne "Enter your choice (1-2): "
	read -r debian_choice

	case $debian_choice in
		1)
			tmpDIST="12"
			DIST="bookworm"
			ubuntuDigital="12"
			echo -ne "${green}✓ Selected: Debian 12 (bookworm)${plain}\n"
			;;
		2)
			tmpDIST="13"
			DIST="trixie"
			ubuntuDigital="13"
			echo -ne "${green}✓ Selected: Debian 13 (trixie)${plain}\n"
			;;
		*)
			echo -ne "[${red}Error${plain}] Invalid selection!\n"
			return 1
			;;
	esac

	# Get disk selection
	get_disk

	# Input custom mirror URL
	echo -ne "\n${green}Debian Mirror Source Configuration${plain}\n"
	echo -ne "You can use default mirror or provide a custom pcloud direct link.\n"
	echo -ne "Leave empty to use default mirror.\n"
	echo -ne "Enter mirror URL (or press Enter for default): "
	read -r custom_mirror

	if [[ -n "$custom_mirror" ]]; then
		tmpMirror="$custom_mirror"
	fi

	# Select mirror
	select_mirror "Debian" "$DIST" "$VER" > /dev/null

	# Input DD image URL
	echo -ne "\n${green}Enter DD Image URL${plain}\n"
	echo -ne "This should be a direct link to Debian DD image (pcloud or other source)\n"
	echo -ne "URL: "
	read -r image_url

	if [[ -z "$image_url" ]]; then
		echo -ne "[${red}Error${plain}] Image URL cannot be empty!\n"
		return 1
	fi

	verify_url_validation_of_dd_images "$image_url"
	if [[ $? -ne 0 ]]; then
		return 1
	fi

	echo -ne "\n${green}Configuration Summary:${plain}\n"
	echo -ne "  System: ${yellow}Debian ${ubuntuDigital}${plain}\n"
	echo -ne "  Target Disk: ${yellow}${IncDisk}${plain}\n"
	echo -ne "  Image URL: ${yellow}${DDURL}${plain}\n"
	echo -ne "  Decompression: ${yellow}${DEC_CMD}${plain}\n"
	echo -ne "  Root Password: ${yellow}${tmpWORD}${plain}\n\n"

	echo -ne "${red}WARNING: This will overwrite all data on ${yellow}${IncDisk}${red}!${plain}\n"
	echo -ne "Continue? (yes/no): "
	read -r confirm

	if [[ "$confirm" != "yes" ]]; then
		echo -ne "[${yellow}Cancelled${plain}] Installation aborted.\n"
		return 1
	fi

	generate_config

	echo -ne "\n${green}✓ Debian DD setup completed!${plain}\n"
	echo -ne "${blue}Next steps:${plain}\n"
	echo -ne "  1. Reboot the system\n"
	echo -ne "  2. The system will start Alpine Linux\n"
	echo -ne "  3. Debian will be automatically installed via DD\n"
	echo -ne "  4. After installation, the system will reboot into Debian\n\n"

	read -p "Press Enter to return to main menu..."
	return 0
}

# ============================================================================
# Function: Setup Ubuntu DD
# ============================================================================
setup_ubuntu_dd() {
	clear
	echo -ne "\n${blue}========== DD Ubuntu Setup ==========${plain}\n"

	Relese="Ubuntu"
	targetRelease="Ubuntu"
	ddMode='1'

	# Ask for Ubuntu version
	echo -ne "\n${green}Select Ubuntu version:${plain}\n"
	echo -ne "  ${yellow}1${plain}) Ubuntu 22.04 LTS (jammy)\n"
	echo -ne "  ${yellow}2${plain}) Ubuntu 24.04 LTS (noble)\n"
	echo -ne "Enter your choice (1-2): "
	read -r ubuntu_choice

	case $ubuntu_choice in
		1)
			tmpDIST="22.04"
			finalDIST="22.04"
			DIST="jammy"
			ubuntuDigital="22.04"
			echo -ne "${green}✓ Selected: Ubuntu 22.04 LTS (jammy)${plain}\n"
			;;
		2)
			tmpDIST="24.04"
			finalDIST="24.04"
			DIST="noble"
			ubuntuDigital="24.04"
			echo -ne "${green}✓ Selected: Ubuntu 24.04 LTS (noble)${plain}\n"
			;;
		*)
			echo -ne "[${red}Error${plain}] Invalid selection!\n"
			return 1
			;;
	esac

	# Get disk selection
	get_disk

	# Input custom mirror URL
	echo -ne "\n${green}Ubuntu Mirror Source Configuration${plain}\n"
	echo -ne "You can use default Ubuntu cloud-images or provide a custom pcloud direct link.\n"
	echo -ne "Leave empty to use default cloud-images mirror.\n"
	echo -ne "Enter mirror URL (or press Enter for default): "
	read -r custom_mirror

	if [[ -n "$custom_mirror" ]]; then
		tmpMirror="$custom_mirror"
	fi

	# Input DD image URL
	echo -ne "\n${green}Enter DD Image URL${plain}\n"
	echo -ne "Examples:\n"
	echo -ne "  - https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img.xz\n"
	echo -ne "  - pcloud direct link to Ubuntu image\n"
	echo -ne "URL: "
	read -r image_url

	if [[ -z "$image_url" ]]; then
		# Try to use default Ubuntu cloud-images
		echo -ne "${yellow}Using default Ubuntu cloud-images...${plain}\n"
		image_url="https://cloud-images.ubuntu.com/${DIST}/current/${DIST}-server-cloudimg-amd64.img.xz"
	fi

	verify_url_validation_of_dd_images "$image_url"
	if [[ $? -ne 0 ]]; then
		return 1
	fi

	echo -ne "\n${green}Configuration Summary:${plain}\n"
	echo -ne "  System: ${yellow}Ubuntu ${ubuntuDigital}${plain}\n"
	echo -ne "  Target Disk: ${yellow}${IncDisk}${plain}\n"
	echo -ne "  Image URL: ${yellow}${DDURL}${plain}\n"
	echo -ne "  Decompression: ${yellow}${DEC_CMD}${plain}\n"
	echo -ne "  Root Password: ${yellow}${tmpWORD}${plain}\n\n"

	echo -ne "${red}WARNING: This will overwrite all data on ${yellow}${IncDisk}${red}!${plain}\n"
	echo -ne "Continue? (yes/no): "
	read -r confirm

	if [[ "$confirm" != "yes" ]]; then
		echo -ne "[${yellow}Cancelled${plain}] Installation aborted.\n"
		return 1
	fi

	generate_config

	echo -ne "\n${green}✓ Ubuntu DD setup completed!${plain}\n"
	echo -ne "${blue}Next steps:${plain}\n"
	echo -ne "  1. Reboot the system\n"
	echo -ne "  2. The system will start Alpine Linux\n"
	echo -ne "  3. Ubuntu will be automatically installed via DD\n"
	echo -ne "  4. After installation, the system will reboot into Ubuntu\n\n"

	read -p "Press Enter to return to main menu..."
	return 0
}

# ============================================================================
# Main Program
# ============================================================================
main() {
	# Check dependencies
	dependence

	# Check system architecture
	check_architecture

	# Check if running on Chinese network
	ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1 || IsCN='cn'

	# Main loop
	while true; do
		show_main_menu
		read -r choice

		case $choice in
			1)
				setup_debian_dd
				;;
			2)
				setup_ubuntu_dd
				;;
			3)
				clear_dd_params
				;;
			0)
				echo -ne "\n${blue}Exiting...${plain}\n\n"
				exit 0
				;;
			*)
				echo -ne "[${red}Error${plain}] Invalid choice! Please try again.\n"
				sleep 2
				;;
		esac
	done
}

# Run main program
main
