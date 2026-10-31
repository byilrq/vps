#!/usr/bin/env bash
##
## License: GPL
## DD 重装脚本（中文菜单入口）— Debian 12/13 netboot、Ubuntu 22.04/24.04 DD
## 本地引擎和初始化脚本；首次缺文件时从指定 GitHub 仓库补齐整个发行包。
## 用法: bash /root/ddlinux/d.sh [--check|--sync|--help]
## 注意：本文件需先保存到磁盘，不能通过 curl ... | bash 运行。

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR
engineFile="$SCRIPT_DIR/engine.sh"
readonly BUNDLE_BASE_URL='https://raw.githubusercontent.com/byilrq/vps/main/ddlinux'
readonly -a PACKAGE_FILES=(
    d.sh engine.sh ubuntuInit.sh README.md
    CloudInit/dhcp_interfaces.cfg
    CloudInit/ipv4_dhcp_ipv6_static_interfaces.cfg
    CloudInit/ipv4_static_interfaces.cfg
    CloudInit/ipv4_static_ipv6_dhcp_interfaces.cfg
    CloudInit/ipv4_static_ipv6_static_interfaces.cfg
    CloudInit/ipv6_static_interfaces.cfg
)

blue='\033[34m'
yellow='\033[33m'
green='\033[32m'
red='\033[31m'
plain='\033[0m'
sshPORT='2222'
tmpWORD=''
HOSTNAME_SET=''
ARCH='amd64'

show_help() {
    cat <<'HELP'
用法: bash d.sh [选项]
  无参数   进入 Debian 12/13、Ubuntu 22.04/24.04 的安装管理菜单
  --check  离线检查全部本地文件的 SHA256、脚本语法及依赖文件，不写盘、不联网
  --sync   主动从 github.com/byilrq/vps/main/ddlinux 下载完整最新版并校验
  -h, --help  显示本说明

首次只有 d.sh、缺少其它文件时，将自动下载整套文件。已安装的完整文件
优先离线使用，不会每次联网；若校验不通过则阻止安装，使用 --sync 修复。
请先将本压缩包内的整套文件更新到你的 GitHub 仓库，才能启用在线补齐。
警告：确认并重启进入重装环境后，目标磁盘全部数据将被覆盖。
HELP
}

have_sha256sum() {
    command -v sha256sum >/dev/null 2>&1 || {
        printf '[ERROR] 缺少 sha256sum，无法验证文件完整性。\n' >&2
        return 1
    }
}

# SHA256SUMS 的文件列表必须与我们定义的发行包完全一致，不接受路径穿越、重复项或额外文件。
validate_manifest() {
    local manifest="$1" line hash name expected found count=0
    local -A seen=()
    [[ -s "$manifest" && -r "$manifest" ]] || {
        printf '[ERROR] 缺少校验清单: %s\n' "$manifest" >&2
        return 1
    }
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ ${#line} -ge 67 && "${line:64:2}" == '  ' ]] || {
            printf '[ERROR] SHA256SUMS 格式异常。\n' >&2; return 1;
        }
        hash="${line:0:64}"
        name="${line:66}"
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || {
            printf '[ERROR] SHA256SUMS 包含无效哈希。\n' >&2; return 1;
        }
        found=0
        for expected in "${PACKAGE_FILES[@]}"; do
            [[ "$expected" == "$name" ]] && { found=1; break; }
        done
        [[ "$found" -eq 1 && -z "${seen[$name]+x}" ]] || {
            printf '[ERROR] SHA256SUMS 包含意外或重复路径: %s\n' "$name" >&2
            return 1
        }
        seen["$name"]=1
        count=$((count + 1))
    done < "$manifest"
    if [[ "$count" -ne "${#PACKAGE_FILES[@]}" ]]; then
        printf '[ERROR] SHA256SUMS 条目数量不匹配: %s/%s\n' "$count" "${#PACKAGE_FILES[@]}" >&2
        return 1
    fi
    return 0
}

# 只检查；不会写文件或联网。
verify_bundle() {
    local dir="$1" f
    have_sha256sum || return 1
    validate_manifest "$dir/SHA256SUMS" || return 1
    for f in "${PACKAGE_FILES[@]}"; do
        [[ -s "$dir/$f" && -r "$dir/$f" ]] || {
            printf '[ERROR] 缺少本地文件: %s\n' "$dir/$f" >&2
            return 1
        }
    done
    (cd "$dir" && sha256sum -c --status SHA256SUMS) || {
        printf '[ERROR] 文件 SHA256 校验不一致: %s\n' "$dir" >&2
        return 1
    }
    for f in d.sh engine.sh ubuntuInit.sh; do
        bash -n "$dir/$f" || return 1
    done
    bash "$dir/engine.sh" --check || return 1
    return 0
}

# 仅用于判断缺件：只有缺少文件、清单时才自动下载；内容篡改不静默覆盖。
bundle_is_missing() {
    local f
    [[ -s "$SCRIPT_DIR/SHA256SUMS" ]] || return 0
    for f in "${PACKAGE_FILES[@]}"; do
        [[ -s "$SCRIPT_DIR/$f" ]] || return 0
    done
    return 1
}

# 固定下载源；不使用第三方脚本回退，不禁用 TLS 证书验证。
fetch_file() {
    local relative="$1" output="$2"
    local url="$BUNDLE_BASE_URL/$relative"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error \
            --retry 3 --retry-delay 1 --connect-timeout 10 --max-time 90 \
            --proto '=https' --output "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --timeout=30 --tries=3 -q -O "$output" "$url"
    else
        printf '[ERROR] 缺少 curl/wget，无法补齐本地文件。\n' >&2
        return 1
    fi
}

# 所有文件先下载至临时目录并完成校验，失败时不替换原有文件。
# 替换失败时根据事前备份回滚；通过检查才清理旧版 dd.sh / ddlinux.sh。
sync_bundle() {
    local stage backup f target temp failed=0
    have_sha256sum || return 1
    stage="$(mktemp -d "$SCRIPT_DIR/.d-stage.XXXXXXXX")" || return 1
    printf '[INFO] 正在从个人 GitHub 仓库下载完整 ddlinux 项目文件...\n'
    for f in SHA256SUMS "${PACKAGE_FILES[@]}"; do
        mkdir -p "$stage/$(dirname -- "$f")" || { failed=1; break; }
        printf '  获取 %s\n' "$f"
        if ! fetch_file "$f" "$stage/$f"; then
            printf '[ERROR] 下载失败: %s（本地原文件未修改）。\n' "$f" >&2
            failed=1
            break
        fi
    done
    if [[ "$failed" -ne 0 ]] || ! verify_bundle "$stage"; then
        printf '[ERROR] 远程文件不完整、版本未同步或校验失败，已取消更新。\n' >&2
        rm -rf -- "$stage"
        return 1
    fi

    backup="$(mktemp -d "$SCRIPT_DIR/.d-backup.XXXXXXXX")" || { rm -rf -- "$stage"; return 1; }
    for f in "${PACKAGE_FILES[@]}" SHA256SUMS; do
        target="$SCRIPT_DIR/$f"
        if [[ -e "$target" ]]; then
            mkdir -p "$backup/$(dirname -- "$f")" && cp -p -- "$target" "$backup/$f" || {
                printf '[ERROR] 备份原文件失败，未部署。\n' >&2
                rm -rf -- "$stage" "$backup"
                return 1
            }
        fi
    done
    for f in "${PACKAGE_FILES[@]}" SHA256SUMS; do
        target="$SCRIPT_DIR/$f"
        temp="$target.d-new.$$"
        if ! mkdir -p "$(dirname -- "$target")" || \
           ! cp -- "$stage/$f" "$temp" || \
           ! chmod 644 "$temp" || \
           ! mv -f -- "$temp" "$target"; then
            rm -f -- "$temp"
            failed=1
            break
        fi
        [[ "$f" == 'd.sh' ]] && chmod 755 "$target"
    done
    if [[ "$failed" -ne 0 ]] || ! verify_bundle "$SCRIPT_DIR"; then
        printf '[ERROR] 部署失败，正在恢复原文件。\n' >&2
        for f in "${PACKAGE_FILES[@]}" SHA256SUMS; do
            target="$SCRIPT_DIR/$f"
            if [[ -e "$backup/$f" ]]; then
                cp -p -- "$backup/$f" "$target" || {
                    printf '[CRITICAL] 无法恢复: %s\n' "$target" >&2
                }
            else
                rm -f -- "$target"
            fi
        done
        rm -rf -- "$stage" "$backup"
        return 1
    fi

    # 仅清理本项目目录中旧的、已停用的入口和专用初始化文件。
    rm -f -- "$SCRIPT_DIR/dd.sh" "$SCRIPT_DIR/ddlinux.sh"
    rm -rf -- "$stage" "$backup"
    printf '[OK] 已下载并校验完整发行包。旧版 dd.sh / ddlinux.sh 已从本地项目目录清理。\n'
    return 0
}

case "${1:-}" in
    --check)
        [[ $# -eq 1 ]] || { printf '[ERROR] --check 不接受其它参数。\n' >&2; exit 2; }
        verify_bundle "$SCRIPT_DIR" || exit 1
        printf '[OK] d.sh、engine.sh、ubuntuInit.sh、README 与 6 个网络模板校验及语法均通过。\n'
        exit 0 ;;
    --sync)
        [[ $# -eq 1 ]] || { printf '[ERROR] --sync 不接受其它参数。\n' >&2; exit 2; }
        [[ "$EUID" -eq 0 ]] || { printf '[ERROR] --sync 需以 root 执行。\n' >&2; exit 1; }
        sync_bundle || exit 1
        printf '[INFO] 请重新执行 bash "%s/d.sh" 进入菜单。\n' "$SCRIPT_DIR"
        exit 0 ;;
    -h|--help)
        show_help
        exit 0 ;;
    '')
        [[ $# -eq 0 ]] || { show_help >&2; exit 2; } ;;
    *)
        printf '[ERROR] 未知选项: %s\n' "$1" >&2
        show_help >&2
        exit 2 ;;
esac

[[ "$EUID" -eq 0 ]] || { printf '[ERROR] 请以 root 身份运行。\n' >&2; exit 1; }
if bundle_is_missing; then
    printf '[INFO] 检测到缺少完整本地文件，将自动补齐全部文件。\n'
    sync_bundle || {
        printf '[ERROR] 自动补齐失败。请先将新版压缩包完整上传到 GitHub，再执行 bash d.sh --sync。\n' >&2
        exit 1
    }
fi
if ! verify_bundle "$SCRIPT_DIR"; then
    printf '[ERROR] 已阻止安装。请检查本地改动，或运行 bash d.sh --sync 重新同步。\n' >&2
    exit 1
fi

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
# 重装前再次校验本地引擎和初始化文件，防止启动菜单后发生文件变更。
# ============================================================================
load_local_engine() {
    verify_bundle "$SCRIPT_DIR"
}

# ============================================================================
# 固定密码
# ============================================================================


# ============================================================================
# 设置 root 密码与 SSH 端口
# ============================================================================
set_password_port() {
	tmpWORD='123456'
	echo -ne "\n${green}root 密码已固定: ${yellow}${tmpWORD}${plain}\n"

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
# 设置主机名（回车使用默认 debian，通过引擎 -hostname 传入新系统）
# ============================================================================
set_hostname() {
	echo -ne "${green}主机名设置：${plain}\n"
	echo -ne "直接回车使用默认主机名 ${yellow}debian${plain}，或输入自定义主机名: "
	read -e -r input_hostname
	HOSTNAME_SET='debian'
	if [[ -n "$input_hostname" ]]; then
		if [[ "$input_hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
			HOSTNAME_SET="$input_hostname"
		else
			echo -ne "[${red}错误${plain}] 主机名无效（仅限字母数字与中划线），已改用默认 debian\n"
		fi
	fi
	echo -ne "${green}✓ 主机名: ${yellow}${HOSTNAME_SET}${plain}\n"
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
# 网络方式：固定 DHCP（避免静态 IP 格式问题）
# ============================================================================
NET_ARGS=''
check_network() {
	NET_ARGS="--network dhcp"
	echo -ne "${green}✓ 使用 DHCP${plain}\n"
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
	IMG_URL=''

	echo -ne "\n${green}请选择镜像来源:${plain}\n"
		echo -ne "  ${yellow}1${plain}) 默认镜像源（引擎内置 Ubuntu 云镜像）\n"
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

    # The existing Ubuntu image URL selection remains in engine.sh.
    IMG_URL=''
    printf '[OK] Using the built-in Ubuntu image source.\n'
    return 0
}
# ============================================================================
# 调用引擎执行安装
#   Debian: 走引擎原生 preseed 安装分支（-debian 12/13），root 密码由
#           "d-i passwd/root-password-crypted" 在安装阶段直接写入，
#           不依赖 cloud-init，密码/SSH 端口最可靠。
#   Ubuntu: 走引擎云镜像 DD 分支（-ubuntu 22.04/24.04），密码经
#           cloud-init(NoCloud) 注入。
# 参数: $1=OS(Debian/Ubuntu)  $2=版本号(Debian:12/13, Ubuntu:22.04/24.04)
#       $3=可选自定义镜像URL(仅 Ubuntu/DD 有效)
# ============================================================================
run_engine() {
	local os="$1" ver="$2" img="$3"
	local args=()
	if [[ "$os" == "Debian" ]]; then
		args=(-debian "$ver" -port "$sshPORT" -pwd "$tmpWORD" -setdisk "$DISK")
	else
		args=(-ubuntu "$ver" -port "$sshPORT" -pwd "$tmpWORD" -setdisk "$DISK")
		[[ -n "$img" ]] && args+=(-dd "$img")
	fi
	args+=(-hostname "$HOSTNAME_SET")
	# 网络参数（DHCP 或静态）
	[[ -n "$NET_ARGS" ]] && args+=($NET_ARGS)

	echo -ne "\n${blue}即将调用安装引擎，参数如下:${plain}\n"
	echo -ne "  ${yellow}engine.sh ${args[*]}${plain}\n\n"
	bash "$engineFile" "${args[@]}"
}

# ============================================================================
# 安装通用流程
# 参数: $1=OS(Debian/Ubuntu)  $2=代号  $3=版本号(Debian:12/13, Ubuntu:22.04/24.04)
# ============================================================================
setup_dd() {
	local os="$1" dist="$2" ver="$3"

	get_disk || return 1
	check_network || return 1
	set_password_port
	set_hostname
	# Debian 走官方 netboot，不提供自定义镜像；Ubuntu 可以设置镜像直链。
	if [[ "$os" == "Debian" ]]; then
		IMG_URL=''
	else
		select_image_source "$os" "$dist" "$ver" || return 1
	fi

	echo -ne "\n${green}配置确认:${plain}\n"
	echo -ne "  系统:     ${yellow}${os} ${ver}${plain}\n"
	echo -ne "  磁盘:     ${yellow}${DISK}${plain}\n"
	if [[ "$os" == "Debian" ]]; then
		echo -ne "  方式:     ${yellow}官方 netboot + preseed 无人值守安装${plain}\n"
	else
		echo -ne "  镜像:     ${yellow}${IMG_URL:-引擎默认源}${plain}\n"
	fi
	echo -ne "  网络:     ${yellow}${NET_ARGS:---network dhcp}${plain}\n"
	echo -ne "  主机名:   ${yellow}${HOSTNAME_SET}${plain}\n"
	echo -ne "  SSH 端口: ${yellow}${sshPORT}${plain}\n"
	echo -ne "  root 密码: ${yellow}${tmpWORD}${plain}\n\n"
	echo -ne "${red}警告: ${yellow}${DISK}${red} 上的所有数据将被销毁！${plain}\n"
	echo -ne "输入 ${yellow}yes${plain} 确认: "
	read -e -r confirm
	[[ "$confirm" != "yes" ]] && echo -ne "[${yellow}已取消${plain}]\n" && return 1

	echo -ne "${yellow}请务必先保存好上方的 root 密码和 SSH 端口！${plain}\n"
    local engine_status=0
    run_engine "$os" "$ver" "$IMG_URL" || engine_status=$?
    if [[ "$engine_status" -eq 0 ]]; then
        printf '\n%s\n' '安装引导已准备好。确认密码、SSH 端口和备份后，手动执行 reboot 开始重装。'
        printf '%s\n' '重启前可用菜单 3 撤销引导；重装开始后不能撤销磁盘覆写。'
    else
        printf '\n[ERROR] Engine exited with status %s. DO NOT REBOOT; inspect the errors above.\n' "$engine_status" >&2
    fi
    read -e -r -p '按回车键返回主菜单...' || true
    return "$engine_status"
}

setup_debian() {
	echo -ne "\n${green}请选择 Debian 官方网络安装版本:${plain}\n  ${yellow}1${plain}) Debian 12 (bookworm) - netboot\n  ${yellow}2${plain}) Debian 13 (trixie) - netboot\n请输入 (1-2): "
	read -e -r c
	case $c in
	1) load_local_engine && setup_dd "Debian" "bookworm" "12" ;;
	2) load_local_engine && setup_dd "Debian" "trixie" "13" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
}

setup_ubuntu_dd() {
	echo -ne "\n${green}请选择 Ubuntu 版本:${plain}\n  ${yellow}1${plain}) Ubuntu 22.04 (jammy)\n  ${yellow}2${plain}) Ubuntu 24.04 (noble)\n请输入 (1-2): "
	read -e -r c
	case $c in
	1) load_local_engine && setup_dd "Ubuntu" "jammy" "22.04" ;;
	2) load_local_engine && setup_dd "Ubuntu" "noble" "24.04" ;;
	*) echo -ne "[${red}错误${plain}] 选择无效！\n" && return 1 ;;
	esac
}

# ============================================================================
# 清除 DD 参数：撤销引擎写入的 grub 引导项，避免系统反复进入 DD
# ============================================================================
clear_dd_params() {
    printf '\n%s\n' 'Restoring normal GRUB boot; local source and existing kernel files will be retained.'
    local gcfg='' mkconfig='' f
    for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
        [[ -f "$f" ]] && { gcfg="$f"; break; }
    done
    if [[ "$gcfg" == /boot/grub2/* ]] && command -v grub2-mkconfig >/dev/null 2>&1; then
        mkconfig='grub2-mkconfig'
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        mkconfig='grub-mkconfig'
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        mkconfig='grub2-mkconfig'
    fi
    [[ -n "$gcfg" && -n "$mkconfig" ]] || {
        printf '[ERROR] Cannot find GRUB configuration/generator. No files removed.\n' >&2
        return 1
    }
    # Match only entries emitted by this engine, not unrelated custom entries.
    if [[ -f /etc/grub.d/40_custom ]]; then
        sed -i "/^menuentry 'Install \(OS \[\)\?\(Debian\|Ubuntu\|AlpineLinux\) /,/^}/d" /etc/grub.d/40_custom || return 1
    fi
    if [[ -f /etc/default/grub ]]; then
        sed -ri 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub || return 1
    fi
    if command -v grub-set-default >/dev/null 2>&1; then
        grub-set-default 0 || return 1
    elif command -v grub2-set-default >/dev/null 2>&1; then
        grub2-set-default 0 || return 1
    fi
    if command -v grub-editenv >/dev/null 2>&1; then
        grub-editenv - unset next_entry || return 1
    elif command -v grub2-editenv >/dev/null 2>&1; then
        grub2-editenv - unset next_entry || return 1
    fi
    chattr -i "$gcfg" 2>/dev/null || true
    chmod 644 "$gcfg" || return 1
    "$mkconfig" -o "$gcfg" || {
        printf '[ERROR] GRUB regeneration failed. Do not reboot until repaired.\n' >&2
        return 1
    }
    printf '[OK] GRUB regenerated: %s\n' "$gcfg"
    printf '%s\n' 'Local project scripts and existing kernel files have not been deleted.'
    read -e -r -p 'Press Enter to return...' || true
}

# ============================================================================
# 主程序
# ============================================================================
main() {
	dependence
	check_architecture
	while true; do
		[[ -t 1 && -n "${TERM:-}" ]] && clear || true
		echo -ne "\n${blue}==============================${plain}\n"
		echo -ne "${blue}   DD 重装脚本 (Debian/Ubuntu)${plain}\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "  ${yellow}1${plain}) 重装 Debian (12/13，官方 netboot)\n"
		echo -ne "  ${yellow}2${plain}) DD Ubuntu (22.04/24.04)\n"
		echo -ne "  ${yellow}3${plain}) 清除 DD 参数\n"
		echo -ne "  ${yellow}0${plain}) 退出\n"
		echo -ne "${blue}==============================${plain}\n"
		echo -ne "请选择: "
		read -e -r choice || return 0
		case $choice in
		1) setup_debian ;;
		2) setup_ubuntu_dd ;;
		3) clear_dd_params ;;
		0) exit 0 ;;
		*) sleep 1 ;;
		esac
	done
}

main
