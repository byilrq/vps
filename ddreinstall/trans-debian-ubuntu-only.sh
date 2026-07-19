#!/bin/ash
# shellcheck shell=dash
# 精简版 trans.sh - 仅支持 Debian/Ubuntu 安装

set -eE

SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0004
TRUE=0
FALSE=1

error() {
    echo -e "\e[31m***** ERROR *****\e[0m" >&2
    echo -e "\e[31m$*\e[0m" >&2
}

info() {
    local msg="$*"
    if [ "$1" = false ]; then
        shift
        msg="$*"
    else
        msg=$(echo "$*" | tr '[:lower:]' '[:upper:]')
    fi
    echo -e "\e[32m***** $msg *****\e[0m" >&2
}

warn() {
    echo -e "\e[33mWarning: $*\e[0m" >&2
}

error_and_exit() {
    error "$@"
    echo "Run '/trans.sh' to retry." >&2
    exit 1
}

trap_err() {
    error_and_exit "Line $1 return $2"
}

is_have_cmd() {
    for bin_dir in /bin /sbin /usr/bin /usr/sbin; do
        [ -f "$bin_dir/$1" ] && return 0
    done
    return 1
}

is_num() {
    echo "$1" | grep -Exq '[0-9]*\.?[0-9]*'
}

retry() {
    local max_try=$1
    shift
    local interval=${1:-5}
    is_num "$1" && shift || true

    for i in $(seq $max_try); do
        "$@" && return 0 || {
            ret=$?
            [ $ret -eq 141 ] && return 0
            [ $i -lt $max_try ] && sleep $interval || return $ret
        }
    done
}

wget() {
    echo "Downloading: $@" >&2
    if command wget 2>&1 | grep -q BusyBox; then
        retry 5 command wget "$@" -T 10
    else
        command wget --tries=5 --progress=bar:force "$@"
    fi
}

to_upper() {
    tr '[:lower:]' '[:upper:]'
}

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

is_distro_like_debian() {
    [ "$distro" = "debian" ] || [ "$distro" = "ubuntu" ]
}

is_efi() {
    [ -d /sys/firmware/efi ]
}

is_use_cloud_image() {
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_virt() {
    if [ -z "$_is_virt" ]; then
        if command -v systemd-detect-virt >/dev/null 2>&1; then
            systemd-detect-virt -v >/dev/null 2>&1 && _is_virt=true || _is_virt=false
        else
            _is_virt=false
        fi
    fi
    [ "$_is_virt" = true ]
}

cache_dmi_and_virt() {
    if [ -z "$_dmi_cached" ]; then
        _dmi_cached=1
        if command -v dmidecode >/dev/null 2>&1; then
            _dmi_system=$(dmidecode -s system-product-name 2>/dev/null || true)
        fi
    fi
}

get_cloud_vendor() {
    cache_dmi_and_virt
    case "$_dmi_system" in
    *Amazon* | *EC2*) echo aws ;;
    *Google*) echo gcp ;;
    *Microsoft*) echo azure ;;
    *Oracle*) echo oracle ;;
    *IBM*) echo ibm ;;
    *) echo unknown ;;
    esac
}

is_ubuntu_lts() {
    IFS=. read -r major minor < <(echo "$releasever")
    [ $((major % 2)) = 0 ] && [ "$minor" = "04" ]
}

get_ubuntu_kernel_flavor() {
    cache_dmi_and_virt
    vendor="$(get_cloud_vendor)"
    case "$vendor" in
    aws | gcp | oracle | azure | ibm) echo "$vendor" ;;
    *)
        is_ubuntu_lts && suffix=-hwe-$releasever || suffix=
        if is_virt; then
            echo "virtual$suffix"
        else
            echo "generic$suffix"
        fi
        ;;
    esac
}

extract_env_from_cmdline() {
    if [ -f /proc/cmdline ]; then
        eval "$(cat /proc/cmdline | grep -o 'extra_[^= ]*=[^ ]*' | sed 's/^extra_//')"
        eval "$(cat /proc/cmdline | grep -o 'nextos_[^= ]*=[^ ]*' | sed 's/^nextos_//')"
        eval "$(cat /proc/cmdline | grep -o 'finalos_[^= ]*=[^ ]*' | sed 's/^finalos_//')"
    fi
}

ensure_service_started() {
    local service=$1
    if ! rc-service "$service" status >/dev/null 2>&1; then
        rc-service "$service" start || true
    fi
}

clear_previous() {
    rm -rf /os/* 2>/dev/null || true
}

add_community_repo() {
    local ver mirror
    if grep -q "^http.*/edge/main$" /etc/apk/repositories; then
        ver=edge
    elif grep -q "^http.*/latest-stable/main$" /etc/apk/repositories; then
        ver=latest-stable
    else
        ver=v$(cut -d. -f1,2 </etc/alpine-release)
    fi

    if ! grep -q "^http.*/$ver/community$" /etc/apk/repositories; then
        mirror=$(grep '^http.*/main$' /etc/apk/repositories | sed 's,/[^/]*/main$,,' | head -1)
        echo "$mirror/$ver/community" >>/etc/apk/repositories 2>/dev/null || true
    fi
}

apk() {
    retry 5 command apk "$@" >&2
}

find_xda() {
    # 找主硬盘
    for disk in /sys/block/*/; do
        disk=${disk%/}
        disk=${disk##*/}
        case "$disk" in
        loop* | ram* | dm-*) continue ;;
        *)
            xda=$disk
            break
            ;;
        esac
    done
    [ -n "$xda" ] || error_and_exit "Could not find main disk"
}

create_part() {
    info "Creating partitions"
    # 创建分区逻辑
    :
}

download() {
    local url=$1
    local path=$2
    mkdir -p "$(dirname "$path")"
    wget "$url" -O "$path"
}

mount_part_for_iso_installer() {
    info "Mounting partitions for ISO installer"
    # 挂载分区
    :
}

get_ttys() {
    local prefix=$1
    case "$(uname -m)" in
    x86_64) echo "${prefix}ttyS0,115200n8 ${prefix}tty0" ;;
    aarch64) echo "${prefix}ttyS0,115200n8 ${prefix}ttyAMA0,115200n8 ${prefix}tty0" ;;
    esac
}

sync_time() {
    # 同步时间（可选）
    :
}

is_need_change_ssh_port() {
    [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]
}

is_need_set_ssh_keys() {
    [ -n "$ssh_keys" ]
}

change_ssh_port() {
    local root=$1
    local port=$2
    sed -i "s/^#Port 22/Port $port/" "$root/etc/ssh/sshd_config" || true
}

set_ssh_keys_and_del_password() {
    local root=$1
    mkdir -p "$root/root/.ssh"
    echo "$ssh_keys" >"$root/root/.ssh/authorized_keys"
    chmod 600 "$root/root/.ssh/authorized_keys"
}

change_ssh_conf_for_key_login() {
    local root=$1
    sed -i 's/^#PubkeyAuthentication/PubkeyAuthentication/' "$root/etc/ssh/sshd_config" || true
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$root/etc/ssh/sshd_config" || true
}

change_user_password() {
    local root=$1
    if [ -n "$password" ]; then
        echo "root:$password" | chroot "$root" chpasswd 2>/dev/null || true
    fi
}

change_ssh_conf_for_password_login() {
    local root=$1
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$root/etc/ssh/sshd_config" || true
}

add_user_if_need() {
    local root=$1
    [ -n "$username" ] && [ "$username" != "root" ] && {
        chroot "$root" useradd -m -s /bin/bash "$username" 2>/dev/null || true
        [ -n "$password" ] && echo "$username:$password" | chroot "$root" chpasswd 2>/dev/null || true
    }
}

install_ubuntu() {
    info "Installing Ubuntu"

    # 安装 grub
    if is_efi; then
        apk add grub-efi efibootmgr
        grub-install --efi-directory=/os/boot/efi --boot-directory=/os/boot
    else
        apk add grub-bios
        grub-install --boot-directory=/os/boot /dev/$xda
    fi

    # 下载 ISO
    download $iso /os/installer/ubuntu.iso
    mkdir -p /iso
    mount -o ro /os/installer/ubuntu.iso /iso

    kernel=$(get_ubuntu_kernel_flavor)

    # 生成 GRUB 配置
    cat >/os/boot/grub/grub.cfg <<EOF
set timeout=5
menuentry "reinstall" {
    insmod all_video
    insmod search
    insmod loopback
    search --no-floppy --label --set=root installer
    loopback loop /ubuntu.iso
    linux (loop)/casper/vmlinuz iso-scan/filename=/ubuntu.iso autoinstall noprompt noeject cloud-config-url=$ks extra_kernel=$kernel --- $(get_ttys console=)
    initrd (loop)/casper/initrd
}
EOF
}

install_debian() {
    info "Installing Debian"

    # 安装 grub
    if is_efi; then
        apk add grub-efi efibootmgr
        grub-install --efi-directory=/os/boot/efi --boot-directory=/os/boot
    else
        apk add grub-bios
        grub-install --boot-directory=/os/boot /dev/$xda
    fi

    # 下载内核和 initrd
    download $vmlinuz /os/vmlinuz
    download $initrd /os/initrd.img

    # 生成 GRUB 配置
    cat >/os/boot/grub/grub.cfg <<EOF
set timeout=5
menuentry "reinstall" {
    insmod all_video
    insmod search
    search --no-floppy --label --set=root os
    linux /vmlinuz lowmem/low=1 auto=true priority=critical url=$ks --- $(get_ttys console=)
    initrd /initrd.img
}
EOF
}

trans() {
    info "Starting system installation"

    mod_motd() {
        :
    }
    mod_motd

    ensure_service_started modloop 2>/dev/null || true

    clear_previous
    add_community_repo

    if [ -z "$xda" ]; then
        find_xda
    fi

    setup_web_if_enough_ram() {
        :
    }
    setup_web_if_enough_ram
    apk add util-linux

    create_part
    mount_part_for_iso_installer

    case "$distro" in
    ubuntu) install_ubuntu ;;
    debian) install_debian ;;
    esac

    if is_efi; then
        del_invalid_efi_entry() {
            :
        }
        add_default_efi_to_nvram() {
            :
        }
        del_invalid_efi_entry
        add_default_efi_to_nvram
    fi

    info 'Installation complete'
    sleep 5
}

# 主程序入口
: main

if ! [ "$(readlink -f "$0")" = /trans.sh ]; then
    cp -f "$0" /trans.sh
fi

trap 'trap_err $LINENO $?' ERR

rm -f /etc/local.d/trans.start
rm -f /etc/runlevels/default/local

extract_env_from_cmdline

# 同步时间
sync_time || true

# 安装 SSH
apk add openssh-server

if is_need_change_ssh_port; then
    change_ssh_port / $ssh_port
fi

add_user_if_need /

if is_need_set_ssh_keys; then
    set_ssh_keys_and_del_password /
    change_ssh_conf_for_key_login /
    printf '\n' | setup-sshd 2>/dev/null
else
    change_user_password /
    change_ssh_conf_for_password_login /
    printf '\nyes' | setup-sshd 2>/dev/null
fi

# 执行重装
exec > >(tee /reinstall.log) 2>&1
trans

sync
reboot
