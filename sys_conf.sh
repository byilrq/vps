#!/bin/bash
# sys_conf.sh - System configuration menu (timezone/DNS/swap/IPv4-IPv6/BBR3/BBR-TCP/cron/SSH/Firewall)

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PLAIN="\033[0m"
tianlan='\033[96m'
hui='\e[37m'

red(){ echo -e "${RED}\033[01m$1${PLAIN}"; }
green(){ echo -e "${GREEN}\033[01m$1${PLAIN}"; }
yellow(){ echo -e "${YELLOW}\033[01m$1${PLAIN}"; }
skyblue(){ echo -e "\033[1;36m$1\033[0m"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    red "注意: 请在 root 用户下运行脚本"
    exit 1
  fi
}

# -----------------------------
# Wait apt locks (Debian/Ubuntu)
# -----------------------------
wait_for_apt_lock() {
  local max_attempts=60
  local attempt=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ $attempt -ge $max_attempts ]; then
      red "apt 锁等待超时，请手动检查进程并释放锁（例如 kill <PID>），然后重试。"
      return 1
    fi
    yellow "apt 锁被占用（可能有其他更新进程），等待中... ($attempt/$max_attempts)"
    sleep 1
    attempt=$((attempt + 1))
  done
  return 0
}

# -----------------------------
# Package helpers
# -----------------------------
pkg_update() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || return 1
    DEBIAN_FRONTEND=noninteractive apt-get update -y
  elif command -v yum >/dev/null 2>&1; then
    yum -y update
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y update
  else
    return 1
  fi
}

pkg_install() {
  local pkgs=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum -y install "${pkgs[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y install "${pkgs[@]}"
  else
    red "未知的包管理器，无法自动安装依赖。"
    return 1
  fi
}

# -----------------------------
# Get current SSH port
# -----------------------------
get_ssh_port() {
  local port
  port=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}')
  [[ -z "$port" ]] && port=22
  echo "$port"
}

# -----------------------------
# 1) Change timezone
# -----------------------------
change_tz(){
  need_root
  local tz
  read -rp "请输入要设置的时区（默认 Asia/Shanghai，留空使用默认）: " tz
  [[ -z "$tz" ]] && tz="Asia/Shanghai"
  if ! timedatectl list-timezones | grep -qx "$tz"; then
    red "时区无效：$tz"
    yellow "提示：timedatectl list-timezones 查看可用时区"
    return 1
  fi
  timedatectl set-timezone "$tz"
  green "系统时区已经改为：$tz"
  timedatectl
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 2) Set DNS and lock resolv.conf
# -----------------------------
set_dns_ui() {
  need_root

  if ! command -v curl >/dev/null 2>&1; then
    pkg_update || true
    pkg_install curl || return 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    pkg_update || true
    pkg_install sudo || return 1
  fi

  yellow "将把 DNS 固定为 8.8.8.8 / 1.1.1.1，并对 /etc/resolv.conf 加不可变锁。"
  yellow "注意：这可能影响 systemd-resolved / 网络管理自动更新 DNS。"
  read -rp "确认继续？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
    touch /etc/resolv.conf
  fi

  chattr -i /etc/resolv.conf 2>/dev/null || true

  cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

  chattr +i /etc/resolv.conf
  green "resolv.conf 已设置并锁定"

  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; then
    if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
      yellow "正在禁用 systemd-resolved..."
      systemctl disable --now systemd-resolved || true
      green "systemd-resolved 已禁用"
    fi
  fi

  read -rp "回车返回菜单..." _
}

# -----------------------------
# 3) Swap cache - keep only /swapfile
# -----------------------------
swap_cache() {
  need_root
  local size_mb confirm fs_type keep="/swapfile"

  echo "当前 Swap："
  free -h | awk 'NR==1 || /Swap:/ {print}'
  echo ""

  read -rp "请输入 Swap 大小（MB，建议 >=512）: " size_mb
  [[ "$size_mb" =~ ^[0-9]+$ ]] || { red "请输入有效数字"; return 1; }

  read -rp "确认创建/重建 Swap=${size_mb}MB ? (y/n): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  while read -r sw; do
    [[ -z "$sw" ]] && continue
    [[ "$sw" == "$keep" ]] && continue
    swapoff "$sw" >/dev/null 2>&1 || true
    if [[ -f /etc/fstab ]]; then
      sed -i -E "s|^(\s*${sw//\//\\/}\s+.*\s+swap\s+.*)$|# disabled_by_swap_cache: \1|g" /etc/fstab >/dev/null 2>&1 || true
    fi
    if [[ "$sw" == /* && -f "$sw" ]]; then
      rm -f "$sw" >/dev/null 2>&1 || true
    fi
  done < <(swapon --noheadings --raw --show=NAME 2>/dev/null)

  if swapon --noheadings --raw --show=NAME 2>/dev/null | grep -qx "$keep"; then
    swapoff "$keep" >/dev/null 2>&1 || true
  fi
  rm -f "$keep" >/dev/null 2>&1 || true

  fs_type="$(stat -f -c %T / 2>/dev/null || true)"
  touch "$keep" || { red "无法创建 $keep"; return 1; }

  if [[ "$fs_type" == "btrfs" ]] && command -v chattr >/dev/null 2>&1; then
    chattr +C "$keep" >/dev/null 2>&1 || true
  fi

  if command -v fallocate >/dev/null 2>&1; then
    if ! fallocate -l "${size_mb}M" "$keep" 2>/dev/null; then
      yellow "fallocate 失败，改用 dd 创建（会慢一点）"
      dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress || { red "dd 创建失败"; rm -f "$keep"; return 1; }
    fi
  else
    yellow "系统无 fallocate，使用 dd 创建（会慢一点）"
    dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress || { red "dd 创建失败"; rm -f "$keep"; return 1; }
  fi

  chmod 600 "$keep" || { red "chmod 600 失败"; rm -f "$keep"; return 1; }
  mkswap "$keep" >/dev/null 2>&1 || { red "mkswap 失败（文件系统可能不支持 swapfile）"; rm -f "$keep"; return 1; }
  swapon "$keep" >/dev/null 2>&1 || { red "swapon 失败（容器限制或文件系统限制）"; rm -f "$keep"; return 1; }

  if ! grep -qE '^\s*/swapfile\s' /etc/fstab 2>/dev/null; then
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
  fi

  green "Swap 已启用（只保留 /swapfile）："
  swapon --show
  free -h | awk 'NR==1 || /Swap:/ {print}'
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 4) IPv4 / IPv6 priority
# -----------------------------
set_ip_priority() {
  need_root
  while true; do
    clear
    echo "设置 v4/v6 优先级"
    echo "------------------------"
    local ipv6_disabled
    ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)
    if [[ "$ipv6_disabled" -eq 1 ]]; then
      echo -e "当前网络优先级: ${YELLOW}IPv4${PLAIN} 优先"
    else
      echo -e "当前网络优先级: ${YELLOW}IPv6${PLAIN} 优先"
    fi
    echo ""
    echo "1. IPv4 优先"
    echo "2. IPv6 优先"
    echo "3. IPv6 修复工具（外部脚本）"
    echo "0. 返回"
    read -rp "选择: " choice
    case "$choice" in
      1) sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true; green "已切换为 IPv4 优先"; sleep 1 ;;
      2) sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true; green "已切换为 IPv6 优先"; sleep 1 ;;
      3) yellow "将运行外部 IPv6 修复脚本（jhb.ovh/jb/v6.sh）"; bash <(curl -fsSL jhb.ovh/jb/v6.sh) || red "脚本执行失败"; read -rp "回车返回..." _ ;;
      0) break ;;
      *) yellow "无效选择"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# 5) Install BBRv3 (Debian/Ubuntu preferred)
# -----------------------------
bbrv3() {
  need_root
  local cpu_arch
  cpu_arch=$(uname -m)

  if [[ "$cpu_arch" == "aarch64" ]]; then
    yellow "检测到 aarch64，尝试运行外部 BBRv3 ARM 脚本（jhb.ovh/jb/bbrv3arm.sh）"
    bash <(curl -fsSL jhb.ovh/jb/bbrv3arm.sh) || red "脚本执行失败"
    read -rp "回车返回菜单..." _
    return 0
  fi

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
      red "BBRv3 默认仅支持 Debian/Ubuntu（当前: $ID）"
      read -rp "回车返回菜单..." _
      return 1
    fi
  fi

  yellow "将添加 XanMod 源并安装 BBRv3 内核（需重启生效）。"
  read -rp "确定继续吗？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  pkg_update || return 1
  pkg_install wget gnupg ca-certificates || return 1

  wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes || {
    red "获取 XanMod key 失败"
    return 1
  }

  echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' \
    > /etc/apt/sources.list.d/xanmod-release.list

  pkg_update || return 1

  local version
  wget -q https://dl.xanmod.org/check_x86-64_psabi.sh -O /tmp/check_x86-64_psabi.sh || {
    red "下载 psabi 检测脚本失败"
    return 1
  }
  chmod +x /tmp/check_x86-64_psabi.sh
  version=$(/tmp/check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+' | head -n1)
  [[ -z "$version" ]] && version="3"

  pkg_install "linux-xanmod-x64v${version}" || { red "安装 XanMod 内核失败"; return 1; }

  green "BBRv3 内核已安装。请重启后生效。"
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 6) BBR/TCP tuning (external)
# -----------------------------
bbrx() {
  need_root
  local url="https://raw.githubusercontent.com/byilrq/vps/main/tcpx.sh"
  local tmp_file="/tmp/tcpx.sh"

  yellow "正在下载并执行 BBR/TCP 优化脚本：$url"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp_file" || { red "下载失败"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp_file" "$url" || { red "下载失败"; return 1; }
  else
    pkg_update || true
    pkg_install curl wget || true
    curl -fsSL "$url" -o "$tmp_file" || wget -qO "$tmp_file" "$url" || { red "下载失败"; return 1; }
  fi

  [[ -s "$tmp_file" ]] || { red "下载文件为空"; return 1; }
  chmod +x "$tmp_file"
  bash "$tmp_file"
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 7) Schedule reboot (cron)
# -----------------------------
cron_reboot() {
  need_root
  yellow "将下载定时任务文件到 /etc/cron.d/mdadm，并重启系统。"
  read -rp "确认继续？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { yellow "已取消"; return 0; }

  if ! command -v wget >/dev/null 2>&1; then
    pkg_update || true
    pkg_install wget || return 1
  fi

  wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/vps/main/mdadm -O /etc/cron.d/mdadm || {
    red "文件下载失败"
    return 1
  }

  green "文件下载成功：/etc/cron.d/mdadm"
  yellow "即将重启..."
  reboot
}

# -----------------------------
# 8) Change SSH port (default 2222)
# -----------------------------
ssh_port() {
  need_root
  local new_port="$1"
  [[ -z "$new_port" ]] && { red "请提供新的端口号"; return 1; }
  [[ "$new_port" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; return 1; }
  (( new_port >= 1 && new_port <= 65535 )) || { red "端口范围必须 1-65535"; return 1; }

  local SSH_CONFIG="/etc/ssh/sshd_config"
  [[ -f "$SSH_CONFIG" ]] || { red "未找到 $SSH_CONFIG"; return 1; }

  if grep -qE '^[#[:space:]]*Port[[:space:]]+' "$SSH_CONFIG"; then
    sed -i -E "s|^[#[:space:]]*Port[[:space:]]+[0-9]+|Port ${new_port}|g" "$SSH_CONFIG"
  else
    echo "Port ${new_port}" >> "$SSH_CONFIG"
  fi

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || {
    red "重启 SSH 服务失败，请检查日志"
    return 1
  }

  green "SSH 端口已经修改为：$new_port"
  yellow "请确保防火墙放行该端口，避免被锁在外面。"
  read -rp "回车返回菜单..." _
}

# -----------------------------
# 9) Firewall (ufw)
# -----------------------------
firewall() {
  need_root
  while true; do
    clear
    echo "---------------- 防火墙设置 (ufw) ----------------"
    echo " 1) 开启防火墙并设置放行端口"
    echo " 2) 关闭防火墙"
    echo " 0) 返回上级菜单"
    echo "-------------------------------------------------"
    read -rp " 请选择 [0-2]: " ans
    case "$ans" in
      1)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，尝试安装"
          pkg_update || true
          pkg_install ufw || { red "安装 ufw 失败"; read -rp "回车返回..." _; continue; }
        fi

        local sshp
        sshp="$(get_ssh_port)"
        yellow "当前 SSH 端口：$sshp，将自动放行 tcp/udp 防止失联。"
        read -rp "请输入需要额外放行的端口（例如：2222 52000-53000，可留空）: " ports

        ufw --force enable
        ufw allow "${sshp}/tcp"
        ufw allow "${sshp}/udp"

        for p in $ports; do
          if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
            local start end
            IFS='-' read -r start end <<< "$p"
            ufw allow "${start}:${end}/tcp"
            ufw allow "${start}:${end}/udp"
          elif [[ "$p" =~ ^[0-9]+$ ]]; then
            ufw allow "${p}/tcp"
            ufw allow "${p}/udp"
          else
            yellow "忽略非法端口格式：$p"
          fi
        done

        echo ""
        ufw status numbered
        read -rp "回车返回菜单..." _
        ;;
      2)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，无需关闭。"
          read -rp "回车返回..." _
          continue
        fi
        ufw disable
        ufw status
        read -rp "回车返回菜单..." _
        ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}
# -----------------------------
#  系统清理
# -----------------------------
sys_cle() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_cle.sh"
  local script="/root/sys_cle.sh"
  local cron_line='0 0 * * * /bin/bash /root/sys_cle.sh >> /root/sys_cle.cron.log 2>&1'

  # 1) 先下载/更新脚本
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget >/dev/null 2>&1 || true
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$script" || { echo "下载失败"; return 1; }
  else
    wget -qO "$script" "$url" || { echo "下载失败"; return 1; }
  fi
  chmod +x "$script" >/dev/null 2>&1 || true

  # 2) 对话菜单
  echo ""
  echo "=============================="
  echo "sys_cle 管理菜单（已更新脚本）"
  echo "脚本位置: $script"
  echo "=============================="
  echo "1) 添加 cron：每天 00:00 执行"
  echo "2) 删除 cron：移除该定时任务"
  echo "3) 立即执行一次清理"
  echo "4) 查看当前 cron 状态"
  echo "0) 退出"
  echo "------------------------------"
  read -r -p "请选择 [0-4]: " choice

  case "$choice" in
    1)
      # 去重后添加
      ( crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh" ; echo "$cron_line" ) | crontab -
      echo "OK: 已添加每日 00:00 cron"
      ;;
    2)
      # 删除包含 /root/sys_cle.sh 的行
      crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh" | crontab - 2>/dev/null || true
      echo "OK: 已删除 sys_cle 的 cron"
      ;;
    3)
      /bin/bash "$script"
      echo "OK: 已执行一次清理"
      ;;
    4)
      echo "当前 crontab 中与 sys_cle 相关的条目："
      crontab -l 2>/dev/null | grep -F "/root/sys_cle.sh" || echo "（未设置）"
      ;;
    0)
      echo "已退出"
      ;;
    *)
      echo "输入无效：$choice（只允许 0-4）"
      return 1
      ;;
  esac
}
# -----------------------------
# Menu (1..9)
# -----------------------------
menu_sys_conf() {
  need_root
  while true; do
    clear
    echo "#############################################################"
    echo -e "# ${tianlan}系统参数配置（sys_conf.sh）#"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${tianlan} 修改时区"
    echo -e " ${GREEN}2.${tianlan} 修改DNS"
    echo -e " ${GREEN}3.${tianlan} 设置缓存"
    echo -e " ${GREEN}4.${tianlan} 设置IPV4/6优先级"
    echo -e " ${GREEN}5.${tianlan} 安装BBR3"
    echo -e " ${GREEN}6.${tianlan} BBR/TCP 优化"
    echo -e " ${GREEN}7.${tianlan} 设置定时重启"
    echo -e " ${GREEN}8.${tianlan} 修改SSH端口2222"
    echo -e " ${GREEN}9.${tianlan} 设置防火墙"
    echo -e " ${GREEN}10.${tianlan} 系统清理"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回/退出"
    echo ""
    read -rp "请选择 [0-10]: " choice
    case "$choice" in
      1) change_tz ;;
      2) set_dns_ui ;;
      3) swap_cache ;;
      4) set_ip_priority ;;
      5) bbrv3 ;;
      6) bbrx ;;
      7) cron_reboot ;;
      8) ssh_port 2222 ;;
      9) firewall ;;
      10) sys_cle ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

menu_sys_conf
