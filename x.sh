#!/bin/bash
############################# x #####################################

if [[ $EUID -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi

set -e

# -----------------------------
#  颜色/输出函数
# -----------------------------
msg_ok() { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }

# 菜单配色
none='\033[0m'
red='\033[31m'
green='\033[32m'
yellow='\033[33m'
blue='\033[34m'
cyan='\033[36m'


red()    { echo -e "\033[31m$*\033[0m"; }
green()  { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
# -----------------------------
#  常量/全局变量
# -----------------------------
XUIDB="/etc/x-ui/x-ui.db"
domain=""
UNINSTALL="x"
INSTALL="n"
PNLNUM=1
CFALLOW="n"
CLASH=0
CUSTOMWEBSUB=0
Pak=$(type apt &>/dev/null && echo "apt" || echo "yum")

# 固定面板端口
PANEL_PORT_FIXED=8443

# 本地 nginx TLS 伪装站端口（仅本机监听）
fallback_port=""
reality_listen_port=443
reality_port=443
ws_port=2053
ws_path="xian"

# -----------------------------
#  标题横幅
# -----------------------------
show_banner() {
    echo
    msg_inf '           ___    _   _   _  '
    msg_inf ' \/ __ | |  | __ |_) |_) / \ '
    msg_inf ' /\    |_| _|_   |   | \ \_/ '
    echo
}

# -----------------------------
#  通用暂停
# -----------------------------
pause() {
    echo
    read -rp "按回车键继续..." _
}

# -----------------------------
#  兼容式读取输入
# -----------------------------
read_tty() {
    local prompt="$1"
    local __var_name="$2"
    local __tmp=""
    read -rp "$prompt" __tmp
    printf -v "$__var_name" '%s' "$__tmp"
}

# -----------------------------
#  下载文件（带重试）
# -----------------------------
download_with_retry() {
    local url="$1"
    local out="$2"
    local retry="${3:-3}"
    local i

    for ((i=1; i<=retry; i++)); do
        rm -f "$out" 2>/dev/null || true

        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --connect-timeout 10 --retry 2 "$url" -o "$out" && return 0
        elif command -v wget >/dev/null 2>&1; then
            wget -q --timeout=10 --tries=2 -O "$out" "$url" && return 0
        else
            red "未检测到 curl 或 wget，无法下载文件"
            return 1
        fi

        yellow "下载失败，正在重试 (${i}/${retry})..."
        sleep 1
    done

    return 1
}

# -----------------------------
#  清理运行中的服务
# -----------------------------
cleanup_services() {
    systemctl stop x-ui 2>/dev/null || true
    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true

    # 不停止 nginx/apache2/caddy — 避免影响已有业务
    sleep 2
}

# -----------------------------
#  生成随机端口
# -----------------------------
get_port() {
    echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 ))
}

# -----------------------------
#  生成随机字符串
# -----------------------------
gen_random_string() {
    local length="$1"
    head -c 4096 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$length"
    echo
}

# -----------------------------
#  检查端口是否占用
# -----------------------------
check_free() {
    local port=$1
    nc -z 127.0.0.1 "$port" &>/dev/null
    return $?
}

# -----------------------------
#  生成可用端口
# -----------------------------
make_port() {
    while true; do
        PORT=$(get_port)
        if ! check_free "$PORT"; then
            echo "$PORT"
            break
        fi
    done
}

# -----------------------------
#  初始化随机变量
# -----------------------------
init_runtime_vars() {
    sub_port=$(make_port)
    panel_port="${PANEL_PORT_FIXED}"
    panel_path=$(gen_random_string 10)
    sub_path=$(gen_random_string 10)
    web_path=$(gen_random_string 10)
    json_path=$(gen_random_string 10)
    sub2singbox_path=$(gen_random_string 10)
    config_username=$(gen_random_string 10)
    config_password=$(gen_random_string 10)
    AUTODOMAIN="n"
    fallback_port=8080
    short_id=$(openssl rand -hex 4)

    # 双协议默认参数
    ws_port=2053
    ws_path="xian"
    ws_email=$(gen_random_string 8)
}
parse_args() {
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -auto_domain) AUTODOMAIN="$2"; shift 2 ;;
        -install|-Install) INSTALL="$2"; shift 2 ;;
        -panel) PNLNUM="$2"; shift 2 ;;
        -subdomain) domain="$2"; shift 2 ;;
        -ONLY_CF_IP_ALLOW) CFALLOW="$2"; shift 2 ;;
        -websub) CUSTOMWEBSUB="$2"; shift 2 ;;
        -clash) CLASH="$2"; shift 2 ;;
        -uninstall|-Uninstall) UNINSTALL="$2"; shift 2 ;;
        *) shift 1 ;;
      esac
    done
}

# -----------------------------
#  卸载 x-ui / xray / nginx / 网页（保留证书）
# -----------------------------
UNINSTALL_XUI() {
    systemctl stop x-ui 2>/dev/null || true
    systemctl disable x-ui 2>/dev/null || true

    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true

    printf 'y\n' | x-ui uninstall 2>/dev/null || true

    rm -rf "/etc/x-ui/" "/usr/local/x-ui/" "/usr/bin/x-ui/"
    rm -rf /etc/systemd/system/x-ui.service

    # 清理 x-ui 自己添加的 nginx 配置（不影响已有业务）
    rm -f "/etc/nginx/sites-available/${domain}" 2>/dev/null || true
    rm -f "/etc/nginx/sites-enabled/${domain}" 2>/dev/null || true
    rm -f /etc/nginx/sites-available/80.conf /etc/nginx/sites-enabled/80.conf 2>/dev/null || true

    msg_ok "已卸载 x-ui / xray，已保留 nginx 与证书。"
}

# -----------------------------
#  菜单式卸载入口
# -----------------------------
uninstall_xui_menu() {
    clear >/dev/null 2>&1 || true
    show_banner
    echo "----------------------------------------------------------------"
    echo "卸载确认"
    echo "----------------------------------------------------------------"
    echo "即将卸载 x-ui / xray 与相关 nginx 配置，但不会删除 nginx、已申请的证书和依赖。"
    read -rp "确认继续卸载？(y/N): " confirm_uninstall
    if [[ ! "$confirm_uninstall" =~ ^[Yy]$ ]]; then
        msg_err "已取消卸载。"
        return 0
    fi

    UNINSTALL_XUI
    clear >/dev/null 2>&1 || true
    msg_ok "已卸载完成！"
    exit 0
}

# -----------------------------
#  获取公网 IPv4
# -----------------------------
get_public_ipv4() {
    IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*' || true)
    [[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com | tr -d '[:space:]')
    echo "$IP4"
}

# -----------------------------
#  初始化域名参数
# -----------------------------
prepare_domain_vars() {
    local ip4_now=""
    ip4_now="$(get_public_ipv4)"

    if [[ ${AUTODOMAIN} == *"y"* ]]; then
        domain="${ip4_now}.cdn-one.org"
    fi

    while true; do
        if [[ -n "$domain" ]]; then
            break
        fi
        echo "初始化配置（回车后继续）"
        echo "----------------------------------------------------------------"
        echo "单域名配置（请输入可解析到本机的域名）"
        echo "格式示例：domain.tld"
        read -rp "请输入域名（domain.tld）: " domain
    done

    domain=$(echo "$domain" | tr -d '[:space:]')
    SubDomain=$(echo "$domain" | sed 's/^[^ ]* \|\..*//g')
    MainDomain=$(echo "$domain" | sed 's/.*\.\([^.]*\..*\)$/\1/')

    if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]]; then
        MainDomain=${domain}
    fi
}

# -----------------------------
#  修复 dpkg/apt 中断状态
# -----------------------------
fix_dpkg_interrupt() {
    export DEBIAN_FRONTEND=noninteractive
    mkdir -p /var/lib/dpkg >/dev/null 2>&1 || true
    mkdir -p /var/lib/apt/lists/partial >/dev/null 2>&1 || true
    mkdir -p /var/cache/apt/archives/partial >/dev/null 2>&1 || true

    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1 || true
    rm -f /var/cache/apt/archives/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || true

    dpkg --configure -a >/dev/null 2>&1 || true
    apt-get -f install -y >/dev/null 2>&1 || true
}

# -----------------------------
#  刷新软件源缓存
# -----------------------------
pkg_update() {
    export DEBIAN_FRONTEND=noninteractive
    fix_dpkg_interrupt

    if command -v apt-get >/dev/null 2>&1; then
        timeout 300 apt-get update -y -q </dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum makecache -q
    fi
}

# -----------------------------
#  安装基础依赖
# -----------------------------
install_packages() {
    ufw disable >/dev/null 2>&1 || true

    if [[ ${INSTALL} == *"y"* ]]; then
        echo "----------------------------------------------------------------"
        echo "安装基础依赖"
        echo "----------------------------------------------------------------"
        echo "即将安装/更新以下组件：curl wget jq bash sudo nginx-full certbot sqlite3 ufw qrencode cron"
        read -rp "确认继续安装依赖？(Y/n): " confirm_install_pkg
        if [[ "$confirm_install_pkg" =~ ^[Nn]$ ]]; then
            msg_inf "已跳过依赖安装，继续执行后续流程。"
            return 0
        fi

        msg_inf "正在刷新软件源缓存..."
        fix_dpkg_interrupt

        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -q >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then
            yum makecache -q || true
        fi

        msg_inf "安装基础依赖..."
        fix_dpkg_interrupt

        if command -v apt-get >/dev/null 2>&1; then
        # 检测 nginx 是否已安装，不重复安装
        local install_nginx=""
        if ! command -v nginx >/dev/null 2>&1; then
            install_nginx="nginx-full"
        fi

        if ! env DEBIAN_FRONTEND=noninteractive \
            DEBCONF_NONINTERACTIVE_SEEN=true \
            DEBIAN_PRIORITY=critical \
            NEEDRESTART_MODE=a \
            APT_LISTCHANGES_FRONTEND=none \
            timeout 300 apt-get install -y --no-install-recommends \
            -o Dpkg::Use-Pty=0 \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confnew" \
            -o DPkg::Pre-Install-Pkgs::= \
            curl wget jq bash sudo $install_nginx certbot sqlite3 ufw cron unzip \
            netcat-traditional uuid-runtime openssl </dev/null; then

                msg_err "基础依赖安装失败，尝试刷新软件源并自动修复后重试..."
                fix_dpkg_interrupt
                pkg_update || {
                    msg_err "软件源更新失败"
                    exit 1
                }

                env DEBIAN_FRONTEND=noninteractive \
                    DEBCONF_NONINTERACTIVE_SEEN=true \
                    DEBIAN_PRIORITY=critical \
                    NEEDRESTART_MODE=a \
                    APT_LISTCHANGES_FRONTEND=none \
                    timeout 300 apt-get install -y --no-install-recommends \
                    -o Dpkg::Use-Pty=0 \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confnew" \
                    -o DPkg::Pre-Install-Pkgs::= \
                    curl wget jq bash sudo nginx-full certbot sqlite3 ufw cron unzip \
                    netcat-traditional uuid-runtime openssl </dev/null || {
                        msg_err "基础依赖安装失败"
                        exit 1
                    }
            fi

            msg_inf "安装二维码工具 qrencode..."
            fix_dpkg_interrupt

            if ! env DEBIAN_FRONTEND=noninteractive \
                DEBCONF_NONINTERACTIVE_SEEN=true \
                DEBIAN_PRIORITY=critical \
                NEEDRESTART_MODE=a \
                APT_LISTCHANGES_FRONTEND=none \
                timeout 300 apt-get install -y --no-install-recommends \
                -o Dpkg::Use-Pty=0 \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confnew" \
                -o DPkg::Pre-Install-Pkgs::= \
                qrencode </dev/null; then

                msg_err "qrencode 安装失败，尝试刷新软件源并自动修复后重试..."
                fix_dpkg_interrupt
                pkg_update || {
                    msg_err "软件源更新失败"
                    exit 1
                }

                env DEBIAN_FRONTEND=noninteractive \
                    DEBCONF_NONINTERACTIVE_SEEN=true \
                    DEBIAN_PRIORITY=critical \
                    NEEDRESTART_MODE=a \
                    APT_LISTCHANGES_FRONTEND=none \
                    timeout 300 apt-get install -y --no-install-recommends \
                    -o Dpkg::Use-Pty=0 \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confnew" \
                    -o DPkg::Pre-Install-Pkgs::= \
                    qrencode </dev/null || {
                        msg_err "qrencode 安装失败，二维码功能将不可用"
                    }
            fi

        elif command -v yum >/dev/null 2>&1; then
            if ! yum install -y curl wget jq bash sudo nginx certbot sqlite ufw cronie nc openssl unzip; then
                msg_err "基础依赖安装失败"
                exit 1
            fi

            yum install -y qrencode || {
                msg_err "qrencode 安装失败，二维码功能将不可用"
            }
        else
            msg_err "未检测到受支持的包管理器（apt-get / yum）"
            exit 1
        fi

        systemctl daemon-reload
        systemctl enable nginx >/dev/null 2>&1 || true

        if command -v apt-get >/dev/null 2>&1; then
            systemctl enable cron >/dev/null 2>&1 || true
            systemctl restart cron >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then
            systemctl enable crond >/dev/null 2>&1 || true
            systemctl restart crond >/dev/null 2>&1 || true
        fi

        msg_ok "环境依赖安装完成"
        msg_inf "已跳过在依赖安装阶段启动 nginx，稍后会在 nginx 配置写入并校验通过后再启动。"
    fi
}

# -----------------------------
#  工具菜单静默安装依赖
# -----------------------------
install_tool_deps() {
    export DEBIAN_FRONTEND=noninteractive

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y -q >/dev/null 2>&1 || true
        apt-get install -y -q --no-install-recommends \
            curl wget jq sqlite3 openssl qrencode \
            net-tools lsof xxd ca-certificates \
            iproute2 procps cron ufw sudo \
            dnsutils inetutils-ping traceroute \
            >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget jq sqlite openssl qrencode \
            net-tools lsof vim-common ca-certificates \
            iproute procps-ng cronie sudo \
            bind-utils iputils traceroute >/dev/null 2>&1 || true
    fi
}

# -----------------------------
#  获取服务器 IPv4/IPv6
# -----------------------------
get_server_ips() {
    IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
    IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*' || true)
    IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*' || true)
    [[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com)
    [[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com || true)
}

# -----------------------------
#  工具菜单获取公网 IP
# -----------------------------
get_public_ips_tool() {
    TOOL_IPV4="$(curl -4s --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2; exit}' || true)"
    TOOL_IPV6="$(curl -6s --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2; exit}' || true)"
}

# -----------------------------
#  校验域名是否解析到本机
# -----------------------------
resolve_to_ip() {
    local host="$1"
    local a
    a=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
    [[ -n "$a" ]] && [[ "$a" == "$IP4" ]]
}

# -----------------------------
#  查找证书目录名
# -----------------------------
find_cert_name_by_domain() {
    local cert_domain="$1"
    local d

    if [[ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${cert_domain}/privkey.pem" ]]; then
        echo "${cert_domain}"
        return 0
    fi

    for d in /etc/letsencrypt/live/"${cert_domain}"*; do
        [[ -d "$d" ]] || continue
        if [[ -f "$d/fullchain.pem" && -f "$d/privkey.pem" ]]; then
            basename "$d"
            return 0
        fi
    done

    return 1
}

# -----------------------------
#  检查证书文件是否存在
# -----------------------------
cert_files_exist() {
    local cert_domain="$1"
    local cert_name

    if [[ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${cert_domain}/privkey.pem" ]]; then
        return 0
    fi

    cert_name=$(find_cert_name_by_domain "$cert_domain" 2>/dev/null || true)
    [[ -n "$cert_name" ]] && [[ -f "/etc/letsencrypt/live/${cert_name}/fullchain.pem" && -f "/etc/letsencrypt/live/${cert_name}/privkey.pem" ]]
}

# -----------------------------
#  获取证书路径
# -----------------------------
get_cert_paths() {
    local cert_domain="$1"
    local cert_name cert_file key_file

    cert_name=$(find_cert_name_by_domain "$cert_domain" 2>/dev/null || true)
    [[ -n "$cert_name" ]] || return 1

    cert_file="/etc/letsencrypt/live/${cert_name}/fullchain.pem"
    key_file="/etc/letsencrypt/live/${cert_name}/privkey.pem"

    [[ -f "$cert_file" && -f "$key_file" ]] || return 1

    echo "$cert_name|$cert_file|$key_file"
}

# -----------------------------
#  校验证书有效性
# -----------------------------
cert_is_valid() {
    local cert_domain="$1"
    local cert_info cert_file

    cert_info=$(get_cert_paths "$cert_domain") || return 1
    cert_file=$(echo "$cert_info" | cut -d'|' -f2)

    [[ -f "$cert_file" ]] || return 1
    openssl x509 -checkend 0 -noout -in "$cert_file" >/dev/null 2>&1 || return 1

    if openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | grep -qw "DNS:${cert_domain}"; then
        return 0
    fi

    openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -Eq "CN[[:space:]]*=[[:space:]]*${cert_domain}([,/]|$)"
}

# -----------------------------
#  校验证书与私钥是否匹配
# -----------------------------
cert_key_matches() {
    local cert_domain="$1"
    local cert_info cert_file key_file

    cert_info=$(get_cert_paths "$cert_domain") || return 1
    cert_file=$(echo "$cert_info" | cut -d'|' -f2)
    key_file=$(echo "$cert_info" | cut -d'|' -f3)

    [[ -f "$cert_file" && -f "$key_file" ]] || return 1

    local cert_pub key_pub
    cert_pub=$(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform pem 2>/dev/null)
    key_pub=$(openssl pkey -in "$key_file" -pubout -outform pem 2>/dev/null)

    [[ -n "$cert_pub" && -n "$key_pub" && "$cert_pub" == "$key_pub" ]]
}

# -----------------------------
#  打印证书路径
# -----------------------------
print_cert_paths() {
    local cert_domain="$1"
    local cert_info cert_name cert_file key_file

    cert_info=$(get_cert_paths "$cert_domain" 2>/dev/null || true)
    if [[ -n "$cert_info" ]]; then
        cert_name=$(echo "$cert_info" | cut -d'|' -f1)
        cert_file=$(echo "$cert_info" | cut -d'|' -f2)
        key_file=$(echo "$cert_info" | cut -d'|' -f3)
        echo "本脚本将检查以下证书路径："
        echo "检查 ${cert_file}"
        echo "检查 ${key_file}"
        echo "证书目录名：${cert_name}"
    else
        echo "当前尚未发现 ${cert_domain} 对应的本地证书目录。"
    fi
}

# -----------------------------
#  显示本地证书信息
# -----------------------------
show_local_cert_info() {
    local cert_domain="$1"
    local cert_info cert_file

    cert_info=$(get_cert_paths "$cert_domain" 2>/dev/null || true)
    cert_file=$(echo "$cert_info" | cut -d'|' -f2)

    if [[ -f "$cert_file" ]]; then
        echo "域名: ${cert_domain}"
        openssl x509 -noout -subject -issuer -dates -in "$cert_file" 2>/dev/null
    else
        echo "域名: ${cert_domain}"
        echo "本地未找到证书文件。"
    fi
}

# -----------------------------
#  为域名申请证书
# -----------------------------
issue_cert_for_domain() {
    local cert_domain="$1"

    mkdir -p /var/www/acme
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/html

    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true
    pkill -f apache2 2>/dev/null || true
    pkill -f caddy 2>/dev/null || true
    sleep 2

    if ss -lnt | grep -q ':80 '; then
        msg_err "80 端口仍被占用，无法申请证书。"
        ss -lntp | grep ':80 ' || true
        return 1
    fi

    cat > /etc/nginx/sites-available/acme-bootstrap.conf <<EOF
server {
    listen 80;
    server_name ${cert_domain};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }

    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF

    rm -f /etc/nginx/sites-enabled/*
    ln -sf /etc/nginx/sites-available/acme-bootstrap.conf /etc/nginx/sites-enabled/acme-bootstrap.conf

    nginx -t || return 1
    systemctl restart nginx || return 1

    certbot certonly --webroot -w /var/www/acme --non-interactive --agree-tos --register-unsafely-without-email -d "$cert_domain" || return 1

    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        return 0
    fi

    return 1
}

# -----------------------------
#  尝试复用本地证书
# -----------------------------
try_use_local_cert() {
    local cert_domain="$1"

    echo "----------------------------------------------------------------"
    echo "检查本地已有证书：${cert_domain}"
    echo "----------------------------------------------------------------"
    print_cert_paths "$cert_domain"

    if ! cert_files_exist "$cert_domain"; then
        msg_err "${cert_domain} 本地证书文件不存在。"
        return 1
    fi

    if ! cert_is_valid "$cert_domain"; then
        msg_err "${cert_domain} 本地证书无效：可能已过期、无法读取，或证书域名与 ${cert_domain} 不匹配。"
        return 1
    fi

    if ! cert_key_matches "$cert_domain"; then
        msg_err "${cert_domain} 的 fullchain.pem 与 privkey.pem 不匹配。"
        return 1
    fi

    msg_ok "${cert_domain} 本地证书有效，且私钥匹配，继续使用。"
    show_local_cert_info "$cert_domain"
    return 0
}

# -----------------------------
#  处理证书选择流程
# -----------------------------
prepare_cert_for_domain() {
    local cert_domain="$1"
    local cert_choice=""

    while true; do
        echo "----------------------------------------------------------------"
        echo "证书处理：${cert_domain}"
        echo "----------------------------------------------------------------"
        print_cert_paths "$cert_domain"
        echo
        echo "Y = 重新申请 Let's Encrypt 证书"
        echo "n = 使用 VPS 本地已有证书（若有效）"
        echo "q = 退出脚本"
        read -rp "请选择 [Y/n/q]: " cert_choice

        case "$cert_choice" in
            [Nn])
                if try_use_local_cert "$cert_domain"; then
                    return 0
                fi
                echo
                msg_inf "你可以现在手动放置正确证书后，再次选择 n 继续检测。"
                ;;
            [Qq])
                msg_err "已退出证书处理流程。"
                return 1
                ;;
            *)
                echo "开始为 ${cert_domain} 申请新证书..."
                if issue_cert_for_domain "$cert_domain"; then
                    msg_ok "${cert_domain} 证书申请成功。"
                    show_local_cert_info "$cert_domain"
                    return 0
                else
                    msg_err "${cert_domain} 证书申请失败！"
                    msg_inf "你可以修复解析/端口问题，或手动放置证书后再次选择 n。"
                fi
                ;;
        esac
    done
}

# -----------------------------
#  CPU 架构识别
# -----------------------------
arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo "不支持的 CPU 架构！" && exit 1 ;;
    esac
}

# -----------------------------
#  x-ui 安装后初始化配置
# -----------------------------
config_after_install() {
    /usr/local/x-ui/x-ui setting -username "asdfasdf" -password "asdfasdf" -port "8443" -webBasePath "asdfasdf"
    /usr/local/x-ui/x-ui migrate
}

# -----------------------------
#  安装 3x-ui 面板（MHSanaei/3x-ui）
# -----------------------------
install_panel() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y -q wget curl tar tzdata
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget curl tar tzdata
    fi

    cd /usr/local/

    # 如果传入了参数（如安装特定版本），则走原逻辑
    if [ $# -gt 0 ]; then
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"

        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo "请使用更高版本（至少 v2.3.5），安装已终止。"
            exit 1
        fi

        url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo "开始安装 x-ui $1"
        wget -N -O /usr/local/x-ui-linux-$(arch).tar.gz "${url}"
        if [[ $? -ne 0 ]]; then
            echo "下载 x-ui $1 失败，请检查版本是否存在。"
            exit 1
        fi
    else
        # 交互模式：获取最新版本，让用户选择
        echo "正在获取 3x-ui 最新版本信息..."
        tag_version_latest=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version_latest" ]]; then
            echo "尝试使用 IPv4 获取版本信息..."
            tag_version_latest=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version_latest" ]]; then
                echo "获取 x-ui 版本失败，可能受到 GitHub API 限制。将使用默认版本 v2.8.11 进行安装。"
                tag_version_latest="v2.8.11"
            fi
        fi

        echo "--------------------------------------------------------------"
        echo "当前 3x-ui 最新版本为: ${tag_version_latest}"
        echo "默认安装版本: v2.8.11"
        echo "提示: 直接回车将安装 v2.8.11，输入 latest 则安装最新版 ${tag_version_latest}"
        echo "或者输入其他具体版本号（例如 v2.8.11 或 2.8.11）进行安装"
        read -rp "请选择: " version_input

        # 处理用户输入
        if [[ -z "$version_input" ]]; then
            tag_version="v2.8.11"
            echo "将安装默认版本: ${tag_version}"
        elif [[ "$version_input" == "latest" ]]; then
            tag_version="${tag_version_latest}"
            echo "将安装最新版本: ${tag_version}"
        else
            # 确保版本号以 v 开头
            if [[ "$version_input" =~ ^v[0-9] ]]; then
                tag_version="$version_input"
            else
                tag_version="v${version_input}"
            fi
            echo "将安装指定版本: ${tag_version}"
        fi

        # 版本号有效性检查（最低版本要求）
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"
        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo "错误: 版本 ${tag_version} 低于最低要求 v2.3.5，安装终止。"
            exit 1
        fi

        url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo "开始下载 x-ui ${tag_version} ..."
        wget -N -O /usr/local/x-ui-linux-$(arch).tar.gz "${url}"
        if [[ $? -ne 0 ]]; then
            echo "下载 x-ui ${tag_version} 失败，请检查版本是否存在或网络连接。"
            exit 1
        fi
    fi

    # 以下为公共安装步骤（下载 x-ui.sh、解压、配置等）
    wget -O /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        echo "下载 x-ui.sh 失败。"
        exit 1
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui 2>/dev/null || true
        rm -rf /usr/local/x-ui/
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm -f x-ui-linux-$(arch).tar.gz

    cd x-ui
    chmod +x x-ui
    chmod +x x-ui.sh

    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi

    chmod +x x-ui 2>/dev/null || true
    local installed_core_path
    installed_core_path="$(xray_panel_core_path)" || return 1
    [[ -f "$installed_core_path" ]] || { msg_err "面板安装包中找不到 Xray-core：$installed_core_path"; return 1; }
    chmod +x "$installed_core_path" || return 1

    # Panel archive includes its own Xray binary; replace it with the explicitly
    # selected version before 3X-UI starts. Never silently keep bundled latest.
    choose_xray_core_version || return 1
    xray_install_selected_core || return 1

    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    config_after_install

    cp -f x-ui.service.debian /etc/systemd/system/x-ui.service
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui

    echo "x-ui ${tag_version} 安装完成，当前已启动。"
}

# -----------------------------
#  Xray-core: independently select and install the actual 3X-UI core.
#  The panel's own version selection above is intentionally unchanged.
# -----------------------------
XRAY_DEFAULT_CORE_VERSION="v26.6.27"
XRAY_REQUESTED_CORE_VERSION=""

xray_panel_core_path() {
    case "$(arch)" in
        armv5|armv6|armv7) printf '%s\n' '/usr/local/x-ui/bin/xray-linux-arm' ;;
        *) printf '/usr/local/x-ui/bin/xray-linux-%s\n' "$(arch)" ;;
    esac
}

xray_release_asset_name() {
    case "$(arch)" in
        amd64) printf 'Xray-linux-64.zip\n' ;;
        386)   printf 'Xray-linux-32.zip\n' ;;
        arm64) printf 'Xray-linux-arm64-v8a.zip\n' ;;
        armv7) printf 'Xray-linux-arm32-v7a.zip\n' ;;
        armv6) printf 'Xray-linux-arm32-v6.zip\n' ;;
        armv5) printf 'Xray-linux-arm32-v5.zip\n' ;;
        s390x) printf 'Xray-linux-s390x.zip\n' ;;
        *) msg_err "当前架构 $(arch) 尚未配置官方 Xray-core 安装包映射" >&2; return 1 ;;
    esac
}

xray_core_installed_version() {
    local binary="${1:-$(xray_panel_core_path)}"
    [[ -x "$binary" ]] || return 1
    "$binary" version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

xray_official_latest_tag() {
    local tag
    # Official GitHub latest, not a pre-release and not the 'highest' arbitrary tag.
    tag="$(curl -fsSL --retry 2 --connect-timeout 10 --max-time 25 \
        'https://api.github.com/repos/XTLS/Xray-core/releases/latest' \
        | grep -m1 -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9]+\.[0-9]+\.[0-9]+"' \
        | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" || return 1
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s\n' "$tag"
}

choose_xray_core_version() {
    local input='' latest='' current=''
    current="$(xray_core_installed_version 2>/dev/null || true)"
    echo
    echo -e "${cyan}========== Xray-core 内核版本选择 ==========${none}"
    echo "3X-UI 面板版本：按前面的面板选择安装（两者相互独立）"
    echo "当前 / 面板附带 Xray-core：${current:-未检测到}"
    echo "默认 Xray-core：${XRAY_DEFAULT_CORE_VERSION}（已验证 NekoBox 可连接）"
    echo '直接回车：安装 v26.6.27'
    echo '输入 latest：从 XTLS/Xray-core 官方 GitHub 获取最新发布版'
    echo '也可以输入具体版本，如 v26.9.30（或 26.9.30）'
    echo -e "${yellow}提示：旧版本可能缺少后续安全修复；最新版本可能与旧 NekoBox 不兼容。${none}"
    read -erp '请选择 Xray-core 版本 [回车=v26.6.27]: ' input || return 1
    case "$input" in
        '' ) XRAY_REQUESTED_CORE_VERSION="$XRAY_DEFAULT_CORE_VERSION" ;;
        latest|LATEST)
            echo '查询 Xray-core 官方 latest 版本中...'
            latest="$(xray_official_latest_tag)" || {
                msg_err '无法获取官方最新版本。未回退为其他未知版本，请检查 GitHub API 网络。'
                return 1
            }
            XRAY_REQUESTED_CORE_VERSION="$latest"
            ;;
        *)
            [[ "$input" == v* ]] || input="v$input"
            if [[ ! "$input" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                msg_err '内核版本格式错误（应为 v26.6.27、latest 或其他 vX.Y.Z）。'
                return 1
            fi
            XRAY_REQUESTED_CORE_VERSION="$input"
            ;;
    esac
    echo -e "${green}本次选择 Xray-core：${XRAY_REQUESTED_CORE_VERSION}${none}"
    if [[ "$XRAY_REQUESTED_CORE_VERSION" == "$XRAY_DEFAULT_CORE_VERSION" ]]; then
        msg_inf '兼容版本已固定；若开启 Xray 自动更新，未来可能再次出现 NekoBox 不兼容。'
    fi
}

# Download/verify before touching the panel's executable; keep old binary for rollback.
xray_install_selected_core() {
    local selected="${XRAY_REQUESTED_CORE_VERSION:-}"
    local dest asset tmpdir='' url checksum_file='' sha='' actual='' current='' backup='' config=''
    local need_start=n
    [[ "$selected" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { msg_err '请先选择正确的 Xray-core 版本'; return 1; }
    local needed
    for needed in curl unzip sha256sum; do
        if ! command -v "$needed" >/dev/null 2>&1; then
            msg_err "缺少依赖：$needed。Debian/Ubuntu 可运行 apt-get install -y curl unzip coreutils。"
            return 1
        fi
    done
    dest="$(xray_panel_core_path)" || return 1
    [[ -x "$dest" ]] || { msg_err "找不到 3X-UI 内核文件：$dest"; return 1; }
    current="$(xray_core_installed_version "$dest" 2>/dev/null || true)"
    if [[ "$current" == "${selected#v}" ]]; then
        msg_ok "面板现有 Xray-core 已是 $selected，无需重复替换。"
        return 0
    fi
    asset="$(xray_release_asset_name)" || return 1
    url="https://github.com/XTLS/Xray-core/releases/download/${selected}/${asset}"
    tmpdir="$(mktemp -d /tmp/xray-core-select.XXXXXXXX)" || return 1
    echo "下载官方 Xray-core $selected：$asset"
    if ! curl -fL --retry 3 --connect-timeout 15 --max-time 210 -o "$tmpdir/core.zip" "$url"; then
        msg_err "下载失败：$url（未修改当前内核）"
        rm -rf "$tmpdir"; return 1
    fi
    if ! unzip -tqq "$tmpdir/core.zip" || ! unzip -p "$tmpdir/core.zip" xray > "$tmpdir/xray" || [[ ! -s "$tmpdir/xray" ]]; then
        msg_err 'Xray 官方 ZIP 无效或缺少 xray 文件（未修改当前内核）'
        rm -rf "$tmpdir"; return 1
    fi
    # Xray release normally publishes a separate *.dgst file; verify SHA256 if available.
    if curl -fsSL --connect-timeout 8 --max-time 25 "${url}.dgst" -o "$tmpdir/core.dgst" 2>/dev/null; then
        sha="$(grep -iE 'SHA2[-_]?256|SHA[-_]?256' "$tmpdir/core.dgst" | head -n1 | grep -Eo '[[:xdigit:]]{64}' | head -n1 || true)"
        if [[ -n "$sha" ]]; then
            if ! printf '%s  %s\n' "$sha" "$tmpdir/core.zip" | sha256sum -c - >/dev/null 2>&1; then
                msg_err 'Xray ZIP SHA256 校验失败，拒绝替换。'
                rm -rf "$tmpdir"; return 1
            fi
            msg_inf '官方 SHA256 校验通过。'
        else
            msg_inf '未能解析官方摘要文件的 SHA256 字段；已校验 ZIP 完整性及下载内核版本。'
        fi
    else
        msg_inf '未找到对应的官方摘要文件；已校验 ZIP 完整性及下载内核版本。'
    fi
    chmod 755 "$tmpdir/xray"
    actual="$(xray_core_installed_version "$tmpdir/xray" 2>/dev/null || true)"
    if [[ "$actual" != "${selected#v}" ]]; then
        msg_err "下载内核版本异常：期望 $selected，检测到 ${actual:-未知}；拒绝替换。"
        rm -rf "$tmpdir"; return 1
    fi
    config='/usr/local/x-ui/bin/config.json'
    if [[ -s "$config" ]]; then
        if ! XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$tmpdir/xray" run -test -config "$config"; then
            msg_err '所选 Xray-core 与当前运行配置不兼容；旧内核和原节点未修改。'
            rm -rf "$tmpdir"; return 1
        fi
    fi
    mkdir -p /root/xray-core-backups || { rm -rf "$tmpdir"; return 1; }
    chmod 700 /root/xray-core-backups || true
    backup="/root/xray-core-backups/xray-before-$(date +%Y%m%d-%H%M%S)-$$"
    cp -p "$dest" "$backup" || { msg_err '旧内核备份失败，取消更换'; rm -rf "$tmpdir"; return 1; }
    if systemctl is-active --quiet x-ui; then
        need_start=y
        if ! systemctl stop x-ui; then
            msg_err '未能停止 3X-UI，拒绝替换内核'; rm -rf "$tmpdir"; return 1
        fi
    fi
    if ! install -m 755 "$tmpdir/xray" "$dest"; then
        msg_err '安装新内核失败，正在恢复旧内核。'
        install -m 755 "$backup" "$dest" || true
        [[ "$need_start" == y ]] && systemctl start x-ui || true
        rm -rf "$tmpdir"; return 1
    fi
    if [[ "$need_start" == y ]]; then
        if ! systemctl start x-ui || ! systemctl is-active --quiet x-ui; then
            msg_err '新内核启动失败，自动恢复旧内核。'
            systemctl stop x-ui 2>/dev/null || true
            install -m 755 "$backup" "$dest" || true
            systemctl start x-ui 2>/dev/null || true
            rm -rf "$tmpdir"; return 1
        fi
    fi
    actual="$(xray_core_installed_version "$dest" 2>/dev/null || true)"
    rm -rf "$tmpdir"
    msg_ok "已安装 Xray-core v${actual}；3X-UI 面板版本没有变更。"
    echo "旧内核备份：$backup"
    if [[ "$selected" != "$XRAY_DEFAULT_CORE_VERSION" ]]; then
        msg_inf '提示：新内核通过本地配置/启动检查，并不代表旧版 NekoBox 一定兼容。'
    fi
}

# After a one-time manual core update, avoid leaving an old monthly updater silently overwriting it.
xray_disable_legacy_auto_update_if_present() {
    local old='' choice=''
    old="$(crontab -l 2>/dev/null | grep -E '/root/xray_(update|fresh)\.sh' || true)"
    [[ -n "$old" ]] || return 0
    echo -e "${yellow}[WARN] 检测到旧版每月 Xray 自动更新任务，它会覆盖刚选择的内核版本：${none}"
    printf '%s\n' "$old"
    read -erp '是否清除上述自动更新任务以固定当前内核？[Y/n]: ' choice || return 1
    if [[ ! "$choice" =~ ^[Nn]$ ]]; then
        (crontab -l 2>/dev/null | grep -Ev '/root/xray_(update|fresh)\.sh' || true) | crontab -
        msg_ok '已关闭旧版 Xray 月度自动更新任务。'
    else
        msg_inf '已保留定时更新：未来可能自动升级 Xray-core。'
    fi
}

# -----------------------------
#  Xray-core maintenance: manual vs explicitly opted-in scheduled update.
#  The cron copy runs this same script with --xray-auto-update, never an
#  external mutable xray_update.sh downloaded on every run.
# -----------------------------
XRAY_MANAGED_CRON_MARKER='X_SH_MANAGED_XRAY_CORE_UPDATE'
XRAY_CRON_RUNNER='/root/xray-core-manager/xray-core-maintenance.sh'
XRAY_CRON_LOG='/var/log/xray-core-auto-update.log'

xray_auto_cron_listing() {
    crontab -l 2>/dev/null | grep -E 'X_SH_MANAGED_XRAY_CORE_UPDATE|/root/xray_(update|fresh)\.sh' || true
}

# Keep all unrelated cron entries and clear only this script's old/new updaters.
xray_clear_managed_cron() {
    local existing=''
    existing="$(crontab -l 2>/dev/null || true)"
    if [[ -z "$existing" ]]; then
        return 0
    fi
    if ! printf '%s\n' "$existing" | grep -Eq 'X_SH_MANAGED_XRAY_CORE_UPDATE|/root/xray_(update|fresh)\.sh'; then
        return 0
    fi
    if ! printf '%s\n' "$existing" \
        | grep -Ev 'X_SH_MANAGED_XRAY_CORE_UPDATE|/root/xray_(update|fresh)\.sh' \
        | crontab -; then
        msg_err '移除旧 Xray 自动更新任务失败；请检查 crontab -l。'
        return 1
    fi
    return 0
}

# Cron's own invocation is non-interactive and updates only Xray-core.
xray_auto_update_once() {
    local latest=''
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 启动 Xray-core 定时更新检查"
    latest="$(xray_official_latest_tag)" || {
        msg_err '自动更新无法查询官方最新版本，本次不修改内核。'
        return 1
    }
    XRAY_REQUESTED_CORE_VERSION="$latest"
    echo "[INFO] XTLS 官方最新发布版本：$XRAY_REQUESTED_CORE_VERSION"
    xray_install_selected_core || return 1
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] 本次更新检查完成"
}

# Menu 3, item 1: one-time manual change. Does not enable cron.
xray_updata() {
    echo '----------------------------------------------------------------'
    echo '手动更新 Xray-core（不会升级 3X-UI 面板或启用定时任务）'
    echo '----------------------------------------------------------------'
    choose_xray_core_version || return 1
    xray_install_selected_core || return 1
    if [[ -n "$(xray_auto_cron_listing)" ]]; then
        echo -e "${yellow}[WARN] 检测到仍在生效的 Xray 定时更新任务，未来可能覆盖本次手动选择的内核。${none}"
        echo '若需固定当前版本，请使用菜单 3 → 子菜单 3 取消定时任务。'
    else
        msg_inf '本次手动更新没有创建定时任务。'
    fi
}

# Menu 3, item 2: install explicitly opted-in cron schedule.
xray_setup_auto_update() {
    local confirm='' hour='' minute='' day='' cron_entry='' script_source='' existing_crontab=''
    echo
    echo -e "${yellow}[警告] 自动更新会替换 Xray-core，可能使手机 NekoBox、旧版 sing-box 等客户端的 REALITY 等代理协议失效。${none}"
    echo -e "${yellow}[警告] 语法/启动检查无法证明每个客户端都兼容新内核；服务可启动也可能存在协议握手不兼容。${none}"
    echo '自动更新默认关闭；只有主动确认才创建计划任务。'
    echo '默认计划：每月 1 日 03:00（VPS 本地时间）。'
    read -erp '每月日期 [1-28，回车默认 1]: ' day || return 1
    read -erp '执行小时 [0-23，回车默认 3]: ' hour || return 1
    read -erp '执行分钟 [0-59，回车默认 0]: ' minute || return 1
    day="${day:-1}"; hour="${hour:-3}"; minute="${minute:-0}"
    if [[ ! "$day" =~ ^[0-9]+$ || ! "$hour" =~ ^[0-9]+$ || ! "$minute" =~ ^[0-9]+$ ]] \
       || ((10#$day < 1 || 10#$day > 28 || 10#$hour > 23 || 10#$minute > 59)); then
        msg_err '计划时间不合法：日期 1-28，小时 0-23，分钟 0-59。'
        return 1
    fi
    day=$((10#$day)); hour=$((10#$hour)); minute=$((10#$minute))
    echo "计划执行：每月 ${day} 日 ${hour}:$(printf '%02d' "$minute")"
    echo '升级失败且配置或服务检查未通过时，将尝试恢复旧内核；无法保证自动识别 NekoBox 兼容性。'
    read -erp '确认接受可能导致代理中断的风险？输入 AUTO 才启用：' confirm || return 1
    if [[ "$confirm" != 'AUTO' ]]; then
        msg_inf '未开启定时更新。'
        return 0
    fi
    if ! command -v crontab >/dev/null 2>&1; then
        msg_err '系统没有 crontab，请先安装 cron/cronie。'
        return 1
    fi
    script_source="$0"
    if [[ ! -s "$script_source" ]] || ! bash -n "$script_source"; then
        msg_err '无法读取当前完整的 x.sh，取消定时任务安装。'
        return 1
    fi
    mkdir -p "$(dirname "$XRAY_CRON_RUNNER")" || return 1
    chmod 700 "$(dirname "$XRAY_CRON_RUNNER")" || true
    if ! install -m 700 "$script_source" "$XRAY_CRON_RUNNER"; then
        msg_err '未能生成独立的定时维护脚本。'
        return 1
    fi
    # Copy is self-contained and invokes only the --xray-auto-update dispatch.
    if ! grep -q -- '--xray-auto-update' "$XRAY_CRON_RUNNER"; then
        msg_err '生成的定时脚本缺少自动更新入口，已取消。'
        return 1
    fi
    xray_clear_managed_cron || return 1
    cron_entry="$minute $hour $day * * /bin/bash $XRAY_CRON_RUNNER --xray-auto-update >>$XRAY_CRON_LOG 2>&1 # $XRAY_MANAGED_CRON_MARKER"
    existing_crontab="$(crontab -l 2>/dev/null || true)"
    if ! printf '%s\n%s\n' "$existing_crontab" "$cron_entry" | crontab -; then
        msg_err '计划任务安装失败。'
        return 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files cron.service --no-legend 2>/dev/null | grep -q 'cron.service'; then
            systemctl enable --now cron >/dev/null 2>&1 || msg_inf 'cron 可能未启动，请检查 systemctl status cron。'
        elif systemctl list-unit-files crond.service --no-legend 2>/dev/null | grep -q 'crond.service'; then
            systemctl enable --now crond >/dev/null 2>&1 || msg_inf 'crond 可能未启动，请检查 systemctl status crond。'
        fi
    fi
    msg_ok '已启用每月 Xray-core 自动更新。'
    echo "计划：$cron_entry"
    echo "日志：$XRAY_CRON_LOG"
    echo '注意：自动更新前会备份旧内核，但不能自动保证手机 NekoBox 兼容。'
}

# Menu 3, item 3: show status, then disable with explicit confirmation.
xray_auto_update_status_or_disable() {
    local tasks='' choice=''
    echo '----------------------------------------------------------------'
    echo 'Xray-core 定时更新任务状态'
    echo '----------------------------------------------------------------'
    tasks="$(xray_auto_cron_listing)"
    if [[ -z "$tasks" ]]; then
        msg_ok '当前没有本脚本管理的 Xray 自动更新任务。'
        return 0
    fi
    echo "$tasks"
    echo -e "${yellow}[WARN] 如自动升级内核，旧版客户端可能发生 REALITY 握手失败。${none}"
    read -erp '是否取消上述 Xray 定时更新任务？(y/N): ' choice || return 1
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        xray_clear_managed_cron || return 1
        msg_ok '已取消 Xray 定时自动更新；不会删除面板或内核。'
    else
        msg_inf '已保留当前计划任务。'
    fi
}

xray_core_menu() {
    local choice=''
    while true; do
        echo
        echo -e "${cyan}========== Xray-core 维护 ==========${none}"
        echo '1) 手动更新 Xray-core（默认 v26.6.27，latest 获取最新版）'
        echo '2) 设置定时自动更新（默认关闭，需确认风险）'
        echo '3) 查看 / 取消定时自动更新'
        echo '0) 返回主菜单'
        echo -e "${yellow}[WARN] 自动更新后可能导致 NekoBox 等客户端代理协议失效。${none}"
        read -erp '请选择 [0-3]: ' choice || return 0
        case "$choice" in
            1) xray_updata || true; pause ;;
            2) xray_setup_auto_update || true; pause ;;
            3) xray_auto_update_status_or_disable || true; pause ;;
            0) return 0 ;;
            *) msg_err '输入无效，请重新选择。' ;;
        esac
    done
}

# -----------------------------
#  写入 x-ui 数据库与 REALITY 配置
# -----------------------------
UPDATE_XUIDB() {
if [[ -f $XUIDB ]]; then
        x-ui stop 2>/dev/null || true
        pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
        pkill -f 'xray-linux' 2>/dev/null || true
        pkill -x xray 2>/dev/null || true
        sleep 2

        XRAY_BIN="$(xray_panel_core_path)"
        [[ -x "$XRAY_BIN" ]] || XRAY_BIN="/usr/local/x-ui/bin/xray"

        output=$($XRAY_BIN x25519 2>/dev/null || true)

        private_key=$(printf '%s\n' "$output" | sed -nE 's/^(PrivateKey|Private key):[[:space:]]*//p' | head -n1 | tr -d '\r')

        public_key=$(printf '%s\n' "$output" | sed -nE 's/^(Password|Password \(PublicKey\)|PublicKey|Public key):[[:space:]]*//p' | head -n1 | tr -d '\r')

        hash32=$(printf '%s\n' "$output" | sed -nE 's/^Hash32:[[:space:]]*//p' | head -n1 | tr -d '\r')

        if [[ -z "$private_key" ]]; then
            msg_err "生成 REALITY 私钥失败！"
            echo "$output"
            exit 1
        fi

        if [[ -z "$public_key" ]]; then
            msg_err "生成 REALITY 客户端密钥失败！"
            echo "$output"
            exit 1
        fi

        client_id=$($XRAY_BIN uuid 2>/dev/null | head -n1 | tr -d '\r')
        if [[ -z "$client_id" ]]; then
            if command -v uuidgen >/dev/null 2>&1; then
                client_id=$(uuidgen | tr 'A-Z' 'a-z' | tr -d '\r')
            else
                client_id=$(cat /proc/sys/kernel/random/uuid | tr 'A-Z' 'a-z' | tr -d '\r')
            fi
        fi

        if [[ -z "$client_id" ]]; then
            msg_err "生成 Reality UUID 失败！"
            exit 1
        fi

        ws_client_id=$($XRAY_BIN uuid 2>/dev/null | head -n1 | tr -d '\r')
        if [[ -z "$ws_client_id" ]]; then
            if command -v uuidgen >/dev/null 2>&1; then
                ws_client_id=$(uuidgen | tr 'A-Z' 'a-z' | tr -d '\r')
            else
                ws_client_id=$(cat /proc/sys/kernel/random/uuid | tr 'A-Z' 'a-z' | tr -d '\r')
            fi
        fi

        if [[ -z "$ws_client_id" ]]; then
            msg_err "生成 WS UUID 失败！"
            exit 1
        fi

        if [[ -z "$short_id" ]]; then
            msg_err "short_id 为空，请确认脚本前面已设置 short_id=\$(openssl rand -hex 8)"
            exit 1
        fi

        sub_uri="https://${domain}/${sub_path}/"
        json_uri="https://${domain}/${web_path}?name="

        reality_uri="vless://${client_id}@${domain}:${reality_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&spx=%2F&type=tcp&headerType=none#R"
        ws_uri="vless://${ws_client_id}@${domain}:${ws_port}?encryption=none&security=tls&sni=${domain}&host=${domain}&type=ws&path=%2F${ws_path}#W"

        sqlite3 "$XUIDB" <<EOF_SQL
DELETE FROM "inbounds";
DELETE FROM "client_traffics";
DELETE FROM sqlite_sequence WHERE name IN ('inbounds','client_traffics');

DELETE FROM "settings" WHERE "key" IN (
  "subPort","subPath","subURI","subJsonPath","subJsonURI","subEnable","webListen","webDomain",
  "webCertFile","webKeyFile","sessionMaxAge","pageSize","expireDiff","trafficDiff","remarkModel",
  "tgBotEnable","tgBotToken","tgBotProxy","tgBotAPIServer","tgBotChatId","tgRunTime","tgBotBackup",
  "tgBotLoginNotify","tgCpu","tgLang","timeLocation","secretEnable","subDomain","subCertFile",
  "subKeyFile","subUpdates","subEncrypt","subShowInfo","subJsonFragment","subJsonNoises",
  "subJsonMux","subJsonRules","datepicker"
);

INSERT INTO "settings" ("key", "value") VALUES ("subPort",  '${sub_port}');
INSERT INTO "settings" ("key", "value") VALUES ("subPath",  '/${sub_path}/');
INSERT INTO "settings" ("key", "value") VALUES ("subURI",  '${sub_uri}');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonPath",  '${json_path}');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonURI",  '${json_uri}');
INSERT INTO "settings" ("key", "value") VALUES ("subEnable",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("webListen",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webDomain",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webCertFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("webKeyFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("sessionMaxAge",  '60');
INSERT INTO "settings" ("key", "value") VALUES ("pageSize",  '50');
INSERT INTO "settings" ("key", "value") VALUES ("expireDiff",  '0');
INSERT INTO "settings" ("key", "value") VALUES ("trafficDiff",  '0');
INSERT INTO "settings" ("key", "value") VALUES ("remarkModel",  '-ieo');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotEnable",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotToken",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotProxy",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotAPIServer",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotChatId",  '');
INSERT INTO "settings" ("key", "value") VALUES ("tgRunTime",  '@daily');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotBackup",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("tgBotLoginNotify",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("tgCpu",  '80');
INSERT INTO "settings" ("key", "value") VALUES ("tgLang",  'en-US');
INSERT INTO "settings" ("key", "value") VALUES ("timeLocation",  'Europe/Moscow');
INSERT INTO "settings" ("key", "value") VALUES ("secretEnable",  'false');
INSERT INTO "settings" ("key", "value") VALUES ("subDomain",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subCertFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subKeyFile",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subUpdates",  '12');
INSERT INTO "settings" ("key", "value") VALUES ("subEncrypt",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("subShowInfo",  'true');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonFragment",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonNoises",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonMux",  '');
INSERT INTO "settings" ("key", "value") VALUES ("subJsonRules",  '');
INSERT INTO "settings" ("key", "value") VALUES ("datepicker",  'gregorian');

INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing")
VALUES (
'1','0','0','0','R','1','0','','${reality_listen_port}','vless',
'{
  "clients": [
    {
      "id": "${client_id}",
      "flow": "xtls-rprx-vision",
      "email": "",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "R",
      "reset": 0
    }
  ],
  "decryption": "none",
  "fallbacks": [
    {
      "dest": "127.0.0.1:${fallback_port}",
      "xver": 0
    }
  ]
}',
'{
  "network": "tcp",
  "security": "reality",
  "externalProxy": [],
  "realitySettings": {
    "show": false,
    "xver": 0,
    "target": "127.0.0.1:${fallback_port}",
    "serverNames": [
      "${domain}"
    ],
    "privateKey": "${private_key}",
    "minClientVer": "",
    "maxClientVer": "",
    "maxTimeDiff": 0,
    "shortIds": [
      "${short_id}"
    ],
    "mldsa65Seed": "",
    "settings": {
      "publicKey": "${public_key}",
      "fingerprint": "chrome",
      "serverName": "${domain}",
      "spiderX": "/",
      "mldsa65Verify": ""
    }
  },
  "tcpSettings": {
    "acceptProxyProtocol": false,
    "header": {
      "type": "none"
    }
  }
}',
'inbound-reality',
'{
  "enabled": true,
  "destOverride": [
    "http",
    "tls",
    "quic",
    "fakedns"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
);

INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing")
VALUES (
'1','0','0','0','W','1','0','','${ws_port}','vless',
'{
  "clients": [
    {
      "id": "${ws_client_id}",
      "flow": "",
      "email": "${ws_email}",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": "",
      "subId": "W",
      "reset": 0
    }
  ],
  "decryption": "none"
}',
'{
  "network": "ws",
  "security": "tls",
  "externalProxy": [],
  "tlsSettings": {
    "serverName": "${domain}",
    "minVersion": "1.2",
    "alpn": [
      "h2",
      "h3"
    ],
    "certificates": [
      {
        "certificateFile": "/root/cert/${domain}/fullchain.pem",
        "keyFile": "/root/cert/${domain}/privkey.pem",
        "ocspStapling": 3600
      }
    ]
  },
  "wsSettings": {
    "acceptProxyProtocol": false,
    "path": "/${ws_path}",
    "host": ""
  }
}',
'inbound-ws-tls-cdn',
'{
  "enabled": true,
  "destOverride": [
    "http",
    "tls"
  ],
  "metadataOnly": false,
  "routeOnly": false
}'
);

INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset")
VALUES ('1','1','','0','0','0','0','0');
INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset")
VALUES ('2','1','${ws_email}','0','0','0','0','0');
EOF_SQL

        /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${panel_port}" -webBasePath "${panel_path}"
        /usr/local/x-ui/x-ui cert \
			-webCert "/etc/letsencrypt/live/${domain}/fullchain.pem" \
		-webCertKey "/etc/letsencrypt/live/${domain}/privkey.pem"
        x-ui start
        sleep 3

        msg_ok "双协议节点写入完成"
        echo "Reality PrivateKey: ${private_key}"
        echo "Reality PublicKey(客户端 pbk): ${public_key}"
        echo "Hash32(可忽略): ${hash32}"
        echo "Reality URI: ${reality_uri}"
        echo "WS+TLS+CDN URI: ${ws_uri}"

else
    msg_err "x-ui.db 文件不存在！可能 x-ui 尚未安装。"
    exit 1
fi
}
configure_nginx() {
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets /var/www/html /var/www/acme

    cat > "/etc/nginx/sites-available/80.conf" <<EOF
server {
    listen 80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

    cat > "/etc/nginx/snippets/includes.conf" <<EOF
    location /${sub2singbox_path}/ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8090/;
    }

    location ~ ^/${web_path}/clashmeta/(.+)\$ {
        default_type text/plain;
        ssi on;
        ssi_types text/plain;
        set \$subid \$1;
        root /var/www/subpage;
        try_files /clash.yaml =404;
    }

    location ~ ^/${web_path} {
        root /var/www/subpage;
        index index.html;
        try_files \$uri \$uri/ /index.html =404;
    }

    location /${sub_path} {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
        break;
    }
    location /${sub_path}/ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
        break;
    }

    location /${json_path} {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
        break;
    }
    location /${json_path}/ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
        break;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
EOF

    local nginx_ver_raw nginx_ver_major nginx_ver_minor nginx_ver_patch
    local use_new_http2_syntax="n"
    local has_ipv6="n"
    local use_ipv6="n"
    local listen_line_v4 listen_line_v6 http2_extra_line

    port_in_use() {
        local port="$1"
        if command -v ss >/dev/null 2>&1; then
            ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)$port$"
        elif command -v netstat >/dev/null 2>&1; then
            netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)$port$"
        else
            return 1
        fi
    }

    check_cert_files() {
        [[ -n "${CERT_FULLCHAIN:-}" ]] || { msg_err "CERT_FULLCHAIN 为空！"; exit 1; }
        [[ -n "${CERT_PRIVKEY:-}" ]] || { msg_err "CERT_PRIVKEY 为空！"; exit 1; }

        [[ -f "${CERT_FULLCHAIN}" ]] || { msg_err "证书文件不存在：${CERT_FULLCHAIN}"; exit 1; }
        [[ -f "${CERT_PRIVKEY}" ]] || { msg_err "私钥文件不存在：${CERT_PRIVKEY}"; exit 1; }

        [[ -s "${CERT_FULLCHAIN}" ]] || { msg_err "证书文件为空：${CERT_FULLCHAIN}"; exit 1; }
        [[ -s "${CERT_PRIVKEY}" ]] || { msg_err "私钥文件为空：${CERT_PRIVKEY}"; exit 1; }

        msg_inf "证书文件检测通过"
    }

    check_ports() {
        if [[ -z "${fallback_port:-}" ]]; then
            msg_err "fallback_port 为空！"
            exit 1
        fi

        if [[ -z "${sub_port:-}" ]]; then
            msg_err "sub_port 为空！"
            exit 1
        fi

        if port_in_use "${fallback_port}"; then
            msg_err "fallback_port 端口已被占用：${fallback_port}"
            exit 1
        fi

        if ! port_in_use "${sub_port}"; then
            msg_inf "检测到 sub_port 未监听：${sub_port}，请确认后端服务是否已启动"
        else
            msg_inf "检测到 sub_port 已监听：${sub_port}"
        fi
    }

    detect_nginx_http2_mode() {
        nginx_ver_raw="$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9]\+\)\.\([0-9]\+\)\.\([0-9]\+\).*#\1 \2 \3#p')"

        if [[ -n "$nginx_ver_raw" ]]; then
            nginx_ver_major="$(echo "$nginx_ver_raw" | awk '{print $1}')"
            nginx_ver_minor="$(echo "$nginx_ver_raw" | awk '{print $2}')"
            nginx_ver_patch="$(echo "$nginx_ver_raw" | awk '{print $3}')"

            if (( nginx_ver_major > 1 )) || \
               (( nginx_ver_major == 1 && nginx_ver_minor > 25 )) || \
               (( nginx_ver_major == 1 && nginx_ver_minor == 25 && nginx_ver_patch >= 1 )); then
                use_new_http2_syntax="y"
            fi
        fi

        if [[ "$use_new_http2_syntax" == "y" ]]; then
            listen_line_v4="    listen 127.0.0.1:${fallback_port} ssl;"
            http2_extra_line="    http2 on;"
            msg_inf "检测到较新 nginx 版本，使用 http2 on; 写法"
        else
            listen_line_v4="    listen 127.0.0.1:${fallback_port} ssl http2;"
            http2_extra_line=""
            msg_inf "检测到较旧 nginx 版本，使用 listen ... ssl http2; 写法"
        fi
    }

    detect_ipv6() {
        if [[ -f /proc/net/if_inet6 ]] && grep -q "00000000000000000000000000000001" /proc/net/if_inet6 2>/dev/null; then
            has_ipv6="y"
            msg_inf "检测到系统存在 IPv6 回环地址 ::1"
        else
            has_ipv6="n"
            msg_inf "未检测到可用 IPv6 回环地址，默认仅使用 IPv4"
        fi
    }

    build_domain_conf() {
        cat > "/etc/nginx/sites-available/${domain}" <<EOF
server {
    server_tokens off;
    server_name ${domain};
${listen_line_v4}
${listen_line_v6}
${http2_extra_line}
    index index.html index.htm index.php index.nginx-debian.html;
    root /var/www/html/;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_certificate ${CERT_FULLCHAIN};
    ssl_certificate_key ${CERT_PRIVKEY};

    error_page 400 401 402 403 500 501 502 503 504 =404 /404;
    proxy_intercept_errors on;

    include /etc/nginx/snippets/includes.conf;
}
EOF
    }

    enable_sites() {
        [[ -f "/etc/nginx/sites-available/${domain}" ]] || {
            msg_err "${domain} nginx 配置文件不存在！"
            exit 1
        }

        # 只移除以 domain 命名的 x-ui 站点配置，不碰其他站点
        rm -f "/etc/nginx/sites-enabled/${domain}" 2>/dev/null || true
        rm -f /etc/nginx/sites-enabled/80.conf 2>/dev/null || true
        ln -sf "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
        ln -sf "/etc/nginx/sites-available/80.conf" "/etc/nginx/sites-enabled/80.conf"
    }

    test_and_reload_nginx() {
        echo "----------------------------------------------------------------"
        echo "Nginx 配置检查"
        echo "----------------------------------------------------------------"
        echo "正在测试 nginx 配置..."

        if ! nginx -t; then
            msg_err "nginx 配置检查未通过！"
            exit 1
        fi

        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl restart nginx || {
            msg_err "nginx 重启失败！"
            exit 1
        }

        msg_inf "nginx 配置完成并已重启"
    }

    check_cert_files
    check_ports
    detect_nginx_http2_mode
    detect_ipv6

    listen_line_v6=""
    if [[ "$has_ipv6" == "y" ]]; then
        if [[ "$use_new_http2_syntax" == "y" ]]; then
            listen_line_v6="    listen [::1]:${fallback_port} ssl;"
        else
            listen_line_v6="    listen [::1]:${fallback_port} ssl http2;"
        fi
        use_ipv6="y"
    fi

    build_domain_conf
    enable_sites

    if nginx -t >/dev/null 2>&1; then
        msg_inf "已生成 IPv4${use_ipv6:+/IPv6} 配置"
        test_and_reload_nginx
        return 0
    fi

    if [[ "$use_ipv6" == "y" ]]; then
        msg_inf "检测到 IPv6 监听测试失败，自动回退为仅 IPv4..."
        listen_line_v6=""
        build_domain_conf
        enable_sites

        if nginx -t >/dev/null 2>&1; then
            msg_inf "已自动回退为仅 IPv4 配置"
            test_and_reload_nginx
            return 0
        fi
    fi

    echo "----------------------------------------------------------------"
    echo "Nginx 配置检查"
    echo "----------------------------------------------------------------"
    echo "正在测试 nginx 配置..."
    if ! nginx -t; then
        msg_err "nginx 配置检查未通过！"
        msg_inf "请重点检查以下内容："
        echo "1. 域名变量 domain 是否为空"
        echo "2. 证书文件是否正确：${CERT_FULLCHAIN}"
        echo "3. 私钥文件是否正确：${CERT_PRIVKEY}"
        echo "4. fallback_port 是否被占用：${fallback_port}"
        echo "5. sub_port 后端是否已启动：${sub_port}"
        echo "6. web_path / sub_path / json_path / sub2singbox_path 是否包含非法字符"
        exit 1
    fi
}

# -----------------------------
#  安装 sub2sing-box （提供订阅服务）
# -----------------------------
install_sub2sing_box() {
    echo "----------------------------------------------------------------"
    echo "安装 sub2sing-box（将订阅/节点连接转换为 sing-box 配置的工具）"
    echo "----------------------------------------------------------------"
    echo "即将安装本地 sub2sing-box 服务（127.0.0.1:8090）。"
    read -rp "确认继续安装 sub2sing-box？(Y/n): " confirm_sub2sing
    if [[ ! "$confirm_sub2sing" =~ ^[Nn]$ ]]; then
        if pgrep -x "sub2sing-box" > /dev/null; then
            echo "检测到 sub2sing-box 正在运行，准备停止..."
            pkill -x "sub2sing-box"
        fi
        if [ -f "/usr/bin/sub2sing-box" ]; then
            echo "删除旧版 sub2sing-box..."
            rm -f /usr/bin/sub2sing-box
        fi
        wget -P /root/ https://github.com/legiz-ru/sub2sing-box/releases/download/v0.0.9/sub2sing-box_0.0.9_linux_amd64.tar.gz
        tar -xvzf /root/sub2sing-box_0.0.9_linux_amd64.tar.gz -C /root/ --strip-components=1 sub2sing-box_0.0.9_linux_amd64/sub2sing-box
        mv /root/sub2sing-box /usr/bin/
        chmod +x /usr/bin/sub2sing-box
        rm /root/sub2sing-box_0.0.9_linux_amd64.tar.gz
        su -c "/usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8090 > /dev/null 2>&1 &" root
    else
        msg_err "已跳过 sub2sing-box 安装。"
    fi
}

# -----------------------------
#  配置计划任务
# -----------------------------
setup_cronjob() {
    echo "----------------------------------------------------------------"
    echo "配置计划任务"
    echo "----------------------------------------------------------------"
    echo "即将写入以下3个 crontab："
    echo "1. 开机启动 sub2sing-box"
    echo "2. 每日重启 x-ui 并重载 nginx"
    echo "3. 每月自动续签证书"
    read -rp "确认是否写入3个计划任务？(Y/n): " confirm_cron
    if [[ "$confirm_cron" =~ ^[Nn]$ ]]; then
        msg_err "已跳过计划任务配置。"
    else
        {
            crontab -l 2>/dev/null | grep -v "certbot\|x-ui\|cloudflareips\|sub2sing-box" || true
            echo '@reboot /usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8090 > /dev/null 2>&1'
            echo '@daily x-ui restart > /dev/null 2>&1 && nginx -s reload > /dev/null 2>&1'
            echo '@monthly certbot renew --webroot -w /var/www/acme --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1'
        } | crontab -
    fi

    echo
    msg_inf 'Xray-core 自动更新默认关闭；以后需要定时更新，请在主菜单 3 → 子菜单 2 中手动设置。'
    if [[ -n "$(xray_auto_cron_listing)" ]]; then
        echo -e "${yellow}[WARN] 检测到先前的 Xray 自动更新任务，会覆盖本次选定的 ${XRAY_REQUESTED_CORE_VERSION:-v26.6.27}。${none}"
        echo '为保留本次安装的兼容内核，安装流程将关闭旧 Xray 内核定时更新任务。'
        xray_clear_managed_cron || msg_err '未能清理旧定时任务，请在主菜单 3 → 子菜单 3 中检查。'
    fi
}

# -----------------------------
#  获取当前 SSH 端口
# -----------------------------
get_ssh_port() {
    local p
    p="$(grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n1)"
    [[ -z "$p" ]] && p=22
    echo "$p"
}

# -----------------------------
#  配置 UFW 防火墙
# -----------------------------
setup_ufw() {

  _check_listen_ports() {
    local ports="$1"
    ports="${ports//,/ }"
    ports="${ports//，/ }"

    local listen_ports
    listen_ports="$(ss -lntuH 2>/dev/null | awk '{print $5}' | sed 's/.*://')"

    local p start end i found any=0 mid
    for p in $ports; do
      [[ -z "$p" ]] && continue
      any=1
      if [[ "$p" =~ ^[0-9]+$ ]]; then
        if echo "$listen_ports" | grep -qx "$p"; then
          echo "  ✅ 端口 $p 正在监听"
        else
          echo "  ❌ 端口 $p 未监听（防火墙放行≠服务已启动）"
        fi
      elif [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
        IFS='-' read -r start end <<< "$p"
        if (( start > end )); then
          echo "  ⚠️ 忽略非法端口范围：$p"
          continue
        fi
        mid=$(( (start + end) / 2 ))
        found=0
        for i in "$start" "$mid" "$end"; do
          if echo "$listen_ports" | grep -qx "$i"; then
            found=1
            break
          fi
        done
        if [[ $found -eq 1 ]]; then
          echo "  ✅ 端口范围 $p 内检测到有端口在监听（抽样）"
        else
          echo "  ❌ 端口范围 $p 内未检测到监听（抽样：$start,$mid,$end）"
        fi
      else
        echo "  ⚠️ 忽略非法端口格式：$p"
      fi
    done
    [[ $any -eq 0 ]] && echo "  （未提供额外端口，略过监听检查）"
  }

  _purge_except_ssh() {
    if ! command -v ufw >/dev/null 2>&1; then
      yellow "未检测到 ufw。"
      return 1
    fi

    local sshp
    sshp="$(get_ssh_port)"
    yellow "将清除除 SSH(${sshp}) 以外的所有 UFW 入站规则（含 v6），SSH tcp/udp 会保留。"
    read -rp "确认执行？输入 YES 继续: " confirm
    [[ "$confirm" == "YES" ]] || { yellow "已取消"; return 0; }

    local nums
    nums="$(
      ufw status numbered 2>/dev/null \
      | sed -nE 's/^\[\s*([0-9]+)\]\s+(.+)$/\1|\2/p' \
      | awk -F'|' -v p="$sshp" '
          {
            line=$2
            if (line ~ ("^" p "/tcp") || line ~ ("^" p "/udp")) next
            print $1
          }'
    )"

    if [[ -z "$nums" ]]; then
      green "没有需要清除的规则（除了 SSH 外已无其它规则）。"
      return 0
    fi

    while read -r n; do
      [[ -z "$n" ]] && continue
      ufw --force delete "$n" >/dev/null 2>&1 || true
    done < <(echo "$nums" | sort -nr)

    ufw reload >/dev/null 2>&1 || true
    green "清理完成。当前规则如下："
    ufw status numbered
    return 0
  }

  while true; do
    clear
    echo "---------------- 防火墙设置 (ufw) ----------------"
    echo " 1) 开启防火墙并设置放行端口（默认放行 SSH/80/443/8443/2053）"
    echo " 2) 关闭防火墙"
    echo " 3) 查看当前防火墙状态/规则（并检查监听）"
    echo " 4) 清除除 SSH 以外的所有放行规则"
    echo " 0) 返回上级菜单"
    echo "-------------------------------------------------"
    read -rp " 请选择 [0-4]: " ans

    case "$ans" in
      1)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，尝试安装"
          apt-get update || true
          DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || {
            red "安装 ufw 失败"
            read -rp "回车返回..." _
            continue
          }
        fi

        local sshp ports default_ports all_ports p start end
        sshp="$(get_ssh_port)"
        default_ports="80 443 8443 2053"

        yellow "当前 SSH 端口：$sshp，将自动放行 tcp/udp 防止失联。"
        yellow "默认还将放行端口：$default_ports"
        read -rp "请输入需要额外放行的端口（例如：2222 51000-52000，可留空）: " ports

        ufw --force enable >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1 || true
        ufw default allow outgoing >/dev/null 2>&1 || true

        ufw allow "${sshp}/tcp" >/dev/null 2>&1
        ufw allow "${sshp}/udp" >/dev/null 2>&1

        all_ports="$default_ports $ports"
        all_ports="${all_ports//,/ }"
        all_ports="${all_ports//，/ }"

        for p in $all_ports; do
          [[ -z "$p" ]] && continue

          if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
            IFS='-' read -r start end <<< "$p"
            if (( start < 1 || end > 65535 || start > end )); then
              yellow "忽略非法端口范围：$p"
              continue
            fi
            ufw allow "${start}:${end}/tcp" >/dev/null 2>&1
            ufw allow "${start}:${end}/udp" >/dev/null 2>&1

          elif [[ "$p" =~ ^[0-9]+$ ]]; then
            if (( p < 1 || p > 65535 )); then
              yellow "忽略非法端口：$p"
              continue
            fi
            ufw allow "${p}/tcp" >/dev/null 2>&1
            ufw allow "${p}/udp" >/dev/null 2>&1

          else
            yellow "忽略非法端口格式：$p"
          fi
        done

        ufw reload >/dev/null 2>&1 || true

        echo ""
        green "UFW 已开启，当前规则如下："
        ufw status numbered
        echo ""
        yellow "监听检查（用于判断“端口不通”是否其实是服务没起来）："
        _check_listen_ports "$all_ports"
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
      3)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw。"
          read -rp "回车返回..." _
          continue
        fi
        echo ""
        ufw status verbose
        echo ""
        ufw status numbered
        echo ""
        yellow "当前系统监听端口（节选）："
        ss -lntu | head -n 30
        echo ""
        yellow "默认关注端口监听情况：SSH/80/443/8443/2053"
        _check_listen_ports "$(get_ssh_port) 80 443 8443 2053"
        echo ""
        read -rp "回车返回菜单..." _
        ;;
      4)
        _purge_except_ssh
        read -rp "回车返回菜单..." _
        ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

# -----------------------------
#  显示安装结果
# -----------------------------
show_final_details() {
    if systemctl is-active --quiet x-ui; then
        clear >/dev/null 2>&1 || true
        systemctl status x-ui --no-pager -l | sed -n '1,12p' || true
        msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        nginx -T 2>/dev/null | grep -i 'ssl_certificate\|ssl_certificate_key' || true
        msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        certbot certificates 2>/dev/null | grep -i 'Path:\|Domains:\|Expiry Date:' || true

        msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        msg_inf "X-UI 安全面板: https://${domain}:${panel_port}/${panel_path}/\n"
        echo -e "用户名:  ${config_username} \n"
        echo -e "密码:    ${config_password} \n"
        msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        msg_inf "网站入口（内容需手动部署，Nginx 当前反代至 127.0.0.1:8080）: https://${domain}/\n"
        msg_inf "首个客户端 Web 订阅页: https://${domain}/${web_path}?name=first\n"
        msg_inf "本地 sub2sing-box 地址: https://${domain}/${sub2singbox_path}/\n"

        msg_inf "[1] VLESS + REALITY 默认节点\n"
        msg_inf "Reality 域名/SNI: ${domain}\n"
        msg_inf "Reality 端口: ${reality_port}\n"
        msg_inf "Reality 伪装站（本地 Nginx TLS）: 127.0.0.1:${fallback_port}\n"
        msg_inf "Reality UUID: ${client_id}\n"
        msg_inf "Reality PublicKey: ${public_key}\n"
        msg_inf "Reality ShortId: ${short_id}\n"
        msg_inf "Reality URI: ${reality_uri}\n"

        msg_inf "[2] VLESS + WS + TLS + CDN 默认节点\n"
        msg_inf "WS 域名/SNI/Host: ${domain}\n"
        msg_inf "WS 端口: ${ws_port}\n"
        msg_inf "WS Path: /${ws_path}\n"
        msg_inf "WS UUID: ${ws_client_id}\n"
        msg_inf "WS URI: ${ws_uri}\n"

        if command -v qrencode >/dev/null 2>&1; then
            msg_inf "Reality URI 二维码："
            qrencode -t ANSIUTF8 "${reality_uri}"
            echo
            msg_inf "WS+TLS+CDN URI 二维码："
            qrencode -t ANSIUTF8 "${ws_uri}"
            echo
        else
            msg_err "未检测到 qrencode，无法输出二维码。"
            echo
        fi

        msg_inf "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        msg_inf "请务必保存本次安装输出信息！"
    else
        nginx -t && systemctl status x-ui --no-pager -l | sed -n '1,20p' || true
        msg_err "请检查 sqlite 与 x-ui 状态，建议在全新 Linux 环境重试！"
    fi
}
read_xui_reality_info() {
    [[ -f "$XUIDB" ]] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1

    local row

    # 优先读取 remark=R 或 tag=inbound-reality 的 Reality 入站
    row="$(sqlite3 -separator '|' "$XUIDB" "
        SELECT
            port,
            json_extract(settings, '\$.clients[0].id'),
            json_extract(settings, '\$.clients[0].flow'),
            json_extract(stream_settings, '\$.security'),
            json_extract(stream_settings, '\$.realitySettings.serverNames[0]'),
            json_extract(stream_settings, '\$.realitySettings.privateKey'),
            json_extract(stream_settings, '\$.realitySettings.settings.publicKey'),
            json_extract(stream_settings, '\$.realitySettings.shortIds[0]'),
            json_extract(stream_settings, '\$.realitySettings.settings.fingerprint'),
            json_extract(stream_settings, '\$.realitySettings.settings.spiderX')
        FROM inbounds
        WHERE protocol='vless'
          AND (
                remark='R'
                OR tag='inbound-reality'
              )
          AND json_extract(stream_settings, '\$.security')='reality'
        ORDER BY id DESC
        LIMIT 1;
    " 2>/dev/null || true)"

    # 如果没找到，再退回查任意 Reality 入站
    if [[ -z "$row" ]]; then
        row="$(sqlite3 -separator '|' "$XUIDB" "
            SELECT
                port,
                json_extract(settings, '\$.clients[0].id'),
                json_extract(settings, '\$.clients[0].flow'),
                json_extract(stream_settings, '\$.security'),
                json_extract(stream_settings, '\$.realitySettings.serverNames[0]'),
                json_extract(stream_settings, '\$.realitySettings.privateKey'),
                json_extract(stream_settings, '\$.realitySettings.settings.publicKey'),
                json_extract(stream_settings, '\$.realitySettings.shortIds[0]'),
                json_extract(stream_settings, '\$.realitySettings.settings.fingerprint'),
                json_extract(stream_settings, '\$.realitySettings.settings.spiderX')
            FROM inbounds
            WHERE protocol='vless'
              AND json_extract(stream_settings, '\$.security')='reality'
            ORDER BY id DESC
            LIMIT 1;
        " 2>/dev/null || true)"
    fi

    [[ -n "$row" ]] || return 1

    IFS='|' read -r \
        REALITY_PORT_DB \
        REALITY_UUID_DB \
        REALITY_FLOW_DB \
        REALITY_SECURITY_DB \
        REALITY_DOMAIN_DB \
        REALITY_PRIVATE_KEY_DB \
        REALITY_PUBLIC_KEY_DB \
        REALITY_SHORT_ID_DB \
        REALITY_FP_DB \
        REALITY_SPIDERX_DB <<< "$row"

    [[ "$REALITY_SECURITY_DB" == "reality" ]] || return 1
    [[ -n "$REALITY_PORT_DB" ]] || return 1
    [[ -n "$REALITY_UUID_DB" ]] || return 1
    [[ -n "$REALITY_DOMAIN_DB" ]] || return 1
    [[ -n "$REALITY_PUBLIC_KEY_DB" ]] || return 1
    [[ -n "$REALITY_SHORT_ID_DB" ]] || return 1

    [[ -z "$REALITY_FLOW_DB" || "$REALITY_FLOW_DB" == "null" ]] && REALITY_FLOW_DB="xtls-rprx-vision"
    [[ -z "$REALITY_FP_DB" || "$REALITY_FP_DB" == "null" ]] && REALITY_FP_DB="chrome"
    [[ -z "$REALITY_SPIDERX_DB" || "$REALITY_SPIDERX_DB" == "null" ]] && REALITY_SPIDERX_DB="/"

    return 0
}
# -----------------------------
#  打印节点信息
# -----------------------------
print_node_info() {
    install_tool_deps

    if ! read_xui_reality_info; then
        msg_err "未能从 x-ui 数据库读取 Reality 节点信息。下面输出当前 inbounds 供排查："
        sqlite3 -line "$XUIDB" "SELECT id, protocol, port, remark FROM inbounds;" 2>/dev/null || true
        return 1
    fi

    local show_addr reality_uri info_file
    show_addr="${REALITY_DOMAIN_DB}"

	reality_uri="vless://${REALITY_UUID_DB}@${REALITY_DOMAIN_DB}:${REALITY_PORT_DB}?encryption=none&flow=${REALITY_FLOW_DB}&security=reality&sni=${REALITY_DOMAIN_DB}&fp=${REALITY_FP_DB}&pbk=${REALITY_PUBLIC_KEY_DB}&sid=${REALITY_SHORT_ID_DB}&spx=%2F&type=tcp&headerType=none#R"
    info_file="/root/_xui_reality_node_info.txt"

    echo
    msg_inf "---------- 节点信息 -------------"
    echo -e "${yellow}地址(Address)${none} = ${cyan}${show_addr}${none}"
    echo -e "${yellow}端口(Port)${none} = ${cyan}${REALITY_PORT_DB}${none}"
    echo -e "${yellow}UUID${none} = ${cyan}${REALITY_UUID_DB}${none}"
    echo -e "${yellow}Flow${none} = ${cyan}${REALITY_FLOW_DB}${none}"
    echo -e "${yellow}安全(TLS)${none} = ${cyan}reality${none}"
    echo -e "${yellow}SNI${none} = ${cyan}${REALITY_DOMAIN_DB}${none}"
    echo -e "${yellow}Fingerprint${none} = ${cyan}${REALITY_FP_DB}${none}"
    echo -e "${yellow}PublicKey${none} = ${cyan}${REALITY_PUBLIC_KEY_DB}${none}"
    echo -e "${yellow}ShortID${none} = ${cyan}${REALITY_SHORT_ID_DB}${none}"
    echo
    msg_inf "---------- VLESS Reality URI ----------"
    echo -e "${cyan}${reality_uri}${none}"
    echo

    if command -v qrencode >/dev/null 2>&1; then
        msg_inf "二维码（UTF8）"
        qrencode -t UTF8 "${reality_uri}"
        echo
    else
        msg_err "未检测到 qrencode，无法输出二维码。"
    fi

    {
        echo "---------- 节点信息 -------------"
        echo "Address = ${show_addr}"
        echo "Port = ${REALITY_PORT_DB}"
        echo "UUID = ${REALITY_UUID_DB}"
        echo "Flow = ${REALITY_FLOW_DB}"
        echo "TLS = reality"
        echo "SNI = ${REALITY_DOMAIN_DB}"
        echo "Fingerprint = ${REALITY_FP_DB}"
        echo "PublicKey = ${REALITY_PUBLIC_KEY_DB}"
        echo "ShortID = ${REALITY_SHORT_ID_DB}"
        echo
        echo "---------- VLESS Reality URI ----------"
        echo "${reality_uri}"
    } > "${info_file}"

    msg_ok "节点信息已保存到：${info_file}"
}

# -----------------------------
#  更新域名 / SNI
# -----------------------------
update_domain_sni() {
    clear >/dev/null 2>&1 || true
    show_banner
    echo "----------------------------------------------------------------"
    echo "更新域名 / SNI"
    echo "----------------------------------------------------------------"

    local old_domain=""
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$XUIDB" ]]; then
        old_domain=$(sqlite3 "$XUIDB" "
            SELECT json_extract(stream_settings, '\$.realitySettings.serverNames[0]')
            FROM inbounds
            WHERE protocol='vless'
              AND json_extract(stream_settings, '\$.security')='reality'
            LIMIT 1;
        " 2>/dev/null | tr -d '\n')
    fi

    if [[ -z "$old_domain" ]]; then
        msg_err "无法从数据库读取当前域名，请确认 x-ui 已安装且 Reality 节点存在。"
        pause
        return 1
    fi

    echo "当前域名/SNI: ${old_domain}"
    echo

    local new_domain=""
    while [[ -z "$new_domain" ]]; do
        read -rp "请输入新域名 (如 example.com): " new_domain
        new_domain=$(echo "$new_domain" | tr -d '[:space:]')
    done

    if [[ "$new_domain" == "$old_domain" ]]; then
        msg_err "新域名与当前域名相同，无需更新。"
        pause
        return 0
    fi

    get_server_ips

    echo "当前服务器 IPv4: ${IP4}"
    echo "请确保新域名 ${new_domain} 已解析到本机 IP，否则证书申请可能失败。"

    read -rp "确认解析已完成？(y/N): " dns_ok

    if [[ ! "$dns_ok" =~ ^[Yy]$ ]]; then
        msg_err "用户取消操作。"
        pause
        return 0
    fi

    if ! prepare_cert_for_domain "$new_domain"; then
        msg_err "证书处理失败，域名更新中止。"
        pause
        return 1
    fi

    local cert_info cert_name cert_file key_file

    cert_info=$(get_cert_paths "$new_domain" 2>/dev/null || true)

    if [[ -z "$cert_info" ]]; then
        msg_err "无法定位新域名证书文件。"
        pause
        return 1
    fi

    cert_name=$(echo "$cert_info" | cut -d'|' -f1)
    cert_file=$(echo "$cert_info" | cut -d'|' -f2)
    key_file=$(echo "$cert_info" | cut -d'|' -f3)

    mkdir -p "/root/cert/${new_domain}"

    ln -sf "$cert_file" "/root/cert/${new_domain}/fullchain.pem"
    ln -sf "$key_file" "/root/cert/${new_domain}/privkey.pem"

    echo "----------------------------------------------------------------"
    echo "更新 nginx 配置..."

    local nginx_conf="/etc/nginx/sites-available/${old_domain}"
    local nginx_conf_new="/etc/nginx/sites-available/${new_domain}"
    local nginx_enabled="/etc/nginx/sites-enabled"

    if [[ -f "$nginx_conf" ]]; then

        cp -a "$nginx_conf" "$nginx_conf_new"

        sed -i "s/server_name ${old_domain};/server_name ${new_domain};/g" "$nginx_conf_new"

        sed -i "s|ssl_certificate .*;|ssl_certificate ${cert_file};|g" "$nginx_conf_new"

        sed -i "s|ssl_certificate_key .*;|ssl_certificate_key ${key_file};|g" "$nginx_conf_new"

        rm -f "$nginx_enabled/${old_domain}"

        ln -sf "$nginx_conf_new" "$nginx_enabled/${new_domain}"

    else
        msg_err "未找到 nginx 配置文件: ${nginx_conf}"
        pause
        return 1
    fi

    local http_conf="/etc/nginx/sites-available/80.conf"

    if [[ -f "$http_conf" ]]; then
        sed -i "s/server_name ${old_domain};/server_name ${new_domain};/g" "$http_conf"
    fi

    #
    # 删除 ACME 临时配置
    #
    rm -f /etc/nginx/sites-enabled/acme-bootstrap.conf 2>/dev/null

    if ! nginx -t; then
        msg_err "nginx 配置测试失败，请检查配置文件。"
        pause
        return 1
    fi

    systemctl reload nginx || {
        msg_err "nginx 重载失败"
        pause
        return 1
    }

    msg_ok "nginx 配置更新完成"

    echo "----------------------------------------------------------------"
    echo "更新 x-ui 数据库中的域名/SNI 字段..."

    local backup_db="${XUIDB}.backup.$(date +%Y%m%d_%H%M%S)"

    cp -a "$XUIDB" "$backup_db" \
        && msg_inf "数据库已备份至 $backup_db"

    sqlite3 "$XUIDB" <<EOF
UPDATE inbounds
SET stream_settings = json_set(
    stream_settings,
    '$.realitySettings.serverNames', json_array('${new_domain}'),
    '$.realitySettings.settings.serverName', '${new_domain}'
)
WHERE protocol='vless'
  AND json_extract(stream_settings, '\$.security')='reality';

UPDATE inbounds
SET stream_settings = json_set(
    stream_settings,
    '$.tlsSettings.serverName', '${new_domain}',
    '$.tlsSettings.certificates[0].certificateFile', '/root/cert/${new_domain}/fullchain.pem',
    '$.tlsSettings.certificates[0].keyFile', '/root/cert/${new_domain}/privkey.pem'
)
WHERE protocol='vless'
  AND json_extract(stream_settings, '\$.security')='tls';
EOF

    sqlite3 "$XUIDB" \
        "UPDATE settings SET value='${new_domain}' WHERE key='webDomain';" \
        2>/dev/null || true

    sqlite3 "$XUIDB" \
        "UPDATE settings SET value='${new_domain}' WHERE key='subDomain';" \
        2>/dev/null || true

    #
    # 修复 webCertFile / webKeyFile
    #
    sqlite3 "$XUIDB" \
        "UPDATE settings SET value='/root/cert/${new_domain}/fullchain.pem' WHERE key='webCertFile';" \
        2>/dev/null || true

    sqlite3 "$XUIDB" \
        "UPDATE settings SET value='/root/cert/${new_domain}/privkey.pem' WHERE key='webKeyFile';" \
        2>/dev/null || true

    /usr/local/x-ui/x-ui cert \
        -webCert "/root/cert/${new_domain}/fullchain.pem" \
        -webCertKey "/root/cert/${new_domain}/privkey.pem" \
        >/dev/null 2>&1

    msg_ok "数据库更新完成"

    systemctl restart x-ui

    sleep 2

    if systemctl is-active --quiet x-ui; then
        msg_ok "x-ui 服务已重启"
    else
        msg_err "x-ui 服务启动失败，请检查日志"
    fi

    local panel_path

    panel_path=$(sqlite3 "$XUIDB" \
        "select value from settings where key='webBasePath';" \
        2>/dev/null)

    [[ -z "$panel_path" ]] && panel_path="/"

    echo "----------------------------------------------------------------"
    msg_ok "域名/SNI 更新成功！"

    echo "原域名: ${old_domain}"
    echo "新域名: ${new_domain}"
    echo "证书路径: ${cert_file}"

    echo
    echo "Reality SNI:"
    echo "${new_domain}"

    echo
    echo "x-ui 面板地址:"
    echo "https://${new_domain}:${PANEL_PORT_FIXED}${panel_path}"

    pause
}

# -----------------------------
#  域名校验
# -----------------------------
is_domain_like() {
    [[ "$1" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]]
}

# -----------------------------
#  目标网站检测
# -----------------------------
detect_target_site() {
    install_tool_deps

    local check_domain=""
    local out=""
    local proto=""
    local alpn=""
    local http_code=""
    local server_hdr=""
    local via_hdr=""
    local location_hdr=""
    local total_t=""
    local ok_tls13="no"
    local ok_h2="no"
    local ok_x25519="no"
    local temp_key=""
    local x25519_test=""

    echo
    read -rp "请输入要检测的目标域名（如 www.yahoo.co.jp）: " check_domain
    check_domain="$(echo -n "$check_domain" | tr -d '\r\n[:space:]')"

    if [[ -z "$check_domain" ]]; then
        msg_err "域名不能为空。"
        return 1
    fi

    if ! is_domain_like "$check_domain"; then
        msg_err "域名格式不合法：${check_domain}"
        return 1
    fi

    echo
    msg_inf "══════════════════════════════════════════"
    msg_inf "   REALITY 目标站检测: ${check_domain}"
    msg_inf "══════════════════════════════════════════"

    echo
    echo -e "${yellow}[1/5] TLS 1.3 + ALPN(h2) + X25519 握手检测...${none}"
    out="$(openssl s_client \
        -connect "${check_domain}:443" \
        -servername "${check_domain}" \
        -tls1_3 \
        -alpn h2 \
        </dev/null 2>/dev/null || true)"

    proto="$(printf '%s\n' "$out" | awk -F': ' '/Protocol/ {print $2; exit}')"
    alpn="$(printf '%s\n' "$out" | awk -F': ' '/ALPN protocol/ {print $2; exit}')"
    temp_key="$(printf '%s\n' "$out" | awk -F': ' '/Server Temp Key/ {print $2; exit}')"

    if printf '%s\n' "$out" | grep -q 'TLSv1.3'; then
        ok_tls13="yes"
    fi
    if [[ "$alpn" == "h2" ]]; then
        ok_h2="yes"
    fi
    if printf '%s\n' "$temp_key" | grep -qi 'X25519'; then
        ok_x25519="yes"
    fi

    echo -e "  TLS 1.3: ${cyan}${ok_tls13}${none}"
    echo -e "  ALPN(h2): ${cyan}${ok_h2}${none}"
    echo -e "  X25519: ${cyan}${ok_x25519}${none}"
    [[ -n "$proto" ]] && echo -e "  Protocol: ${cyan}${proto}${none}"
    [[ -n "$alpn" ]] && echo -e "  ALPN: ${cyan}${alpn}${none}"
    [[ -n "$temp_key" ]] && echo -e "  Server Temp Key: ${cyan}${temp_key}${none}"

    echo
    echo -e "${yellow}[2/5] X25519 定向检测...${none}"
    x25519_test="$(openssl s_client \
        -connect "${check_domain}:443" \
        -servername "${check_domain}" \
        -tls1_3 \
        -groups X25519 \
        </dev/null 2>/dev/null || true)"

    if printf '%s\n' "$x25519_test" | grep -q 'TLSv1.3'; then
        if printf '%s\n' "$x25519_test" | awk -F': ' '/Server Temp Key/ {print $2}' | grep -qi 'X25519'; then
            echo -e "  X25519 定向握手: ${green}支持${none}"
        else
            echo -e "  X25519 定向握手: ${yellow}握手成功，但未明确显示 X25519${none}"
        fi
    else
        echo -e "  X25519 定向握手: ${red}失败或不支持${none}"
    fi

    echo
    echo -e "${yellow}[3/5] HTTP/2 响应头检测...${none}"
    out="$(curl -I --http2 --tlsv1.3 -sS "https://${check_domain}/" 2>/dev/null || true)"
    http_code="$(printf '%s\n' "$out" | awk 'toupper($1) ~ /^HTTP\/2$/ {print $2; exit}')"
    server_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^server:/ {sub(/\r$/,""); print substr($0,9); exit}')"
    via_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^via:/ {sub(/\r$/,""); print substr($0,6); exit}')"
    location_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/\r$/,""); print substr($0,11); exit}')"

    [[ -n "$http_code" ]] && echo -e "  HTTP 状态: ${cyan}${http_code}${none}" || echo -e "  HTTP 状态: ${red}获取失败${none}"
    [[ -n "$server_hdr" ]] && echo -e "  Server: ${cyan}${server_hdr}${none}"
    [[ -n "$via_hdr" ]] && echo -e "  Via/CDN: ${cyan}${via_hdr}${none}"
    [[ -n "$location_hdr" ]] && echo -e "  Location: ${cyan}${location_hdr}${none}"

    echo
    echo -e "${yellow}[4/5] 单次时延检测...${none}"
    out="$(curl -o /dev/null -s --http2 --tlsv1.3 \
      -w 'connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}' \
      "https://${check_domain}/" 2>/dev/null || true)"
    echo -e "  ${cyan}${out}${none}"
    total_t="$(printf '%s\n' "$out" | sed -n 's/.*total=\([0-9.]*\).*/\1/p')"

    echo
    echo -e "${yellow}[5/5] 连续 3 次稳定性测试...${none}"
    local i
    for i in 1 2 3; do
        out="$(curl -o /dev/null -s --http2 --tlsv1.3 \
          -w "第${i}次: connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}" \
          "https://${check_domain}/" 2>/dev/null || true)"
        echo -e "  ${cyan}${out}${none}"
    done

    echo
    echo -e "${yellow}结论：${none}"
    if [[ "$ok_tls13" == "yes" && "$ok_h2" == "yes" && "$ok_x25519" == "yes" ]]; then
        if awk "BEGIN{exit !(${total_t:-9} < 0.20)}"; then
            echo -e "  ${green}适合做 REALITY 候选目标站${none}"
            echo -e "  ${green}理由：TLS 1.3 正常、h2 正常、X25519 正常、总耗时较低。${none}"
        elif awk "BEGIN{exit !(${total_t:-9} < 0.50)}"; then
            echo -e "  ${yellow}可以作为 REALITY 候选，但时延表现一般${none}"
            echo -e "  ${yellow}理由：TLS 1.3 / h2 / X25519 均满足。${none}"
        else
            echo -e "  ${yellow}协议层合格，但延迟偏高，建议再对比其他站点${none}"
            echo -e "  ${yellow}理由：TLS 1.3 / h2 / X25519 均满足。${none}"
        fi
    else
        echo -e "  ${red}不推荐作为 REALITY 目标站${none}"
        echo -e "  ${red}原因：TLS 1.3、h2 或 X25519 不满足。${none}"
    fi
}









# -----------------------------
#  系统参数配置菜单（独立脚本）
# -----------------------------
run_sys_conf() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_conf.sh"
  local tmp="/tmp/sys_conf.sh"

  download_with_retry "$url" "$tmp" || { red "下载 sys_conf.sh 失败"; read -rp "回车返回..." _; return 1; }
  [[ -s "$tmp" ]] || { red "sys_conf.sh 文件为空"; read -rp "回车返回..." _; return 1; }
  bash "$tmp"
}

# -----------------------------
#  回程路由测试
# -----------------------------
besttrace_test() {
    install_tool_deps
    if command -v curl >/dev/null 2>&1; then
        bash <(curl -fsSL git.io/besttrace)
    else
        bash <(wget -qO- git.io/besttrace)
    fi
}

# -----------------------------
#  IP 质量检测
# -----------------------------
ip_quality_check() {
    install_tool_deps
    echo "检查 IP 质量中..."
    if ! curl -fsSL --max-time 15 https://Check.Place | bash -s -- -I; then
        msg_err "IP 质量检测执行失败，可能无法访问 Check.Place。"
        return 1
    fi
}

# -----------------------------
#  系统查询
# -----------------------------
system_query() {
    install_tool_deps
    clear >/dev/null 2>&1 || true

    local cpu_info cpu_cores cpu_freq mem_info disk_info load os_info kernel_version cpu_arch hostname now timezone runtime dns_addresses
    local cc_algo qdisc_algo headers_status active_qdisc default_iface
    local ipinfo country city isp
    local TOOL_IPV4="${TOOL_IPV4:-}" TOOL_IPV6="${TOOL_IPV6:-}"
    local xray_cur_ver xray_latest_ver xray_ver_str

    cpu_info="$(lscpu 2>/dev/null | awk -F': +' '/Model name:/ {print $2; exit}')"
    [ -z "${cpu_info:-}" ] && cpu_info="$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)"
    [ -z "${cpu_info:-}" ] && cpu_info="未知"

    cpu_cores="$(nproc 2>/dev/null || echo 1)"

    cpu_freq="$(awk -F': ' '/cpu MHz/ {printf "%.1f GHz", $2/1000; exit}' /proc/cpuinfo 2>/dev/null || true)"

    mem_info="$(awk '
      /MemTotal/     {t=$2}
      /MemFree/      {f=$2}
      /^Buffers:/    {b=$2}
      /^Cached:/     {c=$2}
      /SReclaimable/ {r=$2}
      /Shmem:/       {s=$2}
      END{
        if (t == 0) {
          print "未知"
          exit
        }
        used = t - f - b - c - r + s
        if (used < 0) used = 0
        printf "%.2f/%.2f MB (%.2f%%)", used/1024, t/1024, used*100/t
      }' /proc/meminfo 2>/dev/null)"

    disk_info="$(df -hP / 2>/dev/null | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')"
    [ -z "${disk_info:-}" ] && disk_info="未知"

    load="$(awk '{printf "%s, %s, %s", $1, $2, $3}' /proc/loadavg 2>/dev/null)"
    [ -z "${load:-}" ] && load="$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs || true)"
    [ -z "${load:-}" ] && load="未知"

    if [ -r /etc/os-release ]; then
        os_info="$(. /etc/os-release && echo "${PRETTY_NAME:-未知}")"
    else
        os_info="未知"
    fi

    kernel_version="$(uname -r 2>/dev/null || echo 未知)"
    cpu_arch="$(uname -m 2>/dev/null || echo 未知)"
    hostname="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo 未知)"
    now="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 未知)"
    timezone="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo '未知')"

    runtime="$(awk '{
      d=int($1/86400);
      h=int(($1%86400)/3600);
      m=int(($1%3600)/60);
      printf("%d天 %d时 %d分", d, h, m)
    }' /proc/uptime 2>/dev/null)"
    [ -z "${runtime:-}" ] && runtime="未知"

    dns_addresses="$(awk '/^nameserver[ \t]+/ {printf "%s ", $2} END{print ""}' /etc/resolv.conf 2>/dev/null | xargs)"
    [ -z "${dns_addresses:-}" ] && dns_addresses="未知"

    cc_algo="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    [ -z "${cc_algo:-}" ] && cc_algo="未知"

    qdisc_algo="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
    [ -z "${qdisc_algo:-}" ] && qdisc_algo="未知"

    default_iface="$(ip route get 1.1.1.1 2>/dev/null | awk '{
      for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}
    }')"
    [ -z "${default_iface:-}" ] && default_iface="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{
      for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}
    }')"

    if [ -n "${default_iface:-}" ]; then
        active_qdisc="$(tc qdisc show dev "$default_iface" 2>/dev/null | awk '/^qdisc/ {print $2; exit}')"
    else
        active_qdisc=""
    fi

    if command -v dpkg-query >/dev/null 2>&1; then
        if dpkg-query -W -f='${Status}\n' "linux-headers-${kernel_version}" 2>/dev/null | grep -q '^install ok installed$'; then
            headers_status="已匹配"
        elif [ -d "/lib/modules/${kernel_version}/build" ] || [ -e "/usr/src/linux-headers-${kernel_version}" ]; then
            headers_status="已匹配"
        else
            headers_status="未匹配"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -q "kernel-headers-${kernel_version}" >/dev/null 2>&1 || [ -d "/lib/modules/${kernel_version}/build" ]; then
            headers_status="已匹配"
        else
            headers_status="未匹配"
        fi
    else
        if [ -d "/lib/modules/${kernel_version}/build" ] || [ -e "/usr/src/linux-headers-${kernel_version}" ]; then
            headers_status="已匹配"
        else
            headers_status="未知"
        fi
    fi

    get_public_ips_tool

    # 获取 Xray 当前版本和最新版本
    xray_cur_ver=""
    xray_latest_ver=""
    if [[ -f /usr/local/x-ui/bin/xray-linux-$(arch) ]]; then
        xray_cur_ver=$(/usr/local/x-ui/bin/xray-linux-$(arch) version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    if [[ -z "$xray_cur_ver" && -f "$XUIDB" ]]; then
        xray_cur_ver=$(sqlite3 "$XUIDB" "SELECT value FROM settings WHERE key='xrayVersion';" 2>/dev/null | tr -d '\r\n' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    fi
    # 从 releases 列表取版本号最高的（与 xray_update.sh 一致）
    xray_latest_ver=$(curl -fsSL --connect-timeout 10 --max-time 20 \
      "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=50" 2>/dev/null \
      | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9]+\.[0-9]+\.[0-9]+"' \
      | sed -E 's/.*"v([0-9]+\.[0-9]+\.[0-9]+)".*/\1/' \
      | sort -V | tail -n1 || true)
    xray_ver_str="未知"
    if [[ -n "$xray_cur_ver" ]]; then
        xray_ver_str="当前 ${xray_cur_ver}"
        [[ -n "$xray_latest_ver" ]] && xray_ver_str+="，最新 ${xray_latest_ver}"
    fi

    ipinfo="$(curl -fsS --max-time 3 ipinfo.io/json 2>/dev/null || true)"
    if [ -n "${ipinfo:-}" ]; then
        country="$(echo "$ipinfo" | awk -F'"' '/"country"/ {print $4; exit}')"
        city="$(echo "$ipinfo" | awk -F'"' '/"city"/ {print $4; exit}')"
        isp="$(echo "$ipinfo" | awk -F'"' '/"org"/ {print $4; exit}')"
    fi

    echo
    echo -e "${cyan}系统信息查询${none}"
    echo -e "${cyan}------------------------------${none}"
    echo -e "主机名:       ${hostname}"
    echo -e "系统版本:     ${os_info}"
    echo -e "Linux版本:    ${kernel_version}"
    echo -e "${cyan}------------------------------${none}"
    echo -e "CPU架构:      ${cpu_arch}"
    echo -e "CPU型号:      ${cpu_info}"
    echo -e "CPU核心数:    ${cpu_cores}"
    [ -n "${cpu_freq:-}" ] && echo -e "CPU频率:      ${cpu_freq}"
    echo -e "${cyan}------------------------------${none}"
    echo -e "系统负载:     ${load}"
    echo -e "物理内存:     ${mem_info}"
    echo -e "硬盘占用:     ${disk_info}"
    echo -e "${cyan}------------------------------${none}"
    [ -n "${isp:-}" ] && echo -e "运营商:       ${isp}"
    [ -n "${TOOL_IPV4:-}" ] && echo -e "IPv4地址:     ${TOOL_IPV4}"
    [ -n "${TOOL_IPV6:-}" ] && echo -e "IPv6地址:     ${TOOL_IPV6}"
    echo -e "DNS地址:      ${dns_addresses}"
    [ -n "${country:-}${city:-}" ] && echo -e "地理位置:     ${country:-未知} ${city:-}"
    echo -e "${cyan}------------------------------${none}"
    echo -e "Xray版本:      ${xray_ver_str}"
    echo -e "拥塞控制算法: ${cc_algo}"
    echo -e "默认队列算法: ${qdisc_algo}"
    [ -n "${default_iface:-}" ] && echo -e "主网卡:       ${default_iface}"
    [ -n "${active_qdisc:-}" ] && echo -e "网卡队列算法: ${active_qdisc}"
    echo -e "系统时间:     ${now}"
    echo -e "系统时区:     ${timezone}"
    echo -e "运行时长:     ${runtime}"
    echo
}

# -----------------------------
#  查看状态
# -----------------------------
view_status() {
    clear >/dev/null 2>&1 || true
    echo
    msg_inf "x-ui 服务状态："
    systemctl status x-ui --no-pager -l 2>/dev/null | sed -n '1,20p' || true
    echo

    msg_inf "nginx 服务状态："
    systemctl status nginx --no-pager -l 2>/dev/null | sed -n '1,20p' || true
    echo

    if [[ -f "$XUIDB" ]]; then
        msg_inf "x-ui 数据库：${XUIDB}"
    else
        msg_err "未找到 x-ui 数据库：${XUIDB}"
    fi

    echo
    msg_inf "监听端口："
    ss -lntp 2>/dev/null | grep -E ":(${PANEL_PORT_FIXED}|443|80)\b" || true
    echo

    if read_xui_reality_info; then
        echo -e "${yellow}Reality 端口${none}: ${cyan}${REALITY_PORT_DB}${none}"
        echo -e "${yellow}Reality SNI${none}: ${cyan}${REALITY_DOMAIN_DB}${none}"
        echo -e "${yellow}Reality UUID${none}: ${cyan}${REALITY_UUID_DB}${none}"
        echo -e "${yellow}Reality PublicKey${none}: ${cyan}${REALITY_PUBLIC_KEY_DB}${none}"
        echo -e "${yellow}Reality ShortID${none}: ${cyan}${REALITY_SHORT_ID_DB}${none}"
    else
        msg_err "未能解析 Reality 节点状态。"
    fi

    echo
    if command -v certbot >/dev/null 2>&1; then
        msg_inf "证书状态："
        certbot certificates 2>/dev/null | grep -i 'Domains:\|Expiry Date:\|Path:' || true
    fi
    echo
}

# -----------------------------
#  安装/重装主流程
# -----------------------------
install_xui_pro() {
    clear >/dev/null 2>&1 || true
    show_banner

    # Original menu 1 rebuilds the panel and UPDATE_XUIDB deletes all existing
    # inbound rows. Do not let a core-only change accidentally reset clients.
    if [[ -s "$XUIDB" ]]; then
        local confirm_rebuild=''
        msg_err '已检测到原有 3X-UI 节点数据库。菜单 1 会重装面板、清空节点并重新生成 UUID/REALITY 密钥。'
        msg_inf '如果你只是要切换 Xray 内核版本，请使用主菜单 3，原节点不会被重建。'
        read_tty '确实要清空原节点并重装？请输入 REBUILD 确认：' confirm_rebuild
        if [[ "$confirm_rebuild" != 'REBUILD' ]]; then
            msg_inf '已取消重新安装，原面板及节点保持不变。'
            return 0
        fi
    fi

    # 检测端口 443 冲突：hysteria 2 也默认监听 443
    if ss -lntp 2>/dev/null | grep -q ':443 '; then
        local proc_443
        proc_443=$(ss -lntp 2>/dev/null | grep ':443 ' | head -1)
        if echo "$proc_443" | grep -qi "hysteria"; then
            msg_err "检测到 Hysteria 2 正在占用端口 443。x.sh 和 h.sh 不能同时安装（均默认监听 443）。"
            msg_err "请先卸载 h.sh（Hysteria 2）后再安装 x.sh。"
            pause
            return 1
        fi
    fi

    cleanup_services
    init_runtime_vars
    prepare_domain_vars
    install_packages
    get_server_ips

    if [[ ${AUTODOMAIN} == *"y"* ]]; then
        if ! resolve_to_ip "$domain"; then
            msg_err "自动域名 $domain 没有解析到当前服务器 IP ($IP4)，请先修复 DNS/服务后重试。"
            exit 1
        fi
    fi

    echo "----------------------------------------------------------------"
    echo "SSL 证书处理"
    echo "----------------------------------------------------------------"
    echo "单域名: $domain"
    echo "接下来将处理这个域名的证书。"
    echo "你可以选择重新申请，或复用 VPS 本地已有证书。"

    if ! prepare_cert_for_domain "$domain"; then
        systemctl start nginx >/dev/null 2>&1 || true
        msg_err "$domain 的证书不可用，程序终止！"
        exit 1
    fi

    CERT_INFO=$(get_cert_paths "$domain" 2>/dev/null || true)
    CERT_NAME=$(echo "$CERT_INFO" | cut -d'|' -f1)
    CERT_FULLCHAIN=$(echo "$CERT_INFO" | cut -d'|' -f2)
    CERT_PRIVKEY=$(echo "$CERT_INFO" | cut -d'|' -f3)

    if [[ -z "$CERT_NAME" || -z "$CERT_FULLCHAIN" || -z "$CERT_PRIVKEY" ]]; then
        msg_err "无法定位 ${domain} 的证书文件，程序终止。"
        exit 1
    fi

    mkdir -p /root/cert/${domain}
    chmod 755 /root/cert 2>/dev/null || true
    chmod 755 /root/cert/${domain} 2>/dev/null || true
    ln -sf "${CERT_FULLCHAIN}" /root/cert/${domain}/fullchain.pem
    ln -sf "${CERT_PRIVKEY}" /root/cert/${domain}/privkey.pem

    echo "----------------------------------------------------------------"
    echo "安装 x-ui 面板"
    echo "----------------------------------------------------------------"
    echo "如果系统未检测到 x-ui，将自动下载安装并初始化配置。"

    if systemctl is-active --quiet x-ui; then
        # Usually unreachable due to cleanup_services above; keep behavior for compatibility.
        x-ui restart
        choose_xray_core_version || return 1
        xray_install_selected_core || return 1
    else
        install_panel || { msg_err '面板或所选 Xray-core 安装失败，停止后续节点重建。'; return 1; }
    fi

    UPDATE_XUIDB
    configure_nginx
    install_sub2sing_box
    msg_inf "已跳过伪装站点安装；网站内容由用户手动部署。"
    setup_cronjob
    show_final_details
    pause
}

# -----------------------------
#  主菜单
# -----------------------------
menu() {
    while :; do
        clear >/dev/null 2>&1 || true

        local bold='\033[1m'
        local dim='\033[2m'
        local gray='\033[90m'

        echo -e "${cyan}${bold}╔══════════════════════════════════════════════╗${none}"
        echo -e "${cyan}${bold}║                x-ui-pro 管理界面             ║${none}"
        echo -e "${cyan}${bold}╚══════════════════════════════════════════════╝${none}"
        echo -e "${gray}--------------------------------------------------${none}"

        echo -e " ${blue}${bold}1)${none} ${blue}安装${none}"
        echo -e " ${red}${bold}2)${none} ${red}卸载${none}"
        echo -e "${gray}--------------------------------------------------${none}"
        echo -e " ${yellow}${bold}3)${none} ${yellow}Xray-core 更新管理（手动 / 定时）${none}"
        echo -e " ${yellow}${bold}4)${none} ${yellow}查看状态${none}"
        echo -e " ${yellow}${bold}5)${none} ${yellow}打印节点信息${none}"
        echo -e " ${yellow}${bold}6)${none} ${yellow}目标网站检测${none}"
        echo -e " ${yellow}${bold}7)${none} ${yellow}系统参数配置${none}"
        echo -e " ${yellow}${bold}8)${none} ${yellow}回程路由测试${none}"
        echo -e " ${yellow}${bold}9)${none} ${yellow}IP质量检测${none}"
        echo -e " ${yellow}${bold}10)${none} ${yellow}系统查询${none}"
		echo -e " ${green}${bold}11)${none} ${green}更新域名/SNI${none}"   # 新增行
        echo -e " ${red}${bold}0)${none} 退出"

        echo -e "${gray}--------------------------------------------------${none}"
        echo -e "${dim}${gray}提示：输入数字后回车${none}"
        echo -ne "${green}${bold}请选择 [0-11]${none}${green}: ${none}"

        local choice=""

        read_tty "" choice

        case "${choice}" in
            1) INSTALL="y"; UNINSTALL="n"; install_xui_pro ;;
            2) uninstall_xui_menu ;;
            3) xray_core_menu ;;
            4) view_status ;;
            5) print_node_info ;;
            6) detect_target_site ;;
            7) run_sys_conf ;;
            8) besttrace_test ;;
            9) ip_quality_check ;;
            10) system_query ;;
            11) update_domain_sni ;;
            0) exit 0 ;;
            *) msg_err "无效输入，请重新选择。"; pause ;;
        esac
    done
}

# -----------------------------
#  程序入口
# -----------------------------
main() {
    if [[ "${1:-}" == '--xray-auto-update' ]]; then
        xray_auto_update_once
        return $?
    fi
    parse_args "$@"

    if [[ ${UNINSTALL} == *"y"* ]]; then
        UNINSTALL_XUI
        exit 0
    fi

    if [[ ${INSTALL} == *"y"* ]]; then
        install_xui_pro
        exit 0
    fi

    menu
}

main "$@"

#################################################N-joy##################################################
