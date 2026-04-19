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
ws_port=2083
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
#  清理运行中的服务
# -----------------------------
cleanup_services() {
    systemctl stop x-ui 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true

    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true
    pkill -f apache2 2>/dev/null || true
    pkill -f caddy 2>/dev/null || true

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
    fallback_port=$(make_port)
    short_id=$(openssl rand -hex 4)

    # 双协议默认参数
    ws_port=2083
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
    systemctl stop nginx 2>/dev/null || true
    systemctl disable nginx 2>/dev/null || true

    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true

    printf 'y\n' | x-ui uninstall 2>/dev/null || true

    rm -rf "/etc/x-ui/" "/usr/local/x-ui/" "/usr/bin/x-ui/"
    rm -rf /etc/systemd/system/x-ui.service

    $Pak -y remove nginx nginx-common nginx-core nginx-full || true
    $Pak -y purge nginx nginx-common nginx-core nginx-full || true

    rm -rf "/var/www/html/" "/usr/share/nginx/"
    rm -rf "/var/www/subpage/" 2>/dev/null || true
    rm -rf "/etc/nginx/" 2>/dev/null || true

    msg_ok "已卸载 x-ui / xray / nginx / 网页内容，但已保留证书与依赖。"
    msg_inf "保留目录：/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/www/acme"
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
    echo "即将卸载 x-ui / xray / nginx / 网页内容，但不会删除已申请的证书和依赖。"
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
                curl wget jq bash sudo nginx-full certbot sqlite3 ufw cron \
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
                    curl wget jq bash sudo nginx-full certbot sqlite3 ufw cron \
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
            if ! yum install -y curl wget jq bash sudo nginx certbot sqlite ufw cronie nc openssl; then
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

    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo "尝试使用 IPv4 获取版本信息..."
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                echo "获取 x-ui 版本失败，可能受到 GitHub API 限制，请稍后重试。"
                exit 1
            fi
        fi
        echo "已获取 x-ui 最新版本: ${tag_version}，开始安装..."
        wget -N -O /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo "下载 x-ui 失败，请确认服务器可以访问 GitHub。"
            exit 1
        fi
    else
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
    fi

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

    chmod +x x-ui bin/xray-linux-$(arch) 2>/dev/null || true

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
#  手动更新 Xray + 固定写入每月 1 日 03:00 cron
# -----------------------------
xray_updata() {
    local RAW_XRAY_FRESH_URL="https://raw.githubusercontent.com/byilrq/vps/main/xray_fresh.sh"
    local LOCAL_XRAY_FRESH="/root/xray_fresh.sh"
    local XRAY_CRON_LOG="/var/log/xray_fresh.log"

    echo "----------------------------------------------------------------"
    echo "更新 Xray-core"
    echo "----------------------------------------------------------------"

    touch "$XRAY_CRON_LOG" >/dev/null 2>&1 || true

    echo "下载最新 xray_fresh.sh 到 /root ..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$RAW_XRAY_FRESH_URL" -o "$LOCAL_XRAY_FRESH" || {
            msg_err "下载 xray_fresh.sh 失败"
            return 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$LOCAL_XRAY_FRESH" "$RAW_XRAY_FRESH_URL" || {
            msg_err "下载 xray_fresh.sh 失败"
            return 1
        }
    else
        msg_err "未检测到 curl/wget，无法下载 xray_fresh.sh"
        return 1
    fi

    chmod +x "$LOCAL_XRAY_FRESH" || {
        msg_err "赋予执行权限失败：$LOCAL_XRAY_FRESH"
        return 1
    }

    echo "执行一次本地 xray_fresh.sh ..."
    /bin/bash "$LOCAL_XRAY_FRESH" || {
        msg_err "xray_fresh.sh 执行失败"
        return 1
    }

    echo "写入固定月度计划任务 ..."
    (
        crontab -l 2>/dev/null | grep -Fv "$LOCAL_XRAY_FRESH" || true
        echo "0 3 1 * * /bin/bash $LOCAL_XRAY_FRESH >>$XRAY_CRON_LOG 2>&1"
    ) | crontab -

    msg_ok "Xray 手动更新已执行完成"
    msg_ok "已设置 cron：每月 1 日 03:00 执行 /root/xray_fresh.sh"
    echo "本地脚本: $LOCAL_XRAY_FRESH"
    echo "日志文件: $XRAY_CRON_LOG"
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

        XRAY_BIN="/usr/local/x-ui/bin/xray-linux-$(arch)"
        [[ -x "$XRAY_BIN" ]] || XRAY_BIN="/usr/local/x-ui/bin/xray"

        output=$($XRAY_BIN x25519 2>/dev/null || true)

        private_key=$(printf '%s\n' "$output" | sed -n 's/^PrivateKey: //p' | head -n1 | tr -d '\r')
        [[ -z "$private_key" ]] && private_key=$(printf '%s\n' "$output" | sed -n 's/^Private key: //p' | head -n1 | tr -d '\r')

        public_key=$(printf '%s\n' "$output" | sed -n 's/^Password: //p' | head -n1 | tr -d '\r')
        [[ -z "$public_key" ]] && public_key=$(printf '%s\n' "$output" | sed -n 's/^PublicKey: //p' | head -n1 | tr -d '\r')
        [[ -z "$public_key" ]] && public_key=$(printf '%s\n' "$output" | sed -n 's/^Public key: //p' | head -n1 | tr -d '\r')

        hash32=$(printf '%s\n' "$output" | sed -n 's/^Hash32: //p' | head -n1 | tr -d '\r')

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
      "http/1.1"
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
        /usr/local/x-ui/x-ui cert -webCert "/root/cert/${domain}/fullchain.pem" -webCertKey "/root/cert/${domain}/privkey.pem"
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
        proxy_pass http://127.0.0.1:8080/;
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
        try_files \$uri \$uri/ /index.html =404;
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

        rm -f /etc/nginx/sites-enabled/*
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
    echo "即将安装本地 sub2sing-box 服务（127.0.0.1:8080）。"
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
        su -c "/usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8080 > /dev/null 2>&1 &" root
    else
        msg_err "已跳过 sub2sing-box 安装。"
    fi
}

# -----------------------------
#  安装伪装站点
# -----------------------------
install_fake_site() {

    echo "----------------------------------------------------------------"
    echo "重置伪装站点"
    echo "----------------------------------------------------------------"

    ZIP_URL="https://raw.githubusercontent.com/byilrq/vps/main/html.zip"
    ZIP_FILE="$HOME/html.zip"
    WEB_ROOT="/var/www/html"

    Green="\033[32m"
    Red="\033[31m"
    Blue="\033[36m"
    Font="\033[0m"
    OK="${Green}[OK]${Font}"
    ERROR="${Red}[ERROR]${Font}"

    msg_inf() { echo -e "${Blue} $1 ${Font}"; }
    msg_ok()  { echo -e "${OK} ${Blue} $1 ${Font}"; }
    msg_err() { echo -e "${ERROR} ${Blue} $1 ${Font}"; }

	msg_inf "开始安装 unzip..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y -q >/dev/null 2>&1 || true
        apt-get install -y unzip >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y unzip >/dev/null 2>&1 || true
    fi

    cd "$HOME" || return 1

    msg_inf "开始下载网站压缩包..."
    rm -f "$ZIP_FILE"
    wget -O "$ZIP_FILE" "$ZIP_URL" || {
        msg_err "网站压缩包下载失败！"
        return 1
    }

    [[ -d "$WEB_ROOT" ]] || mkdir -p "$WEB_ROOT"

    msg_inf "清空当前网站目录..."
    rm -rf "${WEB_ROOT:?}"/*

    msg_inf "正在解压到 $WEB_ROOT ..."
    unzip -o "$ZIP_FILE" -d "$WEB_ROOT" >/dev/null 2>&1 || {
        msg_err "网站压缩包解压失败！"
        return 1
    }

    # 防止压缩包内多套一层 html 目录，避免变成 /var/www/html/html
    if [[ -d "$WEB_ROOT/html" ]]; then
        msg_inf "检测到多余 html 目录，正在整理..."
        cp -a "$WEB_ROOT/html/." "$WEB_ROOT/" && rm -rf "$WEB_ROOT/html"
    fi

    msg_ok "网站已成功重置并部署到 $WEB_ROOT"
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
            echo '@reboot /usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8080 > /dev/null 2>&1'
            echo '@daily x-ui restart > /dev/null 2>&1 && nginx -s reload > /dev/null 2>&1'
            echo '@monthly certbot renew --webroot -w /var/www/acme --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1'
        } | crontab -
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
    echo " 1) 开启防火墙并设置放行端口（默认放行 SSH/80/443/8443/2083）"
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
        default_ports="80 443 8443 2083"

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
        yellow "默认关注端口监听情况：SSH/80/443/8443/2083"
        _check_listen_ports "$(get_ssh_port) 80 443 8443 2083"
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
        msg_inf "伪装站主页: https://${domain}/\n"
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
#  修改时区
# -----------------------------
change_tz() {
    local tz=""
    read -rp "请输入时区（回车默认 Asia/Shanghai，例如 Asia/Shanghai）: " tz
    [[ -z "$tz" ]] && tz="Asia/Shanghai"
    timedatectl set-timezone "$tz" && msg_ok "系统时区已设置为：$tz" || msg_err "设置失败，请检查 timedatectl / 时区名是否存在"
}

# -----------------------------
#  修改 DNS
# -----------------------------
set_dns_ui() {
    echo -e "${yellow}正在配置 DNS（8.8.8.8 / 1.1.1.1）并锁定 /etc/resolv.conf ...${none}"

    if [[ -L /etc/resolv.conf ]]; then
        rm -f /etc/resolv.conf
        touch /etc/resolv.conf
    fi

    chattr -i /etc/resolv.conf 2>/dev/null || true

    cat >/etc/resolv.conf <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

    chattr +i /etc/resolv.conf 2>/dev/null || true
    msg_ok "resolv.conf 已写入并尝试加锁（chattr +i）"

    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; then
        systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
    fi
}

# -----------------------------
#  设置 Swap
# -----------------------------
swap_cache() {
    local size_mb confirm fs_type

    echo "当前 Swap："
    free -h | awk 'NR==1 || /Swap:/ {print}'
    echo

    read -rp "请输入 Swap 大小（MB，建议 >=512）: " size_mb
    [[ "$size_mb" =~ ^[0-9]+$ ]] || { msg_err "请输入有效数字"; return 1; }

    read -rp "确认创建/重建 Swap=${size_mb}MB ? (y/n): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { msg_err "已取消"; return 0; }

    swapoff /swapfile >/dev/null 2>&1 || true
    rm -f /swapfile >/dev/null 2>&1 || true

    fs_type="$(stat -f -c %T / 2>/dev/null || true)"
    touch /swapfile || { msg_err "无法创建 /swapfile"; return 1; }

    if [[ "$fs_type" == "btrfs" ]] && command -v chattr >/dev/null 2>&1; then
        chattr +C /swapfile >/dev/null 2>&1 || true
    fi

    if command -v fallocate >/dev/null 2>&1; then
        fallocate -l "${size_mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="${size_mb}" conv=fsync status=progress
    else
        dd if=/dev/zero of=/swapfile bs=1M count="${size_mb}" conv=fsync status=progress
    fi

    chmod 600 /swapfile || { msg_err "chmod 600 失败"; rm -f /swapfile; return 1; }
    mkswap /swapfile >/dev/null 2>&1 || { msg_err "mkswap 失败"; rm -f /swapfile; return 1; }
    swapon /swapfile >/dev/null 2>&1 || { msg_err "swapon 失败"; rm -f /swapfile; return 1; }

    grep -qE '^\s*/swapfile\s' /etc/fstab 2>/dev/null || echo "/swapfile none swap sw 0 0" >> /etc/fstab

    msg_ok "Swap 已启用："
    swapon --show
    free -h | awk 'NR==1 || /Swap:/ {print}'
}

# -----------------------------
#  修改 SSH 端口
# -----------------------------
ssh_port_change() {
    local new_port="$1"
    local SSH_CONFIG="/etc/ssh/sshd_config"

    # 检查 root 权限
    if [[ $EUID -ne 0 ]]; then
        msg_err "请使用 root 权限执行"
        return 1
    fi

    # 参数校验
    [[ -z "$new_port" ]] && { msg_err "请提供新的端口号"; return 1; }
    [[ "$new_port" =~ ^[0-9]+$ ]] || { msg_err "端口必须是数字"; return 1; }
    (( new_port >= 1 && new_port <= 65535 )) || { msg_err "端口范围必须 1-65535"; return 1; }

    # 修改 SSH 配置文件
    if grep -qE '^[[:space:]]*Port[[:space:]]+' "$SSH_CONFIG"; then
        sed -i "s/^[[:space:]]*Port[[:space:]]\+[0-9]\+/Port ${new_port}/" "$SSH_CONFIG"
    elif grep -q "^#Port 22" "$SSH_CONFIG"; then
        sed -i "s/^#Port 22/Port ${new_port}/" "$SSH_CONFIG"
    else
        echo "Port ${new_port}" >> "$SSH_CONFIG"
    fi

    # 重启 SSH 服务
    systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        msg_err "重启 SSH 服务失败，请检查配置文件"
        return 1
    fi

    # 自动放行新端口（防火墙）
    local fw_opened=false
    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        if firewall-cmd --add-port=${new_port}/tcp --permanent &>/dev/null && firewall-cmd --reload &>/dev/null; then
            msg_ok "已通过 firewalld 放行端口 ${new_port}/tcp"
            fw_opened=true
        else
            msg_err "firewalld 放行端口失败，请手动检查"
        fi
    # ufw
    elif command -v ufw &>/dev/null; then
        if ufw allow ${new_port}/tcp &>/dev/null; then
            msg_ok "已通过 ufw 放行端口 ${new_port}/tcp"
            fw_opened=true
        else
            msg_err "ufw 放行端口失败，请手动检查"
        fi
    # iptables
    elif command -v iptables &>/dev/null; then
        if iptables -A INPUT -p tcp --dport ${new_port} -j ACCEPT; then
            # 尝试持久化
            if command -v iptables-save &>/dev/null; then
                if command -v netfilter-persistent &>/dev/null; then
                    netfilter-persistent save &>/dev/null
                elif command -v iptables-save >/dev/null && [ -f /etc/iptables/rules.v4 ]; then
                    iptables-save > /etc/iptables/rules.v4
                elif command -v service iptables save &>/dev/null; then
                    service iptables save &>/dev/null
                else
                    msg_warn "无法自动持久化 iptables 规则，重启后可能失效"
                fi
            fi
            msg_ok "已通过 iptables 放行端口 ${new_port}/tcp"
            fw_opened=true
        else
            msg_err "iptables 放行端口失败，请手动检查"
        fi
    else
        msg_warn "未检测到常见防火墙（firewalld/ufw/iptables），请手动放行端口 ${new_port}"
    fi

    # 最终提示
    msg_ok "SSH 端口已修改为 ${new_port}"
    if [[ "$fw_opened" == true ]]; then
        msg_warn "防火墙已自动放行端口 ${new_port}，请确认 SSH 服务可用后再断开当前连接。"
    else
        msg_warn "请手动确保防火墙放行端口 ${new_port}，否则可能导致断连。"
    fi
}
# -----------------------------
#  设置BBR
# -----------------------------
bbr() {
  set -Eeuo pipefail

  local SYSCTL_FILE="/etc/sysctl.d/99-bbr.conf"

  local G Y R C N
  if [ -t 1 ]; then
    G='\033[32m'
    Y='\033[33m'
    R='\033[31m'
    C='\033[36m'
    N='\033[0m'
  else
    G=''; Y=''; R=''; C=''; N=''
  fi

  info()  { echo -e "${C}[信息]${N} $*"; }
  warn()  { echo -e "${Y}[警告]${N} $*"; }
  error() { echo -e "${R}[错误]${N} $*" >&2; }
  ok()    { echo -e "${G}[完成]${N} $*"; }

  require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
      error "请使用 root 运行"
      return 1
    fi
  }

  pause() {
    echo
    read -r -p "按回车继续..." _
  }

  backup_if_exists() {
    local f="$1"
    if [ -f "$f" ]; then
      cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
    fi
  }

  get_os_id() {
    local id=""
    if [ -r /etc/os-release ]; then
      . /etc/os-release
      id="${ID:-}"
    fi
    echo "$id"
  }

  is_debian_like() {
    local id
    id="$(get_os_id)"
    [[ "$id" == "debian" || "$id" == "ubuntu" ]]
  }

  is_x86_64() {
    [[ "$(uname -m)" == "x86_64" ]]
  }

  bbr_supported() {
    local available
    available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
    echo "$available" | grep -qw bbr
  }

  show_status() {
    local kern cc qdisc headers_status="unknown" available="unknown"

    kern="$(uname -r)"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
    available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"

    if command -v dpkg-query >/dev/null 2>&1; then
      if dpkg-query -W -f='${Status}\n' "linux-headers-$(uname -r)" 2>/dev/null | grep -q '^install ok installed$'; then
        headers_status="installed"
      else
        headers_status="not installed"
      fi
    elif command -v rpm >/dev/null 2>&1; then
      if rpm -q "kernel-headers-$(uname -r)" >/dev/null 2>&1 || rpm -qa | grep -q '^kernel-headers'; then
        headers_status="installed"
      else
        headers_status="not installed"
      fi
    fi

    echo
    echo "内核版本: $kern"
    echo "当前拥塞控制算法: $cc"
    echo "当前队列算法: $qdisc"
    echo "可用拥塞控制算法: $available"
    echo "headers: $headers_status"
    echo
  }

  install_base_packages() {
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y wget gnupg ca-certificates apt-transport-https
    else
      error "当前系统不支持自动安装依赖"
      return 1
    fi
  }

  setup_xanmod_repo() {
    install_base_packages || return 1

    mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
    local keyring="/usr/share/keyrings/xanmod-archive-keyring.gpg"
    local repo_file="/etc/apt/sources.list.d/xanmod-release.list"
    local tmp
    tmp="$(mktemp)"

    if ! wget -qO "$tmp" https://dl.xanmod.org/archive.key; then
      rm -f "$tmp"
      error "下载 XanMod GPG 密钥失败"
      return 1
    fi

    if ! gpg --dearmor -o "$keyring" --yes < "$tmp"; then
      rm -f "$tmp"
      error "导入 XanMod GPG 密钥失败"
      return 1
    fi
    rm -f "$tmp"

    echo "deb [signed-by=${keyring}] https://deb.xanmod.org releases main" > "$repo_file"
    apt-get update -y
  }

  cpu_level_to_flavor() {
    local level="2"
    if grep -qiE 'avx512f|avx512bw|avx512dq|avx512vl' /proc/cpuinfo 2>/dev/null; then
      level="4"
    elif grep -qiE 'avx2|bmi1|bmi2|fma|movbe' /proc/cpuinfo 2>/dev/null; then
      level="3"
    elif grep -qiE 'sse4_2|cx16|popcnt' /proc/cpuinfo 2>/dev/null; then
      level="2"
    else
      level="1"
    fi
    echo "x64v${level}"
  }

  install_bbr_kernel_if_needed() {
    if bbr_supported; then
      info "当前内核已支持 bbr，跳过内核安装"
      return 0
    fi

    warn "当前内核不支持 bbr，需要安装支持 BBR 的内核"

    if ! is_debian_like; then
      error "自动安装仅支持 Debian/Ubuntu"
      return 1
    fi

    if ! is_x86_64; then
      error "自动安装仅支持 x86_64"
      return 1
    fi

    setup_xanmod_repo || return 1

    local flavor pkg
    flavor="$(cpu_level_to_flavor)"
    pkg="linux-xanmod-${flavor}"

    info "准备安装支持 BBR 的 XanMod 内核: ${pkg}"
    if apt-get install -y "$pkg"; then
      update-grub >/dev/null 2>&1 || true
      ok "XanMod 内核安装完成"
    else
      error "XanMod 内核安装失败"
      return 1
    fi

    if bbr_supported; then
      info "当前会话已检测到 bbr 支持"
      return 0
    fi

    warn "新内核已安装，但当前系统可能仍在运行旧内核"
    warn "请先 reboot 重启系统，然后再次执行 bbr"
    return 2
  }

  disable_conflicts() {
    local ts f
    ts="$(date +%Y%m%d_%H%M%S)"

    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
      [ -f "$f" ] || continue
      [ "$f" = "$SYSCTL_FILE" ] && continue

      if grep -Eq '^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=' "$f" 2>/dev/null ||
         grep -Eq '^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=' "$f" 2>/dev/null; then
        backup_if_exists "$f"
        sed -ri \
          -e 's@^[[:space:]]*(net\.core\.default_qdisc[[:space:]]*=.*)$@# disabled by bbr '"$ts"': \1@' \
          -e 's@^[[:space:]]*(net\.ipv4\.tcp_congestion_control[[:space:]]*=.*)$@# disabled by bbr '"$ts"': \1@' \
          "$f"
        warn "已处理可能冲突的配置: $f"
      fi
    done
  }

  write_bbr_config() {
    mkdir -p /etc/sysctl.d
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" <<'EOF'
# Minimal stable BBR config
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  }

  apply_bbr_config() {
    if ! bbr_supported; then
      error "当前内核还不支持 bbr，无法启用"
      return 1
    fi

    disable_conflicts
    write_bbr_config

    if ! sysctl --system >/dev/null; then
      error "sysctl 应用失败"
      return 1
    fi

    local cc qdisc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"

    echo
    echo "最终结果:"
    echo "拥塞控制算法: $cc"
    echo "队列算法: $qdisc"
    echo

    if [ "$cc" = "bbr" ] && [ "$qdisc" = "fq" ]; then
      ok "已成功启用 bbr + fq"
      return 0
    else
      error "结果不符合预期，请检查是否有其他配置覆盖"
      return 1
    fi
  }

  remove_bbr_config() {
    if [ -f "$SYSCTL_FILE" ]; then
      backup_if_exists "$SYSCTL_FILE"
      rm -f "$SYSCTL_FILE"
      sysctl --system >/dev/null 2>&1 || true
      ok "已删除本脚本写入的 BBR 配置: $SYSCTL_FILE"
    else
      warn "未发现本脚本写入的配置文件"
    fi
  }

  install_and_enable_bbr() {
    install_bbr_kernel_if_needed
    local rc=$?
    if [ "$rc" -eq 2 ]; then
      return 0
    elif [ "$rc" -ne 0 ]; then
      return "$rc"
    fi

    apply_bbr_config
  }

  menu() {
    while true; do
      clear
      echo -e "${C}========== BBR 管理菜单 ========== ${N}"
      show_status
      echo "1. 查看当前状态"
      echo "2. 安装支持 BBR 的内核"
      echo "3. 启用 BBR + FQ"
      echo "4. 安装并启用 BBR"
      echo "5. 删除本脚本写入的 BBR 配置"
      echo "0. 退出"
      echo

      local choice
      read -r -p "请输入选择: " choice
      echo

      case "$choice" in
        1)
          show_status
          pause
          ;;
        2)
          install_bbr_kernel_if_needed || true
          pause
          ;;
        3)
          apply_bbr_config || true
          pause
          ;;
        4)
          install_and_enable_bbr || true
          pause
          ;;
        5)
          remove_bbr_config || true
          pause
          ;;
        0)
          return 0
          ;;
        *)
          warn "无效选择"
          sleep 1
          ;;
      esac
    done
  }

  require_root || return 1

  if [ $# -gt 0 ]; then
    case "${1:-}" in
      status)
        show_status
        ;;
      install)
        install_bbr_kernel_if_needed
        ;;
      enable)
        apply_bbr_config
        ;;
      all)
        install_and_enable_bbr
        ;;
      remove)
        remove_bbr_config
        ;;
      menu)
        menu
        ;;
      *)
        echo "用法:"
        echo "  bbr menu     打开菜单"
        echo "  bbr status   查看状态"
        echo "  bbr install  安装支持 BBR 的内核"
        echo "  bbr enable   启用 bbr + fq"
        echo "  bbr all      安装并启用"
        echo "  bbr remove   删除本脚本写入的配置"
        return 1
        ;;
    esac
  else
    menu
  fi
}

# -----------------------------
# 设置 IPv4 / IPv6 priority
# -----------------------------
set_ip_priority() {
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
      1) sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true; echo -e "\033[32m已切换为 IPv4 优先\033[0m"; sleep 1 ;;
      2) sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true; echo -e "\033[32m已切换为 IPv6 优先\033[0m"; sleep 1 ;;
      3) yellow "将运行外部 IPv6 修复脚本（jhb.ovh/jb/v6.sh）"; bash <(curl -fsSL jhb.ovh/jb/v6.sh) || red "脚本执行失败"; read -rp "回车返回..." _ ;;
      0) break ;;
      *) yellow "无效选择"; sleep 1 ;;
    esac
  done
}
# -----------------------------
#  设置 SSH 登录方式
# -----------------------------
auth_key() {
    local target_user="${1:-root}"
    local target_group user_home ssh_dir ak pubkey cfg bak choice new_pass
    local sshd_bin cloud_cfg cloud_bak

    if [[ $EUID -ne 0 ]]; then
        msg_err "请使用 root 权限执行此函数。"
        return 1
    fi

    user_home="$(getent passwd "$target_user" | cut -d: -f6)"
    target_group="$(id -gn "$target_user" 2>/dev/null)"
    target_group="${target_group:-$target_user}"

    cfg="/etc/ssh/sshd_config"
    cloud_cfg="/etc/ssh/sshd_config.d/50-cloud-init.conf"
    sshd_bin="$(command -v sshd 2>/dev/null)"

    if [[ -z "$user_home" || ! -d "$user_home" ]]; then
        msg_err "找不到用户或家目录：$target_user"
        return 1
    fi

    if [[ ! -f "$cfg" ]]; then
        msg_err "找不到 SSH 配置文件：$cfg"
        return 1
    fi

    _auth_key_backup_cfg() {
        bak="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$cfg" "$bak" || return 1
    }

    _auth_key_backup_cloud_cfg() {
        if [[ -f "$cloud_cfg" ]]; then
            cloud_bak="${cloud_cfg}.bak.$(date +%Y%m%d-%H%M%S)"
            cp -a "$cloud_cfg" "$cloud_bak" || return 1
        fi
    }

    _auth_key_set_cfg() {
        local key="$1"
        local value="$2"

        if grep -qE "^[#[:space:]]*${key}[[:space:]]+" "$cfg"; then
            sed -i -E "s#^[#[:space:]]*${key}[[:space:]].*#${key} ${value}#g" "$cfg"
        else
            echo "${key} ${value}" >> "$cfg"
        fi
    }

    _auth_key_set_cloud_password_auth() {
        local value="$1"

        mkdir -p /etc/ssh/sshd_config.d || return 1

        if [[ -f "$cloud_cfg" ]]; then
            _auth_key_backup_cloud_cfg || return 1
        fi

        cat > "$cloud_cfg" <<EOF
PasswordAuthentication ${value}
EOF
    }

    _auth_key_restore_on_fail() {
        [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$cfg"
        [[ -n "$cloud_bak" && -f "$cloud_bak" ]] && cp -a "$cloud_bak" "$cloud_cfg"
    }

    _auth_key_check_and_restart() {
        if [[ -n "$sshd_bin" ]]; then
            if ! "$sshd_bin" -t -f "$cfg" >/dev/null 2>&1; then
                _auth_key_restore_on_fail
                msg_err "sshd_config 校验失败，已恢复备份。"
                return 1
            fi
        fi

        if systemctl restart ssh >/dev/null 2>&1 \
            || systemctl restart sshd >/dev/null 2>&1 \
            || service ssh restart >/dev/null 2>&1 \
            || service sshd restart >/dev/null 2>&1; then
            return 0
        fi

        _auth_key_restore_on_fail
        msg_err "SSH 服务重启失败，已恢复备份。"
        return 1
    }

    _auth_key_gen_password() {
        local upper lower digit special all result

        upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower='abcdefghijklmnopqrstuvwxyz'
        digit='0123456789'
        special='$%*&#'
        all="${upper}${lower}${digit}${special}"

        _pick_one() {
            local chars="$1"
            printf '%s' "$chars" | fold -w1 | shuf -n1
        }

        result="$(_pick_one "$upper")"
        result+="$(_pick_one "$lower")"
        result+="$(_pick_one "$digit")"
        result+="$(_pick_one "$special")"

        while [[ ${#result} -lt 16 ]]; do
            result+="$(_pick_one "$all")"
        done

        printf '%s\n' "$result" | fold -w1 | shuf | tr -d '\n'
    }

    while true; do
        echo "=============================="
        echo " SSH 管理用户：$target_user"
        echo " 1. 仅 SSH 密钥登录"
        echo " 2. 仅 SSH 密码登录"
        echo " 3. 重置 SSH 密码"
        echo " 0. 返回上一级"
        echo "=============================="
        read -rp "请选择 [0-3]： " choice

        bak=""
        cloud_bak=""

        case "$choice" in
            1)
                echo "请输入公钥字符串（一整行，以 ssh-ed25519/ssh-rsa/ecdsa... 开头）："
                read -r pubkey

                if ! printf '%s\n' "$pubkey" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+([[:space:]].*)?$'; then
                    msg_err "公钥格式不正确。"
                    echo
                    continue
                fi

                ssh_dir="$user_home/.ssh"
                ak="$ssh_dir/authorized_keys"

                mkdir -p "$ssh_dir" || { msg_err "创建 .ssh 目录失败。"; echo; continue; }
                chmod 700 "$ssh_dir"
                touch "$ak" || { msg_err "创建 authorized_keys 失败。"; echo; continue; }
                chmod 600 "$ak"
                chown -R "$target_user:$target_group" "$ssh_dir"

                if ! awk '{print $1" "$2}' "$ak" | grep -Fxq "$(printf '%s\n' "$pubkey" | awk '{print $1" "$2}')"; then
                    printf '%s\n' "$pubkey" >> "$ak"
                fi

                _auth_key_backup_cfg || {
                    msg_err "备份 SSH 配置失败。"
                    echo
                    continue
                }

                _auth_key_set_cfg "PubkeyAuthentication" "yes"
                _auth_key_set_cfg "PasswordAuthentication" "no"
                _auth_key_set_cfg "KbdInteractiveAuthentication" "no"
                _auth_key_set_cfg "ChallengeResponseAuthentication" "no"
                _auth_key_set_cfg "UsePAM" "yes"
                _auth_key_set_cfg "AuthorizedKeysFile" ".ssh/authorized_keys"

                if [[ "$target_user" == "root" ]]; then
                    _auth_key_set_cfg "PermitRootLogin" "yes"
                fi

                _auth_key_set_cloud_password_auth "no" || {
                    msg_err "写入 cloud-init SSH 配置失败。"
                    echo
                    continue
                }

                if _auth_key_check_and_restart; then
                    msg_ok "已切换为仅 SSH 密钥登录。建议保留当前会话，并新开终端先测试登录。"
                fi
                echo
                ;;

            2)
                _auth_key_backup_cfg || {
                    msg_err "备份 SSH 配置失败。"
                    echo
                    continue
                }

                _auth_key_set_cfg "PubkeyAuthentication" "no"
                _auth_key_set_cfg "PasswordAuthentication" "yes"
                _auth_key_set_cfg "KbdInteractiveAuthentication" "no"
                _auth_key_set_cfg "ChallengeResponseAuthentication" "no"
                _auth_key_set_cfg "UsePAM" "yes"

                if [[ "$target_user" == "root" ]]; then
                    _auth_key_set_cfg "PermitRootLogin" "yes"
                fi

                _auth_key_set_cloud_password_auth "yes" || {
                    msg_err "写入 cloud-init SSH 配置失败。"
                    echo
                    continue
                }

                if _auth_key_check_and_restart; then
                    msg_ok "已切换为仅 SSH 密码登录。测试示例：ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no ${target_user}@IP"
                fi
                echo
                ;;

            3)
                new_pass="$(_auth_key_gen_password)"

                if [[ -z "$new_pass" || ${#new_pass} -ne 16 ]]; then
                    msg_err "生成随机密码失败。"
                    echo
                    continue
                fi

                if ! printf '%s:%s\n' "$target_user" "$new_pass" | chpasswd; then
                    msg_err "重置密码失败。"
                    echo
                    continue
                fi

                msg_ok "用户 [$target_user] 的 SSH 密码已重置。"
                echo "新密码：$new_pass"

                if grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no\b' "$cfg" \
                    || [[ -f "$cloud_cfg" && -n "$(grep -iE '^[[:space:]]*PasswordAuthentication[[:space:]]+no\b' "$cloud_cfg" 2>/dev/null)" ]]; then
                    echo "注意：当前 SSH 可能未开启密码登录，如需使用密码登录，请执行菜单 2。"
                fi
                echo
                ;;

            0)
                return 0
                ;;

            *)
                msg_err "无效选项，请重新输入。"
                echo
                ;;
        esac
    done
}

# -----------------------------
#  系统清理脚本
# -----------------------------
sys_cle() {
    local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_cle.sh"
    local script="/root/sys_cle.sh"
    local cron_line='0 0 * * * /bin/bash /root/sys_cle.sh >> /root/sys_cle.cron.log 2>&1'

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$script" || { msg_err "下载失败"; return 1; }
    else
        wget -qO "$script" "$url" || { msg_err "下载失败"; return 1; }
    fi
    chmod +x "$script" >/dev/null 2>&1 || true

    echo
    echo "=============================="
    echo "sys_cle 管理菜单"
    echo "1) 添加 cron：每天 00:00 执行"
    echo "2) 删除 cron"
    echo "3) 立即执行一次清理"
    echo "4) 查看当前 cron 状态"
    echo "0) 退出"
    echo "=============================="

    local choice
    read -rp "请选择 [0-4]: " choice

    case "$choice" in
        1)
            (crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh"; echo "$cron_line") | crontab -
            msg_ok "已添加每日 00:00 cron"
            ;;
        2)
            crontab -l 2>/dev/null | grep -Fv "/root/sys_cle.sh" | crontab -
            msg_ok "已删除 sys_cle cron"
            ;;
        3)
            /bin/bash "$script"
            ;;
        4)
            crontab -l 2>/dev/null | grep -F "/root/sys_cle.sh" || echo "未设置"
            ;;
        0) return 0 ;;
        *) msg_err "无效选择" ;;
    esac
}
# -----------------------------
# 系统重启(cron)
# -----------------------------
cron_reboot() {
  green "将下载定时任务文件到 /etc/cron.d/mdadm，并重启系统。"
  read -rp "确认继续？(y/n): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { green "已取消"; return 0; }

  if ! command -v wget >/dev/null 2>&1; then
    pkg_update || true
    pkg_install wget || return 1
  fi

  wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/vps/main/mdadm -O /etc/cron.d/mdadm || {
    red "文件下载失败"
    return 1
  }

  green "文件下载成功：/etc/cron.d/mdadm"
  green "即将重启..."
  reboot
}
# -----------------------------
#  系统参数配置菜单
# -----------------------------
system_config_menu() {
    while :; do
        clear >/dev/null 2>&1 || true
        echo -e "${cyan}系统参数配置${none}"
        echo "--------------------------------------------------"
        echo "1) BBR 优化"
        echo "2) 配置 firewall"
        echo "3) 修改时区"
        echo "4) 修改 DNS"
        echo "5) 设置 Swap"
        echo "6) 修改 SSH 端口2222"
        echo "7) 设置 SSH 登录方式"
        echo "8) 设置系统清理"
		echo "9) 设置IP优先级"
		echo "10) 设置定时重启"
        echo "0) 返回"
        echo "--------------------------------------------------"

        local c=""
        read -rp "请选择: " c

        case "$c" in
            1) bbr; pause ;;
            2) setup_ufw; pause ;;
            3) change_tz; pause ;;
            4) set_dns_ui; pause ;;
            5) swap_cache; pause ;;
            6) ssh_port_change 2222; pause ;;
            7) auth_key root; pause ;;
            8) sys_cle; pause ;;
			9) set_ip_priority;;
			10) cron_reboot;;
            0) return 0 ;;
            *) msg_err "无效输入"; pause ;;
        esac
    done
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

    local cpu_info cpu_cores cpu_freq mem_info disk_info load os_info kernel_version cpu_arch hostname now runtime dns_addresses
    local cc_algo qdisc_algo headers_status active_qdisc default_iface
    local ipinfo country city isp
    local TOOL_IPV4="${TOOL_IPV4:-}" TOOL_IPV6="${TOOL_IPV6:-}"

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
    echo -e "拥塞控制算法: ${cc_algo}"
    echo -e "默认队列算法: ${qdisc_algo}"
    [ -n "${default_iface:-}" ] && echo -e "主网卡:       ${default_iface}"
    [ -n "${active_qdisc:-}" ] && echo -e "网卡队列算法: ${active_qdisc}"
    echo -e "内核headers:  ${headers_status}"
    echo -e "系统时间:     ${now}"
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
        x-ui restart
    else
        install_panel
    fi

    UPDATE_XUIDB
    configure_nginx
    install_sub2sing_box
    install_fake_site
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
        echo -e " ${yellow}${bold}3)${none} ${yellow}更新xray${none}"
        echo -e " ${yellow}${bold}4)${none} ${yellow}打印节点信息${none}"
        echo -e " ${yellow}${bold}5)${none} ${yellow}目标网站检测${none}"
        echo -e " ${yellow}${bold}6)${none} ${yellow}系统参数配置${none}"
        echo -e " ${yellow}${bold}7)${none} ${yellow}回程路由测试${none}"
        echo -e " ${yellow}${bold}8)${none} ${yellow}IP质量检测${none}"
        echo -e " ${yellow}${bold}9)${none} ${yellow}系统查询${none}"
        echo -e " ${yellow}${bold}10)${none} ${yellow}查看状态${none}"
        echo -e " ${red}${bold}0)${none} 退出"

        echo -e "${gray}--------------------------------------------------${none}"
        echo -e "${dim}${gray}提示：输入数字后回车${none}"
        echo -ne "${green}${bold}请选择 [0-10]${none}${green}: ${none}"

        local choice=""

        read_tty "" choice

        case "${choice}" in
            1) INSTALL="y"; UNINSTALL="n"; install_xui_pro ;;
            2) uninstall_xui_menu ;;
            3) xray_updata ;;
            4) print_node_info ;;
            5) detect_target_site ;;
            6) system_config_menu ;;
            7) besttrace_test ;;
            8) ip_quality_check ;;
            9) system_query ;;
            10) view_status ;;
            0) exit 0 ;;
            *) msg_err "无效输入，请重新选择。"; pause ;;
        esac
    done
}

# -----------------------------
#  程序入口
# -----------------------------
main() {
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