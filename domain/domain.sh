#!/bin/bash
############################# SSL Certificate Manager #####################################

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
#  日志记录
# -----------------------------
LOG_FILE="/var/log/cert-manager.log"
log_action() {
    local domain="$1"
    local action="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${action} - ${domain}" >> "$LOG_FILE"
}

# -----------------------------
#  通用暂停
# -----------------------------
pause() {
    echo
    read -rp "按回车键继续..." _
}

# -----------------------------
#  仅停止占用 80 端口的非 nginx 服务（不影响现有 nginx 站点）
# -----------------------------
cleanup_80_port_non_nginx() {
    systemctl stop apache2 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    pkill -f apache2 2>/dev/null || true
    pkill -f caddy 2>/dev/null || true
    sleep 1
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
#  安装必要工具（nginx, certbot, certbot-dns-cloudflare）
# -----------------------------
install_tool_deps() {
    export DEBIAN_FRONTEND=noninteractive

    local tools=("curl" "wget" "openssl" "ca-certificates" "nginx" "certbot" "python3-certbot-dns-cloudflare")
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1 && ! dpkg -l | grep -q "^ii  $tool"; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        msg_ok "所有依赖已安装，跳过安装。"
        return 0
    fi

    echo "检测到缺失依赖，开始安装..."

    if command -v apt-get >/dev/null 2>&1; then
        fix_dpkg_interrupt
        echo -ne "正在更新软件包列表 "
        for i in {1..5}; do
            echo -n "→"
            sleep 0.2
        done
        echo
        apt-get update -y -q >/dev/null 2>&1 || true

        echo -ne "正在安装依赖 "
        for i in {1..10}; do
            echo -n "→"
            sleep 0.2
        done
        echo
        apt-get install -y -q --no-install-recommends \
            curl wget openssl ca-certificates \
            nginx certbot python3-certbot-dns-cloudflare \
            >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        echo -ne "正在安装 epel-release "
        for i in {1..3}; do
            echo -n "→"
            sleep 0.2
        done
        echo
        yum install -y epel-release >/dev/null 2>&1 || true

        echo -ne "正在安装依赖 "
        for i in {1..10}; do
            echo -n "→"
            sleep 0.2
        done
        echo
        yum install -y curl wget openssl ca-certificates \
            nginx certbot python3-certbot-dns-cloudflare \
            >/dev/null 2>&1 || true
    fi
}

# -----------------------------
#  获取服务器 IPv4（仅用于 HTTP 验证的解析检查）
# -----------------------------
get_server_ips() {
    IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*' || true)
    [[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com)
}

# -----------------------------
#  校验域名解析到本机（仅用于 HTTP 验证）
# -----------------------------
resolve_to_ip() {
    local host="$1"
    local a
    a=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
    [[ -n "$a" ]] && [[ "$a" == "$IP4" ]]
}

# -----------------------------
#  证书相关函数（查找、验证）
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

cert_files_exist() {
    local cert_domain="$1"
    local cert_name
    if [[ -f "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${cert_domain}/privkey.pem" ]]; then
        return 0
    fi
    cert_name=$(find_cert_name_by_domain "$cert_domain" 2>/dev/null || true)
    [[ -n "$cert_name" ]] && [[ -f "/etc/letsencrypt/live/${cert_name}/fullchain.pem" && -f "/etc/letsencrypt/live/${cert_name}/privkey.pem" ]]
}

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
#  HTTP 验证申请（仅新增临时 ACME 配置，不删除/覆盖现有站点）
# -----------------------------
issue_cert_http() {
    local cert_domain="$1"

    mkdir -p /var/www/acme
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/html

    cleanup_80_port_non_nginx

    # 如果 nginx 没运行则启动它；如果已在运行则不要 stop/restart
    if ! systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl start nginx 2>/dev/null || true
        sleep 1
    fi

    # 等待 80 端口空闲
    if ss -lnt | grep -q ':80 '; then
        local port_owner
        port_owner=$(ss -lntp 2>/dev/null | grep ':80 ' || true)
        if [[ -n "$port_owner" ]] && ! echo "$port_owner" | grep -q 'nginx'; then
            msg_err "80 端口仍被非 nginx 进程占用，无法申请证书。"
            echo "$port_owner"
            return 1
        fi
    fi

    local acme_conf="/etc/nginx/sites-available/dcf-acme-${cert_domain}.conf"
    local acme_link="/etc/nginx/sites-enabled/dcf-acme-${cert_domain}.conf"

    cat > "$acme_conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${cert_domain};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }

    location / {
        return 404;
    }
}
EOF

    # 不要删除 sites-enabled 下任何已有配置！只添加临时 ACME 配置
    ln -sf "$acme_conf" "$acme_link"

    nginx -t || { rm -f "$acme_link" "$acme_conf"; return 1; }
    systemctl reload nginx || { rm -f "$acme_link" "$acme_conf"; return 1; }

    certbot certonly --webroot -w /var/www/acme --non-interactive --agree-tos --register-unsafely-without-email -d "$cert_domain" || return 1

    # 申请成功后清理临时 ACME 配置，避免长期占用 80 端口 server_name
    rm -f "$acme_link" "$acme_conf"
    systemctl reload nginx 2>/dev/null || true

    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        log_action "$cert_domain" "ISSUED/RENEWED (HTTP)"
        return 0
    fi
    return 1
}

# -----------------------------
#  DNS 验证申请（Cloudflare API）
# -----------------------------
issue_cert_dns() {
    local cert_domain="$1"
    local cf_creds="/root/.cloudflare.ini"

    # 检查凭据文件是否存在
    if [[ ! -f "$cf_creds" ]]; then
        msg_inf "未检测到 Cloudflare API 凭据，请配置。"
        read -rp "请输入您的 Cloudflare API Token（需具备 Zone:Read 和 DNS:Edit 权限）: " cf_token
        if [[ -z "$cf_token" ]]; then
            msg_err "Token 不能为空。"
            return 1
        fi
        # 写入凭据文件
        cat > "$cf_creds" <<EOF
dns_cloudflare_api_token = ${cf_token}
EOF
        chmod 600 "$cf_creds"
        msg_ok "Cloudflare API Token 已保存至 $cf_creds（权限 600）"
    fi

    # 调用 certbot 使用 DNS 插件
    certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$cf_creds" \
        --non-interactive --agree-tos --register-unsafely-without-email -d "$cert_domain" || return 1

    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        log_action "$cert_domain" "ISSUED/RENEWED (DNS-Cloudflare)"
        return 0
    fi
    return 1
}

# -----------------------------
#  交互式申请证书（菜单1）
# -----------------------------
request_certificate() {
    local domain=""
    local verify_method=""

    # 选择验证方式
    echo "----------------------------------------------------------------"
    echo "请选择证书验证方式："
    echo "  1) HTTP 验证（需开放 80 端口，适合未套 CDN）"
    echo "  2) DNS 验证（Cloudflare API，适合套 CDN 或无法开放 80 端口）"
    read -rp "请输入 [1/2]: " verify_method

    while [[ "$verify_method" != "1" && "$verify_method" != "2" ]]; do
        msg_err "无效选择，请重新输入 1 或 2。"
        read -rp "请输入 [1/2]: " verify_method
    done

    # 获取域名
    while true; do
        read -rp "请输入需要申请证书的域名（如 example.com）: " domain
        domain=$(echo "$domain" | tr -d '[:space:]')
        if [[ -z "$domain" ]]; then
            msg_err "域名不能为空，请重新输入。"
            continue
        fi
        break
    done

    # 如果是 HTTP 验证，检查解析
    if [[ "$verify_method" == "1" ]]; then
        get_server_ips
        echo "当前服务器 IPv4: ${IP4}"
        if ! resolve_to_ip "$domain"; then
            msg_err "域名 $domain 未解析到本机 IP ($IP4)，请先添加正确的 A 记录。"
            read -rp "是否继续尝试？(y/N): " retry
            if [[ ! "$retry" =~ ^[Yy]$ ]]; then
                msg_err "已取消操作。"
                return
            fi
        else
            msg_ok "域名解析验证通过。"
        fi
    fi

    # 执行申请
    local success=0
    if [[ "$verify_method" == "1" ]]; then
        echo "开始使用 HTTP 验证申请证书..."
        if issue_cert_http "$domain"; then
            success=1
        fi
    else
        echo "开始使用 DNS 验证（Cloudflare）申请证书..."
        if issue_cert_dns "$domain"; then
            success=1
        fi
    fi

    if [[ $success -eq 1 ]]; then
        CERT_INFO=$(get_cert_paths "$domain" 2>/dev/null || true)
        if [[ -n "$CERT_INFO" ]]; then
            cert_name=$(echo "$CERT_INFO" | cut -d'|' -f1)
            cert_file=$(echo "$CERT_INFO" | cut -d'|' -f2)
            key_file=$(echo "$CERT_INFO" | cut -d'|' -f3)
            echo "----------------------------------------------------------------"
            msg_ok "证书已就绪！"
            echo "证书目录: /etc/letsencrypt/live/${cert_name}"
            echo "证书文件: ${cert_file}"
            echo "私钥文件: ${key_file}"
            echo "----------------------------------------------------------------"
        fi
    else
        msg_err "证书申请失败。"
    fi
    pause
}

# -----------------------------
#  添加自动续签计划任务（菜单2）
# -----------------------------
add_cron_renew() {
    echo "----------------------------------------------------------------"
    echo "添加自动续签计划任务"
    echo "----------------------------------------------------------------"

    if ! command -v certbot >/dev/null 2>&1; then
        msg_err "certbot 未安装，请先执行选项1申请证书（会自动安装）。"
        pause
        return
    fi

    # 续签命令（注意：certbot renew 会自动使用之前的验证方式）
    local renew_cmd="/usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx' >> /var/log/certbot-renew.log 2>&1"

    # 检查是否已存在
    local existing
    existing=$(crontab -l 2>/dev/null | grep -F "$renew_cmd" || true)
    if [[ -n "$existing" ]]; then
        msg_ok "已存在自动续签任务，无需重复添加。"
        echo "当前任务: $existing"
        pause
        return
    fi

    (crontab -l 2>/dev/null; echo "0 3 * * 0 $renew_cmd") | crontab -
    msg_ok "已添加每周自动续签任务（每周日 3:00 执行）。"
    echo "日志文件: /var/log/certbot-renew.log"
    pause
}

# -----------------------------
#  显示证书状态（菜单3）
# -----------------------------
show_cert_status() {
    echo "----------------------------------------------------------------"
    echo "证书状态查询"
    echo "----------------------------------------------------------------"

    if [[ ! -d /etc/letsencrypt/live ]]; then
        msg_err "尚未发现任何证书，请先申请证书。"
        pause
        return
    fi

    local cert_domains=()
    local idx=0
    for d in /etc/letsencrypt/live/*; do
        if [[ -d "$d" && -f "$d/fullchain.pem" && -f "$d/privkey.pem" ]]; then
            local name=$(basename "$d")
            [[ -z "$name" || "$name" == ".*" ]] && continue
            cert_domains+=("$name")
            echo "  $((++idx))) $name"
        fi
    done

    if [[ ${#cert_domains[@]} -eq 0 ]]; then
        msg_err "未找到有效的证书目录。"
        pause
        return
    fi

    local choice
    echo
    read -rp "请输入要查询的证书域名（或输入序号）: " choice

    local domain=""
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#cert_domains[@]} ]]; then
        domain="${cert_domains[$((choice-1))]}"
    else
        domain="$choice"
    fi

    if ! cert_files_exist "$domain"; then
        msg_err "域名 '$domain' 的证书不存在，请重新输入。"
        pause
        return
    fi

    local cert_info cert_file
    cert_info=$(get_cert_paths "$domain" 2>/dev/null || true)
    if [[ -z "$cert_info" ]]; then
        msg_err "无法获取证书路径。"
        pause
        return
    fi
    cert_file=$(echo "$cert_info" | cut -d'|' -f2)

    local not_before not_after
    not_before=$(openssl x509 -in "$cert_file" -noout -startdate 2>/dev/null | cut -d= -f2)
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)

    if [[ -z "$not_before" || -z "$not_after" ]]; then
        msg_err "无法解析证书日期，请检查证书文件是否有效。"
        pause
        return
    fi

    local expire_epoch issue_epoch
    expire_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
    issue_epoch=$(date -d "$not_before" +%s 2>/dev/null || echo 0)
    current_epoch=$(date +%s)
    days_left=$(( (expire_epoch - current_epoch) / 86400 ))

    echo "----------------------------------------------------------------"
    echo "证书域名: ${domain}"
    echo "上次更新（签发时间）: ${not_before}"
    echo "过期时间: ${not_after}"
    if [[ $days_left -ge 0 ]]; then
        echo "剩余有效天数: ${days_left} 天"
        if [[ $days_left -lt 30 ]]; then
            msg_err "警告：证书将在 ${days_left} 天后过期，建议续签。"
        else
            msg_ok "证书状态正常。"
        fi
    else
        msg_err "证书已过期！"
    fi

    if [[ -f "$LOG_FILE" ]]; then
        local last_log
        last_log=$(grep -E "${domain}" "$LOG_FILE" | tail -1)
        if [[ -n "$last_log" ]]; then
            echo "最近日志记录: $last_log"
        else
            echo "暂无操作日志记录。"
        fi
    else
        echo "日志文件不存在，未记录历史操作。"
    fi
    echo "----------------------------------------------------------------"
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
        echo -e "${cyan}${bold}║         SSL 证书管理工具                    ║${none}"
        echo -e "${cyan}${bold}╚══════════════════════════════════════════════╝${none}"
        echo -e "${gray}--------------------------------------------------${none}"

        echo -e " ${blue}${bold}1)${none} ${blue}申请域名证书${none}"
        echo -e " ${green}${bold}2)${none} ${green}添加自动续签计划任务（每周检测并续签）${none}"
        echo -e " ${yellow}${bold}3)${none} ${yellow}显示证书状态（过期时间/签发时间）${none}"
        echo -e "${gray}--------------------------------------------------${none}"
        echo -e " ${red}${bold}0)${none} 退出"

        echo -e "${gray}--------------------------------------------------${none}"
        echo -e "${dim}${gray}提示：输入数字后回车${none}"
        echo -ne "${green}${bold}请选择 [0-3]${none}${green}: ${none}"

        local choice=""
        read -r choice

        case "${choice}" in
            1) request_certificate ;;
            2) add_cron_renew ;;
            3) show_cert_status ;;
            0) exit 0 ;;
            *) msg_err "无效输入，请重新选择。"; pause ;;
        esac
    done
}

# -----------------------------
#  程序入口
# -----------------------------
main() {
    install_tool_deps
    echo

    # 入口不再清理服务；HTTP 验证时按需临时 reload nginx，DNS 验证完全不碰 nginx
    menu
}

main "$@"