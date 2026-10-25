#!/usr/bin/env bash
# SB_REALITY_MANAGER_V1
# V1.2: simpler domain input, safe cert selection, QR code, monthly core-update scheduler, legacy uninstall
# Sing-box VLESS REALITY :443 + isolated local Nginx HTTPS fallback.
# Independently managed: NEVER stop/change x-ui, xray, 3x-ui, user Nginx vhosts or certificates.
set -uo pipefail

SB_DIR="${SB_DIR:-/etc/sing-box}"
SB_CONF="$SB_DIR/config.json"
SB_STATE="$SB_DIR/.s_reality_state.json"
SB_URI="$SB_DIR/uris.txt"
SB_SERVICE="${SB_SERVICE:-sing-box}"
SB_UNIT="${SB_UNIT:-/etc/systemd/system/sing-box.service}"
SB_MARK='SB_REALITY_MANAGED_V1'
NGINX_DIR="${NGINX_DIR:-/etc/nginx/conf.d}"
SB_BACKUPS="$SB_DIR/s-reality-backups"
SB_INSTALL_COPY="/usr/local/lib/s-reality/s.sh"
SB_ALIAS="/usr/local/bin/sb"
SB_CRON_FILE="${SB_CRON_FILE:-/etc/cron.d/s-reality-core-update}"
SB_CRON_LOG="${SB_CRON_LOG:-/var/log/s-reality-core-update.log}"

none='\033[0m'; blue='\033[34m'; red='\033[31m'; yellow='\033[33m'; green='\033[32m'; cyan='\033[36m'; gray='\033[90m'; bold='\033[1m'
info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }
read_tty() {
    # Avoid Bash dynamic-scoping collisions with caller variables.
    local _rt_prompt="$1" _rt_target="$2" _rt_value=''
    if [[ -t 0 ]]; then
        IFS= read -e -r -p "$_rt_prompt" _rt_value || return 1
    else
        IFS= read -r -p "$_rt_prompt" _rt_value || return 1
    fi
    printf -v "$_rt_target" '%s' "$_rt_value"
}
pause() { local ignored=''; read_tty '按回车返回菜单...' ignored || true; }
is_yes() { [[ "${1:-}" == [Yy] ]]; }
is_no() { [[ "${1:-}" == [Nn] ]]; }
require_root() { (( EUID == 0 )) || { err '请以 root 执行：sudo bash s.sh'; return 1; }; }
valid_domain() {
    local name="$1" item
    [[ ${#name} -ge 4 && ${#name} -le 253 && "$name" == *.* && "$name" != *..* ]] || return 1
    [[ "$name" =~ ^[a-zA-Z0-9.-]+$ ]] || return 1
    local IFS='.'; read -r -a parts <<< "$name"
    (( ${#parts[@]} >= 2 )) || return 1
    for item in "${parts[@]}"; do
        [[ ${#item} -ge 1 && ${#item} -le 63 && "$item" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
    done
}
valid_host() { valid_domain "$1" || [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 > 0 && 10#$1 <= 65535 )); }
# The original s.sh supports Alpine, Debian/Ubuntu and RedHat families.
require_debian_or_rhel() {
    [[ -r /etc/os-release ]] || { err 'Cannot identify OS'; return 1; }
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu) PKG=apt-get ;;
        alpine) PKG=apk; [[ "$NGINX_DIR" == /etc/nginx/conf.d && -d /etc/nginx/http.d ]] && NGINX_DIR=/etc/nginx/http.d ;;
        fedora|rhel|centos|rocky|almalinux)
            PKG=dnf
            command -v dnf >/dev/null 2>&1 || PKG=yum
            ;;
        *) err 'Unsupported Linux family; please use Alpine/Debian/Ubuntu/RHEL.'; return 1 ;;
    esac
    if [[ "$PKG" == apk ]]; then
        command -v rc-service >/dev/null 2>&1 || return 1
    else
        command -v systemctl >/dev/null 2>&1 || return 1
    fi
}
install_deps() {
    info '安装必要依赖（包含二维码 qrencode 和定时任务 cron），保留现有网站配置。'
    case "$PKG" in
        apt-get)
            local packages=(curl ca-certificates openssl jq certbot iproute2 python3 qrencode cron)
            # Do not upgrade/replace the user's existing Nginx just for this script.
            command -v nginx >/dev/null 2>&1 || packages+=(nginx)
            DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
                apt-get update -y || return 1
            DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
                apt-get install -y --no-install-recommends "${packages[@]}" || return 1
            ;;
        dnf|yum)
            local packages=(curl ca-certificates openssl jq certbot iproute python3 qrencode cronie)
            command -v nginx >/dev/null 2>&1 || packages+=(nginx)
            "$PKG" install -y "${packages[@]}" || return 1
            ;;
        apk)
            apk update || return 1
            apk add --no-cache bash curl ca-certificates openssl jq nginx certbot iproute2 python3 qrencode cronie || return 1
            [[ "$NGINX_DIR" == /etc/nginx/conf.d && -d /etc/nginx/http.d ]] && NGINX_DIR=/etc/nginx/http.d
            ;;
    esac
    command -v qrencode >/dev/null 2>&1 || { err '二维码组件 qrencode 安装失败。'; return 1; }
}
nginx_reload_or_start() {
    nginx -t || return 1
    if [[ "${PKG:-}" == apk ]]; then
        if rc-service nginx status >/dev/null 2>&1; then rc-service nginx reload
        else rc-service nginx start; fi
    elif systemctl is-active --quiet nginx 2>/dev/null; then systemctl reload nginx
    else systemctl start nginx; fi
}
install_singbox() {
    if command -v sing-box >/dev/null 2>&1; then
        info "Using $(sing-box version | head -n1)"
        return 0
    fi
    if [[ "${PKG:-}" == apk ]]; then
        apk add sing-box 2>/dev/null || apk add --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community sing-box
    else
        local installer=''
        installer="$(mktemp /tmp/s-reality-installer.XXXXXX)" || return 1
        curl -fsSL --retry 3 'https://sing-box.app/install.sh' -o "$installer" || { rm -f "$installer"; return 1; }
        bash "$installer" || { rm -f "$installer"; return 1; }
        rm -f "$installer"
    fi
    command -v sing-box >/dev/null 2>&1 || { err 'sing-box installation failed'; return 1; }
}

# Output if the requested *TCP* port is listening anywhere (v4/v6).
port_busy() {
    command -v ss >/dev/null 2>&1 || { err '缺少 ss 命令，无法安全检查端口'; return 0; }
    [[ -n "$(ss -H -lnt "( sport = :$1 )" 2>/dev/null)" ]]
}
port_owner() { ss -H -lntp "( sport = :$1 )" 2>/dev/null | head -n 4 || true; }
nginx_preflight() {
    command -v nginx >/dev/null 2>&1 || return 0
    local result=''
    if ! result="$(nginx -t 2>&1)"; then
        err '现有 Nginx 配置不通过 nginx -t；为保护原站点，拒绝自动修改。'
        printf '%s\n' "$result" >&2
        return 1
    fi
}

# Reuse *only* a certificate that currently matches the domain and its key.
check_pair() {
    local domain="$1" cert="$2" key="$3" a b
    [[ -r "$cert" && -r "$key" ]] || return 1
    openssl x509 -checkend 0 -noout -in "$cert" >/dev/null 2>&1 || return 1
    openssl x509 -checkhost "$domain" -noout -in "$cert" 2>/dev/null | grep -q 'does match' || return 1
    a="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    b="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    [[ -n "$a" && "$a" == "$b" ]]
}
locate_existing_cert() {
    local domain="$1" p cert key
    # Existing original-xpro or manual certificates are referenced, never rewritten.
    for p in "/etc/letsencrypt/live/$domain" /etc/letsencrypt/live/"$domain"-* \
             /etc/letsencrypt/live/* "/root/cert/$domain"; do
        [[ -d "$p" ]] || continue
        cert="$p/fullchain.pem"; key="$p/privkey.pem"
        if check_pair "$domain" "$cert" "$key"; then
            CERT_FULLCHAIN="$cert"; CERT_PRIVKEY="$key"
            return 0
        fi
    done
    return 1
}
# The TLS bridge is separate from user sites. For an existing HTTP website,
# proxy to its original port; otherwise use its existing local document root.
choose_backend() {
    local suggested='' input='' candidate='' code='' scheme='' port=''
    # Prefer common existing application ports over :80 (may be generic nginx).
    for candidate in \
        'http://127.0.0.1:8080' 'http://127.0.0.1:8081' \
        'https://127.0.0.1:8081' 'http://127.0.0.1:80' \
        'http://127.0.0.1:8000'; do
        if ! port_busy "${candidate##*:}"; then continue; fi
        scheme="${candidate%%://*}"; port="${candidate##*:}"
        if [[ "$scheme" == https ]]; then
            code="$(curl --noproxy '*' -k -sS -o /dev/null -w '%{http_code}' \
                --resolve "$DOMAIN:$port:127.0.0.1" --connect-timeout 2 --max-time 4 \
                "https://$DOMAIN:$port/" 2>/dev/null || true)"
        else
            code="$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
                -H "Host: $DOMAIN" --connect-timeout 2 --max-time 4 \
                "$candidate/" 2>/dev/null || true)"
        fi
        if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then suggested="$candidate"; break; fi
    done
    [[ -n "$suggested" ]] || suggested='static:/var/www/html'
    echo "回落到现有网站（默认 ${suggested}）"
    echo '支持 http://127.0.0.1:8080、https://127.0.0.1:8081 或 static:/绝对目录'
    read_tty '回车使用默认值: ' input || return 1
    BACKEND="${input:-$suggested}"
    if [[ "$BACKEND" =~ ^https?://127\.0\.0\.1:([0-9]{1,5})/?$ ]]; then
        # The BASH_REMATCH array is overwritten by valid_port; retain port first.
        local backend_port="${BASH_REMATCH[1]}"
        valid_port "$backend_port" || { err '原站端口无效'; return 1; }
        [[ "$backend_port" != 443 ]] || { err '回落目标不能指向公网 443，以免循环回落'; return 1; }
    elif [[ "$BACKEND" == static:/* ]]; then
        local root="${BACKEND#static:}"
        [[ -d "$root" && "$root" =~ ^/[A-Za-z0-9_./-]+$ ]] || { err '静态网站目录不存在或包含不安全字符'; return 1; }
    else
        err '仅允许本机 HTTP/HTTPS 或 static:/绝对目录，防止回落到外部服务'; return 1
    fi
    info "选定回落目标：$BACKEND"
}

# The fallback is local-only on 18081+, not HTTP 8080 (e.g. user's wow site).
choose_fallback_port() {
    local p
    for ((p=18081;p<=18199;p++)); do
        if ! port_busy "$p"; then FALLBACK_PORT="$p"; return 0; fi
    done
    err '18081-18199 无空闲 TCP 端口'; return 1
}
owned_nginx_conf() { printf '%s/s-reality-fallback-%s.conf\n' "$NGINX_DIR" "$1"; }
create_fallback_file() {
    local domain="$1" port="$2" cert="$3" key="$4" backend="$5" output="$6"
    local root
    {
        printf '# %s\n' "$SB_MARK"
        printf '# Loopback TLS only. User Nginx vhosts are NOT edited.\n'
        printf 'server {\n    listen 127.0.0.1:%s ssl;\n    server_name %s;\n' "$port" "$domain"
        printf '    ssl_certificate %s;\n    ssl_certificate_key %s;\n' "$cert" "$key"
        printf '    ssl_protocols TLSv1.2 TLSv1.3;\n'
        if [[ "$backend" == http://* || "$backend" == https://* ]]; then
            printf '    location / {\n'
            printf '        proxy_pass %s;\n' "${backend%/}"
            printf '        proxy_http_version 1.1;\n'
            if [[ "$backend" == https://* ]]; then
                printf '        proxy_ssl_server_name on;\n'
                printf '        proxy_ssl_name $host;\n'
                printf '        proxy_ssl_verify off; # Loopback-only HTTPS upstream\n'
            fi
            printf '        proxy_set_header Host $host;\n'
            printf '        proxy_set_header X-Real-IP $remote_addr;\n'
            printf '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            printf '        proxy_set_header X-Forwarded-Proto https;\n'
            printf '    }\n'
        else
            root="${backend#static:}"
            printf '    root %s;\n    index index.html index.htm;\n' "$root"
            printf '    location / { try_files $uri $uri/ =404; }\n'
        fi
        printf '}\n'
    } > "$output"
}
verify_tls() {
    local port="$1" domain="$2" pem
    pem="$(timeout 10 openssl s_client -connect "127.0.0.1:$port" -servername "$domain" -showcerts </dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | head -n 80)" || return 1
    [[ "$pem" == *'-----BEGIN CERTIFICATE-----'* ]] || return 1
    openssl x509 -noout -checkhost "$domain" 2>/dev/null <<< "$pem" | grep -q 'does match'
}
# No existing file except OUR marker may be replaced. Existing Nginx files stay untouched.
activate_fallback() {
    local domain="$1" port="$2" cert="$3" key="$4" backend="$5" file tmp previous=''
    file="$(owned_nginx_conf "$domain-$port")"
    mkdir -p "$NGINX_DIR" || return 1
    if [[ -e "$file" || -L "$file" ]]; then
        [[ -f "$file" && ! -L "$file" ]] && grep -Fqx "# $SB_MARK" "$file" || { err "拒绝覆盖非本脚本拥有的配置：$file"; return 1; }
        previous="$(mktemp /tmp/s-reality-nginx-old.XXXXXX)" || return 1
        cp -p "$file" "$previous" || return 1
    fi
    tmp="$(mktemp "$NGINX_DIR/.s-reality.XXXXXX")" || return 1
    if ! create_fallback_file "$domain" "$port" "$cert" "$key" "$backend" "$tmp" || ! mv -f "$tmp" "$file"; then
        rm -f "$tmp" "$previous"; return 1
    fi
    if ! nginx_reload_or_start || ! verify_tls "$port" "$domain"; then
        err '回落 HTTPS 未通过验证，正在撤销本脚本写入的配置。'
        if [[ -n "$previous" ]]; then cp -p "$previous" "$file"; else rm -f "$file"; fi
        nginx_reload_or_start >/dev/null 2>&1 || true
        rm -f "$previous"
        return 1
    fi
    rm -f "$previous"
    FALLBACK_CONF="$file"
    ok "Nginx 本地 HTTPS 回落：127.0.0.1:$port → $backend"
}

keys_generate() {
    local key_text
    key_text="$(sing-box generate reality-keypair 2>/dev/null)" || return 1
    REALITY_PK="$(sed -nE 's/^[[:space:]]*(PrivateKey|PrivateKey \(Secret\)):[[:space:]]*([^[:space:]]+).*/\2/p' <<< "$key_text" | head -n1)"
    REALITY_PUB="$(sed -nE 's/^[[:space:]]*(PublicKey|Public key):[[:space:]]*([^[:space:]]+).*/\2/p' <<< "$key_text" | head -n1)"
    REALITY_SID="$(openssl rand -hex 8)" || return 1
    [[ -n "$REALITY_PK" && -n "$REALITY_PUB" && -n "$REALITY_SID" ]] || { err 'Reality 密钥解析失败'; return 1; }
}
load_state() {
    [[ -f "$SB_STATE" ]] || return 1
    jq -e --arg mark "$SB_MARK" '.manager == $mark and .port == 443' "$SB_STATE" >/dev/null 2>&1 || return 1
    DOMAIN="$(jq -r '.domain' "$SB_STATE")"
    ADDRESS="$(jq -r '.address' "$SB_STATE")"
    CERT_FULLCHAIN="$(jq -r '.cert_fullchain' "$SB_STATE")"
    CERT_PRIVKEY="$(jq -r '.cert_privkey' "$SB_STATE")"
    FALLBACK_PORT="$(jq -r '.fallback_port' "$SB_STATE")"
    FALLBACK_CONF="$(jq -r '.fallback_conf' "$SB_STATE")"
    BACKEND="$(jq -r '.backend' "$SB_STATE")"
    NODE_NAME="$(jq -r '.node_name // "R"' "$SB_STATE")"
    REALITY_PUB="$(jq -r '.reality_pub' "$SB_STATE")"
    MIGRATION_BACKUP="$(jq -r '.migration_backup // ""' "$SB_STATE")"
    ACME_CONF="$(jq -r '.acme_conf // ""' "$SB_STATE")"
}
save_state() {
    mkdir -p "$SB_DIR"
    local tmp
    tmp="$(mktemp "$SB_DIR/.state.XXXXXX")" || return 1
    jq -n --arg marker "$SB_MARK" --arg domain "$DOMAIN" --arg address "$ADDRESS" \
        --arg cert "$CERT_FULLCHAIN" --arg key "$CERT_PRIVKEY" \
        --argjson fallback "$FALLBACK_PORT" --arg conf "$FALLBACK_CONF" \
        --arg backend "$BACKEND" --arg node "$NODE_NAME" --arg pub "$REALITY_PUB" \
        --arg migration "${MIGRATION_BACKUP:-}" --arg acme "${ACME_CONF:-}" '{manager:$marker,domain:$domain,address:$address,port:443,cert_fullchain:$cert,cert_privkey:$key,fallback_port:$fallback,fallback_conf:$conf,backend:$backend,node_name:$node,reality_pub:$pub,migration_backup:$migration,acme_conf:$acme}' > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp"; mv -f "$tmp" "$SB_STATE"
}
write_config() {
    local output="$1" uid="$2" pk="$3" sid="$4" domain="$5" fallback="$6"
    jq -n --arg uid "$uid" --arg pk "$pk" --arg sid "$sid" \
        --arg domain "$domain" --argjson fb "$fallback" \
        '{log:{level:"info",timestamp:true},inbounds:[{type:"vless",tag:"vless-in",listen:"::",listen_port:443,users:[{uuid:$uid,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$domain,reality:{enabled:true,handshake:{server:"127.0.0.1",server_port:$fb},private_key:$pk,short_id:[$sid]}}}],outbounds:[{type:"direct",tag:"direct-out"}]}' > "$output"
}
check_config() { sing-box check -c "$1"; }
read_reality_config() {
    [[ -f "$SB_CONF" ]] || return 1
    REALITY_UUID="$(jq -r '.inbounds[] | select(.type == "vless") | .users[0].uuid // empty' "$SB_CONF" | head -n1)"
    REALITY_PK="$(jq -r '.inbounds[] | select(.type == "vless") | .tls.reality.private_key // empty' "$SB_CONF" | head -n1)"
    REALITY_SID="$(jq -r '.inbounds[] | select(.type == "vless") | .tls.reality.short_id[0] // empty' "$SB_CONF" | head -n1)"
    [[ -n "$REALITY_UUID" && -n "$REALITY_PK" && -n "$REALITY_SID" ]]
}
encode_url() {
    # URI fragment only; pass UTF-8 text via jq and percent encode.
    jq -nr --arg t "$1" '$t|@uri'
}
get_public_ip() {
    local result
    result="$(curl -4fsS --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null || true)"
    [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && printf '%s\n' "$result"
}
print_node_info() {
    load_state || { err '未找到本脚本安装的节点'; return 1; }
    read_reality_config || { err 'Reality 配置不完整'; return 1; }
    local host="$ADDRESS" name uri
    [[ -n "$host" ]] || host="$DOMAIN"
    name="$(encode_url "${NODE_NAME:-R}")"
    uri="vless://${REALITY_UUID}@${host}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${name}"
    echo
    echo '------------- Sing-box VLESS REALITY -------------'
    printf '地址: %s\n端口: 443\nUUID: %s\nFlow: xtls-rprx-vision\nSNI: %s\nPublicKey: %s\nShortID: %s\n' "$host" "$REALITY_UUID" "$DOMAIN" "$REALITY_PUB" "$REALITY_SID"
    printf 'HTTPS 回落: 127.0.0.1:%s -> %s\n' "$FALLBACK_PORT" "$BACKEND"
    echo '------------- 客户端导入链接 -------------'
    printf '%s\n' "$uri"
    printf '%s\n' "$uri" > "$SB_URI"; chmod 600 "$SB_URI"
    echo '------------- 节点二维码 -------------'
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "$uri" 2>/dev/null || qrencode -t UTF8 "$uri" || warn '二维码生成失败。'
    else
        warn 'qrencode 未安装，无法显示二维码；可执行 apt install qrencode。'
    fi
    info "已保存：$SB_URI"
}

# ---- Manager: installed service, snapshots, preflights ----
service_active() {
    if [[ "${PKG:-}" == apk ]]; then rc-service "$SB_SERVICE" status >/dev/null 2>&1
    else systemctl is-active --quiet "$SB_SERVICE" 2>/dev/null; fi
}
service_start() {
    if [[ "${PKG:-}" == apk ]]; then rc-service "$SB_SERVICE" start
    else systemctl start "$SB_SERVICE"; fi
}
service_stop() {
    if [[ "${PKG:-}" == apk ]]; then rc-service "$SB_SERVICE" stop
    else systemctl stop "$SB_SERVICE"; fi
}
service_restart() {
    if [[ "${PKG:-}" == apk ]]; then rc-service "$SB_SERVICE" restart
    else systemctl restart "$SB_SERVICE"; fi
}
service_disable() {
    if [[ "${PKG:-}" == apk ]]; then
        rc-service "$SB_SERVICE" stop >/dev/null 2>&1 || true
        rc-update del "$SB_SERVICE" default >/dev/null 2>&1 || true
    else
        systemctl disable --now "$SB_SERVICE" >/dev/null 2>&1 || true
    fi
}
service_unit_file() {
    if [[ "${PKG:-}" == apk ]]; then printf '%s\n' /etc/init.d/sing-box
    else printf '%s\n' "$SB_UNIT"; fi
}
unit_is_owned() {
    local path
    path="$(service_unit_file)"
    [[ -f "$path" ]] && grep -Fq "$SB_MARK" "$path"
}
state_is_owned() {
    [[ -f "$SB_STATE" ]] && jq -e --arg m "$SB_MARK" '.manager == $m' "$SB_STATE" >/dev/null 2>&1
}
port_free_or_owned() {
    local existing
    existing="$(port_owner 443)"
    [[ -z "$existing" ]] && return 0
    if [[ "$1" == managed || "$1" == migrate ]]; then
        if [[ "$existing" == *sing-box* ]] && [[ "$existing" != *xray* ]]; then return 0; fi
    fi
    err 'TCP/443 is already in use; no other service will be stopped:'
    printf '%s\n' "$existing" >&2
    return 1
}
need_tools() {
    local tool
    for tool in jq openssl curl nginx ss; do
        command -v "$tool" >/dev/null 2>&1 || { err "Missing dependency: $tool"; return 1; }
    done
}
choose_domain() {
    local value=''
    while :; do
        read_tty "请输入域名（domain.tld）: " value || return 1
        value="${value,,}"
        value="${value//[[:space:]]/}"
        if valid_domain "$value"; then DOMAIN="$value"; break; fi
        err 'Invalid domain. Please enter one hostname, without scheme or port.'
    done
    info "Selected domain: $DOMAIN"
    local ips remote
    ips="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
    remote="$(get_public_ip || true)"
    if [[ -n "$ips" && -n "$remote" && " $ips " != *" $remote "* ]]; then
        warn "DNS IPv4: $ips ; server detected IPv4: $remote"
        warn 'DNS may not point to this VPS. ACME HTTP-01 may fail.'
    fi
}
choose_address() {
    local value=''
    read_tty "Client connection host (Enter = $DOMAIN): " value || return 1
    value="${value//[[:space:]]/}"
    if [[ -n "$value" ]] && ! valid_host "$value"; then
        err 'Client host must be a domain or IPv4 address.'; return 1
    fi
    ADDRESS="${value:-$DOMAIN}"
}
choose_node_name() {
    read_tty 'Node name (Enter = R): ' NODE_NAME || return 1
    NODE_NAME="${NODE_NAME:-R}"
    [[ ${#NODE_NAME} -le 100 ]] || { err 'Node name too long'; return 1; }
}
choose_existing_backend() {
    if [[ -n "${BACKEND:-}" ]]; then
        info "Current backend: $BACKEND"
    fi
    choose_backend
}

# Snapshot only manager-owned files; never archive/edit any user Nginx site.
create_snapshot() {
    local kind="${1:-manual}" dest path unit binary
    mkdir -p "$SB_BACKUPS" || return 1
    dest="$SB_BACKUPS/$(date +%Y%m%d-%H%M%S)-${kind}-$RANDOM"
    mkdir -m 700 -p "$dest" || return 1
    # Config and keys are essential backups, never silently ignore copy errors.
    for path in "$SB_CONF" "$SB_STATE" "$SB_URI"; do
        if [[ -e "$path" || -L "$path" ]]; then
            cp -a "$path" "$dest/$(basename "$path")" || return 1
        fi
    done
    unit="$(service_unit_file)"
    if [[ -f "$unit" ]]; then cp -a "$unit" "$dest/service-unit" || return 1; fi
    if state_is_owned && load_state; then
        if [[ -f "${FALLBACK_CONF:-}" ]] && grep -Fqx "# $SB_MARK" "$FALLBACK_CONF"; then
            cp -a "$FALLBACK_CONF" "$dest/fallback.conf" || return 1
        fi
    fi
    binary="$(command -v sing-box || true)"
    if [[ -n "$binary" && -f "$binary" ]]; then
        cp -L -p "$binary" "$dest/sing-box-bin" || warn 'Could not include optional sing-box binary in snapshot.'
    fi
    printf 'kind=%s\ncreated=%s\nbinary=%s\n' "$kind" "$(date -Is)" "$binary" > "$dest/manifest.txt" || return 1
    chmod -R go-rwx "$dest" || true
    SNAPSHOT="$dest"
    ok "Snapshot created: $dest"
}

is_single_legacy_reality() {
    [[ -s "$SB_CONF" ]] || return 1
    jq -e '(.inbounds|length) == 1 and (.inbounds[0].type == "vless") and (.inbounds[0].tls.reality.enabled == true) and (.inbounds[0].users|length) == 1 and (.inbounds[0].users[0].flow == "xtls-rprx-vision")' "$SB_CONF" >/dev/null 2>&1
}
old_public_key() {
    local result=''
    for f in "$SB_DIR/.reality_pub"; do
        if [[ -s "$f" ]]; then result="$(tr -d '\r\n' < "$f")"; break; fi
    done
    if [[ -z "$result" && -s "$SB_DIR/.config_cache" ]]; then
        result="$(sed -n 's/^REALITY_PUB=//p' "$SB_DIR/.config_cache" | tail -n1)"
    fi
    if [[ -z "$result" && -s "$SB_DIR/uris.txt" ]]; then
        result="$(sed -nE 's/.*[?&]pbk=([A-Za-z0-9_-]+).*/\1/p' "$SB_DIR/uris.txt" | head -n1)"
    fi
    if [[ -z "$result" || ! "$result" =~ ^[A-Za-z0-9_-]{43,44}$ ]]; then
        warn 'Legacy public key not found in cache or URI.'
        read_tty 'Paste the PUBLIC key (pbk) from your existing client link: ' result || return 1
    fi
    [[ "$result" =~ ^[A-Za-z0-9_-]{43,44}$ ]] || { err 'Invalid public key'; return 1; }
    REALITY_PUB="$result"
}

# --- Detect and archive the original (multi-protocol-capable) s.sh installation ---
legacy_sb_command() {
    [[ -f "$SB_ALIAS" && ! -L "$SB_ALIAS" ]] || return 1
    grep -Fq 'Sing-box 管理面板 (快速指令sb)' "$SB_ALIAS" &&
        grep -Fq '/etc/sing-box/config.json' "$SB_ALIAS"
}
legacy_unit_matches() {
    local unit
    unit="$(service_unit_file)"
    [[ -f "$unit" && ! -L "$unit" ]] || return 1
    # Old s.sh installed exactly sing-box run -c /etc/sing-box/config.json.
    grep -Eq '(^|[[:space:]])(ExecStart|command_args)[[:space:]]*=' "$unit" &&
        grep -Fq -- "$SB_CONF" "$unit" &&
        grep -q 'sing-box' "$unit"
}
legacy_cache_matches() {
    if [[ -s "$SB_DIR/.protocols" ]] &&
       grep -Eq '^ENABLE_(REALITY|SS|HY2|TUIC)=(true|false)$' "$SB_DIR/.protocols"; then return 0; fi
    if [[ -s "$SB_DIR/.config_cache" ]] &&
       grep -Eq '^(ENABLE_REALITY|REALITY_PORT|REALITY_UUID)=' "$SB_DIR/.config_cache"; then return 0; fi
    if [[ -s "$SB_DIR/.reality_pub" && -s "$SB_DIR/.reality_sid" ]]; then return 0; fi
    return 1
}
legacy_config_matches() {
    [[ -s "$SB_CONF" && ! -L "$SB_CONF" ]] || return 1
    jq -e '(.inbounds | type) == "array" and
      any(.inbounds[]; .type == "vless" and .tls.reality.enabled == true) and
      all(.inbounds[]; .type == "vless" or .type == "shadowsocks" or
                        .type == "hysteria2" or .type == "tuic")'        "$SB_CONF" >/dev/null 2>&1
}
legacy_install_detected() {
    state_is_owned && return 1
    # A matching old cache or old sb executable identifies the original script.
    # A broken install with just the service/cache left is also recognized.
    if legacy_config_matches; then
        legacy_cache_matches || legacy_sb_command || return 1
        return 0
    fi
    [[ ! -e "$SB_CONF" && ! -L "$SB_CONF" ]] || return 1
    legacy_cache_matches && { legacy_sb_command || legacy_unit_matches; }
}
snapshot_legacy_artifacts() {
    local dest="$SNAPSHOT/legacy-files" file name
    mkdir -m 700 -p "$dest" || return 1
    for name in .protocols .config_cache .reality_pub .reality_sid                 uris.txt relay_uri.txt; do
        file="$SB_DIR/$name"
        if [[ -e "$file" || -L "$file" ]]; then
            cp -a "$file" "$dest/$name" || return 1
        fi
    done
    if [[ -d "$SB_DIR/certs" && ! -L "$SB_DIR/certs" ]]; then
        cp -a "$SB_DIR/certs" "$dest/certs" || return 1
    fi
    if [[ -f /root/node_names.txt ]]; then
        cp -a /root/node_names.txt "$dest/node_names.txt" || return 1
    fi
    if legacy_sb_command; then
        cp -a "$SB_ALIAS" "$dest/old-sb-command" || return 1
    fi
    # If a newer manager left orphaned fallback configs, preserve their bytes.
    mkdir -p "$dest/nginx" || return 1
    for file in "$NGINX_DIR"/s-reality-fallback-*.conf "$NGINX_DIR"/s-reality-acme-*.conf; do
        [[ -f "$file" && ! -L "$file" ]] || continue
        grep -Fqx "# $SB_MARK" "$file" || continue
        cp -a "$file" "$dest/nginx/$(basename "$file")" || return 1
    done
    chmod -R go-rwx "$dest" || true
}

# Make separate ACME HTTP-01 route only if no existing matching Nginx site owns the domain.
# If an existing domain website handles :80, the user provides its webroot instead.
acme_conf_for_domain() { printf '%s/s-reality-acme-%s.conf\n' "$NGINX_DIR" "$1"; }
nginx_vhost_for_domain_exists() {
    local file
    for file in /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [[ -f "$file" ]] || continue
        [[ "$(basename "$file")" == "s-reality-acme-$DOMAIN.conf" ]] && continue
        # This is deliberately conservative: even a TLS-only matching vhost is user-owned.
        if grep -Eq "(^|[[:space:]])server_name[[:space:]]+[^;]*${DOMAIN//./\\.}([[:space:];]|$)" "$file"; then
            return 0
        fi
    done
    return 1
}
setup_acme_webroot() {
    local path content challenge actual expected old=''
    ACME_ROOT='/var/lib/s-reality/acme'
    ACME_CONF=''
    mkdir -p "$ACME_ROOT/.well-known/acme-challenge" "$NGINX_DIR" || return 1
    if nginx_vhost_for_domain_exists; then
        warn 'An existing Nginx server_name matches this domain; it is left unchanged.'
        read_tty 'Webroot of its existing ACME challenge route (blank to cancel): ' ACME_ROOT || return 1
        [[ -d "$ACME_ROOT" ]] || { err 'Provided webroot does not exist.'; return 1; }
        return 0
    fi
    # A foreign service owning 80 cannot be displaced by Nginx.
    if port_busy 80 && [[ "$(port_owner 80)" != *nginx* ]]; then
        warn 'TCP/80 belongs to a non-Nginx service; it will not be changed.'
        read_tty 'Webroot already exposed by that server for ACME (blank to cancel): ' ACME_ROOT || return 1
        [[ -d "$ACME_ROOT" ]] || { err 'Invalid webroot'; return 1; }
        return 0
    fi
    path="$(acme_conf_for_domain "$DOMAIN")"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] && grep -Fqx "# $SB_MARK" "$path" || {
            err 'ACME config path is not owned by this script; refusing overwrite.'; return 1;
        }
        old="$(mktemp /tmp/s-reality-acme-old.XXXXXX)" || return 1
        cp -p "$path" "$old" || return 1
    fi
    content="$(mktemp "$NGINX_DIR/.s-reality-acme.XXXXXX")" || return 1
    cat > "$content" <<ACME
# $SB_MARK
server {
    listen 80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/s-reality/acme;
        default_type text/plain;
        try_files \$uri =404;
    }
    location / { return 404; }
}
ACME
    if ! mv -f "$content" "$path" || ! nginx_reload_or_start; then
        if [[ -n "$old" ]]; then cp -p "$old" "$path"; else rm -f "$path"; fi
        nginx_reload_or_start >/dev/null 2>&1 || true
        rm -f "$old" "$content"
        err 'ACME Nginx route activation failed; rolled back.'
        return 1
    fi
    rm -f "$old"
    ACME_CONF="$path"
    challenge="s-reality-$(date +%s)-$RANDOM"
    expected="acme-test-$RANDOM"
    printf '%s' "$expected" > "$ACME_ROOT/.well-known/acme-challenge/$challenge"
    actual="$(curl --noproxy '*' -fsS -H "Host: $DOMAIN" --connect-timeout 2 --max-time 4 "http://127.0.0.1/.well-known/acme-challenge/$challenge" 2>/dev/null || true)"
    rm -f "$ACME_ROOT/.well-known/acme-challenge/$challenge"
    if [[ "$actual" != "$expected" ]]; then
        err 'ACME challenge is not being served over TCP/80 with the matching Host header.'
        # A newly created owned route is intentionally left for diagnostics and retry.
        return 1
    fi
}
select_certificate_with_acme() {
    local choice='' had_existing=0 issue_flag=''
    CERT_FULLCHAIN=''; CERT_PRIVKEY=''; ACME_CONF=''
    echo
    echo '------------------------------------------------'
    echo "域名证书处理：$DOMAIN"
    echo '------------------------------------------------'
    if locate_existing_cert "$DOMAIN"; then
        had_existing=1
        ok "本地证书有效且与域名/私钥匹配：$CERT_FULLCHAIN"
        openssl x509 -in "$CERT_FULLCHAIN" -noout -enddate 2>/dev/null || true
        read_tty '是否重新申请证书？(y/N，回车复用现有证书): ' choice || return 1
        if ! is_yes "$choice"; then
            ok '复用原证书；证书文件和原有 Nginx 网站配置均不修改。'
            return 0
        fi
        warn '已选择重新申请/续签，证书颁发机构可能有限频限制。'
        issue_flag='--force-renewal'
    else
        warn "未找到可用于 $DOMAIN 的有效本地证书。"
        echo '可复用的证书位置：/etc/letsencrypt/live/<证书名>/ 或 /root/cert/<域名>/'
        read_tty "是否申请 Let's Encrypt 证书？(Y/n): " choice || return 1
        if is_no "$choice"; then info '已取消证书申请。'; return 1; fi
        if [[ -n "$choice" ]] && ! is_yes "$choice"; then warn '请输入 Y/y 或 N/n。'; return 1; fi
    fi
    command -v certbot >/dev/null 2>&1 || { err '缺少 certbot'; return 1; }
    if ! setup_acme_webroot; then
        err '没有可用的 HTTP-01 验证路径；未改动原有网站。'
        return 1
    fi
    # For an already existing lineage, Certbot reuses its name. Do not
    # stop Nginx, erase sites-enabled, or change any user certificate link.
    if ! certbot certonly --webroot --webroot-path "$ACME_ROOT" \
        --non-interactive --agree-tos --register-unsafely-without-email \
        ${issue_flag:+"$issue_flag"} -d "$DOMAIN"; then
        err '证书申请失败；请检查 DNS A/AAAA、80 端口与 ACME 验证路径。'
        return 1
    fi
    if ! locate_existing_cert "$DOMAIN"; then
        err '证书申请后未找到可校验的 fullchain.pem / privkey.pem。'
        return 1
    fi
    ok "证书申请/续签成功：$CERT_FULLCHAIN"
    if command -v nginx >/dev/null 2>&1; then nginx_reload_or_start || warn 'Nginx 证书重载失败；检查 nginx -t。'; fi
}
safe_reality_config_write() {
    local config_file="$1" uid="$2" pk="$3" sid="$4" name="$5" target_port="$6"
    write_config "$config_file" "$uid" "$pk" "$sid" "$name" "$target_port" || return 1
    chmod 600 "$config_file" || return 1
    if ! check_config "$config_file"; then
        err 'sing-box check failed. The current running config is unchanged.'
        return 1
    fi
}

# Explicitly mark owned services; Alpine gets OpenRC supervise-daemon.
setup_managed_service() {
    local binary unit
    binary="$(command -v sing-box)" || return 1
    unit="$(service_unit_file)"
    if [[ -e "$unit" ]] && ! unit_is_owned && [[ "${INSTALL_MODE:-}" != migrate ]]; then
        err "Existing sing-box service unit is not owned by this script: $unit"
        err '拒绝覆盖其他程序的 sing-box 服务；请使用菜单 1 确认迁移。'
        return 1
    fi
    mkdir -p "$(dirname "$unit")" || return 1
    if [[ "${PKG:-}" == apk ]]; then
        cat > "$unit" <<OPENRC
#!/sbin/openrc-run
# $SB_MARK
name="sing-box Reality"
command="$binary"
command_args="run -c $SB_CONF"
command_background=true
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"
depend() { need net; }
OPENRC
        chmod 755 "$unit"
        rc-update add "$SB_SERVICE" default >/dev/null 2>&1 || return 1
    else
        cat > "$unit" <<UNIT
# $SB_MARK
[Unit]
Description=Sing-box Reality 443 (managed by s.sh)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=$binary run -c $SB_CONF
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload || return 1
        systemctl enable "$SB_SERVICE" >/dev/null 2>&1 || return 1
    fi
    service_restart >/dev/null 2>&1 || service_start || return 1
    sleep 1
    service_active || { err 'sing-box service is not active.'; return 1; }
}

backup_current_config() {
    local dest="$SB_DIR/.config.before-s-reality.$(date +%Y%m%d%H%M%S).$RANDOM"
    [[ -f "$SB_CONF" ]] || return 0
    cp -a "$SB_CONF" "$dest" || return 1
    chmod 600 "$dest" || true
    CONFIG_ROLLBACK="$dest"
    info "Rollback config: $CONFIG_ROLLBACK"
}
rollback_config_if_possible() {
    if [[ -f "${CONFIG_ROLLBACK:-}" ]]; then
        cp -a "$CONFIG_ROLLBACK" "$SB_CONF" || true
        if service_active || unit_is_owned; then service_restart >/dev/null 2>&1 || true; fi
        warn 'Previous config restored. Previous service unit and Nginx files may need inspection.'
    fi
}


restore_legacy_snapshot() {
    local directory="$1" unit=''
    [[ -n "$directory" && -f "$directory/config.json" && -f "$directory/manifest.txt" ]] || return 1
    service_disable
    unit="$(service_unit_file)"
    if unit_is_owned; then rm -f "$unit"; fi
    if [[ -s "$directory/service-unit" ]]; then
        cp -a "$directory/service-unit" "$unit" || return 1
    fi
    cp -a "$directory/config.json" "$SB_CONF" || return 1
    # Preserve the old manager UX if the user explicitly restored the legacy node.
    # Never overwrite shortcuts or files created by somebody else in the meantime.
    local name source_file target_file
    for name in .protocols .config_cache .reality_pub .reality_sid uris.txt relay_uri.txt; do
        source_file="$directory/legacy-files/$name"
        target_file="$SB_DIR/$name"
        if [[ -e "$source_file" && ! -e "$target_file" && ! -L "$target_file" ]]; then
            cp -a "$source_file" "$target_file" || return 1
        fi
    done
    if [[ -f "$directory/legacy-files/old-sb-command" && ! -e "$SB_ALIAS" && ! -L "$SB_ALIAS" ]]; then
        mkdir -p "$(dirname "$SB_ALIAS")" || return 1
        cp -a "$directory/legacy-files/old-sb-command" "$SB_ALIAS" || return 1
    fi
    if [[ "${PKG:-}" != apk ]]; then
        systemctl daemon-reload || return 1
        systemctl enable "$SB_SERVICE" >/dev/null 2>&1 || true
    else
        rc-update add "$SB_SERVICE" default >/dev/null 2>&1 || true
    fi
    service_start || { err 'Original configuration restored, but its service failed to start.'; return 1; }
    ok 'Pre-migration REALITY and service config restored.'
}
abort_reality_transaction() {
    local added_bridge="$1" unit=''
    case "${INSTALL_MODE:-new}" in
        new)
            service_disable
            unit="$(service_unit_file)"
            if unit_is_owned; then rm -f "$unit"; fi
            if [[ "${PKG:-}" != apk ]]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
            rm -f "$SB_CONF"
            ;;
        managed)
            rollback_config_if_possible
            ;;
        migrate)
            restore_legacy_snapshot "${MIGRATION_BACKUP:-}" || warn 'Automatic legacy recovery failed. Original files are in the migration snapshot.'
            ;;
    esac
    [[ -n "$added_bridge" ]] && safe_remove_nginx_owned "$added_bridge" || true
}

install_reality() {
    require_root || return 1
    require_debian_or_rhel || return 1
    local oldconf='' oldfb='' olddomain='' oldacme='' answer=''
    local current_uuid='' current_pk='' current_sid='' current_pub=''
    local temp_config='' new_fallback_conf='' actual_443=''
    INSTALL_MODE=new; MIGRATION_BACKUP=''; ACME_CONF=''; CONFIG_ROLLBACK=''

    if state_is_owned; then
        load_state || return 1
        INSTALL_MODE=managed
        oldconf="${FALLBACK_CONF:-}"; oldfb="${FALLBACK_PORT:-}"; olddomain="${DOMAIN:-}"
        oldacme="${ACME_CONF:-}"
        warn "Managed REALITY is already installed for $DOMAIN. Keys will not be changed by a normal rerun."
        read_tty '是否重新安装并生成新节点密钥？(y/N): ' answer || return 1
        is_yes "$answer" || { info '已取消，原节点保持不变。'; return 0; }
        create_snapshot before-rebuild || return 1
    elif [[ -s "$SB_CONF" ]]; then
        if ! is_single_legacy_reality; then
            err 'Existing /etc/sing-box/config.json is not a single Reality inbound.'
            err 'To avoid destroying existing protocols, no changes will be made.'
            return 1
        fi
        warn 'Existing sing-box Reality installation detected (not owned by this manager).'
        read_tty '是否迁移旧版 Reality 并保留 UUID/密钥？(y/N): ' answer || return 1
        is_yes "$answer" || { info '已取消旧版迁移。'; return 0; }
        INSTALL_MODE=migrate
        read_reality_config || return 1
        old_public_key || return 1
        current_uuid="$REALITY_UUID"; current_pk="$REALITY_PK"; current_sid="$REALITY_SID"; current_pub="$REALITY_PUB"
        # Save original unit/config for manual restore before overwriting anything.
        create_snapshot pre-migration || return 1
        snapshot_legacy_artifacts || return 1
        MIGRATION_BACKUP="$SNAPSHOT"
    fi

    port_free_or_owned "$INSTALL_MODE" || return 1
    nginx_preflight || return 1
    choose_domain || return 1
    ADDRESS="$DOMAIN"  # Connect host = Reality SNI = entered domain
    NODE_NAME="R"
    info "连接地址 / Reality SNI：$DOMAIN （统一使用该域名）"
    install_deps || return 1
    need_tools || return 1
    port_free_or_owned "$INSTALL_MODE" || return 1
    nginx_preflight || return 1
    if ! select_certificate_with_acme; then
        err 'A usable certificate is required for local HTTPS fallback.'
        return 1
    fi
    choose_existing_backend || return 1
    choose_fallback_port || return 1

    install_singbox || return 1
    if [[ "$INSTALL_MODE" == managed && -z "${ACME_CONF:-}" && "${DOMAIN:-}" == "${olddomain:-}" ]]; then
        ACME_CONF="$oldacme"
    fi
    if [[ "$INSTALL_MODE" == migrate ]]; then
        REALITY_UUID="$current_uuid"; REALITY_PK="$current_pk"; REALITY_SID="$current_sid"; REALITY_PUB="$current_pub"
    else
        REALITY_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || sing-box generate uuid)" || return 1
        keys_generate || return 1
    fi
    temp_config="$(mktemp /tmp/s-reality-config.XXXXXX)" || return 1
    if ! safe_reality_config_write "$temp_config" "$REALITY_UUID" "$REALITY_PK" "$REALITY_SID" "$DOMAIN" "$FALLBACK_PORT"; then
        rm -f "$temp_config"; return 1
    fi
    # Ownership checked BEFORE modifying current service/config.
    if [[ "$INSTALL_MODE" != migrate && "$INSTALL_MODE" != managed ]] && [[ -e "$(service_unit_file)" ]] && ! unit_is_owned; then
        rm -f "$temp_config"
        err 'An existing service unit is not managed by s.sh; aborting.'
        return 1
    fi
    if ! activate_fallback "$DOMAIN" "$FALLBACK_PORT" "$CERT_FULLCHAIN" "$CERT_PRIVKEY" "$BACKEND"; then
        rm -f "$temp_config"; return 1
    fi
    new_fallback_conf="$FALLBACK_CONF"
    mkdir -p "$SB_DIR" || return 1
    backup_current_config || { rm -f "$temp_config"; return 1; }
    if ! mv -f "$temp_config" "$SB_CONF"; then return 1; fi
    chmod 600 "$SB_CONF"
    if ! setup_managed_service; then
        err 'Service start failed. Restoring pre-install state.'
        abort_reality_transaction "$new_fallback_conf"
        return 1
    fi
    # Test public TCP/443 listener and actual local HTTPS fallback, not just config syntax.
    actual_443="$(port_owner 443)"
    if [[ "$actual_443" != *sing-box* ]] || ! verify_tls "$FALLBACK_PORT" "$DOMAIN"; then
        err 'Post-install TLS or TCP/443 verification failed.'
        abort_reality_transaction "$new_fallback_conf"
        return 1
    fi
    save_state || { err 'Failed to save managed state'; abort_reality_transaction "$new_fallback_conf"; return 1; }
    # The original s.sh created a real /usr/local/bin/sb script. After
    # successful migration replace ONLY that recognizable legacy command.
    if [[ "$INSTALL_MODE" == migrate ]] && legacy_sb_command; then
        rm -f "$SB_ALIAS" || warn 'Could not remove legacy sb shortcut; use sreality.'
    fi
    install_manager_command || warn 'Could not create sb shortcut.'
    # Remove ONLY the former manager-owned TLS bridge after a successful rebuild.
    if [[ "$INSTALL_MODE" == managed && -n "$oldconf" && "$oldconf" != "$new_fallback_conf" ]]; then
        safe_remove_nginx_owned "$oldconf" || true
    fi
    print_node_info || true
    if authenticated_probe; then
        ok 'Sing-box REALITY installation and proxy verification passed. TCP/443 + independent HTTPS fallback are ready.'
    else
        warn 'Service and TLS fallback are up, but the authenticated proxy test was inconclusive. Do not assume the node works; use menu 6 and review logs.'
    fi
}

safe_remove_nginx_owned() {
    local path="$1"
    [[ -n "$path" && -f "$path" && ! -L "$path" ]] || return 0
    if ! grep -Fqx "# $SB_MARK" "$path"; then
        warn "Not managed by s.sh: $path"; return 1
    fi
    rm -f "$path" || return 1
    nginx_reload_or_start >/dev/null 2>&1 || warn 'Nginx reload failed after deleting a managed bridge.'
}

update_domain_sni() {
    require_root || return 1
    require_debian_or_rhel || return 1
    load_state || { err 'Install the managed Reality node first.'; return 1; }
    read_reality_config || return 1
    local prevdomain="$DOMAIN" prevconf="$FALLBACK_CONF" prevport="$FALLBACK_PORT"
    local prevstate="$SB_DIR/.state.before-update.$(date +%Y%m%d%H%M%S).$RANDOM"
    local uid="$REALITY_UUID" pk="$REALITY_PK" sid="$REALITY_SID" pub="$REALITY_PUB"
    local config_tmp=''
    cp -p "$SB_STATE" "$prevstate" || return 1
    create_snapshot before-domain-change || return 1
    choose_domain || return 1
    if [[ "$DOMAIN" == "$prevdomain" ]]; then info 'Domain is unchanged.'; return 0; fi
    ADDRESS="$DOMAIN"
    install_deps || return 1
    nginx_preflight || return 1
    select_certificate_with_acme || return 1
    choose_existing_backend || return 1
    choose_fallback_port || return 1
    config_tmp="$(mktemp /tmp/s-reality-update.XXXXXX)" || return 1
    safe_reality_config_write "$config_tmp" "$uid" "$pk" "$sid" "$DOMAIN" "$FALLBACK_PORT" || { rm -f "$config_tmp"; return 1; }
    activate_fallback "$DOMAIN" "$FALLBACK_PORT" "$CERT_FULLCHAIN" "$CERT_PRIVKEY" "$BACKEND" || { rm -f "$config_tmp"; return 1; }
    backup_current_config || return 1
    mv -f "$config_tmp" "$SB_CONF" || return 1
    if ! service_restart || ! service_active || ! verify_tls "$FALLBACK_PORT" "$DOMAIN"; then
        err 'New domain activation failed; rolling back old config/state.'
        rollback_config_if_possible
        cp -p "$prevstate" "$SB_STATE" || true
        safe_remove_nginx_owned "$FALLBACK_CONF" || true
        return 1
    fi
    REALITY_PUB="$pub"
    save_state || { err 'New state could not be saved'; return 1; }
    safe_remove_nginx_owned "$prevconf" || true
    ok "Domain/SNI changed: $prevdomain => $DOMAIN; UUID/keys unchanged."
    print_node_info
}

# Real authenticated path test: temporary local SOCKS client -> Reality 443 ->
# sing-box direct outbound -> temporary local HTTP server. No Internet required.
authenticated_probe() {
    require_debian_or_rhel || return 1
    load_state || return 1
    read_reality_config || return 1
    local s_port='' h_port='' probe_dir='' client_tmp='' cli_pid='' web_pid='' result=''
    s_port="$(get_unused_port 26500)" || return 1
    h_port="$(get_unused_port 27500)" || return 1
    [[ "$s_port" != "$h_port" ]] || return 1
    probe_dir="$(mktemp -d /tmp/s-reality-probe.XXXXXX)" || return 1
    client_tmp="$probe_dir/client.json"
    printf '%s' "s-reality-pass-$$" > "$probe_dir/index.html"
    jq -n --arg domain "$DOMAIN" --arg uuid "$REALITY_UUID" --arg pub "$REALITY_PUB" --arg sid "$REALITY_SID" --argjson socks "$s_port" \
        '{log:{level:"warn"},inbounds:[{type:"socks",tag:"socks-probe",listen:"127.0.0.1",listen_port:$socks}],outbounds:[{type:"vless",tag:"reality-test",server:"127.0.0.1",server_port:443,uuid:$uuid,flow:"xtls-rprx-vision",tls:{enabled:true,server_name:$domain,utls:{enabled:true,fingerprint:"chrome"},reality:{enabled:true,public_key:$pub,short_id:$sid}}}]}' > "$client_tmp" || return 1
    if ! sing-box check -c "$client_tmp" >/dev/null 2>&1; then
        err 'Local self-test client config invalid; installed server remains unchanged.'
        rm -rf "$probe_dir"
        return 1
    fi
    python3 -m http.server "$h_port" --bind 127.0.0.1 --directory "$probe_dir" > "$probe_dir/http.log" 2>&1 &
    web_pid="$!"
    sing-box run -c "$client_tmp" > "$probe_dir/client.log" 2>&1 &
    cli_pid="$!"
    sleep 2
    result="$(curl --noproxy '' -fsS --connect-timeout 4 --max-time 12 \
        --proxy "socks5h://127.0.0.1:$s_port" "http://127.0.0.1:$h_port/" 2>/dev/null || true)"
    kill "$cli_pid" "$web_pid" 2>/dev/null || true
    wait "$cli_pid" "$web_pid" 2>/dev/null || true
    if [[ "$result" == "s-reality-pass-$$" ]]; then
        ok 'Authenticated Reality proxy self-test passed (local SOCKS->443->HTTP).'
        rm -rf "$probe_dir"; return 0
    fi
    warn "Authenticated Reality probe failed. Logs: $probe_dir/client.log"
    return 1
}
get_unused_port() {
    local candidate base="${1:-26000}"
    for ((candidate=base;candidate<base+300;candidate++)); do
        if ! port_busy "$candidate"; then printf '%s\n' "$candidate"; return 0; fi
    done
    return 1
}

# ---- Menu operations ----
show_status() {
    require_debian_or_rhel || return 1
    echo
    echo 'Sing-box REALITY service status'
    if service_active; then ok 'Service running'; else warn 'Service stopped'; fi
    command -v sing-box >/dev/null 2>&1 && sing-box version | head -n1 || true
    echo 'TCP ports 80, 443 and managed fallback:'
    ss -lntp 2>/dev/null | grep -E ':(80|443|180[0-9][0-9]|181[0-9][0-9])\b' || true
    echo
    if load_state; then
        printf 'Domain/SNI: %s\nConnect address: %s\nFallback: 127.0.0.1:%s -> %s\n' "$DOMAIN" "$ADDRESS" "$FALLBACK_PORT" "$BACKEND"
        printf 'Certificate: %s\nConfig: %s\n' "$CERT_FULLCHAIN" "$SB_CONF"
        if [[ -f "$CERT_FULLCHAIN" ]]; then openssl x509 -in "$CERT_FULLCHAIN" -noout -dates 2>/dev/null; fi
        if verify_tls "$FALLBACK_PORT" "$DOMAIN"; then ok 'HTTPS fallback TLS valid'; else warn 'Fallback HTTPS TLS unavailable'; fi
        if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then ok 'Nginx config valid'; else warn 'Nginx config invalid'; fi
    else
        warn 'No managed state found.'
    fi
    echo
    if [[ "${PKG:-}" == apk ]]; then
        tail -n 12 /var/log/sing-box.log 2>/dev/null || true
    else
        journalctl -u sing-box -n 12 --no-pager 2>/dev/null || true
    fi
    cron_update_status
}
website_test() {
    require_debian_or_rhel || return 1
    load_state || { err 'No managed state'; return 1; }
    echo "Checking domain/SNI: $DOMAIN"
    if check_pair "$DOMAIN" "$CERT_FULLCHAIN" "$CERT_PRIVKEY"; then ok 'Certificate and private key valid'; else warn 'Certificate or key invalid'; fi
    if verify_tls "$FALLBACK_PORT" "$DOMAIN"; then ok 'Local TLS fallback valid'; else warn 'Local TLS fallback invalid'; fi
    if command -v curl >/dev/null 2>&1; then
        curl --noproxy '*' --resolve "$DOMAIN:443:127.0.0.1" -k -sSI --connect-timeout 4 --max-time 9 "https://$DOMAIN/" | head -n 12 || true
    fi
    authenticated_probe || true
}

restore_core_binary() {
    local backup="$1" dest="$2" actual='' tmp=''
    [[ -s "$backup" && -n "$dest" ]] || return 1
    actual="$(readlink -f "$dest" 2>/dev/null || true)"
    [[ -n "$actual" && -d "$(dirname "$actual")" ]] || return 1
    tmp="$(mktemp "$(dirname "$actual")/.s-reality-core-restore.XXXXXX")" || return 1
    if ! cp -p "$backup" "$tmp" || ! chmod +x "$tmp" || ! mv -f "$tmp" "$actual"; then
        rm -f "$tmp"; return 1
    fi
}
safe_update() {
    require_root || return 1
    require_debian_or_rhel || return 1
    state_is_owned || { err '请先安装由 s.sh 管理的 Reality 节点。'; return 1; }
    command -v sing-box >/dev/null 2>&1 || { err '找不到 sing-box 可执行文件。'; return 1; }
    create_snapshot before-upgrade || return 1
    local prev_binary="$SNAPSHOT/sing-box-bin" binary='' prior='' updated='' setupfile='' install_ok=0
    binary="$(command -v sing-box)"
    prior="$(sing-box version | head -n1)"
    info "更新前 Sing-box：$prior"
    if [[ "${PKG:-}" == apk ]]; then
        if apk update && apk upgrade sing-box; then install_ok=1; fi
    else
        setupfile="$(mktemp /tmp/singbox-upgrade.XXXXXX)" || return 1
        if curl -fsSL --retry 3 'https://sing-box.app/install.sh' -o "$setupfile" &&
           bash "$setupfile"; then
            install_ok=1
        fi
        rm -f "$setupfile"
    fi
    if (( install_ok )); then
        updated="$(sing-box version | head -n1 || true)"
        if sing-box check -c "$SB_CONF" &&
           service_restart && service_active &&
           load_state && verify_tls "$FALLBACK_PORT" "$DOMAIN" &&
           authenticated_probe; then
            ok "Sing-box 更新成功并通过 Reality 认证自测：$prior => $updated"
            return 0
        fi
        err '更新后检查未通过，开始恢复原版。'
    else
        err 'Sing-box 安装器运行失败，开始恢复原版。'
    fi
    # Restore original binary atomically where possible; a failed package
    # update may already have replaced it on disk.
    if [[ -s "$prev_binary" ]]; then
        restore_core_binary "$prev_binary" "$binary" || warn '核心文件自动恢复失败，请查看快照手动处理。'
    else
        warn '快照没有可用的旧核心文件，请手动检查。'
    fi
    if [[ -s "$SNAPSHOT/config.json" ]]; then
        cp -a "$SNAPSHOT/config.json" "$SB_CONF" || warn '配置文件恢复失败。'
    fi
    local unit=''
    unit="$(service_unit_file)"
    if [[ -s "$SNAPSHOT/service-unit" ]]; then
        cp -a "$SNAPSHOT/service-unit" "$unit" || warn '服务文件恢复失败。'
    fi
    if [[ "${PKG:-}" != apk ]]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    if service_restart && service_active; then
        warn "已恢复升级前服务配置。备份目录：$SNAPSHOT"
    else
        err "恢复后仍未能启动服务，请检查：$SNAPSHOT"
    fi
    return 1
}
# ---- Optional Sing-box core updates (NOT the Linux kernel) ----
# Cron time is interpreted in the VPS's own local timezone.
cron_update_installed() {
    if [[ "${PKG:-}" == apk ]]; then
        [[ -f /etc/crontabs/root ]] && grep -Fq "$SB_MARK CORE-UPDATE" /etc/crontabs/root
    else
        [[ -f "$SB_CRON_FILE" && ! -L "$SB_CRON_FILE" ]] &&
            grep -Fqx "# $SB_MARK CORE-UPDATE" "$SB_CRON_FILE"
    fi
}
cron_update_enable() {
    require_root || return 1
    require_debian_or_rhel || return 1
    state_is_owned || { err '请先安装受 s.sh 管理的 Reality 节点，再开启自动更新。'; return 1; }
    command -v sing-box >/dev/null 2>&1 || return 1
    command -v qrencode >/dev/null 2>&1 || warn '未找到 qrencode；节点二维码可能不可用。'
    install_manager_command || { err '安装管理命令失败，定时任务未写入。'; return 1; }
    local command='/bin/bash /usr/local/lib/s-reality/s.sh --cron-update'
    local entry="0 2 1 * * $command >> $SB_CRON_LOG 2>&1"
    if [[ "${PKG:-}" == apk ]]; then
        local root_file='/etc/crontabs/root' tmp=''
        mkdir -p /etc/crontabs || return 1
        tmp="$(mktemp /tmp/s-reality-cron.XXXXXX)" || return 1
        if [[ -f "$root_file" ]]; then
            grep -vF "$SB_MARK CORE-UPDATE" "$root_file" | grep -vF "$command" > "$tmp" || true
        fi
        printf '# %s CORE-UPDATE\n%s\n' "$SB_MARK" "$entry" >> "$tmp"
        cat "$tmp" > "$root_file" || { rm -f "$tmp"; return 1; }
        rm -f "$tmp"
        chmod 600 "$root_file"
        rc-update add crond default >/dev/null 2>&1 || true
        if ! rc-service crond status >/dev/null 2>&1; then
            rc-service crond start >/dev/null 2>&1 || {
                err '定时任务已写入，但 crond 服务无法启动。'; return 1;
            }
        fi
    else
        mkdir -p "$(dirname "$SB_CRON_FILE")" || return 1
        if [[ -e "$SB_CRON_FILE" || -L "$SB_CRON_FILE" ]]; then
            [[ -f "$SB_CRON_FILE" && ! -L "$SB_CRON_FILE" ]] &&
                grep -Fqx "# $SB_MARK CORE-UPDATE" "$SB_CRON_FILE" || {
                err "已有其他定时任务文件占用 $SB_CRON_FILE；拒绝覆盖。"; return 1;
            }
        fi
        local tmp=''
        tmp="$(mktemp "$(dirname "$SB_CRON_FILE")/.s-reality-cron.XXXXXX")" || return 1
        printf '# %s CORE-UPDATE\n' "$SB_MARK" > "$tmp"
        printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' >> "$tmp"
        printf '0 2 1 * * root %s >> %s 2>&1\n' "$command" "$SB_CRON_LOG" >> "$tmp"
        chmod 644 "$tmp"
        mv -f "$tmp" "$SB_CRON_FILE" || return 1
        systemctl enable --now cron >/dev/null 2>&1 ||
            systemctl enable --now crond >/dev/null 2>&1 || {
                err '定时任务已写入，但 cron/crond 服务无法启动，请检查。'; return 1;
            }
    fi
    ok "已安装定时更新：每月 1 日 02:00（VPS 本地时间：$(date +%Z)），更新 Sing-box 内核。"
    printf '记录日志：%s\n' "$SB_CRON_LOG"
}
cron_update_remove() {
    require_root || return 1
    require_debian_or_rhel || return 1
    if [[ "${PKG:-}" == apk ]]; then
        local root_file='/etc/crontabs/root' tmp=''
        [[ -f "$root_file" ]] || { info '未安装定时更新任务。'; return 0; }
        tmp="$(mktemp /tmp/s-reality-cron-remove.XXXXXX)" || return 1
        awk -v marker="# $SB_MARK CORE-UPDATE" -v cmd='/usr/local/lib/s-reality/s.sh --cron-update' \
            '$0 != marker && index($0,cmd) == 0' "$root_file" > "$tmp" || { rm -f "$tmp"; return 1; }
        cat "$tmp" > "$root_file" || { rm -f "$tmp"; return 1; }
        rm -f "$tmp"
        chmod 600 "$root_file"
    else
        if [[ -f "$SB_CRON_FILE" && ! -L "$SB_CRON_FILE" ]] &&
           grep -Fqx "# $SB_MARK CORE-UPDATE" "$SB_CRON_FILE"; then
            rm -f "$SB_CRON_FILE" || return 1
        elif [[ -e "$SB_CRON_FILE" || -L "$SB_CRON_FILE" ]]; then
            err '定时任务文件无管理标记，拒绝删除。'; return 1
        fi
    fi
    ok '已取消每月自动更新 Sing-box 内核的定时任务。'
}
cron_update_status() {
    if cron_update_installed; then ok '定时更新：已开启（每月 1 日 02:00，VPS 本地时间）'
    else info '定时更新：未开启'; fi
    echo "日志文件：$SB_CRON_LOG"
}
update_menu() {
    local selection=''
    while :; do
        echo
        echo '======= Sing-box 内核更新管理 ======='
        echo '1) 手动更新内核（备份、检查、失败回滚）'
        echo '2) 安装定时更新（每月 1 日 02:00）'
        echo '3) 取消定时更新'
        echo '0) 返回'
        cron_update_status
        read_tty '请选择 [0-3]: ' selection || return 1
        case "$selection" in
            1) safe_update || warn '内核更新失败或已回滚。' ;;
            2) cron_update_enable || warn '定时任务安装失败。' ;;
            3) cron_update_remove || warn '定时任务取消失败。' ;;
            0) return 0 ;;
            *) warn '无效选项。' ;;
        esac
    done
}

rollback_snapshot() {
    require_root || return 1
    require_debian_or_rhel || return 1
    local path='' unit='' binary='' answer=''
    echo 'Available snapshot folders:'
    ls -1dt "$SB_BACKUPS"/* 2>/dev/null | head -n 15 || true
    read_tty 'Absolute snapshot folder to restore (blank to cancel): ' path || return 1
    [[ -n "$path" && "$path" == "$SB_BACKUPS"/* && -f "$path/manifest.txt" ]] || { err 'Invalid snapshot folder'; return 1; }
    read_tty '确认恢复该备份？(y/N): ' answer || return 1
    is_yes "$answer" || return 0
    create_snapshot before-manual-rollback || return 1
    service_stop >/dev/null 2>&1 || true
    [[ -s "$path/config.json" ]] && cp -a "$path/config.json" "$SB_CONF"
    [[ -s "$path/.s_reality_state.json" ]] && cp -a "$path/.s_reality_state.json" "$SB_STATE"
    if [[ -s "$path/sing-box-bin" ]]; then
        restore_core_binary "$path/sing-box-bin" "$(command -v sing-box)" || warn '核心文件恢复失败。'
    fi
    if [[ -s "$path/fallback.conf" && -s "$SB_STATE" ]]; then
        local restore_fb=''
        restore_fb="$(jq -r '.fallback_conf // ""' "$SB_STATE" 2>/dev/null || true)"
        if [[ "$restore_fb" == "$NGINX_DIR"/s-reality-fallback-*.conf ]] &&
           [[ ! -e "$restore_fb" || ( -f "$restore_fb" && ! -L "$restore_fb" && "$(head -n1 "$restore_fb")" == "# $SB_MARK" ) ]]; then
            cp -a "$path/fallback.conf" "$restore_fb" || true
            nginx_reload_or_start >/dev/null 2>&1 || warn 'Nginx fallback restore needs manual inspection.'
        fi
    fi
    unit="$(service_unit_file)"
    [[ -s "$path/service-unit" ]] && cp -a "$path/service-unit" "$unit"
    if [[ "${PKG:-}" != apk ]]; then systemctl daemon-reload || true; fi
    if sing-box check -c "$SB_CONF" && service_start && service_active; then
        ok 'Snapshot restored. If domain/fallback changed, inspect your Nginx bridge.'
        return 0
    fi
    err 'Snapshot core/config could not start. Current snapshot remains in backups.'
    return 1
}
maintenance_menu() {
    local choice=''
    while :; do
        echo
        echo 'Sing-box safe maintenance (same menu position as xpro.sh option 12)'
        echo '1) Upgrade core with snapshot and automatic rollback'
        echo '2) Create a manual snapshot'
        echo '3) Restore a saved snapshot'
        echo '4) Show available snapshots'
        echo '0) Back'
        read_tty 'Choose [0-4]: ' choice || return 1
        case "$choice" in
            1) safe_update || true ;;
            2) create_snapshot manual || true ;;
            3) rollback_snapshot || true ;;
            4) ls -1dt "$SB_BACKUPS"/* 2>/dev/null | head -n 30 || true ;;
            0) return 0 ;;
            *) warn 'Invalid choice.' ;;
        esac
    done
}

# Stop only a verified sing-box unit. Failure must not be followed by
# deleting its live config, which could leave an unmanageable running process.
stop_for_uninstall() {
    local unit
    unit="$(service_unit_file)"
    if [[ -e "$unit" || -L "$unit" ]]; then
        if ! unit_is_owned && ! legacy_unit_matches; then
            err "sing-box service unit is not recognized; refusing to stop it: $unit"
            return 1
        fi
    elif service_active; then
        err 'sing-box is active but its service unit could not be verified. Nothing removed.'
        return 1
    fi
    if service_active; then
        service_stop || { err 'sing-box service could not be stopped. Nothing removed.'; return 1; }
    fi
    if service_active; then
        err 'sing-box is still running; refusing to delete its configuration.'
        return 1
    fi
    if [[ "${PKG:-}" == apk ]]; then
        rc-update del "$SB_SERVICE" default >/dev/null 2>&1 || true
    elif [[ -e "$unit" || -L "$unit" ]]; then
        systemctl disable "$SB_SERVICE" >/dev/null 2>&1 || {
            err 'Failed to disable sing-box at boot; config has been preserved.'
            return 1
        }
    fi
}
remove_recognized_unit() {
    local unit
    unit="$(service_unit_file)"
    if unit_is_owned || legacy_unit_matches; then
        rm -f "$unit" || return 1
        if [[ "${PKG:-}" != apk ]]; then systemctl daemon-reload || return 1; fi
    fi
}
remove_manager_shortcuts() {
    if [[ -L "$SB_ALIAS" && "$(readlink "$SB_ALIAS")" == "$SB_INSTALL_COPY" ]]; then
        rm -f "$SB_ALIAS"
    elif legacy_sb_command; then
        rm -f "$SB_ALIAS"
    fi
    if [[ -L /usr/local/bin/sreality && "$(readlink /usr/local/bin/sreality)" == "$SB_INSTALL_COPY" ]]; then
        rm -f /usr/local/bin/sreality
    fi
    if [[ -f "$SB_INSTALL_COPY" ]] && grep -Fq "$SB_MARK" "$SB_INSTALL_COPY"; then
        rm -f "$SB_INSTALL_COPY"
    fi
}
remove_orphan_managed_nginx() {
    local file
    for file in "$NGINX_DIR"/s-reality-fallback-*.conf "$NGINX_DIR"/s-reality-acme-*.conf; do
        [[ -f "$file" && ! -L "$file" ]] || continue
        if grep -Fqx "# $SB_MARK" "$file"; then
            safe_remove_nginx_owned "$file" || warn "Managed Nginx file needs manual cleanup: $file"
        fi
    done
}
uninstall_legacy_reality() {
    local unit='' types=''
    # Supports the ORIGINAL s.sh even when it was never migrated. Also
    # handles a damaged newer installation that lost its state file.
    if ! legacy_install_detected && ! unit_is_owned; then
        err '未检测到旧版 s.sh 安装标记；为保护其他 Sing-box 服务，拒绝强制卸载。'
        err '如需排查，请检查 /etc/sing-box/config.json、.protocols、.config_cache 和 sing-box.service。'
        return 1
    fi
    if [[ -s "$SB_CONF" ]]; then
        types="$(jq -r '[.inbounds[]?.type] | unique | join(", ")' "$SB_CONF" 2>/dev/null || true)"
    fi
    warn "发现旧版 s.sh / 缺少状态文件的 Reality 安装。协议：${types:-unknown}"
    warn '将停用 sing-box 服务，并移除旧版节点配置、缓存和可识别的旧 sb 命令。'
    warn '不会修改 Xray / 3X-UI / S-UI / 任何原有 Nginx 站点或网站证书。'
    warn 'sing-box 软件包本身将保留，便于从菜单 1 重新安装；旧凭据会先行备份。'
    # Explicit verification before both snapshot and service change.
    unit="$(service_unit_file)"
    if [[ -e "$unit" || -L "$unit" ]] && ! unit_is_owned && ! legacy_unit_matches; then
        err "无法确认该 sing-box 服务属于旧 s.sh：$unit。已中止。"
        return 1
    fi
    create_snapshot before-legacy-uninstall || return 1
    snapshot_legacy_artifacts || { err '旧版配置备份失败，拒绝卸载。'; return 1; }
    [[ -s "$SB_CONF" && ! -s "$SNAPSHOT/config.json" ]] && { err '原配置备份不完整，拒绝卸载。'; return 1; }
    stop_for_uninstall || return 1
    remove_recognized_unit || { err '卸载服务文件失败，旧配置仍保留供恢复。'; return 1; }
    # ONLY known old s.sh-generated files. Keep /etc/sing-box itself,
    # backups, certs and any unknown extra files untouched.
    rm -f "$SB_CONF" "$SB_STATE" "$SB_URI"         "$SB_DIR/.protocols" "$SB_DIR/.config_cache"         "$SB_DIR/.reality_pub" "$SB_DIR/.reality_sid"         "$SB_DIR/relay_uri.txt" || return 1
    # Orphan bridges may exist after an interrupted migration; marker check.
    remove_orphan_managed_nginx
    cron_update_remove || warn '未能删除全部内核定时任务，请手动检查。'
    remove_manager_shortcuts
    if [[ -f /root/node_names.txt ]] && [[ -s "$SNAPSHOT/legacy-files/node_names.txt" ]]; then
        # This filename belongs to original s.sh; leave it if a different
        # service/script also references it rather than risk deleting user data.
        info '已保留 /root/node_names.txt（旧节点名文件）。'
    fi
    if service_active; then
        warn 'sing-box unexpectedly restarted. Inspect the service; configuration backup is safe.'
        return 1
    fi
    ok '旧版 s.sh Sing-box 已卸载；现在可以选择菜单 1 重新安装 Reality 443 + HTTPS 回落。'
    printf '原配置及密钥备份目录：%s\n' "$SNAPSHOT"
    info '保留 sing-box 核心程序、旧证书和快照；未触碰 Nginx 网站及 Xray。'
}
uninstall_managed_reality() {
    load_state || { err '新版管理状态文件无效。可使用菜单 2 的旧版清理路径排查。'; return 1; }
    local conf="$FALLBACK_CONF" acme="${ACME_CONF:-}" unit='' backup_dir=''
    warn '卸载后 Reality 443 将停止对外服务，网站的 443 回落也会停止。'
    warn '原 Nginx 站点、Xray、3X-UI、S-UI 和公用证书不会被修改。'
    create_snapshot before-uninstall || return 1
    backup_dir="$SNAPSHOT"
    stop_for_uninstall || return 1
    remove_recognized_unit || { err '无法移除服务文件；已保留配置供恢复。'; return 1; }
    if [[ -f "$conf" ]]; then safe_remove_nginx_owned "$conf" || true; fi
    if [[ -n "$acme" && -f "$acme" ]]; then safe_remove_nginx_owned "$acme" || true; fi
    remove_orphan_managed_nginx
    rm -f "$SB_CONF" "$SB_STATE" "$SB_URI" || return 1
    cron_update_remove || warn '未能删除全部内核定时任务，请手动检查。'
    remove_manager_shortcuts
    # Never restore a legacy service silently after uninstall.
    ok '新版 s.sh Reality 已卸载。原网站和证书保留。'
    printf '卸载前备份目录：%s\n' "$backup_dir"
}
uninstall_reality() {
    require_root || return 1
    require_debian_or_rhel || return 1
    if state_is_owned; then
        uninstall_managed_reality
    else
        uninstall_legacy_reality
    fi
}

system_settings() {
    local answer='' tmp=''
    warn 'This option runs the same external sys_conf.sh workflow used by xpro.sh.'
    read_tty 'Download and execute sys_conf.sh from the byilrq/vps repository? (y/N): ' answer || return 1
    [[ "$answer" == y || "$answer" == Y ]] || return 0
    tmp="$(mktemp /tmp/sys-conf.XXXXXX)" || return 1
    curl -fsSL --retry 2 --connect-timeout 10 'https://raw.githubusercontent.com/byilrq/vps/main/sys_conf.sh' -o "$tmp" || { rm -f "$tmp"; return 1; }
    bash "$tmp"; local rc=$?
    rm -f "$tmp"
    return "$rc"
}
route_test() {
    local answer=''
    warn 'Runs a third-party route diagnostic tool, downloaded at execution time.'
    read_tty 'Run besttrace from git.io/besttrace? (y/N): ' answer || return 1
    [[ "$answer" == y || "$answer" == Y ]] || return 0
    local tmp
    tmp="$(mktemp /tmp/s-besttrace.XXXXXX)" || return 1
    curl -fsSL --max-time 30 'https://git.io/besttrace' -o "$tmp" || { rm -f "$tmp"; return 1; }
    bash "$tmp"; local rc=$?
    rm -f "$tmp"
    return "$rc"
}
ip_quality() {
    local answer=''
    warn 'Runs a third-party IP-quality diagnostic tool (Check.Place).'
    read_tty 'Download and run the Check.Place IP check? (y/N): ' answer || return 1
    [[ "$answer" == y || "$answer" == Y ]] || return 0
    local tmp
    tmp="$(mktemp /tmp/s-ip-check.XXXXXX)" || return 1
    curl -fsSL --max-time 30 'https://Check.Place' -o "$tmp" || { rm -f "$tmp"; return 1; }
    bash "$tmp" -I; local rc=$?
    rm -f "$tmp"
    return "$rc"
}
system_query() {
    echo
    echo 'System information'
    printf 'Hostname:    %s\n' "$(hostname 2>/dev/null || true)"
    printf 'OS:          %s\n' "$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
    printf 'Kernel:      %s\n' "$(uname -r)"
    printf 'CPU:         %s\n' "$(awk -F': ' '/model name/{print $2;exit}' /proc/cpuinfo)"
    printf 'Cores:       %s\n' "$(nproc 2>/dev/null || echo unknown)"
    printf 'RAM:         %s\n' "$(free -h 2>/dev/null | awk '/^Mem:/{print $3"/"$2}')"
    printf 'Disk:        %s\n' "$(df -hP / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    printf 'Uptime:      %s\n' "$(uptime -p 2>/dev/null || true)"
    printf 'Public IPv4: %s\n' "$(get_public_ip || true)"
    printf 'Local time:  %s\n' "$(date -Is)"
    printf 'TCP CC:      %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    printf 'Qdisc:       %s\n' "$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
    if command -v sing-box >/dev/null 2>&1; then printf 'Sing-box:    %s\n' "$(sing-box version | head -n1)"; fi
}
install_manager_command() {
    mkdir -p "$(dirname "$SB_INSTALL_COPY")" || return 1
    local own_path=''
    own_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
    [[ -n "$own_path" && -f "$own_path" ]] || return 1
    if [[ "$own_path" != "$SB_INSTALL_COPY" ]]; then
        cp -f "$own_path" "$SB_INSTALL_COPY" || return 1
    fi
    chmod 755 "$SB_INSTALL_COPY"
    local secondary="/usr/local/bin/sreality"
    if [[ ! -e "$secondary" && ! -L "$secondary" ]]; then
        ln -s "$SB_INSTALL_COPY" "$secondary"
    fi
    if [[ ! -e "$SB_ALIAS" && ! -L "$SB_ALIAS" ]]; then
        ln -s "$SB_INSTALL_COPY" "$SB_ALIAS"
        ok 'Management command installed: sb'
    elif [[ -L "$SB_ALIAS" && "$(readlink "$SB_ALIAS")" == "$SB_INSTALL_COPY" ]]; then
        ok 'Management command available: sb'
    else
        warn "Command $SB_ALIAS is owned by another tool; use sreality or $SB_INSTALL_COPY instead."
    fi
}

show_menu() {
    local dim="\033[2m"
        echo -e "${cyan}${bold}╔══════════════════════════════════════════════╗${none}"
        echo -e "${cyan}${bold}║                sing-box Reality 管理界面             ║${none}"
        echo -e "${cyan}${bold}╚══════════════════════════════════════════════╝${none}"
        echo -e "${gray}--------------------------------------------------${none}"
        echo -e " ${blue}${bold}1)${none} ${blue}安装${none}"
        echo -e " ${red}${bold}2)${none} ${red}卸载${none}"
        echo -e "${gray}--------------------------------------------------${none}"
        echo -e " ${yellow}${bold}3)${none} ${yellow}更新 Sing-box 内核/定时任务${none}"
        echo -e " ${yellow}${bold}4)${none} ${yellow}查看状态${none}"
        echo -e " ${yellow}${bold}5)${none} ${yellow}打印节点信息${none}"
        echo -e " ${yellow}${bold}6)${none} ${yellow}目标网站检测${none}"
        echo -e " ${yellow}${bold}7)${none} ${yellow}系统参数配置${none}"
        echo -e " ${yellow}${bold}8)${none} ${yellow}回程路由测试${none}"
        echo -e " ${yellow}${bold}9)${none} ${yellow}IP质量检测${none}"
        echo -e " ${yellow}${bold}10)${none} ${yellow}系统查询${none}"
		echo -e " ${green}${bold}11)${none} ${green}更新域名/SNI${none}"   # 新增行
        echo -e " ${green}${bold}12)${none} ${green}安全升级 sing-box（备份+回滚）${none}"
        echo -e " ${red}${bold}0)${none} 退出"
        echo -e "${gray}--------------------------------------------------${none}"
        echo -e "${dim}${gray}提示：输入数字后回车${none}"
        echo -ne "${green}${bold}请选择 [0-12]${none}${green}: ${none}"
}
main() {
    require_root || return 1
    local choice=''
    if [[ "${1:-}" == --check ]]; then
        command -v sing-box >/dev/null 2>&1 && sing-box check -c "$SB_CONF" || return 1
        load_state && verify_tls "$FALLBACK_PORT" "$DOMAIN" || return 1
        authenticated_probe
        return $?
    fi
    if [[ "${1:-}" == --status ]]; then show_status; return $?; fi
    if [[ "${1:-}" == --cron-update ]]; then
        [[ -f "$SB_STATE" ]] && state_is_owned || { err '定时更新跳过：未找到有效受管理节点。'; return 1; }
        info "$(date -Is) 每月 Sing-box 内核维护开始"
        safe_update
        return $?
    fi
    while :; do
        show_menu
        read_tty '' choice || return 0
        case "$choice" in
            1) install_reality || warn 'Install action failed; review messages above.' ;;
            2) uninstall_reality || warn 'Uninstall action cancelled or failed.' ;;
            3) update_menu || true ;;
            4) show_status || true ;;
            5) print_node_info || true ;;
            6) website_test || true ;;
            7) system_settings || true ;;
            8) route_test || true ;;
            9) ip_quality || true ;;
            10) system_query || true ;;
            11) update_domain_sni || warn 'Domain update failed.' ;;
            12) maintenance_menu || true ;;
            0) return 0 ;;
            *) warn 'Invalid selection.' ;;
        esac
        pause
    done
}


if [[ "${SB_LIBRARY_MODE:-0}" != 1 ]]; then main "$@"; fi
