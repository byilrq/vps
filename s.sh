#!/usr/bin/env bash
# s.sh - standalone sing-box deployment/management (no S-UI, no web panel).
# Revised from the user's s(9).sh: SS, HY2, VLESS REALITY; independent protocol submenus.
# Protocol removal edits only the named sing-box inbound, not other services.
# Kernel updates preserve configs; full uninstall removes ALL protocols and credentials.
# User Nginx sites, global TLS certificates and other panels are never uninstalled.
set -Eeuo pipefail
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

CONFIG=/etc/sing-box/config.json
META=/etc/sing-box/.s-script-meta.json
BACKUPS=/etc/sing-box/backups
OWN_BRIDGE_MARKER='# S_SH_MANAGED_TLS_BRIDGE_V2'

say() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; return 1; }
require_root() { [[ $EUID -eq 0 ]] || { fail 'Run as root: sudo bash s.sh'; exit 1; }; }
command_ok() { command -v "$1" >/dev/null 2>&1; }

ask() {
    local __var="$1" prompt="$2" default="${3:-}" value=''
    if [[ -t 0 ]]; then
        IFS= read -e -r -p "$prompt" value || return 1
    else
        IFS= read -r -p "$prompt" value || return 1
    fi
    printf -v "$__var" '%s' "${value:-$default}"
}
confirm() {
    local answer=''
    ask answer "$1 [y/N]: " '' || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
}
port_valid() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
domain_valid() {
    local d="$1"
    [[ ${#d} -le 253 && "$d" == *.* && "$d" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ && "$d" != *..* && "$d" != *--* ]]
}
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
base64one() { printf '%s' "$1" | base64 | tr -d '\r\n'; }

os_kind() {
    local id='' like=''
    if [[ -f /etc/os-release ]]; then
        # os-release values are shell-quoted strings, not user input.
        . /etc/os-release
        id="${ID:-}"; like="${ID_LIKE:-}"
    fi
    case " $id $like " in
        *alpine*) printf alpine ;;
        *debian*|*ubuntu*) printf debian ;;
        *rhel*|*fedora*|*centos*) printf redhat ;;
        *) printf unknown ;;
    esac
}
service_active() {
    if command_ok systemctl; then systemctl is-active --quiet sing-box
    elif command_ok rc-service; then rc-service sing-box status >/dev/null 2>&1
    else return 1; fi
}
service_start() {
    if command_ok systemctl; then systemctl start sing-box
    else rc-service sing-box start; fi
}
service_restart() {
    if command_ok systemctl; then systemctl restart sing-box
    else rc-service sing-box restart; fi
}
service_stop() {
    if command_ok systemctl; then systemctl stop sing-box
    else rc-service sing-box stop; fi
}
service_enable() {
    if command_ok systemctl; then systemctl enable sing-box >/dev/null
    else rc-update add sing-box default >/dev/null; fi
}
service_disable() {
    if command_ok systemctl; then systemctl disable sing-box >/dev/null 2>&1 || true
    else rc-update del sing-box default >/dev/null 2>&1 || true; fi
}
service_exists() {
    if command_ok systemctl; then
        systemctl cat sing-box >/dev/null 2>&1
    else
        [[ -e /etc/init.d/sing-box ]]
    fi
}

install_deps() {
    require_root
    local os; os="$(os_kind)"
    say 'Installing system utilities: curl, jq, openssl, qrencode, certbot, iproute2...'
    case "$os" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -q && apt-get install -y --no-install-recommends \
                curl ca-certificates openssl jq qrencode certbot iproute2 \
                python3 socat >/dev/null
            ;;
        alpine)
            apk update && apk add --no-cache bash curl ca-certificates openssl jq \
                qrencode certbot iproute2 python3 socat
            ;;
        redhat)
            local pm=dnf
            command_ok dnf || pm=yum
            "$pm" install -y curl ca-certificates openssl jq qrencode \
                certbot iproute python3 socat
            ;;
        *) fail 'Unsupported OS for automated dependencies; install jq, curl, openssl, certbot, qrencode, iproute2 manually.'; return 1 ;;
    esac
    say 'Dependencies ready. No Nginx/firewall configuration was changed.'
}
ensure_tools() {
    local c
    for c in jq openssl curl base64; do
        if ! command_ok "$c"; then fail "Missing $c. Run menu 1 first."; return 1; fi
    done
}
ensure_singbox() {
    require_root
    if command_ok sing-box; then return 0; fi
    say 'sing-box is missing; installing its official standalone core (not S-UI).'
    local os; os="$(os_kind)"
    if [[ "$os" == alpine ]]; then
        apk add --no-cache sing-box
    else
        local installer
        installer="$(mktemp /tmp/s-script-install.XXXXXXXX)" || return 1
        if ! curl -fL --retry 2 --connect-timeout 12 --max-time 50 \
             https://sing-box.app/install.sh -o "$installer"; then
            rm -f "$installer"; return 1
        fi
        bash "$installer" || { rm -f "$installer"; return 1; }
        rm -f "$installer"
    fi
    command_ok sing-box || fail 'sing-box executable was not installed'
}

ensure_state() {
    require_root
    mkdir -p /etc/sing-box "$BACKUPS"
    chmod 700 "$BACKUPS"
    if [[ ! -e "$CONFIG" ]]; then
        printf '%s\n' '{"log":{"level":"info","timestamp":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct-out"}]}' > "$CONFIG"
        chmod 600 "$CONFIG"
    fi
    jq -e 'type=="object" and (.inbounds|type=="array") and (.outbounds|type=="array")' "$CONFIG" >/dev/null || fail "Existing config is invalid: $CONFIG"
    if [[ ! -e "$META" ]]; then
        printf '%s\n' '{"connect_host":"","cert_domain":"","cert_file":"","key_file":"","hy2_insecure":false,"node_name":"","reality":{}}' > "$META"
        chmod 600 "$META"
    fi
    jq -e 'type=="object"' "$META" >/dev/null || fail "Existing state is invalid: $META"
}

get_meta() { [[ -f "$META" ]] && jq -r "$1 // empty" "$META" 2>/dev/null || true; }
set_meta() {
    local expr="$1" tmp
    tmp="$(mktemp /etc/sing-box/.meta.XXXXXX)" || return 1
    if ! jq "$expr" "$META" > "$tmp"; then rm -f "$tmp"; return 1; fi
    chmod 600 "$tmp"; mv -f "$tmp" "$META"
}
set_meta_values() {
    local tmp
    tmp="$(mktemp /etc/sing-box/.meta.XXXXXX)" || return 1
    if ! jq "$@" "$META" > "$tmp"; then rm -f "$tmp"; return 1; fi
    chmod 600 "$tmp"; mv -f "$tmp" "$META"
}
get_public_ip() {
    local ip=''
    ip="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$ip"; return 0
    fi
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -nE 's/.* src ([0-9.]+).*/\1/p' | head -n1 || true)"
    [[ -n "$ip" ]] && { printf '%s' "$ip"; return 0; }
    return 1
}
select_host() {
    local saved default picked
    saved="$(get_meta '.connect_host')"
    # Migrate only the legacy connection-address value, never source old cache.
    if [[ -z "$saved" && -f /etc/sing-box/.config_cache ]]; then
        saved="$(sed -n 's/^CUSTOM_IP=//p' /etc/sing-box/.config_cache | head -n 1)"
    fi
    default="${saved:-$(get_public_ip || true)}"
    ask picked "客户端连接地址（IP / DDNS）[${default:-required}]: " "$default" || return 1
    [[ -n "$picked" && "$picked" =~ ^([a-zA-Z0-9.-]+|[a-fA-F0-9:]+|\[[a-fA-F0-9:]+\])$ ]] || fail 'Invalid client address' 
    CONNECT_HOST="$picked"
    set_meta_values --arg h "$picked" '.connect_host=$h'
}

listener_lines() {
    local proto="$1" port="$2"
    if ! command_ok ss; then fail 'ss command unavailable (install iproute2)'; return 2; fi
    if [[ "$proto" == tcp ]]; then
        ss -H -ltnp "( sport = :${port} )" 2>/dev/null || true
    else
        ss -H -lunp "( sport = :${port} )" 2>/dev/null || true
    fi
}
# Disjoint transports can share the number 443: HY2 UDP and Reality TCP.
check_port_available() {
    local proto="$1" port="$2" skip_tag="$3" collisions='' lines=''
    port_valid "$port" || { fail "Invalid port: $port"; return 1; }
    if [[ -f "$CONFIG" ]]; then
        collisions="$(jq -r --argjson p "$port" --arg tag "$skip_tag" --arg proto "$proto" '
          .inbounds[]? | select(.tag != $tag and .listen_port==$p) |
          select(if .type=="hysteria2" or .type=="tuic" then $proto=="udp"
                 elif .type=="vless" or .type=="trojan" then $proto=="tcp"
                 else true end) | (.tag // .type)
        ' "$CONFIG")"
        [[ -z "$collisions" ]] || { fail "$proto/$port already used by config inbound(s): $collisions"; return 1; }
    fi
    lines="$(listener_lines "$proto" "$port")" || return 1
    if [[ -n "$lines" ]] && grep -qv 'sing-box' <<< "$lines"; then
        fail "$proto/$port is occupied by another process (not stopping it):"
        printf '%s\n' "$lines" >&2
        return 1
    fi
    return 0
}
validate_free_port() {
    local proto="$1" answer="$2" tag="$3"
    check_port_available "$proto" "$answer" "$tag"
}

cert_valid() {
    local d="$1" cert="$2" key="$3"
    [[ -s "$cert" && -s "$key" ]] || return 1
    openssl x509 -checkend 86400 -noout -in "$cert" >/dev/null 2>&1 || return 1
    openssl x509 -checkhost "$d" -noout -in "$cert" 2>/dev/null | grep -qi 'does match' || return 1
    local a b
    a="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    b="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    [[ -n "$a" && "$a" == "$b" ]]
}
find_cert_for_domain() {
    local d="$1" base cert key
    for base in "/etc/letsencrypt/live/$d" /etc/letsencrypt/live/"$d"-*; do
        [[ -d "$base" ]] || continue
        cert="$base/fullchain.pem"; key="$base/privkey.pem"
        if cert_valid "$d" "$cert" "$key"; then
            CERT_FILE="$cert"; KEY_FILE="$key"; CERT_INSECURE=false
            return 0
        fi
    done
    if [[ -f "/etc/sing-box/certs/$d/fullchain.pem" ]]; then
        cert="/etc/sing-box/certs/$d/fullchain.pem"
        key="/etc/sing-box/certs/$d/privkey.pem"
        if cert_valid "$d" "$cert" "$key"; then
            CERT_FILE="$cert"; KEY_FILE="$key"
            CERT_INSECURE="$(get_meta '.hy2_insecure')"
            [[ "$CERT_INSECURE" == true ]] || CERT_INSECURE=false
            return 0
        fi
    fi
    return 1
}
cert_acme() {
    local d="$1" mode="$2" webroot=''
    command_ok certbot || { fail 'certbot is not installed; use menu 1'; return 1; }
    if [[ "$mode" == standalone ]]; then
        local listeners
        listeners="$(listener_lines tcp 80)" || return 1
        if [[ -n "$listeners" ]]; then
            fail 'TCP/80 is occupied. Standalone ACME will not stop the existing server.'; return 1
        fi
        certbot certonly --standalone --preferred-challenges http \
            --non-interactive --agree-tos --register-unsafely-without-email -d "$d"
    elif [[ "$mode" == webroot ]]; then
        ask webroot '现有 80 端口网站的 ACME webroot 路径：' '' || return 1
        [[ -d "$webroot" && "$webroot" == /* ]] || { fail 'Webroot does not exist'; return 1; }
        say "The existing domain must already serve $webroot/.well-known/acme-challenge/ on port 80."
        certbot certonly --webroot -w "$webroot" \
            --non-interactive --agree-tos --register-unsafely-without-email -d "$d"
    else
        fail 'Unknown ACME mode'; return 1
    fi
}
cert_selfsigned() {
    local d="$1" certdir="/etc/sing-box/certs/$d"
    mkdir -p "$certdir"
    chmod 700 "$certdir"
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -subj "/CN=$d" -addext "subjectAltName=DNS:$d" \
        -keyout "$certdir/privkey.pem" -out "$certdir/fullchain.pem" >/dev/null 2>&1 || return 1
    chmod 600 "$certdir/privkey.pem"
    CERT_FILE="$certdir/fullchain.pem"; KEY_FILE="$certdir/privkey.pem"; CERT_INSECURE=true
}
prepare_domain_cert() {
    local d='' chosen='' mode=''
    ensure_state || return 1
    chosen="$(get_meta '.cert_domain')"
    ask d "TLS 证书域名 [${chosen:-example.org}]: " "$chosen" || return 1
    domain_valid "$d" || { fail "Invalid domain: $d"; return 1; }
    if find_cert_for_domain "$d"; then
        say "Reusing existing valid certificate: $CERT_FILE"
    else
        say "No valid certificate for $d."
        printf '%s\n' '1) ACME HTTP-01 独立签发（要求 TCP 80 空闲）' \
            '2) ACME webroot 验证（复用已有 80 网站，不修改站点）' \
            '3) 临时自签证书（客户端必须启用 insecure=1）' \
            '0) 取消'
        ask mode '请选择证书方式 [0]: ' 0 || return 1
        case "$mode" in
            1) cert_acme "$d" standalone || return 1; find_cert_for_domain "$d" || fail 'Issued certificate not found/valid' ;;
            2) cert_acme "$d" webroot || return 1; find_cert_for_domain "$d" || fail 'Issued certificate not found/valid' ;;
            3)
                confirm 'Self-signed is for testing only and weakens client certificate authentication. Continue?' || return 1
                cert_selfsigned "$d" || return 1 ;;
            *) return 1 ;;
        esac
    fi
    CERT_DOMAIN="$d"
    set_meta_values --arg d "$d" --arg c "$CERT_FILE" --arg k "$KEY_FILE" \
        --argjson insecure "$CERT_INSECURE" \
        '.cert_domain=$d | .cert_file=$c | .key_file=$k | .hy2_insecure=$insecure'
    say "Certificate ready for $d; private key path is kept local."
}

# Reuse a valid certificate already prepared by menu 1, without repeating
# certificate issuance/selection in every protocol installer.
ensure_shared_cert() {
    local d c k insecure
    ensure_state || return 1
    d="$(get_meta '.cert_domain')"
    c="$(get_meta '.cert_file')"
    k="$(get_meta '.key_file')"
    insecure="$(get_meta '.hy2_insecure')"
    if [[ -n "$d" && -n "$c" && -n "$k" ]] && cert_valid "$d" "$c" "$k"; then
        CERT_DOMAIN="$d"
        CERT_FILE="$c"
        KEY_FILE="$k"
        CERT_INSECURE=false
        [[ "$insecure" == true ]] && CERT_INSECURE=true
        say "复用菜单 1 中准备的证书：$CERT_DOMAIN"
        return 0
    fi
    say '共享证书尚未准备或已失效，进入菜单 1 的通用证书处理流程。'
    prepare_domain_cert
}

service_setup() {
    # Reuse already-installed system service when possible. Never overwrite an unrelated unit.
    if service_exists; then
        # Refuse to manage a different sing-box instance bound to another config.
        if command_ok systemctl; then
            local unit
            unit="$(systemctl cat sing-box 2>/dev/null || true)"
            if [[ "$unit" != *'/etc/sing-box'* && "$unit" != *"$CONFIG"* ]]; then
                fail 'Existing sing-box service does not reference /etc/sing-box. It is not managed by s.sh.'
                return 1
            fi
        fi
        return 0
    fi
    local bin
    bin="$(command -v sing-box)" || return 1
    if command_ok systemctl; then
        cat > /etc/systemd/system/sing-box.service <<EOF
# S_SH_MANAGED_SINGBOX_SERVICE_V2
[Unit]
Description=sing-box standalone proxy (s.sh)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=$bin run -c $CONFIG
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    elif command_ok rc-service; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
# S_SH_MANAGED_SINGBOX_SERVICE_V2
name="sing-box"
command="$bin"
command_args="run -c $CONFIG"
command_background="yes"
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-delay 5"
depend() { need net; }
EOF
        chmod 700 /etc/init.d/sing-box
    else
        fail 'Systemd/OpenRC unavailable; cannot create a service'
    fi
}

# Build candidate with one named inbound replaced; all other inbounds are preserved.
apply_inbound() {
    local tag="$1" newfile="$2" temp='' snap='' meta_snap='' active_before=false
    ensure_state || return 1
    temp="$(mktemp /etc/sing-box/.candidate.XXXXXX.json)" || return 1
    snap="$(mktemp "$BACKUPS"/.config.pre.XXXXXX)" || return 1
    meta_snap="$(mktemp "$BACKUPS"/.meta.pre.XXXXXX)" || return 1
    cp -a "$CONFIG" "$snap"; cp -a "$META" "$meta_snap"
    service_active && active_before=true
    if ! jq --arg tag "$tag" --slurpfile node "$newfile" '
        .inbounds = ([.inbounds[] | select(.tag != $tag)] + [$node[0]])
      ' "$CONFIG" > "$temp"; then
        rm -f "$temp"; return 1
    fi
    if ! sing-box check -c "$temp"; then
        fail 'sing-box rejected candidate config. Original config and active service are unchanged.' || true
        rm -f "$temp"; return 1
    fi
    chmod 600 "$temp"
    mv -f "$temp" "$CONFIG"
    if ! service_setup || ! service_enable || ! service_restart || ! service_active; then
        warn 'Service failed; restoring the previous config and metadata.'
        cp -a "$snap" "$CONFIG"; cp -a "$meta_snap" "$META"
        if $active_before; then service_restart || true; else service_stop || true; fi
        return 1
    fi
    # Verify that the live daemon actually owns the newly installed listener.
    local expected_port expected_proto listeners
    expected_port="$(jq -r '.listen_port' "$newfile")"
    expected_proto="$(jq -r 'if .type=="hysteria2" or .type=="tuic" then "udp" else "tcp" end' "$newfile")"
    listeners="$(listener_lines "$expected_proto" "$expected_port" 2>/dev/null || true)"
    if [[ -z "$listeners" || "$listeners" != *'sing-box'* ]]; then
        warn "The sing-box service started, but $expected_proto/$expected_port is not owned by sing-box. Rolling back."
        cp -a "$snap" "$CONFIG"; cp -a "$meta_snap" "$META"
        if $active_before; then service_restart || true; else service_stop || true; fi
        return 1
    fi
    # Keep timestamped safety backup for manual restore, without storing secrets in /tmp.
    local when; when="$(date +%Y%m%d_%H%M%S)"
    cp -a "$snap" "$BACKUPS/config.before-${tag}-${when}.json"
    cp -a "$meta_snap" "$BACKUPS/meta.before-${tag}-${when}.json"
    rm -f "$snap" "$meta_snap"
    say 'Configuration checked, saved atomically and service restarted.'
}

make_node_file() { mktemp /etc/sing-box/.inbound.XXXXXXXX; }
random_port() {
    local n i
    for i in $(seq 1 80); do
        n="$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
        n=$(( 12000 + n % 48000 ))
        if check_port_available tcp "$n" no-tag >/dev/null 2>&1 && \
           check_port_available udp "$n" no-tag >/dev/null 2>&1; then
            printf '%s' "$n"; return 0
        fi
    done
    return 1
}

add_ss() {
    ensure_tools || return 1
    ensure_singbox || return 1
    ensure_state || return 1
    local port='' method='' key='' node='' default_port='' method_choice=''
    default_port="$(jq -r '[.inbounds[] | select(.tag=="ss-in") | .listen_port][0] // empty' "$CONFIG")"
    [[ -n "$default_port" ]] || default_port="$(random_port)" || return 1
    say 'Shadowsocks: single-user TCP+UDP inbound.'
    printf '%s\n' '1) 2022-blake3-aes-128-gcm（推荐）' '2) aes-128-gcm（传统兼容）'
    ask method_choice '请选择加密方式 [1]: ' 1 || return 1
    case "$method_choice" in
        1) method='2022-blake3-aes-128-gcm' ;;
        2) method='aes-128-gcm' ;;
        *) fail 'Invalid method'; return 1 ;;
    esac
    ask port "SS TCP+UDP 监听端口 [$default_port]: " "$default_port" || return 1
    check_port_available tcp "$port" ss-in || return 1
    port=$((10#$port))
    check_port_available udp "$port" ss-in || return 1
    if jq -e ".inbounds[] | select(.tag==\"ss-in\")" "$CONFIG" >/dev/null; then
        confirm "Replace existing SS node and rotate its password?" || return 0
    fi
    if [[ "$method" == 2022* ]]; then
        key="$(openssl rand -base64 16 | tr -d '\r\n')"
    else
        key="$(openssl rand -base64 24 | tr -d '\r\n')"
    fi
    node="$(make_node_file)" || return 1
    jq -n --argjson port "$port" --arg m "$method" --arg password "$key" \
        '{type:"shadowsocks",tag:"ss-in",listen:"::",listen_port:$port,method:$m,password:$password}' > "$node"
    if ! apply_inbound ss-in "$node"; then rm -f "$node"; return 1; fi
    rm -f "$node"
    select_host || return 1
    show_links ss
}

add_hy2() {
    ensure_tools || return 1
    ensure_singbox || return 1
    ensure_state || return 1
    local port='' password='' masq='' default_masq='https://www.bing.com' node=''
    say 'Hysteria2 is QUIC/UDP; default UDP port is 443, independent of TCP/443.'
    ask port 'HY2 UDP 监听端口 [443]: ' 443 || return 1
    check_port_available udp "$port" hy2-in || return 1
    port=$((10#$port))
    if jq -e ".inbounds[] | select(.tag==\"hy2-in\")" "$CONFIG" >/dev/null; then
        confirm "Replace existing HY2 node and rotate its password?" || return 0
    fi
    ensure_shared_cert || return 1
    if [[ -n "$(listener_lines tcp 8080 2>/dev/null || true)" ]]; then
        default_masq='http://127.0.0.1:8080'
    fi
    ask masq "未认证 HTTP/3 伪装网站 URL [$default_masq]: " "$default_masq" || return 1
    [[ "$masq" =~ ^https?://[^[:space:]]+$ ]] || { fail 'Masquerade requires http:// or https:// URL'; return 1; }
    password="$(openssl rand -base64 24 | tr -d '\r\n')"
    node="$(make_node_file)" || return 1
    jq -n --argjson port "$port" --arg password "$password" --arg cert "$CERT_FILE" \
        --arg key "$KEY_FILE" --arg masq "$masq" \
        '{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$port,
         users:[{password:$password}],masquerade:$masq,
         tls:{enabled:true,alpn:["h3"],certificate_path:$cert,key_path:$key}}' > "$node"
    if ! apply_inbound hy2-in "$node"; then rm -f "$node"; return 1; fi
    rm -f "$node"
    set_meta_values --arg sni "$CERT_DOMAIN" --argjson insecure "$CERT_INSECURE" \
        '.hy2={sni:$sni,insecure:$insecure}' || warn 'HY2 元数据写入失败，请核对节点链接。'
    select_host || return 1
    show_links hy2
}

check_tls_endpoint() {
    local address="$1" port="$2" sni="$3" pem=''
    command_ok timeout || { fail 'timeout missing'; return 1; }
    pem="$(timeout 8 openssl s_client -connect "$address:$port" -servername "$sni" \
        -showcerts < /dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)"
    [[ "$pem" == *'-----BEGIN CERTIFICATE-----'* ]] || return 1
    openssl x509 -noout -checkhost "$sni" <<< "$pem" 2>/dev/null | grep -qi 'does match'
}

# Optionally create a new isolated HTTPS bridge. Never edit the existing HTTP site.
BRIDGE_NEW_PATH=''
BRIDGE_NEW_BACKUP=''
create_bridge() {
    local d="$1" target_port=8080 bridge_port='' file='' temp='' existing=''
    [[ -n "$(listener_lines tcp "$target_port" 2>/dev/null || true)" ]] || {
        fail "No local HTTP site at 127.0.0.1:$target_port"; return 1;
    }
    command_ok nginx || { fail 'Nginx is not installed'; return 1; }
    [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || return 1
    if ! nginx -t; then
        fail 'Existing Nginx config already fails nginx -t. Site files were not changed.'
        return 1
    fi
    # Reuse an already-valid independently managed loopback TLS bridge if present.
    for bridge_port in $(seq 8081 8199); do
        [[ "$bridge_port" == 8090 ]] && continue
        if check_tls_endpoint 127.0.0.1 "$bridge_port" "$d"; then
            BRIDGE_PORT="$bridge_port"; BRIDGE_NEW_PATH=''
            say "Reusing valid local HTTPS fallback 127.0.0.1:$bridge_port"
            return 0
        fi
        [[ -z "$(listener_lines tcp "$bridge_port" 2>/dev/null || true)" ]] && break
    done
    if [[ -n "$(listener_lines tcp "$bridge_port" 2>/dev/null || true)" ]]; then
        fail "No free TLS bridge port in 8081..8199"; return 1
    fi
    file="/etc/nginx/conf.d/s-script-reality-bridge-$d.conf"
    if [[ -e "$file" || -L "$file" ]]; then
        head -n 1 "$file" | grep -Fqx "$OWN_BRIDGE_MARKER" || {
            fail "User-owned Nginx config exists: $file"; return 1;
        }
        existing="$(mktemp /tmp/s-nginx-previous.XXXXXXXX)" || return 1
        cp -a "$file" "$existing"
    fi
    temp="$(mktemp /etc/nginx/conf.d/.s-bridge.XXXXXXXX)" || return 1
    cat > "$temp" <<EOF
$OWN_BRIDGE_MARKER
server {
    listen 127.0.0.1:$bridge_port ssl;
    server_name $d;
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    location / {
        proxy_pass http://127.0.0.1:$target_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
    mv -f "$temp" "$file"
    if ! nginx -t; then
        warn 'Rolling back invalid s.sh bridge (existing site stays untouched).'
        if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
        rm -f "$existing"; return 1
    fi
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then
                if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
                rm -f "$existing"; return 1
            fi
        else
            if ! systemctl start nginx; then
                if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
                rm -f "$existing"; return 1
            fi
        fi
    else
        if ! nginx -s reload; then
            if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
            rm -f "$existing"; return 1
        fi
    fi
    if ! check_tls_endpoint 127.0.0.1 "$bridge_port" "$d"; then
        warn 'Bridge TLS probe failed; removing only newly created s.sh Nginx config.'
        if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
        if command_ok systemctl; then systemctl reload nginx || true; else nginx -s reload || true; fi
        rm -f "$existing"; return 1
    fi
    BRIDGE_PORT="$bridge_port"
    BRIDGE_NEW_PATH="$file"
    BRIDGE_NEW_BACKUP="$existing"
    say "Local HTTPS bridge ready 127.0.0.1:$bridge_port -> HTTP 127.0.0.1:$target_port"
}
# Optional HY2-only TCP/443 cover website. HY2 itself uses UDP/443; when
# Reality also uses TCP/443, do NOT enable this separate HTTPS listener.
HY2_443_MARKER='# S_SH_MANAGED_HY2_TCP443_V1'
hy2_443_path() {
    local domain="$1"
    domain_valid "$domain" || return 1
    printf '/etc/nginx/conf.d/s-script-hy2-tcp443-%s.conf' "$domain"
}

enable_hy2_tcp443_site() {
    ensure_tools && ensure_state || return 1
    local domain cert key existing tmp dest before='' lines
    domain="$(get_meta '.cert_domain')"
    cert="$(get_meta '.cert_file')"
    key="$(get_meta '.key_file')"
    [[ -n "$domain" && -f "$cert" && -f "$key" ]] || {
        fail 'Configure a valid certificate through menu 1 or install HY2 first.'; return 1;
    }
    [[ "$(get_meta '.hy2_insecure')" != true ]] || {
        fail 'Refusing TCP/443 public disguise with an untrusted self-signed certificate.'; return 1;
    }
    command_ok nginx || { fail 'Nginx not installed; no user website changed'; return 1; }
    lines="$(listener_lines tcp 443)" || return 1
    [[ -z "$lines" ]] || { fail 'TCP/443 is already in use, perhaps by REALITY, Xray or a website.'; return 1; }
    [[ -n "$(listener_lines tcp 8080)" ]] || {
        fail 'No HTTP website listening on 8080; not creating an empty TCP/443 decoy.'; return 1;
    }
    if ! nginx -t; then
        fail 'Existing nginx -t already fails; refusing to edit any original site.'; return 1
    fi
    dest="$(hy2_443_path "$domain")" || return 1
    if [[ -e "$dest" || -L "$dest" ]]; then
        head -n 1 "$dest" | grep -Fqx "$HY2_443_MARKER" || {
            fail "Found non-owned Nginx site: $dest"; return 1;
        }
        before="$(mktemp /tmp/s-hy2-nginx.XXXXXXXX)" || return 1
        cp -a "$dest" "$before"
    fi
    tmp="$(mktemp /etc/nginx/conf.d/.s-hy2-cover.XXXXXXXX)" || return 1
    cat > "$tmp" <<EOF
$HY2_443_MARKER
# Optional TCP camouflage for HY2-only machines; cannot coexist with Reality TCP/443.
server {
    listen 443 ssl;
    server_name $domain;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
    mv -f "$tmp" "$dest"
    if ! nginx -t; then
        if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
        rm -f "$before"
        fail 'Nginx config rejected new TCP/443 cover. New file rolled back.'; return 1
    fi
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then
                if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
                rm -f "$before"; return 1
            fi
        else
            if ! systemctl start nginx; then
                if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
                rm -f "$before"; return 1
            fi
        fi
    else
        if ! nginx -s reload; then
            if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
            rm -f "$before"; return 1
        fi
    fi
    if ! check_tls_endpoint 127.0.0.1 443 "$domain"; then
        warn 'HTTPS TCP/443 did not present expected certificate; rolling back our Nginx file.'
        if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
        if command_ok systemctl; then systemctl reload nginx || true; else nginx -s reload || true; fi
        rm -f "$before"; return 1
    fi
    rm -f "$before"
    say "Optional HY2 TCP/443 HTTPS cover active. To install Reality on TCP/443, disable this cover first."
}

disable_hy2_tcp443_site() {
    local file='' backup=''
    file="$(get_meta '.cert_domain')"
    [[ -n "$file" ]] || { fail 'No recorded domain for an s.sh HY2 TCP/443 site'; return 1; }
    file="$(hy2_443_path "$file")" || return 1
    [[ -f "$file" ]] || { say 'No s.sh HY2 TCP/443 Nginx site is present.'; return 0; }
    head -n 1 "$file" | grep -Fqx "$HY2_443_MARKER" || {
        fail 'Site is not owned by s.sh; refusing to remove it.'; return 1;
    }
    command_ok nginx || return 1
    backup="$(mktemp /tmp/s-hy2-cover-backup.XXXXXXXX)" || return 1
    cp -a "$file" "$backup"
    rm -f "$file"
    if ! nginx -t; then cp -a "$backup" "$file"; rm -f "$backup"; return 1; fi
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then cp -a "$backup" "$file"; rm -f "$backup"; return 1; fi
        fi
    else
        nginx -s reload || warn 'Nginx not active; site file was disabled safely.'
    fi
    rm -f "$backup"
    say 'Only the s.sh-owned HY2 TCP/443 camouflage Nginx file was disabled; original website untouched.'
}

manage_hy2_tcp443_site() {
    printf '%s\n' 'Optional HTTPS website on TCP/443 for HY2-only deployment:' \
        '1) Enable (needs real certificate, local HTTP/8080 and free TCP/443)' \
        '2) Disable only this s.sh-owned Nginx site (frees TCP/443 for REALITY)' \
        '0) Cancel'
    local choice=''
    ask choice 'Select [0]: ' 0 || return 1
    case "$choice" in
        1) enable_hy2_tcp443_site ;;
        2) disable_hy2_tcp443_site ;;
        *) return 0 ;;
    esac
}

rollback_bridge_if_new() {
    [[ -n "$BRIDGE_NEW_PATH" ]] || return 0
    if [[ -n "$BRIDGE_NEW_BACKUP" && -f "$BRIDGE_NEW_BACKUP" ]]; then
        cp -a "$BRIDGE_NEW_BACKUP" "$BRIDGE_NEW_PATH"
    else
        rm -f "$BRIDGE_NEW_PATH"
    fi
    if command_ok systemctl; then systemctl reload nginx || true; else nginx -s reload || true; fi
}

add_reality() {
    ensure_tools || return 1
    ensure_singbox || return 1
    ensure_state || return 1
    local port='' mode='' sni='' target='' targetport=443 uuid='' sid='' keys='' priv='' pub='' node=''
    local saved_sni="$(get_meta '.reality.sni')"
    ask port 'REALITY TCP 监听端口 [443]: ' 443 || return 1
    check_port_available tcp "$port" vless-in || return 1
    port=$((10#$port))
    if jq -e ".inbounds[] | select(.tag==\"vless-in\")" "$CONFIG" >/dev/null; then
        confirm "Replace existing REALITY node and rotate its UUID and key?" || return 0
    fi
    printf '%s\n' 'REALITY 握手失败后的回落方式：' \
        '1) 远程 HTTPS 网站 443（默认，不修改 Nginx）' \
        '2) 复用已有本机 HTTPS 回落（证书须匹配 SNI）' \
        '3) 创建独立本机 HTTPS→HTTP 8080 桥接（仅管理自建配置）' \
        '0) 取消'
    ask mode '请选择 [1]: ' 1 || return 1
    case "$mode" in
        1)
            ask sni "远程 REALITY SNI [${saved_sni:-addons.mozilla.org}]: " "${saved_sni:-addons.mozilla.org}" || return 1
            domain_valid "$sni" || { fail "Invalid SNI: $sni"; return 1; }
            ask target "远程 HTTPS 目标站 [$sni]: " "$sni" || return 1
            ask targetport '远程 HTTPS 端口 [443]: ' 443 || return 1
            port_valid "$targetport" || return 1
            if ! check_tls_endpoint "$target" "$targetport" "$sni"; then
                fail 'Remote HTTPS target does not present a valid matching SNI certificate; try another target.'
                return 1
            fi
            ;;
        2)
            local expected_sni="$(get_meta '.cert_domain')"
            ask sni "本机 HTTPS 证书域名 / SNI [${expected_sni:-required}]: " "$expected_sni" || return 1
            domain_valid "$sni" || return 1
            target=127.0.0.1
            ask targetport '已有本机 HTTPS 端口 [8081]: ' 8081 || return 1
            port_valid "$targetport" || return 1
            check_tls_endpoint "$target" "$targetport" "$sni" || {
                fail "127.0.0.1:$targetport TLS unavailable or certificate does not match $sni"; return 1;
            }
            ;;
        3)
            ensure_shared_cert || return 1
            [[ "$CERT_INSECURE" != true ]] || {
                fail 'REALITY local HTTPS bridge needs a publicly trusted certificate; self-signed not supported here.'; return 1;
            }
            sni="$CERT_DOMAIN"
            create_bridge "$sni" || return 1
            target=127.0.0.1; targetport="$BRIDGE_PORT"
            ;;
        *) return 1 ;;
    esac
    keys="$(sing-box generate reality-keypair)" || return 1
    priv="$(sed -nE 's/^[[:space:]]*PrivateKey:[[:space:]]*//p' <<< "$keys" | head -n 1)"
    pub="$(sed -nE 's/^[[:space:]]*PublicKey:[[:space:]]*//p' <<< "$keys" | head -n 1)"
    if [[ -z "$priv" || -z "$pub" ]]; then
        warn 'Unable to parse Reality keys'; rollback_bridge_if_new; return 1
    fi
    uuid="$(cat /proc/sys/kernel/random/uuid)"
    sid="$(openssl rand -hex 4)"
    node="$(make_node_file)" || return 1
    jq -n --argjson port "$port" --arg uuid "$uuid" --arg sni "$sni" --arg target "$target" \
        --argjson targetport "$targetport" --arg priv "$priv" --arg sid "$sid" \
        '{type:"vless",tag:"vless-in",listen:"::",listen_port:$port,
         users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],
         tls:{enabled:true,server_name:$sni,reality:{enabled:true,
            handshake:{server:$target,server_port:$targetport},private_key:$priv,short_id:[$sid]}}}' > "$node"
    if ! apply_inbound vless-in "$node"; then
        rm -f "$node"; rollback_bridge_if_new; return 1
    fi
    rm -f "$node"
    if [[ -n "$BRIDGE_NEW_BACKUP" ]]; then rm -f "$BRIDGE_NEW_BACKUP"; fi
    BRIDGE_NEW_PATH=''; BRIDGE_NEW_BACKUP=''
    set_meta_values --arg p "$pub" --arg sni "$sni" --arg target "$target" \
        --argjson targetport "$targetport" \
        '.reality={public_key:$p,sni:$sni,fallback_host:$target,fallback_port:$targetport}'
    # Keep legacy sb compatibility without exposing private key.
    printf '%s' "$pub" > /etc/sing-box/.reality_pub
    chmod 600 /etc/sing-box/.reality_pub
    select_host || return 1
    show_links reality
}

show_qr() {
    if command_ok qrencode; then
        qrencode -t ANSIUTF8 -m 1 "$1" || warn 'QR display failed'
    else
        warn 'qrencode not installed. Run menu 1 to install QR dependency.'
    fi
}
show_links() {
    local only="${1:-all}" host='' port='' method='' password='' uri='' sni='' key='' sid='' uuid='' name=''
    ensure_state || return 1
    host="$(get_meta '.connect_host')"
    if [[ -z "$host" && -f /etc/sing-box/.config_cache ]]; then
        host="$(sed -n 's/^CUSTOM_IP=//p' /etc/sing-box/.config_cache | head -n 1)"
    fi
    [[ -n "$host" ]] || host="$(get_public_ip || true)"
    if [[ -z "$host" ]]; then warn 'No public connect address. Set it in menu 1.'; return 1; fi
    local authority_host="$host" label="$(get_meta '.node_name')"
    if [[ -z "$label" && -f /root/node_names.txt ]]; then
        label="$(head -n 1 /root/node_names.txt 2>/dev/null | sed 's/^-//')"
    fi
    [[ "$host" != *:* || "$host" == \[* ]] || authority_host="[$host]"
    if [[ "$only" == all || "$only" == ss ]]; then
        port="$(jq -r '[.inbounds[]|select(.tag=="ss-in")|.listen_port][0]//empty' "$CONFIG")"
        if [[ -n "$port" ]]; then
            method="$(jq -r '[.inbounds[]|select(.tag=="ss-in")|.method][0]//empty' "$CONFIG")"
            password="$(jq -r '[.inbounds[]|select(.tag=="ss-in")|.password][0]//empty' "$CONFIG")"
            name="$(urlenc "ss${label:+-$label}")"
            uri="ss://$(base64one "$method:$password")@$authority_host:$port#$name"
            printf '\n=== Shadowsocks (SS) ===\n%s\n' "$uri"
            say 'Base64 仅为链接编码；在 3X-UI 出站中填写下方原始密码。'
            printf '  Address:    %s\n  Port:       %s\n  Method:     %s\n  Password:   %s\n  Network:    TCP + UDP\n  TLS:        None\n  Transport:  Shadowsocks native; no WS/path/flow\n' \
                "$host" "$port" "$method" "$password"
            printf '%s\n' '  3X-UI/Xray 出站配置示例：'
            jq -n --arg h "$host" --argjson p "$port" --arg m "$method" --arg pw "$password" \
                '{tag:"landing-ss",protocol:"shadowsocks",settings:{servers:[{address:$h,port:$p,method:$m,password:$pw}]}}'
            show_qr "$uri"
        fi
    fi
    if [[ "$only" == all || "$only" == hy2 ]]; then
        port="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.listen_port][0]//empty' "$CONFIG")"
        if [[ -n "$port" ]]; then
            password="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.users[0].password][0]//empty' "$CONFIG")"
            sni="$(get_meta '.hy2.sni')"
            [[ -n "$sni" ]] || sni="$(get_meta '.cert_domain')"
            [[ -n "$sni" ]] || sni="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.tls.certificate_path][0]//empty' "$CONFIG" | sed -nE 's#^/etc/letsencrypt/live/([^/]+)/.*#\1#p')"
            local query="sni=$(urlenc "$sni")&alpn=h3"
            local hy2_insecure="$(get_meta '.hy2.insecure')"
            [[ -n "$hy2_insecure" ]] || hy2_insecure="$(get_meta '.hy2_insecure')"
            [[ "$hy2_insecure" == true ]] && query+='&insecure=1'
            uri="hy2://$(urlenc "$password")@$authority_host:$port/?${query}#$(urlenc "hy2${label:+-$label}")"
            printf '\n=== Hysteria2 (UDP/%s) ===\n%s\n' "$port" "$uri"
            printf '  Address: %s  UDP Port: %s  SNI: %s\n' "$host" "$port" "$sni"
            printf '  HTTP/3 masquerade: %s\n' "$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.masquerade][0]//""' "$CONFIG")"
            show_qr "$uri"
        fi
    fi
    if [[ "$only" == all || "$only" == reality ]]; then
        port="$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.listen_port][0]//empty' "$CONFIG")"
        if [[ -n "$port" ]]; then
            uuid="$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.users[0].uuid][0]//empty' "$CONFIG")"
            sni="$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.server_name][0]//empty' "$CONFIG")"
            sid="$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.reality.short_id[0]][0]//empty' "$CONFIG")"
            key="$(get_meta '.reality.public_key')"
            [[ -n "$key" ]] || key="$(cat /etc/sing-box/.reality_pub 2>/dev/null || true)"
            if [[ -z "$key" ]]; then
                warn 'Public key missing for existing REALITY node; cannot safely generate a link.'
            else
                uri="vless://$uuid@$authority_host:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(urlenc "$sni")&fp=chrome&pbk=$(urlenc "$key")&sid=$sid&type=tcp#$(urlenc "reality${label:+-$label}")"
                printf '\n=== VLESS REALITY (TCP/%s) ===\n%s\n' "$port" "$uri"
                printf '  SNI: %s  PublicKey: %s  ShortID: %s\n' "$sni" "$key" "$sid"
                printf '  Fallback: %s:%s\n' \
                    "$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.reality.handshake.server][0]//empty' "$CONFIG")" \
                    "$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.reality.handshake.server_port][0]//empty' "$CONFIG")"
                show_qr "$uri"
            fi
        fi
    fi
}

# Shared backend for per-protocol uninstall. The sing-box binary/service, TLS
# certificates, unrelated inbounds, and Nginx websites remain untouched.
protocol_tag() {
    case "$1" in
        ss) printf '%s' ss-in ;;
        hy2) printf '%s' hy2-in ;;
        reality) printf '%s' vless-in ;;
        *) return 1 ;;
    esac
}
protocol_name() {
    case "$1" in
        ss) printf '%s' 'Shadowsocks (SS)' ;;
        hy2) printf '%s' 'Hysteria2 (HY2)' ;;
        reality) printf '%s' 'VLESS REALITY' ;;
        *) return 1 ;;
    esac
}
protocol_transport() {
    case "$1" in
        ss) printf 'tcp+udp' ;;
        hy2) printf udp ;;
        reality) printf tcp ;;
        *) return 1 ;;
    esac
}
protocol_inbound() {
    local tag
    tag="$(protocol_tag "$1")" || return 1
    [[ -f "$CONFIG" ]] || return 1
    jq -c --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG" 2>/dev/null | head -n1
}
protocol_installed() {
    [[ -n "$(protocol_inbound "$1" 2>/dev/null || true)" ]]
}

remove_protocol() {
    local kind="$1" tag='' temp='' snap='' active_before=false when=''
    ensure_tools && ensure_state || return 1
    command_ok sing-box || { fail '未找到 sing-box 内核，无法安全卸载入站。'; return 1; }
    tag="$(protocol_tag "$kind")" || return 1
    if ! protocol_installed "$kind"; then
        say "$(protocol_name "$kind") 未安装，无需卸载。"
        return 0
    fi
    printf '\n只卸载 %s 入站；其他协议、sing-box 内核、证书及网站不会被删除。\n' "$(protocol_name "$kind")"
    confirm "确认卸载 $tag？" || { say '已取消。'; return 0; }
    temp="$(mktemp /etc/sing-box/.candidate.XXXXXXXX.json)" || return 1
    snap="$(mktemp "$BACKUPS"/.pre-remove.XXXXXXXX)" || { rm -f "$temp"; return 1; }
    cp -a "$CONFIG" "$snap" || { rm -f "$temp" "$snap"; return 1; }
    service_active && active_before=true
    if ! jq --arg tag "$tag" '.inbounds |= map(select(.tag != $tag))' "$CONFIG" > "$temp" || \
       ! sing-box check -c "$temp"; then
        rm -f "$temp" "$snap"
        fail '移除失败：候选配置不通过 sing-box check，原配置未修改。'
        return 1
    fi
    chmod 600 "$temp"
    mv -f "$temp" "$CONFIG"
    # If the service was intentionally stopped, do not start it by surprise.
    if $active_before; then
        if ! service_restart || ! service_active; then
            cp -a "$snap" "$CONFIG"
            service_restart || true
            rm -f "$snap"
            fail '重启失败，已恢复原配置。'
            return 1
        fi
        # Ensure other inbounds survive this operation and service stays active.
    fi
    when="$(date +%Y%m%d_%H%M%S)"
    cp -a "$snap" "$BACKUPS/config.before-remove-${tag}-${when}.json"
    rm -f "$snap"
    # Shared TLS metadata and REALITY public-key cache are intentionally retained.
    # They are harmless without the inbound, and can be used for recovery.
    say "已卸载 $(protocol_name "$kind") 入站。其他入站保留，sing-box 服务状态未更改。"
    if [[ "$kind" == hy2 ]]; then
        say '如启用了 HY2 专属 TCP/443 伪装站，可在 HY2 子菜单单独关闭；默认不改 Nginx。'
    fi
}

protocol_status() {
    local kind="$1" tag='' proto='' line='' port='' sni='' method='' lines_tcp='' lines_udp=''
    local installed=false running=false valid=false listening=false
    tag="$(protocol_tag "$kind")" || return 1
    proto="$(protocol_transport "$kind")"
    printf '\n========== %s 运行状态 ==========\n' "$(protocol_name "$kind")"
    if [[ ! -f "$CONFIG" ]]; then
        printf '安装状态：未配置\n配置文件：%s 不存在\n' "$CONFIG"
        return 0
    fi
    if command_ok sing-box; then
        if sing-box check -c "$CONFIG" >/dev/null 2>&1; then valid=true; fi
    fi
    if service_active; then running=true; fi
    if protocol_installed "$kind"; then
        installed=true
        line="$(protocol_inbound "$kind")"
        port="$(jq -r '.listen_port // empty' <<< "$line")"
        printf '安装状态：已配置\n传输协议：%s\n监听端口：%s\n' "${proto^^}" "$port"
        case "$kind" in
            ss)
                method="$(jq -r '.method // empty' <<< "$line")"
                printf '加密方式：%s\n' "$method"
                ;;
            hy2)
                sni="$(get_meta '.hy2.sni')"
                [[ -n "$sni" ]] || sni="$(get_meta '.cert_domain')"
                printf 'TLS 域名：%s\nHTTP/3 伪装：%s\n' "${sni:-未记录}" \
                    "$(jq -r '.masquerade // "未设置"' <<< "$line")"
                ;;
            reality)
                sni="$(jq -r '.tls.server_name // empty' <<< "$line")"
                printf 'SNI：%s\nTLS 回落：%s:%s\n' "$sni" \
                    "$(jq -r '.tls.reality.handshake.server // empty' <<< "$line")" \
                    "$(jq -r '.tls.reality.handshake.server_port // empty' <<< "$line")"
                ;;
        esac
    else
        printf '安装状态：未安装（不存在 %s 入站）\n' "$tag"
    fi
    printf 'sing-box 服务：%s\n' "$($running && printf '运行中' || printf '未运行')"
    printf '配置语法检查：%s\n' "$($valid && printf '通过' || printf '失败 / 内核未安装')"
    if $installed && port_valid "$port" && command_ok ss; then
        if [[ "$proto" == *tcp* ]]; then
            lines_tcp="$(listener_lines tcp "$port" 2>/dev/null || true)"
            if [[ "$lines_tcp" == *sing-box* ]]; then
                printf 'TCP/%s：sing-box 正在监听\n' "$port"
            else
                printf 'TCP/%s：未发现 sing-box 监听\n' "$port"
                [[ -n "$lines_tcp" ]] && printf '%s\n' "$lines_tcp"
            fi
        fi
        if [[ "$proto" == *udp* ]]; then
            lines_udp="$(listener_lines udp "$port" 2>/dev/null || true)"
            if [[ "$lines_udp" == *sing-box* ]]; then
                printf 'UDP/%s：sing-box 正在监听\n' "$port"
            else
                printf 'UDP/%s：未发现 sing-box 监听\n' "$port"
                [[ -n "$lines_udp" ]] && printf '%s\n' "$lines_udp"
            fi
        fi
    fi
    printf '配置路径：%s\n' "$CONFIG"
    printf '注意：端口监听正常不等于客户端已通过认证；可用节点链接做实际连接测试。\n'
}

protocol_restart() {
    local kind="$1"
    if ! protocol_installed "$kind"; then
        fail "$(protocol_name "$kind") 尚未安装，不能重启。"
        return 1
    fi
    if ! command_ok sing-box || ! sing-box check -c "$CONFIG"; then
        fail '配置验证失败，不执行重启，防止影响现有节点。'
        return 1
    fi
    if ! service_exists; then
        fail 'sing-box 服务未安装，先使用菜单 1 安装内核，或重新安装该协议。'
        return 1
    fi
    say '三个协议使用同一个 sing-box 进程；本操作将重启服务，但不会修改其他协议配置。'
    service_restart || { fail 'sing-box 重启失败，请查看服务日志。'; return 1; }
    service_active || { fail '服务未保持运行，请查看日志。'; return 1; }
    protocol_status "$kind"
}

protocol_menu() {
    local kind="$1" choice='' name=''
    name="$(protocol_name "$kind")" || return 1
    while true; do
        printf '\n%s\n' '-------------------------------------------'
        printf '  %s 独立管理\n' "$name"
        printf '%s\n' '-------------------------------------------' \
            '1) 安装 / 重装协议' \
            '2) 卸载协议（只删除当前入站）' \
            '3) 重启协议（共享 sing-box 服务）' \
            '4) 查看协议运行状态' \
            '5) 输出节点链接与二维码'
        if [[ "$kind" == hy2 ]]; then
            printf '%s\n' '6) HY2 TCP/443 HTTPS 伪装站（可选，默认关闭）'
        fi
        printf '%s\n' '0) 返回主菜单'
        ask choice '请选择 [0]: ' 0 || return 0
        case "$choice" in
            1)
                case "$kind" in
                    ss) add_ss || true ;;
                    hy2) add_hy2 || true ;;
                    reality) add_reality || true ;;
                esac
                ;;
            2) remove_protocol "$kind" || true ;;
            3) protocol_restart "$kind" || true ;;
            4) protocol_status "$kind" || true ;;
            5) if command_ok jq; then show_links "$kind" || true; else warn '先在菜单 1 安装 jq / qrencode。'; fi ;;
            6) if [[ "$kind" == hy2 ]]; then manage_hy2_tcp443_site || true; else warn '无效选项。'; fi ;;
            0|q|Q) return 0 ;;
            *) warn '无效选项。' ;;
        esac
    done
}

status() {
    printf '\n=== sing-box status ===\n'
    if command_ok sing-box; then sing-box version | head -n 2; else warn 'sing-box binary not installed'; fi
    if service_active; then say 'sing-box service is active'; else warn 'sing-box service is not active'; fi
    if [[ -f "$CONFIG" ]]; then
        if command_ok sing-box; then sing-box check -c "$CONFIG" || true; fi
        jq -r '.inbounds[]? | "  \(.tag // .type)  \(.type)  \(.listen_port)"' "$CONFIG" 2>/dev/null || true
    fi
    if command_ok ss; then
        printf 'TCP 443:\n'; listener_lines tcp 443 || true
        printf 'UDP 443:\n'; listener_lines udp 443 || true
    fi
    printf 'Config: %s\n' "$CONFIG"
    printf 'State:  %s\n' "$META"
}

# Protect other projects sharing the sing-box binary/service name. Only a
# service targeting our /etc/sing-box configuration is in scope.
core_service_is_ours() {
    local unit=''
    service_exists || return 1
    if command_ok systemctl; then
        unit="$(systemctl cat sing-box 2>/dev/null || true)"
        [[ "$unit" == *'run -c /etc/sing-box/config.json'* || "$unit" == *'run -c /etc/sing-box/'* ||
           "$unit" == *'run -D /etc/sing-box'* || "$unit" == *'S_SH_MANAGED_SINGBOX_SERVICE_V2'* ]]
    elif command_ok rc-service; then
        [[ -r /etc/init.d/sing-box ]] || return 1
        grep -Eq 'S_SH_MANAGED_SINGBOX_SERVICE_V2|/etc/sing-box/config.json' /etc/init.d/sing-box
    else
        return 1
    fi
}

# Download the official, standalone installer to a file rather than piping
# uninspected network content directly to the shell. No panel is installed.
core_official_update() {
    local os installer=''
    os="$(os_kind)"
    if [[ "$os" == alpine ]]; then
        apk update && apk upgrade sing-box
        return $?
    fi
    if [[ "$os" != debian && "$os" != redhat ]]; then
        fail '仅支持 Debian/Ubuntu、RHEL 系和 Alpine 手动更新。'
        return 1
    fi
    installer="$(mktemp /tmp/s-sh-core-installer.XXXXXXXX)" || return 1
    if ! curl -fsSL --retry 2 --connect-timeout 12 --max-time 90 \
            https://sing-box.app/install.sh -o "$installer" || [[ ! -s "$installer" ]]; then
        rm -f "$installer"
        fail '官方安装器下载失败，未主动修改已有配置。'
        return 1
    fi
    # Official installer may restart the service as part of a package upgrade.
    if ! bash "$installer"; then
        rm -f "$installer"
        fail '官方 sing-box 更新安装器返回失败。'
        return 1
    fi
    rm -f "$installer"
}

# Update only when explicitly requested from main menu 2. Preserve current
# binary and config, verify the *new* core before accepting the result; on
# failure restore the old executable and the previous running state.
update_singbox_core() {
    require_root
    local binary resolved tmpdir='' was_active=false old_version='' new_version='' outcome=0
    local restore_error=false
    command_ok sing-box || { fail '尚未安装 sing-box 内核，请先使用菜单 1 安装。'; return 1; }
    if service_exists && ! core_service_is_ours; then
        fail 'sing-box 服务并非由 /etc/sing-box/config.json 管理，拒绝更新以免影响其他项目。'
        return 1
    fi
    binary="$(command -v sing-box)"
    resolved="$(readlink -f "$binary")" || return 1
    [[ -f "$resolved" && -x "$resolved" ]] || { fail "内核文件不可执行：$resolved"; return 1; }
    old_version="$(sing-box version 2>/dev/null | head -n1 || true)"
    printf '\n当前 sing-box：%s\n二进制文件：%s\n' "${old_version:-未知版本}" "$resolved"
    printf '%s\n' '更新将通过 sing-box 官方安装渠道进行；如当前服务正在运行，更新期间可能短暂断线。'
    confirm '确认手动更新 sing-box 到官方最新稳定版？' || { say '已取消内核更新。'; return 0; }
    mkdir -p "$BACKUPS"
    chmod 700 "$BACKUPS"
    tmpdir="$(mktemp -d "$BACKUPS"/core-update.XXXXXXXX)" || return 1
    chmod 700 "$tmpdir"
    # Use -L so an existing symbolic-link core is backed up as binary bytes.
    cp -L -p "$resolved" "$tmpdir/sing-box.previous" || return 1
    printf '%s\n' "$resolved" > "$tmpdir/original-bin-path.txt"
    printf '%s\n' "$old_version" > "$tmpdir/previous-version.txt"
    if [[ -f "$CONFIG" ]]; then
        cp -a "$CONFIG" "$tmpdir/config.before-update.json" || return 1
    fi
    if service_active; then was_active=true; fi

    if ! core_official_update; then
        outcome=1
    fi
    if (( outcome == 0 )) && ! command_ok sing-box; then
        fail '更新后找不到 sing-box 命令。' || true
        outcome=1
    fi
    if (( outcome == 0 )) && service_exists && ! core_service_is_ours; then
        fail '更新后 sing-box 服务不再指向原配置；拒绝确认更新。' || true
        outcome=1
    fi
    if (( outcome == 0 )) && [[ -f "$CONFIG" ]]; then
        if [[ -f "$tmpdir/config.before-update.json" ]] && ! cmp -s "$CONFIG" "$tmpdir/config.before-update.json"; then
            warn '更新器意外修改了节点配置，将恢复更新前备份。'
            cp -a "$tmpdir/config.before-update.json" "$CONFIG"
            outcome=1
        elif ! sing-box check -c "$CONFIG"; then
            fail '新内核无法解析现有节点配置。' || true
            outcome=1
        fi
    fi
    if (( outcome == 0 )) && $was_active; then
        if ! service_restart || ! service_active; then
            fail '新内核重启验收失败。' || true
            outcome=1
        fi
    elif (( outcome == 0 )) && service_active; then
        # Package hooks may start an intentionally stopped service.
        # Restore the pre-upgrade stopped state rather than silently enabling it.
        service_stop || { fail '更新后未能恢复原有停止状态。' || true; outcome=1; }
    fi
    if (( outcome != 0 )); then
        warn '升级未完成，正在恢复之前备份的 sing-box 内核。'
        # The updater may replace the file or change symlink destinations.
        # Restore exact previous binary bytes at the original execution path.
        if ! install -m 755 "$tmpdir/sing-box.previous" "$resolved"; then
            restore_error=true
            warn "内核文件恢复失败，请手动查看 $tmpdir/sing-box.previous"
        fi
        if ! $restore_error && [[ -f "$CONFIG" ]] && ! "$resolved" check -c "$CONFIG"; then
            warn '旧内核也未通过当前配置检查；保留原配置供排查。'
        fi
        if $was_active; then
            if ! service_restart || ! service_active; then
                restore_error=true
                warn '旧版本服务恢复失败，请检查 systemctl status sing-box。'
            fi
        elif service_active; then
            service_stop || true
        fi
        warn "更新失败。旧版本备份位于：$tmpdir"
        $restore_error && return 2
        return 1
    fi
    new_version="$(sing-box version 2>/dev/null | head -n1 || true)"
    say "内核更新成功：${old_version:-unknown} -> ${new_version:-unknown}"
    say "旧内核和更新前配置已备份：$tmpdir"
    printf '%s\n' '协议入站、UUID、密码、证书及 Nginx 网站均保持原样。'
}

# Menu 3 is a COMPLETE uninstall: sing-box core + ALL SS/HY2/REALITY
# inbounds, credentials, script metadata, self-signed certs and backups.
# System-wide Let's Encrypt certificates, the owner's Nginx sites and
# xpro.sh / 3X-UI are explicitly out of scope.
# Because our optional Nginx bridge can reference /etc/sing-box/certs, remove
# only its marked vhosts transactionally BEFORE deleting those certificates.
s_sh_owned_nginx_files() {
    local file first
    for file in /etc/nginx/conf.d/s-script-reality-bridge-*.conf \
                /etc/nginx/conf.d/s-script-hy2-tcp443-*.conf; do
        [[ -f "$file" && ! -L "$file" ]] || continue
        first="$(head -n 1 "$file" 2>/dev/null || true)"
        case "$first" in
            "$OWN_BRIDGE_MARKER"|"$HY2_443_MARKER") printf '%s\n' "$file" ;;
        esac
    done
}

# Nginx rollback staging lives outside the directory that will be deleted.
# On an invalid/reload-failed candidate all original marked files are restored.
s_sh_nginx_remove_own() {
    local staged="$1" file basename_file changed=false
    local -a paths=()
    mapfile -t paths < <(s_sh_owned_nginx_files)
    ((${#paths[@]})) || return 0
    command_ok nginx || { fail '检测到 s.sh 专属 Nginx 回落配置，但 nginx 命令缺失；为避免产生无效配置，中止卸载。'; return 1; }
    mkdir -p "$staged/nginx"
    for file in "${paths[@]}"; do
        basename_file="$(basename "$file")"
        # Never follow symbolic links; the source must have the exact owner marker.
        cp -p -- "$file" "$staged/nginx/$basename_file" || return 1
    done
    for file in "${paths[@]}"; do
        rm -f -- "$file" || { s_sh_nginx_restore_own "$staged"; return 1; }
        changed=true
    done
    if ! nginx -t; then
        warn '删除 s.sh 辅助配置后的 Nginx 检查未通过，已回滚这些文件；不影响原网站。'
        s_sh_nginx_restore_own "$staged"
        return 1
    fi
    if $changed; then
        if command_ok systemctl && systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then
                warn 'Nginx reload 失败，恢复 s.sh 辅助配置。'
                s_sh_nginx_restore_own "$staged"
                return 1
            fi
        elif command_ok rc-service && rc-service nginx status >/dev/null 2>&1; then
            if ! rc-service nginx reload; then
                s_sh_nginx_restore_own "$staged"
                return 1
            fi
        fi
    fi
    say '已清理 s.sh 创建的独立 Nginx 回落配置，原有网站文件未改动。'
    return 0
}
s_sh_nginx_restore_own() {
    local staged="$1" file
    for file in "$staged"/nginx/*.conf; do
        [[ -f "$file" ]] || continue
        cp -p -- "$file" "/etc/nginx/conf.d/$(basename "$file")" || warn "回滚 Nginx 文件失败：$file"
    done
    if command_ok nginx && nginx -t >/dev/null 2>&1; then
        if command_ok systemctl && systemctl is-active --quiet nginx; then
            systemctl reload nginx >/dev/null 2>&1 || true
        fi
    fi
}

uninstall_singbox_core() {
    require_root
    local os='' bin='' resolved='' package_name='sing-box' removed=false owned_service=false
    local staged='' owns_files='' token='' was_active=false binary_removed=false
    local config_root='/etc/sing-box'
    # No deletion of a symlink/mounted directory: it could refer to user data.
    if [[ -L "$config_root" ]] || { [[ -e "$config_root" ]] && command_ok mountpoint && mountpoint -q "$config_root"; }; then
        fail '/etc/sing-box 是软链接或挂载点；为避免误删共享目录，拒绝自动卸载。'
        return 1
    fi
    if service_exists; then
        if ! core_service_is_ours; then
            fail '存在非本 s.sh 管理的 sing-box 服务，拒绝卸载，避免影响其他项目。'
            return 1
        fi
        owned_service=true
    fi
    if command_ok sing-box; then
        bin="$(command -v sing-box)"
        resolved="$(readlink -f "$bin")" || return 1
    fi
    # With no clearly associated service, a manually installed binary might be shared.
    if [[ -n "$resolved" && -f "$resolved" ]]; then
        case "$resolved" in
            /usr/local/bin/sing-box|/usr/bin/sing-box) ;;
            *) fail "内核在非标准路径 $resolved，无法确认是否由 s.sh 管理；已取消自动卸载。"; return 1 ;;
        esac
    fi
    if [[ ! -e "$config_root" ]] && ! command_ok sing-box && ! service_exists; then
        say '没有发现本脚本管理的 sing-box 内核或协议配置，无需卸载。'
        return 0
    fi

    printf '\n%s\n' \
      '========== sing-box 完整卸载 ==========' \
      '将永久删除：' \
      '  - 独立 sing-box 内核和服务' \
      '  - /etc/sing-box 下全部协议：SS / HY2 / REALITY（及其他历史入站）' \
      '  - 全部节点配置、UUID、密码、REALITY 密钥、缓存、内部备份' \
      '  - /etc/sing-box/certs 内由 s.sh 保存的自签证书' \
      '  - s.sh 创建且带有所有权标记的独立 Nginx TLS 桥接配置' \
      '保留：Nginx 原有网站、/etc/letsencrypt、PHP、xpro.sh、3X-UI 和系统共用依赖。' \
      '注意：这是不可逆清理；以后安装会生成全新 UUID 和密码。'
    ask token '输入 DELETE 才执行完整卸载：' '' || return 1
    if [[ "$token" != DELETE ]]; then say '已取消完整卸载，未做修改。'; return 0; fi

    os="$(os_kind)"
    if service_active; then was_active=true; fi
    # The clean-up work directory is deliberately outside /etc/sing-box.
    staged="$(mktemp -d /tmp/s-sh-uninstall.XXXXXXXX)" || return 1
    chmod 700 "$staged"
    # Remove only our own Nginx vhosts and verify reload; a failure leaves
    # the core and /etc/sing-box untouched.
    if ! s_sh_nginx_remove_own "$staged"; then
        warn 'Nginx 辅助配置清理失败；未卸载内核和协议。'
        rm -rf -- "$staged"
        return 1
    fi
    # A user-managed Nginx include may independently refer to certificates
    # in /etc/sing-box. Refuse to delete keys that another site still needs.
    # These are the loaded-site directories, NOT the original wow web root.
    local external_refs=''
    if [[ -d /etc/nginx ]]; then
        external_refs="$(grep -RlF '/etc/sing-box/' \
            /etc/nginx/conf.d /etc/nginx/sites-enabled /etc/nginx/snippets \
            /etc/nginx/nginx.conf 2>/dev/null || true)"
        if [[ -n "$external_refs" ]]; then
            warn '检测到其它 Nginx 配置仍引用 /etc/sing-box 的证书，不能直接删除密钥：'
            printf '%s\n' "$external_refs" >&2
            s_sh_nginx_restore_own "$staged"
            rm -rf -- "$staged"
            return 1
        fi
    fi

    # If removing sing-box package fails, restore s.sh-owned Nginx files.
    service_stop || true
    service_disable
    case "$os" in
        debian)
            if command_ok dpkg-query && dpkg-query -W -f='${Status}' "$package_name" 2>/dev/null | grep -q '^install ok installed$'; then
                if ! env DEBIAN_FRONTEND=noninteractive apt-get remove -y --no-install-recommends "$package_name"; then
                    s_sh_nginx_restore_own "$staged"
                    $was_active && service_start || true
                    fail 'sing-box 软件包卸载失败，协议配置没有删除。'
                    return 1
                fi
                removed=true
            fi
            ;;
        redhat)
            if command_ok rpm && rpm -q "$package_name" >/dev/null 2>&1; then
                if command_ok dnf; then
                    dnf remove -y "$package_name" || { s_sh_nginx_restore_own "$staged"; return 1; }
                else
                    yum remove -y "$package_name" || { s_sh_nginx_restore_own "$staged"; return 1; }
                fi
                removed=true
            fi
            ;;
        alpine)
            if apk info -e "$package_name" >/dev/null 2>&1; then
                apk del "$package_name" || { s_sh_nginx_restore_own "$staged"; return 1; }
                removed=true
            fi
            ;;
    esac
    # Handle a manually installed binary only if the matching s.sh unit was
    # verified; never delete arbitrary binaries from unrelated projects.
    if [[ -n "$resolved" && -e "$resolved" ]]; then
        if $owned_service; then
            rm -f -- "$resolved" || { s_sh_nginx_restore_own "$staged"; return 1; }
            binary_removed=true
        elif ! $removed; then
            s_sh_nginx_restore_own "$staged"
            fail "无法确认手动安装内核 $resolved 的所属服务，已保留配置。"
            return 1
        fi
    fi
    # Remove a local s.sh/legacy-s(9).sh unit, not a user-authored service.
    if command_ok systemctl && [[ -f /etc/systemd/system/sing-box.service ]] &&
       { grep -Fqx '# S_SH_MANAGED_SINGBOX_SERVICE_V2' /etc/systemd/system/sing-box.service ||
         grep -Eq '^[[:space:]]*ExecStart=.*sing-box run -c /etc/sing-box/config.json([[:space:]]|$)' /etc/systemd/system/sing-box.service; }; then
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    elif command_ok rc-service && [[ -f /etc/init.d/sing-box ]] &&
         grep -Eq 'S_SH_MANAGED_SINGBOX_SERVICE_V2|/etc/sing-box/config.json' /etc/init.d/sing-box; then
        rm -f /etc/init.d/sing-box
    fi

    # All protocols, generated keys, self-signed certs, metadata and even
    # pre-uninstall backups are deliberately removed, per user instruction.
    if [[ -d "$config_root" && ! -L "$config_root" ]]; then
        rm -rf -- "$config_root" || { fail "删除协议目录失败：$config_root"; return 1; }
    fi
    # Remove the old 'sb' command only when it matches the legacy s(9).sh
    # manager's own recognizable contents; never touch other commands.
    if [[ -f /usr/local/bin/sb ]] &&
       grep -Fq 'Sing-box 管理面板 (快速指令sb)' /usr/local/bin/sb &&
       grep -Fq '/etc/sing-box/config.json' /usr/local/bin/sb; then
        rm -f /usr/local/bin/sb || true
    fi
    rm -rf -- "$staged"
    say '完整卸载成功：sing-box 内核、服务、全部协议配置与密钥已经清理。'
    say '原有网站、Nginx 用户配置、系统共用依赖和 /etc/letsencrypt 证书保持不变。'
    return 0
}

set_node_name() {
    ensure_tools && ensure_state || return 1
    local name=''
    ask name 'Node name suffix (blank clears it): ' "$(get_meta '.node_name')" || return 1
    [[ "$name" != *$'\n'* && ${#name} -lt 64 ]] || return 1
    set_meta_values --arg name "$name" '.node_name=$name'
}

# Shared setup; every protocol reuses the same dependency, address and cert
# functions. SS does not require TLS; HY2 calls prepare_domain_cert itself.
common_setup_all() {
    install_deps || return 1
    ensure_tools && ensure_singbox && ensure_state || return 1
    select_host || return 1
    set_node_name || return 1
    if confirm '现在申请 / 复用一个 HY2 或 REALITY 本机回落可用的 TLS 域名证书？'; then
        prepare_domain_cert || {
            warn 'TLS 证书暂未准备；不影响 SS 安装，可稍后在菜单 1 单独处理。'
        }
    fi
    say '通用环境已准备：sing-box、二维码依赖、连接地址及可选证书。'
}
menu_setup() {
    while true; do
        printf '\n%s\n' '========== 菜单 1：通用环境、域名与证书 =========='
        printf '%s\n' '1) 一键准备通用环境（依赖、二维码、内核、地址、可选证书）' \
            '2) 安装系统及二维码依赖（含 jq、openssl、certbot）' \
            '3) 安装独立 sing-box 内核（无 S-UI 面板）' \
            '4) 设置节点连接地址（IP / DDNS）' \
            '5) 申请或复用域名 TLS 证书（HY2 / REALITY 本机回落）' \
            '6) 设置节点名称后缀' \
            '7) 检查通用依赖、域名和证书状态' \
            '0) 返回主菜单'
        local n=''
        ask n '请选择 [0]: ' 0 || return 0
        case "$n" in
            1) common_setup_all || true ;;
            2) install_deps || true ;;
            3) ensure_tools && ensure_singbox && { sing-box version | head -n 2; } || true ;;
            4) ensure_tools && ensure_state && select_host || true ;;
            5) ensure_tools && prepare_domain_cert || true ;;
            6) set_node_name || true ;;
            7)
                printf '\n通用组件状态：\n'
                for x in sing-box curl jq openssl qrencode certbot ss; do
                    if command_ok "$x"; then printf '  %-12s %s\n' "$x" '已安装'; else printf '  %-12s %s\n' "$x" '未安装'; fi
                done
                if [[ -f "$META" ]]; then
                    printf '  节点地址：%s\n  证书域名：%s\n  证书路径：%s\n' \
                        "$(get_meta '.connect_host')" "$(get_meta '.cert_domain')" "$(get_meta '.cert_file')"
                fi
                ;;
            0|q|Q) return 0 ;;
            *) warn '无效选项。' ;;
        esac
    done
}

show_menu() {
    printf '\n%s\n' '===========================================' \
      '   s.sh | 独立 sing-box 协议管理（不含 S-UI）' \
      '===========================================' \
      '1) 通用依赖、二维码、域名和 TLS 证书' \
      '2) 手动更新 sing-box 内核' \
      '3) 完整卸载 sing-box 内核及全部协议（不可恢复）' \
      '4) Shadowsocks (SS) 管理' \
      '5) Hysteria2 (HY2) 管理（默认 UDP 443）' \
      '6) VLESS REALITY 管理（默认 TCP 443）' \
      '7) sing-box 总体运行状态' \
      '8) 重启 sing-box 服务（含全部入站）' \
      '0) 退出' \
      '-------------------------------------------'
}
main() {
    require_root
    local arg="${1:-}" choice=''
    case "$arg" in
        --help|-h) show_menu; return 0 ;;
        --status) status; return 0 ;;
        --status-ss) protocol_status ss; return 0 ;;
        --status-hy2) protocol_status hy2; return 0 ;;
        --status-reality) protocol_status reality; return 0 ;;
        --show) warn '节点链接与二维码现已移至各协议子菜单（主菜单 4/5/6）。'; return 0 ;;
        --setup) menu_setup; return $? ;;
        --ss-menu) protocol_menu ss; return $? ;;
        --hy2-menu) protocol_menu hy2; return $? ;;
        --reality-menu) protocol_menu reality; return $? ;;
        --install-ss) add_ss; return $? ;;
        --install-hy2) add_hy2; return $? ;;
        --install-reality) add_reality; return $? ;;
        --update-core) update_singbox_core; return $? ;;
        --uninstall-core) uninstall_singbox_core; return $? ;;
        --precheck)
            status
            if command_ok nginx; then nginx -t || true; fi
            return 0 ;;
        --*) fail "Unknown option $arg"; return 1 ;;
    esac
    while true; do
        show_menu
        ask choice '请选择 [0-8]: ' '' || return 0
        case "$choice" in
            1) menu_setup || true ;;
            2) update_singbox_core || true ;;
            3) uninstall_singbox_core || true ;;
            4) protocol_menu ss || true ;;
            5) protocol_menu hy2 || true ;;
            6) protocol_menu reality || true ;;
            7) status ;;
            8)
                if [[ -f "$CONFIG" ]] && command_ok sing-box && sing-box check -c "$CONFIG"; then
                    service_restart && say 'sing-box 已重启' || warn '重启失败'
                else
                    warn '配置验证失败或内核未安装，已取消重启。'
                fi
                ;;
            0|q|Q) return 0 ;;
            *) warn '无效菜单编号。' ;;
        esac
    done
}
main "$@"
