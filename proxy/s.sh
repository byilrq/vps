#!/usr/bin/env bash
# s.sh v6.5 - Auto-detect/reuse local HTTPS fallback; auto-allocate bridge ports for R/H coexistence.
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

# Terminal-aware colors. Display plain text when redirected or TERM=dumb.
if [[ -t 1 && "${TERM:-dumb}" != dumb && "${NO_COLOR:-}" == '' ]]; then
    UI_RESET=$'\033[0m'; UI_CYAN=$'\033[1;36m'; UI_BLUE=$'\033[1;34m'
    UI_GREEN=$'\033[1;32m'; UI_YELLOW=$'\033[1;33m'; UI_RED=$'\033[1;31m'
    UI_BOLD=$'\033[1m'; UI_DIM=$'\033[2m'
else
    UI_RESET=''; UI_CYAN=''; UI_BLUE=''; UI_GREEN=''; UI_YELLOW=''; UI_RED=''
    UI_BOLD=''; UI_DIM=''
fi
say() { printf '%b[INFO]%b %s\n' "$UI_BLUE" "$UI_RESET" "$*"; }
warn() { printf '%b[WARN]%b %s\n' "$UI_YELLOW" "$UI_RESET" "$*" >&2; }
fail() { printf '%b[ERROR]%b %s\n' "$UI_RED" "$UI_RESET" "$*" >&2; return 1; }
ui_rule() { printf '%b--------------------------------------------------%b\n' "$UI_DIM" "$UI_RESET"; }
ui_item() { local num="$1" desc="$2" shade="${3:-$UI_GREEN}"; printf ' %b%2s)%b %s\n' "$shade" "$num" "$UI_RESET" "$desc"; }
ui_banner() {
    printf '\n%b╔══════════════════════════════════════════════╗%b\n' "$UI_CYAN" "$UI_RESET"
    printf '%b║%b          %bs.sh  |  sing-box 管理界面%b          %b║%b\n' \
        "$UI_CYAN" "$UI_RESET" "$UI_BOLD$UI_GREEN" "$UI_RESET" "$UI_CYAN" "$UI_RESET"
    printf '%b╚══════════════════════════════════════════════╝%b\n' "$UI_CYAN" "$UI_RESET"
}

require_root() { [[ $EUID -eq 0 ]] || { fail 'Run as root: sudo bash s.sh'; exit 1; }; }
command_ok() { command -v "$1" >/dev/null 2>&1; }

# read -e uses readline; explicitly support both usual Backspace encodings.
if [[ -t 0 ]]; then
    bind '"\C-h": backward-delete-char' 2>/dev/null || true
    bind '"\C-?": backward-delete-char' 2>/dev/null || true
fi
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
    if command_ok systemctl; then systemctl is-active --quiet sing-box >/dev/null 2>&1
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

# HY2 can use its certificate/SNI domain as the actual connection address,
# independently of the shared SS/REALITY connection host. In contrast to SNI,
# this address MUST resolve directly to the VPS (Cloudflare orange cloud does
# not proxy generic Hysteria2 UDP/QUIC traffic).
hy2_address_valid() {
    local h="$1" part
    [[ "$h" != *$'\n'* && "$h" != *$'\r'* && "$h" != *' '* ]] || return 1
    if [[ "$h" == \[*\] ]]; then h="${h:1:${#h}-2}"; fi
    if [[ "$h" == *:* ]]; then
        command_ok python3 || return 1
        python3 - "$h" <<'PY_HY2_ADDR'
import ipaddress
import sys
try:
    addr = ipaddress.IPv6Address(sys.argv[1])
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError('unsuitable client endpoint')
except ValueError:
    sys.exit(1)
PY_HY2_ADDR
    elif [[ "$h" =~ ^[0-9.]+$ ]]; then
        local o1 o2 o3 o4 rest
        IFS=. read -r o1 o2 o3 o4 rest <<< "$h"
        [[ -z "$rest" && -n "$o4" ]] || return 1
        for part in "$o1" "$o2" "$o3" "$o4"; do
            [[ "$part" =~ ^[0-9]{1,3}$ ]] && (( 10#$part <= 255 )) || return 1
        done
    else
        domain_valid "$h"
    fi
}

# Read DNS without changing the system resolver, DDNS or Cloudflare settings.
# Returns 0 only if one DNS A/AAAA record matches an identifiable local/public
# address. For NAT/VPS proxies where this cannot be established, confirmation
# is required rather than silently publishing an unusable domain URI.
hy2_domain_dns_check() {
    local d="$1" display_kind="${2:-HY2}" v4='' v6='' public_v4='' local_v6='' addr=''
    local matched=false mismatched=false
    if command_ok getent; then
        v4="$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
        v6="$(getent ahostsv6 "$d" 2>/dev/null | awk '{print $1}' | grep -v '^::ffff:' | sort -u | paste -sd, - || true)"
    fi
    public_v4="$(get_public_ip || true)"
    if command_ok ip; then
        local_v6="$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | sort -u | paste -sd, - || true)"
    fi
    printf '  %s 连接域名：%s\n  DNS A：%s\n  DNS AAAA：%s\n' \
        "$display_kind" "$d" "${v4:-未解析到}" "${v6:-未解析到}"
    printf '  当前公网 IPv4：%s\n  本机全局 IPv6：%s\n' \
        "${public_v4:-无法确定}" "${local_v6:-无/无法确定}"
    # Any extra A/AAAA pointing elsewhere can cause clients to select the
    # wrong address (especially AAAA over A), even when one record is valid.
    for addr in ${v4//,/ }; do
        if [[ -n "$public_v4" && "$addr" == "$public_v4" ]]; then
            matched=true
        else
            mismatched=true
        fi
    done
    for addr in ${v6//,/ }; do
        if [[ -n "$local_v6" ]] && [[ ",${local_v6,,}," == *",${addr,,},"* ]]; then
            matched=true
        else
            mismatched=true
        fi
    done
    if $matched && ! $mismatched; then
        say "${display_kind} 域名解析的 A/AAAA 记录均与已检测到的 VPS 地址一致。"
        return 0
    fi
    warn '无法确认域名的所有 A/AAAA 都直接指向本 VPS；若存在多余的 AAAA，客户端可能优先访问错误 IPv6。'
    warn 'Cloudflare 橙云/CDN、错误 A/AAAA 或 DNS 尚未生效都会使 HY2 域名连接失败。'
    warn '请使用 DNS only（灰云）或直连的 A/AAAA，并确保对应 IP 的 UDP 端口可访问。'
    return 1
}

HY2_CONNECT_HOST=''
select_hy2_connect_host() {
    local sni="$1" insecure="$2" default='' chosen='' answer=''
    default="$(get_meta '.hy2.connect_host')"
    if [[ "$insecure" != true ]] && domain_valid "$sni"; then
        default="$sni"
    fi
    [[ -n "$default" ]] || default="$(get_meta '.connect_host')"
    [[ -n "$default" ]] || default="$(get_public_ip || true)"
    printf '\n%s\n' '========== HY2 专用连接地址（不修改 SS/REALITY 的地址） =========='
    say "TLS SNI / 证书域名：$sni"
    ask chosen "HY2 客户端连接地址（建议同 SNI）[${default:-required}]: " "$default" || return 1
    hy2_address_valid "$chosen" || { fail 'HY2 连接地址无效（需要有效 IPv4/IPv6/域名）'; return 1; }
    if domain_valid "$chosen" && [[ ! "$chosen" =~ ^[0-9.]+$ ]]; then
        if ! hy2_domain_dns_check "$chosen"; then
            ask answer '仍强制使用该域名作为连接地址？[y/N]: ' N || return 1
            [[ "$answer" == [Yy] ]] || { warn '已取消使用该域名。请检查 DNS，或重新选择实际可达的连接 IP。'; return 1; }
        fi
    fi
    if [[ "$chosen" != "$sni" ]]; then
        warn "连接地址 $chosen 与 TLS SNI $sni 不同。只要地址实际可达且证书匹配 SNI，协议仍可正常使用。"
    fi
    HY2_CONNECT_HOST="$chosen"
}

# Update only the client address. No HY2 password rotation, config rewrite,
# service restart or unrelated protocol changes are involved.
change_hy2_connect_host() {
    ensure_state || return 1
    protocol_installed hy2 || { fail 'HY2 尚未安装。'; return 1; }
    local sni insecure
    sni="$(get_meta '.hy2.sni')"
    [[ -n "$sni" ]] || sni="$(get_meta '.cert_domain')"
    [[ -n "$sni" ]] || { fail 'HY2 TLS SNI 未记录，无法安全修改客户端地址。'; return 1; }
    insecure="$(get_meta '.hy2.insecure')"
    [[ -n "$insecure" ]] || insecure="$(get_meta '.hy2_insecure')"
    select_hy2_connect_host "$sni" "$insecure" || return 1
    set_meta_values --arg h "$HY2_CONNECT_HOST" \
        '.hy2 = (.hy2 // {}) | .hy2.connect_host=$h' || return 1
    say "HY2 分享链接的连接地址已更新为 $HY2_CONNECT_HOST，服务端和密码均未变化。"
    protocol_report hy2
}

# Avoid asking the connection address again after menu 1 already saved it.
ensure_connect_host() {
    local h
    h="$(get_meta '.connect_host')"
    if [[ -n "$h" ]]; then
        CONNECT_HOST="$h"
        return 0
    fi
    select_host
}

listener_lines() {
    local proto="$1" port="$2"
    if ! command_ok ss; then fail '未安装 ss（请在菜单 1 安装 iproute2）'; return 2; fi
    if [[ "$proto" == tcp ]]; then
        ss -H -ltnp "( sport = :${port} )" 2>/dev/null || true
    else
        ss -H -lunp "( sport = :${port} )" 2>/dev/null || true
    fi
}

# `ss -p` sometimes omits users/PID metadata even for root. The actual
# listening socket is authoritative; owner metadata is corroborating evidence.
# Still reject a listener that *explicitly* belongs to another process.
port_ready() {
    local proto="$1" port="$2" lines='' pid=''
    lines="$(listener_lines "$proto" "$port")" || return 1
    [[ -n "$lines" ]] || return 1
    if [[ "$lines" == *'users:'* && "$lines" != *'sing-box'* ]]; then
        if command_ok systemctl; then
            pid="$(systemctl show sing-box -p MainPID --value 2>/dev/null || true)"
        fi
        if [[ "$pid" =~ ^[1-9][0-9]*$ && "$lines" == *"pid=$pid,"* ]]; then
            return 0
        fi
        return 1
    fi
    return 0
}

# Verify the sockets after the daemon has actually initialized. Single-user SS
# serves TCP and UDP; REALITY serves TCP; HY2 serves UDP.
wait_for_inbound_ready() {
    local proto="$1" port="$2" i=0 max_wait="${S_SH_READY_WAIT_SECONDS:-12}"
    [[ "$max_wait" =~ ^[0-9]+$ ]] || max_wait=12
    (( max_wait >= 1 && max_wait <= 40 )) || max_wait=12
    while (( i < max_wait )); do
        if service_active; then
            case "$proto" in
                tcp+udp)
                    if port_ready tcp "$port" && port_ready udp "$port"; then return 0; fi
                    ;;
                tcp|udp)
                    if port_ready "$proto" "$port"; then return 0; fi
                    ;;
            esac
        fi
        (( i += 1 ))
        sleep 1
    done
    return 1
}

# Print actionable, secret-free diagnostics before reverting a failed install.
service_diagnostics() {
    local proto="$1" port="$2"
    warn "诊断：预期 ${proto}/${port}；sing-box 配置路径 $CONFIG"
    if command_ok systemctl; then
        printf '%s\n' '--- systemd service ExecStart / MainPID ---' >&2
        systemctl show sing-box -p MainPID -p ExecStart -p ActiveState -p SubState --no-pager 2>/dev/null | head -n 8 >&2 || true
        printf '%s\n' '--- sing-box service status (with latest error) ---' >&2
        systemctl status sing-box --no-pager -l -n 12 2>/dev/null >&2 || true
        printf '%s\n' '--- recent sing-box journal (max 35 lines) ---' >&2
        journalctl -u sing-box -n 35 --no-pager -o short-iso 2>/dev/null >&2 || true
    fi
    if command_ok ss; then
        printf '%s\n' '--- matching TCP / UDP listeners ---' >&2
        listener_lines tcp "$port" >&2 || true
        listener_lines udp "$port" >&2 || true
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
# Preflight for Let's Encrypt HTTP-01. Reusing a local cert never requires DNS checks.
cert_dns_preflight() {
    local domain="$1" current="" records="" line="" match=false
    if command_ok getent; then
        records="$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
    fi
    current="$(get_public_ip || true)"
    printf '  证书域名：%s\n  DNS A 记录：%s\n  VPS 公网 IPv4：%s\n' \
        "$domain" "${records:-未解析到 IPv4}" "${current:-未检测到}"
    if [[ -z "$records" ]]; then
        warn '未检测到 IPv4 A 记录。仅 IPv6 的域名请确保 AAAA 解析正确，且 HTTP/80 能从公网访问。'
        return 0
    fi
    if [[ -n "$current" ]]; then
        local ip
        IFS=',' read -r -a iplist <<< "$records"
        for ip in "${iplist[@]}"; do
            [[ "$ip" == "$current" ]] && match=true
        done
        if ! $match; then
            warn '域名 A 记录与本机公网 IPv4 不一致，HTTP-01 可能失败。'
            warn '若使用 Cloudflare 代理/CDN，请确认回源与 HTTP-01 挑战可达。'
            confirm '仍要继续申请证书？' || return 1
        fi
    fi
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
# x.sh-style interactive Y/n/q certificate flow, with safe ACME methods:
# Do not stop Nginx, rewrite sites-enabled, or touch the owner's HTTP website.
prepare_domain_cert() {
    local d='' saved='' connect='' choice='' method='' listeners='' cert_found=false
    ensure_state || return 1
    saved="$(get_meta '.cert_domain')"
    connect="$(get_meta '.connect_host')"
    if [[ -z "$saved" ]] && domain_valid "$connect"; then saved="$connect"; fi
    printf '\n%s\n' '========== TLS 域名证书申请 / 复用（参考 x.sh） =========='
    ask d "TLS 证书域名 [${saved:-输入域名}]: " "$saved" || return 1
    if [[ -z "$d" ]]; then
        warn '没有填写域名，已跳过证书流程；不影响 Shadowsocks。'
        return 0
    fi
    domain_valid "$d" || { fail "域名格式无效：$d"; return 1; }
    printf '  当前域名：%s\n' "$d"
    if find_cert_for_domain "$d"; then
        cert_found=true
        say "发现可复用的有效证书：$CERT_FILE"
        openssl x509 -in "$CERT_FILE" -noout -issuer -dates 2>/dev/null || true
    else
        say "尚未发现可用的 $d 证书。"
    fi
    while true; do
        printf '\n%s\n' "Y = 申请 / 重新申请 Let's Encrypt 证书" \
            'n = 复用 VPS 本地已有有效证书' \
            's = 生成自签证书（仅测试，客户端需 insecure=1）' \
            'q = 跳过证书配置（返回安装向导）'
        if $cert_found; then
            ask choice '请选择 [Y/n/s/q，默认 n]: ' n || return 1
        else
            ask choice '请选择 [Y/n/s/q，默认 Y]: ' Y || return 1
        fi
        case "$choice" in
            n|N)
                if ! find_cert_for_domain "$d"; then
                    warn '未找到可用的域名证书；可以重新申请或稍后手动上传后选择 n。'
                    continue
                fi
                say '本地证书有效，域名和私钥匹配，使用现有证书。'
                break
                ;;
            y|Y)
                cert_dns_preflight "$d" || { warn '已放弃本次申请，请先检查域名 DNS。'; continue; }
                listeners="$(listener_lines tcp 80 2>/dev/null || true)"
                if [[ -z "$listeners" ]]; then
                    say 'TCP/80 空闲，使用 certbot standalone HTTP-01 签发。'
                    method=standalone
                else
                    say 'TCP/80 已被网站占用，不停用 Nginx，不改变站点配置。'
                    say '采用 certbot webroot 验证；输入的网站目录必须能响应 /.well-known/acme-challenge/。'
                    method=webroot
                fi
                if ! cert_acme "$d" "$method"; then
                    warn '证书申请失败，原 Nginx 网站不受影响；可检查 DNS/80 端口后重试或选 q 跳过。'
                    continue
                fi
                if ! find_cert_for_domain "$d"; then
                    warn '申请结束但证书路径无效或私钥不匹配，请检查 certbot certificates。'
                    continue
                fi
                say "证书申请成功：$CERT_FILE"
                openssl x509 -in "$CERT_FILE" -noout -issuer -dates 2>/dev/null || true
                break
                ;;
            s|S)
                confirm '自签证书仅适合临时测试，会降低客户端验证安全性，确认使用？' || continue
                cert_selfsigned "$d" || { warn '生成自签证书失败'; continue; }
                break
                ;;
            q|Q|0)
                say '跳过 TLS 证书配置。SS 无须证书；HY2 安装时如有需要会再次询问。'
                return 0
                ;;
            *) warn '无效选择，请输入 Y / n / s / q。' ;;
        esac
    done
    CERT_DOMAIN="$d"
    set_meta_values --arg d "$d" --arg c "$CERT_FILE" --arg k "$KEY_FILE" \
        --argjson insecure "$CERT_INSECURE" \
        '.cert_domain=$d | .cert_file=$c | .key_file=$k | .hy2_insecure=$insecure'
    say "证书已就绪：$d（私钥仅保存在本机，不对外显示）"
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
    say '共享证书尚未准备或已失效，调用菜单 1 的通用证书处理流程。'
    prepare_domain_cert || return 1
    d="$(get_meta '.cert_domain')"
    c="$(get_meta '.cert_file')"
    k="$(get_meta '.key_file')"
    if [[ -z "$d" || -z "$c" || -z "$k" ]] || ! cert_valid "$d" "$c" "$k"; then
        fail '该协议需要有效 TLS 证书；证书配置已跳过或不匹配，无法继续。'
        return 1
    fi
    CERT_DOMAIN="$d"; CERT_FILE="$c"; KEY_FILE="$k"
    CERT_INSECURE="$(get_meta '.hy2_insecure')"
    [[ "$CERT_INSECURE" == true ]] || CERT_INSECURE=false
}

service_setup() {
    local bin unit override_dir override_file
    if service_exists; then
        # Only manage a unit that already targets /etc/sing-box. Do not hijack
        # another instance using a different config directory.
        if command_ok systemctl; then
            unit="$(systemctl cat sing-box 2>/dev/null || true)"
            if [[ "$unit" != *'/etc/sing-box'* && "$unit" != *"$CONFIG"* ]]; then
                fail '已有 sing-box 服务不使用 /etc/sing-box，拒绝接管。'
                return 1
            fi
            # Official package units commonly use -C /etc/sing-box (load
            # directory). Our installer writes one explicit config.json.
            # A managed drop-in ensures systemd runs this exact file.
            override_dir='/etc/systemd/system/sing-box.service.d'
            override_file="$override_dir/90-s-sh-config.conf"
            if [[ -e "$override_file" ]] && ! grep -Fqx '# S_SH_MANAGED_CONFIG_OVERRIDE_V4' "$override_file"; then
                fail "已有用户自定义 drop-in，拒绝覆盖：$override_file"
                return 1
            fi
            bin="$(command -v sing-box)" || return 1
            case "$bin" in
                /*) ;;
                *) fail 'sing-box 绝对路径无法确认'; return 1 ;;
            esac
            mkdir -p "$override_dir"
            local temp_override
            temp_override="$(mktemp "$override_dir/.s-sh-config.XXXXXX")" || return 1
            cat > "$temp_override" <<EOF
# S_SH_MANAGED_CONFIG_OVERRIDE_V4
[Service]
ExecStart=
ExecStart=$bin -D /var/lib/sing-box run -c $CONFIG
EOF
            chmod 644 "$temp_override"
            if [[ -f "$override_file" ]] && cmp -s "$temp_override" "$override_file"; then
                rm -f "$temp_override"
            else
                mv -f "$temp_override" "$override_file"
                systemctl daemon-reload || return 1
            fi
            say '已确保 systemd 明确加载 /etc/sing-box/config.json（不再依赖整个配置目录的自动扫描）。'
        fi
        return 0
    fi
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
ExecStart=$bin -D /var/lib/sing-box run -c $CONFIG
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
command_args="-D /var/lib/sing-box run -c $CONFIG"
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

# Sing-box's official v1.14.4 package ships with a 635-byte demo config
# containing an untagged Shadowsocks TCP/8080 inbound. It is not a user-
# installed SS node. Match the COMPLETE official JSON, including its public
# sample password, to avoid mistaking a user-configured SS node for a demo.
# We do not rewrite an active service's configuration automatically.
is_official_singbox_sample_config() {
    local file="$1"
    [[ -s "$file" ]] || return 1
    jq -e '. == {
      "log": {"level": "info"},
      "dns": {"servers": [{"type":"tls","tag":"google","server":"8.8.8.8"}]},
      "inbounds": [{
        "type":"shadowsocks", "listen":"::", "listen_port":8080,
        "network":"tcp", "method":"2022-blake3-aes-128-gcm",
        "password":"Gn1JUS14bLUHgv1cWDDp4A==",
        "multiplex":{"enabled":true,"padding":true}
      }],
      "outbounds": [{"type":"direct"}],
      "route": {"rules":[{"port":53,"action":"hijack-dns"}]}
    }' "$file" >/dev/null 2>&1
}

# Detect *retained* inbound sockets BEFORE restarting the shared sing-box service.
# "sing-box check" only validates syntax; it cannot detect an existing Nginx
# listener that clashes with an old inbound from an example config.
# The one automatic migration offered is the inactive, untagged legacy SS/8080
# entry colliding with Nginx. It is never silently removed: an explicit menu
# confirmation is required, and the original config is backed up on success.
preflight_retained_inbounds() {
    local candidate="$1" installing_tag="$2"
    local idx typ tag listen port row protocol lines matched_proto collision_lines
    local only_nginx answer temp now_active=false

    service_active && now_active=true
    while IFS=$'\t' read -r idx typ tag listen port <&3; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        case "$typ" in
            hysteria2|hysteria|tuic) protocol='udp' ;;
            shadowsocks) protocol='tcp+udp' ;;
            vless|vmess|trojan|anytls|mixed|socks|http|shadowtls|naive|snell) protocol='tcp' ;;
            *) continue ;; # Leave unusual/unknown inbound types to sing-box itself.
        esac

        matched_proto=''; collision_lines=''
        for row in tcp udp; do
            case "$protocol:$row" in
                tcp:tcp|udp:udp|tcp+udp:tcp|tcp+udp:udp) ;;
                *) continue ;;
            esac
            lines="$(listener_lines "$row" "$port")" || return 1
            [[ -n "$lines" ]] || continue
            # A running shared sing-box service may already own this retained
            # inbound. Do not treat its own sockets as an external collision.
            if $now_active && [[ "$lines" == *'sing-box'* ]]; then
                if ! grep -qv 'sing-box' <<< "$lines"; then continue; fi
            fi
            matched_proto="$row"
            collision_lines="$lines"
            break
        done
        [[ -n "$matched_proto" ]] || continue

        only_nginx=true
        while IFS= read -r row; do
            [[ "$row" == *'users:'* && "$row" == *'nginx'* && "$row" != *'sing-box'* ]] || only_nginx=false
        done <<< "$collision_lines"

        # Strictly limited to the stale, untagged Shadowsocks listener from the
        # default/old config. Existing named SS or running inbounds are retained.
        if [[ "$installing_tag" == 'hy2-in' && "$typ" == 'shadowsocks' \
           && "$tag" == '__UNNAMED__' && "$port" == '8080' \
           && ( "$listen" == '::' || "$listen" == '0.0.0.0' || "$listen" == '*' ) \
           && "$matched_proto" == 'tcp' ]] && $only_nginx && ! $now_active; then
            warn '发现未命名的旧 Shadowsocks 入站：TCP/8080，当前与 Nginx 伪装站冲突。'
            printf '%s\n' "$collision_lines" >&2
            say '此入站目前无法启动；可以只从本次新配置中移除，Nginx 8080、其他协议和 TLS 证书均不修改。'
            say '成功安装后，原完整配置将保存在 /etc/sing-box/backups/config.before-hy2-in-*.json。'
            if [[ ! -t 0 ]]; then
                fail '非交互式安装不自动删除旧 Shadowsocks；请从 HY2 菜单交互安装并确认归档。'
                return 1
            fi
            ask answer '确认归档冲突的旧 Shadowsocks 入站并继续安装 HY2 [Y/n]: ' Y || return 1
            case "$answer" in
                Y|y|yes|YES) ;;
                *) warn '已取消，原配置及运行服务均未修改。'; return 1 ;;
            esac
            temp="$(mktemp "$(dirname "$candidate")/.candidate-pruned.XXXXXXXX.json")" || return 1
            if ! jq --argjson i "$idx" '.inbounds |= (.[0:$i] + .[($i+1):])' "$candidate" > "$temp"; then
                rm -f "$temp"
                return 1
            fi
            chmod 600 "$temp"
            mv -f "$temp" "$candidate" || { rm -f "$temp"; return 1; }
            say '候选配置已排除冲突的旧 SS/8080，原配置备份仍在；继续验证并安装 HY2。'
            continue
        fi

        warn "旧入站 [$tag / $typ] 监听的 ${matched_proto}/${port} 已被其他进程占用，禁止覆盖或停止该进程："
        printf '%s\n' "$collision_lines" >&2
        fail '请先调整这个旧入站的端口，或处理旧配置后重试；原配置和 Nginx 均未修改。'
        return 1
    done 3< <(jq -r --arg tag "$installing_tag" '
       .inbounds | to_entries | reverse[] |
       select(.value.tag != $tag) |
       select((.value.listen_port | type) == "number") |
       [(.key | tostring), (.value.type // "unknown"),
        (.value.tag // "__UNNAMED__"), (.value.listen // "default"),
        (.value.listen_port | tostring)] | @tsv' "$candidate")
    return 0
}

# Build candidate with one named inbound replaced; all other inbounds are preserved.
apply_inbound() {
    local tag="$1" newfile="$2" temp='' snap='' meta_snap='' active_before=false
    local expected_port expected_proto when='' extra=''
    ensure_state || return 1
    temp="$(mktemp /etc/sing-box/.candidate.XXXXXX.json)" || return 1
    snap="$(mktemp "$BACKUPS"/.config.pre.XXXXXX)" || { rm -f "$temp"; return 1; }
    meta_snap="$(mktemp "$BACKUPS"/.meta.pre.XXXXXX)" || { rm -f "$temp" "$snap"; return 1; }
    cp -a "$CONFIG" "$snap" || return 1
    cp -a "$META" "$meta_snap" || return 1
    service_active && active_before=true
    # Fresh package installs have a demo Shadowsocks/8080 entry even if the
    # operator only ever chose HY2. Build a clean candidate (not a second
    # inbound added to the demo). On success, preserve the original full
    # sample config in BACKUPS; on failure, restore it and the former state.
    if [[ "$active_before" == false ]] && is_official_singbox_sample_config "$CONFIG"; then
        say '检测到 sing-box 官方默认演示配置（并非你安装的 SS 协议）。'
        say '将使用纯净配置安装所选协议，移除示例 SS/8080；Nginx 8080 不变。原配置会备份。'
        if ! jq -n --slurpfile node "$newfile" '
            {log:{level:"info",timestamp:true},
             inbounds:[$node[0]],
             outbounds:[{type:"direct",tag:"direct-out"}]}
        ' > "$temp"; then
            rm -f "$temp" "$snap" "$meta_snap"; return 1
        fi
    else
        if ! jq --arg tag "$tag" --slurpfile node "$newfile" '
            .inbounds = ([.inbounds[] | select(.tag != $tag)] + [$node[0]])
          ' "$CONFIG" > "$temp"; then
            rm -f "$temp" "$snap" "$meta_snap"; return 1
        fi
    fi
    if ! preflight_retained_inbounds "$temp" "$tag"; then
        rm -f "$temp" "$snap" "$meta_snap"
        return 1
    fi
    if ! sing-box check -c "$temp"; then
        warn '候选配置未通过 sing-box check，原服务和配置均未改变。'
        rm -f "$temp" "$snap" "$meta_snap"; return 1
    fi
    chmod 600 "$temp"
    mv -f "$temp" "$CONFIG"
    if ! service_setup || ! service_enable || ! service_restart; then
        warn 'sing-box 服务重启失败，将恢复安装前配置。'
        sleep 1  # Let journald flush a short-lived FATAL message before diagnosis.
        service_diagnostics "$(jq -r 'if .type=="hysteria2" or .type=="tuic" then "udp" else "tcp" end' "$newfile" 2>/dev/null)" "$(jq -r '.listen_port // 0' "$newfile" 2>/dev/null)"
        cp -a "$snap" "$CONFIG"; cp -a "$meta_snap" "$META"
        if $active_before; then service_restart || true; else service_stop || true; fi
        rm -f "$snap" "$meta_snap"
        return 1
    fi
    expected_port="$(jq -r '.listen_port' "$newfile")"
    expected_proto="$(jq -r 'if .type=="hysteria2" or .type=="tuic" then "udp" elif .type=="shadowsocks" then "tcp+udp" else "tcp" end' "$newfile")"
    say "等待实际监听就绪：${expected_proto}/${expected_port}（最多约 ${S_SH_READY_WAIT_SECONDS:-12} 秒）..."
    if ! wait_for_inbound_ready "$expected_proto" "$expected_port"; then
        warn "sing-box 未按预期监听 ${expected_proto}/${expected_port}，先输出诊断，再恢复旧配置。"
        service_diagnostics "$expected_proto" "$expected_port"
        cp -a "$snap" "$CONFIG"; cp -a "$meta_snap" "$META"
        if $active_before; then service_restart || true; else service_stop || true; fi
        rm -f "$snap" "$meta_snap"
        return 1
    fi
    when="$(date +%Y%m%d_%H%M%S)"
    cp -a "$snap" "$BACKUPS/config.before-${tag}-${when}.json"
    cp -a "$meta_snap" "$BACKUPS/meta.before-${tag}-${when}.json"
    rm -f "$snap" "$meta_snap"
    say "${tag} 已启动，${expected_proto}/${expected_port} 真实监听就绪。"
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
    say 'Shadowsocks (SS) 落地节点：单用户加密配置。'
    printf '%s\n' '1) 2022-blake3-aes-128-gcm（推荐）' '2) aes-128-gcm（传统兼容）'
    ask method_choice '请选择加密方式 [1]: ' 1 || return 1
    case "$method_choice" in
        1) method='2022-blake3-aes-128-gcm' ;;
        2) method='aes-128-gcm' ;;
        *) fail 'Invalid method'; return 1 ;;
    esac
    ask port "SS 落地监听端口 [$default_port]: " "$default_port" || return 1
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
    ensure_connect_host || return 1
    protocol_report ss
}

add_hy2() {
    ensure_tools || return 1
    ensure_singbox || return 1
    ensure_state || return 1
    local port='' password='' masq='' default_masq='https://www.bing.com' node=''
    local tcp443_mode=''
    say 'Hysteria2 is QUIC/UDP; default UDP port is 443, independent of TCP/443.'
    ask port 'HY2 UDP 监听端口 [443]: ' 443 || return 1
    check_port_available udp "$port" hy2-in || return 1
    port=$((10#$port))
    if jq -e '.inbounds[] | select(.tag=="hy2-in")' "$CONFIG" >/dev/null; then
        confirm 'Replace existing HY2 node and rotate its password?' || return 0
    fi
    ensure_shared_cert || return 1
    select_hy2_connect_host "$CERT_DOMAIN" "$CERT_INSECURE" || return 1
    if [[ -n "$(listener_lines tcp 8080 2>/dev/null || true)" ]]; then
        default_masq='http://127.0.0.1:8080'
    fi
    ask masq "未认证 HTTP/3 伪装网站 URL [$default_masq]: " "$default_masq" || return 1
    hy2_masq_validate "$masq" "$CERT_DOMAIN" || { fail '伪装 URL 无效或会导致本机回环'; return 1; }
    select_hy2_tcp443_mode "$CERT_DOMAIN" "$CERT_INSECURE" "$masq" || return 1
    tcp443_mode="$HY2_TCP443_MODE"
    password="$(openssl rand -base64 24 | tr -d '\r\n')"
    node="$(make_node_file)" || return 1
    jq -n --argjson port "$port" --arg password "$password" --arg cert "$CERT_FILE" \
        --arg key "$KEY_FILE" --arg masq "$masq" \
        '{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$port,
         users:[{password:$password}],masquerade:$masq,
         tls:{enabled:true,alpn:["h3"],certificate_path:$cert,key_path:$key}}' > "$node"
    if ! apply_inbound hy2-in "$node"; then rm -f "$node"; return 1; fi
    rm -f "$node"
    # Do not overwrite the global .connect_host used by SS/REALITY.
    local wanted=false
    [[ "$tcp443_mode" != off ]] && wanted=true
    if ! set_meta_values --arg sni "$CERT_DOMAIN" --argjson insecure "$CERT_INSECURE" \
        --arg h "$HY2_CONNECT_HOST" --arg mode "$tcp443_mode" --argjson wanted "$wanted" \
        '.hy2={sni:$sni,insecure:$insecure,connect_host:$h,tcp443_mode:$mode,tcp443_wanted:$wanted}'; then
        warn 'HY2 已安装，但节点地址元数据保存失败，请从菜单 6 修复。'
        return 1
    fi
    if [[ "$tcp443_mode" == 'nginx' ]]; then
        if ! enable_hy2_tcp443_site "$CERT_DOMAIN" "$masq"; then
            warn 'HY2 的 UDP 入站已成功安装，但 TCP/443 HTTPS 伪装站启用失败。'
            warn '可以先使用 HY2 节点，修复 Nginx 后通过 HY2 菜单 5 再启用回落。'
            protocol_report hy2
            return 1
        fi
    elif [[ "$tcp443_mode" == 'reality' ]]; then
        say '已复用 REALITY TCP/443 的 HTTPS 握手回落；HY2 UDP/443 独立运行。'
    else
        if hy2_443_owned_site_exists "$CERT_DOMAIN"; then
            disable_hy2_tcp443_site || warn '无法关闭旧的 s.sh 专属 TCP/443 站点，请手动在菜单 5 检查。'
        fi
    fi
    protocol_report hy2
}

check_tls_endpoint() {
    local address="$1" port="$2" sni="$3" timeout_sec="${4:-8}" pem=''
    command_ok timeout || { fail 'timeout missing'; return 1; }
    pem="$(timeout "$timeout_sec" openssl s_client -connect "$address:$port" -servername "$sni" \
        -showcerts < /dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)"
    [[ "$pem" == *'-----BEGIN CERTIFICATE-----'* ]] || return 1
    openssl x509 -noout -checkhost "$sni" <<< "$pem" 2>/dev/null | grep -qi 'does match'
}

# Optionally create a new isolated HTTPS bridge. Never edit the existing HTTP site.
bridge_port_reserved_by_inbound() {
    local port="$1"
    jq -e --argjson p "$port" '.inbounds[]? |
      select(.listen_port==$p and (.type!="hysteria2" and .type!="hysteria" and .type!="tuic"))' \
      "$CONFIG" >/dev/null 2>&1
}

# Automatically discover an already-running loopback HTTPS endpoint whose
# certificate matches the REALITY SNI. No internal port is requested from the
# user. Only inspect ports in the bridge allocation range; skip ports already
# reserved by sing-box inbounds. If none matches, add_reality() creates a
# managed bridge and create_bridge() selects a free port automatically.
find_local_https_fallback_port() {
    local sni="$1" line endpoint candidate bind_addr
    command_ok ss || return 1
    while IFS= read -r line; do
        endpoint="$(awk '{print $4}' <<< "$line")"
        candidate="${endpoint##*:}"
        bind_addr="${endpoint%:*}"
        [[ "$candidate" =~ ^[0-9]+$ ]] || continue
        (( 10#$candidate >= 8081 && 10#$candidate <= 8199 )) || continue
        [[ "$candidate" != 8090 ]] || continue
        # This fallback is configured as 127.0.0.1 in sing-box, so only
        # reuse listeners reachable through IPv4 loopback/wildcard sockets.
        [[ "$bind_addr" != \[* ]] || continue
        bridge_port_reserved_by_inbound "$candidate" && continue
        if check_tls_endpoint 127.0.0.1 "$candidate" "$sni" 3; then
            printf '%s' "$candidate"
            return 0
        fi
    done < <(ss -H -ltnp 2>/dev/null)
    return 1
}
BRIDGE_NEW_PATH=''
BRIDGE_NEW_BACKUP=''
create_bridge() {
    local d="$1" fallback_url="${2:-http://127.0.0.1:8080}" bridge_port='' file='' temp='' existing='' other=''
    local header_host='$host'
    hy2_masq_validate "$fallback_url" "$d" || {
        fail '本机 TLS 桥接的回落 URL 无效或可能导致代理回环。'; return 1;
    }
    if [[ "$fallback_url" == http://127.0.0.1:8080* || "$fallback_url" == http://localhost:8080* ]]; then
        [[ -n "$(listener_lines tcp 8080 2>/dev/null || true)" ]] || {
            fail '没有本机伪装站 127.0.0.1:8080'; return 1;
        }
    else
        header_host='$proxy_host'
    fi
    command_ok nginx || { fail 'Nginx 尚未安装'; return 1; }
    [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || return 1
    nginx -t >/dev/null 2>&1 || { fail '现有 Nginx 配置错误，拒绝修改。'; return 1; }
    file="/etc/nginx/conf.d/s-script-reality-bridge-$d.conf"
    if [[ -e "$file" || -L "$file" ]]; then
        [[ ! -L "$file" ]] && head -n 1 "$file" | grep -Fqx "$OWN_BRIDGE_MARKER" || {
            fail "发现不属于 s.sh 的 Nginx 文件：$file"; return 1;
        }
        # Reuse only the bridge defined in our own file and verify its cert.
        bridge_port="$(sed -nE 's/^[[:space:]]*listen[[:space:]]+127[.]0[.]0[.]1:([0-9]+)[[:space:]]+ssl;.*/\1/p' "$file" | head -n1)"
        if port_valid "$bridge_port" && ! bridge_port_reserved_by_inbound "$bridge_port" &&
            grep -Fq "proxy_pass $fallback_url;" "$file" &&
            check_tls_endpoint 127.0.0.1 "$bridge_port" "$d"; then
            BRIDGE_PORT="$bridge_port"; BRIDGE_NEW_PATH=''; BRIDGE_NEW_BACKUP=''
            say "复用 s.sh 本机 HTTPS 桥接：127.0.0.1:$bridge_port"
            return 0
        fi
        existing="$(mktemp /tmp/s-nginx-previous.XXXXXXXX)" || return 1
        cp -a "$file" "$existing" || { rm -f "$existing"; return 1; }
        if port_valid "$bridge_port" && ! bridge_port_reserved_by_inbound "$bridge_port"; then
            other="$(listener_lines tcp "$bridge_port" 2>/dev/null || true)"
            if [[ -z "$other" || "$other" == *nginx* ]]; then
                : # Recreate previously owned bridge on its original port.
            else
                bridge_port=''
            fi
        else
            bridge_port=''
        fi
    fi
    if [[ -z "$bridge_port" ]]; then
        for other in $(seq 8081 8199); do
            [[ "$other" == 8090 ]] && continue
            if ! bridge_port_reserved_by_inbound "$other" &&
                [[ -z "$(listener_lines tcp "$other" 2>/dev/null || true)" ]]; then
                bridge_port="$other"; break
            fi
        done
    fi
    if ! port_valid "$bridge_port"; then
        rm -f "$existing"
        fail '8081..8199 无空闲本机 TLS 桥接端口。'; return 1
    fi
    temp="$(mktemp /etc/nginx/conf.d/.s-bridge.XXXXXXXX)" || { rm -f "$existing"; return 1; }
    cat > "$temp" <<EOF
$OWN_BRIDGE_MARKER
server {
    listen 127.0.0.1:$bridge_port ssl;
    server_name $d;
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    location / {
        proxy_pass $fallback_url;
        proxy_ssl_server_name on;
        proxy_set_header Host $header_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
    chmod 644 "$temp"
    mv -f "$temp" "$file"
    if ! nginx -t >/dev/null 2>&1 || ! nginx_reload_safely; then
        if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
        nginx_reload_safely || true
        rm -f "$existing"; return 1
    fi
    if ! check_tls_endpoint 127.0.0.1 "$bridge_port" "$d"; then
        warn '本机 TLS 桥接握手检查失败，已恢复 Nginx 原配置。'
        if [[ -n "$existing" ]]; then cp -a "$existing" "$file"; else rm -f "$file"; fi
        nginx_reload_safely || true
        rm -f "$existing"; return 1
    fi
    BRIDGE_PORT="$bridge_port"
    BRIDGE_NEW_PATH="$file"
    BRIDGE_NEW_BACKUP="$existing"
    say "本机 HTTPS 桥接就绪：127.0.0.1:$bridge_port → $fallback_url"
}

# REALITY occupies only TCP; HY2 occupies UDP. When REALITY listens on
# TCP/443, its REALITY handshake target is the only legitimate TCP/443 HTTPS
# fallback path. Nginx must listen on loopback TLS, never concurrently on 443.
reality_tcp443_configured() {
    [[ -f "$CONFIG" ]] || return 1
    jq -e '.inbounds[]? | select(.tag=="vless-in" and .type=="vless" and
        .listen_port==443 and .tls.reality.enabled==true)' "$CONFIG" >/dev/null 2>&1
}
reality_handshake_params() {
    [[ -f "$CONFIG" ]] || return 1
    jq -r '[.inbounds[]? | select(.tag=="vless-in") |
      [(.tls.reality.handshake.server//""),
       ((.tls.reality.handshake.server_port//0)|tostring),
       (.tls.server_name//"") ] | @tsv][0] // empty' "$CONFIG"
}
reality_tcp443_fallback_check() {
    reality_tcp443_configured || return 1
    local target port sni
    IFS=$'\t' read -r target port sni <<< "$(reality_handshake_params)"
    [[ -n "$target" && -n "$sni" ]] && port_valid "$port" || return 1
    if [[ "$target" == '127.0.0.1' || "$target" == '::1' || "$target" == 'localhost' ]]; then
        # An unreachable internal TLS site means the REALITY fallback is broken.
        check_tls_endpoint "$target" "$port" "$sni"
    else
        # A remote handshake target belongs to REALITY itself; do not rewrite
        # its SNI or credentials when HY2 is installed afterwards.
        say "REALITY TCP/443 已配置远程 HTTPS 握手回落：$target:$port（SNI $sni）。"
        check_tls_endpoint "$target" "$port" "$sni"
    fi
}

# Preserve an s.sh-owned HY2 public HTTPS site while handing TCP/443 to
# REALITY. Never touch user-owned Nginx sites or another listener on this port.
REALITY_MIGRATED_HY2_FILE=''
REALITY_MIGRATED_HY2_BACKUP=''
release_hy2_public443_for_reality() {
    local domain="$1" file='' occupied='' backup=''
    file="$(hy2_443_path "$domain")" || return 1
    hy2_443_owned_site_exists "$domain" || return 0
    occupied="$(listener_lines tcp 443)" || return 1
    if [[ -z "$occupied" ]]; then
        warn '发现旧 HY2 专属 TCP/443 站点文件，但未发现监听；将暂时归档并验证 Nginx。'
    elif [[ "$occupied" != *nginx* ]] || grep -qv nginx <<< "$occupied"; then
        fail 'TCP/443 不是纯 Nginx 监听，拒绝迁移以免影响其他服务。'; return 1
    fi
    command_ok nginx && nginx -t >/dev/null 2>&1 || { fail 'Nginx 配置未通过检查，不迁移。'; return 1; }
    backup="$(mktemp /tmp/s-sh-hy2-public443.XXXXXXXX)" || return 1
    cp -a -- "$file" "$backup" || { rm -f "$backup"; return 1; }
    rm -f -- "$file" || { rm -f "$backup"; return 1; }
    if ! nginx -t >/dev/null 2>&1 || ! nginx_reload_safely; then
        cp -a -- "$backup" "$file"
        nginx_reload_safely || true
        rm -f "$backup"
        fail '迁移 HY2 HTTPS 站点失败，已恢复 TCP/443 原站点。'; return 1
    fi
    # A graceful Nginx reload may take a moment to close the old listener.
    # REALITY must not restart until TCP/443 is genuinely released.
    local retry=0
    while (( retry < 10 )); do
        occupied="$(listener_lines tcp 443)" || occupied=''
        [[ -z "$occupied" || "$occupied" == *sing-box* && "$occupied" != *nginx* ]] && break
        sleep 1
        (( retry += 1 ))
    done
    if [[ -n "$occupied" && "$occupied" != *sing-box* ]]; then
        cp -a -- "$backup" "$file"
        nginx_reload_safely || true
        rm -f "$backup"
        fail 'Nginx 仍监听 TCP/443（可能有其他站点）；安全取消迁移并恢复原配置。'; return 1
    fi
    REALITY_MIGRATED_HY2_FILE="$file"
    REALITY_MIGRATED_HY2_BACKUP="$backup"
    say '已将 s.sh 自建 HY2 TCP/443 网站转为 REALITY 回落使用的本机 HTTPS 桥接；HY2 UDP/443 不受影响。'
}
restore_reality_migrated_site() {
    if [[ -n "$REALITY_MIGRATED_HY2_FILE" && -f "$REALITY_MIGRATED_HY2_BACKUP" ]]; then
        cp -a -- "$REALITY_MIGRATED_HY2_BACKUP" "$REALITY_MIGRATED_HY2_FILE" || return 1
        nginx -t >/dev/null 2>&1 && nginx_reload_safely || warn '回滚了 HY2 站点文件，但 Nginx reload 未成功，请检查 nginx -t。'
        rm -f -- "$REALITY_MIGRATED_HY2_BACKUP"
    fi
    REALITY_MIGRATED_HY2_FILE=''; REALITY_MIGRATED_HY2_BACKUP=''
}
commit_reality_migrated_site() {
    if [[ -n "$REALITY_MIGRATED_HY2_BACKUP" && -f "$REALITY_MIGRATED_HY2_BACKUP" ]]; then
        local when
        when="$(date +%Y%m%d_%H%M%S)"
        cp -a -- "$REALITY_MIGRATED_HY2_BACKUP" "$BACKUPS/hy2-public443.before-reality-${when}.conf" || true
        rm -f -- "$REALITY_MIGRATED_HY2_BACKUP"
    fi
    REALITY_MIGRATED_HY2_FILE=''; REALITY_MIGRATED_HY2_BACKUP=''
}
nginx_reload_safely() {
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then systemctl reload nginx
        else systemctl start nginx; fi
    else
        nginx -s reload
    fi
}

# Hysteria2 standalone (h.sh) supports masquerade.listenHTTPS directly.
# sing-box's HY2 inbound only provides HTTP/3 masquerade; implement its
# optional TCP/443 counterpart with a separately owned Nginx HTTPS site.
# With REALITY/443, the HTTPS handshake is instead forwarded to a loopback
# Nginx TLS bridge; no second public TCP/443 listener is created.
HY2_443_MARKER='# S_SH_MANAGED_HY2_TCP443_V1'
HY2_TCP443_MODE='false'
hy2_443_path() {
    local domain="$1"
    domain_valid "$domain" || return 1
    printf '/etc/nginx/conf.d/s-script-hy2-tcp443-%s.conf' "$domain"
}
hy2_443_owned_site_exists() {
    local file
    file="$(hy2_443_path "$1")" || return 1
    [[ -f "$file" ]] && head -n 1 "$file" | grep -Fqx "$HY2_443_MARKER"
}

# Strict URL validation; never interpolate untrusted semicolons, newlines,
# dollar signs or other Nginx syntax into a generated configuration file.
# Also reject local HTTPS/443 recursion (same SNI, same TCP cover).
hy2_masq_validate() {
    local url="$1" domain="${2:-}"
    command_ok python3 || { fail 'python3 is required for masquerade URL validation'; return 1; }
    python3 - "$url" "$domain" <<'PY_VALIDATE_URL'
import re
import sys
from urllib.parse import urlsplit
url, domain = sys.argv[1:]
if len(url) > 2048 or not re.fullmatch(r'[a-zA-Z0-9:/._~%?&=+,-]+', url):
    sys.exit(1)
try:
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.fragment:
        sys.exit(1)
    port = u.port
    host = u.hostname.lower()
    # Host may be FQDN or IPv4; the server's local fallback can use loopback.
    if not re.fullmatch(r'[a-z0-9.-]+', host):
        sys.exit(1)
    if port is not None and not (1 <= port <= 65535):
        sys.exit(1)
    if u.scheme == 'https' and port in (None, 443) and host in (
        domain.lower(), '127.0.0.1', 'localhost', '0.0.0.0'
    ):
        sys.exit(1)
except ValueError:
    sys.exit(1)
PY_VALIDATE_URL
}

# Check whether TCP 443 belongs to our previously created website. This
# avoids treating a reinstallation as an external port conflict.
hy2_tcp443_preflight() {
    local domain="$1" insecure="$2" target="$3" occupied=''
    [[ "$insecure" != true ]] || { warn '自签证书不能提供浏览器可信的 TCP/443 HTTPS 网站，请选择关闭回落。'; return 1; }
    domain_valid "$domain" || return 1
    hy2_masq_validate "$target" "$domain" || { warn '伪装目标 URL 不安全/不支持（可能形成自身代理循环）。'; return 1; }
    command_ok nginx || { warn 'Nginx 未安装，无法提供 TCP/443 HTTPS 伪装站。'; return 1; }
    nginx -t >/dev/null 2>&1 || { warn '现有 Nginx 配置检查失败，不能安全开启新的 HTTPS 站点。'; return 1; }
    if reality_tcp443_configured; then
        warn 'REALITY 正在使用 TCP/443；HY2 不能另外创建 Nginx TCP/443，须复用 REALITY 的 HTTPS 握手回落。'
        return 1
    fi
    occupied="$(listener_lines tcp 443)" || return 1
    if [[ -n "$occupied" ]]; then
        if hy2_443_owned_site_exists "$domain" && \
           [[ "$occupied" == *nginx* ]] && \
           ! grep -qv 'nginx' <<< "$occupied" && \
           check_tls_endpoint 127.0.0.1 443 "$domain"; then
            say 'TCP/443 已由本脚本之前创建的 HY2 HTTPS 伪装站监听；将安全复用。'
        else
            warn 'TCP/443 已被其它进程/网站占用，不会停止 Xray、REALITY 或 Nginx 已有网站。'
            printf '%s\n' "$occupied" >&2
            return 1
        fi
    fi
    # For local HTTP masquerade, verify there is a backend; remote URLs are
    # handled by Nginx's proxy_pass and do not require local TCP 8080.
    if [[ "$target" == http://127.0.0.1:8080* || "$target" == http://localhost:8080* ]]; then
        [[ -n "$(listener_lines tcp 8080)" ]] || {
            warn '伪装目标是本地 HTTP/8080，但没有监听该端口的网站。'; return 1;
        }
    fi
    return 0
}

# Mirror h.sh's install-time 1=enable(default), 2=disable choice. Keep UDP
# completely independent of the TCP camouflage switch.
select_hy2_tcp443_mode() {
    local domain="$1" insecure="$2" target="$3" choice='' real_sni=''
    printf '\n%s\n' '========== HY2 TCP/443 HTTPS 伪装 / 回落 =========='
    if reality_tcp443_configured; then
        real_sni="$(jq -r '[.inbounds[]? | select(.tag=="vless-in") | .tls.server_name][0]//empty' "$CONFIG")"
        printf '%s\n' '检测到 REALITY 已配置 TCP/443（HY2 仍使用 UDP/443）。' \
          '1) 复用 REALITY 的 TCP/443 HTTPS 握手回落（默认，不启动第二个监听）' \
          '2) 不要求 HY2 额外的 TCP HTTPS 伪装' \
          "说明：浏览器走 REALITY 的 SNI ($real_sni) 和其回落站点；HY2 HTTP/3 伪装保持独立。"
        [[ "$real_sni" == "$domain" ]] || warn "REALITY SNI=$real_sni 与 HY2 SNI=$domain 不同；不会自动修改 REALITY 客户端参数。"
        while true; do
            ask choice '请选择 [1/2，默认 1]: ' 1 || return 1
            case "$choice" in
                1)
                    if reality_tcp443_fallback_check; then
                        HY2_TCP443_MODE='reality'; return 0
                    fi
                    warn 'REALITY 的内部 HTTPS 握手目标检测失败；请先修复 REALITY 回落，或选择 2。'
                    ;;
                2) HY2_TCP443_MODE='off'; return 0 ;;
                *) warn '请输入 1 或 2。' ;;
            esac
        done
    fi
    printf '%s\n' '1) 启用 Nginx TCP/443 HTTPS 伪装站（默认，HY2 UDP 独立）' \
        '2) 关闭 TCP/443 HTTPS 伪装站（仅保留 HY2 UDP）' \
        '说明：如果之后安装 REALITY TCP/443，脚本将迁移 s.sh 自建 HTTPS 站点到本机 TLS 桥接。'
    while true; do
        ask choice '请选择 [1/2，默认 1]: ' 1 || return 1
        case "$choice" in
            1)
                if hy2_tcp443_preflight "$domain" "$insecure" "$target"; then
                    HY2_TCP443_MODE='nginx'; return 0
                fi
                warn '无法启用独立 TCP/443 HTTPS 伪装；可选择 2 仅部署 HY2 UDP。'
                ;;
            2) HY2_TCP443_MODE='off'; return 0 ;;
            *) warn '请输入 1 或 2。' ;;
        esac
    done
}

enable_hy2_tcp443_site() {
    ensure_tools && ensure_state || return 1
    local domain="${1:-}" cert key target="${2:-}" existing='' tmp='' dest='' before='' lines='' v6listen=''
    [[ -n "$domain" ]] || domain="$(get_meta '.hy2.sni')"
    [[ -n "$domain" ]] || domain="$(get_meta '.cert_domain')"
    cert="$(get_meta '.cert_file')"
    key="$(get_meta '.key_file')"
    [[ -n "$target" ]] || target="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.masquerade][0]//empty' "$CONFIG")"
    if reality_tcp443_configured; then
        if reality_tcp443_fallback_check; then
            say 'REALITY TCP/443 已接管 HTTPS 回落；不会额外创建 Nginx TCP/443 监听。'
            return 0
        fi
        fail 'REALITY TCP/443 回落未通过检查，不能创建第二个 TCP/443 监听。'; return 1
    fi
    [[ -n "$domain" && -f "$cert" && -f "$key" ]] || {
        fail '请先在菜单 1 配置有效证书，并安装 HY2。'; return 1;
    }
    cert_valid "$domain" "$cert" "$key" || { fail 'TCP/443 回落需要有效且匹配 SNI 的证书。'; return 1; }
    hy2_tcp443_preflight "$domain" "$(get_meta '.hy2_insecure')" "$target" || return 1
    dest="$(hy2_443_path "$domain")" || return 1
    if [[ -e "$dest" || -L "$dest" ]]; then
        head -n 1 "$dest" | grep -Fqx "$HY2_443_MARKER" || {
            fail "发现非 s.sh 所属的 Nginx 配置：$dest"; return 1;
        }
        before="$(mktemp /tmp/s-hy2-nginx.XXXXXXXX)" || return 1
        cp -a "$dest" "$before" || { rm -f "$before"; return 1; }
    fi
    # Nginx generally supports IPv6 sockets. Only add the IPv6 listener when
    # the kernel exposes IPv6; otherwise the IPv4 listener remains sufficient.
    [[ -s /proc/net/if_inet6 ]] && v6listen='    listen [::]:443 ssl;'
    tmp="$(mktemp /etc/nginx/conf.d/.s-hy2-cover.XXXXXXXX)" || return 1
    local header_host='$host'
    if [[ "$target" != http://127.0.0.1:8080* && "$target" != http://localhost:8080* ]]; then
        header_host='$proxy_host'
    fi
    cat > "$tmp" <<EOF
$HY2_443_MARKER
# HY2 TCP/443 HTTPS cover; mirrors sing-box HY2 HTTP/3 masquerade target.
# Managed exclusively by s.sh; user-owned sites are never rewritten.
server {
    listen 443 ssl;
$v6listen
    server_name $domain;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    location / {
        proxy_pass $target;
        proxy_ssl_server_name on;
        proxy_set_header Host $header_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
    chmod 644 "$tmp"
    mv -f "$tmp" "$dest"
    if ! nginx -t; then
        if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
        rm -f "$before"
        fail 'Nginx 拒绝新的 TCP/443 配置，已恢复原配置。'; return 1
    fi
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then
                if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
                if nginx -t >/dev/null 2>&1; then systemctl reload nginx || true; fi
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
        warn 'TCP/443 HTTPS 证书验证失败，撤回本次 s.sh 创建/更新的网站。'
        if [[ -n "$before" ]]; then cp -a "$before" "$dest"; else rm -f "$dest"; fi
        if command_ok systemctl; then systemctl reload nginx || true; else nginx -s reload || true; fi
        rm -f "$before"; return 1
    fi
    rm -f "$before"
    say "HY2 TCP/443 HTTPS 伪装已启用：$domain → $target（UDP 监听独立）"
}

disable_hy2_tcp443_site() {
    local file='' backup='' d=''
    d="$(get_meta '.hy2.sni')"
    [[ -n "$d" ]] || d="$(get_meta '.cert_domain')"
    [[ -n "$d" ]] || { fail '没有记录 HY2 证书域名'; return 1; }
    file="$(hy2_443_path "$d")" || return 1
    [[ -f "$file" ]] || { say '未发现 s.sh 创建的 HY2 TCP/443 伪装站。'; return 0; }
    head -n 1 "$file" | grep -Fqx "$HY2_443_MARKER" || {
        fail '该网站不属于 s.sh，拒绝删除。'; return 1;
    }
    command_ok nginx || return 1
    backup="$(mktemp /tmp/s-hy2-cover-backup.XXXXXXXX)" || return 1
    cp -a "$file" "$backup"
    rm -f "$file"
    if ! nginx -t; then cp -a "$backup" "$file"; rm -f "$backup"; return 1; fi
    if command_ok systemctl; then
        if systemctl is-active --quiet nginx; then
            if ! systemctl reload nginx; then
                cp -a "$backup" "$file"; systemctl reload nginx || true; rm -f "$backup"; return 1
            fi
        fi
    else
        if ! nginx -s reload; then cp -a "$backup" "$file"; rm -f "$backup"; return 1; fi
    fi
    rm -f "$backup"
    say '已关闭 s.sh 专属 HY2 TCP/443 网站；UDP HY2、原 Nginx 网站和其他协议均未改动。'
}

manage_hy2_tcp443_site() {
    local choice='' domain='' target='' mode=''
    domain="$(get_meta '.hy2.sni')"
    [[ -n "$domain" ]] || domain="$(get_meta '.cert_domain')"
    target="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.masquerade][0]//empty' "$CONFIG" 2>/dev/null || true)"
    printf '%s\n' 'HY2 TCP/443 HTTPS 伪装/回落（与 UDP/443 独立）：' \
        '1) 启用 / 修复（若 REALITY 占用 TCP/443，则复用其回落）' \
        '2) 关闭 HY2 自建的公开 HTTPS 站点（不改 REALITY）' \
        '0) 返回'
    if reality_tcp443_configured; then
        say 'REALITY 已接管 TCP/443，此菜单不会停止其 HTTPS 握手回落。'
    fi
    ask choice '请选择 [0]: ' 0 || return 1
    case "$choice" in
        1)
            protocol_installed hy2 || { fail 'HY2 尚未安装。'; return 1; }
            if enable_hy2_tcp443_site "$domain" "$target"; then
                mode=nginx
                reality_tcp443_configured && mode=reality
                set_meta_values --arg m "$mode" '.hy2.tcp443_wanted=true | .hy2.tcp443_mode=$m'
            fi
            ;;
        2)
            disable_hy2_tcp443_site || return 1
            set_meta_values '.hy2.tcp443_wanted=false | .hy2.tcp443_mode="off"'
            ;;
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
    nginx_reload_safely || true
    [[ -z "$BRIDGE_NEW_BACKUP" ]] || rm -f "$BRIDGE_NEW_BACKUP"
    BRIDGE_NEW_PATH=''; BRIDGE_NEW_BACKUP=''
}

REALITY_CONNECT_HOST=''
select_reality_connect_host() {
    local sni="$1" mode="$2" default='' chosen='' answer=''
    default="$(get_meta '.reality.connect_host')"
    if [[ "$mode" == 2 || "$mode" == 3 ]] && domain_valid "$sni"; then
        default="$sni"
    fi
    [[ -n "$default" ]] || default="$(get_meta '.connect_host')"
    [[ -n "$default" ]] || default="$(get_public_ip || true)"
    printf '\n%s\n' '========== REALITY 客户端连接地址 =========='
    say "REALITY TLS SNI：$sni；远程回落 SNI 不是你服务器的连接地址。"
    ask chosen "REALITY 客户端连接域名/IP [${default:-required}]: " "$default" || return 1
    hy2_address_valid "$chosen" || { fail '无效连接地址（需要 IP 或域名）'; return 1; }
    if domain_valid "$chosen" && [[ ! "$chosen" =~ ^[0-9.]+$ ]]; then
        if ! hy2_domain_dns_check "$chosen" REALITY; then
            ask answer '仍强制使用该域名作为 REALITY 连接地址？[y/N]: ' N || return 1
            [[ "$answer" == [Yy] ]] || return 1
        fi
    fi
    REALITY_CONNECT_HOST="$chosen"
}

add_reality() {
    ensure_tools || return 1
    ensure_singbox || return 1
    ensure_state || return 1
    local port='' mode='' sni='' target='' targetport=443 uuid='' sid='' keys='' priv='' pub='' node=''
    local default_mode=2 owned_hy2_site=false old_hy2_sni='' saved_sni=''
    local reality_before='' was_active=false
    saved_sni="$(get_meta '.reality.sni')"
    old_hy2_sni="$(get_meta '.hy2.sni')"
    [[ -n "$old_hy2_sni" ]] || old_hy2_sni="$(get_meta '.cert_domain')"
    ask port 'REALITY TCP 监听端口 [443]: ' 443 || return 1
    port_valid "$port" || { fail "无效 TCP 端口：$port"; return 1; }
    port=$((10#$port))
    if jq -e '.inbounds[]? | select(.tag=="vless-in")' "$CONFIG" >/dev/null; then
        confirm '替换现有 REALITY？将重新生成 UUID、密钥和短 ID。' || return 0
    fi
    if [[ "$port" == 443 ]] && hy2_443_owned_site_exists "$old_hy2_sni"; then
        owned_hy2_site=true
        say '检测到 s.sh 自建 HY2 TCP/443 HTTPS 网站。将先建立本机 TLS 桥接，再安全移交 TCP/443 给 REALITY。'
    fi
    # Mode 2 is now the automatic local-fallback mode and is the default:
    # discover a matching HTTPS listener, otherwise create a managed bridge.
    # Mode 3 explicitly forces the managed Nginx -> HTTP/8080 bridge.
    $owned_hy2_site && default_mode=2
    printf '%s\n' 'REALITY TLS 握手失败后的 HTTPS 回落方式：' \
        '1) 远程 HTTPS 网站 443（不修改 Nginx）' \
        '2) 自动复用本机 HTTPS；未发现则自动创建桥接（内部端口自动分配）' \
        '3) 强制创建/更新 Nginx 本机 HTTPS→HTTP/8080 桥接（内部端口自动分配）' \
        '0) 取消'
    ask mode "请选择 [$default_mode]: " "$default_mode" || return 1
    if $owned_hy2_site && [[ "$mode" == 1 ]]; then
        fail 'HY2 已占用 TCP/443 的自建伪装网站；为保留原网站，请选择模式 2 或 3。'
        return 1
    fi
    case "$mode" in
        1)
            ask sni "远程 REALITY SNI [${saved_sni:-addons.mozilla.org}]: " "${saved_sni:-addons.mozilla.org}" || return 1
            domain_valid "$sni" || { fail "无效 SNI：$sni"; return 1; }
            ask target "远程 HTTPS 目标站 [$sni]: " "$sni" || return 1
            domain_valid "$target" || { fail "无效回落目标：$target"; return 1; }
            ask targetport '远程 HTTPS 端口 [443]: ' 443 || return 1
            port_valid "$targetport" || return 1
            if ! check_tls_endpoint "$target" "$targetport" "$sni"; then
                fail '目标 HTTPS 的证书未匹配 SNI，不能使用该远程握手目标。'; return 1
            fi
            ;;
        2)
            ensure_shared_cert || return 1
            [[ "$CERT_INSECURE" != true ]] || {
                fail 'REALITY 本机 HTTPS 回落要求可信证书；请先准备正式证书。'; return 1;
            }
            local expected_sni="${old_hy2_sni:-$CERT_DOMAIN}"
            [[ -n "$expected_sni" ]] || expected_sni="$CERT_DOMAIN"
            ask sni "本机 HTTPS 证书域名 / SNI [${expected_sni:-required}]: " "$expected_sni" || return 1
            domain_valid "$sni" || return 1
            target=127.0.0.1
            local auto_fallback_url='http://127.0.0.1:8080'
            if $owned_hy2_site; then
                # Preserve the exact HY2 cover destination when handing public
                # TCP/443 from Nginx to REALITY. Internal bridge port is dynamic.
                auto_fallback_url="$(jq -r '[.inbounds[]? | select(.tag=="hy2-in") | .masquerade][0] // "http://127.0.0.1:8080"' "$CONFIG")"
                cert_valid "$sni" "$CERT_FILE" "$KEY_FILE" || {
                    fail "共享证书与 HY2 原伪装站 SNI ($sni) 不匹配，不能安全迁移。"; return 1;
                }
                create_bridge "$sni" "$auto_fallback_url" || return 1
                targetport="$BRIDGE_PORT"
            else
                targetport="$(find_local_https_fallback_port "$sni" || true)"
                if [[ -n "$targetport" ]]; then
                    say "自动发现并复用本机 HTTPS 回落：127.0.0.1:$targetport（证书匹配 $sni）"
                else
                    say '未发现证书匹配的本机 HTTPS 服务，自动创建 Nginx TLS 桥接并分配空闲内部端口。'
                    cert_valid "$sni" "$CERT_FILE" "$KEY_FILE" || {
                        fail "未找到与 $sni 匹配的本机 HTTPS 服务，且共享证书不匹配；请使用证书域名或先配置匹配证书。"; return 1;
                    }
                    create_bridge "$sni" "$auto_fallback_url" || return 1
                    targetport="$BRIDGE_PORT"
                fi
            fi
            ;;
        3)
            ensure_shared_cert || return 1
            [[ "$CERT_INSECURE" != true ]] || {
                fail 'REALITY 本机 HTTPS 桥接要求可信证书；请先申请正式证书。'; return 1;
            }
            sni="$CERT_DOMAIN"
            local fallback_url='http://127.0.0.1:8080'
            if $owned_hy2_site; then
                fallback_url="$(jq -r '[.inbounds[]? | select(.tag=="hy2-in") | .masquerade][0] // "http://127.0.0.1:8080"' "$CONFIG")"
            fi
            create_bridge "$sni" "$fallback_url" || return 1
            target=127.0.0.1; targetport="$BRIDGE_PORT"
            ;;
        0) return 0 ;;
        *) fail '请输入 1、2、3 或 0。'; return 1 ;;
    esac
    if ! select_reality_connect_host "$sni" "$mode"; then
        rollback_bridge_if_new; return 1
    fi
    if $owned_hy2_site; then
        if [[ "$sni" != "$old_hy2_sni" ]]; then
            rollback_bridge_if_new
            fail 'REALITY 与已有 HY2 自建 HTTPS 站点 SNI 不一致，拒绝迁移。'; return 1
        fi
        if ! release_hy2_public443_for_reality "$old_hy2_sni"; then
            rollback_bridge_if_new; return 1
        fi
    fi
    # Release only the s.sh owned HTTPS vhost, not Nginx itself; reject any
    # remaining external TCP listener or another sing-box TCP inbound.
    if ! check_port_available tcp "$port" vless-in; then
        restore_reality_migrated_site
        rollback_bridge_if_new
        return 1
    fi
    keys="$(sing-box generate reality-keypair)" || {
        restore_reality_migrated_site; rollback_bridge_if_new; return 1;
    }
    priv="$(sed -nE 's/^[[:space:]]*PrivateKey:[[:space:]]*//p' <<< "$keys" | head -n 1)"
    pub="$(sed -nE 's/^[[:space:]]*PublicKey:[[:space:]]*//p' <<< "$keys" | head -n 1)"
    if [[ -z "$priv" || -z "$pub" ]]; then
        warn 'REALITY 公私钥解析失败。'
        restore_reality_migrated_site; rollback_bridge_if_new; return 1
    fi
    uuid="$(cat /proc/sys/kernel/random/uuid)"
    sid="$(openssl rand -hex 4)"
    node="$(make_node_file)" || { restore_reality_migrated_site; rollback_bridge_if_new; return 1; }
    if ! jq -n --argjson port "$port" --arg uuid "$uuid" --arg sni "$sni" --arg target "$target" \
        --argjson targetport "$targetport" --arg priv "$priv" --arg sid "$sid" \
        '{type:"vless",tag:"vless-in",listen:"::",listen_port:$port,
         users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],
         tls:{enabled:true,server_name:$sni,reality:{enabled:true,
            handshake:{server:$target,server_port:$targetport},private_key:$priv,short_id:[$sid]}}}' > "$node"; then
        rm -f "$node"; restore_reality_migrated_site; rollback_bridge_if_new; return 1
    fi
    reality_before="$(mktemp /tmp/s-sh-reality-before.XXXXXXXX)" || {
        rm -f "$node"; restore_reality_migrated_site; rollback_bridge_if_new; return 1;
    }
    cp -a "$CONFIG" "$reality_before" || {
        rm -f "$node" "$reality_before"; restore_reality_migrated_site; rollback_bridge_if_new; return 1;
    }
    service_active && was_active=true
    if ! apply_inbound vless-in "$node"; then
        rm -f "$node" "$reality_before"
        restore_reality_migrated_site; rollback_bridge_if_new
        return 1
    fi
    rm -f "$node"
    # For either auto-detected local HTTPS or a managed TLS bridge, verify
    # REALITY's public TCP/443 route reaches the HTTPS website, not merely
    # that its socket is bound.
    if [[ "$port" == 443 && ( "$mode" == 2 || "$mode" == 3 ) ]] &&
       ! check_tls_endpoint 127.0.0.1 443 "$sni"; then
        warn 'REALITY 已监听 TCP/443，但实际 HTTPS 握手回落未通过验证；恢复原配置。'
        cp -a "$reality_before" "$CONFIG"
        if $was_active; then service_restart || true; else service_stop || true; fi
        restore_reality_migrated_site
        rollback_bridge_if_new
        rm -f "$reality_before"
        fail 'REALITY 回落测试失败，旧配置和 HY2 网站已恢复。'; return 1
    fi
    rm -f "$reality_before"
    # From here both Reality and (if installed) HY2 are live; website traffic
    # reaches the loopback TLS bridge via the Reality handshake.
    commit_reality_migrated_site
    [[ -z "$BRIDGE_NEW_BACKUP" ]] || rm -f "$BRIDGE_NEW_BACKUP"
    BRIDGE_NEW_PATH=''; BRIDGE_NEW_BACKUP=''
    if ! set_meta_values --arg p "$pub" --arg sni "$sni" --arg target "$target" \
        --argjson targetport "$targetport" --arg mode "$mode" --arg h "$REALITY_CONNECT_HOST" \
        '.reality={public_key:$p,sni:$sni,connect_host:$h,fallback_host:$target,fallback_port:$targetport,fallback_mode:$mode}'; then
        warn 'REALITY 服务已启动，但元数据记录失败，请检查输出链接的 PublicKey。'
    fi
    printf '%s' "$pub" > /etc/sing-box/.reality_pub
    chmod 600 /etc/sing-box/.reality_pub
    if [[ "$port" == 443 ]] && protocol_installed hy2; then
        # No longer publicly bind TCP/443 in HY2's Nginx vhost; the H public
        # cover preference is preserved so it can be restored if R is removed.
        if [[ "$(get_meta '.hy2.tcp443_wanted')" != false ]]; then
            set_meta_values '.hy2.tcp443_wanted=true | .hy2.tcp443_mode="reality"' || true
        fi
        say '共存成功：REALITY TCP/443、HY2 UDP/443；普通浏览器由 REALITY 回落至 HTTPS 网站。'
    fi
    protocol_report reality
}

# QR output is compact-height UTF-8, with a two-cell quiet zone. Extra
# blank lines and a visible caption keep its upper border separate from the
# credentials/URI and prevent the following menu from visually merging into it.
show_qr() {
    printf '\n\n%b────────── 节点二维码（扫描导入） ──────────%b\n\n' "$UI_CYAN" "$UI_RESET"
    if command_ok qrencode; then
        qrencode -t UTF8 -m 2 "$1" || warn '二维码绘制失败，请使用上方节点链接导入。'
    else
        warn '未安装 qrencode。请先在主菜单 1 安装二维码依赖。'
    fi
    printf '\n%b──────────────────────────────────────────%b\n\n' "$UI_DIM" "$UI_RESET"
}

# Shared SS landing-node presentation for both installation/link output and
# overall status.  The labels describe the X-UI outbound fields, not a claim
# that the sing-box inbound has disabled UDP.
print_ss_landing_params() {
    local host="$1" port="$2" method="$3" password="$4"
    printf '\n%b%s%b\n\n' "$UI_BOLD$UI_GREEN" 'Shadowsocks (SS) 落地节点：' "$UI_RESET"
    printf '%b服务器地址：%b%s\n' "$UI_CYAN" "$UI_RESET" "$host"
    printf '%b服务器端口：%b%s\n' "$UI_CYAN" "$UI_RESET" "$port"
    printf '%b加密方式：%b%s\n' "$UI_CYAN" "$UI_RESET" "$method"
    printf '%b密码：%b%s\n' "$UI_CYAN" "$UI_RESET" "$password"
    printf '\n%b传输类型：%bTCP (RAW)\n' "$UI_CYAN" "$UI_RESET"
    printf '%b传输安全：%bNone\n' "$UI_CYAN" "$UI_RESET"
    printf '%bTLS：%b关闭\n' "$UI_CYAN" "$UI_RESET"
    printf '%b插件：%b无\n' "$UI_CYAN" "$UI_RESET"
}

# Keep the QR visible until the operator chooses to return to the menu.
pause_after_node_output() {
    if [[ -t 0 ]]; then
        local ignored=''
        ask ignored '按回车返回协议菜单（可先扫描上方二维码）: ' '' || true
    fi
}

show_links() {
    local only="${1:-all}" host='' port='' method='' password='' uri='' sni='' key='' sid='' uuid='' name=''
    ensure_state || return 1
    if [[ "$only" != all ]] && ! protocol_installed "$only"; then
        warn "$(protocol_name "$only") 尚未成功安装（或上次安装已经回滚），请先在本协议菜单选择 1 安装。"
        return 1
    fi
    host="$(get_meta '.connect_host')"
    if [[ -z "$host" && -f /etc/sing-box/.config_cache ]]; then
        host="$(sed -n 's/^CUSTOM_IP=//p' /etc/sing-box/.config_cache | head -n 1)"
    fi
    [[ -n "$host" ]] || host="$(get_meta '.hy2.connect_host')"
    [[ -n "$host" ]] || host="$(get_public_ip || true)"
    if [[ -z "$host" ]]; then warn 'No public connect address. Set it in menu 1 or HY2 menu 6.'; return 1; fi
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
            name="$(urlenc 'S')"
            uri="ss://$(base64one "$method:$password")@$authority_host:$port#$name"
            say 'Base64 仅为链接编码；在 X-UI 出站中填写下方落地参数，保存后重启生效。'
            print_ss_landing_params "$host" "$port" "$method" "$password"
            printf '\n%b节点链接（Base64）：%b\n%s\n' "$UI_CYAN" "$UI_RESET" "$uri"
            show_qr "$uri"
        fi
    fi
    if [[ "$only" == all || "$only" == hy2 ]]; then
        port="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.listen_port][0]//empty' "$CONFIG")"
        if [[ -n "$port" ]]; then
            # HY2 has its own DNS connection host, not the shared SS/REALITY IP.
            local hy2_host hy2_authority
            hy2_host="$(get_meta '.hy2.connect_host')"
            [[ -n "$hy2_host" ]] || hy2_host="$host"
            hy2_authority="$hy2_host"
            [[ "$hy2_host" != *:* || "$hy2_host" == \[* ]] || hy2_authority="[$hy2_host]"
            password="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.users[0].password][0]//empty' "$CONFIG")"
            sni="$(get_meta '.hy2.sni')"
            [[ -n "$sni" ]] || sni="$(get_meta '.cert_domain')"
            [[ -n "$sni" ]] || sni="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.tls.certificate_path][0]//empty' "$CONFIG" | sed -nE 's#^/etc/letsencrypt/live/([^/]+)/.*#\1#p')"
            local query="sni=$(urlenc "$sni")&alpn=h3"
            local hy2_insecure="$(get_meta '.hy2.insecure')"
            [[ -n "$hy2_insecure" ]] || hy2_insecure="$(get_meta '.hy2_insecure')"
            [[ "$hy2_insecure" == true ]] && query+='&insecure=1'
            uri="hy2://$(urlenc "$password")@$hy2_authority:$port/?${query}#$(urlenc 'H')"
            printf '\n=== Hysteria2 (UDP/%s) ===\n%s\n' "$port" "$uri"
            printf '  地址/域名：%s\n  UDP 端口：%s\n  HY2 原始密码：%s\n  TLS SNI：%s\n  传输：UDP / QUIC，ALPN h3\n' \
                "$hy2_host" "$port" "$password" "$sni"
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
                local reality_host reality_authority
                reality_host="$(get_meta '.reality.connect_host')"
                [[ -n "$reality_host" ]] || reality_host="$host"
                reality_authority="$reality_host"
                [[ "$reality_host" != *:* || "$reality_host" == \[* ]] || reality_authority="[$reality_host]"
                uri="vless://$uuid@$reality_authority:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(urlenc "$sni")&fp=chrome&pbk=$(urlenc "$key")&sid=$sid&type=tcp#$(urlenc 'R')"
                printf '\n=== VLESS REALITY (TCP/%s) ===\n%s\n' "$port" "$uri"
                printf '  地址/域名：%s\n  TCP 端口：%s\n  UUID：%s\n  SNI：%s\n  PublicKey：%s\n  ShortID：%s\n  Flow：xtls-rprx-vision\n  传输：TCP / REALITY\n' \
                    "$reality_host" "$port" "$uuid" "$sni" "$key" "$sid"
                printf '  Fallback: %s:%s\n' \
                    "$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.reality.handshake.server][0]//empty' "$CONFIG")" \
                    "$(jq -r '[.inbounds[]|select(.tag=="vless-in")|.tls.reality.handshake.server_port][0]//empty' "$CONFIG")"
                show_qr "$uri"
            fi
        fi
    fi
}

# Unified status + connection parameters + node URI + QR for each protocol.
protocol_report() {
    local kind="$1"
    # For SS, display the full landing-node parameter block exactly once in
    # show_links, while keeping service/port health information above it.
    if [[ "$kind" == ss ]]; then
        protocol_status "$kind" compact || return 1
    else
        protocol_status "$kind" || return 1
    fi
    protocol_installed "$kind" || return 0
    show_links "$kind"
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
    elif [[ "$kind" == reality && "$active_before" == true ]] && protocol_installed hy2; then
        if [[ "$(get_meta '.hy2.tcp443_wanted')" == true ]]; then
            local hy2_domain='' hy2_target=''
            hy2_domain="$(get_meta '.hy2.sni')"
            hy2_target="$(jq -r '[.inbounds[]|select(.tag=="hy2-in")|.masquerade][0]//empty' "$CONFIG")"
            say 'REALITY 已卸载；尝试恢复 HY2 原有的 Nginx TCP/443 HTTPS 伪装。'
            if enable_hy2_tcp443_site "$hy2_domain" "$hy2_target"; then
                set_meta_values '.hy2.tcp443_mode="nginx"' || true
            else
                warn 'REALITY 已卸载、HY2 UDP 仍运行，但 HTTPS 网站未能恢复；可在 HY2 菜单 5 手动修复。'
            fi
        fi
    fi
}

protocol_status() {
    local kind="$1" detail_mode="${2:-full}" tag='' proto='' line='' port='' sni='' method='' lines_tcp='' lines_udp=''
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
        local connect_host="$(get_meta '.connect_host')"
        if [[ "$kind" == hy2 ]]; then
            local recorded_hy2_host="$(get_meta '.hy2.connect_host')"
            [[ -z "$recorded_hy2_host" ]] || connect_host="$recorded_hy2_host"
        elif [[ "$kind" == reality ]]; then
            local recorded_reality_host="$(get_meta '.reality.connect_host')"
            [[ -z "$recorded_reality_host" ]] || connect_host="$recorded_reality_host"
        fi
        [[ -n "$connect_host" ]] || connect_host="$(get_public_ip || true)"
        if [[ "$kind" == ss ]]; then
            printf '安装状态：已配置\n'
        else
            printf '安装状态：已配置\n连接域名/IP：%s\n传输协议：%s\n监听端口：%s\n' \
                "${connect_host:-请先在菜单 1 设置}" "${proto^^}" "$port"
        fi
        case "$kind" in
            ss)
                if [[ "$detail_mode" != compact ]]; then
                    method="$(jq -r '.method // empty' <<< "$line")"
                    print_ss_landing_params "${connect_host:-请先在菜单 1 设置}" "$port" "$method" \
                        "$(jq -r '.password // empty' <<< "$line")"
                fi
                ;;
            hy2)
                sni="$(get_meta '.hy2.sni')"
                [[ -n "$sni" ]] || sni="$(get_meta '.cert_domain')"
                local hy2_connect="$(get_meta '.hy2.connect_host')"
                [[ -n "$hy2_connect" ]] || hy2_connect="$connect_host"
                printf 'HY2 专用连接地址：%s\n' "$hy2_connect"
                printf 'TLS 域名/SNI：%s\nHY2 密码：%s\nTLS 证书：%s\nHTTP/3 伪装：%s\n' \
                    "${sni:-未记录}" "$(jq -r '.users[0].password // empty' <<< "$line")" \
                    "$(jq -r '.tls.certificate_path // empty' <<< "$line")" \
                    "$(jq -r '.masquerade // "未设置"' <<< "$line")"
                printf '传输说明：UDP / QUIC / TLS，ALPN h3；出站需支持 Hysteria2\n'
                if reality_tcp443_configured; then
                    if reality_tcp443_fallback_check; then
                        printf 'TCP/443 HTTPS 回落：由 REALITY 握手转发（无需第二个 Nginx 443 监听）\n'
                    else
                        printf 'TCP/443 HTTPS 回落：REALITY 已占用 TCP/443，但握手目标未通过检测\n'
                    fi
                elif domain_valid "$sni" && hy2_443_owned_site_exists "$sni" && check_tls_endpoint 127.0.0.1 443 "$sni"; then
                    printf 'TCP/443 HTTPS 回落：已启用（Nginx）\n'
                else
                    printf 'TCP/443 HTTPS 回落：未启用 / 未通过检测（可用菜单 5 管理）\n'
                fi
                ;;
            reality)
                sni="$(jq -r '.tls.server_name // empty' <<< "$line")"
                printf 'SNI：%s\nUUID：%s\nPublicKey：%s\nShortID：%s\nFlow：%s\n传输方式：TCP / REALITY（无 WS）\nTLS 回落：%s:%s\n' \
                    "$sni" "$(jq -r '.users[0].uuid // empty' <<< "$line")" \
                    "$(get_meta '.reality.public_key')" \
                    "$(jq -r '.tls.reality.short_id[0] // empty' <<< "$line")" \
                    "$(jq -r '.users[0].flow // empty' <<< "$line")" \
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
            if port_ready tcp "$port"; then
                printf 'TCP/%s：sing-box 正在监听\n' "$port"
            else
                printf 'TCP/%s：未发现 sing-box 监听\n' "$port"
                [[ -n "$lines_tcp" ]] && printf '%s\n' "$lines_tcp"
            fi
        fi
        if [[ "$proto" == *udp* ]]; then
            lines_udp="$(listener_lines udp "$port" 2>/dev/null || true)"
            if port_ready udp "$port"; then
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
        printf '\n%b╔══════════════════════════════════════════════╗%b\n' "$UI_CYAN" "$UI_RESET"
        printf '%b║%b  %b%s · 独立管理%b\n' "$UI_CYAN" "$UI_RESET" "$UI_BOLD$UI_GREEN" "$name" "$UI_RESET"
        printf '%b╚══════════════════════════════════════════════╝%b\n' "$UI_CYAN" "$UI_RESET"
        ui_rule
        ui_item 1 '安装 / 重装协议（安装成功立即输出状态、链接和二维码）'
        ui_item 2 '卸载当前协议（不影响其他协议）' "$UI_RED"
        ui_item 3 '重启当前协议（共用 sing-box 服务）'
        ui_item 4 '输出节点详细信息、链接与二维码（含运行状态）'
        if [[ "$kind" == hy2 ]]; then
            ui_item 5 'HY2 TCP/443 HTTPS 伪装/回落开关'
            ui_item 6 '设置 HY2 连接域名/IP（不重置密码）'
        fi
        ui_item 0 '返回主菜单'
        ui_rule
        ask choice '请选择 [0]: ' 0 || return 0
        case "$choice" in
            1)
                case "$kind" in
                    ss) add_ss || true ;;
                    hy2) add_hy2 || true ;;
                    reality) add_reality || true ;;
                esac
                pause_after_node_output
                ;;
            2) remove_protocol "$kind" || true ;;
            3) protocol_restart "$kind" || true ;;
            4) protocol_report "$kind" || true; pause_after_node_output ;;
            5) if [[ "$kind" == hy2 ]]; then manage_hy2_tcp443_site || true; else warn '无效选项。'; fi ;;
            6) if [[ "$kind" == hy2 ]]; then change_hy2_connect_host || true; else warn '无效选项。'; fi ;;
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
    if [[ -f "$CONFIG" ]] && command_ok jq; then
        local kind
        for kind in ss hy2 reality; do
            if protocol_installed "$kind"; then protocol_status "$kind"; fi
        done
        say '在各协议子菜单选择 4 可查看链接与二维码。'
    fi
}

# Protect other projects sharing the sing-box binary/service name. Only a
# service targeting our /etc/sing-box configuration is in scope.
core_service_is_ours() {
    local unit=''
    service_exists || return 1
    if command_ok systemctl; then
        unit="$(systemctl cat sing-box 2>/dev/null || true)"
        [[ "$unit" == *'S_SH_MANAGED_CONFIG_OVERRIDE_V4'* ||
           "$unit" == *'S_SH_MANAGED_SINGBOX_SERVICE_V2'* ||
           "$unit" == *'/etc/sing-box/config.json'* ||
           ( "$unit" == *'-C /etc/sing-box'* && "$unit" == *'sing-box'* && "$unit" == *'run'* ) ]]
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
    # Remove only the explicit service override installed by this s.sh.
    local our_dropin='/etc/systemd/system/sing-box.service.d/90-s-sh-config.conf'
    if [[ -f "$our_dropin" ]] && grep -Fqx '# S_SH_MANAGED_CONFIG_OVERRIDE_V4' "$our_dropin"; then
        rm -f -- "$our_dropin"
        if command_ok systemctl; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
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
    ask name '节点名称后缀（可留空）: ' "$(get_meta '.node_name')" || return 1
    [[ "$name" != *$'\n'* && ${#name} -lt 64 ]] || { warn '节点名称应少于 64 字符'; return 1; }
    set_meta_values --arg name "$name" '.node_name=$name'
}

# One-step setup wizard; protocol installers reuse tools and shared TLS metadata.
common_setup_all() {
    printf '\n%b========== 菜单 1：一键准备通用环境（交互安装） ==========%b\n' "$UI_CYAN" "$UI_RESET"
    say '[1/5] 安装通用依赖（curl / jq / openssl / certbot / qrencode / iproute2）'
    if ! install_deps; then fail '依赖安装失败，已停止向导。'; return 1; fi
    say '[2/5] 安装或检查独立 sing-box 内核（不包含 S-UI）'
    ensure_tools && ensure_singbox && ensure_state || return 1
    if command_ok sing-box; then sing-box version | head -n 2 || true; fi
    say '[3/5] 设置通用节点连接 IP / DDNS（HY2 安装时可单独使用证书域名）'
    select_host || return 1
    say '[4/5] 节点链接名固定为 R（REALITY）、H（HY2）、S（SS），不再设置名称后缀。'
    say '[5/5] 申请或复用 TLS 证书（参照 x.sh 的 Y/n/q 流程）'
    say '请直接输入证书域名进入 Y/n/q 选择；如果仅用 SS，可在域名提示处留空或在证书选项输入 q。'
    prepare_domain_cert || warn '证书尚未准备，可在之后重新运行菜单 1 处理；不影响 SS。'
    printf '\n'
    say '通用环境完成：独立 sing-box 内核、二维码依赖和证书已经准备。'
    printf '  节点连接地址：%s\n  导入名称：R / H / S\n  证书域名：%s\n' \
        "$(get_meta '.connect_host')" "$(get_meta '.cert_domain')"
}
show_menu() {
    local active_label='' version=''
    ui_banner
    ui_rule
    ui_item 1 '一键安装通用环境、域名及证书（交互向导）'
    ui_item 2 '手动更新 sing-box 内核'
    ui_item 3 '完整卸载内核 + 所有协议（不可恢复）' "$UI_RED"
    ui_rule
    ui_item 4 'Shadowsocks (SS) 管理'
    ui_item 5 'Hysteria2 (HY2) 管理 · UDP 443'
    ui_item 6 'VLESS REALITY 管理 · TCP 443'
    ui_rule
    ui_item 7 '查看 sing-box 总体运行状态'
    ui_item 8 '重启 sing-box 内核及所有协议'
    ui_item 0 '退出'
    ui_rule
    if service_active; then
        active_label="${UI_GREEN}运行中${UI_RESET}"
    else
        active_label="${UI_YELLOW}未运行${UI_RESET}"
    fi
    printf ' %b服务状态：%b%b\n' "$UI_DIM" "$active_label" "$UI_RESET"
    if command_ok sing-box; then
        version="$(sing-box version 2>/dev/null | head -n1 || true)"
        [[ -n "$version" ]] && printf ' %b内核：%s%b\n' "$UI_DIM" "$version" "$UI_RESET"
    fi
    ui_rule
}

main() {
    require_root
    local arg="${1:-}" choice=''
    case "$arg" in
        --help|-h) show_menu; return 0 ;;
        --status) status; return 0 ;;
        --status-ss) protocol_status ss; return 0 ;;
        --diag-ss)
            if [[ -f "$CONFIG" ]] && command_ok jq; then
                local ssport
                ssport="$(jq -r '[.inbounds[]|select(.tag=="ss-in")|.listen_port][0]//empty' "$CONFIG")"
                if [[ -n "$ssport" ]]; then service_diagnostics 'tcp+udp' "$ssport"; else warn '尚未配置 SS 入站。'; fi
            else
                warn '缺少配置文件或 jq。'
            fi
            return 0 ;;
        --status-hy2) protocol_status hy2; return 0 ;;
        --status-reality) protocol_status reality; return 0 ;;
        --show) warn '节点链接与二维码请进入对应协议子菜单，选择 4；或执行 --info-ss / --info-hy2 / --info-reality。'; return 0 ;;
        --info-ss) protocol_report ss; return $? ;;
        --info-hy2) protocol_report hy2; return $? ;;
        --info-reality) protocol_report reality; return $? ;;
        --setup) common_setup_all; return $? ;;
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
            1) common_setup_all || true ;;
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
