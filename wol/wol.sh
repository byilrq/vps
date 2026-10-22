#!/usr/bin/env bash
# WOL Web management script
# Menu inputs use normal terminal line editing; Backspace works in SSH terminals.
set -uo pipefail

VERSION="1.5.2"
RAW_WOL_URL="https://raw.githubusercontent.com/byilrq/vps/main/wol/wol.py"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR="${SCRIPT_DIR}/wol"
ETC_DIR="${APP_DIR}"
CONFIG_FILE="${APP_DIR}/config.json"
SERVICE_FILE="/etc/systemd/system/wol-web.service"
SERVICE_NAME="wol-web"
VENV_PY="${APP_DIR}/venv/bin/python"
VENV_PIP="${APP_DIR}/venv/bin/pip"
GENERATED_PASSWORD=""
NGINX_CONF_FILE=""
NGINX_LINK_FILE=""

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[1;31m'
    GREEN=$'\033[1;32m'
    YELLOW=$'\033[1;33m'
    CYAN=$'\033[1;36m'
    BLUE=$'\033[1;34m'
    PURPLE=$'\033[1;35m'
    DIM=$'\033[2m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BLUE='' PURPLE='' DIM='' BOLD='' RESET=''
fi

info() { printf '%s\n' "${CYAN}[INFO]${RESET} $*"; }
ok() { printf '%s\n' "${GREEN}[OK]${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}[WARN]${RESET} $*"; }
err() { printf '%s\n' "${RED}[ERROR]${RESET} $*" >&2; }
pause_menu() { printf '\n'; read -r -p "按 Enter 返回菜单..." _ || true; }
need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "请使用 root 运行：bash wol.sh"
        return 1
    fi
}
is_configured() { [[ -f "$CONFIG_FILE" ]]; }
is_installed() { [[ -f "$CONFIG_FILE" && -f "$SERVICE_FILE" ]]; }

config_get() {
    local key="$1"
    [[ -f "$CONFIG_FILE" ]] || { printf ''; return 0; }
    python3 - "$CONFIG_FILE" "$key" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    v = d
    for part in sys.argv[2].split("."):
        v = v.get(part, {}) if isinstance(v, dict) else {}
    if isinstance(v, (dict, list)):
        print(json.dumps(v, ensure_ascii=False))
    elif v is not None:
        print(v)
except Exception:
    print("")
PY
}

config_set_fields() {
    local arg
    [[ -f "$CONFIG_FILE" ]] || { err "配置文件不存在，请先执行菜单 1。"; return 1; }
    python3 - "$CONFIG_FILE" "$@" <<'PY'
import json, os, sys, tempfile
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as exc:
    print(f"Cannot read config: {exc}", file=sys.stderr)
    raise SystemExit(1)
for item in sys.argv[2:]:
    key, sep, value = item.partition("=")
    if not sep:
        continue
    if key in ("port", "external_port", "internal_port", "send_count", "cooldown_seconds"):
        data[key] = int(value)
    elif key == "auth_enabled":
        data[key] = value.lower() in ("true", "yes", "1")
    else:
        data[key] = value
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".wol-config-", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
}

record_firewall_port() {
    local kind="$1" port="$2"
    python3 - "$CONFIG_FILE" "$kind" "$port" <<'PY'
import json, os, sys, tempfile
path, kind, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
fw = data.setdefault("firewall", {})
key = kind + "_added_ports"
values = fw.setdefault(key, [])
if port not in values:
    values.append(port)
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".wol-config-", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
}

read_default() {
    # Interactive SSH: readline enables Backspace / arrow keys, -i prefills the old value.
    # Enter keeps the current parameter unchanged. Non-TTY also supports Enter defaults.
    local prompt="$1" default_value="${2:-}" entered=""
    if [[ -t 0 ]]; then
        if [[ -n "$default_value" ]]; then
            read -e -r -i "$default_value" -p "${prompt}: " entered || return 1
        else
            read -e -r -p "${prompt}: " entered || return 1
        fi
    elif [[ -n "$default_value" ]]; then
        read -r -p "${prompt} [${default_value}]: " entered || return 1
    else
        read -r -p "${prompt}: " entered || return 1
    fi
    REPLY="${entered:-$default_value}"
}


validate_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

normalize_mac() {
    python3 - "$1" <<'PY'
import re, sys
value = re.sub(r"[^0-9a-fA-F]", "", sys.argv[1])
if not re.fullmatch(r"[0-9a-fA-F]{12}", value):
    raise SystemExit(1)
print(":".join(value[i:i+2] for i in range(0, 12, 2)).upper())
PY
}

validate_host() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
host = sys.argv[1].strip()
if not host or len(host) > 253 or any(c.isspace() for c in host) or "/" in host or "\\" in host or "://" in host:
    raise SystemExit(1)
try:
    address = ipaddress.ip_address(host)
    raise SystemExit(0 if address.version == 4 else 1)
except ValueError:
    pass
candidate = host[:-1] if host.endswith(".") else host
labels = candidate.split(".")
label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
raise SystemExit(0 if candidate and all(label_re.fullmatch(x) for x in labels) else 1)
PY
}

validate_web_domain() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
host = sys.argv[1].strip().lower()
if not host or len(host) > 253 or "." not in host or any(c.isspace() for c in host) or "/" in host or "\\" in host:
    raise SystemExit(1)
try:
    ipaddress.ip_address(host)
    raise SystemExit(1)
except ValueError:
    pass
candidate = host[:-1] if host.endswith(".") else host
labels = candidate.split(".")
label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
raise SystemExit(0 if candidate and all(label_re.fullmatch(x) for x in labels) else 1)
PY
}

prepare_managed_dir() {
    local path="$1" marker="$2"
    if [[ -d "$path" && ! -f "$path/$marker" ]]; then
        if [[ -n "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
            err "$path 已存在且不是本脚本管理的目录，为避免覆盖其他文件，已停止。"
            return 1
        fi
    fi
    mkdir -p "$path" || return 1
    touch "$path/$marker"
}

download_wol_program() {
    local tmp="${APP_DIR}/.wol.py.download.$$"
    local source_ok=0
    rm -f "$tmp"
    # Prefer the colocated release (signed/copy-managed by the operator) to
    # avoid accidentally installing a different cloud snapshot on upgrades.
    if [[ -f "$SCRIPT_DIR/wol.py" ]] && grep -Fq "WOL_WEB_APP_VERSION = \"$VERSION\"" "$SCRIPT_DIR/wol.py"; then
        install -o root -g root -m 644 "$SCRIPT_DIR/wol.py" "$APP_DIR/wol.py" || return 1
        source_ok=1
        info "已使用 wol.sh 同目录的 v${VERSION} wol.py。"
    fi
    if (( source_ok == 0 )) && command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 --max-time 60 "$RAW_WOL_URL" -o "$tmp"; then
            if grep -Fq "WOL_WEB_APP_VERSION = \"$VERSION\"" "$tmp" && "$VENV_PY" -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$tmp" >/dev/null 2>&1; then
                install -o root -g root -m 644 "$tmp" "$APP_DIR/wol.py"
                source_ok=1
                info "已从 GitHub Raw 地址下载 wol.py。"
            else
                warn "GitHub 上的 wol.py 为空、版本不匹配或语法不正确，将尝试使用本地 wol.py。"
            fi
        else
            warn "GitHub 下载失败，将尝试使用本地 wol.py。"
        fi
    fi
    rm -f "$tmp"
    if (( source_ok == 0 )); then
        if [[ -f "$SCRIPT_DIR/wol.py" ]] && grep -Fq "WOL_WEB_APP_VERSION = \"$VERSION\"" "$SCRIPT_DIR/wol.py"; then
            if [[ "$(readlink -f "$SCRIPT_DIR/wol.py" 2>/dev/null || printf '%s' "$SCRIPT_DIR/wol.py")" != "$(readlink -f "$APP_DIR/wol.py" 2>/dev/null || printf '%s' "$APP_DIR/wol.py")" ]]; then
                install -o root -g root -m 644 "$SCRIPT_DIR/wol.py" "$APP_DIR/wol.py"
            fi
            source_ok=1
            info "已使用 wol.sh 同目录中的 wol.py。"
        elif [[ -f "$APP_DIR/wol.py" ]] && grep -Fq "WOL_WEB_APP_VERSION = \"$VERSION\"" "$APP_DIR/wol.py"; then
            source_ok=1
            info "继续使用已安装的 wol.py。"
        fi
    fi
    if (( source_ok == 0 )); then
        err "没有可用的 wol.py。请将 wol.py 与 wol.sh 放在同一目录，或先上传 wol.py 到 GitHub 的 wol/wol.py。"
        return 1
    fi
    if ! "$VENV_PY" -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$APP_DIR/wol.py"; then
        err "wol.py 语法检查失败。"
        return 1
    fi
    chmod 644 "$APP_DIR/wol.py"
}

initialize_config() {
    # Menu 1 deliberately has no interactive settings: no WEB password, no
    # external/internal port prompts, and no firewall manipulation.
    # Menu 3 configures password/ports and opens its own firewall port.
    WOL_CONFIG_FILE="$CONFIG_FILE" python3 - <<'PY_CONFIG'
import json, os, secrets
from pathlib import Path
path = Path(os.environ["WOL_CONFIG_FILE"])
obj = {
    "host": "", "mac": "", "port": 9,
    "send_count": 5, "cooldown_seconds": 20,
    "auth_enabled": True,
    "web_domain": "", "external_port": 8119, "internal_port": 8109,
    "password_hash": "", "secret_key": secrets.token_hex(32),
    "firewall": {"ufw_added_ports": [], "firewalld_added_ports": [], "iptables_added_ports": []},
    "nginx_config_path": "", "nginx_link_path": ""
}
with path.open("x", encoding="utf-8") as f:
    json.dump(obj, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.chmod(path, 0o600)
PY_CONFIG
}

make_password_hash() {
    local passwd="$1"
    WOL_PASSWORD_TO_HASH="$passwd" "$VENV_PY" - <<'PY_HASH'
import os
from werkzeug.security import generate_password_hash
print(generate_password_hash(os.environ["WOL_PASSWORD_TO_HASH"]))
PY_HASH
}

read_secret() {
    local prompt="$1" entered=""
    # readline editing works with Backspace even for hidden terminal input.
    if [[ -t 0 ]]; then
        read -e -r -s -p "$prompt" entered || return 1
    else
        read -r -s -p "$prompt" entered || return 1
    fi
    printf '\n'
    REPLY="$entered"
}

write_service_unit() {
    local internal_port="$1"
    if [[ -f "$SERVICE_FILE" ]] && ! grep -q "WOL-WEB MANAGED SERVICE" "$SERVICE_FILE"; then
        err "$SERVICE_FILE 已存在且不是本脚本创建的文件，为避免影响其他服务，拒绝覆盖。"
        return 1
    fi
    cat > "$SERVICE_FILE" <<EOF
# WOL-WEB MANAGED SERVICE
[Unit]
Description=WOL Web NAS Wake Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Run as root because the requested ${APP_DIR} path may be under /root (mode 0700).
# Restrict privileges with systemd hardening; never chmod /root to world-readable.
User=root
Group=root
WorkingDirectory=${APP_DIR}
Environment=WOL_CONFIG_FILE=${CONFIG_FILE}
Environment=WOL_COOKIE_SECURE=1
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 2 --threads 2 --timeout 30 --bind 127.0.0.1:${internal_port} --access-logfile - --error-logfile - wol:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# /root/wol is user-requested. ReadWritePaths lets SQLite persist the last 5 sends.
ProtectHome=false
ReadWritePaths=${APP_DIR}
# Allow the optional diagnostic/source UDP port 9 bind without granting
# unrelated Linux capabilities to the application process.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SERVICE_FILE"
}

open_firewall_port() {
    local port="$1"
    validate_port "$port" || { err "防火墙端口无效：$port"; return 1; }

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw show added 2>/dev/null | grep -Fq "${port}/tcp" || ufw status 2>/dev/null | grep -Fq "${port}/tcp"; then
            info "UFW 已有 TCP ${port} 规则，不重复添加。"
        elif ufw allow "${port}/tcp" comment 'WOL Web'; then
            record_firewall_port "ufw" "$port"
            ok "已通过 UFW 放行 TCP ${port}。"
        else
            warn "UFW 放行 TCP ${port} 失败，请手动检查。"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1 || firewall-cmd --permanent --query-port="${port}/tcp" >/dev/null 2>&1; then
            info "firewalld 已有 TCP ${port} 规则，不重复添加。"
        elif firewall-cmd --permanent --add-port="${port}/tcp" && firewall-cmd --reload; then
            record_firewall_port "firewalld" "$port"
            ok "已通过 firewalld 放行 TCP ${port}。"
        else
            warn "firewalld 放行 TCP ${port} 失败，请手动检查。"
        fi
    elif command -v ufw >/dev/null 2>&1; then
        if ufw show added 2>/dev/null | grep -Fq "${port}/tcp"; then
            info "UFW 已有 TCP ${port} 规则（当前 UFW 未启用）。"
        elif ufw allow "${port}/tcp" comment 'WOL Web'; then
            record_firewall_port "ufw" "$port"
            warn "已写入 UFW 放行规则，但 UFW 当前未启用；脚本不会擅自启用 UFW，以免影响 SSH/Nginx。"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
            info "iptables 已有 TCP ${port} 规则，不重复添加。"
        elif iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT; then
            record_firewall_port "iptables" "$port"
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1 || true
            else
                warn "已临时添加 iptables 放行规则；系统重启后是否保留取决于本机防火墙持久化配置。"
            fi
            ok "已通过 iptables 放行 TCP ${port}。"
        else
            warn "iptables 放行 TCP ${port} 失败，请手动检查。"
        fi
    else
        warn "未检测到可自动管理的主机防火墙。请同时确认 VPS 云厂商安全组放行 TCP ${port}。"
    fi
}

remove_firewall_rules() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    local firewalld_changed=0
    while IFS=: read -r kind port; do
        [[ -n "${kind:-}" && -n "${port:-}" ]] || continue
        case "$kind" in
            ufw)
                if command -v ufw >/dev/null 2>&1; then
                    ufw --force delete allow "${port}/tcp" >/dev/null 2>&1 || true
                    info "已尝试移除本脚本添加的 UFW TCP ${port} 规则。"
                fi
                ;;
            firewalld)
                if command -v firewall-cmd >/dev/null 2>&1; then
                    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 && firewalld_changed=1
                fi
                ;;
            iptables)
                if command -v iptables >/dev/null 2>&1; then
                    iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
                    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done < <(python3 - "$CONFIG_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    fw = d.get("firewall", {})
    for kind in ("ufw", "firewalld", "iptables"):
        for port in fw.get(kind + "_added_ports", []):
            print(f"{kind}:{int(port)}")
except Exception:
    pass
PY
)
    if (( firewalld_changed == 1 )) && command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

install_deploy() {
    need_root || return 1
    if ! command -v apt-get >/dev/null 2>&1; then
        err "当前脚本按 Debian/Ubuntu 的 apt 环境编写。"
        return 1
    fi
    if [[ -f "$SERVICE_FILE" ]] && ! grep -q "WOL-WEB MANAGED SERVICE" "$SERVICE_FILE"; then
        err "$SERVICE_FILE 已存在且不是本脚本管理的服务，已停止以保护现有服务。"
        return 1
    fi
    prepare_managed_dir "$APP_DIR" ".wol-web-managed" || return 1

    info "安装 Python 运行环境及下载工具..."
    apt-get update || { err "apt-get update 失败。"; return 1; }
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip curl ca-certificates || {
        err "依赖安装失败。"
        return 1
    }

    mkdir -p "$APP_DIR"
    if [[ ! -x "$VENV_PY" ]]; then
        python3 -m venv "$APP_DIR/venv" || { err "创建 Python 虚拟环境失败。"; return 1; }
    fi
    "$VENV_PIP" install --disable-pip-version-check --upgrade "Flask>=3.0,<4.0" "gunicorn>=22,<24" || {
        err "Flask/Gunicorn 安装失败。"
        return 1
    }

    download_wol_program || return 1
    if [[ ! -f "$CONFIG_FILE" ]]; then
        initialize_config || { err "创建默认配置失败。"; return 1; }
        info "已创建配置文件，未设置 WEB 密码和对外端口；请在菜单 3 完成。"
    else
        # Preserve existing password/ports on upgrade; never prompt during menu 1.
        config_set_fields "auth_enabled=true" || return 1
    fi
    chown root:root "$APP_DIR" 2>/dev/null || true
    chmod 700 "$APP_DIR"
    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE"

    local internal_port
    internal_port="$(config_get internal_port)"
    internal_port="${internal_port:-8109}"
    write_service_unit "$internal_port" || return 1
    systemctl daemon-reload || { err "systemd 重新加载失败。"; return 1; }
    if systemctl enable "$SERVICE_NAME" >/dev/null && systemctl restart "$SERVICE_NAME"; then
        ok "WOL Web 服务已安装或更新，并重新启动。"
    else
        err "服务启动失败，最近日志如下："
        journalctl -u "$SERVICE_NAME" -n 40 --no-pager 2>/dev/null || true
        return 1
    fi

    # The WEB external port is opened ONLY after successful menu 3 settings.
    local external_port
    external_port="$(config_get external_port)"
    external_port="${external_port:-8119}"

    # During upgrades, refresh ONLY our managed Nginx snippet so HTTP->HTTPS
    # redirect works immediately after menu 1 without reentering menu 3.
    sync_existing_nginx || warn "WOL 专属 Nginx 配置尚未同步；请运行菜单 3 检查设置。"

    local domain
    domain="$(config_get web_domain)"
    if [[ -n "$domain" ]]; then
        ok "访问地址：https://${domain}:${external_port}/"
    else
        info "下一步请运行菜单 2 配置 NAS，再运行菜单 3 配置网页域名、端口和密码。"
    fi
    ok "内部监听：127.0.0.1:${internal_port}；不会直接暴露内部端口到公网。"
    info "程序目录：${APP_DIR}；配置文件：${CONFIG_FILE}"
    show_status
}

configure_nas() {
    need_root || return 1
    is_configured || { err "请先运行菜单 1 安装部署。"; return 1; }

    local old_mac old_host old_port mac_input host_input port_input mac host port
    old_mac="$(config_get mac)"
    old_host="$(config_get host)"
    old_port="$(config_get port)"
    old_port="${old_port:-9}"

    printf '\n%s\n' "---- NAS 唤醒参数配置 ----"
    read_default "NAS 网卡 MAC 地址（例如 00:11:22:33:44:55）" "$old_mac" || return 1
    mac_input="$REPLY"
    read_default "NAS 公网 IP 或 DDNS 域名" "$old_host" || return 1
    host_input="$REPLY"
    read_default "UDP 端口" "$old_port" || return 1
    port_input="$REPLY"

    if ! mac="$(normalize_mac "$mac_input" 2>/dev/null)"; then
        err "MAC 地址格式错误，请使用 00:11:22:33:44:55 这样的格式。"
        return 1
    fi
    if ! validate_host "$host_input"; then
        err "域名或 IPv4 地址格式错误；不要填写 http:// 或端口。"
        return 1
    fi
    if ! validate_port "$port_input"; then
        err "UDP 端口必须是 1-65535 的整数。"
        return 1
    fi
    config_set_fields "mac=$mac" "host=$host_input" "port=$((10#$port_input))" || return 1
    ok "NAS 参数已保存。"
    printf 'MAC：%s\n目标：%s\nUDP 端口：%s\n' "$mac" "$host_input" "$port_input"
    info "这里的 UDP 端口是家庭路由器转发的 WOL 端口，默认 9；与网页外部 TCP 端口不同。"
    info "每次尝试发送 5 个标准 Magic Packet，并尝试使用源 UDP 9 端口补发 2 个。"
    warn "如果实际唤醒仍失败，请检查家庭路由器 UDP9 转发到关机 NAS 时的 ARP/广播能力。"
    if command -v getent >/dev/null 2>&1; then
        local resolved
        resolved="$(getent ahostsv4 "$host_input" 2>/dev/null | awk 'NR==1 { print $1 }')"
        if [[ -n "$resolved" ]]; then
            info "当前 DDNS IPv4 解析结果：$resolved（请与手机小程序的目标地址核对）。"
        else
            warn "DDNS 未解析到 IPv4；请检查 DNS A 记录。"
        fi
    fi
}

restart_service() {
    need_root || return 1
    if ! systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
        err "服务尚未安装，请先运行菜单 1。"
        show_status
        return 1
    fi
    info "正在重启 WOL Web 服务..."
    if ! systemctl restart "$SERVICE_NAME"; then
        err "systemctl restart 执行失败。"
        show_status
        journalctl -u "$SERVICE_NAME" -n 25 --no-pager 2>/dev/null || true
        return 1
    fi
    sleep 1
    show_status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "重启完成，当前服务状态：运行中。"
    else
        err "服务重启后未处于运行状态，最近日志如下："
        journalctl -u "$SERVICE_NAME" -n 25 --no-pager 2>/dev/null || true
        return 1
    fi
}

stop_service() {
    need_root || return 1
    if systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
        if systemctl stop "$SERVICE_NAME"; then
            ok "WOL Web 服务已停止。"
            show_status
        else
            err "停止服务失败。"
            show_status
            return 1
        fi
    else
        warn "服务尚未安装。"
    fi
}

select_nginx_paths() {
    local dump="/tmp/wol-nginx-test-$$.txt"
    if ! command -v nginx >/dev/null 2>&1; then
        err "未检测到 Nginx。脚本不会自动替换或安装 Nginx，以保护现有业务。"
        return 1
    fi
    if ! systemctl is-active --quiet nginx; then
        err "Nginx 当前未运行。为避免影响其他站点，请先确认现有 Nginx 状态。"
        return 1
    fi
    if ! nginx -T >"$dump" 2>&1; then
        err "nginx -T 检查失败，请先修复现有 Nginx 配置。"
        tail -n 20 "$dump" >&2
        rm -f "$dump"
        return 1
    fi
    if grep -Eq 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf;' "$dump"; then
        NGINX_CONF_FILE="/etc/nginx/conf.d/wol-web.conf"
        NGINX_LINK_FILE=""
    elif grep -Eq 'include[[:space:]]+/etc/nginx/sites-enabled/\*;' "$dump"; then
        NGINX_CONF_FILE="/etc/nginx/sites-available/wol-web.conf"
        NGINX_LINK_FILE="/etc/nginx/sites-enabled/wol-web.conf"
    else
        err "没有在 Nginx 配置中找到标准 conf.d 或 sites-enabled include；为避免修改全局配置，已停止。"
        rm -f "$dump"
        return 1
    fi
    rm -f "$dump"
}

write_nginx_config() {
    local domain="$1" external_port="$2" internal_port="$3"
    if [[ -e "$NGINX_CONF_FILE" ]] && ! grep -q "WOL-WEB MANAGED CONFIG" "$NGINX_CONF_FILE"; then
        err "$NGINX_CONF_FILE 已存在且不是本脚本创建的配置，拒绝覆盖。"
        return 1
    fi
    if [[ -n "$NGINX_LINK_FILE" && ( -e "$NGINX_LINK_FILE" || -L "$NGINX_LINK_FILE" ) ]]; then
        if [[ ! -L "$NGINX_LINK_FILE" || "$(readlink "$NGINX_LINK_FILE" 2>/dev/null)" != "$NGINX_CONF_FILE" ]]; then
            err "$NGINX_LINK_FILE 已存在且不是本脚本的符号链接，拒绝覆盖。"
            return 1
        fi
    fi
    mkdir -p "$(dirname "$NGINX_CONF_FILE")" || return 1
    local listen_v6=""
    if [[ -s /proc/net/if_inet6 ]]; then
        listen_v6="    listen [::]:${external_port} ssl;"
    fi
    cat > "$NGINX_CONF_FILE" <<EOF || return 1
# WOL-WEB MANAGED CONFIG
server {
    listen ${external_port} ssl;
${listen_v6}
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    # Only for HTTP sent to this HTTPS port (Nginx internal status 497).
    # The port must be preserved, e.g. http://domain:8119 -> https://domain:8119.
    error_page 497 =301 https://\$host:\$server_port\$request_uri;
    ssl_session_cache shared:WOLWEB:2m;
    ssl_session_timeout 10m;

    access_log /var/log/nginx/wol-web.access.log;
    error_log /var/log/nginx/wol-web.error.log;

    location / {
        proxy_pass http://127.0.0.1:${internal_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 5s;
        proxy_read_timeout 20s;
    }
}
EOF
    chmod 644 "$NGINX_CONF_FILE"
    if [[ -n "$NGINX_LINK_FILE" && ! -L "$NGINX_LINK_FILE" ]]; then
        ln -s "$NGINX_CONF_FILE" "$NGINX_LINK_FILE" || return 1
    fi
}

sync_existing_nginx() {
    local domain external internal old_file backup
    domain="$(config_get web_domain)"
    [[ -n "$domain" ]] || return 0
    if ! select_nginx_paths; then
        return 1
    fi
    old_file="$NGINX_CONF_FILE"
    # On first installation, a domain may exist in the config without a site yet.
    [[ -f "$old_file" ]] || return 0
    if ! grep -q "WOL-WEB MANAGED CONFIG" "$old_file"; then
        warn "发现与本程序同名的非托管 Nginx 文件，不做任何覆盖。"
        return 1
    fi
    backup="$(mktemp /tmp/wol-nginx-update.XXXXXX)" || return 1
    cp -a "$old_file" "$backup" || { rm -f "$backup"; return 1; }
    external="$(config_get external_port)"
    internal="$(config_get internal_port)"
    if write_nginx_config "$domain" "${external:-8119}" "${internal:-8109}" && nginx -t && systemctl reload nginx; then
        rm -f "$backup"
        ok "已更新 WOL 专属 Nginx 配置，HTTP 497 自动跳转至 HTTPS。"
        return 0
    fi
    err "同步 Nginx 失败，恢复原文件（不会更改其他站点）。"
    cp -a "$backup" "$old_file"
    rm -f "$backup"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    return 1
}

web_settings() {
    need_root || return 1
    is_installed || { err "请先运行菜单 1 安装部署。"; return 1; }

    local domain old_domain external_port internal_port old_external old_internal
    local password password_confirm password_hash=""
    old_domain="$(config_get web_domain)"
    old_external="$(config_get external_port)"
    old_internal="$(config_get internal_port)"
    old_external="${old_external:-8119}"
    old_internal="${old_internal:-8109}"

    printf '\n%s\n' "---- WEB 端设置 ----"
    read_default "网页访问域名（证书目录应为 /etc/letsencrypt/live/域名）" "$old_domain" || return 1
    domain="${REPLY,,}"
    read_default "外部 HTTPS 端口" "$old_external" || return 1
    external_port="$REPLY"
    read_default "内部服务端口（仅本机监听）" "$old_internal" || return 1
    internal_port="$REPLY"

    if ! validate_web_domain "$domain"; then
        err "网页域名格式不正确，请填写真实域名，例如 wol.example.com。"
        return 1
    fi
    if ! validate_port "$external_port" || ! validate_port "$internal_port"; then
        err "外部端口和内部端口必须是 1-65535 的整数。"
        return 1
    fi
    external_port=$((10#$external_port))
    internal_port=$((10#$internal_port))
    if (( external_port == internal_port )); then
        err "外部端口与内部端口不能相同。"
        return 1
    fi
    if [[ ! -s "/etc/letsencrypt/live/${domain}/fullchain.pem" || ! -s "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
        err "没有找到域名证书：/etc/letsencrypt/live/${domain}/fullchain.pem 或 privkey.pem。"
        err "请先确认证书目录名称与输入的域名完全一致。"
        return 1
    fi

    local current_hash generated_password=""
    current_hash="$(config_get password_hash)"
    if [[ -n "$current_hash" ]]; then
        info "已有 WEB 登录密码；此处直接回车保持原密码不变。"
        read_secret "修改网页登录密码（至少 6 位，回车保持原密码）: " || return 1
    else
        warn "尚未设置 WEB 登录密码；直接回车将自动生成随机密码。"
        read_secret "首次设置网页登录密码（至少 6 位，回车自动生成）: " || return 1
    fi
    password="$REPLY"
    if [[ -z "$password" && -z "$current_hash" ]]; then
        generated_password="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(18))')" || return 1
        password="$generated_password"
    fi
    if [[ -n "$password" ]]; then
        if (( ${#password} < 6 )); then
            err "密码至少需要 6 位。"
            return 1
        fi
        if [[ -z "$generated_password" ]]; then
            read_secret "确认网页登录密码: " || return 1
            password_confirm="$REPLY"
            if [[ "$password" != "$password_confirm" ]]; then
                err "两次输入不一致，未修改密码。"
                return 1
            fi
        fi
        password_hash="$(make_password_hash "$password")" || return 1
        unset password password_confirm
    fi

    select_nginx_paths || return 1

    local backup_dir conf_existed=0 link_existed=0 link_created=0
    backup_dir="$(mktemp -d /tmp/wol-web-backup.XXXXXX)" || return 1
    cp -a "$CONFIG_FILE" "$backup_dir/config.json" || { rm -rf "$backup_dir"; return 1; }
    cp -a "$SERVICE_FILE" "$backup_dir/service" || { rm -rf "$backup_dir"; return 1; }
    if [[ -f "$NGINX_CONF_FILE" ]]; then
        cp -a "$NGINX_CONF_FILE" "$backup_dir/nginx.conf"
        conf_existed=1
    fi
    if [[ -n "$NGINX_LINK_FILE" && ( -e "$NGINX_LINK_FILE" || -L "$NGINX_LINK_FILE" ) ]]; then
        link_existed=1
    fi

    local -a fields
    fields=("web_domain=$domain" "external_port=$external_port" "internal_port=$internal_port" "nginx_config_path=$NGINX_CONF_FILE" "nginx_link_path=$NGINX_LINK_FILE")
    fields+=("auth_enabled=true")
    [[ -n "$password_hash" ]] && fields+=("password_hash=$password_hash")
    if ! config_set_fields "${fields[@]}"; then
        err "写入 WEB 设置失败。"
        rm -rf "$backup_dir"
        return 1
    fi
    if ! write_service_unit "$internal_port" || ! write_nginx_config "$domain" "$external_port" "$internal_port"; then
        err "写入服务或 Nginx 配置失败，正在回滚。"
        cp -a "$backup_dir/config.json" "$CONFIG_FILE"
        cp -a "$backup_dir/service" "$SERVICE_FILE"
        if (( conf_existed == 1 )); then cp -a "$backup_dir/nginx.conf" "$NGINX_CONF_FILE"; else rm -f "$NGINX_CONF_FILE"; fi
        if [[ -n "$NGINX_LINK_FILE" && $link_existed -eq 0 ]]; then rm -f "$NGINX_LINK_FILE"; fi
        chown root:root "$CONFIG_FILE" 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        rm -rf "$backup_dir"
        return 1
    fi

    if ! nginx -t; then
        err "nginx -t 失败，正在回滚 WEB 设置。"
        cp -a "$backup_dir/config.json" "$CONFIG_FILE"
        cp -a "$backup_dir/service" "$SERVICE_FILE"
        if (( conf_existed == 1 )); then cp -a "$backup_dir/nginx.conf" "$NGINX_CONF_FILE"; else rm -f "$NGINX_CONF_FILE"; fi
        if [[ -n "$NGINX_LINK_FILE" && $link_existed -eq 0 ]]; then rm -f "$NGINX_LINK_FILE"; fi
        chown root:root "$CONFIG_FILE" 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        rm -rf "$backup_dir"
        return 1
    fi

    if ! systemctl daemon-reload || ! systemctl restart "$SERVICE_NAME"; then
        err "服务重启失败，正在回滚 WEB 设置。"
        cp -a "$backup_dir/config.json" "$CONFIG_FILE"
        cp -a "$backup_dir/service" "$SERVICE_FILE"
        if (( conf_existed == 1 )); then cp -a "$backup_dir/nginx.conf" "$NGINX_CONF_FILE"; else rm -f "$NGINX_CONF_FILE"; fi
        if [[ -n "$NGINX_LINK_FILE" && $link_existed -eq 0 ]]; then rm -f "$NGINX_LINK_FILE"; fi
        chown root:root "$CONFIG_FILE" 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        rm -rf "$backup_dir"
        return 1
    fi

    if ! systemctl reload nginx; then
        err "Nginx 重载失败，正在回滚 WEB 设置。"
        cp -a "$backup_dir/config.json" "$CONFIG_FILE"
        cp -a "$backup_dir/service" "$SERVICE_FILE"
        if (( conf_existed == 1 )); then cp -a "$backup_dir/nginx.conf" "$NGINX_CONF_FILE"; else rm -f "$NGINX_CONF_FILE"; fi
        if [[ -n "$NGINX_LINK_FILE" && $link_existed -eq 0 ]]; then rm -f "$NGINX_LINK_FILE"; fi
        chown root:root "$CONFIG_FILE" 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        rm -rf "$backup_dir"
        return 1
    fi

    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE"
    open_firewall_port "$external_port" || true
    rm -rf "$backup_dir"
    if [[ -n "$generated_password" ]]; then
        printf '\n%s\n' "${YELLOW}首次自动生成的网页登录密码（仅显示一次，请立即保存）：${RESET}"
        printf '%s\n\n' "$generated_password"
    fi
    ok "WEB 设置已应用，WOL 服务已重启，Nginx 配置检查通过并已重载。"
    printf '\n访问地址：%s\n' "https://${domain}:${external_port}/"
    info "Nginx 仅新增独立的 wol-web 配置文件，没有修改 nginx.conf 或其他站点文件。"
    info "网页使用单一密码登录，保留原有唤醒按钮和最近 5 条发送记录。"
    show_status
}

remove_nginx_config() {
    local changed=0
    if [[ -f /etc/nginx/conf.d/wol-web.conf ]] && grep -q "WOL-WEB MANAGED CONFIG" /etc/nginx/conf.d/wol-web.conf; then
        rm -f /etc/nginx/conf.d/wol-web.conf
        changed=1
    fi
    if [[ -L /etc/nginx/sites-enabled/wol-web.conf ]] && [[ "$(readlink /etc/nginx/sites-enabled/wol-web.conf 2>/dev/null)" == "/etc/nginx/sites-available/wol-web.conf" ]]; then
        rm -f /etc/nginx/sites-enabled/wol-web.conf
        changed=1
    fi
    if [[ -f /etc/nginx/sites-available/wol-web.conf ]] && grep -q "WOL-WEB MANAGED CONFIG" /etc/nginx/sites-available/wol-web.conf; then
        rm -f /etc/nginx/sites-available/wol-web.conf
        changed=1
    fi
    if (( changed == 1 )); then
        if nginx -t; then
            systemctl reload nginx && ok "已移除 WOL 专属 Nginx 配置并重载；其他站点配置未删除。"
        else
            warn "WOL 配置已从磁盘移除，但 nginx -t 未通过，因此没有重载 Nginx。请检查现有 Nginx 配置后手动 reload。"
        fi
    fi
}

uninstall_service() {
    need_root || return 1
    printf '\n'
    read -r -p "确认卸载 WOL Web，并删除本程序配置？输入 yes 继续: " answer || return 1
    [[ "$answer" == "yes" ]] || { info "已取消卸载。"; return 0; }

    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    remove_nginx_config

    # Only remove firewall rules recorded as created by this script.
    remove_firewall_rules

    if [[ -f "$SERVICE_FILE" ]] && grep -q "WOL-WEB MANAGED SERVICE" "$SERVICE_FILE"; then
        rm -f "$SERVICE_FILE"
    else
        warn "服务文件不是本脚本创建的，未删除：$SERVICE_FILE"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true

    if [[ -f "$APP_DIR/.wol-web-managed" ]]; then
        rm -rf "$APP_DIR"
    else
        warn "应用目录没有管理标记，未删除：$APP_DIR"
    fi
    ok "WOL Web 已卸载。未删除 /etc/letsencrypt 下的证书，也未删除或覆盖其他 Nginx 站点配置。"
    warn "若 VPS 云厂商还有独立安全组/网络 ACL，请自行移除其中为本服务添加的 TCP 端口规则。"
}

show_status() {
    local state enabled pid internal_port domain external_port
    printf '\n%s\n' "${BLUE}────────────────── WOL Web 运行状态 ──────────────────${RESET}"
    state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
    pid="$(systemctl show "$SERVICE_NAME" --property=MainPID --value 2>/dev/null || true)"
    case "$state" in
        active)   printf '  %s●%s 服务状态：%s运行中 (active)%s\n' "$GREEN" "$RESET" "$GREEN" "$RESET" ;;
        inactive) printf '  %s●%s 服务状态：%s已停止 (inactive)%s\n' "$YELLOW" "$RESET" "$YELLOW" "$RESET" ;;
        failed)   printf '  %s●%s 服务状态：%s启动失败 (failed)%s\n' "$RED" "$RESET" "$RED" "$RESET" ;;
        *)        printf '  %s●%s 服务状态：%s\n' "$YELLOW" "$RESET" "${state:-未安装}" ;;
    esac
    printf '  开机自启：%s\n' "${enabled:-未配置}"
    if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 0 )); then
        printf '  主进程 PID：%s\n' "$pid"
    fi
    if [[ -f "$CONFIG_FILE" ]]; then
        internal_port="$(config_get internal_port)"
        domain="$(config_get web_domain)"
        external_port="$(config_get external_port)"
        printf '  NAS 目标：%s\n' "$(config_get host)"
        printf '  唤醒端口：UDP %s\n' "$(config_get port)"
        printf '  本地监听：127.0.0.1:%s\n' "${internal_port:-8109}"
        if [[ -n "$domain" ]]; then
            printf '  网页入口：https://%s:%s/\n' "$domain" "${external_port:-8119}"
        else
            printf '  网页入口：%s尚未设置（菜单 3）%s\n' "$YELLOW" "$RESET"
        fi
        printf '  应用目录：%s\n' "$APP_DIR"
        printf '  配置文件：%s\n' "$CONFIG_FILE"
        if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 3 "http://127.0.0.1:${internal_port:-8109}/healthz" 2>/dev/null | grep -q '"ok":true'; then
            printf '  页面健康检测：%s正常%s\n' "$GREEN" "$RESET"
        else
            printf '  页面健康检测：%s尚未响应%s\n' "$YELLOW" "$RESET"
        fi
    else
        printf '  配置状态：%s未安装%s\n' "$YELLOW" "$RESET"
    fi
    printf '%s\n' "${BLUE}──────────────────────────────────────────────────────${RESET}"
}

menu_item() {
    local number="$1" label="$2" note="${3:-}" color="${CYAN}"
    [[ "$number" == "6" ]] && color="${RED}"
    printf '  %s[%s]%s  %s  %s%s%s\n' "$color" "$number" "$RESET" "$label" "$DIM" "$note" "$RESET"
}

main_menu() {
    while true; do
        local selection current_status status_text
        printf '\n%s\n' "${BLUE}╔══════════════════════════════════════════════════════╗${RESET}"
        printf '%s\n' "${BLUE}║${RESET}            ${CYAN}${BOLD}WOL NAS 远程唤醒管理中心${RESET}  ${DIM}v${VERSION}${RESET} ${BLUE}║${RESET}"
        printf '%s\n' "${BLUE}╚══════════════════════════════════════════════════════╝${RESET}"
        current_status="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
        if [[ "$current_status" == "active" ]]; then
            status_text="${GREEN}● 服务运行中${RESET}"
        elif [[ "$current_status" == "failed" ]]; then
            status_text="${RED}● 服务启动失败${RESET}"
        else
            status_text="${YELLOW}● 服务未运行${RESET}"
        fi
        printf '  %s\n' "$status_text"
        printf '  %s安装目录：%s%s\n' "$DIM" "$APP_DIR" "$RESET"
        printf '\n%s\n' "${PURPLE}  ── 基础管理 ──${RESET}"
        menu_item 1 '安装部署' '仅安装程序，不询问密码/端口'
        menu_item 2 '配置 NAS' 'MAC / DDNS / UDP 9'
        menu_item 3 'WEB 端设置' '域名 / 端口 / 密码 / 放行防火墙'
        printf '\n%s\n' "${PURPLE}  ── 服务管理 ──${RESET}"
        menu_item 4 '重启服务' '重启后显示当前运行状态'
        menu_item 5 '停止服务' '停止网页服务'
        menu_item 6 '卸载' '仅删除 WOL 专属文件'
        printf '\n'
        menu_item 0 '退出' ''
        printf '%s\n' "${BLUE}──────────────────────────────────────────────────────${RESET}"
        read -r -p '请选择操作 [0-6]: ' selection || exit 0
        case "$selection" in
            1) install_deploy; pause_menu ;;
            2) configure_nas; pause_menu ;;
            3) web_settings; pause_menu ;;
            4) restart_service; pause_menu ;;
            5) stop_service; pause_menu ;;
            6) uninstall_service; pause_menu ;;
            0) exit 0 ;;
            *) warn '无效选项，请输入 0-6。' ;;
        esac
    done
}

main_menu
