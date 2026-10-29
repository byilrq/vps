#!/usr/bin/env bash
# WOL Web management script
# Menu inputs use normal terminal line editing; Backspace works in SSH terminals.
set -uo pipefail

VERSION="1.6.2"
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
    key = sys.argv[2]
    v = d
    for part in key.split("."):
        v = v.get(part) if isinstance(v, dict) else None
    # Missing values print nothing, not JSON braces.
    if isinstance(v, (dict, list)):
        print("")
    elif v is not None:
        print(v)
except Exception:
    print("")
PY
}

config_set_fields() {
    local arg
    ensure_config || return 1
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
    if key in ("port", "relay6_port", "external_port", "internal_port", "send_count", "cooldown_seconds"):
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
    ensure_config || return 1
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

validate_host6() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
host = sys.argv[1].strip()
if not host or any(c.isspace() for c in host) or "://" in host or "/" in host or "\\" in host:
    raise SystemExit(1)
try:
    address = ipaddress.ip_address(host.strip("[]"))
except ValueError:
    domain = host.rstrip(".")
    labels = domain.split(".")
    pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    raise SystemExit(0 if len(domain) <= 253 and all(pattern.fullmatch(label) for label in labels) else 1)
else:
    raise SystemExit(0 if address.version == 6 and address.is_global else 1)
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
    # This release is self-contained: install only the bundled matching wol.py.
    # Do not fetch remote copies or fall back to a different program version.
    if [[ ! -f "$SCRIPT_DIR/wol.py" ]]; then
        err "安装缺少 wol.py。请将本版 wol.py 和 wol.sh 放在同一个目录。"
        return 1
    fi
    if ! grep -Fq "WOL_WEB_APP_VERSION = \"$VERSION\"" "$SCRIPT_DIR/wol.py"; then
        err "wol.py 与 wol.sh 版本不一致，请使用同一 ZIP 中的两个文件。"
        return 1
    fi
    if ! "$VENV_PY" -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$SCRIPT_DIR/wol.py"; then
        err "wol.py 语法检查失败。"
        return 1
    fi
    if [[ "$(readlink -f "$SCRIPT_DIR/wol.py" 2>/dev/null || printf '%s' "$SCRIPT_DIR/wol.py")" != "$(readlink -f "$APP_DIR/wol.py" 2>/dev/null || printf '%s' "$APP_DIR/wol.py")" ]]; then
        install -o root -g root -m 644 "$SCRIPT_DIR/wol.py" "$APP_DIR/wol.py" || return 1
    fi
    chmod 644 "$APP_DIR/wol.py"
    info "已安装本地 v${VERSION} 的 wol.py。"
}

ensure_config() {
    # A missing config is initialized. Missing or unusable individual fields
    # receive safe defaults; existing password, host and port values remain.
    # No schema-version gate and no conversion of unrelated field names.
    python3 - "$CONFIG_FILE" <<'PY_CONFIG'
import json, os, secrets, sys, tempfile
from pathlib import Path

path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
created = not path.exists()
try:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
except (OSError, ValueError) as exc:
    print(f"[ERROR] config.json 无法读取或不是有效 JSON；为保护原配置，未自动覆盖：{exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(data, dict):
    print("[ERROR] config.json 的根内容必须是 JSON 对象；为保护原配置，未自动覆盖。", file=sys.stderr)
    raise SystemExit(1)

changed = created
added = []
strings = ("host1", "host2", "mac", "web_domain", "password_hash",
           "relay6_secret_file",
           "nginx_config_path", "nginx_link_path")
for key in strings:
    if not isinstance(data.get(key), str):
        data[key] = ""
        changed = True
        added.append(key)
if not isinstance(data.get("secret_key"), str) or not data["secret_key"].strip():
    data["secret_key"] = secrets.token_hex(32)
    changed = True
    added.append("secret_key")
if not data["relay6_secret_file"]:
    data["relay6_secret_file"] = str(path.parent / "wol6_secret")
    changed = True
    added.append("relay6_secret_file")
if data.get("wake_mode") not in ("ipv4", "ipv6"):
    data["wake_mode"] = "ipv4"
    changed = True
    added.append("wake_mode")
for key, default in (("port", 9), ("relay6_port", 41996), ("send_count", 5),
                     ("cooldown_seconds", 20), ("external_port", 8119),
                     ("internal_port", 8109)):
    val = data.get(key)
    if isinstance(val, bool):
        val = None
    try:
        num = int(val)
    except (TypeError, ValueError):
        num = default
    valid = ((1024 <= num <= 65535) if key == "relay6_port" else
             (1 <= num <= 65535)) if key.endswith("port") or key == "port" else (num > 0)
    if not valid:
        num = default
    if data.get(key) != num or isinstance(data.get(key), bool):
        data[key] = num
        changed = True
        added.append(key)
if data.get("auth_enabled") is not True:
    data["auth_enabled"] = True
    changed = True
    added.append("auth_enabled")
if not isinstance(data.get("firewall"), dict):
    data["firewall"] = {}
    changed = True
    added.append("firewall")
for kind in ("ufw", "firewalld", "iptables"):
    key = kind + "_added_ports"
    if not isinstance(data["firewall"].get(key), list):
        data["firewall"][key] = []
        changed = True
        added.append("firewall." + key)

if changed:
    fd, tmp = tempfile.mkstemp(prefix=".wol-config-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
os.chmod(path, 0o600)
if created:
    print("[INFO] 已创建默认 config.json；NAS 域名和 WEB 设置请在菜单 2/3 填写。")
elif added:
    print("[INFO] 已自动补齐缺失参数：" + ", ".join(added))
PY_CONFIG
    local rc=$?
    (( rc == 0 )) || return "$rc"
    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
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
    local is_new_config=0
    [[ -f "$CONFIG_FILE" ]] || is_new_config=1
    ensure_config || { err "创建或补齐配置失败。"; return 1; }
    if (( is_new_config == 1 )); then
        info "请在菜单 3 设置 WEB 密码和端口。"
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
    if [[ ! -f "$SERVICE_FILE" && ! -f "$APP_DIR/.wol-web-managed" ]]; then
        err "请先运行菜单 1 安装部署。"
        return 1
    fi
    ensure_config || return 1

    local current_mode mode_selection mode old_host old_backup old_mac old_port
    local host_input backup_input mac_input port_input relay_port secret_file mac resolved
    current_mode="$(config_get wake_mode)"
    printf '\n%s\n' "---- 唤醒模式选择 ----"
    printf '  1) 仅 IPV4：host1 + host2，进行 IPv4 解析比对和双域名发送\n'
    printf '  2) 仅 IPV6：只使用 host1，经 AX6 IPv6 认证中继唤醒，不发送 host2\n'
    if [[ "$current_mode" == "ipv6" ]]; then mode_selection="2"; else mode_selection="1"; fi
    read_default "请选择模式（1=IPV4，2=IPV6）" "$mode_selection" || return 1
    case "$REPLY" in
        1) mode="ipv4" ;;
        2) mode="ipv6" ;;
        *) err "请选择 1（IPV4）或 2（IPV6）。"; return 1 ;;
    esac

    old_host="$(config_get host1)"
    old_backup="$(config_get host2)"
    old_mac="$(config_get mac)"
    old_port="$(config_get port)"; old_port="${old_port:-9}"

    if [[ "$mode" == "ipv4" ]]; then
        printf '\n%s\n' "---- IPV4 唤醒参数（host1 + host2） ----"
        read_default "NAS 网卡 MAC 地址（例如 00:11:22:33:44:55）" "$old_mac" || return 1
        mac_input="$REPLY"
        read_default "主域名 host1（第一轮）" "$old_host" || return 1
        host_input="$REPLY"
        read_default "备域名 host2（第二轮，可留空）" "$old_backup" || return 1
        backup_input="$REPLY"
        [[ "$backup_input" == "-" ]] && backup_input=""
        read_default "UDP 端口（主备共用）" "$old_port" || return 1
        port_input="$REPLY"
        if ! mac="$(normalize_mac "$mac_input" 2>/dev/null)"; then
            err "MAC 地址格式错误，请使用 00:11:22:33:44:55。"
            return 1
        fi
        if ! validate_host "$host_input"; then
            err "主域名或 IPv4 地址格式错误；不要填写 http:// 或端口。"
            return 1
        fi
        if [[ -n "$backup_input" ]]; then
            if ! validate_host "$backup_input"; then
                err "备域名或 IPv4 地址格式错误。"
                return 1
            fi
            if [[ "${backup_input,,}" == "${host_input,,}" || "${backup_input,,}" == "${host_input,,}." || "${backup_input,,}." == "${host_input,,}" ]]; then
                err "主域名与备域名不能相同。"
                return 1
            fi
        fi
        if ! validate_port "$port_input"; then
            err "UDP 端口必须是 1-65535 的整数。"
            return 1
        fi
        config_set_fields "wake_mode=ipv4" "mac=$mac" "host1=$host_input" "host2=$backup_input" "port=$((10#$port_input))" || return 1
        ok "当前模式：IPV4；主备域名参数已保存。"
        printf 'MAC：%s\n主域名：%s\n备域名：%s\nUDP 端口：%s\n' \
            "$mac" "$host_input" "${backup_input:-（未启用）}" "$port_input"
        info "主域名与备域名依次发包，域名解析 IP 比对仍生效。"
        if command -v getent >/dev/null 2>&1; then
            resolved="$(getent ahostsv4 "$host_input" 2>/dev/null | awk 'NR==1 {print $1}')"
            [[ -n "$resolved" ]] && info "主域名 IPv4：$resolved" || warn "主域名暂未解析到 IPv4。"
            if [[ -n "$backup_input" ]]; then
                resolved="$(getent ahostsv4 "$backup_input" 2>/dev/null | awk 'NR==1 {print $1}')"
                [[ -n "$resolved" ]] && info "备域名 IPv4：$resolved" || warn "备域名暂未解析到 IPv4。"
            fi
        fi
    else
        printf '\n%s\n' "---- IPV6 中继唤醒参数（仅 host1） ----"
        read_default "AX6 IPv6 中继域名 host1（AAAA：nas.xyrq.de）" "$old_host" || return 1
        host_input="$REPLY"
        if ! validate_host6 "$host_input"; then
            err "请填写具有公网 AAAA 的 AX6 中继域名或全球单播 IPv6 地址。"
            return 1
        fi
        relay_port="$(config_get relay6_port)"
        read_default "路由器中继 UDP 端口" "${relay_port:-41996}" || return 1
        relay_port="$REPLY"
        if ! validate_port "$relay_port" || (( 10#$relay_port < 1024 )); then
            err "IPv6 中继端口必须是 1024-65535 的整数。"
            return 1
        fi
        secret_file="$(config_get relay6_secret_file)"
        secret_file="${secret_file:-${APP_DIR}/wol6_secret}"
        # This secret is shared with the AX6 relay. Never display it in menus/logs.
        if [[ ! -e "$secret_file" ]]; then
            if ! python3 - "$secret_file" <<'PY_SECRET'
import os, secrets, sys
path = sys.argv[1]
with open(path, "x", encoding="ascii") as f:
    f.write(secrets.token_hex(32) + "\n")
os.chmod(path, 0o600)
PY_SECRET
            then
                err "创建 IPv6 中继共享密钥失败。"
                return 1
            fi
            ok "已生成共享密钥文件：${secret_file}（内容不会显示）"
        fi
        chmod 600 "$secret_file" || return 1
        config_set_fields "wake_mode=ipv6" "host1=$host_input" \
            "relay6_port=$((10#$relay_port))" "relay6_secret_file=$secret_file" || return 1
        ok "当前模式：IPV6；host1 单域名发送；host2 已停用发送（配置值保留）。"
        info "AX6 中继域名：$host_input；中继 UDP 端口：$relay_port"
        info "共享密钥：$secret_file；需将其安全复制到 AX6 的 /data/wol6/secret。"
        warn "IPv6 仅使用经 HMAC 验证的路由器中继 ACK 判定发包成功；NAS 开机状态不由此确认。"
        # One DNS check is informational only; the actual sender does its own AAAA lookup.
        if command -v python3 >/dev/null 2>&1; then
            python3 - "$host_input" <<'PY_DNS' || true
import ipaddress, socket, sys
try:
    records = socket.getaddrinfo(sys.argv[1].strip('[]'), 41996, socket.AF_INET6, socket.SOCK_DGRAM)
    ips = sorted({str(ipaddress.IPv6Address(item[4][0])) for item in records if ipaddress.IPv6Address(item[4][0]).is_global})
    print('[INFO] 当前 AAAA：' + ', '.join(ips) if ips else '[WARN] 尚未解析到公网 AAAA。')
except (OSError, ValueError) as exc:
    print('[WARN] AAAA 暂不可解析：' + str(exc))
PY_DNS
        fi
    fi
    info "设置即时生效，WEB 左上角会显示当前模式。"
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
    [[ -f "$SERVICE_FILE" ]] || { err "请先运行菜单 1 安装部署。"; return 1; }
    ensure_config || return 1

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
        local wake_mode
        wake_mode="$(config_get wake_mode)"
        printf '  唤醒模式：%s\n' "${wake_mode^^}"
        printf '  host1：%s\n' "$(config_get host1)"
        if [[ "$wake_mode" == "ipv6" ]]; then
            printf '  host2：%s\n' '（IPV6 模式不使用）'
            printf '  中继端口：UDP %s\n' "$(config_get relay6_port)"
        else
            local backup_display
            backup_display="$(config_get host2)"
            printf '  备域名 host2：%s\n' "${backup_display:-（未启用）}"
            printf '  唤醒端口：UDP %s\n' "$(config_get port)"
        fi
        printf '  本地监听：127.0.0.1:%s\n' "${internal_port:-8109}"
        if [[ -n "$domain" ]]; then
            printf '  网页入口：https://%s:%s/\n' "$domain" "${external_port:-8119}"
        else
            printf '  网页入口：%s尚未设置（菜单 3）%s\n' "$YELLOW" "$RESET"
        fi
        printf '  应用目录：%s\n' "$APP_DIR"
        printf '  配置文件：%s\n' "$CONFIG_FILE"
        printf '  最近20次本地发送日志：%s\n' "$APP_DIR/wol_send.log"
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
        printf '%s\n' "${BLUE}║${RESET}            ${CYAN}${BOLD}WOL 管理中心${RESET}  ${DIM}v${VERSION}${RESET} ${BLUE}║${RESET}"
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
        menu_item 2 '配置 NAS' '仅 IPV4 / 仅 IPV6 / 域名 / 端口'
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
