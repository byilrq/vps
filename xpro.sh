#!/bin/bash
############################# xpro (3X-UI exclusive manager) #############################
# Restored from the original panel-based version. Independent Xray removed.
# Menu 3 and 12 guard panel/core upgrades and preserve Reality credentials.


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
    read_tty "按回车键继续..." _
}

# -----------------------------
#  兼容式读取输入
# -----------------------------
read_tty() {
    local prompt="$1" name="$2" value=""
    # Readline (-e) handles both BS (Ctrl-H) and DEL in SSH terminals.
    # For automation/pipes keep the usual non-interactive read behavior.
    if [[ -t 0 ]]; then
        IFS= read -e -r -p "$prompt" value || return 1
    else
        IFS= read -r -p "$prompt" value || return 1
    fi
    printf -v "$name" '%s' "$value"
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

# Fallback reinstallation port guard.  Run BEFORE UPDATE_XUIDB writes
# realitySettings.target and fallbacks[].dest.
port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        [[ -n "$(ss -H -lnt "( sport = :${port} )" 2>/dev/null)" ]]
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${port}$"
    else
        echo '[ERROR] neither ss nor netstat is installed; cannot safely check ports' >&2
        return 2
    fi
}

xui_port_listeners() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -H -lntp "( sport = :${port} )" 2>/dev/null
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntp 2>/dev/null | grep -E "(^|:)${port}[[:space:]]" || true
    fi
}

xui_reusable_nginx_fallback() {
    local port="$1" listeners line local_address found=0
    listeners="$(xui_port_listeners "$port")"
    [[ -n "$listeners" ]] || return 1
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        local_address="$(awk '{print $4}' <<< "$line")"
        case "$local_address" in
            "127.0.0.1:${port}"|"[::1]:${port}"|"0.0.0.0:${port}"|"[::]:${port}"|"*:${port}"|":::${port}") ;;
            *) return 1 ;;
        esac
        [[ "$line" == *nginx* ]] || return 1
        found=1
    done <<< "$listeners"
    (( found == 1 ))
}

xui_nginx_tls_responds() {
    local port="$1" tls_host="${domain:-}" pem=''
    command -v openssl >/dev/null 2>&1 || return 1
    if [[ -z "$tls_host" && -s "$XUIDB" ]] && command -v sqlite3 >/dev/null 2>&1; then
        tls_host="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.serverNames[0]') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
    fi
    [[ -n "$tls_host" ]] || return 1
    # The previous check accepted ANY certificate on port 8080, which could
    # silently switch an existing site's 443 fallback to an unrelated vhost.
    pem="$(timeout 7 openssl s_client -connect "127.0.0.1:${port}" \
        -servername "$tls_host" -showcerts < /dev/null 2>/dev/null \
        | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')" || return 1
    [[ "$pem" == *'-----BEGIN CERTIFICATE-----'* ]] || return 1
    openssl x509 -noout -checkhost "$tls_host" 2>/dev/null <<< "$pem" >/dev/null
}

# A user-owned vhost for this hostname must remain the REALITY fallback. If
# it is stopped/broken, choosing a new random fallback would make the old
# website appear offline even though its config/files were not deleted.
xui_user_website_config_exists() {
    local file name="${domain:-}" pattern=''
    [[ -n "$name" ]] || return 1
    pattern="^[[:space:]]*server_name[[:space:]]+.*${name//./\\.}([[:space:];]|$)"
    for file in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$file" ]] || continue
        if grep -Fqx '# XUI_PRO_MANAGED_FALLBACK_V9' "$file" 2>/dev/null; then
            continue
        fi
        if grep -Eq "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

xui_select_fallback_port() {
    local requested="${fallback_port:-8080}" candidate=0
    if ! [[ "$requested" =~ ^[0-9]+$ ]] || (( requested < 1 || requested > 65535 )); then
        echo '[ERROR] invalid fallback port' >&2
        return 1
    fi
    if xui_user_website_config_exists && ! xui_nginx_tls_responds "$requested"; then
        echo "[ERROR] 已有 ${domain} 网站，但其 HTTPS 回落 127.0.0.1:${requested} 不可用。" >&2
        echo '[ERROR] 为保护原网站，不会擅自改用 8081 或覆盖原站配置。请先恢复网站 HTTPS。' >&2
        return 1
    fi
    if port_in_use "$requested"; then
        : # The requested port has an active listener.
    else
        local rc=$?
        (( rc == 1 )) || return 1
        echo "[OK] fallback 127.0.0.1:${requested} is free"
        return 0
    fi
    if xui_reusable_nginx_fallback "$requested" && xui_nginx_tls_responds "$requested"; then
        echo "[OK] existing HTTPS website on 127.0.0.1:${requested}: reuse WITHOUT changing Nginx files"
        return 0
    fi
    echo "[WARN] fallback ${requested} occupied, but not a usable Nginx TLS endpoint: $(xui_port_listeners "$requested" | head -n2)"
    for ((candidate=8081; candidate<=8199; candidate++)); do
        [[ "$candidate" == 8090 ]] && continue  # existing sub2sing-box port
        if port_in_use "$candidate"; then
            continue
        else
            local rc=$?
            (( rc == 1 )) || return 1
            fallback_port="$candidate"
            echo "[OK] using a free local-only TLS fallback ${fallback_port}; existing website stays unchanged"
            return 0
        fi
    done
    echo '[ERROR] no free fallback port in 8081..8199; nothing will be terminated automatically' >&2
    return 1
}


# Website isolation preflight: the installer never changes a user-owned
# sites-enabled vhost to force nginx -t to pass. Fail BEFORE any panel/database
# modifications, avoiding a partially installed X-UI with a broken disguise.
xui_nginx_preflight_preserve() {
    command -v nginx >/dev/null 2>&1 || return 0
    local report=''
    report="$(nginx -t 2>&1)" && return 0
    echo '[ERROR] 当前已有 Nginx 配置无法通过检查，安装/修复已安全中止；未修改网站。' >&2
    printf '%s\n' "$report" >&2
    if [[ "$report" == *'/etc/nginx/sites-enabled/wow:'* && "$report" == *'no "ssl_certificate" is defined'* ]]; then
        echo '[HINT] wow 本身是 HTTP:8080；另一个旧 X.sh SSL:8080 可能与它冲突。' >&2
        echo '[HINT] 使用 v12 独立 TLS 桥接，不要向原 wow 文件添加证书。' >&2
    fi
    echo '[HINT] X.sh 不会擅自移动、覆盖或删除用户 Nginx 网站文件。' >&2
    return 1
}


# The user's /etc/nginx/sites-enabled/wow is a plain HTTP site on 8080.
# An older X.sh-generated SSL server on the SAME socket causes Nginx to
# falsely report that wow (line 1) has no ssl_certificate. Never touch wow.
# Self-contained bridge repair module: xpro.sh no longer requires a third
# uploaded Python file. The module is extracted into a private X-UI directory.
xui_bridge_helper_path() {
    local target='/root/x-ui-safe/repair-http-fallback-xpro.py'
    mkdir -p /root/x-ui-safe || return 1
    chmod 700 /root/x-ui-safe || return 1
    cat > "$target" <<'XPRO_EMBED_BRIDGE_HELPER'
#!/usr/bin/env python3
"""Repair an X.sh-created conflicting SSL listener without editing user website.

Architecture:
  user HTTP site: 127.0.0.1:8080 (untouched)
  managed TLS bridge: 127.0.0.1:8081 (or another free 8081..8199)
  REALITY target: 127.0.0.1:<TLS bridge port>

Only files positively identified as generated by earlier versions of X.sh are
migrated. Every changed Nginx file is backed up outside the include directories.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time


BRIDGE_BACKUP_BASE = Path('/root/x-ui-safe/site-bridge-backups')


def run(args, timeout=25, input_text=None):
    return subprocess.run(args, text=True, input=input_text, capture_output=True, timeout=timeout)


def say(s):
    print(s, flush=True)


def fail(s):
    raise RuntimeError(s)


def nginx_syntax():
    return run(['nginx', '-t'])


def ssl_listen_ports(src):
    return [int(m.group(1)) for m in re.finditer(
        r'\blisten\s+(?:127\.0\.0\.1|\[::1\]):([0-9]{1,5})\b[^;]*\bssl\b[^;]*;', src)]


def parse_http_site(site, domain):
    if not site.is_file():
        return None
    src = site.read_text(encoding='utf-8')
    # The user site MUST be plain HTTP, listen on loopback and match the SNI.
    server_names = re.findall(r'\bserver_name\s+([^;]+);', src)
    if not any(domain in names.split() for names in server_names):
        return None
    matches = re.findall(r'\blisten\s+127\.0\.0\.1:([0-9]{1,5})\b([^;]*);', src)
    http_ports = [int(port) for port, args in matches if 'ssl' not in args.split()]
    if len(http_ports) != 1 or http_ports[0] != 8080 or ssl_listen_ports(src):
        return None
    return http_ports[0]


def validate_cert(domain, cert, key):
    if not cert.is_file() or not key.is_file():
        fail(f'{domain} 证书或私钥不存在：{cert} / {key}；未修改网站')
    for args in [
        ['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'],
        ['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', domain],
    ]:
        proc = run(args)
        if proc.returncode:
            fail('现有证书已过期或与域名不匹配；不修改网站或节点')
    certpub = run(['openssl', 'x509', '-in', str(cert), '-noout', '-pubkey'])
    keypub = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
    if certpub.returncode or keypub.returncode or certpub.stdout.strip() != keypub.stdout.strip():
        fail('证书与私钥不匹配；不修改网站或节点')


def own_legacy(path, domain, fallback_port):
    """True for *only* positively fingerprinted, old X.sh-generated SSL vhosts."""
    if not path.is_file():
        return False
    src = path.read_text(encoding='utf-8')
    if domain not in src or not any(8080 <= p <= 8199 for p in ssl_listen_ports(src)):
        return False
    if path.name == f'xui-pro-fallback-{domain}.conf':
        return '# XUI_PRO_MANAGED_FALLBACK_V9' in src or '# XUI_PRO_MANAGED_FALLBACK_V12' in src
    if path.name == domain and path.is_symlink():
        target = path.resolve()
        if target != (Path('/etc/nginx/sites-available') / domain):
            return False
        return (re.search(r'\bserver_tokens\s+off\s*;', src) is not None
                and re.search(r'\binclude\s+/etc/nginx/snippets/includes\.conf\s*;', src) is not None
                and re.search(r'\broot\s+/var/www/html/?\s*;', src) is not None)
    return False


def socket_free(port):
    proc = run(['ss', '-H', '-lnt', f'( sport = :{port} )'])
    return proc.returncode == 0 and not proc.stdout.strip()


def tls_matches(port, domain):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return False
        pem = ssl.DER_cert_to_PEM_cert(der)
        proc = run(['openssl', 'x509', '-noout', '-checkhost', domain], input_text=pem)
        return proc.returncode == 0
    except (OSError, ssl.SSLError, subprocess.TimeoutExpired):
        return False


def locate_old_stanzas(domain, backend, managed):
    # Do not search, patch or replace arbitrary user-owned vhosts.
    candidates = [managed, Path('/etc/nginx/sites-enabled') / domain]
    stale = []
    for p in candidates:
        if p.exists() and own_legacy(p, domain, backend):
            stale.append(p)
        elif p.is_file() and p == managed:
            src = p.read_text(encoding='utf-8')
            if '# XUI_PRO_MANAGED_FALLBACK_V9' not in src and '# XUI_PRO_MANAGED_FALLBACK_V12' not in src:
                fail(f'已有同名 Nginx 配置不属于 X.sh：{p}；拒绝覆盖')
    return stale


def choose_port(domain, managed, old, requested):
    # Reuse the existing working managed TLS port if it matches the SNI.
    if managed.is_file():
        src = managed.read_text(encoding='utf-8')
        if '# XUI_PRO_MANAGED_FALLBACK_V' in src:
            for port in ssl_listen_ports(src):
                if port != old and tls_matches(port, domain):
                    return port
    for port in ([requested] if requested else []) + list(range(8081, 8200)):
        if port <= 1024 or port == old:
            continue
        if socket_free(port):
            return port
    fail('8081..8199 均被占用，无法创建独立 TLS 回落端口')


def render_conf(domain, backend, port, cert, key):
    return f'''# XUI_PRO_MANAGED_FALLBACK_V12
# Owned by X.sh. User website /etc/nginx/sites-enabled/wow remains unchanged.
# TLS bridge: Xray REALITY -> 127.0.0.1:{port} TLS -> 127.0.0.1:{backend} HTTP
server {{
    listen 127.0.0.1:{port} ssl;
    server_name {domain};
    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {{
        proxy_pass http://127.0.0.1:{backend};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header Connection "";
        proxy_redirect off;
    }}
}}
'''


def nginx_restart_or_reload():
    active = run(['systemctl', 'is-active', '--quiet', 'nginx']).returncode == 0
    action = 'reload' if active else 'start'
    r = run(['systemctl', action, 'nginx'], timeout=25)
    if r.returncode:
        fail(f'Nginx {action} 失败：{r.stderr[-500:]}')


def request_code(domain, port, secure=False):
    if not shutil.which('curl'):
        return None
    if secure:
        args = ['curl', '--noproxy', '*', '-k', '-sS', '--connect-timeout', '3',
                '--max-time', '8', '--resolve', f'{domain}:{port}:127.0.0.1',
                '-o', '/dev/null', '-w', '%{http_code}', f'https://{domain}:{port}/']
    else:
        args = ['curl', '--noproxy', '*', '-sS', '--connect-timeout', '3',
                '--max-time', '8', '-H', f'Host: {domain}', '-o', '/dev/null',
                '-w', '%{http_code}', f'http://127.0.0.1:{port}/']
    try:
        proc = run(args, timeout=10)
        if proc.returncode == 0 and re.fullmatch(r'[0-9]{3}', proc.stdout.strip()):
            return int(proc.stdout.strip())
    except (OSError,subprocess.TimeoutExpired):
        pass
    return None


def apply_nginx(domain, backend, port, managed, stale, config):
    """Make only script-owned changes, with complete file rollback on syntax failure."""
    backup = BRIDGE_BACKUP_BASE / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    moved = []
    old_managed_text = None
    installed_new = False
    try:
        # Migrate the old X.sh SSL vhost symlink; do not modify its target.
        for path in stale:
            if path == managed:
                continue
            dest = backup / ('old-symlink-' + path.name)
            os.replace(path, dest)
            moved.append((path, dest))
            say(f'[BACKUP] 已迁移旧 X.sh 自建 TLS 站点链接：{path} -> {dest}')
        managed.parent.mkdir(parents=True, exist_ok=True)
        if managed.is_file():
            if not ('# XUI_PRO_MANAGED_FALLBACK_V9' in managed.read_text()
                    or '# XUI_PRO_MANAGED_FALLBACK_V12' in managed.read_text()):
                fail(f'不是 X.sh 创建的文件，拒绝覆盖：{managed}')
            old_managed_text = managed.read_text()
            shutil.copy2(managed, backup / 'previous-managed-fallback.conf')
            os.chmod(backup / 'previous-managed-fallback.conf', 0o600)
        # Write into .conf location atomically; old config was backed up.
        with tempfile.NamedTemporaryFile(mode='w', prefix='.xui-bridge-', dir=managed.parent,
                                         encoding='utf-8', delete=False) as fp:
            fp.write(config)
            temp = Path(fp.name)
        temp.chmod(0o644)
        os.replace(temp, managed)
        installed_new = True
        res = nginx_syntax()
        if res.returncode:
            fail('nginx -t 未通过，撤销新增桥接配置：\n' + (res.stdout + res.stderr)[-1400:])
        nginx_restart_or_reload()
        if not tls_matches(port, domain):
            fail(f'TLS 127.0.0.1:{port} 没有返回匹配 {domain} 的证书')
        upstream = request_code(domain, backend)
        wrapper = request_code(domain, port, secure=True)
        if upstream is not None and wrapper is not None:
            say(f'[INFO] 原站 HTTP={upstream}，TLS 桥接 HTTPS={wrapper}')
            if wrapper in (502, 504) and upstream not in (502, 504):
                fail('HTTPS 桥接没有正常转发到用户 HTTP 网站，撤销本次改动')
        say(f'[OK] Nginx TLS 桥接已工作：127.0.0.1:{port} -> HTTP 127.0.0.1:{backend}')
        say(f'[BACKUP] 仅备份了脚本自建配置：{backup}')
        return backup
    except Exception:
        if installed_new:
            if old_managed_text is None:
                managed.unlink(missing_ok=True)
            else:
                managed.write_text(old_managed_text)
        for original, removed in reversed(moved):
            if removed.exists() or removed.is_symlink():
                os.replace(removed, original)
        # Restore running Nginx where possible, retaining user site intact.
        if nginx_syntax().returncode == 0:
            try:
                nginx_restart_or_reload()
            except Exception:
                pass
        say('[ROLLBACK] 已撤销本次对 X.sh 生成配置的修改，原 wow 网站从未改动')
        raise


def get_inbound(db):
    if not db.exists():
        return None
    con = sqlite3.connect(f'file:{db}?mode=ro', uri=True, timeout=10)
    try:
        row = con.execute('''SELECT id,port,settings,stream_settings FROM inbounds
                             WHERE protocol='vless' AND enable=1
                               AND json_extract(stream_settings,'$.security')='reality'
                             ORDER BY id DESC LIMIT 1''').fetchone()
    finally:
        con.close()
    if not row:
        return None
    rid, port, settings, stream = row
    stream = json.loads(stream)
    target = (stream.get('realitySettings') or {}).get('target')
    sni = (stream.get('realitySettings') or {}).get('serverNames') or []
    return {'id':rid,'port':port,'settings':json.loads(settings),'stream':stream,
            'target':target,'sni':sni[0] if sni else ''}


def db_backup(db):
    base=BRIDGE_BACKUP_BASE
    base.mkdir(parents=True,exist_ok=True,mode=0o700)
    out=base / ('db-before-bridge-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.sqlite3')
    with sqlite3.connect(f'file:{db}?mode=ro',uri=True,timeout=10) as src:
        with sqlite3.connect(str(out)) as dest:
            src.backup(dest)
    out.chmod(0o600)
    return out


def update_db(db, domain, port, inbound):
    if inbound is None:
        say('[INFO] 没有已启用的 REALITY 入站；安装阶段稍后写入新回落端口')
        return
    if inbound['sni'] != domain:
        fail(f'数据库 SNI={inbound["sni"]} 与网站 {domain} 不一致；拒绝修改数据库')
    new = f'127.0.0.1:{port}'
    if new == inbound['target']:
        say(f'[OK] REALITY 已指向正确的回落端口 {new}，无需改库')
        return
    snapshot = db_backup(db)
    say(f'[BACKUP] 面板数据库：{snapshot}')
    old = inbound['target']
    stopped=False
    try:
        r=run(['systemctl','stop','x-ui'],timeout=20)
        if r.returncode: fail('停止 3X-UI 失败，拒绝改库')
        stopped=True
        with sqlite3.connect(str(db),timeout=10) as con:
            row=con.execute('SELECT settings,stream_settings FROM inbounds WHERE id=?',
                            (inbound['id'],)).fetchone()
            if not row or json.loads(row[1]) != inbound['stream']:
                fail('数据库已被其他操作修改，拒绝覆盖')
            ss=json.loads(row[1]); st=json.loads(row[0])
            ss['realitySettings']['target']=new
            if 'dest' in ss['realitySettings']:
                ss['realitySettings']['dest']=new
            for fb in st.get('fallbacks') or []:
                if fb.get('dest')==old: fb['dest']=new
            con.execute('UPDATE inbounds SET settings=?,stream_settings=? WHERE id=?',
                        (json.dumps(st,ensure_ascii=False,separators=(',',':')),
                         json.dumps(ss,ensure_ascii=False,separators=(',',':')),
                         inbound['id']))
        r=run(['systemctl','start','x-ui'],timeout=25)
        if r.returncode: fail('3X-UI 启动失败：'+r.stderr[-400:])
        runtime=Path('/usr/local/x-ui/bin/config.json')
        for _ in range(25):
            try:
                conf=json.loads(runtime.read_text())
                matches=[x for x in conf.get('inbounds',[]) if x.get('protocol')=='vless'
                         and int(x.get('port') or 0)==int(inbound['port'])
                         and x.get('streamSettings',{}).get('security')=='reality']
                if matches:
                    rr=matches[0]['streamSettings']['realitySettings']
                    if rr.get('target')==new and len(matches[0].get('settings',{}).get('clients',[]))>=1:
                        say(f'[OK] 运行中的 REALITY 入站包含客户端，target={new}')
                        return
            except (OSError,ValueError,KeyError,TypeError):
                pass
            time.sleep(.3)
        fail('Xray 运行配置未生成新的回落目标或缺少有效客户端')
    except Exception:
        if stopped:
            run(['systemctl','stop','x-ui'],timeout=20)
            with sqlite3.connect(str(snapshot)) as src:
                with sqlite3.connect(str(db),timeout=10) as dest:
                    src.backup(dest)
            run(['systemctl','start','x-ui'],timeout=20)
            say('[ROLLBACK] 面板数据库已恢复，REALITY 节点密钥和 UUID 未变')
        raise


def main():
    p=argparse.ArgumentParser(description='Non-destructive TLS bridge for an existing HTTP wow website')
    p.add_argument('--domain',default='wow.xyrq.de')
    p.add_argument('--site',default='/etc/nginx/sites-enabled/wow')
    p.add_argument('--db',default='/etc/x-ui/x-ui.db')
    p.add_argument('--apply',action='store_true',help='Explicitly install X.sh-owned TLS bridge and reconcile DB')
    p.add_argument('--no-db',action='store_true',help='Install-stage: bridge only; X.sh writes DB later')
    p.add_argument('--port',type=int,default=8081)
    args=p.parse_args()
    if os.geteuid()!=0 and args.apply: fail('执行 --apply 需要 root')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}',args.domain):
        fail('域名不合法')
    site=Path(args.site)
    backend=parse_http_site(site,args.domain)
    if backend is None:
        say('[SKIP] 未发现符合条件的用户原站 HTTP 127.0.0.1:8080；未修改任何文件')
        return 2
    cert=Path(f'/etc/letsencrypt/live/{args.domain}/fullchain.pem')
    key=Path(f'/etc/letsencrypt/live/{args.domain}/privkey.pem')
    managed=Path('/etc/nginx/conf.d') / f'xui-pro-fallback-{args.domain}.conf'
    stale=locate_old_stanzas(args.domain,backend,managed)
    existing=get_inbound(Path(args.db)) if not args.no_db else None
    if existing and existing['sni']!=args.domain:
        fail('面板 SNI 与指定网站不一致，拒绝自动修改')
    port=choose_port(args.domain,managed,backend,args.port)
    say(f'[INFO] 用户原站（保持不变）: {site}，HTTP 127.0.0.1:{backend}')
    say(f'[PLAN] 独立 TLS: 127.0.0.1:{port} -> 原站 HTTP 127.0.0.1:{backend}')
    if stale:
        for item in stale:
            say(f'[PLAN] 迁移早期 X.sh 自建的冲突 SSL 监听：{item}（保留备份）')
    if existing:
        say(f'[PLAN] REALITY target: {existing["target"]} -> 127.0.0.1:{port}')
    if not args.apply:
        say('[SAFE] 只读检查完成。需要实际修复请添加 --apply')
        return 0
    validate_cert(args.domain,cert,key)
    config=render_conf(args.domain,backend,port,cert,key)
    if not stale and managed.is_file() and managed.read_text()==config and tls_matches(port,args.domain):
        say('[OK] 独立 TLS 桥接已存在，无需修改 Nginx')
    else:
        apply_nginx(args.domain,backend,port,managed,stale,config)
    if not tls_matches(port,args.domain):
        fail('回落端口 TLS 验证失败，未修改面板数据库')
    if not args.no_db:
        update_db(Path(args.db),args.domain,port,existing)
    say(f'XUI_BRIDGE_PORT={port}')
    say('[OK] 原 wow 网站配置未被修改；桥接回落完成')
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, sqlite3.Error, subprocess.TimeoutExpired) as e:
        print('[ERROR] '+str(e),file=sys.stderr)
        sys.exit(1)
XPRO_EMBED_BRIDGE_HELPER
    chmod 600 "$target" || return 1
    python3 -m py_compile "$target" || return 1
    printf '%s\n' "$target"
}


xui_bridge_http_site() {
    local short="${domain%%.*}" file
    [[ -n "${domain:-}" && "$domain" == *.* ]] || return 1
    for file in "/etc/nginx/sites-enabled/$short"; do
        [[ -f "$file" ]] || continue
        grep -Eq '^[[:space:]]*listen[[:space:]]+127\.0\.0\.1:8080[[:space:]]*;' "$file" || continue
        grep -Fq "$domain" "$file" || continue
        printf '%s\n' "$file"
        return 0
    done
    return 1
}

# Mode "install" prepares Nginx only, before UPDATE_XUIDB.
# Mode "repair" also reconciles the existing REALITY target (with DB backup).
xui_bridge_apply() {
    local mode="${1:-repair}" helper site result rc selected
    site="$(xui_bridge_http_site 2>/dev/null || true)"
    [[ -n "$site" ]] || return 2
    helper="$(xui_bridge_helper_path 2>/dev/null || true)"
    if [[ -z "$helper" ]]; then
        msg_err '此 VPS 存在 HTTP 8080 原网站，缺少 v12 TLS 桥接修复组件。'
        echo '[HINT] 请确认 python3 可用。xpro.sh 已内置 TLS 回落修复组件。'
        return 1
    fi
    local -a args=(--domain "$domain" --site "$site" --apply)
    [[ "$mode" == install ]] && args+=(--no-db)
    if result="$(python3 "$helper" "${args[@]}" 2>&1)"; then rc=0; else rc=$?; fi
    printf '%s\n' "$result"
    (( rc == 0 )) || return "$rc"
    selected="$(printf '%s\n' "$result" | sed -nE 's/^XUI_BRIDGE_PORT=([0-9]+)$/\1/p' | tail -n1)"
    if ! [[ "$selected" =~ ^[0-9]+$ ]]; then
        msg_err 'TLS 桥接工具未输出回落端口，拒绝继续写库'
        return 1
    fi
    fallback_port="$selected"
    return 0
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
    # Independent 3X-UI uninstaller: never alter Nginx, PHP, certificates,
    # web roots, S-UI/sing-box or third-party services. The 443 public entry
    # may briefly go offline if it was supplied by Xray; this is NOT a reason
    # to block a deliberate 3X-UI uninstall.
    local backup_dir cron_tmp old_crontab
    backup_dir="/root/x-ui-safe/uninstall-before-$(date +%Y%m%d_%H%M%S)-$$"
    mkdir -p "$backup_dir" || return 1
    chmod 700 "$backup_dir"

    if [[ -f "$XUIDB" ]]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$XUIDB" ".backup '$backup_dir/x-ui.db'" || cp -a "$XUIDB" "$backup_dir/x-ui.db" || return 1
        else
            cp -a "$XUIDB" "$backup_dir/x-ui.db" || return 1
        fi
        chmod 600 "$backup_dir/x-ui.db"
    fi
    [[ ! -f /etc/systemd/system/x-ui.service ]] || cp -a /etc/systemd/system/x-ui.service "$backup_dir/" || return 1
    [[ ! -f /usr/local/x-ui/bin/config.json ]] || cp -a /usr/local/x-ui/bin/config.json "$backup_dir/xray-config.json" || return 1

    # Stop only the x-ui unit and its cgroup-owned child Xray process.
    # Do NOT use pkill -x xray, which might terminate unrelated software.
    systemctl stop x-ui 2>/dev/null || true
    systemctl disable x-ui 2>/dev/null || true
    rm -rf -- /etc/x-ui /usr/local/x-ui || return 1
    rm -f -- /usr/bin/x-ui /etc/systemd/system/x-ui.service || return 1
    systemctl daemon-reload 2>/dev/null || true

    # Drop only this script's cron entries. Keep all other user's jobs.
    if command -v crontab >/dev/null 2>&1; then
        old_crontab="$(mktemp)" || return 1
        cron_tmp="$(mktemp)" || { rm -f "$old_crontab"; return 1; }
        if crontab -l > "$old_crontab" 2>/dev/null; then
            grep -Ev '(# XUI_PRO_MANAGED_CRON_V9|/(root/)?(x\.sh|xpro\.sh) --xui-(guard|monthly))' "$old_crontab" > "$cron_tmp" || true
            if [[ -s "$cron_tmp" ]]; then
                crontab "$cron_tmp" || { rm -f "$old_crontab" "$cron_tmp"; return 1; }
            else
                crontab -r 2>/dev/null || true
            fi
        fi
        rm -f -- "$old_crontab" "$cron_tmp"
    fi
    msg_ok '3X-UI 与其自带 Xray 已独立卸载；没有操作 S-UI、Nginx、网站、证书、PHP。'
    echo "[BACKUP] $backup_dir"
    echo '[INFO] 若公网 443 原由 Xray 监听，网站公网入口会中断，直到其他服务接管 443；内网站点与文件保持不变。'
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
    echo "仅卸载 3X-UI / 其自带 Xray；不会操作 S-UI、Nginx、伪装站、证书或网页。"
    read_tty "确认继续卸载？(y/N): " confirm_uninstall
    if [[ ! "$confirm_uninstall" =~ ^[Yy]$ ]]; then
        msg_err "已取消卸载。"
        return 0
    fi

    if UNINSTALL_XUI; then
        msg_ok "已卸载完成！"
        exit 0
    fi
    msg_err "卸载失败，请查看上述错误；未修改 S-UI 或网站"
    return 1
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
        read_tty "请输入域名（domain.tld）: " domain
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
        read_tty "确认继续安装依赖？(Y/n): " confirm_install_pkg
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
            curl wget jq bash sudo $install_nginx certbot sqlite3 ufw cron \
            netcat-traditional uuid-runtime openssl python3 unzip </dev/null; then

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
                    netcat-traditional uuid-runtime openssl python3 unzip </dev/null || {
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
        yum install -y curl wget jq sqlite openssl qrencode python3 unzip \
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
    # NEVER stop nginx, apache, caddy or delete existing enabled sites.
    # Reuse a valid certificate without invoking certbot.
    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        msg_ok "现有证书有效，直接复用：${cert_domain}"
        return 0
    fi
    mkdir -p /var/www/acme
    if ! command -v certbot >/dev/null 2>&1; then
        msg_err '未安装 certbot，且没有可用的本地证书。'
        return 1
    fi
    if port_in_use 80; then
        # Existing HTTP server stays live. This succeeds only if the user's
        # existing :80 site already serves /var/www/acme challenges.
        msg_inf '80 已由现有服务使用：尝试非侵入式 webroot 验证（不修改网站配置）。'
        certbot certonly --webroot -w /var/www/acme \
            --non-interactive --agree-tos --register-unsafely-without-email \
            -d "$cert_domain" || return 1
    else
        # Standalone uses unoccupied port 80; no web service is stopped.
        msg_inf '80 空闲：以 standalone 模式申请证书，不修改 Nginx 配置。'
        certbot certonly --standalone --preferred-challenges http \
            --non-interactive --agree-tos --register-unsafely-without-email \
            -d "$cert_domain" || return 1
    fi
    cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"
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

    if cert_files_exist "$cert_domain" && cert_is_valid "$cert_domain" && cert_key_matches "$cert_domain"; then
        msg_ok "检测到有效的已有证书，直接复用；不签发、不覆盖：${cert_domain}"
        return 0
    fi

    while true; do
        echo "----------------------------------------------------------------"
        echo "证书处理：${cert_domain}"
        echo "----------------------------------------------------------------"
        print_cert_paths "$cert_domain"
        echo
        echo "Y = 重新申请 Let's Encrypt 证书"
        echo "n = 使用 VPS 本地已有证书（若有效）"
        echo "q = 退出脚本"
        read_tty "请选择 [Y/n/q]: " cert_choice

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
# Strict version parser shared by interactive and argument-based installation.
# Reject arbitrary words before making any download or changing the installation.
xui_panel_valid_version() {
    local version="$1" numeric minimum="2.3.5"
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    numeric="${version#v}"
    [[ "$(printf '%s\n' "$minimum" "$numeric" | sort -V | head -n 1)" == "$minimum" ]]
}

xui_panel_fetch_latest() {
    local body="" latest=""
    body="$(curl -fsSL --connect-timeout 8 --max-time 20 \
       'https://api.github.com/repos/MHSanaei/3x-ui/releases/latest' 2>/dev/null)" || return 1
    if command -v jq >/dev/null 2>&1; then
        latest="$(printf '%s' "$body" | jq -r '.tag_name // empty' 2>/dev/null)"
    else
        latest="$(printf '%s\n' "$body" | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"(v[0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' | head -n1)"
    fi
    xui_panel_valid_version "$latest" || return 1
    XUI_PANEL_LATEST="$latest"
}

# Branch selection always uses stable GitHub releases (not prereleases or
# GitHub tags from unreleased commits). Page through all available releases.
xui_panel_resolve_minor() {
    local major="$1" minor="$2" page=1 length=0 body="" matches="" tag=""
    local all_matches=""
    command -v jq >/dev/null 2>&1 || {
        echo '[ERROR] branch resolution requires jq (apt install jq)' >&2
        return 1
    }
    while (( page <= 10 )); do
        body="$(curl -fsSL --connect-timeout 8 --max-time 25 \
          "https://api.github.com/repos/MHSanaei/3x-ui/releases?per_page=100&page=${page}" 2>/dev/null)" || {
            echo '[ERROR] GitHub releases API unavailable; cannot confirm branch version' >&2
            return 1
        }
        if ! printf '%s' "$body" | jq -e 'type == "array"' >/dev/null 2>&1; then
            echo '[ERROR] invalid GitHub releases API reply (or rate limit reached)' >&2
            return 1
        fi
        length="$(printf '%s' "$body" | jq 'length')"
        matches="$(printf '%s' "$body" |
          jq -r --arg branch "v${major}.${minor}." '
            .[] | select(.draft != true and .prerelease != true)
            | (.tag_name // empty)
            | select(type == "string" and startswith($branch))
            | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
          ')"
        [[ -z "$matches" ]] || all_matches+="${matches}"$'\n'
        (( length < 100 )) && break
        if (( page == 10 )); then
            echo '[ERROR] release listing exceeds pagination safety limit; cannot guarantee newest patch' >&2
            return 1
        fi
        (( page += 1 ))
    done
    tag="$(printf '%s' "$all_matches" | sed '/^$/d' | sort -Vu | tail -n1)"
    if ! xui_panel_valid_version "$tag"; then
        echo "[ERROR] official stable release branch v${major}.${minor}.x not found" >&2
        return 1
    fi
    XUI_PANEL_RESOLVED_MINOR="$tag"
}

xui_panel_resolve_input() {
    local input="$1" default_version="$2" candidate="" numeric=""
    XUI_PANEL_SELECTED_TAG=""
    case "${input,,}" in
        '') candidate="$default_version" ;;
        latest)
            if [[ -z "${XUI_PANEL_LATEST:-}" ]] && ! xui_panel_fetch_latest; then
                echo '[ERROR] cannot confirm latest official version; try again' >&2
                return 1
            fi
            candidate="$XUI_PANEL_LATEST"
            ;;
        0|q|quit|exit) echo '[INFO] installation canceled'; return 2 ;;
        *)
            numeric="${input#[vV]}"
            if [[ "$numeric" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
                if ! xui_panel_resolve_minor "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"; then
                    return 1
                fi
                candidate="$XUI_PANEL_RESOLVED_MINOR"
            elif [[ "$numeric" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                candidate="v${numeric}"
            else
                if [[ "${input,,}" == 'latset' ]]; then
                    echo '[ERROR] typo latset; correct command: latest' >&2
                else
                    echo "[ERROR] invalid version: ${input}; use latest, V3.10, V3.9 or v3.10.2" >&2
                fi
                return 1
            fi
            ;;
    esac
    if ! xui_panel_valid_version "$candidate"; then
        echo "[ERROR] version too old or invalid: ${candidate}" >&2
        return 1
    fi
    XUI_PANEL_SELECTED_TAG="$candidate"
    return 0
}

xui_panel_choose_version() {
    local input="" latest="" rc=0
    local default_version="v3.10.2"
    XUI_PANEL_SELECTED_TAG=""
    XUI_PANEL_LATEST=""

    if [[ $# -gt 0 ]]; then
        xui_panel_resolve_input "$1" "$default_version"
        return $?
    fi
    echo '正在获取 3x-ui 最新稳定版本...'
    xui_panel_fetch_latest || true
    latest="${XUI_PANEL_LATEST:-}"

    while :; do
        echo '--------------------------------------------------------------'
        echo "当前 3x-ui 最新稳定版本: ${latest:-unavailable}"
        echo "直接回车：安装默认版本 ${default_version}"
        echo '输入 latest：安装官方最新稳定版'
        echo '输入 V3.10 或 V3.9：安装该分支最新稳定补丁版'
        echo '输入 v3.10.2 或 3.10.2：安装指定版本；0 取消'
        if ! read_tty '请选择: ' input; then
            echo '[INFO] input aborted; installation canceled'
            return 1
        fi
        if xui_panel_resolve_input "$input" "$default_version"; then
            echo "[OK] 将安装官方版本: ${XUI_PANEL_SELECTED_TAG}"
            return 0
        else
            rc=$?
            (( rc == 2 )) && return 1
            echo '[WARN] 输入无效，请重新选择版本。'
        fi
    done
}

# Install from a verified GitHub release artifact.  Never delete an existing
# panel due to malformed version input, a 404, or an incomplete download.
install_panel() {
    local tag_version="" url="" archive="" pending="" package_arch=""
    xui_panel_choose_version "$@" || return 1
    tag_version="$XUI_PANEL_SELECTED_TAG"

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y -q wget curl jq tar tzdata || return 1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget curl jq tar tzdata || return 1
    fi

    package_arch="$(arch)" || return 1
    archive="/usr/local/x-ui-linux-${package_arch}.tar.gz"
    url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-${package_arch}.tar.gz"
    pending="$(mktemp "/usr/local/.x-ui-${tag_version}-XXXXXXXX.tar.gz")" || return 1
    echo "开始下载官方 3x-ui ${tag_version} ..."
    if ! curl -fL --connect-timeout 15 --max-time 180 --retry 2 \
        --output "$pending" "$url"; then
        echo "[ERROR] ${tag_version} 发布包不存在或下载失败。原面板没有被替换。" >&2
        rm -f "$pending"
        return 1
    fi
    if [[ ! -s "$pending" ]] || ! tar -tzf "$pending" >/dev/null 2>&1; then
        echo '[ERROR] 下载包为空或损坏，原面板没有被替换。' >&2
        rm -f "$pending"
        return 1
    fi
    mv -f "$pending" "$archive" || return 1
    cd /usr/local/ || return 1

    # 以下为公共安装步骤（下载 x-ui.sh、解压、配置等）
    if ! curl -fLsS --connect-timeout 12 --max-time 45 \
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/${tag_version}/x-ui.sh" \
        -o /usr/bin/x-ui-temp; then
        echo "[ERROR] 下载 x-ui.sh 失败；未替换面板。"
        rm -f /usr/bin/x-ui-temp
        return 1
    fi

    if [[ ! -s /usr/bin/x-ui-temp ]]; then
        echo '[ERROR] 面板管理脚本为空，未替换原面板。'
        rm -f /usr/bin/x-ui-temp
        return 1
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
#  3X-UI 兼容版本与已验证内核保护（不再强制追最新）
# -----------------------------
setup_xray_update_cron() {
    # Called only after the user already consented. Do not ask twice.
    xui_setup_guard_cron --yes
}

xray_updata() {
    xui_maintenance_menu
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
        # Required by 3X-UI v3 client normalization. Blank email silently
        # removes the user from the generated Xray config after restart.
        reality_email="r_${client_id//-/}"

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

        reality_uri="vless://${client_id}@${domain}:${reality_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&spx=%2F&type=tcp&headerType=none&support-x25519mlkem768=true#R"
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
      "email": "${reality_email}",
      "limitIp": 0,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": true,
      "tgId": 0,
      "subId": "R",
      "reset": 0
    }
  ],
  "decryption": "none"
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
      "tgId": 0,
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
        "certificateFile": "/etc/letsencrypt/live/${domain}/fullchain.pem",
        "keyFile": "/etc/letsencrypt/live/${domain}/privkey.pem",
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
VALUES ('1','1','${reality_email}','0','0','0','0','0');
INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset")
VALUES ('2','1','${ws_email}','0','0','0','0','0');
EOF_SQL

        # 3X-UI >= 3.x reads dedicated normalized client tables on restart.
        # Directly writing inbounds.settings alone creates zero authorized users.
        # Reinstall mode reconciles links after reassigning inbound IDs.
        if ! xui_sync_normalized_clients fresh; then
            msg_err '3X-UI 客户端关联写入失败，拒绝以空用户配置启动'
            return 1
        fi

        if [[ "$(sqlite3 "$XUIDB" 'PRAGMA quick_check;' 2>/dev/null)" != 'ok' ]] ||
           [[ "$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings, '\$.security')='reality';" 2>/dev/null)" != '1' ]]; then
            msg_err '面板数据库写入验证失败，停止后续部署'
            return 1
        fi
        /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${panel_port}" -webBasePath "${panel_path}"
        /usr/local/x-ui/x-ui cert \
			-webCert "/etc/letsencrypt/live/${domain}/fullchain.pem" \
		-webCertKey "/etc/letsencrypt/live/${domain}/privkey.pem"
        x-ui start
        sleep 3

        msg_ok "双协议节点写入完成"
        echo "Reality PrivateKey: [仅保存在 3X-UI 数据库，不打印]"
        echo "Reality PublicKey(客户端 pbk): ${public_key}"
        echo "Hash32(可忽略): ${hash32}"
        echo "Reality URI: ${reality_uri}"
        echo "WS+TLS+CDN URI: ${ws_uri}"

else
    msg_err "x-ui.db 文件不存在！可能 x-ui 尚未安装。"
    exit 1
fi
}
xui_managed_nginx_fallback_path() {
    [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ && "$domain" == *.* ]] || return 1
    printf '/etc/nginx/conf.d/xui-pro-fallback-%s.conf\n' "$domain"
}

configure_nginx() {
    local owned_conf temp_conf previous_conf='' nginx_before='' nginx_after=''
    local listen_line http2_directive='' nginx_version='' major=0 minor=0 patch=0
    [[ -n "${fallback_port:-}" && "$fallback_port" =~ ^[0-9]+$ ]] || {
        msg_err 'REALITY fallback_port 不合法'; return 1;
    }
    [[ -s "${CERT_FULLCHAIN:-/nonexistent}" && -s "${CERT_PRIVKEY:-/nonexistent}" ]] || {
        msg_err '本地 SSL 证书文件不存在，不能创建回落服务'; return 1;
    }

    xui_nginx_preflight_preserve || return 1

    if port_in_use "$fallback_port"; then
        if xui_reusable_nginx_fallback "$fallback_port" && xui_nginx_tls_responds "$fallback_port"; then
            msg_ok "复用现有伪装站 HTTPS 127.0.0.1:${fallback_port}，不修改或重启 Nginx。"
            return 0
        fi
        msg_err "回落端口 ${fallback_port} 被占用且没有可复用的 HTTPS，拒绝修改原网站。"
        return 1
    fi

    # Do not silently disable a preexisting site such as sites-enabled/wow.
    nginx_before="$(nginx -t 2>&1)" || {
        msg_err '现有 Nginx 配置本来就不通过检查，拒绝修改用户网站：'
        printf '%s\n' "$nginx_before"
        return 1
    }
    owned_conf="$(xui_managed_nginx_fallback_path)" || return 1
    mkdir -p /etc/nginx/conf.d
    if [[ -e "$owned_conf" || -L "$owned_conf" ]]; then
        if ! grep -Fqx '# XUI_PRO_MANAGED_FALLBACK_V9' "$owned_conf"; then
            msg_err "同名 Nginx 配置属于其他程序，拒绝覆盖：$owned_conf"
            return 1
        fi
        previous_conf="$(mktemp /tmp/xui-pro-nginx-backup.XXXXXX)" || return 1
        cp -a "$owned_conf" "$previous_conf" || { rm -f "$previous_conf"; return 1; }
    fi
    temp_conf="$(mktemp /etc/nginx/conf.d/.xui-pro.XXXXXX)" || return 1

    nginx_version="$(nginx -v 2>&1 | sed -nE 's#.*nginx/([0-9]+)\.([0-9]+)\.([0-9]+).*#\1 \2 \3#p')"
    if [[ -n "$nginx_version" ]]; then
        read -r major minor patch <<< "$nginx_version"
    fi
    listen_line="    listen 127.0.0.1:${fallback_port} ssl http2;"
    if (( major > 1 || (major == 1 && minor > 25) || (major == 1 && minor == 25 && patch >= 1) )); then
        listen_line="    listen 127.0.0.1:${fallback_port} ssl;"
        http2_directive='    http2 on;'
    fi
    cat > "$temp_conf" <<EOF
# XUI_PRO_MANAGED_FALLBACK_V9
# Dedicated loopback listener owned by this installer. Existing sites are untouched.
server {
    server_name ${domain};
${listen_line}
${http2_directive}
    ssl_certificate ${CERT_FULLCHAIN};
    ssl_certificate_key ${CERT_PRIVKEY};
    root /var/www/html;
    index index.html index.htm;
    location / { try_files \$uri \$uri/ =404; }
}
EOF
    if ! mv -f "$temp_conf" "$owned_conf"; then
        rm -f "$temp_conf" "$previous_conf"
        return 1
    fi
    if ! nginx -t; then
        msg_err '新增回落站点无效，立即撤销我们创建的配置；保留全部原站点。'
        if [[ -n "$previous_conf" ]]; then
            cp -a "$previous_conf" "$owned_conf" || true
        else
            rm -f "$owned_conf"
        fi
        rm -f "$previous_conf"
        return 1
    fi
    if systemctl is-active --quiet nginx; then
        if ! systemctl reload nginx; then
            msg_err 'Nginx reload 失败，撤销新建配置。'
            if [[ -n "$previous_conf" ]]; then cp -a "$previous_conf" "$owned_conf"; else rm -f "$owned_conf"; fi
            rm -f "$previous_conf"
            return 1
        fi
    else
        if ! systemctl start nginx; then
            msg_err 'Nginx 启动失败，撤销新建配置。'
            if [[ -n "$previous_conf" ]]; then cp -a "$previous_conf" "$owned_conf"; else rm -f "$owned_conf"; fi
            rm -f "$previous_conf"
            return 1
        fi
    fi
    rm -f "$previous_conf"
    msg_ok "已新增独立回落监听 127.0.0.1:${fallback_port}；没有修改任何原网站配置。"
}

# Existing installations that were interrupted after the 3X-UI node was
# written can repair nginx without reinstalling or rotating any credentials.
xui_repair_nginx_existing() {
    # Compatibility with --fix-nginx: read-only check, NEVER move or edit site files.
    local sni fb
    [[ -s "$XUIDB" ]] || { msg_err '面板数据库不存在'; return 1; }
    sni="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.serverNames[0]') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
    fb="$(xui_real_fallback_port 2>/dev/null || echo 8080)"
    if xui_reusable_nginx_fallback "$fb" && xui_nginx_tls_responds "$fb"; then
        msg_ok "检测正常：${sni} 使用已存在的 HTTPS 伪装站，未修改文件。"
        return 0
    fi
    msg_err "未能确认 127.0.0.1:${fb} 的 Nginx HTTPS 服务；原网站文件不会被修改。"
    return 1
}

# -----------------------------
#  安装 sub2sing-box （提供订阅服务）
# -----------------------------
install_sub2sing_box() {
    echo "----------------------------------------------------------------"
    echo "安装 sub2sing-box（将订阅/节点连接转换为 sing-box 配置的工具）"
    echo "----------------------------------------------------------------"
    echo "即将安装本地 sub2sing-box 服务（127.0.0.1:8090）。"
    read_tty "确认继续安装 sub2sing-box？(Y/n): " confirm_sub2sing
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
    local confirm_cron confirm_xray_cron
    echo '仅配置 X-UI 专用计划任务；不会改写现有 certbot、Nginx 或其他任务。'
    read_tty '是否设置 X-UI 计划任务？(y/N): ' confirm_cron
    if [[ "$confirm_cron" =~ ^[Yy]$ ]]; then
        (
            crontab -l 2>/dev/null | grep -v '# XUI_PRO_MANAGED_CRON_V9' || true
            echo '@reboot /usr/bin/sub2sing-box server --bind 127.0.0.1 --port 8090 > /dev/null 2>&1 # XUI_PRO_MANAGED_CRON_V9'
            echo '@daily /usr/bin/x-ui restart > /dev/null 2>&1 # XUI_PRO_MANAGED_CRON_V9'
        ) | crontab -
        msg_ok '已添加 X-UI 专属任务；原有计划任务保留。'
    fi
    read_tty '是否设置 Xray 兼容性定期检查？(y/N): ' confirm_xray_cron
    if [[ "$confirm_xray_cron" =~ ^[Yy]$ ]]; then
        setup_xray_update_cron n || msg_err 'Xray 兼容性检查未设置成功'
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
    read_tty "确认执行？输入 YES 继续: " confirm
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
    read_tty " 请选择 [0-4]: " ans

    case "$ans" in
      1)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，尝试安装"
          apt-get update || true
          DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || {
            red "安装 ufw 失败"
            read_tty "回车返回..." _
            continue
          }
        fi

        local sshp ports default_ports all_ports p start end
        sshp="$(get_ssh_port)"
        default_ports="80 443 8443 2053"

        yellow "当前 SSH 端口：$sshp，将自动放行 tcp/udp 防止失联。"
        yellow "默认还将放行端口：$default_ports"
        read_tty "请输入需要额外放行的端口（例如：2222 51000-52000，可留空）: " ports

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
        read_tty "回车返回菜单..." _
        ;;
      2)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw，无需关闭。"
          read_tty "回车返回..." _
          continue
        fi
        ufw disable
        ufw status
        read_tty "回车返回菜单..." _
        ;;
      3)
        if ! command -v ufw >/dev/null 2>&1; then
          yellow "未检测到 ufw。"
          read_tty "回车返回..." _
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
        read_tty "回车返回菜单..." _
        ;;
      4)
        _purge_except_ssh
        read_tty "回车返回菜单..." _
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
        msg_inf "网站入口（手动部署内容至 /var/www/html，回落端口 127.0.0.1:${fallback_port}）: https://${domain}/\n"
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
        if [[ -n "${reality_uri:-}" ]]; then
            (umask 077; printf '%s\n' "$reality_uri" > /root/_xui_reality_uri.txt)
            msg_inf "REALITY 客户端链接已保存：/root/_xui_reality_uri.txt（重装后必须重新导入）\n"
        fi

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

	reality_uri="vless://${REALITY_UUID_DB}@${REALITY_DOMAIN_DB}:${REALITY_PORT_DB}?encryption=none&flow=${REALITY_FLOW_DB}&security=reality&sni=${REALITY_DOMAIN_DB}&fp=${REALITY_FP_DB}&pbk=${REALITY_PUBLIC_KEY_DB}&sid=${REALITY_SHORT_ID_DB}&spx=%2F&type=tcp&headerType=none&support-x25519mlkem768=true#R"
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
        read_tty "请输入新域名 (如 example.com): " new_domain
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

    read_tty "确认解析已完成？(y/N): " dns_ok

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

    msg_inf '复用证书原路径，不改动任何 /root/cert 网站证书软链接。'

    msg_inf '原 Nginx 伪装站保持不变；本操作仅更新 3X-UI 的域名/SNI/面板证书引用。'
    msg_inf '请确保已有网站的证书与新 SNI 匹配；本脚本不会改动网站配置。'

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
    '$.tlsSettings.certificates[0].certificateFile', '${cert_file}',
    '$.tlsSettings.certificates[0].keyFile', '${key_file}'
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
        "UPDATE settings SET value='${cert_file}' WHERE key='webCertFile';" \
        2>/dev/null || true

    sqlite3 "$XUIDB" \
        "UPDATE settings SET value='${key_file}' WHERE key='webKeyFile';" \
        2>/dev/null || true

    /usr/local/x-ui/x-ui cert \
        -webCert "${cert_file}" \
        -webCertKey "${key_file}" \
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
    read_tty "请输入要检测的目标域名（如 www.yahoo.co.jp）: " check_domain
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

  download_with_retry "$url" "$tmp" || { red "下载 sys_conf.sh 失败"; read_tty "回车返回..." _; return 1; }
  [[ -s "$tmp" ]] || { red "sys_conf.sh 文件为空"; read_tty "回车返回..." _; return 1; }
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

    # Refuse to take over an existing website's 443 listener. No service
    # will be stopped and no Nginx configuration will be changed.
    local owner443=""
    owner443="$(xui_port_listeners 443 | head -n3)"
    if [[ -n "$owner443" && "$owner443" != *xray* && "$owner443" != *x-ui* ]]; then
        msg_err "443 由已有服务占用，为保护原网站安装中止：$owner443"
        return 1
    fi

    # Defer Nginx preflight until after the cert and a managed TLS bridge are
    # prepared. Earlier installers may have left an SSL:8080 listener that
    # conflicts with the user's original HTTP:8080 wow website. The site itself
    # must not be edited or disabled.

    # Menu 1 used to DELETE all existing inbounds and reset UUID/REALITY keys.
    # Protect upgrades or re-runs: never overwrite an existing live panel by default.
    if [[ -s "$XUIDB" ]] && command -v sqlite3 >/dev/null 2>&1 &&
       [[ "$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality';" 2>/dev/null || echo 0)" -gt 0 ]]; then
        echo "[WARN] 已检测到 X-UI 现有 REALITY 节点，重装会删除节点并重置 UUID/密钥。"
        local reset_confirm=""
        read_tty "确实要清空节点并重装吗？输入 REBUILD 确认，否则进入安全升级菜单: " reset_confirm
        if [[ "$reset_confirm" != "REBUILD" ]]; then
            xui_maintenance_menu
            return 0
        fi
        local before_rebuild=""
        before_rebuild="$(xui_backup_panel)" || return 1
        echo "[INFO] 已备份面板和旧节点数据库：${before_rebuild}"
    fi
    # Previously tested standalone Xray could still own public TCP 443.
    if systemctl is-active --quiet xray 2>/dev/null; then
        echo '[WARN] 检测到独立 xray.service 正在运行，可能与 X-UI 的 443 冲突。'
        local independent_confirm=""
        read_tty "停止并禁用独立 xray.service，让 X-UI 管理 443？(y/N): " independent_confirm
        if [[ "$independent_confirm" =~ ^[Yy]$ ]]; then
            systemctl disable --now xray || return 1
        else
            echo '[ERROR] 请先处理独立 Xray 的 443 端口占用。'
            return 1
        fi
    fi

    init_runtime_vars
    prepare_domain_vars
    install_packages
    get_server_ips
    # Nginx site preflight is performed after the independent TLS bridge
    # is created below (still BEFORE panel installation/database changes).
    # Choose and verify the release BEFORE touching the running panel.
    local requested_panel_tag=""
    if ! xui_panel_choose_version; then
        echo '[INFO] version selection canceled; current panel was not stopped'
        return 1
    fi
    requested_panel_tag="$XUI_PANEL_SELECTED_TAG"

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
        msg_err "$domain 的证书不可用，程序终止；原网站未作更改！"
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

    msg_inf '直接引用已有证书，不改动 /root/cert 及网站证书软链接。'

    # HTTP wow site (user-owned) stays on 8080. The installer manages ONLY a
    # separate SSL:8081+ bridge and removes old *X.sh-owned* conflicting SSL.
    local bridge_rc=0
    xui_bridge_apply install || bridge_rc=$?
    if (( bridge_rc != 0 && bridge_rc != 2 )); then
        msg_err '无法为现有 HTTP 网站创建独立 TLS 桥接；已停止安装，原站点保持不变'
        return 1
    fi
    xui_nginx_preflight_preserve || return 1
    xui_select_fallback_port || return 1

    echo "----------------------------------------------------------------"
    echo "安装 x-ui 面板"
    echo "----------------------------------------------------------------"
    echo "如果系统未检测到 x-ui，将自动下载安装并初始化配置。"

    # install_panel downloads and validates the release BEFORE stopping or
    # replacing existing x-ui files. REBUILD was explicitly confirmed above.
    if ! install_panel "$requested_panel_tag"; then
        msg_err "3X-UI 安装文件部署失败，未继续写入新节点"
        if [[ -n "${before_rebuild:-}" && -f "${before_rebuild}" ]]; then
            xui_restore_panel_snapshot "$before_rebuild" || true
        fi
        return 1
    fi

    if ! UPDATE_XUIDB; then
        echo '[ERROR] inbound/client data write failed; restoring previous panel where possible'
        if [[ -n "${before_rebuild:-}" && -f "${before_rebuild}" ]]; then
            xui_restore_panel_snapshot "$before_rebuild" || true
        else
            systemctl start x-ui 2>/dev/null || true
        fi
        return 1
    fi
    configure_nginx || return 1
    install_sub2sing_box
    msg_inf "伪装网站内容留给用户自行部署，回落服务使用 Nginx"
    setup_cronjob
    echo
    msg_inf '安装后的 REALITY 真实连接自动验收与修复...'
    if xui_auto_repair; then
        xui_mark_good || true
        show_final_details
        msg_ok '安装成功：3X-UI、443 监听和 REALITY 代理连接均已验证'
    else
        msg_err "安装没有通过 REALITY 代理验收，因此不会报告成功。"
        echo "失败详情：${XUI_SAFE_BASE}/install-last.log"
        if [[ -n "${before_rebuild:-}" && -f "${before_rebuild}" ]]; then
            echo '[WARN] 即将恢复重装前的面板与节点配置'
            xui_restore_panel_snapshot "$before_rebuild" || true
        fi
        return 1
    fi
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
        echo -e " ${yellow}${bold}3)${none} ${yellow}更新 Xray-core${none}"
        echo -e " ${yellow}${bold}4)${none} ${yellow}查看状态${none}"
        echo -e " ${yellow}${bold}5)${none} ${yellow}打印节点信息${none}"
        echo -e " ${yellow}${bold}6)${none} ${yellow}目标网站检测${none}"
        echo -e " ${yellow}${bold}7)${none} ${yellow}系统参数配置${none}"
        echo -e " ${yellow}${bold}8)${none} ${yellow}回程路由测试${none}"
        echo -e " ${yellow}${bold}9)${none} ${yellow}IP质量检测${none}"
        echo -e " ${yellow}${bold}10)${none} ${yellow}系统查询${none}"
		echo -e " ${green}${bold}11)${none} ${green}更新域名/SNI${none}"   # 新增行
        echo -e " ${green}${bold}12)${none} ${green}安全升级 3X-UI 面板（备份+回滚）${none}"
        echo -e " ${red}${bold}0)${none} 退出"

        echo -e "${gray}--------------------------------------------------${none}"
        echo -e "${dim}${gray}提示：输入数字后回车${none}"
        echo -ne "${green}${bold}请选择 [0-12]${none}${green}: ${none}"

        local choice=""

        read_tty "" choice

        case "${choice}" in
            1) INSTALL="y"; UNINSTALL="n"; install_xui_pro ;;
            2) uninstall_xui_menu ;;
            3) xray_updata ;;
            4) view_status ;;
            5) print_node_info ;;
            6) detect_target_site ;;
            7) run_sys_conf ;;
            8) besttrace_test ;;
            9) ip_quality_check ;;
            10) system_query ;;
            11) update_domain_sni ;;
            12) xui_safe_panel_update || true; pause ;;
            0) exit 0 ;;
            *) msg_err "无效输入，请重新选择。"; pause ;;
        esac
    done
}

# =====================================================================
#  3X-UI / Xray-safe maintenance (original x.sh compatible extension)
#  This module never edits Reality UUID, keys, SNI or Nginx fallback.
# =====================================================================
XUI_SAFE_BASE="/root/x-ui-safe"
XUI_COMPAT_CORE="26.10.21"  # Emergency security release; specific REALITY targets may still regress.
# 26.10.10 and 26.10.17 were withdrawn due to compromised bundled trust roots.
# Do NOT re-download or mark them as recommended updates.

xui_xray_bin() {
    local a
    a="$(arch)"
    for candidate in \
        "/usr/local/x-ui/bin/xray-linux-${a}" \
        "/usr/local/x-ui/bin/xray-linux-arm32" \
        "/usr/local/x-ui/bin/xray-linux-arm" \
        "/usr/local/x-ui/bin/xray"; do
        [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    done
    return 1
}

xui_core_version() {
    local b="${1:-}"
    [[ -n "$b" ]] || b="$(xui_xray_bin 2>/dev/null || true)"
    [[ -x "$b" ]] || return 1
    "$b" version 2>/dev/null | head -n 1 | sed -nE 's/^Xray ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p'
}

xui_panel_version() {
    local raw="" v=""
    if [[ -x /usr/local/x-ui/x-ui ]]; then
        raw="$(/usr/local/x-ui/x-ui version 2>&1 | head -n 3 || true)"
    fi
    v="$(printf '%s\n' "$raw" | grep -oEm1 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    if [[ -z "$v" ]]; then
        # 3x-ui v3.10.x records its version at service start; 'x-ui version'
        # on some builds does not implement a useful CLI subcommand.
        raw="$(journalctl -u x-ui --no-pager -n 200 2>/dev/null | grep 'Starting x-ui' | tail -n 1 || true)"
        v="$(printf '%s\n' "$raw" | sed -nE 's/.*Starting x-ui (v?[0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
    fi
    printf '%s\n' "$v"
}

xui_real_port() {
    sqlite3 "$XUIDB" "SELECT port FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' AND enable=1 ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1
}

xui_real_fallback_port() {
    local target
    target="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.target') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' AND enable=1 ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
    if [[ "$target" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    else
        printf '8080\n'
    fi
}

xui_runtime_check() {
    local bin cfg port fallback_runtime_port
    bin="$(xui_xray_bin 2>/dev/null || true)"
    cfg="/usr/local/x-ui/bin/config.json"
    port="$(xui_real_port || true)"
    [[ -n "$port" ]] || port=443
    fallback_runtime_port="$(xui_real_fallback_port)"
    systemctl is-active --quiet x-ui || { echo '[ERROR] x-ui service is not active'; return 1; }
    if [[ -s "$cfg" && -n "$bin" ]]; then
        "$bin" run -test -config "$cfg" >/dev/null 2>&1 || {
            echo '[ERROR] Xray config test failed'
            "$bin" run -test -config "$cfg" 2>&1 | tail -n 8 || true
            return 1
        }
    else
        echo '[ERROR] 面板 Xray 运行配置或内核不存在，不能宣称安装成功'
        return 1
    fi
    if ! ss -lntp 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" && /xray/ {found=1} END{exit !found}'; then
        echo "[ERROR] no Xray process listening on TCP ${port}"
        return 1
    fi
    if ! ss -lnt 2>/dev/null | awk -v p=":${fallback_runtime_port}" '$4 ~ p"$" {found=1} END{exit !found}'; then
        echo "[WARN] Nginx fallback 127.0.0.1:${fallback_runtime_port} not listening"
    fi
    echo "[OK] panel / Xray / ${port} listening; config syntax OK if available"
    return 0
}

# Real authenticated proxy probe. It proves more than checking TCP 443.
# Uses a temporary Xray client and a local HTTP target through VLESS/REALITY.
# If an admin routing policy forbids localhost, it tries an external HTTP target.
xui_reality_probe() {
    # Does not alter panel DB, server binary, routing or REALITY credentials.
    command -v python3 >/dev/null 2>&1 || { echo '[WARN] python3 missing: cannot perform authenticated probe'; return 2; }
    command -v curl >/dev/null 2>&1 || { echo '[WARN] curl missing: cannot perform authenticated probe'; return 2; }
    local bin
    bin="$(xui_xray_bin 2>/dev/null || true)"
    [[ -x "$bin" && -f "$XUIDB" ]] || { echo '[WARN] Xray binary or 3x-ui DB missing'; return 2; }
    python3 - "$XUIDB" "$bin" <<'PYPROBE'
import http.server
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

db, xray = sys.argv[1:]
conn = proxy = server = None

def get_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def extract_pub(text):
    for line in text.splitlines():
        if ':' not in line:
            continue
        name, value = line.split(':', 1)
        if name.strip() in ('Password', 'Password (PublicKey)', 'PublicKey', 'Public key'):
            return value.strip()
    return ''

try:
    conn = sqlite3.connect('file:' + db + '?mode=ro', uri=True, timeout=5)
    row = conn.execute("""SELECT port, settings, stream_settings FROM inbounds
        WHERE protocol='vless' AND enable=1
          AND json_extract(stream_settings, '$.security')='reality'
        ORDER BY id DESC LIMIT 1""").fetchone()
    if not row:
        print('[WARN] 未发现已启用的 REALITY 入站'); sys.exit(2)
    port, settings_raw, stream_raw = row
    settings = json.loads(settings_raw)
    stream = json.loads(stream_raw)
    users = [u for u in settings.get('clients', []) if u.get('id') and u.get('enable', True)]
    reality = stream.get('realitySettings') or {}
    snis, sids = reality.get('serverNames') or [], reality.get('shortIds') or []
    if not users or not snis or not sids:
        print('[WARN] 启用客户端、SNI 或 Short ID 不完整'); sys.exit(2)
    user = users[0]
    # Check the panel's generated *running* config, not only the database.
    live_file = '/usr/local/x-ui/bin/config.json'
    if os.path.isfile(live_file):
        try:
            with open(live_file) as stream_file:
                live = json.load(stream_file)
            matches = [i for i in live.get('inbounds', [])
                       if i.get('protocol') == 'vless' and i.get('port') == int(port)
                       and (i.get('streamSettings') or {}).get('security') == 'reality']
            if not matches:
                print('[FAIL] 面板生成的运行配置没有对应 REALITY 443 入站')
                sys.exit(1)
            live_in = matches[0]
            live_stream = (live_in.get('streamSettings') or {}).get('realitySettings') or {}
            live_clients = (live_in.get('settings') or {}).get('clients') or []
            mismatch = []
            if live_stream.get('privateKey') != reality.get('privateKey'):
                mismatch.append('REALITY privateKey')
            if snis[0] not in (live_stream.get('serverNames') or []):
                mismatch.append('SNI')
            if sids[0] not in (live_stream.get('shortIds') or []):
                mismatch.append('ShortID')
            if user['id'] not in [x.get('id') for x in live_clients]:
                mismatch.append('运行配置缺少该 UUID（请检查 clients/client_inbounds 关联）')
            if mismatch:
                print('[FAIL] 数据库与实际 Xray 配置未同步：' + '；'.join(mismatch))
                print('[INFO] 已生成的有效客户端数量: %d' % len(live_clients))
                sys.exit(1)
        except (ValueError, OSError) as exc:
            print('[WARN] 无法校验面板生成的运行配置: %s' % str(exc)[:120])
    r = reality.get('settings') or {}
    stored_pub = r.get('publicKey') or r.get('password') or ''
    private_key = reality.get('privateKey') or ''
    derived = ''
    if private_key:
        keyinfo = subprocess.run([xray, 'x25519', '-i', private_key],
                                 capture_output=True, text=True, timeout=7)
        derived = extract_pub(keyinfo.stdout + '\n' + keyinfo.stderr)
    if stored_pub and derived and stored_pub != derived:
        print('[FAIL] REALITY 数据库中的 publicKey 与 privateKey 不匹配')
        print('[HINT] 这属于节点密钥配置错误，不是 HTTP 出站限制；请从面板检查公私钥')
        sys.exit(1)
    pub = derived or stored_pub
    if not pub:
        print('[WARN] 无法获取 REALITY 公钥，不能进行认证测试'); sys.exit(2)
    if not derived:
        print('[WARN] 无法从内核推导公钥，仅按数据库中的公钥继续检测')

    socks_port = get_port()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b'xui-reality-probe-ok'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target_port = server.server_address[1]
    config = {
        'log': {'loglevel':'info'},
        'inbounds': [{'listen':'127.0.0.1', 'port':socks_port,
                      'protocol':'socks', 'settings':{'auth':'noauth','udp':False}}],
        'outbounds': [{'tag':'proxy', 'protocol':'vless',
                       'settings':{'vnext':[{'address':'127.0.0.1', 'port':int(port),
                                            'users':[{'id':user['id'], 'encryption':'none',
                                                      'flow':user.get('flow') or 'xtls-rprx-vision'}]}]},
                       'streamSettings':{'network':'tcp','security':'reality',
                           'realitySettings':{'serverName':snis[0],
                                             'fingerprint':r.get('fingerprint') or 'chrome',
                                             'publicKey':pub,'shortId':sids[0],
                                             'spiderX':r.get('spiderX') or '/'}}}]
    }
    candidates = []
    try:
        for info in socket.getaddrinfo(snis[0], int(port), socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip not in candidates:
                candidates.append(ip)
    except socket.gaierror:
        print('[WARN] 当前域名无法解析；将尝试服务器回环地址')
    if '127.0.0.1' not in candidates:
        candidates.append('127.0.0.1')
    failure_details = []
    for address in (candidates[:2] if len(candidates) <= 2 else candidates[:2] + ['127.0.0.1']):
        socks_port = get_port()
        config['inbounds'][0]['port'] = socks_port
        config['outbounds'][0]['settings']['vnext'][0]['address'] = address
        with tempfile.TemporaryDirectory(prefix='xui-real-probe-') as tmp:
            conf_path = os.path.join(tmp, 'probe.json')
            log_path = os.path.join(tmp, 'client.log')
            with open(conf_path, 'w') as f:
                json.dump(config, f)
            os.chmod(conf_path, 0o600)
            with open(log_path, 'w+') as log:
                proxy = subprocess.Popen([xray, 'run', '-config', conf_path],
                                         stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                try:
                    ready = False
                    for _ in range(40):
                        if proxy.poll() is not None:
                            break
                        with socket.socket() as sock:
                            sock.settimeout(.15)
                            if sock.connect_ex(('127.0.0.1', socks_port)) == 0:
                                ready = True
                                break
                        time.sleep(.12)
                    if not ready:
                        failure_details.append(address + ': 临时客户端未启动')
                    else:
                        cases = [
                            ('本机目标测试', 'http://127.0.0.1:%d/' % target_port, True),
                            ('公网出站测试', 'http://example.com/', False),
                        ]
                        for name, url, marker_required in cases:
                            cmd = ['curl', '--silent', '--show-error', '--connect-timeout', '4',
                                   '--max-time', '8', '--retry', '0', '--noproxy', '',
                                   '--socks5-hostname', '127.0.0.1:%d' % socks_port, url]
                            try:
                                result = subprocess.run(cmd, text=True, capture_output=True,
                                                        timeout=10)
                            except subprocess.TimeoutExpired:
                                failure_details.append(address+' '+name+': timeout')
                                continue
                            passed = (result.returncode == 0 and
                                      (('xui-reality-probe-ok' in result.stdout)
                                       if marker_required else bool(result.stdout.strip())))
                            if passed:
                                print('[PASS] REALITY 真实代理连接验证通过，入口 '+address)
                                sys.exit(0)
                            detail = result.stderr.strip().replace('\n', ' ')[:200]
                            failure_details.append('%s %s: curl=%s %s' % (
                                address, name, result.returncode, detail))
                    log.flush()
                    with open(log_path, errors='replace') as inf:
                        lines = inf.read().splitlines()
                    if lines:
                        errors = [line for line in lines if 'unexpected response' in line or
                                  'authentication' in line or 'handshake' in line or
                                  'reality' in line.lower()]
                        for line in errors[-3:]:
                            failure_details.append('xray: ' + line[:260])
                finally:
                    if proxy is not None:
                        try:
                            os.killpg(proxy.pid, signal.SIGTERM)
                            proxy.wait(timeout=3)
                        except Exception:
                            try: proxy.kill()
                            except Exception: pass
                        proxy = None
    print('[FAIL] REALITY 无法建立可用 VLESS 代理连接')
    for detail in failure_details[-12:]:
        print('  '+detail)
    if any('unexpected response version' in d and 'actually 72' in d for d in failure_details):
        print('[HINT] 收到 HTTP 响应而不是 VLESS 响应：REALITY 认证可能落入伪装站')
    sys.exit(1)
except (ValueError, KeyError, sqlite3.Error, OSError, subprocess.SubprocessError) as exc:
    print('[WARN] 临时检测不可用: %s: %s' % (type(exc).__name__, str(exc)[:200]))
    sys.exit(2)
finally:
    if proxy is not None:
        try:
            os.killpg(proxy.pid, signal.SIGTERM)
            proxy.wait(timeout=3)
        except Exception:
            try: proxy.kill()
            except Exception: pass
    if server is not None:
        try: server.shutdown(); server.server_close()
        except Exception: pass
    if conn is not None:
        conn.close()
PYPROBE
}

xui_ensure_safe_dirs() {
    mkdir -p "$XUI_SAFE_BASE/snapshots" "$XUI_SAFE_BASE/known-good"
    chmod 700 "$XUI_SAFE_BASE" "$XUI_SAFE_BASE/snapshots" "$XUI_SAFE_BASE/known-good"
}

xui_backup_panel() {
    xui_ensure_safe_dirs
    local stamp file paths=()
    stamp="$(date +%Y%m%d_%H%M%S)"
    file="$XUI_SAFE_BASE/snapshots/panel-$stamp.tar.gz"
    local p
    for p in /usr/local/x-ui /etc/x-ui /usr/bin/x-ui /etc/systemd/system/x-ui.service /etc/systemd/system/x-ui.service.d /etc/default/x-ui; do
        [[ -e "$p" ]] && paths+=("${p#/}")
    done
    [[ ${#paths[@]} -gt 0 ]] || { echo '[ERROR] no panel files exist'; return 1; }
    # Stop only after the preflight; SQLite WAL backup stays consistent.
    systemctl stop x-ui || return 1
    if ! tar -C / -czpf "$file" "${paths[@]}"; then
        systemctl start x-ui || true
        rm -f "$file"
        return 1
    fi
    chmod 600 "$file"
    systemctl start x-ui || { echo '[ERROR] failed to restart existing panel after backup'; return 1; }
    printf '%s\n' "$file"
}

xui_restore_panel_snapshot() {
    local file="${1:-}"
    [[ -f "$file" ]] || { echo '[ERROR] snapshot missing'; return 1; }
    xui_ensure_safe_dirs
    echo "[INFO] Restoring panel + DB from $file"
    systemctl stop x-ui >/dev/null 2>&1 || true
    local bad_dir="$XUI_SAFE_BASE/failed-panel-$(date +%Y%m%d_%H%M%S)"
    if [[ -d /usr/local/x-ui ]]; then mv /usr/local/x-ui "$bad_dir" || return 1; fi
    if [[ -d /etc/x-ui ]]; then mv /etc/x-ui "${bad_dir}.db" || return 1; fi
    if ! tar -C / -xzpf "$file"; then
        echo '[ERROR] tar restoration failed; failed panel preserved'
        return 1
    fi
    systemctl daemon-reload
    systemctl enable --now x-ui || return 1
    echo '[OK] previous panel, database and core restored'
    return 0
}

xui_mark_good() {
    xui_runtime_check || return 1
    if ! xui_reality_probe; then
        echo '[ERROR] no authenticated probe success, refusing to mark this binary as good'
        return 1
    fi
    local bin archval ver tmp
    bin="$(xui_xray_bin)" || return 1
    archval="$(arch)"
    ver="$(xui_core_version "$bin")"
    xui_ensure_safe_dirs
    tmp="$XUI_SAFE_BASE/known-good/.core-${archval}.$$"
    cp -p "$bin" "$tmp" || return 1
    mv -f "$tmp" "$XUI_SAFE_BASE/known-good/core-${archval}"
    printf '%s\n' "$ver" > "$XUI_SAFE_BASE/known-good/version-${archval}"
    chmod 600 "$XUI_SAFE_BASE/known-good/version-${archval}"
    echo "[OK] known working Xray-core saved: $ver"
}

xui_restore_good() {
    local dest good rollback
    dest="$(xui_xray_bin 2>/dev/null || true)"
    good="$XUI_SAFE_BASE/known-good/core-$(arch)"
    [[ -x "$dest" && -s "$good" ]] || { echo '[WARN] 尚无通过认证测试的已验证内核快照，不能使用此项恢复；此前升级前的备份在 snapshots/core-before-*'; return 1; }
    rollback="$XUI_SAFE_BASE/snapshots/core-pre-restore-$(date +%Y%m%d_%H%M%S)"
    xui_ensure_safe_dirs
    cp -p "$dest" "$rollback" || return 1
    chmod 700 "$rollback"
    systemctl stop x-ui || return 1
    install -m 755 "$good" "$dest" || return 1
    systemctl start x-ui || true
    sleep 2
    if xui_runtime_check && xui_reality_probe; then
        echo '[OK] restored last verified core and REALITY handshake passes'
        return 0
    fi
    echo '[ERROR] verified core did not work with this panel; rolling back to previous binary'
    systemctl stop x-ui || true
    install -m 755 "$rollback" "$dest"
    systemctl start x-ui || true
    return 1
}

xui_download_compat_core() {
    local requested="${1:-$XUI_COMPAT_CORE}" archval asset url tmp expected actual
    case "$requested" in
       26.10.10|26.10.17)
           echo '[ERROR] 该 Xray 版本已被上游撤回（内置根证书安全问题），禁止从非官方镜像下载' >&2
           return 1 ;;
       26.10.21|26.9.30|26.7.28) ;;
       *) echo '[ERROR] 当前菜单只允许选择已核查存在的官方版本：26.10.21 或 26.9.30' >&2; return 1 ;;
    esac
    archval="$(arch)"
    case "$archval" in
        amd64) asset='Xray-linux-64.zip' ;;
        386) asset='Xray-linux-32.zip' ;;
        arm64) asset='Xray-linux-arm64-v8a.zip' ;;
        *) echo "[ERROR] Xray automatic update unsupported on $archval" >&2; return 1 ;;
    esac
    for c in curl unzip sha256sum; do
        command -v "$c" >/dev/null 2>&1 || { echo "[ERROR] missing $c" >&2; return 1; }
    done
    tmp="$(mktemp -d /tmp/xray-safe.XXXXXX)" || return 1
    url="https://github.com/XTLS/Xray-core/releases/download/v${requested}/${asset}"
    if ! curl -fL --retry 2 --connect-timeout 12 --max-time 180 "$url" -o "$tmp/core.zip"; then
        rm -rf "$tmp"; echo '[ERROR] 下载 Xray 官方 ZIP 失败；现有内核未改变' >&2; return 1
    fi
    if ! curl -fL --retry 2 --connect-timeout 12 --max-time 40 "${url}.dgst" -o "$tmp/core.dgst"; then
        rm -rf "$tmp"; echo '[ERROR] 官方 SHA256 校验文件不存在；拒绝安装' >&2; return 1
    fi
    # Official .dgst records several hash algorithms. Select SHA256 specifically.
    expected="$(sed -nE 's/^[[:space:]]*(SHA2-256|SHA-256|SHA256)[[:space:]]*=[[:space:]]*([a-fA-F0-9]{64})[[:space:]]*$/\2/Ip' "$tmp/core.dgst" | head -n1 | tr 'A-F' 'a-f')"
    actual="$(sha256sum "$tmp/core.zip" | awk '{print $1}')"
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        rm -rf "$tmp"; echo '[ERROR] 官方 SHA256 不匹配，拒绝安装' >&2; return 1
    fi
    if ! unzip -p "$tmp/core.zip" xray > "$tmp/xray" || [[ ! -s "$tmp/xray" ]]; then
        rm -rf "$tmp"; echo '[ERROR] Xray ZIP 缺少 xray 可执行文件' >&2; return 1
    fi
    chmod 755 "$tmp/xray"
    if [[ "$(xui_core_version "$tmp/xray")" != "$requested" ]]; then
        rm -rf "$tmp"; echo '[ERROR] 下载的内核版本与要求不一致' >&2; return 1
    fi
    printf '%s\n' "$tmp/xray"
}

xui_install_compat_core() {
    local dest prev cfg staged stage_dir requested confirm current
    dest="$(xui_xray_bin 2>/dev/null || true)"
    cfg='/usr/local/x-ui/bin/config.json'
    [[ -x "$dest" && -s "$cfg" ]] || { echo '[ERROR] 未找到面板 Xray 内核或生成的 config.json'; return 1; }
    current="$(xui_core_version "$dest" || true)"
    echo "[INFO] 当前版本：${current:-unknown}"
    echo '[WARN] 26.10.10 与 26.10.17 已被 XTLS 撤版，不能从 GitHub 重新安装。'
    echo '[INFO] 推荐安全更新：26.10.21（特定 REALITY TLS 回落目标上存在握手回归报告）。'
    echo '[INFO] 临时旧版对比：26.9.30（仅用于兼容性排查，不建议长期使用旧内核）。'
    read_tty '目标版本 [回车=26.10.21 / 26.9.30 / 0=取消]: ' requested
    [[ "$requested" == 0 ]] && return 0
    requested="${requested:-26.10.21}"
    case "$requested" in
        26.10.21|26.9.30|26.7.28) ;;
        *) echo '[ERROR] 不支持或已撤版的版本'; return 1 ;;
    esac
    if [[ "$current" == "$requested" ]]; then
        echo "[INFO] 已安装 Xray $requested，无需重复下载。"
        xui_runtime_check || true
        xui_reality_probe || true
        return 0
    fi
    echo '[WARN] 将短暂重启 x-ui，并自动保存当前二进制以便失败时回滚；不修改数据库和节点参数。'
    read_tty "确认安装 Xray $requested? (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return 0
    staged="$(xui_download_compat_core "$requested")" || return 1
    stage_dir="$(dirname "$staged")"
    if ! XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$staged" run -test -config "$cfg"; then
        echo '[ERROR] 目标内核配置校验失败（已显示原始错误），保持原版本'
        rm -rf "$stage_dir"
        return 1
    fi
    xui_ensure_safe_dirs
    prev="$XUI_SAFE_BASE/snapshots/core-before-$(date +%Y%m%d_%H%M%S)"
    cp -p "$dest" "$prev" || { rm -rf "$stage_dir"; return 1; }
    chmod 700 "$prev"
    if ! systemctl stop x-ui; then rm -rf "$stage_dir"; return 1; fi
    if ! install -m 755 "$staged" "$dest"; then
        install -m 755 "$prev" "$dest" || true
        systemctl start x-ui || true
        rm -rf "$stage_dir"; return 1
    fi
    rm -rf "$stage_dir"
    systemctl start x-ui || true
    sleep 2
    if xui_runtime_check && xui_reality_probe; then
        echo "[OK] Xray $requested 运行通过，REALITY 端到端测试成功"
        xui_mark_good || true
        return 0
    fi
    echo '[ERROR] 新版本未通过端到端测试；自动恢复升级前的二进制（数据库/证书不变）'
    systemctl stop x-ui || true
    install -m 755 "$prev" "$dest"
    systemctl start x-ui || true
    echo "[INFO] 已回滚到升级前的内核版本：$current"
    return 1
}

xui_diagnostic() {
    local bin panelver corever
    bin="$(xui_xray_bin 2>/dev/null || true)"
    panelver="$(xui_panel_version)"
    corever="$(xui_core_version "$bin" 2>/dev/null || true)"
    echo "3x-ui version: ${panelver:-unknown}"
    echo "Xray-core: ${corever:-unknown}"
    echo "Xray path: ${bin:-missing}"
    echo "DB: $XUIDB"
    echo 'Reality / fallback from DB (no secrets):'
    sqlite3 -header -column "$XUIDB" "SELECT port, json_extract(settings,'\$.clients[0].flow') AS flow, json_extract(settings,'\$.fallbacks[0].dest') AS fallback, json_extract(stream_settings,'\$.realitySettings.target') AS target, json_extract(stream_settings,'\$.realitySettings.serverNames[0]') AS sni FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' LIMIT 1;" 2>/dev/null || true
    [[ "$corever" == '26.10.21' ]] && echo '[WARN] Xray 26.10.21 特定 REALITY 目标存在握手回归报告 (XTLS #7243)'
    [[ "$corever" == '26.10.10' || "$corever" == '26.10.17' ]] && echo '[WARN] 当前内核对应的官方发布包已因根证书安全事件撤回，建议在验证兼容性后尽快升级'
    xui_runtime_check || true
    xui_reality_probe || true
    echo '[INFO] 重新安装会重置 UUID/公钥/ShortID，请通过主菜单 5 复制当前链接并在客户端重新导入。'
    echo 'Recent x-ui logs:'
    journalctl -u x-ui -n 18 --no-pager 2>/dev/null | sed -E 's/(PrivateKey|privateKey|password)[=:][^, ]+/\1=[REDACTED]/Ig' || true
    if [[ -f /usr/local/x-ui/bin/config.json && -n "$bin" ]]; then
        echo '[INFO] test the panel-generated config, rather than a standalone config.json'
    fi
}

xui_safe_panel_update() {
    local backup before after downloaded code
    echo '[WARN] Only use when 3X-UI is already installed and working.'
    echo '[WARN] This makes a full panel+DB snapshot before running upstream stable update.'
    echo '[WARN] New major releases may migrate the database. Rollback restores BOTH panel and DB.'
    read_tty 'Start protected stable panel upgrade? (y/N): ' code
    [[ "$code" =~ ^[Yy]$ ]] || return 0
    xui_runtime_check || { echo '[ERROR] original panel not healthy; refusing upgrade'; return 1; }
    if ! xui_reality_probe; then
        echo '[WARN] pre-upgrade REALITY authenticated probe failed; upgrade is not safe'
        return 1
    fi
    xui_mark_good || return 1
    backup="$(xui_backup_panel)" || return 1
    echo "Panel snapshot: $backup"
    downloaded="$(mktemp /tmp/xui-update.XXXXXX.sh)" || return 1
    if ! curl -fsSL --connect-timeout 15 --max-time 60 \
      'https://raw.githubusercontent.com/MHSanaei/3x-ui/main/update.sh' -o "$downloaded"; then
        rm -f "$downloaded"; echo '[ERROR] official 3x-ui update script download failed'; return 1
    fi
    if ! bash -n "$downloaded"; then
        rm -f "$downloaded"; echo '[ERROR] upstream update.sh has syntax errors'; return 1
    fi
    echo '[INFO] Starting official 3x-ui stable update (interactive if upstream requires)'
    if ! bash "$downloaded"; then
        echo '[ERROR] updater failed; restoring previous working panel'
        rm -f "$downloaded"
        xui_restore_panel_snapshot "$backup" || true
        return 1
    fi
    rm -f "$downloaded"
    sleep 3
    if xui_runtime_check && xui_reality_probe; then
        echo '[OK] updated panel and current Xray passed end-to-end verification'
        xui_mark_good || true
        return 0
    fi
    echo '[WARN] upgraded panel failed REALITY probe, trying bundled known-good core'
    if xui_restore_good && xui_runtime_check && xui_reality_probe; then
        echo '[OK] updated panel works after restoring last verified core'
        return 0
    fi
    echo '[ERROR] restored core did not fix the upgrade; rolling back full panel + database'
    xui_restore_panel_snapshot "$backup" || true
    return 1
}

xui_guard_watch() {
    # Does not overwrite a known-good core after a transient network error.
    # Only revert after the binary changed and the actual probe failed.
    local code=0 bin good
    bin="$(xui_xray_bin 2>/dev/null || true)"
    good="$XUI_SAFE_BASE/known-good/core-$(arch)"
    if xui_runtime_check >/dev/null 2>&1 && xui_reality_probe >/dev/null 2>&1; then
        echo "$(date -Is) [OK] panel/REALITY working: $(xui_core_version)"
        return 0
    fi
    if [[ ! -s "$good" ]]; then
        echo "$(date -Is) [WARN] REALITY failed; no verified core available, no automatic changes"
        return 1
    fi
    if [[ -x "$bin" ]] && cmp -s "$bin" "$good"; then
        echo "$(date -Is) [WARN] current core matches verified version, skipped restart; investigate network/route"
        return 1
    fi
    echo "$(date -Is) [WARN] Xray binary changed and REALITY probe failed; testing rollback"
    if xui_restore_good; then
        echo "$(date -Is) [OK] verified core restored after upgrade"
        return 0
    fi
    echo "$(date -Is) [ERROR] restore could not validate, original updated binary restored"
    return 1
}

xui_setup_guard_cron() {
    local script='/root/xpro.sh' confirm
    # Must copy the whole self-contained script, not fetch a mutable remote URL.
    if [[ ! -f "$script" || ! "$script" -ef "$0" ]]; then
        install -m 700 "$0" "$script" || return 1
    fi
    echo 'Guard runs once an hour and checks REALITY end-to-end; if failed, restores only a previously verified core.'
    echo 'Monthly 03:00 check reports current version; it does not blindly install upstream latest.'
    if [[ "${1:-}" == '--yes' ]]; then
        confirm=y
    else
        read_tty 'Enable hourly auto-repair + monthly version check? (y/N): ' confirm
    fi
    [[ "$confirm" =~ ^[Yy]$ ]] || return 0
    (
        crontab -l 2>/dev/null | grep -Ev '(/root/(x.sh|xpro.sh) --xui-guard|/root/(x.sh|xpro.sh) --xui-monthly)' || true
        printf '%s\n' '0 * * * * /usr/bin/flock -n /run/xui-reality-guard.lock /bin/bash /root/xpro.sh --xui-guard >>/var/log/xui-reality-guard.log 2>&1'
        printf '%s\n' '0 3 1 * * /bin/bash /root/xpro.sh --xui-monthly >>/var/log/xui-reality-guard.log 2>&1'
    ) | crontab -
    echo '[OK] configured non-disruptive Xray health monitoring; does not install unknown versions'
}


# 3X-UI 3.9+ ignores inbounds.settings.clients when building its runtime.
# It loads clients JOIN client_inbounds, including per-inbound flow_override.
# Keep this embedded so the original x.sh remains a standalone installer.
xui_sync_normalized_clients() {
    local mode="${1:-repair}"
    [[ -s "$XUIDB" ]] || { echo '[ERROR] 3X-UI DB missing'; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo '[ERROR] python3 is required'; return 1; }
    python3 - "$XUIDB" "$mode" <<'PY_SYNC_NORMALIZED'
#!/usr/bin/env python3
"""Sync 3X-UI legacy inbound.settings.clients to 3.x normalized client tables.

The 3X-UI 3.9.0 runtime reads `clients JOIN client_inbounds`, not just
`inbounds.settings.clients`; direct SQL installation must maintain both.
Run while x-ui.service is stopped; caller is responsible for snapshot/restart.
"""
import json
import sqlite3
import sys
import time


def columns(conn, table):
    return {row[1] for row in conn.execute('PRAGMA table_info("%s")' % table)}


def has_table(conn, table):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def identity(user, protocol):
    if protocol in ('vless', 'vmess'):
        return str(user.get('id') or '').strip()
    if protocol == 'trojan':
        return str(user.get('password') or '').strip()
    return ''


def make_email(inbound_id, uuid_or_password, index, taken):
    hint = ''.join(c for c in uuid_or_password if c.isalnum())[:16] or str(index)
    base = 'node%s_%s' % (inbound_id, hint)
    email = base + '@xui.local'
    j = 1
    while email in taken:
        email = '%s_%d@xui.local' % (base, j)
        j += 1
    taken.add(email)
    return email


def sync(db, mode='repair'):
    if mode not in ('repair', 'fresh'):
        raise ValueError('unsupported mode: ' + mode)
    conn = sqlite3.connect(db, timeout=25)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout = 25000')
    try:
        if not has_table(conn, 'inbounds'):
            raise RuntimeError('the inbounds table is missing')
        normalized = has_table(conn, 'clients') and has_table(conn, 'client_inbounds')
        if has_table(conn, 'clients') != has_table(conn, 'client_inbounds'):
            raise RuntimeError('incomplete normalized schema: clients/client_inbounds')
        client_columns = columns(conn, 'clients') if normalized else set()
        link_columns = columns(conn, 'client_inbounds') if normalized else set()
        if normalized and not {'id', 'email', 'uuid', 'enable'}.issubset(client_columns):
            raise RuntimeError('unsupported normalized clients schema')
        if normalized and not {'client_id', 'inbound_id', 'flow_override'}.issubset(link_columns):
            raise RuntimeError('unsupported client_inbounds schema')
        traffic_exists = has_table(conn, 'client_traffics')
        traffic_columns = columns(conn, 'client_traffics') if traffic_exists else set()
        taken = set()
        if normalized:
            taken = {row[0] for row in conn.execute('SELECT email FROM clients') if row[0]}
        now = int(time.time() * 1000)
        counters = {'clients_created': 0, 'links_created': 0, 'links_updated': 0,
                    'profiles_updated': 0, 'inbounds_rewritten': 0, 'stale_links_removed': 0}
        inbound_columns = columns(conn, 'inbounds')
        query = "SELECT id,protocol,settings FROM inbounds WHERE protocol IN ('vless','vmess','trojan')"
        if 'node_id' in inbound_columns:
            query += ' AND node_id IS NULL'
        inbounds = conn.execute(query).fetchall()
        conn.execute('BEGIN IMMEDIATE')
        for inbound in inbounds:
            inbound_id, protocol = inbound['id'], inbound['protocol']
            try:
                settings = json.loads(inbound['settings'] or '{}')
            except (TypeError, ValueError) as exc:
                raise RuntimeError('inbound %d settings invalid: %s' % (inbound_id, exc))
            users = settings.get('clients') or []
            if not isinstance(users, list):
                raise RuntimeError('inbound %d clients is not array' % inbound_id)
            changed = False
            linked_ids = set()
            for index, user in enumerate(users):
                if not isinstance(user, dict):
                    continue
                raw_identity = identity(user, protocol)
                if not raw_identity:
                    continue
                email = user.get('email')
                if not isinstance(email, str) or not email.strip():
                    email = make_email(inbound_id, raw_identity, index, taken)
                    user['email'] = email
                    changed = True
                elif email.strip() != email:
                    email = email.strip()
                    user['email'] = email
                    changed = True
                tg = user.get('tgId', 0)
                if isinstance(tg, bool) or not isinstance(tg, int):
                    try:
                        user['tgId'] = int(str(tg).strip())
                    except (ValueError, TypeError):
                        user['tgId'] = 0
                    changed = True
                if not normalized:
                    continue
                # The panel gets UUID from clients.uuid and VLESS flow from
                # client_inbounds.flow_override; legacy inbound JSON alone is ignored.
                existing = conn.execute('SELECT id,uuid FROM clients WHERE email=?', (email,)).fetchone()
                existing_link = False
                other_links = 0
                if existing:
                    cid = existing['id']
                    existing_link = conn.execute(
                        'SELECT 1 FROM client_inbounds WHERE client_id=? AND inbound_id=?',
                        (cid, inbound_id)).fetchone() is not None
                    other_links = conn.execute(
                        'SELECT count(*) FROM client_inbounds WHERE client_id=? AND inbound_id<>?',
                        (cid, inbound_id)).fetchone()[0]
                # If a panel-managed profile is already linked and differs,
                # keep the live identity; legacy JSON may be stale after UI edits.
                if existing_link and mode == 'repair' and existing['uuid'] and protocol in ('vless', 'vmess'):
                    if user.get('id') != existing['uuid']:
                        user['id'] = existing['uuid']
                        changed = True
                    raw_identity = existing['uuid']
                elif existing and mode == 'repair' and other_links and existing['uuid'] and protocol in ('vless', 'vmess'):
                    if user.get('id') != existing['uuid']:
                        user['id'] = existing['uuid']
                        changed = True
                    raw_identity = existing['uuid']
                profile = {
                    'email': email,
                    'uuid': raw_identity if protocol in ('vless', 'vmess') else '',
                    'password': raw_identity if protocol == 'trojan' else '',
                    'flow': str(user.get('flow') or ''),
                    'sub_id': str(user.get('subId') or ''),
                    'limit_ip': int(user.get('limitIp') or 0),
                    'total_gb': int(user.get('totalGB') or 0),
                    'expiry_time': int(user.get('expiryTime') or 0),
                    'enable': 1 if user.get('enable', True) else 0,
                    'tg_id': int(user.get('tgId') or 0),
                    'reset': int(user.get('reset') or 0),
                    'traffic_reset': str(user.get('trafficReset') or 'never'),
                    'traffic_reset_day': int(user.get('trafficResetDay') or 1),
                    'created_at': int(user.get('created_at') or now),
                    'updated_at': now,
                }
                if existing:
                    cid = existing['id']
                    # Update only newly attached records, or a deliberately
                    # rebuilt inbound. Never overwrite existing linked profiles
                    # during a routine repair.
                    if mode == 'fresh' or (not existing_link and not other_links):
                        up_cols = [k for k in profile if k in client_columns and k not in ('email', 'created_at')]
                        if up_cols:
                            conn.execute('UPDATE clients SET %s WHERE id=?' % (
                                ','.join('"%s"=?' % k for k in up_cols)),
                                [profile[k] for k in up_cols] + [cid])
                            counters['profiles_updated'] += 1
                else:
                    keys = [k for k in profile if k in client_columns]
                    conn.execute('INSERT INTO clients (%s) VALUES (%s)' % (
                        ','.join('"%s"' % k for k in keys),
                        ','.join('?' for _ in keys)), [profile[k] for k in keys])
                    cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                    counters['clients_created'] += 1
                    taken.add(email)
                linked_ids.add(cid)
                flow = str(user.get('flow') or '')
                current = conn.execute(
                    'SELECT flow_override FROM client_inbounds WHERE client_id=? AND inbound_id=?',
                    (cid, inbound_id)).fetchone()
                if current is None:
                    link_data = {'client_id': cid, 'inbound_id': inbound_id,
                                 'flow_override': flow, 'created_at': now}
                    keys = [k for k in link_data if k in link_columns]
                    conn.execute('INSERT INTO client_inbounds (%s) VALUES (%s)' % (
                        ','.join('"%s"' % k for k in keys),
                        ','.join('?' for _ in keys)), [link_data[k] for k in keys])
                    counters['links_created'] += 1
                elif current['flow_override'] != flow:
                    if mode == 'fresh' or not existing_link:
                        conn.execute('UPDATE client_inbounds SET flow_override=? WHERE client_id=? AND inbound_id=?',
                                     (flow, cid, inbound_id))
                        counters['links_updated'] += 1
                    else:
                        # A user managed in the UI may have an intentional
                        # per-inbound flow override; don't undo it on repair.
                        user['flow'] = current['flow_override']
                        changed = True
                # Preserve existing traffic values and disabled state. Only
                # repair a missing counter row; do not overwrite active quotas.
                if traffic_exists and {'inbound_id', 'email'}.issubset(traffic_columns):
                    trow = conn.execute('SELECT 1 FROM client_traffics WHERE email=?', (email,)).fetchone()
                    if trow is None:
                        tfields = {'inbound_id': inbound_id, 'email': email, 'enable': 1,
                                   'up': 0, 'down': 0, 'total': 0,
                                   'expiry_time': 0, 'reset': 0}
                        keys = [k for k in tfields if k in traffic_columns]
                        conn.execute('INSERT INTO client_traffics (%s) VALUES (%s)' % (
                            ','.join('"%s"' % k for k in keys),
                            ','.join('?' for _ in keys)), [tfields[k] for k in keys])
            if normalized and mode == 'fresh':
                # Reinstallation rewrites inbound IDs: remove only obsolete
                # links of those freshly-created inbounds, never other links.
                current_ids = [r[0] for r in conn.execute(
                    'SELECT client_id FROM client_inbounds WHERE inbound_id=?', (inbound_id,))]
                for old_id in current_ids:
                    if old_id not in linked_ids:
                        conn.execute('DELETE FROM client_inbounds WHERE client_id=? AND inbound_id=?',
                                     (old_id, inbound_id))
                        counters['stale_links_removed'] += 1
            if changed:
                settings['clients'] = users
                conn.execute('UPDATE inbounds SET settings=? WHERE id=?',
                             (json.dumps(settings, ensure_ascii=False, separators=(',', ':')), inbound_id))
                counters['inbounds_rewritten'] += 1
        # Check the actual source of Xray runtime users, not only JSON.
        if normalized:
            for inbound in inbounds:
                row = conn.execute('SELECT settings,stream_settings FROM inbounds WHERE id=?',
                                   (inbound['id'],)).fetchone()
                if row is None:
                    continue
                stream = json.loads(row['stream_settings'] or '{}')
                if stream.get('security') != 'reality':
                    continue
                users = [u for u in json.loads(row['settings'] or '{}').get('clients', [])
                         if isinstance(u, dict) and u.get('enable', True) and u.get('id')]
                for u in users:
                    link = conn.execute('SELECT c.uuid, l.flow_override, c.enable FROM clients c '
                        'JOIN client_inbounds l ON l.client_id=c.id '
                        'WHERE l.inbound_id=? AND c.email=?',
                        (inbound['id'], u.get('email'))).fetchone()
                    if link is None or link['uuid'] != u['id'] or link['enable'] != 1:
                        raise RuntimeError('REALITY inbound %s normalized client missing/mismatched' % inbound['id'])
                    if link['flow_override'] != str(u.get('flow') or ''):
                        raise RuntimeError('REALITY inbound %s flow override mismatch' % inbound['id'])
        conn.commit()
        if normalized:
            print('[OK] 3X-UI clients/client_inbounds 同步完成：新客户端=%d, 新关联=%d, 清理旧关联=%d' % (
                counters['clients_created'], counters['links_created'], counters['stale_links_removed']))
        else:
            print('[INFO] 旧版面板无独立客户端表，使用传统入站设置')
        return 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        sys.exit('usage: sync_clients.py /etc/x-ui/x-ui.db [repair|fresh]')
    try:
        sys.exit(sync(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else 'repair'))
    except Exception as exc:
        print('[ERROR] 3X-UI 客户端同步失败：%s' % exc, file=sys.stderr)
        sys.exit(1)

PY_SYNC_NORMALIZED
}

# Repair direct-SQL client records after taking a reversible DB snapshot.
# No client UUID, REALITY server private key, SNI or ShortID is rotated.
xui_repair_client_records() {
    [[ -s "$XUIDB" ]] || { echo '[ERROR] 3X-UI database missing'; return 1; }
    xui_ensure_safe_dirs || return 1
    local backup="$XUI_SAFE_BASE/snapshots/clients-before-sync-$(date +%Y%m%d_%H%M%S).db"
    echo '[INFO] 自动同步 3X-UI 客户端记录及关联（保留现有节点参数）'
    systemctl stop x-ui || return 1
    if ! sqlite3 "$XUIDB" ".backup '$backup'"; then
        echo '[ERROR] database backup failed; no modifications made'
        systemctl start x-ui || true
        return 1
    fi
    chmod 600 "$backup" 2>/dev/null || true
    if ! xui_sync_normalized_clients repair; then
        echo '[ERROR] client synchronization failed; restoring backup'
        cp -p "$backup" "$XUIDB" || true
        systemctl start x-ui || true
        return 1
    fi
    if ! systemctl start x-ui; then
        echo '[ERROR] panel failed to start; restoring original DB'
        systemctl stop x-ui || true
        cp -p "$backup" "$XUIDB" || true
        systemctl start x-ui || true
        return 1
    fi
    sleep 3
    echo '[OK] normalized clients synchronized and 3X-UI restarted'
}

# After installation, test the real authenticated connection and repair automatically.
# No node identity is changed. Each attempted change is transactional and reversible.
xui_auto_repair() {
    xui_ensure_safe_dirs
    local report="$XUI_SAFE_BASE/install-last.log" rc=1
    echo "[INFO] 自动验收日志：$report"
    (
        echo "===== $(date -Is) X-UI REALITY installation verification ====="
        echo "Panel $(xui_panel_version), Core $(xui_core_version)"
        if xui_runtime_check && xui_reality_probe; then
            echo '[OK] 安装验证成功，无需修复'
            exit 0
        fi
        echo '[WARN] 代理检测失败，优先修复旧版本写入的不完整客户端记录'
        if ! xui_repair_client_records; then
            echo '[ERROR] 自动修复客户端记录失败，保留原数据库快照'
            exit 1
        fi
        if xui_runtime_check && xui_reality_probe; then
            echo '[OK] 客户端记录修复后 REALITY 认证已通过'
            exit 0
        fi
        # A restart regenerates the panel configuration and normalised client links.
        systemctl restart x-ui || true
        sleep 2
        if xui_runtime_check && xui_reality_probe; then
            echo '[OK] 3X-UI 重建运行配置后 REALITY 连接正常'
            exit 0
        fi
        echo '[ERROR] 代理验证仍失败，保留原内核；不再盲目升级/降级。请查看上方明确的故障原因'
        exit 1
    ) 2>&1 | tee "$report"
    rc=${PIPESTATUS[0]}
    chmod 600 "$report" 2>/dev/null || true
    return "$rc"
}

xui_auto_try_without_vless_fallback() {
    [[ -s "$XUIDB" ]] || return 1
    command -v python3 >/dev/null || return 1
    local saved
    saved="$(mktemp /tmp/xui-reality-inbound.XXXXXX)" || return 1
    chmod 600 "$saved"
    if ! python3 - "$XUIDB" "$saved" <<'PYSAVE'
import json, sqlite3, sys
conn=sqlite3.connect(sys.argv[1],timeout=10)
row=conn.execute("SELECT id,settings FROM inbounds WHERE protocol='vless' AND enable=1 AND json_extract(stream_settings, '$.security')='reality' ORDER BY id DESC LIMIT 1").fetchone()
if not row: sys.exit(1)
settings=json.loads(row[1])
if not settings.get('fallbacks'):
    print('[INFO] 当前无需删除 VLESS fallback')
    sys.exit(1)
with open(sys.argv[2],'w') as f: json.dump({'id':row[0],'settings':row[1]},f)
settings.pop('fallbacks',None)
with conn:
    conn.execute('UPDATE inbounds SET settings=? WHERE id=?',(json.dumps(settings),row[0]))
print('[INFO] 暂时删除重复的 VLESS fallback，保留 REALITY target')
PYSAVE
    then
        rm -f "$saved"
        return 1
    fi
    systemctl restart x-ui || true
    sleep 2
    if xui_runtime_check && xui_reality_probe; then
        mv -f "$saved" "$XUI_SAFE_BASE/snapshots/reality-settings-before-fallback-adjust-$(date +%Y%m%d_%H%M%S).json"
        return 0
    fi
    echo '[WARN] 删除重复 fallback 没有解决问题，恢复原有入站参数'
    python3 - "$XUIDB" "$saved" <<'PYRESTORE'
import json,sqlite3,sys
with open(sys.argv[2]) as f: data=json.load(f)
conn=sqlite3.connect(sys.argv[1],timeout=10)
with conn:
    conn.execute('UPDATE inbounds SET settings=? WHERE id=?',(data['settings'],data['id']))
PYRESTORE
    rm -f "$saved"
    systemctl restart x-ui || true
    sleep 2
    return 1
}

xui_auto_install_core() {
    local version="$1" destination current staged tmp_dir snapshot cfg
    destination="$(xui_xray_bin)" || return 1
    current="$(xui_core_version "$destination")"
    [[ "$current" != "$version" ]] || return 1
    cfg='/usr/local/x-ui/bin/config.json'
    staged="$(xui_download_compat_core "$version")" || return 1
    tmp_dir="$(dirname "$staged")"
    local validation_log
    validation_log="$(mktemp /tmp/xui-staged-validation.XXXXXX)"
    if ! XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$staged" run -test -config "$cfg" >"$validation_log" 2>&1; then
        echo '[WARN] 内核兼容性测试失败（保留现有内核）：'
        tail -n 7 "$validation_log"
        rm -f "$validation_log"
        rm -rf "$tmp_dir"
        return 1
    fi
    rm -f "$validation_log"
    snapshot="$XUI_SAFE_BASE/snapshots/core-before-$(date +%Y%m%d_%H%M%S)"
    cp -p "$destination" "$snapshot" || { rm -rf "$tmp_dir"; return 1; }
    systemctl stop x-ui || true
    if ! install -m 755 "$staged" "$destination"; then
        install -m 755 "$snapshot" "$destination" || true
        systemctl start x-ui || true
        rm -rf "$tmp_dir"
        return 1
    fi
    rm -rf "$tmp_dir"
    systemctl start x-ui || true
    sleep 2
    if xui_runtime_check && xui_reality_probe; then
        echo "[OK] 核心已由 $current 更新至 $version，且代理已通过测试"
        return 0
    fi
    echo '[WARN] 核心更新没有通过真实代理测试，立即回滚'
    systemctl stop x-ui || true
    install -m 755 "$snapshot" "$destination" || return 1
    systemctl start x-ui || true
    return 1
}

xui_maintenance_menu() {
    local choice
    while true; do
        echo
        echo '---------- Xray / REALITY ----------'
        echo '1) 自动检查并修复（推荐）'
        echo '2) 查看详细诊断'
        echo '3) 安全更新 Xray（失败回滚）'
        echo '4) 恢复上次已验证的内核'
        echo '0) 返回'
        read_tty '请选择 [0-4，回车默认 1]: ' choice
        case "${choice:-1}" in
            1) xui_auto_repair && xui_mark_good || true; pause ;;
            2) xui_diagnostic; pause ;;
            3) xui_install_compat_core || true; pause ;;
            4) xui_restore_good || true; pause ;;
            0) return 0 ;;
            *) echo '无效选择' ;;
        esac
    done
}


# Non-destructive report for failure to connect; no secrets printed.
xui_site_reality_report() {
    local fb='' sni=''
    fb="$(xui_real_fallback_port 2>/dev/null || echo 8080)"
    sni="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.serverNames[0]') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
    echo '===== Nginx syntax ====='
    if command -v nginx >/dev/null 2>&1; then nginx -t 2>&1 || true; else echo 'nginx not installed'; fi
    echo '===== Actual listeners ====='
    ss -lntp 2>/dev/null | grep -E "(:443|:${fb}|:8443)([[:space:]]|$)" || true
    echo '===== Website HTTP backend / TLS fallback ====='
    echo "SNI=${sni:-unknown} fallback=127.0.0.1:${fb}"
    if [[ -f /etc/nginx/sites-enabled/wow ]] && grep -Eq 'listen[[:space:]]+127\.0\.0\.1:8080[[:space:]]*;' /etc/nginx/sites-enabled/wow; then
        echo '[INFO] wow 网站使用 HTTP 127.0.0.1:8080，不应该给它强行配置 ssl_certificate'
    fi
    if xui_nginx_tls_responds "$fb"; then
        echo "[OK] TLS 127.0.0.1:${fb} certificate matches SNI"
    else
        echo "[WARN] TLS 127.0.0.1:${fb} not reachable or certificate does not match SNI"
    fi
    echo '===== Panel DB and generated Xray client counts ====='
    if command -v sqlite3 >/dev/null 2>&1 && [[ -s "$XUIDB" ]]; then
        sqlite3 -header -column "$XUIDB" "SELECT port,remark,enable,json_array_length(json_extract(settings,'\$.clients')) AS legacy_clients FROM inbounds WHERE protocol='vless';" 2>/dev/null || true
    fi
    if command -v jq >/dev/null 2>&1 && [[ -s /usr/local/x-ui/bin/config.json ]]; then
        jq -r '.inbounds[] | select(.protocol=="vless") | "runtime port=\(.port) security=\(.streamSettings.security) clients=\((.settings.clients // [])|length)"' /usr/local/x-ui/bin/config.json || true
    fi
    echo '===== recent x-ui messages ====='
    journalctl -u x-ui -n 18 --no-pager 2>/dev/null | tail -n 18 || true
}

# -----------------------------
#  程序入口
# -----------------------------
main() {
    case "${1:-}" in
       --xui-guard) xui_guard_watch; return $? ;;
       --xui-monthly)
           echo "$(date -Is) monthly check: 3X-UI=$(xui_panel_version) Xray=$(xui_core_version)"
           xui_diagnostic; return 0 ;;
       --xui-diagnose) xui_diagnostic; return 0 ;;
       --site-diag) xui_site_reality_report; return 0 ;;
       --uninstall|--uninstall-xui) uninstall_xui_menu; return $? ;;
       --fix-nginx)
           domain="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.serverNames[0]') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
           local fix_rc=0
           xui_bridge_apply repair || fix_rc=$?
           (( fix_rc == 0 || fix_rc == 2 )) || return 1
           xui_nginx_preflight_preserve || return 1
           xui_repair_nginx_existing; return $? ;;
       --repair)
           domain="$(sqlite3 "$XUIDB" "SELECT json_extract(stream_settings,'\$.realitySettings.serverNames[0]') FROM inbounds WHERE protocol='vless' AND json_extract(stream_settings,'\$.security')='reality' ORDER BY id DESC LIMIT 1;" 2>/dev/null | head -n1)"
           local bridge_rc=0
           xui_bridge_apply repair || bridge_rc=$?
           (( bridge_rc == 0 || bridge_rc == 2 )) || return 1
           xui_nginx_preflight_preserve || return 1
           local existing_fb
           existing_fb="$(xui_real_fallback_port 2>/dev/null || true)"
           [[ "$existing_fb" =~ ^[0-9]+$ ]] || existing_fb=8080
           if ! xui_nginx_tls_responds "$existing_fb"; then
               echo "[ERROR] REALITY HTTPS 回落 127.0.0.1:${existing_fb} 不可用，停止无意义的客户端/内核修复。" >&2
               echo '[HINT] 原 wow 为 HTTP:8080，请执行：python3 /root/xui-v12/repair-http-fallback.py --apply' >&2
               return 1
           fi
           xui_auto_repair; return $? ;;
    esac
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
