#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WOL WEB: single-button Wake-on-LAN dashboard with persistent send history."""
WOL_WEB_APP_VERSION = "1.5.12"

import errno
import fcntl
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
import tempfile
from datetime import datetime
from functools import wraps
from contextlib import contextmanager
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, abort, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

APP_DIR = Path(__file__).resolve().parent
CONFIG_FILE = Path(os.environ.get("WOL_CONFIG_FILE", str(APP_DIR / "config.json")))
DB_FILE = Path(os.environ.get("WOL_HISTORY_FILE", str(APP_DIR / "wol_history.db")))
SEND_LOG_FILE = Path(os.environ.get("WOL_SEND_LOG_FILE", str(APP_DIR / "wol_send.log")))
TZ = ZoneInfo("Asia/Shanghai")
os.umask(0o077)

PAGE = r'''<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b1320"><title>WOL</title>
<style>
:root{color-scheme:dark;--bg:#0b1320;--text:#e9f3ff;--muted:#8296ad;--mint:#70e3b2;--border:#2d4059}
*{box-sizing:border-box}html,body{min-height:100%;margin:0}
body{background:radial-gradient(circle at 50% 22%,#18344b 0%,#101c2e 36%,#0b1320 77%);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:22px 16px}
.wrap{width:100%;max-width:460px;margin:0 auto;min-height:calc(100dvh - 44px);display:flex;flex-direction:column}
.bar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:3px 0 12px}
.logo{font-size:14px;letter-spacing:.22em;color:#d8e8f5;font-weight:850}.dot{color:var(--mint);font-size:18px;margin-right:9px}
.logout{color:#9eb2c9;background:transparent;border:1px solid #344861;border-radius:10px;padding:7px 13px;cursor:pointer}
.btn-box{text-align:center;padding:17px 0 5px}
.wake{width:196px;height:196px;max-width:65vw;max-height:65vw;cursor:pointer;border-radius:50%;border:1px solid #75e6b3;background:radial-gradient(circle at 36% 22%,#2e6b63 0%,#1a514b 43%,#0d3039 82%);box-shadow:0 0 0 11px #70e3b20c,0 0 0 24px #70e3b208,0 0 55px #33d9a331;color:#f1fff9;display:inline-flex;align-items:center;justify-content:center;flex-direction:column;gap:4px;transition:transform .12s,opacity .12s}
.wake:active{transform:scale(.97)}.wake:disabled{cursor:not-allowed;opacity:.55}.wake:focus-visible,.refresh:focus-visible{outline:3px solid #f0fffc;outline-offset:5px}
.power-icon{display:block;width:72px;height:72px;fill:none;stroke:#84f4c4;stroke-width:5.5;stroke-linecap:round;stroke-linejoin:round;flex:none}
.feedback{margin:13px 0 14px;min-height:24px;text-align:center;color:#91aac2;font-size:13px;overflow-wrap:anywhere}
.feedback.ok{color:#9cf6d0}.feedback.err{color:#ffb0b9}.feedback.refused{color:#ffcf8b}
.history{margin-top:5px;background:#111f31dc;border:1px solid var(--border);border-radius:18px;padding:18px 17px 12px}
.heading{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:10px}
.heading strong{font-size:15px;font-weight:700}.heading small{font-size:11px;color:#7890aa;margin-left:5px;font-weight:400}
.refresh{border:1px solid #37506a;background:#172d40;color:#bdebd9;padding:8px 12px;font:inherit;font-size:12px;border-radius:9px;cursor:pointer}
.empty{color:#8196af;text-align:center;padding:26px 2px;font-size:13px}
.entry{padding:11px 0;border-top:1px solid #23394d;display:flex;gap:7px 12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.state{font-size:13px;font-weight:650}.state.ok{color:#8eebbf}.state.err{color:#ffacb9}.state.refused{color:#ffcf8b}
.when{font-size:11px;color:#839ab4;white-space:nowrap;margin-left:auto;font-variant-numeric:tabular-nums}
.login{background:#101e2fcf;border:1px solid var(--border);border-radius:20px;padding:30px 24px 28px;margin:clamp(40px,12vh,112px) auto 0;width:100%;max-width:390px}
.login-mark{display:flex;align-items:center;justify-content:center;margin:0 auto 20px;width:40px;height:40px;border-radius:50%;background:#132b3a;border:1px solid #477c78;box-shadow:0 0 14px #33d9a31a}.login-mark svg{width:22px;height:22px;fill:none;stroke:#84f4c4;stroke-width:4;stroke-linecap:round;stroke-linejoin:round}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.login input{background:#0b1726;border:1px solid #39516a;color:#fff;padding:13px 14px;border-radius:11px;font:inherit;width:100%;height:50px;outline:none}.login input::placeholder{color:#7b90a7}.login input:focus{border-color:#82e7ba;box-shadow:0 0 0 3px #82e7ba20}
.login button{margin-top:12px;width:100%;height:50px;padding:12px;border:0;border-radius:11px;background:#82e7ba;color:#0d3026;font:inherit;font-weight:750;cursor:pointer}.login button:active{opacity:.86}.login .login-error{min-height:0;margin:13px 0 0;text-align:center;color:#ffb0b9;font-size:13px}
@media(max-height:720px){.bar{margin-bottom:12px}.lead{margin-bottom:11px}.wake{width:165px;height:165px}.btn-box{padding:8px 0}.feedback{margin:12px 0}}
</style></head><body><main class="wrap">
<header class="bar">
<div class="logo">WOL</div>
{% if auth_enabled and logged_in %}<form action="{{ url_for('logout') }}" method="post"><input name="csrf" type="hidden" value="{{ csrf }}"><button class="logout" type="submit">退出</button></form>{% endif %}
</header>
{% if auth_enabled and not logged_in %}
<section class="login" aria-label="登录">
  <div class="login-mark" role="img" aria-label="电源图标"><svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><path d="M32 7 V30"/><path d="M20 12 A24 24 0 1 0 44 12"/></svg></div>
  <form action="{{ url_for('login') }}" method="post">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label class="sr-only" for="pw">密码</label>
    <input id="pw" name="password" type="password" placeholder="密码" autocomplete="current-password" required>
    <button type="submit">登录</button>
  </form>
  {% if message %}<p class="login-error" role="alert">{{ message }}</p>{% endif %}
</section>
{% else %}
<div class="btn-box"><button id="wakeButton" class="wake" type="button" aria-label="唤醒 NAS"><svg class="power-icon" viewBox="0 0 64 64" role="img" aria-label="电源" xmlns="http://www.w3.org/2000/svg"><path d="M32 7 V30"/><path d="M20 12 A24 24 0 1 0 44 12"/></svg></button></div>
<div id="feedback" class="feedback" aria-live="polite"></div>
<section class="history" aria-label="最近五条发送记录"><div class="heading"><strong>发送记录 <small>最近 5 条 · 北京时间</small></strong><button id="refreshButton" class="refresh" type="button">↻ 刷新</button></div><div id="historyList" class="empty">加载中...</div></section>
<script>
const csrf = {{ csrf|tojson }};
const historyList = document.getElementById('historyList');
const wakeButton = document.getElementById('wakeButton');
const refreshButton = document.getElementById('refreshButton');
const feedback = document.getElementById('feedback');
function makeEl(tag, cls, text){const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;}
async function refreshHistory(){
  refreshButton.disabled=true;
  try{
    const resp=await fetch('/api/history',{credentials:'same-origin',cache:'no-store'});
    if(resp.status===401){location.reload();return;}
    if(!resp.ok)throw new Error('HTTP '+resp.status);
    const data=await resp.json();historyList.replaceChildren();historyList.className='';
    if(!data.records || !data.records.length){historyList.className='empty';historyList.textContent='暂无发送记录';return;}
    for(const item of data.records){
      const div=makeEl('div','entry');
      const ok=item.status==='sent';const pending=item.status==='sending';const refused=item.status==='refused';
      const statusText=ok?'✓ 唤醒数据包已发送':(pending?'… 正在发送':refused?'Send refused！':'发送失败');
      div.append(makeEl('div','state '+(ok?'ok':pending?'':refused?'refused':'err'),statusText));
      div.append(makeEl('time','when',item.time));historyList.append(div);
    }
  }catch(ex){historyList.className='empty';historyList.textContent='记录加载失败，请点击刷新';}
  finally{refreshButton.disabled=false;}
}
wakeButton.addEventListener('click',async()=>{
  wakeButton.disabled=true;feedback.className='feedback';feedback.textContent='正在发送 WOL 唤醒包...';
  try{
    const resp=await fetch('/api/wake',{method:'POST',headers:{'X-CSRF-Token':csrf},credentials:'same-origin',cache:'no-store'});
    if(resp.status===401){location.reload();return;}
    const data=await resp.json();feedback.className='feedback '+(data.refused?'refused':resp.ok?'ok':'err');
    feedback.textContent=data.message || '请求失败';await refreshHistory();
  }catch(ex){feedback.className='feedback err';feedback.textContent='连接失败，请检查 WEB 服务或网络连接';}
  finally{wakeButton.disabled=false;}
});
refreshButton.addEventListener('click',refreshHistory);
refreshHistory();
</script>
{% endif %}
</main></body></html>'''


def load_config():
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            obj = json.load(handle)
            return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


# Missing optional configuration fields do not prevent the web service from
# starting. The management script fills in defaults before deploying the app.
# Keep authentication unavailable until a persistent secret/password exists.
_boot = load_config()
_has_persistent_secret = isinstance(_boot.get("secret_key"), str) and bool(_boot.get("secret_key"))

app = Flask(__name__)
app.secret_key = _boot["secret_key"] if _has_persistent_secret else secrets.token_hex(32)
# Only trust the locally configured Nginx proxy; do not bind the app to public interfaces.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True)

_failed_logins = {}
_login_lock = threading.Lock()


def auth_enabled():
    """Login is always required, including for upgraded auth_enabled=false configs."""
    return True


def logged_in():
    return session.get("logged_in") is True and session.get("login_method") == "password"


def require_auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not logged_in():
            return jsonify({"ok": False, "message": "请先登录"}), 401
        return fn(*args, **kwargs)
    return wrapped


def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(28)
        session["_csrf"] = token
    return token


def check_csrf():
    submitted = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf", "")
    expected = session.get("_csrf", "")
    if not submitted or not expected or not hmac.compare_digest(submitted, expected):
        return False
    # Same-site token is required for all state-changing actions.
    return True


def normalize_mac(mac):
    mac = str(mac or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f]{12}", mac):
        compact = mac
    elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", mac):
        compact = mac.replace(":", "").replace("-", "")
    else:
        raise ValueError("MAC 地址不合法，请检查菜单 2 配置")
    return bytes.fromhex(compact)


def validate_host(value):
    host = str(value or "").strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host) or "://" in host or "/" in host or "\\" in host:
        raise ValueError("未设置合法的 DDNS 域名/IP，请先运行管理脚本菜单 2")
    try:
        if ipaddress.ip_address(host).version != 4:
            raise ValueError("目前仅支持 IPv4 WOL 转发目标")
        return host
    except ValueError as exc:
        if "IPv4 WOL" in str(exc):
            raise
    domain = host.rstrip(".")
    pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    if not domain or not all(pattern.fullmatch(label) for label in domain.split(".")):
        raise ValueError("NAS 域名格式不合法")
    return host


def build_packet(mac):
    return b"\xff" * 6 + normalize_mac(mac) * 16


class WOLSendError(OSError):
    """UDP submission failure, optionally carrying ICMP-related errno 111.

    ECONNREFUSED is a network hint, never proof of NAS online/offline status.
    """

    def __init__(self, message, *, refused=False, ips=None, failed_packets=0, errors=None):
        super().__init__(message)
        self.refused = bool(refused)
        self.ips = list(ips or [])
        self.failed_packets = int(failed_packets)
        self.errors = list(errors or [])


def _send_wol_to_host(host, port, packet):
    """Submit separate unconnected IPv4 UDP datagrams to one DDNS host.

    A successful sendto only proves local submission, not receipt or boot.
    """
    target = validate_host(host)
    try:
        resolved = socket.getaddrinfo(target, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError(f"DDNS 解析 IPv4 失败：{exc}") from exc

    ips = list(dict.fromkeys(item[4][0] for item in resolved))
    if not ips:
        raise ValueError("域名没有解析到 IPv4 地址")
    if len(ips) > 4:
        raise ValueError("域名解析出过多 IPv4 地址；请检查是否误开 CDN 代理")

    sent = 0
    sources = []
    errors = []
    refused = False

    def send_one(destination, use_source_port_9):
        # One fresh UDP socket per packet avoids stale errors on a connected
        # socket; it does not guarantee the remote router/NAS received data.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            if use_source_port_9:
                sock.bind(("0.0.0.0", 9))
            written = sock.sendto(packet, destination)
            if written != len(packet):
                raise OSError(f"UDP 发包不完整：{written}/{len(packet)} 字节")
            try:
                return sock.getsockname()[1]
            except OSError:
                return 9 if use_source_port_9 else 0

    for ip in ips:
        destination = (ip, port)
        for index in range(5):
            try:
                src_port = send_one(destination, False)
                sent += 1
                sources.append(f"随机源端口:{src_port}")
            except OSError as exc:
                if exc.errno == errno.ECONNREFUSED:
                    refused = True
                errors.append(f"{ip} UDP 发送：{exc}")
            if index < 4:
                time.sleep(0.10)

        # Two best-effort packets from UDP source port 9. A bind failure
        # does not invalidate successful submissions from random ports.
        for index in range(2):
            try:
                src_port = send_one(destination, True)
                sent += 1
                sources.append(f"源端口:{src_port}")
            except OSError as exc:
                if exc.errno == errno.ECONNREFUSED:
                    refused = True
                errors.append(f"{ip} 源端口9：{exc}")
            if index == 0:
                time.sleep(0.10)

    unique_errors = list(dict.fromkeys(errors))
    if sent == 0:
        brief = "；".join(unique_errors[:3]) or "没有数据包提交成功"
        raise WOLSendError(
            f"没有数据包成功提交：{brief}", refused=refused,
            ips=ips, failed_packets=len(errors), errors=unique_errors,
        )

    return ips, sent, sources, unique_errors, refused, len(errors)


def send_wol(config):
    """Attempt host1 then host2; a single successful host wins overall.

    For any configured target, capture its own genuine UDP submission
    outcome.  Both failures are represented in the result instead of
    throwing away per-host diagnostics in an exception.
    """
    try:
        port = int(config.get("port", 9))
    except (TypeError, ValueError) as exc:
        raise ValueError("WOL 端口不合法") from exc
    if not 1 <= port <= 65535:
        raise ValueError("WOL UDP 端口必须在 1-65535 之间")
    packet = build_packet(config.get("mac", ""))
    if len(packet) != 102:
        raise ValueError("Magic Packet 长度不正确")

    primary = config.get("host1", "")
    backup = config.get("host2", "")
    primary = primary.strip() if isinstance(primary, str) else ""
    backup = backup.strip() if isinstance(backup, str) else ""
    if not primary:
        raise ValueError("主域名尚未设置，请在管理菜单 2 填写 host1")
    if backup and backup.lower().rstrip(".") == primary.lower().rstrip("."):
        raise ValueError("主域名和备域名不能相同")

    targets = [("primary", primary)]
    if backup:
        targets.append(("backup", backup))

    attempts = []
    for i, (route, host) in enumerate(targets):
        if i:
            time.sleep(0.20)
        try:
            ips, sent, sources, errors, refused, failed_packets = _send_wol_to_host(host, port, packet)
            attempts.append({
                "route": route, "host": host, "ok": True,
                "ips": ips, "packets": sent, "failed_packets": failed_packets,
                "sources": sources, "error": "", "warnings": errors,
                "refused": refused,
            })
        except (OSError, ValueError) as exc:
            attempts.append({
                "route": route, "host": host, "ok": False,
                "ips": list(getattr(exc, "ips", [])), "packets": 0,
                "failed_packets": int(getattr(exc, "failed_packets", 0)),
                "sources": [], "error": str(exc),
                "warnings": list(getattr(exc, "errors", [])),
                "refused": bool(getattr(exc, "refused", False) or
                                getattr(exc, "errno", None) == errno.ECONNREFUSED),
            })

    succeeded = [attempt for attempt in attempts if attempt["ok"]]
    reasons = [
        f"{'主域名' if item['route'] == 'primary' else '备域名'}"
        f"({item['host']})：{item['error']}"
        for item in attempts if not item["ok"]
    ]
    return {
        "ok": bool(succeeded),
        "refused": any(item["refused"] for item in attempts),
        "attempts": attempts,
        "port": port,
        "success_count": len(succeeded),
        "target_count": len(attempts),
        "packets": sum(item["packets"] for item in attempts),
        "error": "；".join(reasons),
    }


def _log_host(config, route, attempts, error=""):
    """One independent and truthful status per host, per click."""
    key = "host1" if route == "primary" else "host2"
    configured = config.get(key, "")
    configured = configured.strip() if isinstance(configured, str) else ""
    attempt = next((item for item in attempts if item["route"] == route), None)
    if attempt is None:
        return {
            "domain": configured,
            "status": "not_attempted" if (route == "primary" or configured) else "disabled",
            "resolved_ipv4": [], "packets_sent": 0, "packets_failed": 0,
            "errno111": False,
            "errors": [str(error)[:250]] if error and (route == "primary" or configured) else [],
        }

    sent = int(attempt.get("packets", 0))
    failed = int(attempt.get("failed_packets", 0))
    if sent and failed:
        status = "partial"
    elif sent:
        status = "sent"
    else:
        status = "failed"
    errors = list(attempt.get("warnings", []))
    if attempt.get("error") and attempt["error"] not in errors:
        errors.append(attempt["error"])
    return {
        "domain": attempt.get("host", configured),
        "status": status,
        "resolved_ipv4": list(attempt.get("ips", [])),
        "packets_sent": sent,
        "packets_failed": failed,
        "errno111": bool(attempt.get("refused", False)),
        "errors": [str(message)[:250] for message in errors[:4]],
    }


def append_send_log(config, result=None, *, trigger="web", error=""):
    """Keep exactly the latest 20 actual send attempts in a local JSONL log.

    Each line = one click, with separate host1 / host2 network outcomes.
    A stable sidecar flock serializes updates among Gunicorn workers; write
    to a private temporary file and atomically rename to avoid torn lines.
    """
    attempts = result.get("attempts", []) if result else []
    overall = ("sent" if result and result.get("ok") else
               "refused" if result and result.get("refused") else "failed")
    entry = {
        "time": datetime.now(TZ).isoformat(timespec="seconds"),
        "trigger": trigger,
        "overall": overall,
        "host1": _log_host(config, "primary", attempts, error),
        "host2": _log_host(config, "backup", attempts, error),
    }
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
    logfile = SEND_LOG_FILE
    lockfile = logfile.with_name(logfile.name + ".lock")
    logfile.parent.mkdir(parents=True, exist_ok=True)
    lockfd = os.open(str(lockfile), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(lockfd, "rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    with logfile.open("r", encoding="utf-8") as existing:
                        previous = existing.readlines()[-19:]
                except FileNotFoundError:
                    previous = []
                fd, name = tempfile.mkstemp(prefix=".wol-send-", dir=str(logfile.parent))
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        for old in previous:
                            if old.strip():
                                handle.write(old.rstrip("\r\n") + "\n")
                        handle.write(line)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(name, 0o600)
                    os.replace(name, logfile)
                finally:
                    if os.path.exists(name):
                        os.unlink(name)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise
    return entry


@contextmanager
def database():
    con = sqlite3.connect(str(DB_FILE), timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=10000")
        con.execute("CREATE TABLE IF NOT EXISTS sends ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, "
                    "status TEXT NOT NULL, detail TEXT NOT NULL)")
        yield con
    finally:
        con.close()


def history_items():
    """Expose only status and Beijing time; never return saved network details."""
    with database() as con:
        rows = con.execute("SELECT at,status FROM sends ORDER BY id DESC LIMIT 5").fetchall()
    return [
        {"time": datetime.fromtimestamp(ts, TZ).strftime("%m/%d %H:%M:%S"),
         "status": status}
        for ts, status in rows
    ]


def reserve_send(cooldown):
    """Atomic, persistent rate limit shared across all gunicorn workers."""
    now = int(time.time())
    with database() as con:
        con.execute("BEGIN IMMEDIATE")
        last = con.execute("SELECT at FROM sends ORDER BY id DESC LIMIT 1").fetchone()
        if last and now - last[0] < cooldown:
            con.rollback()
            return None, max(1, cooldown - (now - last[0]))
        cursor = con.execute("INSERT INTO sends(at,status,detail) VALUES(?,?,?)",
                             (now, "sending", "正在准备发送"))
        row_id = cursor.lastrowid
        con.execute("DELETE FROM sends WHERE id NOT IN (SELECT id FROM sends ORDER BY id DESC LIMIT 5)")
        con.commit()
        return row_id, 0


def finish_send(row_id, status, detail):
    with database() as con:
        con.execute("UPDATE sends SET status=?,detail=? WHERE id=?", (status, detail[:220], row_id))


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                                   "style-src 'self' 'unsafe-inline'; "
                                                   "connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
    return response


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "version": WOL_WEB_APP_VERSION})


@app.get("/")
def index():
    config = load_config()
    if not config.get("password_hash") or not config.get("secret_key"):
        return "WEB 未完成初始化：请运行 wol.sh，选择菜单 1 补齐配置，再在菜单 3 设置访问密码。", 503
    return render_template_string(PAGE, csrf=csrf_token(),
                                  auth_enabled=auth_enabled(), logged_in=logged_in(),
                                  message=request.args.get("error", ""))


@app.post("/login")
def login():
    if not check_csrf():
        abort(400)
    ip = request.remote_addr or "unknown"
    with _login_lock:
        now = time.time()
        _failed_logins[ip] = [t for t in _failed_logins.get(ip, []) if now - t < 300]
        if len(_failed_logins[ip]) >= 8:
            abort(429)
    stored_hash = load_config().get("password_hash", "")
    pw = request.form.get("password", "")
    try:
        valid = bool(pw) and bool(stored_hash) and check_password_hash(stored_hash, pw)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        with _login_lock:
            _failed_logins.setdefault(ip, []).append(time.time())
        return redirect(url_for("index", error="密码错误"))
    session.clear()
    session["logged_in"] = True
    session["login_method"] = "password"
    session["_csrf"] = secrets.token_urlsafe(28)
    with _login_lock:
        _failed_logins.pop(ip, None)
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    if not check_csrf():
        abort(400)
    session.clear()
    return redirect(url_for("index"))


@app.get("/api/history")
@require_auth
def history():
    return jsonify({"records": history_items()})


def _safe_log_send(config, result=None, *, trigger="web", error=""):
    try:
        append_send_log(config, result, trigger=trigger, error=error)
    except (OSError, ValueError, TypeError):
        # A log I/O problem must never mask the real packet submission result.
        app.logger.exception("Unable to rotate 20-entry WOL send log")


@app.post("/api/wake")
@require_auth
def wake():
    if not check_csrf():
        return jsonify({"ok": False, "message": "页面验证失效，请刷新后重试"}), 400
    config = load_config()
    try:
        cooldown = max(5, min(600, int(config.get("cooldown_seconds") or 20)))
    except (TypeError, ValueError):
        cooldown = 20
    try:
        row_id, seconds_left = reserve_send(cooldown)
    except sqlite3.Error:
        app.logger.exception("Unable to store WOL history")
        return jsonify({"ok": False, "message": "发送记录数据库暂时不可写，请检查服务权限"}), 503
    if row_id is None:
        return jsonify({"ok": False, "message": f"操作过于频繁，请 {seconds_left} 秒后再试"}), 429

    try:
        result = send_wol(config)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # A malformed configuration did not begin sending to either host.
        _safe_log_send(config, trigger="web", error=str(exc))
        app.logger.warning("WOL preparation failed: %s", exc)
        finish_send(row_id, "failed", "发送失败")
        return jsonify({"ok": False, "message": "WOL 发送失败"}), 502

    # One click -> exactly one rotated local log entry, with BOTH independent
    # host outcomes, even when one target fails DNS or all packets fail.
    _safe_log_send(config, result)
    for attempt in result["attempts"]:
        level = app.logger.info if attempt["ok"] else app.logger.warning
        level("WOL route=%s host=%s ips=%s submitted=%s failed=%s errno111=%s details=%s",
              attempt["route"], attempt["host"], attempt["ips"],
              attempt["packets"], attempt["failed_packets"],
              attempt["refused"], attempt["warnings"] or attempt["error"])

    if result["ok"]:
        # Success of either host wins.  Even ECONNREFUSED on the other host
        # must not turn the whole click into a failure.
        finish_send(row_id, "sent", "唤醒数据包已发送")
        return jsonify({"ok": True, "refused": False,
                        "message": "✓ 唤醒数据包已发送"})

    if result["refused"]:
        finish_send(row_id, "refused", "Send refused！")
        return jsonify({"ok": False, "refused": True,
                        "message": "Send refused！"}), 502

    finish_send(row_id, "failed", "发送失败")
    return jsonify({"ok": False, "refused": False,
                    "message": "WOL 发送失败"}), 502


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == "--test-wol":
        config = load_config()
        try:
            result = send_wol(config)
            _safe_log_send(config, result, trigger="ssh_test")
            for attempt in result["attempts"]:
                label = "主域名" if attempt["route"] == "primary" else "备域名"
                status = "已提交" if attempt["ok"] else "失败"
                print(f"{label} {attempt['host']}：{status} {attempt['packets']} 个包；错误包 {attempt['failed_packets']} 个；Errno111={attempt['refused']}")
            if result["ok"]:
                print("✓ 唤醒数据包已发送")
            elif result["refused"]:
                print("Send refused！", file=sys.stderr)
                sys.exit(1)
            else:
                print("WOL 发送失败", file=sys.stderr)
                sys.exit(1)
            print("注意：本地发送成功不等于 NAS 已经开机。")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            _safe_log_send(config, trigger="ssh_test", error=str(exc))
            print(f"WOL 测试发送失败：{exc}", file=sys.stderr)
            sys.exit(1)
    elif len(sys.argv) > 1:
        print("用法：python wol.py [--test-wol]", file=sys.stderr)
        sys.exit(2)
    else:
        app.run(host="127.0.0.1", port=int(os.environ.get("WOL_WEB_PORT", "8109")), debug=False)
