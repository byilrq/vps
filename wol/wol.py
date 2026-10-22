#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WOL WEB: single-button Wake-on-LAN dashboard with persistent send history."""
WOL_WEB_APP_VERSION = "1.4.0"

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
TZ = ZoneInfo("Asia/Shanghai")
os.umask(0o077)

PAGE = r'''<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b1320"><title>NAS 远程唤醒</title>
<style>
:root{color-scheme:dark;--bg:#0b1320;--text:#e9f3ff;--muted:#8296ad;--mint:#70e3b2;--border:#2d4059}
*{box-sizing:border-box}html,body{min-height:100%;margin:0}
body{background:radial-gradient(circle at 50% 22%,#18344b 0%,#101c2e 36%,#0b1320 77%);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:22px 16px}
.wrap{width:100%;max-width:460px;margin:0 auto;min-height:calc(100dvh - 44px);display:flex;flex-direction:column}
.bar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:3px 0 29px}
.logo{font-size:13px;letter-spacing:.17em;color:#b8d1e4;font-weight:800}.dot{color:var(--mint);font-size:18px;margin-right:9px}
.logout{color:#9eb2c9;background:transparent;border:1px solid #344861;border-radius:10px;padding:7px 13px;cursor:pointer}
h1{font-size:26px;letter-spacing:.04em;text-align:center;margin:1px 0 7px}
.lead{text-align:center;color:var(--muted);font-size:13px;margin:0 0 26px}
.btn-box{text-align:center;padding:17px 0 5px}
.wake{width:196px;height:196px;max-width:65vw;max-height:65vw;cursor:pointer;border-radius:50%;border:1px solid #75e6b3;background:radial-gradient(circle at 36% 22%,#2e6b63 0%,#1a514b 43%,#0d3039 82%);box-shadow:0 0 0 11px #70e3b20c,0 0 0 24px #70e3b208,0 0 55px #33d9a331;color:#f1fff9;display:inline-flex;align-items:center;justify-content:center;flex-direction:column;gap:4px;transition:transform .12s,opacity .12s}
.wake:active{transform:scale(.97)}.wake:disabled{cursor:not-allowed;opacity:.55}.wake:focus-visible,.refresh:focus-visible{outline:3px solid #f0fffc;outline-offset:5px}
.power-icon{display:block;width:62px;height:62px;fill:none;stroke:#84f4c4;stroke-width:6;stroke-linecap:round;stroke-linejoin:round;flex:none}.wake-text{font-size:23px;font-weight:750;letter-spacing:.25em;padding-left:.25em}
.feedback{margin:23px 0 22px;min-height:43px;text-align:center;color:#91aac2;font-size:13px;overflow-wrap:anywhere}
.feedback.ok{color:#9cf6d0}.feedback.err{color:#ffb0b9}
.history{margin-top:5px;background:#111f31dc;border:1px solid var(--border);border-radius:18px;padding:18px 17px 12px}
.heading{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:10px}
.heading strong{font-size:15px;font-weight:700}.heading small{font-size:11px;color:#7890aa;margin-left:5px;font-weight:400}
.refresh{border:1px solid #37506a;background:#172d40;color:#bdebd9;padding:8px 12px;font:inherit;font-size:12px;border-radius:9px;cursor:pointer}
.empty{color:#8196af;text-align:center;padding:26px 2px;font-size:13px}
.entry{padding:11px 0;border-top:1px solid #23394d;display:flex;gap:9px;align-items:flex-start;justify-content:space-between}
.entry-main{flex:1;min-width:0}.state{font-size:13px;font-weight:650}.state.ok{color:#8eebbf}.state.err{color:#ffacb9}.item-desc{font-size:12px;color:#829bb3;margin-top:3px;overflow-wrap:anywhere}
.when{font-size:11px;color:#839ab4;white-space:nowrap;margin-top:2px;font-variant-numeric:tabular-nums}
.foot{color:#557088;text-align:center;font-size:11px;margin:20px 0 8px}
.login{background:#101e2fcf;border:1px solid var(--border);border-radius:16px;padding:22px;margin-top:28px}
.login label{color:#b2c6d9;display:block;font-size:13px;margin:13px 0 7px}
.login input{background:#0b1726;border:1px solid #39516a;color:#fff;padding:12px;border-radius:10px;font:inherit;width:100%}
.login button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:10px;background:#82e7ba;color:#0d3026;font:inherit;font-weight:bold;cursor:pointer}
@media(max-height:720px){.bar{margin-bottom:12px}.lead{margin-bottom:11px}.wake{width:165px;height:165px}.btn-box{padding:8px 0}.feedback{margin:12px 0}}
</style></head><body><main class="wrap">
<header class="bar"><div class="logo"><span class="dot">●</span>NAS WAKE</div>
{% if auth_enabled and logged_in %}<form action="{{ url_for('logout') }}" method="post"><input name="csrf" type="hidden" value="{{ csrf }}"><button class="logout" type="submit">退出</button></form>{% else %}<span style="font-size:11px;color:#6986a1">WOL WEB</span>{% endif %}
</header>
{% if auth_enabled and not logged_in %}
<div class="login"><h1>NAS 远程唤醒</h1><p class="lead">请输入 WEB 登录密码</p><form action="{{ url_for('login') }}" method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><label for="pw">访问密码</label><input id="pw" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">登录</button></form><p id="loginMessage" class="feedback err">{{ message }}</p></div>
{% else %}
<h1>NAS 远程唤醒</h1><p class="lead">点击圆形按钮向家庭 NAS 发送网络唤醒数据包</p>
<div class="btn-box"><button id="wakeButton" class="wake" type="button"><svg class="power-icon" viewBox="0 0 64 64" role="img" aria-label="电源" xmlns="http://www.w3.org/2000/svg"><path d="M32 7 V30"/><path d="M20 12 A24 24 0 1 0 44 12"/></svg><span class="wake-text">唤醒</span></button></div>
<div id="feedback" class="feedback" aria-live="polite">准备就绪</div>
<section class="history" aria-label="最近五条发送记录"><div class="heading"><strong>发送记录 <small>最近 5 条 · 北京时间</small></strong><button id="refreshButton" class="refresh" type="button">↻ 刷新</button></div><div id="historyList" class="empty">加载中...</div></section>
<div class="foot">发送成功仅表示数据包已交给 VPS 网络协议栈，不代表 NAS 已开机</div>
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
      const div=makeEl('div','entry');const left=makeEl('div','entry-main');
      const ok=item.status==='sent';const pending=item.status==='sending';left.append(makeEl('div','state '+(ok?'ok':pending?'':'err'),ok?'✓ 唤醒数据包已发送':pending?'… 正在发送':'发送失败'));
      left.append(makeEl('div','item-desc',item.detail));
      div.append(left,makeEl('time','when',item.time));historyList.append(div);
    }
  }catch(ex){historyList.className='empty';historyList.textContent='记录加载失败，请点击刷新';}
  finally{refreshButton.disabled=false;}
}
wakeButton.addEventListener('click',async()=>{
  wakeButton.disabled=true;feedback.className='feedback';feedback.textContent='正在发送 WOL 唤醒包...';
  try{
    const resp=await fetch('/api/wake',{method:'POST',headers:{'X-CSRF-Token':csrf},credentials:'same-origin',cache:'no-store'});
    if(resp.status===401){location.reload();return;}
    const data=await resp.json();feedback.className='feedback '+(resp.ok?'ok':'err');
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


_boot = load_config()
if not _boot.get("secret_key"):
    raise SystemExit(f"WOL 配置文件不可用或缺少 secret_key: {CONFIG_FILE}")

app = Flask(__name__)
app.secret_key = _boot["secret_key"]
# Only trust the locally configured Nginx proxy; do not bind the app to public interfaces.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True)

_failed_logins = {}
_login_lock = threading.Lock()


def auth_enabled():
    """Login is always required, including for upgraded auth_enabled=false configs."""
    return True


def logged_in():
    return session.get("logged_in") is True


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


def send_wol(config):
    """Send conventional 102-byte Magic Packets over public IPv4/UDP.

    Strategy differs from the previous release:
      - five datagrams using an OS-selected ephemeral UDP source port;
      - a second, best-effort two-datagram pass with source UDP port 9.
    Both use the *configured destination port*, normally UDP/9. The alternate
    source port can help only with unusual router/firewall rules; it does not
    solve a home router's missing ARP or broken port forwarding.

    Returns resolved targets, target port, packets sent, source-port summary.
    """
    host = validate_host(config.get("host", ""))
    try:
        port = int(config.get("port", 9))
    except (TypeError, ValueError):
        raise ValueError("WOL 端口不合法")
    if not 1 <= port <= 65535:
        raise ValueError("WOL UDP 端口必须在 1-65535 之间")
    packet = build_packet(config.get("mac", ""))
    if len(packet) != 102:
        raise ValueError("Magic Packet 长度不正确")
    try:
        resolved = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError("DDNS 解析 IPv4 失败，请核实域名 A 记录") from exc
    ips = list(dict.fromkeys(result[4][0] for result in resolved))
    if not ips:
        raise ValueError("没有解析到 IPv4 地址")
    if len(ips) > 4:
        raise ValueError("域名解析出过多 IPv4 地址；请检查是否误开 CDN 代理")

    # Repeating with a different source port is not a substitute for
    # LAN-level broadcast; keep logging sufficiently detailed to diagnose.
    sent = 0
    source_descriptions = []
    for address in ips:
        dest = (address, port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect(dest)
            source_ip, source_port = sock.getsockname()
            source_descriptions.append(f"{source_ip}:{source_port}")
            for index in range(5):
                sock.send(packet)
                sent += 1
                if index != 4:
                    time.sleep(0.10)
        # Optional second attempt, bound to local UDP source port 9.
        # Binding is not always allowed (port already in use / upstream rules).
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.bind(("0.0.0.0", 9))
                sock.connect(dest)
                local_ip, source_port = sock.getsockname()
                source_descriptions.append(f"{local_ip}:{source_port}")
                for index in range(2):
                    sock.send(packet)
                    sent += 1
                    if index == 0:
                        time.sleep(0.10)
        except OSError as exc:
            source_descriptions.append(f"源端口9不可用({exc.__class__.__name__})")

    return ips, port, sent, source_descriptions


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
    with database() as con:
        rows = con.execute("SELECT at,status,detail FROM sends ORDER BY id DESC LIMIT 5").fetchall()
    return [
        {"time": datetime.fromtimestamp(ts, TZ).strftime("%m/%d %H:%M:%S"),
         "status": status, "detail": detail}
        for ts, status, detail in rows
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
    if not load_config().get("password_hash"):
        return "WEB 未完成初始化：请运行 wol.sh，选择菜单 3 设置访问密码。", 503
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


@app.post("/api/wake")
@require_auth
def wake():
    if not check_csrf():
        return jsonify({"ok": False, "message": "页面验证失效，请刷新后重试"}), 400
    config = load_config()
    cooldown = max(5, min(600, int(config.get("cooldown_seconds", 20))))
    try:
        row_id, seconds_left = reserve_send(cooldown)
    except sqlite3.Error:
        app.logger.exception("Unable to store WOL history")
        return jsonify({"ok": False, "message": "发送记录数据库暂时不可写，请检查服务权限"}), 503
    if row_id is None:
        return jsonify({"ok": False, "message": f"操作过于频繁，请 {seconds_left} 秒后再试"}), 429
    try:
        ips, port, count, sources = send_wol(config)
        detail = f"目标 {', '.join(ips)}:{port} · UDP {count} 包 · 出站 {', '.join(sources)}"
        finish_send(row_id, "sent", detail)
        app.logger.info("WOL sent: resolved=%s port=%s packets=%s sources=%s", ips, port, count, sources)
        return jsonify({"ok": True, "message": f"已发送 {count} 个唤醒包至 {', '.join(ips)}:{port}；仅确认 VPS 已发出，请检查 NAS 是否启动"})
    except (OSError, ValueError, TypeError, KeyError) as exc:
        app.logger.warning("WOL failed: %s", exc)
        finish_send(row_id, "failed", str(exc))
        return jsonify({"ok": False, "message": f"WOL 发送失败：{exc}"}), 502


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == "--test-wol":
        # Operator-only SSH diagnostic: use the installed config, bypassing
        # browser/HTTPS. This makes it possible to isolate VPS UDP vs WEB.
        try:
            ips, port, count, sources = send_wol(load_config())
            print(f"WOL 测试：已向 {', '.join(ips)}:{port} 发送 {count} 个 Magic Packet")
            print("VPS 本机 UDP 出站地址/端口：" + ", ".join(sources))
            print("注意：发送成功不代表家庭路由器已转发或 NAS 已启动。")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(f"WOL 测试发送失败：{exc}", file=sys.stderr)
            sys.exit(1)
    elif len(sys.argv) > 1:
        print("用法：python wol.py [--test-wol]", file=sys.stderr)
        sys.exit(2)
    else:
        app.run(host="127.0.0.1", port=int(os.environ.get("WOL_WEB_PORT", "8109")), debug=False)
