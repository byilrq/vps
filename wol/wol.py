#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authenticated Wake-on-LAN web button."""
WOL_WEB_APP_VERSION = "1.1.0"

import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

CONFIG_FILE = Path(os.environ.get("WOL_CONFIG_FILE", str(Path(__file__).resolve().parent / "config.json")))
WEB_BIND = os.environ.get("WOL_WEB_BIND", "127.0.0.1")
WEB_PORT = int(os.environ.get("WOL_WEB_PORT", "8109"))
COOKIE_SECURE = os.environ.get("WOL_COOKIE_SECURE", "1") == "1"
WAKE_COOLDOWN_SECONDS = 8

PAGE = r"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#09111f">
<title>NAS 远程唤醒</title>
<style>
:root{color-scheme:dark;--bg:#09111f;--panel:#101c2d;--text:#edf4ff;--muted:#8fa4bf;--mint:#66e5ad}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:radial-gradient(ellipse at 50% 35%,#142844 0%,var(--bg) 62%);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
body{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:22px}
.shell{width:100%;max-width:460px;text-align:center}
.top{display:flex;justify-content:space-between;align-items:center;margin:0 0 44px;color:var(--muted);font-size:12px;letter-spacing:.18em}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;letter-spacing:.14em;color:#c9d8ed}
.brand-mark{display:inline-flex;align-items:center;justify-content:center;width:29px;height:29px;border-radius:9px;background:#18334a;color:var(--mint);font-size:18px;letter-spacing:0}
.logout{color:#9db1cb;text-decoration:none;font-size:13px;letter-spacing:0;border:1px solid #263951;border-radius:20px;padding:7px 11px;background:#0c1726}
h1{font-size:26px;line-height:1.2;margin:0 0 10px;font-weight:750;letter-spacing:.02em}
.subtitle{font-size:14px;color:var(--muted);margin:0 0 44px}
.wake-form{margin:0}
.wake-button{appearance:none;border:1px solid rgba(137,255,205,.65);border-radius:50%;width:202px;height:202px;max-width:68vw;max-height:68vw;background:radial-gradient(circle at 34% 25%,#275c57 0%,#16433f 37%,#0e2c32 72%,#0b222d 100%);color:#eafff5;box-shadow:0 0 0 10px rgba(102,229,173,.055),0 0 0 22px rgba(102,229,173,.025),0 0 52px rgba(57,224,163,.18),inset 0 1px 0 rgba(255,255,255,.16);display:inline-flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;cursor:pointer;transition:transform .12s ease,box-shadow .18s ease;font:inherit;-webkit-tap-highlight-color:transparent}
.wake-button:hover{box-shadow:0 0 0 10px rgba(102,229,173,.08),0 0 0 22px rgba(102,229,173,.035),0 0 68px rgba(57,224,163,.28),inset 0 1px 0 rgba(255,255,255,.2)}
.wake-button:active{transform:scale(.97)}
.wake-button:focus-visible{outline:3px solid #d4ffec;outline-offset:7px}
.power{font-size:56px;line-height:1;font-weight:300;color:var(--mint)}
.wake-label{font-size:23px;font-weight:750;letter-spacing:.16em;padding-left:.16em}
.hint{margin:43px 0 0;color:#758ba7;font-size:12px;letter-spacing:.04em}
.messages{margin:0 auto 22px;max-width:380px}
.message{padding:11px 14px;border:1px solid #2d6a55;border-radius:12px;background:#102d28;color:#b9f9dc;font-size:14px;overflow-wrap:anywhere}
.message.error{border-color:#75404a;background:#321b25;color:#ffc4cd}
.login-card{margin:0 auto;padding:25px 22px;background:rgba(16,28,45,.9);border:1px solid #253851;border-radius:20px;text-align:left;box-shadow:0 24px 80px #0004}
.login-card h1{text-align:center;margin-bottom:8px}
.login-card .subtitle{text-align:center;margin-bottom:25px}
label{display:block;color:#b8c9df;font-size:13px;margin:14px 0 7px}
input{display:block;width:100%;padding:13px 14px;border:1px solid #334964;border-radius:11px;background:#091421;color:#fff;font:inherit;font-size:16px;outline:none}
input:focus{border-color:#66e5ad;box-shadow:0 0 0 3px #66e5ad22}
.login-button{display:block;width:100%;border:0;border-radius:11px;padding:13px 16px;margin-top:20px;background:var(--mint);color:#08271c;font:inherit;font-weight:800;cursor:pointer}
.foot{color:#536982;font-size:11px;margin-top:28px}
@media(max-height:650px){.top{margin-bottom:24px}.subtitle{margin-bottom:25px}.wake-button{width:170px;height:170px}.hint{margin-top:30px}}
</style>
</head>
<body>
<div class="shell">
{% if not logged_in %}
  <div class="top"><div class="brand"><span class="brand-mark">⏻</span><span>NAS WAKE</span></div><span>REMOTE ACCESS</span></div>
  <div class="login-card">
    <h1>NAS 远程唤醒</h1>
    <p class="subtitle">请验证身份后继续</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="messages"><div class="message {{ 'error' if category == 'error' else '' }}">{{ message }}</div></div>
      {% endfor %}
    {% endwith %}
    <form method="post" action="{{ url_for('login') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <label for="password">网页访问密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button class="login-button" type="submit">登录</button>
    </form>
  </div>
{% else %}
  <div class="top">
    <div class="brand"><span class="brand-mark">⏻</span><span>NAS WAKE</span></div>
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="logout" type="submit">退出</button>
    </form>
  </div>
  <h1>NAS 远程唤醒</h1>
  <p class="subtitle">轻触按钮，发送网络唤醒指令</p>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
      <div class="messages"><div class="message {{ 'error' if category == 'error' else '' }}">{{ message }}</div></div>
    {% endfor %}
  {% endwith %}
  <form class="wake-form" method="post" action="{{ url_for('wake') }}">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <button class="wake-button" type="submit" aria-label="唤醒 NAS">
      <span class="power">⏻</span>
      <span class="wake-label">唤醒</span>
    </button>
  </form>
  <p class="hint">WAKE ON LAN · MAGIC PACKET</p>
{% endif %}
<div class="foot">SECURE CONNECTION · WOL WEB</div>
</div>
</body>
</html>
"""

def load_config():
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

_BOOT_CONFIG = load_config()
if not _BOOT_CONFIG.get("secret_key"):
    raise SystemExit(
        f"WOL config missing or invalid: {CONFIG_FILE}. Run wol.sh and choose menu 1 first."
    )

app = Flask(__name__)
app.secret_key = _BOOT_CONFIG["secret_key"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

_failed_logins = {}
_failed_lock = threading.Lock()

def get_csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

def check_csrf():
    supplied = request.form.get("csrf", "")
    expected = session.get("_csrf", "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        abort(400, description="Invalid CSRF token")

def logged_in_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped

def normalize_mac(value):
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise ValueError("MAC 地址格式不正确，请在管理脚本菜单 2 中配置。")
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2)).upper()

def validate_host(value):
    host = str(value or "").strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        raise ValueError("NAS 域名或 IP 未配置，请先运行管理脚本菜单 2。")
    if "/" in host or "\\" in host or "://" in host:
        raise ValueError("NAS 地址只填写域名或 IP，不要填写 http:// 或 https://。")
    try:
        parsed = ipaddress.ip_address(host)
        if parsed.version != 4:
            raise ValueError("当前公网 WOL 发送方式需要可解析到 IPv4 的域名或 IPv4 地址。")
        return host
    except ValueError as exc:
        if "当前公网" in str(exc):
            raise
    candidate = host[:-1] if host.endswith(".") else host
    labels = candidate.split(".")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not candidate or any(not label_re.fullmatch(label) for label in labels):
        raise ValueError("NAS 域名格式不正确。")
    return host

def make_magic_packet(mac):
    raw = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + raw * 16

def send_wol(config):
    host = validate_host(config.get("host"))
    try:
        port = int(config.get("port", 9))
    except (TypeError, ValueError):
        raise ValueError("UDP 端口配置无效，请运行管理脚本菜单 2 检查。")
    if not 1 <= port <= 65535:
        raise ValueError("UDP 端口必须在 1-65535 之间。")
    packet = make_magic_packet(config.get("mac"))
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError(f"域名无法解析到 IPv4 地址：{exc}") from exc
    targets = []
    for info in infos:
        ip = info[4][0]
        if ip not in targets:
            targets.append(ip)
    if not targets:
        raise ValueError("没有找到可用的 IPv4 目标地址。")
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for ip in targets:
            for index in range(3):
                sock.sendto(packet, (ip, port))
                sent += 1
                if index < 2:
                    time.sleep(0.06)
    return targets, port, sent

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response

@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        PAGE, logged_in=bool(session.get("logged_in")), csrf=get_csrf_token()
    )

@app.route("/login", methods=["POST"])
def login():
    check_csrf()
    remote = request.remote_addr or "unknown"
    now = time.time()
    with _failed_lock:
        recent = [stamp for stamp in _failed_logins.get(remote, []) if now - stamp < 300]
        _failed_logins[remote] = recent
        if len(recent) >= 8:
            abort(429, description="Too many login attempts")
    config = load_config()
    stored_hash = config.get("password_hash", "")
    password = request.form.get("password", "")
    ok = False
    if stored_hash and password:
        try:
            ok = check_password_hash(stored_hash, password)
        except (ValueError, TypeError):
            ok = False
    if ok:
        with _failed_lock:
            _failed_logins.pop(remote, None)
        session.clear()
        session["logged_in"] = True
        session["_csrf"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("index"))
    with _failed_lock:
        _failed_logins[remote] = _failed_logins.get(remote, []) + [now]
    flash("密码不正确，请重试。", "error")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
@logged_in_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("index"))

@app.route("/wake", methods=["POST"])
@logged_in_required
def wake():
    check_csrf()
    now = time.time()
    last = float(session.get("last_wake", 0) or 0)
    if now - last < WAKE_COOLDOWN_SECONDS:
        flash("操作太频繁，请稍等几秒再试。", "error")
        return redirect(url_for("index"))
    try:
        targets, port, sent = send_wol(load_config())
        session["last_wake"] = now
        app.logger.info("WOL packet sent to %s:%s; packets=%s", ",".join(targets), port, sent)
        flash(
            f"唤醒包已发送至 {', '.join(targets)} 的 UDP {port} 端口。"
            "数据包发出不代表 NAS 已完成启动。",
            "success",
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        app.logger.warning("WOL send failed: %s", exc)
        flash(f"发送失败：{exc}", "error")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host=WEB_BIND, port=WEB_PORT, debug=False)
