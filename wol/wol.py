#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WOL WEB: single-button Wake-on-LAN dashboard with persistent send history."""
WOL_WEB_APP_VERSION = "1.6.3"

import errno
import hashlib
import stat
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
.logo{font-size:14px;letter-spacing:.12em;color:#d8e8f5;font-weight:850;display:flex;align-items:center;gap:10px}.mode-tag{font-size:10px;letter-spacing:.05em;font-weight:800;border:1px solid #477c78;border-radius:8px;color:#8eebbf;background:#173344;padding:3px 6px}.mode-tag{font-family:inherit;cursor:pointer}.mode-tag:disabled{cursor:wait;opacity:.65}.mode-tag:focus-visible{outline:2px solid #e9f3ff;outline-offset:3px}.mode-tag.temporary{border-color:#a5834d;color:#ffda95;background:#403424}.dot{color:var(--mint);font-size:18px;margin-right:9px}
.logout{color:#9eb2c9;background:transparent;border:1px solid #344861;border-radius:10px;padding:7px 13px;cursor:pointer}
.btn-box{text-align:center;padding:17px 0 5px}
.wake{width:196px;height:196px;max-width:65vw;max-height:65vw;cursor:pointer;border-radius:50%;border:1px solid #75e6b3;background:radial-gradient(circle at 36% 22%,#2e6b63 0%,#1a514b 43%,#0d3039 82%);box-shadow:0 0 0 11px #70e3b20c,0 0 0 24px #70e3b208,0 0 55px #33d9a331;color:#f1fff9;display:inline-flex;align-items:center;justify-content:center;flex-direction:column;gap:4px;transition:transform .12s,opacity .12s}
.wake:active{transform:scale(.97)}.wake:disabled{cursor:not-allowed;opacity:.55}.wake:focus-visible,.refresh:focus-visible{outline:3px solid #f0fffc;outline-offset:5px}
.power-icon{display:block;width:72px;height:72px;fill:none;stroke:#84f4c4;stroke-width:5.5;stroke-linecap:round;stroke-linejoin:round;flex:none}
.feedback{margin:13px 0 14px;min-height:24px;text-align:center;color:#91aac2;font-size:13px;overflow-wrap:anywhere}
/* Independent IP-check and UDP-send indicators share the existing mint/red palette. */
.feedback.ok{color:#9cf6d0}.feedback.err{color:#ffb0b9}.feedback.refused{color:#ffcf8b}
.result-pair{display:inline-flex;flex-wrap:wrap;align-items:center;justify-content:center;row-gap:4px;line-height:1.55}
.entry .result-pair{justify-content:flex-start}
.result-item{display:inline-flex;align-items:center;white-space:nowrap;font-size:13px;font-weight:650}
.result-item.ok{color:#8eebbf}.result-item.err{color:#ffacb9}.result-item.refused{color:#ffcf8b}
.result-icon{display:inline-block;flex:none;width:15px;height:15px;margin-right:4px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.result-separator{margin:0 4px;color:#8296ad}
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
<div class="logo">WOL {% if auth_enabled and logged_in %}<button id="modeToggle" class="mode-tag" type="button" title="点击临时切换 IPV4/IPV6，刷新网页恢复默认模式" aria-label="当前 {{ wake_mode|upper }}，点击切换唤醒模式" aria-pressed="false">{{ wake_mode|upper }}</button>{% else %}<span class="mode-tag">{{ wake_mode|upper }}</span>{% endif %}</div>
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
const modeToggle = document.getElementById('modeToggle');
const defaultWakeMode = {{ wake_mode|tojson }};
let selectedWakeMode = defaultWakeMode;
// Only in this page's JavaScript memory; not stored in cookies or config.
// A full page refresh restores the mode configured by wol.sh.
function showSelectedWakeMode(){
  const isTemporary = selectedWakeMode !== defaultWakeMode;
  modeToggle.textContent = selectedWakeMode.toUpperCase();
  modeToggle.classList.toggle('temporary', isTemporary);
  modeToggle.setAttribute('aria-pressed', String(isTemporary));
  modeToggle.setAttribute('aria-label', '当前 '+selectedWakeMode.toUpperCase()+'，点击临时切换唤醒模式');
  modeToggle.title = isTemporary
    ? '临时模式 '+selectedWakeMode.toUpperCase()+'；刷新网页恢复 '+defaultWakeMode.toUpperCase()
    : '默认模式 '+defaultWakeMode.toUpperCase()+'；点击临时切换 IPV4/IPV6';
}
modeToggle.addEventListener('click',()=>{
  if(modeToggle.disabled)return;
  selectedWakeMode = selectedWakeMode === 'ipv4' ? 'ipv6' : 'ipv4';
  showSelectedWakeMode();
  feedback.className='feedback';
  feedback.textContent='已临时切换到 '+selectedWakeMode.toUpperCase()+'，刷新网页恢复默认模式';
});
showSelectedWakeMode();
function makeEl(tag, cls, text){const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;}
function resultIcon(kind){
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','result-icon');svg.setAttribute('viewBox','0 0 20 20');
  svg.setAttribute('aria-hidden','true');svg.setAttribute('focusable','false');
  const circle=document.createElementNS('http://www.w3.org/2000/svg','circle');
  circle.setAttribute('cx','10');circle.setAttribute('cy','10');circle.setAttribute('r','8');svg.append(circle);
  const path=document.createElementNS('http://www.w3.org/2000/svg','path');
  path.setAttribute('d',kind==='ok'?'M5.7 10.2l2.8 2.8 5.8-6':'M7.2 7.2l5.6 5.6m0-5.6l-5.6 5.6');
  svg.append(path);return svg;
}
function resultItem(kind,text){
  const item=makeEl('span','result-item '+kind);
  item.append(resultIcon(kind),document.createTextNode(text));return item;
}
function makeResultPair(ipStatus,sendStatus){
  const line=makeEl('span','result-pair');
  const parts=[];
  if(ipStatus==='matched')parts.push(resultItem('ok','IP解析一致'));
  if(ipStatus==='mismatched')parts.push(resultItem('err','IP解析不一致'));
  if(sendStatus==='sent')parts.push(resultItem('ok','唤醒数据包已发送'));
  if(sendStatus==='refused')parts.push(resultItem('refused','Send refused！'));
  if(sendStatus==='failed')parts.push(resultItem('err','WOL 发送失败'));
  if(sendStatus==='sending')parts.push(makeEl('span','','… 正在发送'));
  parts.forEach((part,index)=>{if(index)line.append(makeEl('span','result-separator','，'));line.append(part);});
  return line;
}
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
      const ipStatus=item.ip_status || (item.status==='ip_mismatch'?'mismatched':'none');
      const sendStatus=item.send_status || (item.status==='ip_mismatch'?'none':item.status);
      div.append(makeResultPair(ipStatus,sendStatus));
      div.append(makeEl('time','when',item.time));historyList.append(div);
    }
  }catch(ex){historyList.className='empty';historyList.textContent='记录加载失败，请点击刷新';}
  finally{refreshButton.disabled=false;}
}
wakeButton.addEventListener('click',async()=>{
  const sendMode = selectedWakeMode;
  wakeButton.disabled=true;modeToggle.disabled=true;
  feedback.className='feedback';feedback.textContent='正在通过 '+sendMode.toUpperCase()+' 发送 WOL 唤醒包...';
  try{
    const resp=await fetch('/api/wake',{method:'POST',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/json'},body:JSON.stringify({mode:sendMode}),credentials:'same-origin',cache:'no-store'});
    if(resp.status===401){location.reload();return;}
    const data=await resp.json();
    feedback.className='feedback';
    if(data.ip_status || data.send_status){
      feedback.replaceChildren(makeResultPair(data.ip_status||'none',data.send_status||'failed'));
    }else{
      feedback.className='feedback '+(resp.ok?'ok':'err');
      feedback.textContent=data.message || '请求失败';
    }
    await refreshHistory();
  }catch(ex){feedback.className='feedback err';feedback.textContent='连接失败，请检查 WEB 服务或网络连接';}
  finally{wakeButton.disabled=false;modeToggle.disabled=false;}
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


def _resolve_host_ipv4(host, port):
    """Resolve once so the compared IPs are exactly the ones used to send."""
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
    return ips


def _send_wol_to_host(host, port, packet, *, resolved_ips=None):
    """Submit unconnected IPv4 UDP datagrams using a fixed DNS snapshot.

    A successful sendto only proves local submission, not receipt or boot.
    """
    ips = _resolve_host_ipv4(host, port) if resolved_ips is None else list(resolved_ips)
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


def _send_ipv4_wol(config):
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

    # Take one DNS snapshot for each configured domain BEFORE transmitting.
    # The same resolved addresses are then used by the UDP sender, so DNS
    # changes between resolution and send cannot hide a mismatch.
    resolved_ips = {}
    resolution_errors = {}
    for route, host in targets:
        try:
            resolved_ips[route] = _resolve_host_ipv4(host, port)
        except (OSError, ValueError) as exc:
            resolution_errors[route] = exc

    # IPv4 single-channel mode: an empty/whitespace host2 means ONLY host1
    # is resolved and used. No host2 DNS lookup and NO IP equality check.
    # Two configured hosts retain the existing independent DNS comparison
    # as a diagnostic warning (never a WOL packet-delivery verdict).
    compared = bool(backup)
    fully_resolved = bool(compared and "primary" in resolved_ips and "backup" in resolved_ips)
    ips_equal = bool(fully_resolved and
                     set(resolved_ips["primary"]) == set(resolved_ips["backup"]))
    ip_mismatch = bool(compared and not ips_equal)
    ip_comparison = {
        "checked": compared,
        "matched": ips_equal if compared else None,
        "resolution_complete": fully_resolved,
        "reason": ("single_channel" if not compared else
                   "resolution_failed" if not fully_resolved else
                   "matched" if ips_equal else "different_ipv4"),
        "host1_ipv4": list(resolved_ips.get("primary", [])),
        "host2_ipv4": list(resolved_ips.get("backup", [])),
    }

    # A mismatch is a DDNS diagnostic warning, not a UDP delivery verdict.
    # Continue sending to BOTH configured domains to preserve redundancy.
    attempts = []
    for i, (route, host) in enumerate(targets):
        if i:
            time.sleep(0.20)
        try:
            if route in resolution_errors:
                raise resolution_errors[route]
            ips, sent, sources, errors, refused, failed_packets = _send_wol_to_host(
                host, port, packet, resolved_ips=resolved_ips[route])
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
        "ip_mismatch": ip_mismatch,
        "ip_comparison": ip_comparison,
        "attempts": attempts,
        "port": port,
        "success_count": len(succeeded),
        "target_count": len(attempts),
        "packets": sum(item["packets"] for item in attempts),
        "error": "；".join(reasons),
    }



def _ipv6_relay_wol(config):
    """IPv6-only: host1 -> authenticated AX6 relay -> LAN broadcast.

    A valid ACK with submitted packets is required. UDP submission from VPS
    alone NEVER counts as successful relay delivery or NAS boot.
    """
    host = str(config.get("host1") or "").strip()
    if not host:
        raise ValueError("IPv6 模式必须配置 host1（AX6 的 AAAA 域名）")
    # Validate the host and require a public IPv6 DNS result below.
    host = validate_relay6_host(host)
    try:
        port = int(config.get("relay6_port", 41996))
    except (ValueError, TypeError) as exc:
        raise ValueError("IPv6 中继端口无效") from exc
    if not 1024 <= port <= 65535:
        raise ValueError("IPv6 中继端口必须在 1024-65535 之间")
    key_path = Path(config.get("relay6_secret_file") or str(APP_DIR / "wol6_secret"))
    if not key_path.is_file():
        raise ValueError("缺少 IPv6 中继密钥，请按部署手册上传 wol6_secret")
    if not key_path.is_absolute():
        raise ValueError("IPv6 中继密钥必须使用绝对路径")
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise ValueError("IPv6 中继密钥权限过宽，请执行 chmod 600")
    try:
        key = bytes.fromhex(key_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("IPv6 中继密钥内容无效") from exc
    if len(key) != 32:
        raise ValueError("IPv6 中继密钥长度必须为 32 字节")

    ips = []
    dns_error = ""
    try:
        records = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_DGRAM)
        ips = list(dict.fromkeys(str(ipaddress.IPv6Address(item[4][0])) for item in records
                                  if ipaddress.IPv6Address(item[4][0]).is_global))
        if len(ips) != 1:
            raise ValueError("IPv6 中继域名必须仅解析到一个公网 AAAA 地址")
    except (socket.gaierror, ValueError, OSError) as exc:
        dns_error = str(exc)

    ack_ok = False
    sent_lan = 0
    error_text = dns_error
    refused = False
    if not dns_error:
        nonce = secrets.token_hex(16)
        body = f"WOL1|{int(time.time())}|{nonce}"
        signed = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
        payload = f"{body}|{signed}".encode("ascii")
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3.5)
                sock.sendto(payload, (ips[0], port, 0, 0))
                raw, peer = sock.recvfrom(512)
            # The router/ISP may use or NAT to another public IPv6 for replies.
            # A matching DNS address is not a cryptographic identity. Authenticate
            # nonce + HMAC BEFORE accepting this ACK, independent of source IP.
            # Check the expected UDP service port as additional hygiene.
            if peer[1] != port:
                raise ValueError("IPv6 中继确认来源端口不正确")
            parts = raw.decode("ascii").split("|")
            if len(parts) != 4 or parts[0] != "ACK1" or parts[1] != nonce:
                raise ValueError("IPv6 中继确认格式不正确")
            proof = "|".join(parts[:3]).encode("ascii")
            expected = hmac.new(key, proof, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(parts[3], expected):
                raise ValueError("IPv6 中继确认签名不正确")
            # Authenticated ACK is accepted even if its reply address differs
            # from the Cloudflare AAAA target (multi-address router / NAT66).
            if not parts[2].isdigit():
                raise ValueError("IPv6 中继确认包数无效")
            sent_lan = int(parts[2])
            if not 1 <= sent_lan <= 7:
                raise ValueError("IPv6 中继未能提交局域网唤醒包")
            ack_ok = True
        except (OSError, ValueError, UnicodeError) as exc:
            refused = getattr(exc, "errno", None) == errno.ECONNREFUSED
            error_text = str(exc)

    attempt = {
        "route": "primary", "host": host, "ok": ack_ok,
        "ips": [], "ipv6": ips, "packets": sent_lan if ack_ok else 0,
        "failed_packets": 0 if ack_ok else 1,
        "sources": [], "error": error_text, "warnings": [],
        "refused": refused, "relay_ack": ack_ok,
    }
    return {
        "mode": "ipv6", "ok": ack_ok, "refused": refused,
        "ip_mismatch": False,
        "ip_comparison": {"checked": False, "matched": None,
                          "resolution_complete": False, "reason": "ipv6_mode",
                          "host1_ipv4": [], "host2_ipv4": []},
        "attempts": [attempt], "port": port,
        "success_count": 1 if ack_ok else 0, "target_count": 1,
        "packets": sent_lan if ack_ok else 0, "error": error_text,
        "ipv6_relay": {"domain": host, "resolved_ipv6": ips,
                       "status": "acknowledged" if ack_ok else "failed",
                       "relay_ack": ack_ok, "lan_packets_submitted": sent_lan if ack_ok else 0,
                       "error": error_text[:250]},
    }


def validate_relay6_host(value):
    host = str(value or "").strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host) or "://" in host or "/" in host or "\\" in host:
        raise ValueError("IPv6 中继 host1 格式不正确")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        domain = host.rstrip(".")
        label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        if not domain or not all(label_re.fullmatch(label) for label in domain.split(".")):
            raise ValueError("IPv6 中继 host1 域名不合法")
    else:
        if not isinstance(ip, ipaddress.IPv6Address) or not ip.is_global:
            raise ValueError("IPv6 中继 host1 必须是公网 IPv6 地址或 AAAA 域名")
    return host.strip("[]")


def send_wol(config):
    mode = config.get("wake_mode", "ipv4")
    if mode == "ipv4":
        result = _send_ipv4_wol(config)
        result["mode"] = "ipv4"
        return result
    if mode == "ipv6":
        return _ipv6_relay_wol(config)
    raise ValueError("不支持的唤醒模式：请在菜单 2 选择 IPV4 或 IPV6")

def _log_host(config, route, attempts, error="", *, mode="ipv4"):
    """One independent and truthful status per host, per click."""
    key = "host1" if route == "primary" else "host2"
    configured = "" if mode == "ipv6" and route == "backup" else config.get(key, "")
    configured = configured.strip() if isinstance(configured, str) else ""
    attempt = next((item for item in attempts if item["route"] == route), None)
    if attempt is None:
        return {
            "domain": configured,
            "status": "not_attempted" if (route == "primary" or configured) else "disabled",
            "resolved_ipv4": [], "resolved_ipv6": [], "relay_ack": False,
            "packets_sent": 0, "packets_failed": 0,
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
        "resolved_ipv6": list(attempt.get("ipv6", [])),
        "relay_ack": bool(attempt.get("relay_ack", False)),
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
    mode = result.get("mode", config.get("wake_mode", "ipv4")) if result else config.get("wake_mode", "ipv4")
    # Overall is the UDP submission outcome; IP comparison is independent.
    overall = ("sent" if result and result.get("ok") else
               "refused" if result and result.get("refused") else "failed")
    entry = {
        "time": datetime.now(TZ).isoformat(timespec="seconds"),
        "trigger": trigger,
        "mode": mode,
        "overall": overall,
        "host1": _log_host(config, "primary", attempts, error, mode=mode),
        "host2": _log_host(config, "backup", attempts, error, mode=mode),
        "ip_comparison": (result.get("ip_comparison") if result else {
            "checked": False, "matched": None,
            "host1_ipv4": [], "host2_ipv4": [],
        }),
    }
    if mode == "ipv6":
        entry["ipv6_relay"] = (result.get("ipv6_relay") if result else {
            "domain": str(config.get("host1") or ""), "resolved_ipv6": [],
            "status": "not_attempted", "relay_ack": False,
            "lan_packets_submitted": 0, "error": str(error)[:250]})
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
    """Return separate display states, without exposing IPs or log diagnostics."""
    with database() as con:
        rows = con.execute("SELECT at,status,detail FROM sends ORDER BY id DESC LIMIT 5").fetchall()
    items = []
    for ts, status, detail in rows:
        ip_status = "none"
        send_status = status
        if status == "ip_mismatch":
            # Older rows lack a separate send outcome; do not invent one.
            ip_status, send_status = "mismatched", "none"
        else:
            try:
                metadata = json.loads(detail)
                if isinstance(metadata, dict):
                    ip_status = metadata.get("ip_status", "none")
                    send_status = metadata.get("send_status", status)
            except (TypeError, ValueError):
                pass
        items.append({
            "time": datetime.fromtimestamp(ts, TZ).strftime("%m/%d %H:%M:%S"),
            "status": status,
            "ip_status": ip_status if ip_status in ("none", "matched", "mismatched") else "none",
            "send_status": send_status if send_status in ("none", "sent", "refused", "failed", "sending") else "failed",
        })
    return items


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
                                  message=request.args.get("error", ""),
                                  wake_mode=("ipv6" if config.get("wake_mode") == "ipv6" else "ipv4"))


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
    # A web override is PER REQUEST only: never mutate config.json or session.
    # With no override, use the persistent mode chosen by wol.sh menu 2.
    if request.is_json:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"ok": False, "message": "无效的模式切换请求"}), 400
    else:
        payload = {}
    selected_mode = payload.get("mode", config.get("wake_mode", "ipv4"))
    if selected_mode not in ("ipv4", "ipv6"):
        return jsonify({"ok": False, "message": "无效的唤醒模式，仅支持 IPV4 或 IPV6"}), 400
    request_config = dict(config)
    request_config["wake_mode"] = selected_mode
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
        result = send_wol(request_config)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # A malformed configuration did not begin sending to either host.
        _safe_log_send(request_config, trigger="web", error=str(exc))
        app.logger.warning("WOL preparation failed: %s", exc)
        finish_send(row_id, "failed", "发送失败")
        return jsonify({"ok": False, "message": "WOL 发送失败"}), 502

    # One click -> exactly one rotated local log entry, with BOTH independent
    # host outcomes, even when one target fails DNS or all packets fail.
    _safe_log_send(request_config, result)
    for attempt in result["attempts"]:
        level = app.logger.info if attempt["ok"] else app.logger.warning
        level("WOL mode=%s route=%s host=%s ips=%s submitted=%s failed=%s errno111=%s details=%s",
              result.get("mode", "ipv4"), attempt["route"], attempt["host"],
              attempt.get("ipv6") or attempt["ips"],
              attempt["packets"], attempt["failed_packets"],
              attempt["refused"], attempt["warnings"] or attempt["error"])

    # IPv4 retains dual-host DNS and errno111 presentation. IPv6 has only
    # one host and a signed relay ACK: no IP comparison / no Send refused label.
    if result.get("mode") == "ipv6":
        ip_status = "none"
        send_status = "sent" if result["ok"] else "failed"
    else:
        ip_status = ("mismatched" if result["ip_mismatch"] else
                     "matched" if result["ip_comparison"]["checked"] else "none")
        send_status = ("sent" if result["ok"] else
                       "refused" if result["refused"] else "failed")
    ip_text = ("IP解析一致" if ip_status == "matched" else
               "IP解析不一致" if ip_status == "mismatched" else "")
    send_text = ("唤醒数据包已发送" if send_status == "sent" else
                 "Send refused！" if send_status == "refused" else "WOL 发送失败")
    display_message = "，".join(text for text in (ip_text, send_text) if text)

    if result["ip_mismatch"]:
        app.logger.warning("WOL DDNS IPv4 comparison warning: %s", result["ip_comparison"])

    # A single click is one history row. Store only display states there;
    # detailed independent host outcomes remain in the rolling JSONL log.
    history_detail = json.dumps({"ip_status": ip_status, "send_status": send_status},
                                ensure_ascii=False, separators=(",", ":"))
    finish_send(row_id, send_status, history_detail)
    response = {"ok": result["ok"], "mode": result.get("mode", selected_mode),
                "ip_mismatch": result["ip_mismatch"],
                "ip_status": ip_status, "send_status": send_status,
                "refused": send_status == "refused", "message": display_message}
    return jsonify(response), (200 if result["ok"] else 502)


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
            if result["ip_comparison"]["checked"]:
                print("✖ IP解析不一致" if result["ip_mismatch"] else "✔ IP解析一致")
                if result["ip_mismatch"]:
                    print("主域名 IPv4：" + ", ".join(result["ip_comparison"]["host1_ipv4"]))
                    print("备域名 IPv4：" + ", ".join(result["ip_comparison"]["host2_ipv4"]))
            if result["ok"]:
                print("✔ 唤醒数据包已发送")
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
